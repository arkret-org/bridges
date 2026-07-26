//! The arkret protocol-side edge (replaces the Matrix bridge's
//! `MatrixAppservice`).
//!
//! - **Outbound (app -> arkret)**: [`ArkretEdge::mint_event_unsigned_async`] and
//!   [`ArkretEdge::mint_event_as_unsigned_async`] build unsigned `Event`s; callers finalize signed
//!   envelope fields, sign once with [`ArkretEdge::resign_event`], then submit via
//!   [`arkret::http_client::Client::events_submit`].
//! - **Inbound (arkret → app)**: transactions pushed by the arkret server via the applet HTTP
//!   endpoints are placed into the `inbound_tx` queue by [`BridgeAppletHandler`]; after the core
//!   consumes them they are forwarded to the app adapter.
//! - **Media**: [`ArkretEdge::upload_blob`] / [`ArkretEdge::download_blob`].
//!
//! The restart-safe monotonic actor-sequence allocator is abstracted behind the
//! [`SeqStore`] trait so a host can inject a non-diesel persistence backend. The
//! diesel-backed implementation [`DbSeqStore`] is only compiled under the `db`
//! feature.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use arkret::http_client::{Auth, Client};
#[cfg(any(feature = "web", test))]
use arkret::signatures::{
    DidVerificationMethodResolver, EventProofBuilder, VerificationMethodDocument,
};
use arkret::signatures::{SignEventOptions, sign_event};
use arkret::{
    AppletId, Did, Ed25519MoveSigner, Event, EventId, Hlc, HlcGenerator, MoveSigner, RealmId,
};
#[cfg(any(feature = "web", test))]
use arkret::{DidDocumentVerificationMethodResolver, DidResolver, WireError};
use arkret_models_collaboration::event_sync::{
    EventsFrontierSelector, EventsFrontierView, RealmActorFrontierView,
};
use arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope;
use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
use arkret_models_discovery::ServiceDescribe;
use arkret_models_integration::AppletPackage;
#[cfg(any(feature = "web", test))]
use arkret_models_integration::{
    AppletActorView, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome,
};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
#[cfg(any(feature = "web", test))]
use serde_json::json;
use tokio::sync::mpsc::Sender;

#[cfg(any(feature = "web", test))]
use crate::app::AppletResolver;
use crate::config::Config;
use crate::error::{BridgeError, Result};
#[cfg(any(feature = "web", test))]
use crate::idempotency::{DedupVerdict, EventDedupStore};

/// Bound on the inbound (arkret → app) event queue. Past this depth the applet
/// handler stops accepting events and asks the server to retry (backpressure)
/// rather than buffering without limit. Sized so a healthy consumer drains it
/// well within the server's retry window; a persistently full queue means the
/// app side is wedged, in which case shedding load back to the server (which
/// will redeliver) is the correct behaviour.
pub const INBOUND_QUEUE_CAPACITY: usize = 1024;

/// Bound on the best-effort ephemeral queue. When full, new ephemeral envelopes
/// are dropped instead of back-pressuring durable transaction delivery.
pub const EPHEMERAL_QUEUE_CAPACITY: usize = 1024;

/// Hard bound for per-Realm HLC generator state retained by one bridge process.
const MAX_REALM_HLC_GENERATORS: usize = 4_096;

/// Retry hint (ms) returned to the server when the inbound queue is full, so it
/// re-pushes the unaccepted events after a short delay instead of dropping them.
const INBOUND_QUEUE_FULL_RETRY_MS: u64 = 1000;

/// How many actor sequence numbers to reserve in the store per refill. A larger
/// block means fewer store writes at the cost of skipping more numbers on each
/// restart (gaps are harmless; only monotonicity matters).
const SEQ_RESERVE_BLOCK: i64 = 256;
/// The default `bridge_state` row key under which the reserved actor-seq
/// high-water mark is persisted.
pub const SEQ_STATE_KEY: &str = "actor_seq_reserved";

/// Pluggable, restart-safe high-water-mark storage backing [`SeqAllocator`].
///
/// A host injects an implementation so the runtime can allocate strictly
/// monotonic actor sequence numbers without depending on diesel. The contract:
/// `reserve_block` atomically advances the persisted value for `key` by `block`
/// and returns the **new** value (the highest sequence number now reserved).
pub trait SeqStore: Send + Sync + 'static {
    fn reserve_block(&self, key: &str, block: i64) -> crate::error::Result<i64>;
}

/// Restart-safe monotonic allocator for the service actor's event sequence.
///
/// Numbers are reserved from the backing [`SeqStore`] in blocks: on each refill
/// the persisted high-water mark is advanced by [`SEQ_RESERVE_BLOCK`] and the
/// reserved range handed out from memory. A restart resumes strictly above the
/// last reserved block, so sequence numbers never regress (unused numbers in a
/// partially consumed block are skipped — gaps are acceptable).
#[derive(Clone)]
pub struct SeqAllocator {
    store: Arc<dyn SeqStore>,
    key: String,
    state: Arc<Mutex<SeqWindow>>,
}

#[derive(Default)]
struct SeqWindow {
    /// Next sequence number to hand out.
    next: i64,
    /// Exclusive upper bound of the currently reserved window.
    limit: i64,
}

impl SeqAllocator {
    /// Build an allocator over `store`, persisting its high-water mark under
    /// `key`. Infallible: no migration is performed here (the store owns its own
    /// initialization).
    pub fn new(store: Arc<dyn SeqStore>, key: impl Into<String>) -> Self {
        Self {
            store,
            key: key.into(),
            state: Arc::new(Mutex::new(SeqWindow::default())),
        }
    }

    /// Allocate the next sequence number, reserving a fresh block when the
    /// in-memory window is exhausted.
    pub fn alloc(&self) -> Result<u64> {
        let mut win = self.state.lock();
        if win.next >= win.limit {
            let reserved = self.store.reserve_block(&self.key, SEQ_RESERVE_BLOCK)?;
            win.next = reserved - SEQ_RESERVE_BLOCK + 1;
            win.limit = reserved + 1;
        }
        let seq = win.next;
        win.next += 1;
        Ok(seq as u64)
    }

    /// Async-path allocation that moves the synchronous backing-store refill
    /// onto Tokio's blocking pool. The hot path stays lock-only when the current
    /// reserved window still has numbers.
    pub async fn alloc_blocking(&self) -> Result<u64> {
        if let Some(seq) = self.try_alloc_from_window() {
            return Ok(seq);
        }

        let store = self.store.clone();
        let key = self.key.clone();
        let state = self.state.clone();
        crate::run_blocking(move || {
            let mut win = state.lock();
            if win.next >= win.limit {
                let reserved = store.reserve_block(&key, SEQ_RESERVE_BLOCK)?;
                win.next = reserved - SEQ_RESERVE_BLOCK + 1;
                win.limit = reserved + 1;
            }
            let seq = win.next;
            win.next += 1;
            Ok(seq as u64)
        })
        .await
    }

    fn try_alloc_from_window(&self) -> Option<u64> {
        let mut win = self.state.try_lock()?;
        if win.next >= win.limit {
            return None;
        }
        let seq = win.next;
        win.next += 1;
        Some(seq as u64)
    }
}

/// The arkret edge client.
pub struct ArkretEdge {
    config: Arc<Config>,
    client: Client,
    signer: Ed25519MoveSigner,
    service_id: Did,
    applet_id: AppletId,
    /// Store-backed, restart-safe actor sequence allocator.
    seq: SeqAllocator,
    /// Realm-scoped SDK HLC generators. The node id derives from
    /// `(realm_id, bridge_id, signing seed)`, so events from the same bridge are
    /// not linkable across realms by HLC node id.
    hlc_generators: Mutex<HashMap<String, HlcGenerator>>,
    hlc_device_id: String,
    hlc_secret: [u8; 32],
    /// Inbound event queue: arkret server push → core consumer loop. Bounded so
    /// a slow consumer applies backpressure (the handler returns `retry_after_ms`
    /// when full) instead of buffering without limit. `None` for outbound-only
    /// edges.
    inbound_tx: Option<Sender<Event>>,
    /// Inbound ephemeral queue (typing/presence/receipts/call-signal as the SDK
    /// [`EphemeralEnvelope`] wire type): arkret server push → core consumer loop.
    /// `None` for outbound-only edges.
    ephemeral_tx: Option<Sender<EphemeralEnvelope>>,
}

impl ArkretEdge {
    /// Build an inbound-capable edge: signs with the seed from
    /// [`Config::signing_seed`] and queues inbound events into `inbound_tx`.
    pub fn new(
        config: Arc<Config>,
        seq: Arc<dyn SeqStore>,
        inbound_tx: Sender<Event>,
    ) -> Result<Self> {
        let service_id = Did::new(config.arkret.service_id.clone())?;
        let seed = config.signing_seed()?;
        let signer = Ed25519MoveSigner::from_did_key_seed(
            seed,
            service_id.clone(),
            config.arkret.verification_method_id.clone(),
        );
        let client = default_client(&config)?;
        Self::build(
            config,
            client,
            signer,
            service_id,
            seed,
            SeqAllocator::new(seq, SEQ_STATE_KEY),
            Some(inbound_tx),
        )
    }

    /// Build an outbound-only edge from host-managed authenticated transport,
    /// signing material, and a reusable sequence allocator.
    ///
    /// This is the integration path for hosts that own authentication and key
    /// storage. No inbound queues are allocated, and rebuilding an edge can
    /// reuse the same allocator without discarding its current reservation.
    pub fn new_outbound(
        config: Arc<Config>,
        client: Client,
        signer: Ed25519MoveSigner,
        seq: SeqAllocator,
    ) -> Result<Self> {
        let service_id = Did::new(config.arkret.service_id.clone())?;
        let hlc_secret = signer.verifying_key().to_bytes();
        Self::build(config, client, signer, service_id, hlc_secret, seq, None)
    }

    fn build(
        config: Arc<Config>,
        client: Client,
        signer: Ed25519MoveSigner,
        service_id: Did,
        hlc_secret: [u8; 32],
        seq: SeqAllocator,
        inbound_tx: Option<Sender<Event>>,
    ) -> Result<Self> {
        let base = url::Url::parse(&config.arkret.server_url)
            .map_err(|e| BridgeError::Config(format!("server_url: {e}")))?;
        // Outbound transport policy (spec §7, sync/api-conventions §11.2): the
        // bridge actively connects out to this address, so require TLS. A plain
        // `http://` server_url would carry the bearer access token and signed
        // events in plaintext. Loopback over http is the one operator-controlled
        // dev exception. Fail closed otherwise.
        if base.scheme() != "https" && !host_is_loopback(base.host_str()) {
            return Err(BridgeError::Config(format!(
                "arkret.server_url must use https (got scheme `{}`); only loopback may use http",
                base.scheme()
            )));
        }
        // The default applet namespaces and ghost actor ids derive from the
        // service DID by appending a `:ghost:*` suffix (applet-integration §3.4).
        // Only `did:webvh` is accepted: the workspace-wide rule (and the §3.4
        // examples) mandate webvh-only service identities, so fail closed at
        // startup for any other method (including `did:web`) rather than later
        // minting a ghost DID under a non-verifiable-history identity.
        match service_id.method() {
            "webvh" => {}
            other => {
                return Err(BridgeError::Config(format!(
                    "service DID method `{other}` is not allowed; \
                     a bridge service DID must be did:webvh"
                )));
            }
        }

        let applet_id = AppletId::new(config.arkret.applet_id.clone())?;
        let hlc_device_id = config.bridge.bridge_id.clone();

        Ok(Self {
            config,
            client,
            signer,
            service_id,
            applet_id,
            seq,
            hlc_generators: Mutex::new(HashMap::new()),
            hlc_device_id,
            hlc_secret,
            inbound_tx,
            ephemeral_tx: None,
        })
    }

    /// Install the ephemeral (typing/presence/receipts) sender. Used by the
    /// `run_bridge` path which wires a parallel queue.
    pub fn set_ephemeral_sender(&mut self, tx: Sender<EphemeralEnvelope>) {
        self.ephemeral_tx = Some(tx);
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn service_id(&self) -> &Did {
        &self.service_id
    }

    /// The inbound event sender (bounded), if this edge was built with one.
    pub fn inbound_sender(&self) -> Option<Sender<Event>> {
        self.inbound_tx.clone()
    }

    /// The ephemeral sender, if installed.
    pub fn ephemeral_sender(&self) -> Option<Sender<EphemeralEnvelope>> {
        self.ephemeral_tx.clone()
    }

    /// Generate the next Realm-scoped HLC through the SDK implementation.
    pub fn next_hlc(&self, realm_id: &RealmId) -> Result<Hlc> {
        let mut generators = self.hlc_generators.lock();
        if !generators.contains_key(realm_id.as_str())
            && generators.len() >= MAX_REALM_HLC_GENERATORS
        {
            return Err(BridgeError::Runtime(format!(
                "realm HLC generator cache reached the {MAX_REALM_HLC_GENERATORS} realm limit"
            )));
        }
        let generator = generators
            .entry(realm_id.as_str().to_owned())
            .or_insert_with(|| {
                HlcGenerator::new(realm_id.as_str(), &self.hlc_device_id, &self.hlc_secret)
            });
        generator
            .try_generate()
            .map_err(|e| BridgeError::Arkret(e.to_string()))
    }

    /// Build an unsigned service-actor event for runtime hot paths. Any
    /// backing-store refill for actor sequence numbers runs on the blocking pool
    /// instead of a Tokio worker.
    pub async fn mint_event_unsigned_async<T>(
        &self,
        kind: &str,
        realm_id: &RealmId,
        content: T,
    ) -> Result<Event>
    where
        T: Serialize,
    {
        let content = spec_payload_value(content)?;
        self.build_service_event_async(kind, realm_id, content)
            .await
    }

    /// Build an unsigned event authored by the service actor (seq + HLC
    /// allocated, no proof). Applet-originated writes carry the top-level
    /// `applet_id` in the signed envelope.
    async fn build_service_event_async(
        &self,
        kind: &str,
        realm_id: &RealmId,
        content: Value,
    ) -> Result<Event> {
        let seq = self.seq.alloc_blocking().await?;
        let hlc = self.next_hlc(realm_id)?;
        let mut event = Event::new(
            kind,
            realm_id.clone(),
            self.service_id.clone(),
            seq,
            hlc,
            content,
        )?;
        event.applet_id = Some(self.applet_id.clone());
        Ok(event)
    }

    async fn build_delegated_event_async(
        &self,
        actor: &arkret::Did,
        kind: &str,
        realm_id: &RealmId,
        content: Value,
        authorization_ref: &str,
    ) -> Result<Event> {
        let authorization_ref = validate_authorization_ref(authorization_ref)?;
        let seq = self.seq.alloc_blocking().await?;
        let hlc = self.next_hlc(realm_id)?;
        let mut event = Event::new(kind, realm_id.clone(), actor.clone(), seq, hlc, content)?;
        event.executed_by = Some(self.service_id.clone());
        event.authorization_ref = Some(authorization_ref);
        event.applet_id = Some(self.applet_id.clone());
        Ok(event)
    }

    /// Build an unsigned delegated-actor event asynchronously.
    ///
    /// Hosts may mutate signed-envelope fields or replace plaintext content
    /// with encrypted content before calling [`Self::resign_event`] once and
    /// submitting the result.
    pub async fn mint_event_as_unsigned_async<T>(
        &self,
        actor: &Did,
        kind: &str,
        realm_id: &RealmId,
        content: T,
        authorization_ref: &str,
    ) -> Result<Event>
    where
        T: Serialize,
    {
        let content = spec_payload_value(content)?;
        self.build_delegated_event_async(actor, kind, realm_id, content, authorization_ref)
            .await
    }

    /// Sign `event` with the service key over the current canonical envelope.
    /// Used after all signed-envelope fields are in place so the event is signed
    /// exactly once.
    fn sign_as_service(&self, event: &mut Event) -> Result<()> {
        let verification_method = self.verification_method_for_actor(&self.service_id)?;
        sign_event(
            event,
            &self.signer,
            &verification_method,
            SignEventOptions::new(),
        )?;
        Ok(())
    }

    fn verification_method_for_actor(&self, actor: &Did) -> Result<String> {
        let (_, fragment) = self
            .config
            .arkret
            .verification_method_id
            .rsplit_once('#')
            .ok_or_else(|| {
                BridgeError::Config(
                    "verification_method_id must contain a #key fragment".to_owned(),
                )
            })?;
        if fragment.trim().is_empty() {
            return Err(BridgeError::Config(
                "verification_method_id key fragment must not be empty".to_owned(),
            ));
        }
        Ok(format!("{}#{fragment}", actor.as_str()))
    }

    /// Outbound: submit an already-minted event and return its event_id.
    /// Generic over event kind — carries no messaging assumptions.
    pub async fn submit_event(&self, event: &Event) -> Result<String> {
        let event_id = event.event_id.to_string();
        self.client.events_submit(event).await?;
        Ok(event_id)
    }

    /// Re-sign an already-minted event after signed-envelope mutation (e.g.
    /// setting `redacts`, overriding `created_at`, or adding `external_ref`).
    /// Clears the existing proofs and signs with the service key over the
    /// current canonical envelope.
    pub fn resign_event(&self, event: &mut Event) -> Result<()> {
        event.proofs.clear();
        self.sign_as_service(event)
    }

    /// Sign an already-canonicalized payload-proof transcript with the
    /// configured Applet service key.
    pub fn sign_detached_jws(&self, canonical_bytes: &[u8]) -> Result<String> {
        Ok(self.signer.sign_payload(canonical_bytes)?.jws)
    }

    /// Return the service-owned absolute verification method used by Event and
    /// payload proofs. Configs may use a fragment-only shorthand.
    pub fn service_verification_method(&self) -> Result<String> {
        self.verification_method_for_actor(&self.service_id)
    }

    /// Fetch the exact Realm-scoped authoring frontier for an existing actor.
    pub async fn realm_actor_frontier(
        &self,
        realm_id: &RealmId,
        actor_id: &Did,
    ) -> Result<Option<RealmActorFrontierView>> {
        let state = match self
            .client
            .events_frontier(&EventsFrontierSelector::RealmActor {
                realm_id: realm_id.clone(),
                actor_id: actor_id.clone(),
            })
            .await
        {
            Ok(state) => state,
            Err(arkret::http_client::Error::Api { status: 404, .. }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        match state.frontier {
            EventsFrontierView::RealmActor(frontier) => Ok(Some(frontier)),
            _ => Err(BridgeError::Arkret(
                "events frontier returned the wrong variant".to_owned(),
            )),
        }
    }

    /// Allocate the next Realm-scoped HLC for a caller-built Event.
    pub fn next_event_hlc(&self, realm_id: &RealmId) -> Result<Hlc> {
        self.next_hlc(realm_id)
    }

    /// Outbound convenience with bridge provenance and an explicit delegated
    /// actor. Used by messaging bridges to submit per-user Ghost Actor events
    /// after provisioning returned a durable authorization ref.
    ///
    /// applet-integration §8 requires the signed Event Envelope top-level
    /// `external_ref` for bridge-originated events.
    pub async fn submit_with_external_ref_as<T, E>(
        &self,
        actor: &Did,
        realm_id: &str,
        kind: &str,
        content: T,
        external_ref: E,
        authorization_ref: &str,
    ) -> Result<String>
    where
        T: Serialize,
        E: Serialize,
    {
        let realm = RealmId::new(realm_id.to_owned())?;
        let content = spec_payload_value(content)?;
        let external_ref = spec_external_ref_map(external_ref)?;
        // Set the signed-envelope `external_ref` before the single signature so
        // the proof covers it (no discarded first sign).
        let mut event = self
            .build_delegated_event_async(actor, kind, &realm, content, authorization_ref)
            .await?;
        event.external_ref = Some(external_ref);
        self.sign_as_service(&mut event)?;
        self.submit_event(&event).await
    }

    /// Submit a message redaction attributed to a delegated app actor while
    /// setting the signed envelope `redacts` target. External app expiry or
    /// retention drops must be filtered by callers before reaching this helper.
    pub async fn submit_redaction_with_external_ref_as<T, E>(
        &self,
        actor: &Did,
        realm_id: &str,
        target_event_id: &str,
        content: T,
        external_ref: E,
        authorization_ref: &str,
    ) -> Result<String>
    where
        T: Serialize,
        E: Serialize,
    {
        let realm = RealmId::new(realm_id.to_owned())?;
        let content = spec_payload_value(content)?;
        let external_ref = spec_external_ref_map(external_ref)?;
        // Set `redacts` + `external_ref` before the single signature so the proof
        // covers them (no discarded first sign).
        let mut event = self
            .build_delegated_event_async(
                actor,
                "ak.message.redact",
                &realm,
                content,
                authorization_ref,
            )
            .await?;
        event.redacts = Some(EventId::new(target_event_id.to_owned())?);
        event.external_ref = Some(external_ref);
        self.sign_as_service(&mut event)?;
        self.submit_event(&event).await
    }

    /// Emit a `ak.applet.bridge_error` Event so a bridging failure is durable
    /// and auditable rather than silently dropped (applet-integration §14/§16;
    /// Event Draft [`arkret_event_draft::AppletBridgeErrorBuilder`]). The builder is filled with
    /// all required bindings (realm/failed_transaction_ref/retriable/visibility) by
    /// the caller; this allocates the actor seq + HLC, signs with the service
    /// key, and submits. Returns the new event_id.
    pub async fn submit_bridge_error(
        &self,
        realm_id: &RealmId,
        builder: arkret_event_draft::AppletBridgeErrorBuilder,
    ) -> Result<String> {
        let seq = self.seq.alloc_blocking().await?;
        let hlc = self.next_hlc(realm_id)?;
        let mut event = builder.build(seq, hlc)?;
        // applet-integration §8: the signed envelope of every Applet-originated
        // write Event MUST carry the top-level `applet_id`; the builder only
        // binds it inside the content, so stamp it before the single signature.
        event.applet_id = Some(self.applet_id.clone());
        // The builder produced an unsigned event; sign it with the service key
        // over the current canonical envelope.
        self.resign_event(&mut event)?;
        self.submit_event(&event).await
    }

    /// The configured applet id this bridge presents to arkret.
    pub fn applet_id(&self) -> &str {
        self.applet_id.as_str()
    }

    /// Media upload: returns the blob reference string.
    pub async fn upload_blob(&self, bytes: &[u8], mime: &str) -> Result<String> {
        let meta = arkret_models_collaboration::objects::blob::BlobUploadMetadata {
            realm_id: None,
            content_digest: None,
            size_bytes: bytes.len() as u64,
            media_type: Some(mime.to_owned()),
            filename: None,
            purpose: None,
        };
        let res = self.client.blob_upload_bytes(&meta, bytes.to_vec()).await?;
        Ok(res.blob_ref.to_string())
    }

    /// Media download.
    pub async fn download_blob(&self, blob_ref: &str) -> Result<Vec<u8>> {
        let r = arkret::BlobRef::new(blob_ref.to_owned())?;
        Ok(self.client.blob_download(&r, None).await?)
    }
}

fn validate_authorization_ref(authorization_ref: &str) -> Result<String> {
    let authorization_ref = authorization_ref.trim();
    if authorization_ref.is_empty() {
        return Err(BridgeError::Arkret(
            "delegated actor events require authorization_ref".to_owned(),
        ));
    }
    Ok(authorization_ref.to_owned())
}

fn default_client(config: &Config) -> Result<Client> {
    let base = url::Url::parse(&config.arkret.server_url)
        .map_err(|e| BridgeError::Config(format!("server_url: {e}")))?;
    Client::builder(base)
        .auth(Auth::Bearer(config.arkret.access_token.clone()))
        .build()
        .map_err(Into::into)
}

fn spec_payload_value<T>(content: T) -> Result<Value>
where
    T: Serialize,
{
    serde_json::to_value(content).map_err(|error| {
        BridgeError::Arkret(format!("event payload serialization failed: {error}"))
    })
}

fn spec_external_ref_map<T>(external_ref: T) -> Result<BTreeMap<String, Value>>
where
    T: Serialize,
{
    let value = serde_json::to_value(external_ref).map_err(|error| {
        BridgeError::Arkret(format!("event external_ref serialization failed: {error}"))
    })?;
    match value {
        Value::Object(map) => Ok(map.into_iter().collect()),
        _ => Err(BridgeError::Arkret(
            "event external_ref must serialize as an object".to_owned(),
        )),
    }
}

/// Diesel-backed [`SeqStore`]. Persists each key's high-water mark in a
/// runtime-owned `bridge_state` table. Only compiled under the `db` feature.
#[cfg(feature = "db")]
pub struct DbSeqStore {
    db: Arc<crate::db::DatabaseManager>,
}

/// Runtime-owned key/value state table (generic; not messaging-specific).
#[cfg(feature = "db")]
mod state_schema {
    diesel::table! {
        bridge_state (state_key) {
            state_key -> Text,
            state_value -> BigInt,
        }
    }
}

#[cfg(feature = "db")]
impl DbSeqStore {
    /// Build the store, running the embedded runtime migrations (which include
    /// the `bridge_state` table; already-applied migrations are skipped).
    pub fn new(db: Arc<crate::db::DatabaseManager>) -> Result<Self> {
        db.run_migrations(crate::db::MIGRATIONS)?;
        Ok(Self { db })
    }
}

#[cfg(feature = "db")]
impl SeqStore for DbSeqStore {
    /// Advance the persisted high-water mark for `key` by `block` and return the
    /// new value (the highest sequence number now reserved).
    fn reserve_block(&self, key: &str, block: i64) -> Result<i64> {
        use diesel::prelude::*;
        use state_schema::bridge_state::dsl;

        let mut conn = self.db.conn()?;
        let current: i64 = dsl::bridge_state
            .filter(dsl::state_key.eq(key))
            .select(dsl::state_value)
            .first::<i64>(&mut conn)
            .optional()?
            .unwrap_or(0);
        let reserved = current + block;

        let updated = diesel::update(dsl::bridge_state.filter(dsl::state_key.eq(key)))
            .set(dsl::state_value.eq(reserved))
            .execute(&mut conn)?;
        if updated == 0 {
            diesel::insert_into(dsl::bridge_state)
                .values((dsl::state_key.eq(key), dsl::state_value.eq(reserved)))
                .execute(&mut conn)?;
        }
        Ok(reserved)
    }
}

#[cfg(any(feature = "web", test))]
/// Stable 64-bit FNV-1a fingerprint over an event's signed canonical envelope,
/// bit-cast to `i64` for storage. Used only for same-id content-equality
/// comparison in an [`EventDedupStore`]; not a security primitive (a mismatch
/// only ever leads to a safe rejection).
fn event_content_fingerprint(event: &Event) -> i64 {
    let canonical = EventProofBuilder::new()
        .envelope_bytes(event)
        .unwrap_or_default();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in canonical {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash as i64
}

#[cfg(any(feature = "web", test))]
/// The receiver for transactions pushed by the arkret server (implements
/// [`arkret::AppletHandler`]). It delivers the events in a transaction to the
/// inbound queue; the business forwarding is done in the core consumer loop.
pub struct BridgeAppletHandler {
    applet_id: String,
    service_id: Did,
    trust_domain: arkret::TypedTrustDomainId,
    namespaces: Value,
    inbound_tx: Sender<Event>,
    ephemeral_tx: Option<Sender<EphemeralEnvelope>>,
    resolver: Option<Arc<dyn AppletResolver>>,
    /// Event kinds this bridge consumes on the inbound path. `None` ⇒ permissive
    /// (accept all). When `Some`, a pushed event whose kind is not listed is
    /// rejected as `capability_denied` (applet-integration §7/§13).
    handled_event_kinds: Option<Vec<String>>,
    /// Durable single-event-level dedup store (applet-integration §7.3; the
    /// runtime path injects [`crate::db::DbEventDedupStore`]).
    dedup: Arc<dyn EventDedupStore>,
    /// Trust-root DID resolver the SDK applet router uses to authenticate the
    /// source service DID's HTTP message signature and every pushed Event proof
    /// on the inbound `POST /_arkret/edge/applet/transactions` path
    /// (applet-integration §7.3). Scoped to the methods this bridge accepts for
    /// inbound pushes (did:key / did:webvh, fail-closed).
    source_did_resolver: Arc<dyn DidResolver + Send + Sync>,
}

#[cfg(any(feature = "web", test))]
fn default_applet_namespaces(bridge_id: &str, service_id: &Did) -> Value {
    let service_id = service_id.as_str();
    json!({
        "actors": [{
            "exclusive": true,
            "pattern": format!("{service_id}:ghost:*"),
        }],
        "realms": [{
            "exclusive": true,
            "pattern": format!("{bridge_id}:*"),
        }],
        "handles": [{
            "exclusive": true,
            "pattern": format!("{bridge_id}/*"),
        }],
    })
}

#[cfg(any(feature = "web", test))]
impl BridgeAppletHandler {
    /// Build the handler from an inbound-capable edge. The edge must have been
    /// constructed with an inbound sender (the run_bridge/web path always is).
    /// `dedup` is the durable event-dedup store enforcing §7.3.
    pub fn new(
        edge: &ArkretEdge,
        resolver: Option<Arc<dyn AppletResolver>>,
        dedup: Arc<dyn EventDedupStore>,
        handled_event_kinds: Option<Vec<String>>,
        source_did_resolver: Arc<dyn DidResolver + Send + Sync>,
    ) -> Result<Self> {
        let bridge_id = edge.config.bridge.bridge_id.clone();
        let service_id = edge.service_id.clone();
        Ok(Self {
            applet_id: edge.config.arkret.applet_id.clone(),
            service_id: service_id.clone(),
            trust_domain: edge.config.arkret.trust_domain.clone(),
            namespaces: edge
                .config
                .arkret
                .applet_namespaces
                .clone()
                .unwrap_or_else(|| default_applet_namespaces(&bridge_id, &service_id)),
            inbound_tx: edge.inbound_sender().ok_or_else(|| {
                BridgeError::Config("applet handler requires an inbound-enabled edge".into())
            })?,
            ephemeral_tx: edge.ephemeral_sender(),
            resolver,
            dedup,
            handled_event_kinds,
            source_did_resolver,
        })
    }

    /// Whether this applet consumes `kind` on the inbound path. Permissive when
    /// no kind set was declared (a generic bridge that did not constrain kinds).
    fn handles_event_kind(&self, kind: &str) -> bool {
        match &self.handled_event_kinds {
            Some(kinds) => kinds.iter().any(|k| k == kind),
            None => true,
        }
    }

    /// Whether `realm_id` falls inside one of the realm namespace patterns this
    /// applet declared in `describe` (applet-integration §7/§13 namespace
    /// matching). Patterns use the spec's `*` suffix-glob form (e.g.
    /// `{bridge_id}:*`). When no realm patterns are declared the check is
    /// permissive (cannot constrain what was never declared).
    fn realm_in_namespace(&self, realm_id: &str) -> bool {
        let patterns = self
            .namespaces
            .get("realms")
            .and_then(Value::as_array)
            .map(|realms| {
                realms
                    .iter()
                    .filter_map(|entry| entry.get("pattern").and_then(Value::as_str))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if patterns.is_empty() {
            return true;
        }
        patterns
            .iter()
            .any(|pattern| glob_suffix_match(pattern, realm_id))
    }
}

/// Whether a URL host is a loopback address (the only operator-controlled
/// exception to the https requirement on `arkret.server_url`, for local dev).
fn host_is_loopback(host: Option<&str>) -> bool {
    match host {
        Some(host) => {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false)
        }
        None => false,
    }
}

/// Match a spec namespace pattern against a candidate id. Supports a trailing
/// `*` wildcard (prefix match) and exact equality otherwise; an interior `*` is
/// treated literally (the spec only uses trailing globs for namespaces).
fn glob_suffix_match(pattern: &str, candidate: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => candidate.starts_with(prefix),
        None => pattern == candidate,
    }
}

#[cfg(any(feature = "web", test))]
impl arkret::AppletHandler for BridgeAppletHandler {
    fn resolve_verification_method(
        &self,
        verification_method: &str,
    ) -> std::result::Result<VerificationMethodDocument, WireError> {
        DidDocumentVerificationMethodResolver::new(self.source_did_resolver.as_ref())
            .resolve_verification_method(verification_method)
            .map_err(|error| WireError::Protocol(error.to_string()))
    }

    fn ping(&self) -> std::result::Result<AppletPingOutcome, WireError> {
        Ok(AppletPingOutcome {
            ok: true,
            applet_id: self.applet_id.clone(),
            service_id: self.service_id.clone(),
            protocol_version: arkret::PROTOCOL_VERSION.to_owned(),
        })
    }

    fn describe(&self) -> std::result::Result<ServiceDescribe, WireError> {
        let mut description = ServiceDescribe::development(
            self.service_id.clone(),
            self.trust_domain.clone(),
            arkret::ServiceType::AppletService,
        );
        description.supported_profiles = vec![AppletPackage::BASE_PROFILE.to_owned()];
        description.supported_operations = vec![
            arkret::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION.to_owned(),
            arkret::ServiceOperationId::EDGE_APPLET_QUERY_DESCRIBE.to_owned(),
            arkret::ServiceOperationId::EDGE_APPLET_QUERY_PING.to_owned(),
            arkret::ServiceOperationId::EDGE_APPLET_ACTOR_QUERY_RESOLVE.to_owned(),
            arkret::ServiceOperationId::EDGE_APPLET_REALM_QUERY_RESOLVE.to_owned(),
            arkret::ServiceOperationId::EDGE_APPLET_QUERY_PROTOCOL_METADATA.to_owned(),
        ];
        description.validate()?;
        Ok(description)
    }

    fn handle_transaction(
        &self,
        _idempotency_key: &str,
        req: AppletTransactionRequestBody,
    ) -> std::result::Result<AppletTransactionOutcome, WireError> {
        let mut rejected: Vec<arkret::RejectedItem> = Vec::new();
        let mut enqueue_failed = false;
        // Set when the bounded inbound queue is full: we ask the server to retry
        // the whole batch shortly (backpressure) rather than buffering without
        // limit or dropping events.
        let mut queue_full = false;

        for event in req.events {
            let event_id = event.event_id.to_string();

            // Backpressure (BRG-02-001): once the bounded inbound queue is full we
            // stop accepting the remainder of this batch and ask the server to
            // redeliver, instead of growing memory without bound. Events skipped
            // here were never dedup-recorded, so the redelivery is clean.
            if queue_full {
                rejected.push(arkret::RejectedItem {
                    event_id: Some(event.event_id.clone()),
                    reason_code: "queue_full".to_owned(),
                    retry_after_ms: None,
                });
                continue;
            }

            // Namespace enforcement (applet-integration §7 / §13): the pushed
            // event's realm MUST fall inside the realm namespace this applet
            // declared in `describe`. A trusted-channel event for a realm outside
            // our namespace is rejected before it can be forwarded to the app.
            if !self.realm_in_namespace(event.realm_id.as_ref()) {
                tracing::warn!(
                    %event_id,
                    realm = %event.realm_id,
                    "rejecting event: realm is outside this applet's declared namespace"
                );
                rejected.push(arkret::RejectedItem {
                    event_id: Some(event.event_id.clone()),
                    reason_code: "applet_namespace_mismatch".to_owned(),
                    retry_after_ms: None,
                });
                continue;
            }

            // Capability enforcement (applet-integration §7 / §13; BRG-01-009):
            // reject event kinds this bridge did not declare it handles, so an
            // unsupported kind is surfaced to the server rather than forwarded
            // and silently ignored by the adapter. Permissive when no kind set
            // was declared (generic bridges).
            if !self.handles_event_kind(event.kind.as_str()) {
                tracing::warn!(
                    %event_id,
                    kind = %event.kind,
                    "rejecting event: kind is not in this applet's declared capability set"
                );
                rejected.push(arkret::RejectedItem {
                    event_id: Some(event.event_id.clone()),
                    reason_code: "capability_denied".to_owned(),
                    retry_after_ms: None,
                });
                continue;
            }

            // Reserve a slot in the bounded queue BEFORE recording dedup, so an
            // event that cannot be enqueued is never marked as seen (otherwise a
            // server redelivery would be silently dropped as a duplicate). A full
            // queue switches the rest of the batch to the backpressure path; a
            // closed receiver means the consumer is gone (internal error).
            let permit = match self.inbound_tx.try_reserve() {
                Ok(permit) => permit,
                Err(tokio::sync::mpsc::error::TrySendError::Full(())) => {
                    queue_full = true;
                    rejected.push(arkret::RejectedItem {
                        event_id: Some(event.event_id.clone()),
                        reason_code: "queue_full".to_owned(),
                        retry_after_ms: None,
                    });
                    continue;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
                    enqueue_failed = true;
                    tracing::error!(%event_id, "failed to enqueue inbound event: consumer gone");
                    rejected.push(arkret::RejectedItem {
                        event_id: Some(event.event_id.clone()),
                        reason_code: "internal_error".to_owned(),
                        retry_after_ms: None,
                    });
                    continue;
                }
            };

            // Single-event-level dedup (§7.3): identical re-push is accepted
            // without re-forwarding; a conflicting body under the same id is
            // rejected. The store is durable, so the rule holds across
            // restarts. A store failure must not silently double-deliver:
            // signal a retry instead. The reserved permit is released (dropped)
            // on every non-Fresh path, returning the queue slot.
            match self
                .dedup
                .check_and_record(&event_id, event_content_fingerprint(&event))
            {
                Ok(DedupVerdict::Fresh) => {
                    // Enqueue for the core consumer loop via the reserved permit.
                    permit.send(event);
                }
                Ok(DedupVerdict::DuplicateSameContent) => {
                    // Already processed with identical content — accept silently,
                    // do not fan out again.
                    continue;
                }
                Ok(DedupVerdict::DuplicateConflict) => {
                    tracing::warn!(
                        %event_id,
                        "rejecting event: same event_id pushed with conflicting content"
                    );
                    rejected.push(arkret::RejectedItem {
                        event_id: Some(event.event_id.clone()),
                        reason_code: "duplicate_conflict".to_owned(),
                        retry_after_ms: None,
                    });
                    continue;
                }
                Err(err) => {
                    enqueue_failed = true;
                    tracing::error!(%event_id, error = %err, "event dedup store failed");
                    rejected.push(arkret::RejectedItem {
                        event_id: Some(event.event_id.clone()),
                        reason_code: "internal_error".to_owned(),
                        retry_after_ms: None,
                    });
                    continue;
                }
            }
        }

        // Forward SDK-typed ephemeral envelopes one at a time. Ephemeral loss
        // is non-fatal (best-effort) and does not affect the durable ack.
        if let (Some(tx), Some(envelopes)) = (self.ephemeral_tx.as_ref(), req.ephemeral) {
            for envelope in envelopes {
                if let Err(err) = envelope.validate() {
                    tracing::warn!(
                        error = %err,
                        "dropping invalid ephemeral envelope"
                    );
                    continue;
                }
                if let Err(err) = tx.try_send(envelope) {
                    tracing::warn!(
                        error = %err,
                        "dropping ephemeral envelope because the best-effort queue is full or closed"
                    );
                }
            }
        }

        // `ok` reflects whether every durable event was accepted (either freshly
        // enqueued or de-duplicated). When enqueueing failed or the queue is full
        // (backpressure), signal a retry so the server re-pushes the unaccepted
        // events rather than dropping the batch.
        let retry_after_ms = (enqueue_failed || queue_full).then_some(INBOUND_QUEUE_FULL_RETRY_MS);
        Ok(AppletTransactionOutcome {
            ok: rejected.is_empty(),
            rejected,
            retry_after_ms,
        })
    }

    fn resolve_actor(&self, actor_id: &str) -> std::result::Result<AppletActorView, WireError> {
        if let Some(resolved) = self
            .resolver
            .as_ref()
            .and_then(|r| r.resolve_actor(actor_id))
            && let Ok(did) = Did::new(resolved.actor_id)
        {
            return Ok(AppletActorView {
                exists: true,
                actor_id: Some(did),
                display_name: resolved.display_name,
                external_ref: resolved.external_ref,
            });
        }
        Ok(AppletActorView {
            exists: false,
            actor_id: None,
            display_name: None,
            external_ref: None,
        })
    }

    fn resolve_realm(
        &self,
        realm_id_or_alias: &str,
    ) -> std::result::Result<AppletRealmView, WireError> {
        if let Some(resolved) = self
            .resolver
            .as_ref()
            .and_then(|r| r.resolve_realm(realm_id_or_alias))
            && let Ok(realm) = RealmId::new(resolved.realm_id)
        {
            return Ok(AppletRealmView {
                exists: true,
                realm_id: Some(realm),
                title: resolved.title,
                external_ref: resolved.external_ref,
            });
        }
        Ok(AppletRealmView {
            exists: false,
            realm_id: None,
            title: None,
            external_ref: None,
        })
    }

    fn resolve_protocol(
        &self,
        protocol: &str,
    ) -> std::result::Result<AppletProtocolMetadata, WireError> {
        Ok(AppletProtocolMetadata {
            protocol: protocol.to_owned(),
            display_name: protocol.to_owned(),
            icon_blob_ref: None,
            field_types: Default::default(),
            instances: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// An in-memory [`SeqStore`] for tests: maps key -> reserved high-water mark.
    #[derive(Default)]
    struct MemSeqStore {
        inner: Mutex<HashMap<String, i64>>,
    }

    impl SeqStore for MemSeqStore {
        fn reserve_block(&self, key: &str, block: i64) -> Result<i64> {
            let mut guard = self.inner.lock();
            let current = guard.get(key).copied().unwrap_or(0);
            let reserved = current + block;
            guard.insert(key.to_owned(), reserved);
            Ok(reserved)
        }
    }

    #[test]
    fn alloc_is_monotonic() {
        let store: Arc<dyn SeqStore> = Arc::new(MemSeqStore::default());
        let alloc = SeqAllocator::new(store, "k");
        let mut prev = None;
        for _ in 0..1000 {
            let n = alloc.alloc().unwrap();
            if let Some(p) = prev {
                assert!(n > p, "expected {n} > {p}");
            }
            prev = Some(n);
        }
    }

    #[test]
    fn alloc_crosses_block_boundaries() {
        let store: Arc<dyn SeqStore> = Arc::new(MemSeqStore::default());
        let alloc = SeqAllocator::new(store, "k");
        // SEQ_RESERVE_BLOCK numbers come from the first reserved block; the next
        // alloc must trigger a fresh block and still be strictly greater.
        let first_block: Vec<u64> = (0..SEQ_RESERVE_BLOCK)
            .map(|_| alloc.alloc().unwrap())
            .collect();
        let next = alloc.alloc().unwrap();
        assert_eq!(*first_block.first().unwrap(), 1);
        assert_eq!(*first_block.last().unwrap(), SEQ_RESERVE_BLOCK as u64);
        assert_eq!(next, SEQ_RESERVE_BLOCK as u64 + 1);
        // Confirm contiguity within the first block.
        for (i, n) in first_block.iter().enumerate() {
            assert_eq!(*n, (i as u64) + 1);
        }
    }

    #[test]
    fn cloned_allocator_shares_the_current_window() {
        let store: Arc<dyn SeqStore> = Arc::new(MemSeqStore::default());
        let first = SeqAllocator::new(store, "k");
        let second = first.clone();
        assert_eq!(first.alloc().unwrap(), 1);
        assert_eq!(second.alloc().unwrap(), 2);
        assert_eq!(first.alloc().unwrap(), 3);
    }

    #[test]
    fn event_fingerprint_ignores_unsigned_and_proofs() {
        let realm = RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d").unwrap();
        let actor = Did::new("did:webvh:alice.example").unwrap();
        let hlc = Hlc::new("01970e589d21-0001-a13f9c2e").unwrap();
        let mut first = Event::new(
            "ak.message.create",
            realm,
            actor,
            1,
            hlc,
            json!({ "body": "hello" }),
        )
        .unwrap();
        let mut second = first.clone();

        first
            .unsigned
            .insert("delivery".to_owned(), json!({ "attempt": 1 }));
        second
            .unsigned
            .insert("delivery".to_owned(), json!({ "attempt": 2 }));
        first.proofs.push(test_proof("header.payload.signature-a"));
        second.proofs.push(test_proof("header.payload.signature-b"));

        assert_eq!(
            event_content_fingerprint(&first),
            event_content_fingerprint(&second)
        );

        second.payload = BTreeMap::from([("body".to_owned(), json!("changed"))]);
        assert_ne!(
            event_content_fingerprint(&first),
            event_content_fingerprint(&second)
        );
    }

    fn test_proof(jws: &str) -> arkret::Proof {
        arkret::Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:alice.example#key-1".to_owned(),
            event_digest: arkret::Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: jws.to_owned(),
        }
    }

    #[test]
    fn fresh_allocator_resumes_above_high_water_mark() {
        let store: Arc<dyn SeqStore> = Arc::new(MemSeqStore::default());

        // First allocator hands out a few numbers (consuming part of one block).
        let last_handed_out;
        {
            let a1 = SeqAllocator::new(store.clone(), "k");
            let mut last = 0;
            for _ in 0..5 {
                last = a1.alloc().unwrap();
            }
            last_handed_out = last;
        }

        // A fresh allocator over the SAME store must resume strictly above the
        // prior reserved high-water mark (no regression). Since the first
        // allocator reserved a full block of SEQ_RESERVE_BLOCK, the resumed
        // value starts at SEQ_RESERVE_BLOCK + 1.
        let a2 = SeqAllocator::new(store, "k");
        let resumed = a2.alloc().unwrap();
        assert!(
            resumed > last_handed_out,
            "expected resumed {resumed} > last {last_handed_out}"
        );
        assert_eq!(resumed, SEQ_RESERVE_BLOCK as u64 + 1);
    }
}
