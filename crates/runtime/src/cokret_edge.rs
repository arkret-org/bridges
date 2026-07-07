//! The cokret protocol-side edge (replaces the Matrix bridge's
//! `MatrixAppservice`).
//!
//! - **Outbound (app -> cokret)**: [`CokretEdge::mint_event`] / [`CokretEdge::submit`] build and
//!   sign an `Event` and submit it via [`cokret::http_client::Client::events_submit`].
//! - **Inbound (cokret → app)**: transactions pushed by the cokret server via the applet HTTP
//!   endpoints are placed into the `inbound_tx` queue by [`BridgeAppletHandler`]; after the core
//!   consumes them they are forwarded to the app adapter.
//! - **Media**: [`CokretEdge::upload_blob`] / [`CokretEdge::download_blob`].
//!
//! The restart-safe monotonic actor-sequence allocator is abstracted behind the
//! [`SeqStore`] trait so a host can inject a non-diesel persistence backend. The
//! diesel-backed implementation [`DbSeqStore`] is only compiled under the `db`
//! feature.

use std::collections::HashMap;
use std::sync::Arc;

#[cfg(any(feature = "web", test))]
use cokret::DidResolver;
use cokret::http_client::{Auth, Client};
use cokret::models::EphemeralEnvelope;
#[cfg(any(feature = "web", test))]
use cokret::models::{
    AppletActorView, AppletDescription, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome, AppletTransactionRequestBody,
};
#[cfg(any(feature = "web", test))]
use cokret::signatures::EventProofBuilder;
use cokret::signatures::{SignEventOptions, sign_event};
use cokret::{AppletId, Did, Ed25519MoveSigner, Event, EventId, Hlc, HlcGenerator, RealmId};
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

/// Bound on the inbound (cokret → app) event queue. Past this depth the applet
/// handler stops accepting events and asks the server to retry (backpressure)
/// rather than buffering without limit. Sized so a healthy consumer drains it
/// well within the server's retry window; a persistently full queue means the
/// app side is wedged, in which case shedding load back to the server (which
/// will redeliver) is the correct behaviour.
pub const INBOUND_QUEUE_CAPACITY: usize = 1024;

/// Bound on the best-effort ephemeral queue. When full, new ephemeral envelopes
/// are dropped instead of back-pressuring durable transaction delivery.
pub const EPHEMERAL_QUEUE_CAPACITY: usize = 1024;

/// Retry hint (ms) returned to the server when the inbound queue is full, so it
/// re-pushes the unaccepted events after a short delay instead of dropping them.
const INBOUND_QUEUE_FULL_RETRY_MS: u64 = 1000;

#[cfg(any(feature = "web", test))]
fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

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
pub struct SeqAllocator {
    store: Arc<dyn SeqStore>,
    key: String,
    state: Mutex<SeqWindow>,
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
            state: Mutex::new(SeqWindow::default()),
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
}

/// The cokret edge client.
pub struct CokretEdge {
    config: Arc<Config>,
    client: Client,
    signer: Ed25519MoveSigner,
    service_did: Did,
    applet_id: AppletId,
    /// Store-backed, restart-safe actor sequence allocator.
    seq: SeqAllocator,
    /// Realm-scoped SDK HLC generators. The node id derives from
    /// `(realm_id, bridge_id, signing seed)`, so events from the same bridge are
    /// not linkable across realms by HLC node id.
    hlc_generators: Mutex<HashMap<String, HlcGenerator>>,
    hlc_device_id: String,
    hlc_secret: [u8; 32],
    /// Inbound event queue: cokret server push → core consumer loop. Bounded so
    /// a slow consumer applies backpressure (the handler returns `retry_after_ms`
    /// when full) instead of buffering without limit. `None` for outbound-only
    /// edges.
    inbound_tx: Option<Sender<Event>>,
    /// Inbound ephemeral queue (typing/presence/receipts/call-signal as the SDK
    /// [`EphemeralEnvelope`] wire type): cokret server push → core consumer loop.
    /// `None` for outbound-only edges.
    ephemeral_tx: Option<Sender<EphemeralEnvelope>>,
}

impl CokretEdge {
    /// Build an inbound-capable edge: signs with the seed from
    /// [`Config::signing_seed`] and queues inbound events into `inbound_tx`.
    pub fn new(
        config: Arc<Config>,
        seq: Arc<dyn SeqStore>,
        inbound_tx: Sender<Event>,
    ) -> Result<Self> {
        let service_did = Did::new(config.cokret.service_did.clone())?;
        let seed = config.signing_seed()?;
        let signer = Ed25519MoveSigner::from_did_key_seed(
            seed,
            service_did.clone(),
            config.cokret.verification_method_id.clone(),
        );
        Self::build(config, seq, signer, service_did, seed, Some(inbound_tx))
    }

    fn build(
        config: Arc<Config>,
        seq: Arc<dyn SeqStore>,
        signer: Ed25519MoveSigner,
        service_did: Did,
        hlc_secret: [u8; 32],
        inbound_tx: Option<Sender<Event>>,
    ) -> Result<Self> {
        let base = url::Url::parse(&config.cokret.server_url)
            .map_err(|e| BridgeError::Config(format!("server_url: {e}")))?;
        // Outbound transport policy (spec §7, sync/api-conventions §11.2): the
        // bridge actively connects out to this address, so require TLS. A plain
        // `http://` server_url would carry the bearer access token and signed
        // events in cleartext. Loopback over http is the one operator-controlled
        // dev exception. Fail closed otherwise.
        if base.scheme() != "https" && !host_is_loopback(base.host_str()) {
            return Err(BridgeError::Config(format!(
                "cokret.server_url must use https (got scheme `{}`); only loopback may use http",
                base.scheme()
            )));
        }
        let client = Client::builder(base)
            .auth(Auth::Bearer(config.cokret.access_token.clone()))
            .build()?;

        // The default applet namespaces and ghost actor ids derive from the
        // service DID by appending a `:ghost:*` suffix (applet-integration §3.4).
        // Only `did:webvh` is accepted: the workspace-wide rule (and the §3.4
        // examples) mandate webvh-only service identities, so fail closed at
        // startup for any other method (including `did:web`) rather than later
        // minting a ghost DID under a non-verifiable-history identity.
        match service_did.method() {
            "webvh" => {}
            other => {
                return Err(BridgeError::Config(format!(
                    "service DID method `{other}` is not allowed; \
                     a bridge service DID must be did:webvh"
                )));
            }
        }

        let applet_id = AppletId::new(config.cokret.applet_id.clone())?;
        let hlc_device_id = config.bridge.bridge_id.clone();

        let seq = SeqAllocator::new(seq, SEQ_STATE_KEY);

        Ok(Self {
            config,
            client,
            signer,
            service_did,
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

    pub fn service_did(&self) -> &Did {
        &self.service_did
    }

    /// The inbound event sender (bounded), if this edge was built with one.
    pub fn inbound_sender(&self) -> Option<Sender<Event>> {
        self.inbound_tx.clone()
    }

    /// The ephemeral sender, if installed.
    pub fn ephemeral_sender(&self) -> Option<Sender<EphemeralEnvelope>> {
        self.ephemeral_tx.clone()
    }

    /// Allocate the next monotonic actor sequence number.
    pub fn alloc_seq(&self) -> Result<u64> {
        self.seq.alloc()
    }

    /// Generate the next Realm-scoped HLC through the SDK implementation.
    pub fn next_hlc(&self, realm_id: &RealmId) -> Result<Hlc> {
        let mut generators = self.hlc_generators.lock();
        let generator = generators
            .entry(realm_id.as_str().to_owned())
            .or_insert_with(|| {
                HlcGenerator::new(realm_id.as_str(), &self.hlc_device_id, &self.hlc_secret)
            });
        generator.try_generate().map_err(Into::into)
    }

    /// Build and sign an event emitted by this bridge's service actor.
    pub fn mint_event<T>(&self, kind: &str, realm_id: &RealmId, content: T) -> Result<Event>
    where
        T: Serialize,
    {
        let mut event = self.build_service_event(kind, realm_id, content)?;
        self.sign_as_service(&mut event)?;
        Ok(event)
    }

    /// Build an unsigned service-actor event. Callers that set signed-envelope
    /// fields (`external_ref`, `created_at`, …) before submitting do so on the
    /// returned event and then call [`Self::sign_as_service`] exactly once,
    /// avoiding a discarded first signature.
    pub fn mint_event_unsigned<T>(
        &self,
        kind: &str,
        realm_id: &RealmId,
        content: T,
    ) -> Result<Event>
    where
        T: Serialize,
    {
        self.build_service_event(kind, realm_id, content)
    }

    /// Build an unsigned event authored by the service actor (seq + HLC
    /// allocated, no proof).
    ///
    /// applet-integration §8 requires every Applet-originated write Event to
    /// carry the top-level `applet_id` in the signed envelope, including
    /// service-actor self-signed events (portal strand creation, audit
    /// events), so it is stamped here. Whether `authorization_ref` applies to
    /// service-actor self-signed events (vs. delegated ghost events, where it
    /// references the durable authorization) is not spelled out by §8; it is
    /// intentionally left unset pending a spec clarification.
    fn build_service_event<T>(&self, kind: &str, realm_id: &RealmId, content: T) -> Result<Event>
    where
        T: Serialize,
    {
        let content = spec_payload_value(content)?;
        let seq = self.seq.alloc()?;
        let hlc = self.next_hlc(realm_id)?;
        let mut event = Event::new(
            kind,
            realm_id.clone(),
            self.service_did.clone(),
            seq,
            hlc,
            content,
        )?;
        event.applet_id = Some(self.applet_id.clone());
        Ok(event)
    }

    /// Build and sign an event attributed to `actor` and executed by this
    /// bridge service under a durable delegated authorization.
    ///
    /// The proof verification method stays on the service DID. The envelope
    /// carries `executed_by = service_did` and `authorization_ref`, allowing the
    /// reducer to verify who actually signed while preserving the virtual
    /// actor as `actor_id`.
    pub fn mint_event_as<T>(
        &self,
        actor: &cokret::Did,
        kind: &str,
        realm_id: &RealmId,
        content: T,
        authorization_ref: &str,
    ) -> Result<Event>
    where
        T: Serialize,
    {
        let mut event =
            self.build_delegated_event(actor, kind, realm_id, content, authorization_ref)?;
        self.sign_as_service(&mut event)?;
        Ok(event)
    }

    /// Build an unsigned delegated-actor event (provenance fields set, no proof
    /// yet). Callers that still need to set signed-envelope fields
    /// (`external_ref`, `redacts`, `created_at`) do so before a single
    /// [`Self::sign_as_service`], avoiding a discarded first signature.
    fn build_delegated_event<T>(
        &self,
        actor: &cokret::Did,
        kind: &str,
        realm_id: &RealmId,
        content: T,
        authorization_ref: &str,
    ) -> Result<Event>
    where
        T: Serialize,
    {
        let authorization_ref = validate_authorization_ref(authorization_ref)?;
        let content = spec_payload_value(content)?;
        let seq = self.seq.alloc()?;
        let hlc = self.next_hlc(realm_id)?;
        let mut event = Event::new(kind, realm_id.clone(), actor.clone(), seq, hlc, content)?;
        event.executed_by = Some(self.service_did.clone());
        event.authorization_ref = Some(authorization_ref);
        event.applet_id = Some(self.applet_id.clone());
        Ok(event)
    }

    /// Sign `event` with the service key over the current canonical envelope.
    /// Used after all signed-envelope fields are in place so the event is signed
    /// exactly once.
    fn sign_as_service(&self, event: &mut Event) -> Result<()> {
        let verification_method = self.verification_method_for_actor(&self.service_did)?;
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
            .cokret
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
        // Set the signed-envelope `external_ref` before the single signature so
        // the proof covers it (no discarded first sign).
        let mut event =
            self.build_delegated_event(actor, kind, &realm, content, authorization_ref)?;
        event.external_ref = Some(spec_external_ref_value(external_ref)?);
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
        // Set `redacts` + `external_ref` before the single signature so the proof
        // covers them (no discarded first sign).
        let mut event = self.build_delegated_event(
            actor,
            "ck.message.redact",
            &realm,
            content,
            authorization_ref,
        )?;
        event.redacts = Some(EventId::new(target_event_id.to_owned())?);
        event.external_ref = Some(spec_external_ref_value(external_ref)?);
        self.sign_as_service(&mut event)?;
        self.submit_event(&event).await
    }

    /// Emit a `ck.applet.bridge_error` Event so a bridging failure is durable
    /// and auditable rather than silently dropped (applet-integration §14/§16;
    /// SDK [`cokret::AppletBridgeErrorBuilder`]). The builder is filled with all
    /// required bindings (realm/failed_transaction_ref/retriable/visibility) by
    /// the caller; this allocates the actor seq + HLC, signs with the service
    /// key, and submits. Returns the new event_id.
    pub async fn submit_bridge_error(
        &self,
        realm_id: &RealmId,
        builder: cokret::AppletBridgeErrorBuilder,
    ) -> Result<String> {
        let seq = self.seq.alloc()?;
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

    /// The configured applet id this bridge presents to cokret.
    pub fn applet_id(&self) -> &str {
        self.applet_id.as_str()
    }

    /// Media upload: returns the blob reference string.
    pub async fn upload_blob(&self, bytes: &[u8], mime: &str) -> Result<String> {
        let meta = cokret::models::BlobUploadMetadata {
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
        let r = cokret::BlobRef::new(blob_ref.to_owned())?;
        Ok(self.client.blob_download(&r, None).await?)
    }
}

fn validate_authorization_ref(authorization_ref: &str) -> Result<String> {
    let authorization_ref = authorization_ref.trim();
    if authorization_ref.is_empty() {
        return Err(BridgeError::Cokret(
            "delegated actor events require authorization_ref".to_owned(),
        ));
    }
    Ok(authorization_ref.to_owned())
}

fn spec_payload_value<T>(content: T) -> Result<Value>
where
    T: Serialize,
{
    serde_json::to_value(content).map_err(|error| {
        BridgeError::Cokret(format!("event payload serialization failed: {error}"))
    })
}

fn spec_external_ref_value<T>(external_ref: T) -> Result<Value>
where
    T: Serialize,
{
    serde_json::to_value(external_ref).map_err(|error| {
        BridgeError::Cokret(format!("event external_ref serialization failed: {error}"))
    })
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
/// The receiver for transactions pushed by the cokret server (implements
/// [`cokret::AppletHandler`]). It delivers the events in a transaction to the
/// inbound queue; the business forwarding is done in the core consumer loop.
pub struct BridgeAppletHandler {
    applet_id: String,
    service_did: Did,
    protocols: Vec<String>,
    namespaces: Value,
    limits: Value,
    auth: Value,
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
    /// on the inbound `POST /_cokret/edge/applet/transactions` path
    /// (applet-integration §7.3). Scoped to the methods this bridge accepts for
    /// inbound pushes (did:key / did:webvh, fail-closed).
    source_did_resolver: Arc<dyn DidResolver + Send + Sync>,
}

#[cfg(any(feature = "web", test))]
/// Advisory per-transaction event ceiling published in `describe.limits`.
const DESCRIBE_MAX_EVENTS_PER_TRANSACTION: usize = 8192;

#[cfg(any(feature = "web", test))]
fn default_applet_namespaces(bridge_id: &str, service_did: &Did) -> Value {
    let service_did = service_did.as_str();
    json!({
        "actors": [{
            "exclusive": true,
            "pattern": format!("{service_did}:ghost:*"),
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
fn default_applet_limits() -> Value {
    json!({
        "max_events_per_transaction": DESCRIBE_MAX_EVENTS_PER_TRANSACTION,
        "receive_events": true,
        "receive_ephemeral": true,
        "rate_limited": true,
    })
}

#[cfg(any(feature = "web", test))]
fn default_applet_auth(service_did: &Did, verification_method_id: &str) -> Value {
    let key_ref = if verification_method_id.starts_with("did:") {
        verification_method_id.to_owned()
    } else {
        format!("{}{}", service_did.as_str(), verification_method_id)
    };
    json!({
        "type": "http_message_signature",
        "key_ref": key_ref,
    })
}

#[cfg(any(feature = "web", test))]
impl BridgeAppletHandler {
    /// Build the handler from an inbound-capable edge. The edge must have been
    /// constructed with an inbound sender (the run_bridge/web path always is).
    /// `dedup` is the durable event-dedup store enforcing §7.3.
    pub fn new(
        edge: &CokretEdge,
        resolver: Option<Arc<dyn AppletResolver>>,
        dedup: Arc<dyn EventDedupStore>,
        handled_event_kinds: Option<Vec<String>>,
        source_did_resolver: Arc<dyn DidResolver + Send + Sync>,
    ) -> Self {
        let bridge_id = edge.config.bridge.bridge_id.clone();
        let service_did = edge.service_did.clone();
        let verification_method_id = edge.config.cokret.verification_method_id.clone();
        Self {
            applet_id: edge.config.cokret.applet_id.clone(),
            service_did: service_did.clone(),
            protocols: vec![bridge_id.clone()],
            namespaces: edge
                .config
                .cokret
                .applet_namespaces
                .clone()
                .unwrap_or_else(|| default_applet_namespaces(&bridge_id, &service_did)),
            limits: edge
                .config
                .cokret
                .applet_limits
                .clone()
                .unwrap_or_else(default_applet_limits),
            auth: edge
                .config
                .cokret
                .applet_auth
                .clone()
                .unwrap_or_else(|| default_applet_auth(&service_did, &verification_method_id)),
            inbound_tx: edge.inbound_sender().expect("inbound enabled"),
            ephemeral_tx: edge.ephemeral_sender(),
            resolver,
            dedup,
            handled_event_kinds,
            source_did_resolver,
        }
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
/// exception to the https requirement on `cokret.server_url`, for local dev).
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
impl cokret::AppletHandler for BridgeAppletHandler {
    fn source_did_resolver(&self) -> &dyn DidResolver {
        self.source_did_resolver.as_ref()
    }

    fn ping(&self) -> cokret::Result<AppletPingOutcome> {
        Ok(AppletPingOutcome {
            ok: true,
            applet_id: self.applet_id.clone(),
            service_did: self.service_did.clone(),
            protocol_version: "1.0".to_owned(),
        })
    }

    fn describe(&self) -> cokret::Result<AppletDescription> {
        Ok(AppletDescription {
            applet_id: self.applet_id.clone(),
            service_did: self.service_did.clone(),
            protocols: self.protocols.clone(),
            namespaces: self.namespaces.clone(),
            limits: self.limits.clone(),
            auth: self.auth.clone(),
        })
    }

    fn handle_transaction(
        &self,
        _idempotency_key: &str,
        req: AppletTransactionRequestBody,
    ) -> cokret::Result<AppletTransactionOutcome> {
        let mut rejected: Vec<Value> = Vec::new();
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
                rejected.push(serde_json::json!({
                    "event_id": event_id,
                    "reason_code": "queue_full",
                }));
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
                rejected.push(serde_json::json!({
                    "event_id": event_id,
                    "reason_code": "applet_namespace_mismatch",
                }));
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
                rejected.push(serde_json::json!({
                    "event_id": event_id,
                    "reason_code": "capability_denied",
                }));
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
                    rejected.push(serde_json::json!({
                        "event_id": event_id,
                        "reason_code": "queue_full",
                    }));
                    continue;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
                    enqueue_failed = true;
                    tracing::error!(%event_id, "failed to enqueue inbound event: consumer gone");
                    rejected.push(serde_json::json!({
                        "event_id": event_id,
                        "reason_code": "internal_error",
                    }));
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
                    rejected.push(serde_json::json!({
                        "event_id": event_id,
                        "reason_code": "duplicate_conflict",
                    }));
                    continue;
                }
                Err(err) => {
                    enqueue_failed = true;
                    tracing::error!(%event_id, error = %err, "event dedup store failed");
                    rejected.push(serde_json::json!({
                        "event_id": event_id,
                        "reason_code": "internal_error",
                    }));
                    continue;
                }
            }
        }

        // Forward spec-shaped ephemeral arrays one envelope at a time, parsed
        // into the SDK `EphemeralEnvelope` wire type
        // (`schemas/ephemeral-envelope.schema.json`). Ephemeral loss is
        // non-fatal (best-effort) and does not affect the durable ack; an
        // element that does not deserialize into a valid envelope is dropped
        // rather than failing the batch.
        if let Some(tx) = self.ephemeral_tx.as_ref() {
            match req.ephemeral {
                Value::Null => {}
                Value::Array(envelopes) => {
                    for envelope in envelopes {
                        let envelope: EphemeralEnvelope = match serde_json::from_value(envelope) {
                            Ok(envelope) => envelope,
                            Err(err) => {
                                tracing::warn!(
                                    error = %err,
                                    "dropping ephemeral element that is not a valid EphemeralEnvelope"
                                );
                                continue;
                            }
                        };
                        if let Err(err) = tx.try_send(envelope) {
                            tracing::warn!(
                                error = %err,
                                "dropping ephemeral envelope because the best-effort queue is full or closed"
                            );
                        }
                    }
                }
                other => {
                    tracing::warn!(
                        payload_type = %value_type_name(&other),
                        "dropping malformed applet transaction ephemeral payload; expected array"
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

    fn resolve_actor(&self, actor_id: &str) -> cokret::Result<AppletActorView> {
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
            external_ref: Value::Null,
        })
    }

    fn resolve_realm(&self, realm_id_or_alias: &str) -> cokret::Result<AppletRealmView> {
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
            external_ref: Value::Null,
        })
    }

    fn resolve_protocol(&self, protocol: &str) -> cokret::Result<AppletProtocolMetadata> {
        Ok(AppletProtocolMetadata {
            protocol: protocol.to_owned(),
            display_name: protocol.to_owned(),
            icon_blob_ref: None,
            field_types: Value::Null,
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
    fn event_fingerprint_ignores_unsigned_and_proofs() {
        let realm = RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d").unwrap();
        let actor = Did::new("did:webvh:alice.example").unwrap();
        let hlc = Hlc::new("01970e589d21-0001-a13f9c2e").unwrap();
        let mut first = Event::new(
            "ck.message.create",
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

        second.content = json!({ "body": "changed" });
        assert_ne!(
            event_content_fingerprint(&first),
            event_content_fingerprint(&second)
        );
    }

    fn test_proof(jws: &str) -> cokret::Proof {
        cokret::Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:alice.example#key-1".to_owned(),
            event_digest: cokret::Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
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
