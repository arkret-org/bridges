//! The arkret protocol-side edge (replaces the Matrix bridge's
//! `MatrixAppservice`).
//!
//! - **Outbound (app -> arkret)**: [`ArkretEdge::mint_event_unsigned_async`] and
//!   [`ArkretEdge::mint_event_as_unsigned_async`] build unsigned `Event`s; callers finalize signed
//!   envelope fields, sign once with [`ArkretEdge::resign_event`], build an initial-publication
//!   wrapper, then submit an [`EventInitialSubmission`].
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

#[cfg(any(feature = "web", test))]
use arkret::WireError;
use arkret::http_client::{Auth, Client};
#[cfg(any(feature = "web", test))]
use arkret::identity::public_key_material_from_binding;
#[cfg(any(feature = "web", test))]
use arkret::signatures::{EventProofBuilder, VerificationMethodDocument};
use arkret::signatures::{SignEventOptions, sign_event};
use arkret::{
    ActorId, AppletId, Did, Ed25519PayloadSigner, Event, EventId, Hlc, HlcGenerator, PayloadSigner,
    RealmId, ScopeRef, project_full_id_to_core_id,
};
use arkret_event_draft::{EventSpec, TypedEventDraft};
use arkret_models_collaboration::event_sync::{
    EventsFrontierSelector, EventsFrontierView, RealmActorFrontierView,
};
use arkret_models_collaboration::events_payloads::MessageRedactPayload;
#[cfg(any(feature = "web", test))]
use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
#[cfg(any(feature = "web", test))]
use arkret_models_discovery::ServiceDescribe;
#[cfg(any(feature = "web", test))]
use arkret_models_integration::{
    AppletActorView, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome,
};
use arkret_wire::{AuthorizationRef, DidUrl, EventInitialSubmission, SignalEnvelope, event_spec};
#[cfg(any(feature = "web", test))]
use arkret_wire::{ProfileId, ServiceOperationId};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
#[cfg(any(feature = "web", test))]
use serde_json::json;
use tokio::sync::mpsc::Sender;

#[cfg(any(feature = "web", test))]
use crate::app::AppletResolver;
use crate::config::Config;
#[cfg(any(feature = "web", test))]
use crate::did_binding::DidAuthority;
use crate::error::{BridgeError, Result};
#[cfg(any(feature = "web", test))]
use crate::idempotency::{DedupVerdict, EventDedupStore};

/// Bound on the inbound (arkret → app) event queue. Past this depth the applet
/// handler stops accepting events and asks the server to retry (backpressure)
/// rather than buffering without limit. Sized so a healthy consumer drains it
/// well within the server's retry window; a persistently full queue means the
/// app side is wedged, in which case shedding load back to the server (which
/// will redeliver) is the correct behaviour.
#[cfg(feature = "runtime")]
pub const INBOUND_QUEUE_CAPACITY: usize = 1024;

/// Bound on the best-effort Signal queue. When full, new Signal envelopes are
/// dropped instead of back-pressuring durable transaction delivery.
#[cfg(feature = "runtime")]
pub const SIGNAL_QUEUE_CAPACITY: usize = 1024;

/// Hard bound for per-Realm HLC generator state retained by one bridge process.
const MAX_REALM_HLC_GENERATORS: usize = 4_096;

/// Retry hint (ms) returned to the server when the inbound queue is full, so it
/// re-pushes the unaccepted events after a short delay instead of dropping them.
#[cfg(any(feature = "web", test))]
const INBOUND_QUEUE_FULL_RETRY_MS: u64 = 1000;

/// How many actor sequence numbers to reserve in the store per refill. A larger
/// block means fewer store writes at the cost of skipping more numbers on each
/// restart (gaps are harmless; only monotonicity matters).
const SEQ_RESERVE_BLOCK: i64 = 256;
/// The default `bridge_state` row key under which the reserved actor-seq
/// high-water mark is persisted.
pub const SEQ_STATE_KEY: &str = "actor_seq_reserved";

/// Host integration that wraps a fully-authored, fully-signed Event for initial
/// publication.
///
/// The default online path has no authorization lease. A delayed-publication
/// provider may use a local authority component or an authenticated remote
/// authz service to attach publication evidence. Every provider must return the
/// exact Event it was given wrapped in an [`EventInitialSubmission`]. The
/// runtime validates both the wrapper and exact Event identity before sending.
#[async_trait]
pub trait EventInitialSubmissionProvider: Send + Sync + 'static {
    async fn initial_submission(&self, event: &Event) -> Result<EventInitialSubmission>;
}

/// Production provider backed by the authenticated Principal Server.
///
/// The default SDK path returns an online wrapper without an authorization
/// lease. Delayed publication can install a different provider.
#[derive(Clone)]
pub struct PrincipalServerSubmissionProvider {
    client: Client,
}

impl PrincipalServerSubmissionProvider {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl EventInitialSubmissionProvider for PrincipalServerSubmissionProvider {
    async fn initial_submission(&self, event: &Event) -> Result<EventInitialSubmission> {
        self.client
            .prepare_initial_submission(event)
            .await
            .map_err(Into::into)
    }
}

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
    signer: Ed25519PayloadSigner,
    /// Authority transport for issuer-produced AuthorizationLease/CBA
    /// evidence. The default uses the authenticated Principal Server.
    submission_provider: Mutex<Arc<dyn EventInitialSubmissionProvider>>,
    /// Resolvable full DID used for key lookup and proof `verification_method`.
    service_id: Did,
    /// Stable service actor core written into Event envelopes.
    service_actor_id: ActorId,
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
    /// Inbound encrypted Signal queue: arkret server push → core consumer loop.
    /// Product kind and payload stay inside ciphertext; this layer only
    /// validates and forwards the SDK [`SignalEnvelope`] wire type.
    /// `None` for outbound-only edges.
    signal_tx: Option<Sender<SignalEnvelope>>,
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
        // The signer's `kid` MUST be the absolute DID URL
        // `<service_id>#<fragment>`; `verification_method_id` is configured as
        // a bare fragment, so it is absolutized here instead of being handed to
        // the signer verbatim.
        let signer = Ed25519PayloadSigner::from_did_key_seed(
            seed,
            service_id.clone(),
            config.arkret.verification_method_for(&service_id)?,
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
        signer: Ed25519PayloadSigner,
        seq: SeqAllocator,
    ) -> Result<Self> {
        let service_id = Did::new(config.arkret.service_id.clone())?;
        let hlc_secret = signer.verifying_key().to_bytes();
        Self::build(config, client, signer, service_id, hlc_secret, seq, None)
    }

    fn build(
        config: Arc<Config>,
        client: Client,
        signer: Ed25519PayloadSigner,
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
        let service_actor_id = ActorId::from(project_full_id_to_core_id(&service_id)?);
        let hlc_device_id = config.bridge.bridge_id.clone();

        let submission_provider: Arc<dyn EventInitialSubmissionProvider> =
            Arc::new(PrincipalServerSubmissionProvider::new(client.clone()));
        Ok(Self {
            config,
            client,
            signer,
            submission_provider: Mutex::new(submission_provider),
            service_id,
            service_actor_id,
            applet_id,
            seq,
            hlc_generators: Mutex::new(HashMap::new()),
            hlc_device_id,
            hlc_secret,
            inbound_tx,
            signal_tx: None,
        })
    }

    /// Install the encrypted Signal sender. Used by the `run_bridge` path which
    /// wires a parallel best-effort queue.
    pub fn set_signal_sender(&mut self, tx: Sender<SignalEnvelope>) {
        self.signal_tx = Some(tx);
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Override the default authenticated Principal Server publication
    /// provider. This is intended for another production authority transport;
    /// returned wrappers are still validated before network submission.
    pub fn set_initial_submission_provider(
        &self,
        provider: Arc<dyn EventInitialSubmissionProvider>,
    ) {
        *self.submission_provider.lock() = provider;
    }

    pub fn service_id(&self) -> &Did {
        &self.service_id
    }

    /// Stable service actor core used in Event envelopes. The full service DID
    /// remains available through [`Self::service_id`] for resolution and proof
    /// verification-method construction.
    pub fn service_actor_id(&self) -> &ActorId {
        &self.service_actor_id
    }

    /// The inbound event sender (bounded), if this edge was built with one.
    pub fn inbound_sender(&self) -> Option<Sender<Event>> {
        self.inbound_tx.clone()
    }

    /// The Signal sender, if installed.
    pub fn signal_sender(&self) -> Option<Sender<SignalEnvelope>> {
        self.signal_tx.clone()
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
    pub async fn mint_event_unsigned_async<K>(
        &self,
        realm_id: &RealmId,
        content: K::Payload,
    ) -> Result<Event>
    where
        K: EventSpec,
    {
        self.build_service_event_async::<K>(realm_id, content).await
    }

    /// Build an unsigned event authored by the service actor (seq + HLC
    /// allocated, no proof). Applet-originated writes carry the top-level
    /// `applet_id` in the signed envelope.
    async fn build_service_event_async<K>(
        &self,
        realm_id: &RealmId,
        content: K::Payload,
    ) -> Result<Event>
    where
        K: EventSpec,
    {
        let seq = self.seq.alloc_blocking().await?;
        let hlc = self.next_hlc(realm_id)?;
        Ok(TypedEventDraft::<K>::new(
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            self.service_actor_id.clone(),
            content,
        )?
        .with_applet_id(self.applet_id.clone())
        .author_now(seq, hlc)?)
    }

    async fn build_delegated_event_async<K>(
        &self,
        actor: &arkret::Did,
        realm_id: &RealmId,
        content: K::Payload,
        authorization_ref: &str,
    ) -> Result<Event>
    where
        K: EventSpec,
    {
        let authorization_ref = validate_authorization_ref(authorization_ref)?;
        let seq = self.seq.alloc_blocking().await?;
        let hlc = self.next_hlc(realm_id)?;
        let actor_id = ActorId::from(project_full_id_to_core_id(actor)?);
        Ok(TypedEventDraft::<K>::new(
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor_id,
            content,
        )?
        .with_executed_by(self.service_actor_id.clone())
        .with_authorization_ref(authorization_ref)
        .with_applet_id(self.applet_id.clone())
        .author_now(seq, hlc)?)
    }

    /// Build an unsigned delegated-actor event asynchronously.
    ///
    /// Hosts may mutate signed-envelope fields or replace plaintext content
    /// with encrypted content before calling [`Self::resign_event`] once and
    /// submitting the result.
    pub async fn mint_event_as_unsigned_async<K>(
        &self,
        actor: &Did,
        realm_id: &RealmId,
        content: K::Payload,
        authorization_ref: &str,
    ) -> Result<Event>
    where
        K: EventSpec,
    {
        self.build_delegated_event_async::<K>(actor, realm_id, content, authorization_ref)
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

    fn verification_method_for_actor(&self, actor: &Did) -> Result<DidUrl> {
        self.config.arkret.verification_method_for(actor)
    }

    /// Submit a signed Event in an initial-publication wrapper and return its
    /// event id.
    ///
    /// This boundary deliberately accepts the SDK wrapper rather than a bare
    /// [`Event`]. Online wrappers omit the lease; delayed wrappers may carry
    /// authority-produced publication evidence.
    pub async fn submit_initial(&self, submission: &EventInitialSubmission) -> Result<String> {
        let event_id = submission.event.event_id.to_string();
        submission
            .validate_structural()
            .map_err(|error| BridgeError::Arkret(error.to_string()))?;
        self.client.events_submit(submission).await?;
        Ok(event_id)
    }

    /// Ask the authority provider to wrap an exact signed Event, then submit
    /// it. The default provider calls the authenticated Principal Server.
    pub async fn submit_event(&self, event: &Event) -> Result<String> {
        let provider = self.submission_provider.lock().clone();
        let submission = provider.initial_submission(event).await?;
        if submission.event != *event {
            return Err(BridgeError::Runtime(
                "EventInitialSubmissionProvider replaced or mutated the signed Event".to_owned(),
            ));
        }
        self.submit_initial(&submission).await
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
    pub fn service_verification_method(&self) -> Result<DidUrl> {
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
                actor_id: ActorId::from(project_full_id_to_core_id(actor_id)?),
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
    pub async fn submit_with_external_ref_as<K, E>(
        &self,
        actor: &Did,
        realm_id: &str,
        content: K::Payload,
        external_ref: E,
        authorization_ref: &str,
    ) -> Result<String>
    where
        K: EventSpec,
        E: Serialize,
    {
        let realm = RealmId::new(realm_id.to_owned())?;
        let external_ref = spec_external_ref_map(external_ref)?;
        // Set the signed-envelope `external_ref` before the single signature so
        // the proof covers it (no discarded first sign).
        let mut event = self
            .build_delegated_event_async::<K>(actor, &realm, content, authorization_ref)
            .await?;
        event.external_ref = Some(external_ref);
        self.sign_as_service(&mut event)?;
        self.submit_event(&event).await
    }

    /// Submit a message redaction attributed to a delegated app actor while
    /// setting the signed envelope `redacts` target. External app expiry or
    /// retention drops must be filtered by callers before reaching this helper.
    pub async fn submit_redaction_with_external_ref_as<E>(
        &self,
        actor: &Did,
        realm_id: &str,
        target_event_id: &str,
        content: MessageRedactPayload,
        external_ref: E,
        authorization_ref: &str,
    ) -> Result<String>
    where
        E: Serialize,
    {
        let realm = RealmId::new(realm_id.to_owned())?;
        let external_ref = spec_external_ref_map(external_ref)?;
        // Set `redacts` + `external_ref` before the single signature so the proof
        // covers them (no discarded first sign).
        let mut event = self
            .build_delegated_event_async::<event_spec::MessageRedact>(
                actor,
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

fn validate_authorization_ref(authorization_ref: &str) -> Result<AuthorizationRef> {
    let authorization_ref = authorization_ref.trim();
    if authorization_ref.is_empty() {
        return Err(BridgeError::Arkret(
            "delegated actor events require authorization_ref".to_owned(),
        ));
    }
    AuthorizationRef::new(authorization_ref.to_owned()).map_err(|error| {
        BridgeError::Arkret(format!("invalid delegated authorization_ref: {error}"))
    })
}

fn default_client(config: &Config) -> Result<Client> {
    let base = url::Url::parse(&config.arkret.server_url)
        .map_err(|e| BridgeError::Config(format!("server_url: {e}")))?;
    Client::builder(base)
        .auth(Auth::Bearer(config.arkret.access_token.clone()))
        .build()
        .map_err(Into::into)
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
    signal_tx: Option<Sender<SignalEnvelope>>,
    resolver: Option<Arc<dyn AppletResolver>>,
    /// Event kinds this bridge consumes on the inbound path. `None` ⇒ permissive
    /// (accept all). When `Some`, a pushed event whose kind is not listed is
    /// rejected as `capability_denied` (applet-integration §7/§13).
    handled_event_kinds: Option<Vec<String>>,
    /// Durable single-event-level dedup store (applet-integration §7.3; the
    /// runtime path injects [`crate::db::DbEventDedupStore`]).
    dedup: Arc<dyn EventDedupStore>,
    /// Inbound DID **authority adapter** (`did-usage-and-verification.md` §6).
    ///
    /// The handler holds the adapter, not a resolver: `DidAuthority` keeps its
    /// `CompositeDidResolver` in a private field with no accessor, so the only
    /// way to reach the network from here is one of its explicitly named §4
    /// authority entry points. Ordinary per-signature verification consumes
    /// [`DidAuthority::bindings`], which has no resolver at all.
    did_authority: Arc<DidAuthority>,
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
        did_authority: Arc<DidAuthority>,
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
            signal_tx: edge.signal_sender(),
            resolver,
            dedup,
            handled_event_kinds,
            did_authority,
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
#[cfg(any(feature = "web", test))]
fn glob_suffix_match(pattern: &str, candidate: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => candidate.starts_with(prefix),
        None => pattern == candidate,
    }
}

#[cfg(any(feature = "web", test))]
impl arkret::AppletHandler for BridgeAppletHandler {
    /// SDK `AppletHandler` authority hook.
    ///
    /// This is an authority surface by definition (the SDK router calls it to
    /// authenticate an inbound push), so it delegates to [`DidAuthority`] rather
    /// than holding a resolver here. The adapter is store-first: an already
    /// accepted `service`-purpose binding answers with zero network calls, and
    /// only a genuine §4 trigger resolves — exactly once.
    fn resolve_verification_method(
        &self,
        verification_method: &DidUrl,
    ) -> std::result::Result<VerificationMethodDocument, WireError> {
        let accepted = self
            .did_authority
            .service_verification_method(verification_method, chrono::Utc::now())
            .map_err(WireError::Protocol)?;
        let public_key = public_key_material_from_binding(&accepted, verification_method)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        let key_bytes = public_key
            .ed25519_bytes()
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        Ok(VerificationMethodDocument {
            did: accepted.binding().did().clone(),
            verification_method: verification_method.clone(),
            public_key_multibase: arkret::ed25519_pubkey_to_did_key_multibase(&key_bytes),
            controller: None,
        })
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
            arkret::ServiceKind::AppletService,
        );
        description.supported_profiles = vec![ProfileId::APPLET_SERVICE_V1.to_owned()];
        description.supported_operations = vec![
            ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION.to_owned(),
            ServiceOperationId::EDGE_APPLET_READ_DESCRIBE.to_owned(),
            ServiceOperationId::EDGE_APPLET_READ_PING.to_owned(),
            ServiceOperationId::EDGE_APPLET_ACTOR_READ_RESOLVE.to_owned(),
            ServiceOperationId::EDGE_APPLET_REALM_READ_RESOLVE.to_owned(),
            ServiceOperationId::EDGE_APPLET_READ_PROTOCOL_METADATA.to_owned(),
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
                    reason_code: arkret_wire::ReasonCode::from_wire(
                        arkret_wire::ReasonCode::QUEUE_FULL,
                    ),
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
                    reason_code: arkret_wire::ReasonCode::from_wire(
                        arkret_wire::ReasonCode::APPLET_NAMESPACE_MISMATCH,
                    ),
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
                    reason_code: arkret_wire::ReasonCode::from_wire(
                        arkret_wire::ErrorCode::CAPABILITY_DENIED,
                    ),
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
                        reason_code: arkret_wire::ReasonCode::from_wire(
                            arkret_wire::ReasonCode::QUEUE_FULL,
                        ),
                        retry_after_ms: None,
                    });
                    continue;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
                    enqueue_failed = true;
                    tracing::error!(%event_id, "failed to enqueue inbound event: consumer gone");
                    rejected.push(arkret::RejectedItem {
                        event_id: Some(event.event_id.clone()),
                        reason_code: arkret_wire::ReasonCode::from_wire(
                            arkret_wire::ReasonCode::INTERNAL_ERROR,
                        ),
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
                        reason_code: arkret_wire::ReasonCode::from_wire(
                            arkret_wire::ReasonCode::DUPLICATE_CONFLICT,
                        ),
                        retry_after_ms: None,
                    });
                    continue;
                }
                Err(err) => {
                    enqueue_failed = true;
                    tracing::error!(%event_id, error = %err, "event dedup store failed");
                    rejected.push(arkret::RejectedItem {
                        event_id: Some(event.event_id.clone()),
                        reason_code: arkret_wire::ReasonCode::from_wire(
                            arkret_wire::ReasonCode::INTERNAL_ERROR,
                        ),
                        retry_after_ms: None,
                    });
                    continue;
                }
            }
        }

        // Forward SDK-typed encrypted Signal envelopes one at a time. Signal
        // loss is non-fatal (best-effort) and does not affect the durable ack.
        if let (Some(tx), Some(envelopes)) = (self.signal_tx.as_ref(), req.signals) {
            for envelope in envelopes {
                if let Err(err) = envelope.validate_structural() {
                    tracing::warn!(
                        error = %err,
                        "dropping invalid Signal envelope"
                    );
                    continue;
                }
                if let Err(err) = tx.try_send(envelope) {
                    tracing::warn!(
                        error = %err,
                        "dropping Signal envelope because the best-effort queue is full or closed"
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
            field_definitions: Default::default(),
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
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let actor = ActorId::from(
            project_full_id_to_core_id(&Did::new("did:webvh:z6mkfixture:alice.example").unwrap())
                .unwrap(),
        );
        let hlc = Hlc::new("01970e589d21-0001-a13f9c2e").unwrap();
        let mut first = arkret_wire::test_support::raw_event(
            "ak.message.create",
            ScopeRef::Realm { realm_id: realm },
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
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1")
                .expect("fixture verification method is a valid DID URL"),
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
