//! The arkret protocol-side edge (replaces the Matrix bridge's
//! `MatrixAppservice`).
//!
//! - **Outbound (app -> arkret)**: [`ArkretEdge::service_intent`] and
//!   [`ArkretEdge::delegated_intent`] build `EventIntent`s with everything except the actor chain
//!   position filled in; [`ArkretEdge::author_and_sign`] positions and signs one, then
//!   [`ArkretEdge::submit_event`] wraps it in an initial-publication submission and sends it.
//! - **Inbound (arkret → app)**: transactions pushed by the arkret server via the applet HTTP
//!   endpoints are placed into the `inbound_tx` queue by [`BridgeAppletHandler`]; after the core
//!   consumes them they are forwarded to the app adapter.
//! - **Media**: [`ArkretEdge::upload_blob`] / [`ArkretEdge::download_blob`].
//!
//! The restart-safe monotonic actor-sequence allocator lives in
//! [`crate::seq`]; a host injects a [`crate::seq::SeqStore`] implementation so
//! the runtime does not depend on diesel.

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
    AppletId, AuthoredEvent, DidCoreId, DidFullId, DigestSuite, Ed25519PayloadSigner, Event,
    EventIntent, Hlc, HlcGenerator, RealmId, ScopeRef, project_full_id_to_core_id,
};
use arkret_event_draft::{EventSpec, TypedEventDraft};
use arkret_models_collaboration::events_payloads::MessageRedactPayload;
#[cfg(any(feature = "web", test))]
use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
#[cfg(any(feature = "web", test))]
use arkret_models_discovery::ServiceDescribe;
#[cfg(any(feature = "web", test))]
use arkret_models_integration::{
    AppletActorView, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome, AppletWireNamespaces,
};
use arkret_wire::{AuthorizationRef, DidUrl, EventInitialSubmission, SignalEnvelope, event_spec};
#[cfg(any(feature = "web", test))]
use arkret_wire::{ProfileId, ServiceOperationId};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
#[cfg(test)]
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
use crate::seq::{SEQ_STATE_KEY, SeqAllocator, SeqStore};

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

/// Submission wrapper backed by the authenticated Principal Server.
///
/// The default SDK path returns an online wrapper without an authorization
/// lease.
#[derive(Clone)]
pub struct PrincipalServerSubmissionProvider {
    client: Client,
}

impl PrincipalServerSubmissionProvider {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Wrap a fully-authored, fully-signed Event for initial publication,
    /// returning the exact Event it was given inside an
    /// [`EventInitialSubmission`]. The runtime validates both the wrapper and
    /// exact Event identity before sending.
    async fn initial_submission(
        &self,
        event: &Event,
        digest_suite: DigestSuite,
    ) -> Result<EventInitialSubmission> {
        self.client
            .prepare_initial_submission(event, digest_suite)
            .await
            .map_err(Into::into)
    }
}

/// The arkret edge client.
pub struct ArkretEdge {
    config: Arc<Config>,
    client: Client,
    signer: Ed25519PayloadSigner,
    /// Authority transport for issuer-produced AuthorizationLease/CBA
    /// evidence: the authenticated Principal Server submission wrapper.
    submission_provider: PrincipalServerSubmissionProvider,
    /// Resolvable full DID used for key lookup and proof `verification_method`.
    service_id: DidFullId,
    /// Stable service actor core written into Event envelopes.
    service_actor_id: DidCoreId,
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
        let service_id = DidFullId::new(config.arkret.service_id.clone())?;
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
    ///
    /// Kept for the out-of-repo consumer `savfox`
    /// (`../../../savfox-ai/savfox/crates/gateway-server/src/channels/arkret_applet.rs`);
    /// do not delete it without checking that consumer first.
    pub fn new_outbound(
        config: Arc<Config>,
        client: Client,
        signer: Ed25519PayloadSigner,
        seq: SeqAllocator,
    ) -> Result<Self> {
        let service_id = DidFullId::new(config.arkret.service_id.clone())?;
        let hlc_secret = signer.verifying_key().to_bytes();
        Self::build(config, client, signer, service_id, hlc_secret, seq, None)
    }

    fn build(
        config: Arc<Config>,
        client: Client,
        signer: Ed25519PayloadSigner,
        service_id: DidFullId,
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
        // Applet service identities use verifiable-history DIDs. Managed actor
        // identities and namespaces are independent package-authority inputs,
        // unrelated to this service identity.
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
        let service_actor_id = project_full_id_to_core_id(&service_id)?;
        let hlc_device_id = config.bridge.bridge_id.clone();

        let submission_provider = PrincipalServerSubmissionProvider::new(client.clone());
        Ok(Self {
            config,
            client,
            signer,
            submission_provider,
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

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Stable service actor core used in Event envelopes.
    pub fn service_actor_id(&self) -> &DidCoreId {
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

    /// The service-actor write for `content`, with everything except the actor
    /// chain position filled in. Applet-originated writes carry the top-level
    /// `applet_id` in the signed envelope.
    ///
    /// A write is an [`EventIntent`] until [`Self::author_and_sign`] positions
    /// it: hosts fill in producer-signed members (`created_at`, `external_ref`,
    /// encrypted content) HERE, because the Event's identity is derived from
    /// them exactly once at authoring and nothing may rewrite it afterwards.
    pub fn service_intent<K>(&self, realm_id: &RealmId, content: K::Payload) -> Result<EventIntent>
    where
        K: EventSpec,
    {
        Ok(TypedEventDraft::<K>::new(
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            self.service_actor_id.clone(),
            self.service_actor_id.clone(),
            content,
        )?
        .with_applet_id(self.applet_id.clone())
        .into_intent(chrono::Utc::now())?)
    }

    /// [`Self::service_intent`] with an explicit delegated actor and the
    /// durable authorization it acts under.
    pub fn delegated_intent<K>(
        &self,
        actor: &DidFullId,
        realm_id: &RealmId,
        content: K::Payload,
        authorization_ref: &str,
    ) -> Result<EventIntent>
    where
        K: EventSpec,
    {
        let authorization_ref = validate_authorization_ref(authorization_ref)?;
        let actor_id = project_full_id_to_core_id(actor)?;
        Ok(TypedEventDraft::<K>::new(
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor_id,
            self.service_actor_id.clone(),
            content,
        )?
        .with_executed_by(self.service_actor_id.clone())
        .with_authorization_ref(authorization_ref)
        .with_applet_id(self.applet_id.clone())
        .into_intent(chrono::Utc::now())?)
    }

    /// Position `intent` on the service actor chain, derive its one identity,
    /// and attach the service proof.
    ///
    /// Any backing-store refill for actor sequence numbers runs on the blocking
    /// pool instead of a Tokio worker. An intent that pinned its own
    /// `prev_refs` (e.g. from a fetched frontier) keeps them.
    pub async fn author_and_sign(
        &self,
        realm_id: &RealmId,
        intent: EventIntent,
    ) -> Result<AuthoredEvent> {
        let digest_suite = self.realm_digest_suite(realm_id).await?;
        let seq = self.seq.alloc_blocking().await?;
        let hlc = self.next_hlc(realm_id)?;
        let mut event = intent
            .author_with_digest_suite(seq, hlc, digest_suite)
            .map_err(|error| BridgeError::Arkret(error.to_string()))?;
        self.sign_as_service(&mut event)?;
        Ok(event)
    }

    /// Sign `event` with the service key. The signer verifies the authored
    /// identity against its own content and fails closed on a mismatch, so
    /// there is no signed-envelope mutation after this point.
    fn sign_as_service(&self, event: &mut AuthoredEvent) -> Result<()> {
        let verification_method = self.verification_method_for_actor(&self.service_id)?;
        sign_event(
            event,
            &self.signer,
            &verification_method,
            SignEventOptions::new(),
        )?;
        Ok(())
    }

    fn verification_method_for_actor(&self, actor: &DidFullId) -> Result<DidUrl> {
        self.config.arkret.verification_method_for(actor)
    }

    /// Submit a signed Event in an initial-publication wrapper and return its
    /// event id.
    ///
    /// This boundary deliberately accepts the SDK wrapper rather than a bare
    /// [`Event`]. Online wrappers omit the lease; delayed wrappers may carry
    /// authority-produced publication evidence.
    pub async fn submit_initial(
        &self,
        submission: &EventInitialSubmission,
        digest_suite: DigestSuite,
    ) -> Result<String> {
        let event_id = submission.event.event_id.to_string();
        submission
            .validate_structural(digest_suite)
            .map_err(|error| BridgeError::Arkret(error.to_string()))?;
        self.client.events_submit(submission).await?;
        Ok(event_id)
    }

    /// Ask the authority provider to wrap an exact signed Event, then submit
    /// it. The provider calls the authenticated Principal Server.
    pub async fn submit_event(&self, event: &AuthoredEvent) -> Result<String> {
        let digest_suite = event.digest_suite();
        let submission = self
            .submission_provider
            .initial_submission(event.event(), digest_suite)
            .await?;
        if submission.event != *event.event() {
            return Err(BridgeError::Runtime(
                "submission wrapper replaced or mutated the signed Event".to_owned(),
            ));
        }
        self.submit_initial(&submission, digest_suite).await
    }

    /// Resolve the current Realm digest suite from the authenticated
    /// Seal-frontier projection. The state and control roots must agree; an
    /// Event or Seal identifier prefix is never used as governance state.
    pub async fn realm_digest_suite(&self, realm_id: &RealmId) -> Result<DigestSuite> {
        // `seals_frontier` fails closed on a realm mismatch or an
        // out-of-bounds frontier before returning.
        let frontier = self.client.seals_frontier(realm_id.clone()).await?.frontier;
        // The frontier view carries no service-derived root hint, so the
        // accepted leaf Seal is resolved and its own signed roots are read.
        let leaf = frontier
            .sole_leaf()
            .map_err(|error| BridgeError::Arkret(error.to_string()))?
            .clone();
        let resolved = self
            .client
            .seals_resolve(&arkret::SelfSealResolveRequestBody {
                realm_id: realm_id.clone(),
                seal_refs: vec![leaf.clone()],
                history_traversal_access: None,
            })
            .await?;
        let seal = resolved
            .seals
            .into_iter()
            .find(|seal| seal.id == leaf)
            .ok_or_else(|| {
                BridgeError::Arkret("accepted Realm Seal frontier leaf did not resolve".to_owned())
            })?;
        let state_suite = seal
            .state_root
            .digest_suite()
            .map_err(|error| BridgeError::Arkret(error.to_string()))?;
        let control_suite = seal
            .control_event_set_root
            .digest_suite()
            .map_err(|error| BridgeError::Arkret(error.to_string()))?;
        if state_suite != control_suite {
            return Err(BridgeError::Arkret(
                "Realm Seal frontier roots use different digest suites".to_owned(),
            ));
        }
        Ok(state_suite)
    }

    /// Outbound convenience with bridge provenance and an explicit delegated
    /// actor. Used by messaging bridges to submit per-user Ghost Actor events
    /// after provisioning returned a durable authorization ref.
    ///
    /// applet-integration §8 requires the signed Event Envelope top-level
    /// `external_ref` for bridge-originated events.
    pub async fn submit_with_external_ref_as<K, E>(
        &self,
        actor: &DidFullId,
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
        // `external_ref` is producer-signed content: it rides the intent, so the
        // one derived identity covers it.
        let intent = self
            .delegated_intent::<K>(actor, &realm, content, authorization_ref)?
            .with_external_ref(external_ref);
        let event = self.author_and_sign(&realm, intent).await?;
        self.submit_event(&event).await
    }

    /// Submit a message redaction attributed to a delegated app actor. The
    /// redaction target travels in `content.message_id`, the single registered
    /// target carrier. External app expiry or retention drops must be filtered
    /// by callers before reaching this helper.
    pub async fn submit_redaction_with_external_ref_as<E>(
        &self,
        actor: &DidFullId,
        realm_id: &str,
        content: MessageRedactPayload,
        external_ref: E,
        authorization_ref: &str,
    ) -> Result<String>
    where
        E: Serialize,
    {
        let realm = RealmId::new(realm_id.to_owned())?;
        let external_ref = spec_external_ref_map(external_ref)?;
        // `external_ref` is producer-signed content: it rides the intent, so the
        // one derived identity covers it.
        let intent = self
            .delegated_intent::<event_spec::MessageRedact>(
                actor,
                &realm,
                content,
                authorization_ref,
            )?
            .with_external_ref(external_ref);
        let event = self.author_and_sign(&realm, intent).await?;
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
        // applet-integration §8: the signed envelope of every Applet-originated
        // write Event MUST carry the top-level `applet_id`; the builder only
        // binds it inside the content, so it rides the intent and the one
        // derived identity covers it.
        let intent = builder
            .build(chrono::Utc::now())?
            .with_applet_id(self.applet_id.clone());
        let event = self.author_and_sign(realm_id, intent).await?;
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
    applet_id: AppletId,
    service_id: DidFullId,
    trust_domain: arkret::TrustDomainId,
    namespaces: AppletWireNamespaces,
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
    /// Inbound DID **binding store** (`did-usage-and-verification.md` §6).
    ///
    /// A bridge has no registered DID authority call site, so [`DidAuthority`]
    /// owns no resolver: it holds the operator-configured acceptances and
    /// nothing else, and every lookup from here is in-memory.
    did_authority: Arc<DidAuthority>,
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
        let service_id = edge.service_id.clone();
        Ok(Self {
            applet_id: edge.applet_id.clone(),
            service_id: service_id.clone(),
            trust_domain: edge.config.arkret.trust_domain.clone(),
            namespaces: edge.config.arkret.applet_namespaces.clone(),
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
    /// matching). Patterns use the spec's trailing `*` suffix-glob form. An
    /// empty explicit Realm namespace accepts no Realm.
    fn realm_in_namespace(&self, realm_id: &str) -> bool {
        self.namespaces
            .realms
            .iter()
            .any(|entry| glob_suffix_match(&entry.pattern, realm_id))
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
    /// The SDK router calls this to authenticate an inbound push, so it
    /// delegates to [`DidAuthority`] rather than holding key material here. The
    /// lookup is store-only: the operator-configured `service`-purpose anchor
    /// answers with zero network calls, and an unconfigured method fails closed
    /// because there is no resolver to fall back on.
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
            applet_id: self.applet_id.clone(),
            // The wire field is the stable identity core; the configured
            // resolvable DID is projected through the registered method
            // adapter rather than re-spelled.
            service_id: project_full_id_to_core_id(&self.service_id)
                .map_err(|error| WireError::Protocol(error.to_string()))?,
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
        description.operation_bindings = [
            ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION.to_owned(),
            ServiceOperationId::EDGE_APPLET_READ_DESCRIBE.to_owned(),
            ServiceOperationId::EDGE_APPLET_READ_PING.to_owned(),
            ServiceOperationId::EDGE_APPLET_ACTOR_READ_RESOLVE.to_owned(),
            ServiceOperationId::EDGE_APPLET_REALM_READ_RESOLVE.to_owned(),
            ServiceOperationId::EDGE_APPLET_READ_PROTOCOL_METADATA.to_owned(),
        ]
        .into_iter()
        .map(|operation| {
            let operation_id = ServiceOperationId::from_wire(&operation)
                .expect("generated applet operation id is registered");
            arkret_models_discovery::OperationBinding::current_http_json(operation_id)
                .expect("generated applet operation descriptor is valid")
        })
        .collect();
        description.validate()?;
        Ok(description)
    }

    fn handle_transaction(
        &self,
        _idempotency_key: &str,
        req: AppletTransactionRequestBody,
    ) -> std::result::Result<AppletTransactionOutcome, WireError> {
        let event_count = req.events.len();
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

        // `status` reflects whether every durable event was accepted (either freshly
        // enqueued or de-duplicated). When enqueueing failed or the queue is full
        // (backpressure), signal a retry so the server re-pushes the unaccepted
        // events rather than dropping the batch.
        let retry_after_ms = (enqueue_failed || queue_full).then_some(INBOUND_QUEUE_FULL_RETRY_MS);
        Ok(AppletTransactionOutcome {
            status: if rejected.is_empty() {
                arkret_models_integration::AppletTransactionStatus::Accepted
            } else if rejected.len() == event_count {
                arkret_models_integration::AppletTransactionStatus::Rejected
            } else {
                arkret_models_integration::AppletTransactionStatus::Partial
            },
            rejected,
            retry_after_ms,
        })
    }

    fn resolve_actor(&self, actor_id: &str) -> std::result::Result<AppletActorView, WireError> {
        // `ResolvedActor::actor_id` carries the resolvable ghost DID that was
        // persisted at provisioning time. The wire view answers with the
        // stable identity core, so the string is parsed as a full DID and
        // projected; either step failing means the mapping row cannot be
        // vouched for and the probe answers `exists: false`.
        if let Some(resolved) = self
            .resolver
            .as_ref()
            .and_then(|r| r.resolve_actor(actor_id))
            && let Ok(did) = DidFullId::new(resolved.actor_id)
            && let Ok(core_id) = project_full_id_to_core_id(&did)
        {
            return Ok(AppletActorView {
                exists: true,
                actor_id: Some(core_id),
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
    use super::*;

    #[test]
    fn event_fingerprint_ignores_unsigned_and_proofs() {
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let actor = project_full_id_to_core_id(
            &DidFullId::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        )
        .unwrap();
        let hlc = Hlc::new("01970e589d21-0001-a13f9c2e").unwrap();
        let mut first = arkret_wire::test_support::raw_event(
            "ak.message.create",
            ScopeRef::Realm { realm_id: realm },
            actor.clone(),
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
        first
            .proofs
            .push(test_proof("header.payload.signature-a").into());
        second
            .proofs
            .push(test_proof("header.payload.signature-b").into());

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

    fn test_proof(jws: &str) -> arkret::ProducerEventProof {
        arkret::ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1")
                .expect("fixture verification method is a valid DID URL"),
            event_digest: arkret::Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            signer_resolution_evidence_ref: None,
            signer_resolution_evidence_digest: None,
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: jws.to_owned(),
        }
    }
}
