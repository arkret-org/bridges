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
//! A host injects a durable [`crate::AuthoringJournal`] so retries retain exact
//! signed Events and Realm/Actor accepted frontiers without requiring diesel.

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
    AppletId, AuthoredEvent, Did, DidCoreId, DigestSuite, Ed25519PayloadSigner, Event, EventIntent,
    Hlc, HlcGenerator, RealmId, ScopeRef, project_did_to_core_id,
};
use arkret_event_draft::{EventSpec, TypedEventDraft};
use arkret_models_collaboration::event_sync::{EventsFrontierSelector, EventsFrontierView};
use arkret_models_collaboration::events_payloads::MessageRedactPayload;
#[cfg(any(feature = "web", test))]
use arkret_models_collaboration::http_bodies::AppletTransactionRequestBody;
#[cfg(any(feature = "web", test))]
use arkret_models_discovery::{ServiceDescribe, TransportBinding};
#[cfg(any(feature = "web", test))]
use arkret_models_integration::{
    AppletActorView, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome, AppletWireNamespaces,
};
#[cfg(any(feature = "web", test))]
use arkret_wire::ProfileId;
use arkret_wire::{
    AuthContext, AuthorizationRef, DidUrl, EventInitialSubmission, ProofAuthenticatedPublication,
    SignalEnvelope, event_spec,
};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use tokio::sync::mpsc::Sender;

#[cfg(any(feature = "web", test))]
use crate::app::AppletResolver;
use crate::authoring::{
    AuthoringJournal, AuthoringStore, PublicationRecord, ReceiverObservation, ScopeJournal,
    external_operation_key, merge_frontier, publication_outcome, scope_key,
};
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

/// The arkret edge client.
pub struct ArkretEdge {
    config: Arc<Config>,
    client: Client,
    signer: Ed25519PayloadSigner,
    /// Resolvable DID used for key lookup and proof `verification_method`.
    service_did: Did,
    /// Stable service actor core written into Event envelopes.
    service_actor_id: DidCoreId,
    /// Frozen service signer evidence retained in local configuration.
    signer_resolution_evidence_ref: arkret::SignerEvidenceRef,
    applet_id: AppletId,
    /// Durable accepted frontiers and immutable pending publications.
    journal: AuthoringJournal,
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
        store: Arc<dyn AuthoringStore>,
        inbound_tx: Sender<Event>,
    ) -> Result<Self> {
        let service_did = config.arkret.service_did.clone();
        let seed = config.signing_seed()?;
        // The signer's `kid` MUST be the absolute DID URL
        // `<service_did>#<fragment>`; `verification_method_fragment` is configured as
        // a bare fragment, so it is absolutized here instead of being handed to
        // the signer verbatim.
        let signer = Ed25519PayloadSigner::from_did_key_seed(
            seed,
            service_did.clone(),
            config.arkret.verification_method_for(&service_did)?,
        );
        let client = default_client(&config)?;
        Self::build(
            config,
            client,
            signer,
            service_did,
            seed,
            AuthoringJournal::new(store),
            Some(inbound_tx),
        )
    }

    /// Build an outbound-only edge from host-managed authenticated transport,
    /// signing material, and a reusable durable authoring journal.
    ///
    /// This is the integration path for hosts that own authentication and key
    /// storage. No inbound queues are allocated, and rebuilding an edge can
    /// reuse the same journal without discarding pending signed publications.
    ///
    /// Kept for the out-of-repo consumer `savfox`
    /// (`../../../savfox-ai/savfox/crates/gateway-server/src/channels/arkret_applet.rs`);
    /// do not delete it without checking that consumer first.
    pub fn new_outbound(
        config: Arc<Config>,
        client: Client,
        signer: Ed25519PayloadSigner,
        journal: AuthoringJournal,
    ) -> Result<Self> {
        let service_did = config.arkret.service_did.clone();
        let hlc_secret = signer.verifying_key().to_bytes();
        Self::build(
            config,
            client,
            signer,
            service_did,
            hlc_secret,
            journal,
            None,
        )
    }

    fn build(
        config: Arc<Config>,
        client: Client,
        signer: Ed25519PayloadSigner,
        service_did: Did,
        hlc_secret: [u8; 32],
        journal: AuthoringJournal,
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
        match service_did.method() {
            "webvh" => {}
            other => {
                return Err(BridgeError::Config(format!(
                    "service DID method `{other}` is not allowed; \
                     a bridge service DID must be did:webvh"
                )));
            }
        }

        let applet_id = AppletId::new(config.arkret.applet_id.clone())?;
        let service_actor_id = project_did_to_core_id(&service_did)?;
        let signer_resolution_evidence_ref = config.arkret.signer_resolution_evidence_ref.clone();
        let hlc_device_id = config.bridge.bridge_id.clone();

        Ok(Self {
            config,
            client,
            signer,
            service_did,
            service_actor_id,
            signer_resolution_evidence_ref,
            applet_id,
            journal,
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

    /// Applet service verification method used by Event, payload and aggregate
    /// proofs. Managed actors have separate root keys; this method only exposes
    /// the installed Applet service authority.
    pub fn service_verification_method(&self) -> Result<DidUrl> {
        self.verification_method_for_actor(&self.service_did)
    }

    /// Author the closed managed-actor creation unit with the installed Applet
    /// service authority. Event construction lives in the shared SDK kernel;
    /// this runtime wrapper keeps the service seed private.
    pub fn author_managed_actor_bundle(
        &self,
        request: &arkret::AppletManagedActorAuthoringRequest,
        input: arkret::AppletManagedActorBundleAuthoringInput,
    ) -> Result<arkret::AppletManagedActorAuthoringBundle> {
        Ok(arkret::author_applet_managed_actor_bundle(
            request,
            input,
            &self.signer,
        )?)
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
            arkret::ActorId::service(self.service_actor_id.clone()),
            content,
        )?
        .with_applet_id(self.applet_id.clone())
        .into_intent(chrono::Utc::now())?)
    }

    /// [`Self::service_intent`] with an explicit delegated actor and the
    /// durable authorization it acts under. The complete Account comes from
    /// provisioning; the Applet service identity cannot supply its Station.
    pub fn delegated_intent<K>(
        &self,
        actor: &arkret::AccountId,
        realm_id: &RealmId,
        content: K::Payload,
        authorization_ref: &str,
    ) -> Result<EventIntent>
    where
        K: EventSpec,
    {
        let authorization_ref = validate_authorization_ref(authorization_ref)?;
        actor.validate()?;
        Ok(TypedEventDraft::<K>::new(
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            arkret::ActorId::account(actor.clone()),
            content,
        )?
        .with_executed_by(arkret::ActorId::service(self.service_actor_id.clone()))
        .with_authorization_ref(authorization_ref)
        .with_applet_id(self.applet_id.clone())
        .into_intent(chrono::Utc::now())?)
    }

    /// Position `intent` on the service actor chain, derive its one identity,
    /// and attach the service proof.
    ///
    /// `operation_id` is the upstream delivery identity, stable across retries.
    /// Signed bytes are durable before this method returns.
    pub async fn author_and_sign(
        &self,
        realm_id: &RealmId,
        operation_id: &str,
        intent: EventIntent,
    ) -> Result<AuthoredEvent> {
        let auth_context = intent.auth_context().cloned().or_else(|| {
            self.config
                .arkret
                .ordinary_authoring_contexts
                .get(realm_id.as_str())
                .cloned()
        }).ok_or_else(|| {
            BridgeError::Arkret(format!(
                "frontier_unavailable: no locally retained authoring authority for Realm {realm_id}"
            ))
        })?;
        self.author_and_sign_with_auth_context(realm_id, operation_id, intent, auth_context)
            .await
    }

    /// Freeze an ordinary Event using retained authority and its accepted Actor frontier.
    /// Only the first use of an unknown scope asks the configured Station for a frontier.
    pub async fn author_and_sign_with_auth_context(
        &self,
        realm_id: &RealmId,
        operation_id: &str,
        intent: EventIntent,
        auth_context: AuthContext,
    ) -> Result<AuthoredEvent> {
        if operation_id.is_empty() || intent.realm_id_opt() != Some(realm_id) {
            return Err(BridgeError::App(
                "publication needs a stable operation id and exact Realm".into(),
            ));
        }
        if arkret::classify_intent_execution(&intent)
            .map_err(|error| BridgeError::Arkret(error.to_string()))?
            == Some(arkret::CbsEffectPlane::Control)
        {
            return Err(BridgeError::App(
                "ordinary authoring cannot publish a security command".into(),
            ));
        }
        auth_context.validate()?;
        let digest_suite = authority_digest_suite(&auth_context)?;
        if intent
            .auth_context()
            .is_some_and(|existing| existing != &auth_context)
        {
            return Err(BridgeError::Arkret(
                "ordinary intent carries a different authority context".into(),
            ));
        }
        let intent = intent.with_auth_context(auth_context);
        let key = scope_key(realm_id, intent.actor_id())?;
        for _ in 0..16 {
            let loaded = self.journal.load(&key).await?;
            let (raw, mut state) = match loaded {
                Some((raw, state)) => (Some(raw), state),
                None => {
                    let selector = EventsFrontierSelector::RealmActor {
                        realm_id: realm_id.clone(),
                        actor_id: intent.actor_id().clone(),
                    };
                    let resolved = self.client.events_frontier(&selector).await?;
                    let EventsFrontierView::RealmActor(frontier) = resolved.frontier else {
                        return Err(BridgeError::Arkret(
                            "frontier response has the wrong query domain".into(),
                        ));
                    };
                    frontier.validate_with_suite(digest_suite)?;
                    let state = ScopeJournal::new(frontier);
                    if !self.journal.cas(&key, None, &state).await? {
                        continue;
                    }
                    continue;
                }
            };
            if let Some(record) = self.journal.load_operation(&key, operation_id).await? {
                // Transport retries retain the original creation time, signature and authority.
                let mut retry_refs = intent.prev_refs().to_vec();
                retry_refs.extend(record.basis.frontier_event_ids.iter().cloned());
                retry_refs.sort();
                retry_refs.dedup();
                let retry = intent
                    .clone()
                    .with_prev_refs(retry_refs)
                    .with_created_at(record.intent.created_at());
                if !retry.authored_envelope_matches(record.authored.event()) {
                    return Err(BridgeError::App(
                        "operation id is already bound to different publication content".into(),
                    ));
                }
                return Ok(record.authored.clone());
            }
            if state.pending.is_some() {
                return Err(BridgeError::Arkret(
                    "frontier_unavailable: a previous exact publication is unresolved".into(),
                ));
            }
            state.frontier.validate_with_suite(digest_suite)?;
            if state.frontier.next_actor_seq == u64::MAX {
                return Err(BridgeError::Arkret("actor sequence exhausted".into()));
            }
            if state.candidates.iter().count()
                >= arkret_wire::event_envelope::MAX_ACTOR_SEQ_TOTAL_SIBLINGS
            {
                return Err(BridgeError::Arkret(
                    "frontier_unavailable: observed Actor position reached the sibling bound"
                        .into(),
                ));
            }
            let mut prev_refs = intent.prev_refs().to_vec();
            prev_refs.extend(state.frontier.frontier_event_ids.iter().cloned());
            prev_refs.sort();
            prev_refs.dedup();
            // Array equality is exact equality of the canonical prev_refs digest input.
            if state
                .candidates
                .iter()
                .filter(|record| record.prev_refs == prev_refs)
                .count()
                >= arkret_wire::event_envelope::MAX_ACTOR_SEQ_SIBLINGS
            {
                return Err(BridgeError::Arkret(
                    "frontier_unavailable: Actor predecessor bucket reached the sibling bound"
                        .into(),
                ));
            }
            let positioned = intent.clone().with_prev_refs(prev_refs);
            let mut event = positioned.clone().author_with_digest_suite(
                state.frontier.next_actor_seq,
                self.next_hlc(realm_id)?,
                digest_suite,
            )?;
            self.sign_as_service(&mut event)?;
            ProofAuthenticatedPublication::new(
                EventInitialSubmission::online(event.event().clone()),
                digest_suite,
            )?;
            state.pending = Some(operation_id.to_owned());
            state.operations.insert(
                operation_id.to_owned(),
                PublicationRecord {
                    basis: state.frontier.clone(),
                    intent: positioned,
                    authored: event.clone(),
                    outcome: None,
                    observations: vec![],
                    result_raw: None,
                    observation_count: 0,
                },
            );
            if self.journal.cas(&key, raw.as_deref(), &state).await? {
                return Ok(event);
            }
        }
        Err(BridgeError::Runtime(
            "ordinary authoring contention; retry the same operation".into(),
        ))
    }

    /// Recover a delivery before regenerating timestamps, encryption or other producer inputs.
    pub async fn retained_publication(
        &self,
        realm: &RealmId,
        actor: &arkret::ActorId,
        operation_id: &str,
    ) -> Result<Option<AuthoredEvent>> {
        let key = scope_key(realm, actor)?;
        Ok(self
            .journal
            .load_operation(&key, operation_id)
            .await?
            .map(|record| record.authored))
    }

    /// Resume immutable pending Events after a restart. No authoring/authority lookup occurs.
    pub async fn retry_pending_publications(&self) -> Result<()> {
        for event in self.journal.pending_events().await? {
            let submission = EventInitialSubmission::online(event.event().clone());
            if let Err(error) = self
                .submit_initial_with_policy(&submission, event.digest_suite(), false)
                .await
            {
                tracing::warn!(event_id = %event.event_id(), %error, "ordinary publication remains pending");
            }
        }
        Ok(())
    }

    /// Sign `event` with the service key. The signer verifies the authored
    /// identity against its own content and fails closed on a mismatch, so
    /// there is no signed-envelope mutation after this point.
    fn sign_as_service(&self, event: &mut AuthoredEvent) -> Result<()> {
        let verification_method = self.verification_method_for_actor(&self.service_did)?;
        sign_event(
            event,
            &self.signer,
            &verification_method,
            SignEventOptions::new(self.signer_resolution_evidence_ref.clone()),
        )?;
        Ok(())
    }

    fn verification_method_for_actor(&self, actor: &Did) -> Result<DidUrl> {
        self.config.arkret.verification_method_for(actor)
    }

    /// Submit a signed Event in an initial-publication wrapper and return its
    /// event id.
    ///
    /// The wrapper must equal the locally frozen SDK online publication.
    /// An arbitrary signed Event cannot bypass the durable authoring boundary.
    pub async fn submit_initial(
        &self,
        submission: &EventInitialSubmission,
        digest_suite: DigestSuite,
    ) -> Result<String> {
        self.submit_initial_with_policy(submission, digest_suite, true)
            .await
    }

    async fn submit_initial_with_policy(
        &self,
        submission: &EventInitialSubmission,
        digest_suite: DigestSuite,
        retry_rejected: bool,
    ) -> Result<String> {
        submission.validate_structural(digest_suite)?;
        let event =
            AuthoredEvent::from_verified_with_digest_suite(submission.event.clone(), digest_suite)?;
        let realm = event
            .scope_ref
            .realm_id_opt()
            .ok_or_else(|| BridgeError::App("ordinary publication lacks Realm".into()))?;
        let key = scope_key(realm, &event.actor_id)?;
        let (stored_scope, operation) = self
            .journal
            .operation_for_event(event.event_id())
            .await?
            .ok_or_else(|| {
            BridgeError::App("publication is outside the durable journal".into())
        })?;
        if stored_scope != key {
            return Err(BridgeError::Database(
                "publication scope index mismatch".into(),
            ));
        }
        let original = self
            .journal
            .load_operation(&key, &operation)
            .await?
            .ok_or_else(|| BridgeError::Database("frozen publication disappeared".into()))?;
        if original.authored.event() != event.event()
            || submission != &EventInitialSubmission::online(original.authored.event().clone())
        {
            return Err(BridgeError::App(
                "frozen publication bytes or wrapper changed".into(),
            ));
        }
        if original.outcome.as_ref().is_some_and(|outcome| {
            matches!(
                outcome.status,
                arkret_models_collaboration::http_bodies::EventsSubmitStatus::Accepted
                    | arkret_models_collaboration::http_bodies::EventsSubmitStatus::Duplicate
            )
        }) {
            return Ok(event.event_id().to_string());
        }
        // An explicit retry of a previously rejected delivery becomes pending
        // again before transport. Its original basis and bytes stay immutable.
        if original.outcome.is_some() {
            if !retry_rejected {
                return Err(BridgeError::App(
                    "automatic replay stopped after receiver-local rejection".into(),
                ));
            }
            let mut acquired = false;
            for _ in 0..16 {
                let (raw, mut state) = self.journal.load(&key).await?.ok_or_else(|| {
                    BridgeError::Database("publication journal disappeared".into())
                })?;
                if state
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending != &operation)
                {
                    return Err(BridgeError::Arkret(
                        "another ordinary publication is unresolved".into(),
                    ));
                }
                let mut record = self
                    .journal
                    .load_operation(&key, &operation)
                    .await?
                    .ok_or_else(|| BridgeError::Database("publication disappeared".into()))?;
                if let Some(outcome) = &record.outcome {
                    if publication_outcome(&event, outcome)?.is_some() {
                        return Ok(event.event_id().to_string());
                    }
                } else {
                    acquired = true;
                    break;
                }
                record.outcome = None;
                state.operations.insert(operation.clone(), record);
                state.pending = Some(operation.clone());
                if self.journal.cas(&key, Some(&raw), &state).await? {
                    acquired = true;
                    break;
                }
            }
            if !acquired {
                return Err(BridgeError::Runtime("publication retry contention".into()));
            }
        }
        let outcome = self.client.events_submit(submission).await?;
        let accepted = publication_outcome(&event, &outcome)?;
        for _ in 0..16 {
            let (raw, mut state) =
                self.journal.load(&key).await?.ok_or_else(|| {
                    BridgeError::Database("publication journal disappeared".into())
                })?;
            let mut record = self
                .journal
                .load_operation(&key, &operation)
                .await?
                .ok_or_else(|| BridgeError::Database("frozen operation disappeared".into()))?;
            if record.authored.event() != event.event() {
                return Err(BridgeError::Database("frozen publication changed".into()));
            }
            if let Some(previous) = &record.outcome {
                if publication_outcome(&event, previous)?.is_some() {
                    return Ok(event.event_id().to_string());
                }
            }
            record.observations.push(ReceiverObservation {
                receiver: self.config.arkret.trusted_server_did.clone(),
                outcome: outcome.clone(),
            });
            record.outcome = Some(outcome.clone());
            state.operations.insert(operation.clone(), record);
            if state.pending.as_deref() == Some(operation.as_str()) {
                state.pending = None;
            }
            if let Some(frontier) = &accepted {
                state.frontier = merge_frontier(&state.frontier, frontier, digest_suite)?;
            } else {
                for frontier in &outcome.frontiers {
                    state.frontier = merge_frontier(&state.frontier, frontier, digest_suite)?;
                }
            }
            if self.journal.cas(&key, Some(&raw), &state).await? {
                return if accepted.is_some() {
                    Ok(event.event_id().to_string())
                } else {
                    Err(BridgeError::App(format!(
                        "receiver rejected exact publication {}: {}",
                        event.event_id(),
                        outcome.rejections[0].reason_code.as_str()
                    )))
                };
            }
        }
        Err(BridgeError::Runtime(
            "acceptance persistence contention; retry exact publication".into(),
        ))
    }

    /// Wrap one exact signed ordinary Event locally, then submit it.
    pub async fn submit_event(&self, event: &AuthoredEvent) -> Result<String> {
        let digest_suite = event.digest_suite();
        let publication = ProofAuthenticatedPublication::new(
            EventInitialSubmission::online(event.event().clone()),
            digest_suite,
        )
        .map_err(|error| BridgeError::Arkret(error.to_string()))?;
        self.submit_initial(publication.submission(), digest_suite)
            .await
    }

    /// Return one coherent accepted Seal basis and its signed digest suite for
    /// authoring a Control Move. Both values come from the same frontier read.
    pub async fn realm_authoring_basis(
        &self,
        realm_id: &RealmId,
    ) -> Result<(arkret::SealBasis, DigestSuite)> {
        // `seals_frontier` fails closed on a realm mismatch or an
        // out-of-bounds frontier before returning.
        let frontier = self.client.seals_frontier(realm_id.clone()).await?.frontier;
        let seal_basis = frontier.seal_basis();
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
                selection:
                    arkret_models_collaboration::http_bodies::SealResolveSelection::SealRefs {
                        seal_refs: vec![leaf.clone()],
                    },
                history_traversal_access: None,
            })
            .await?;
        let seal = resolved
            .into_seals()?
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
        Ok((seal_basis, state_suite))
    }

    /// Outbound convenience with bridge provenance and an explicit delegated
    /// actor. Used by messaging bridges to submit per-user Ghost Actor events
    /// after provisioning returned a durable authorization ref.
    ///
    /// applet-integration §8 requires the signed Event Envelope top-level
    /// `external_ref` for bridge-originated events.
    pub async fn submit_with_external_ref_as<K, E>(
        &self,
        actor: &arkret::AccountId,
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
        let operation_id = external_operation_key(K::KIND_STR, &external_ref)?;
        if let Some(event) = self
            .retained_publication(
                &realm,
                &arkret::ActorId::account(actor.clone()),
                &operation_id,
            )
            .await?
        {
            return self.submit_event(&event).await;
        }
        let intent = self
            .delegated_intent::<K>(actor, &realm, content, authorization_ref)?
            .with_external_ref(external_ref);
        let event = self.author_and_sign(&realm, &operation_id, intent).await?;
        self.submit_event(&event).await
    }

    /// Submit a message redaction attributed to a delegated app actor. The
    /// redaction target travels in `content.message_id`, the single registered
    /// target carrier. External app expiry or retention drops must be filtered
    /// by callers before reaching this helper.
    pub async fn submit_redaction_with_external_ref_as<E>(
        &self,
        actor: &arkret::AccountId,
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
        let operation_id = external_operation_key("ak.message.redact", &external_ref)?;
        if let Some(event) = self
            .retained_publication(
                &realm,
                &arkret::ActorId::account(actor.clone()),
                &operation_id,
            )
            .await?
        {
            return self.submit_event(&event).await;
        }
        let intent = self
            .delegated_intent::<event_spec::MessageRedact>(
                actor,
                &realm,
                content,
                authorization_ref,
            )?
            .with_external_ref(external_ref);
        let event = self.author_and_sign(&realm, &operation_id, intent).await?;
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
        let failed = intent
            .payload()
            .get("failed_transaction_ref")
            .ok_or_else(|| {
                BridgeError::App("bridge error lacks upstream transaction identity".into())
            })?;
        let operation_id = serde_json::to_string(&("bridge_error", failed))?;
        let event = self
            .author_and_sign(realm_id, &operation_id, intent)
            .await?;
        self.submit_event(&event).await
    }

    /// Emit a bridge error from an explicitly retained local authority context.
    pub async fn submit_bridge_error_with_auth_context(
        &self,
        realm_id: &RealmId,
        builder: arkret_event_draft::AppletBridgeErrorBuilder,
        auth_context: AuthContext,
    ) -> Result<String> {
        let intent = builder
            .build(chrono::Utc::now())?
            .with_applet_id(self.applet_id.clone())
            .with_auth_context(auth_context);
        let failed = intent
            .payload()
            .get("failed_transaction_ref")
            .ok_or_else(|| {
                BridgeError::App("bridge error lacks upstream transaction identity".into())
            })?;
        let operation_id = serde_json::to_string(&("bridge_error", failed))?;
        let event = self
            .author_and_sign(realm_id, &operation_id, intent)
            .await?;
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

fn authority_digest_suite(auth_context: &AuthContext) -> Result<DigestSuite> {
    let mut suites = auth_context.authority_refs.iter().map(|authority_ref| {
        let digest = authority_ref
            .as_str()
            .strip_prefix("ak:seal:")
            .ok_or_else(|| {
                BridgeError::Arkret("authority reference is not a Seal id".to_owned())
            })?;
        arkret::Hash::new(digest.to_owned())?
            .digest_suite()
            .map_err(|error| BridgeError::Arkret(error.to_string()))
    });
    let suite = suites.next().ok_or_else(|| {
        BridgeError::Arkret("ordinary authority context has no references".to_owned())
    })??;
    for candidate in suites {
        if candidate? != suite {
            return Err(BridgeError::Arkret(
                "ordinary authority references use different digest suites".to_owned(),
            ));
        }
    }
    Ok(suite)
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
    crate::install_default_crypto_provider();
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
    service_did: Did,
    trust_domain: arkret::TrustDomainId,
    transport_base_url: String,
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
        let service_did = edge.service_did.clone();
        Ok(Self {
            applet_id: edge.applet_id.clone(),
            service_did: service_did.clone(),
            trust_domain: edge.config.arkret.trust_domain.clone(),
            transport_base_url: format!("http://{}", edge.config.bridge.admin_addr()),
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
            service_id: project_did_to_core_id(&self.service_did)
                .map_err(|error| WireError::Protocol(error.to_string()))?,
            protocol_version: arkret::PROTOCOL_VERSION.to_owned(),
        })
    }

    fn describe(&self) -> std::result::Result<ServiceDescribe, WireError> {
        let service_kind = arkret::ServiceKind::AppletService;
        let describe_bundle = arkret_wire::role_describe_bundle_descriptor(service_kind)
            .expect("Applet service describe bundle is registered")
            .operation_bundle_id
            .to_owned();
        let mut description = ServiceDescribe::development(
            self.service_did.clone(),
            self.trust_domain.clone(),
            service_kind,
            vec![describe_bundle],
            vec![TransportBinding::HttpJson {
                base_url: self.transport_base_url.clone(),
                extension_profile_required: (),
            }],
        );
        description.supported_profiles = vec![ProfileId::APPLET_SERVICE_V1.to_owned()];
        description.validate()?;
        Ok(description)
    }

    fn handle_transaction(
        &self,
        _idempotency_key: &str,
        req: AppletTransactionRequestBody,
    ) -> std::result::Result<AppletTransactionOutcome, WireError> {
        let event_count = req.events.len();
        let mut rejections: Vec<arkret::AppletEventRejection> = Vec::new();
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
                rejections.push(arkret::AppletEventRejection {
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
                rejections.push(arkret::AppletEventRejection {
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
                rejections.push(arkret::AppletEventRejection {
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
                    rejections.push(arkret::AppletEventRejection {
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
                    rejections.push(arkret::AppletEventRejection {
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
                    rejections.push(arkret::AppletEventRejection {
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
                    rejections.push(arkret::AppletEventRejection {
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
            status: if rejections.is_empty() {
                arkret_models_integration::AppletTransactionStatus::Accepted
            } else if rejections.len() == event_count {
                arkret_models_integration::AppletTransactionStatus::Rejected
            } else {
                arkret_models_integration::AppletTransactionStatus::Partial
            },
            rejections,
            retry_after_ms,
        })
    }

    fn resolve_actor(&self, actor_id: &str) -> std::result::Result<AppletActorView, WireError> {
        // The resolver returns the stable Ghost identity that was bound to the
        // required DID during provisioning.
        if let Some(resolved) = self
            .resolver
            .as_ref()
            .and_then(|r| r.resolve_actor(actor_id))
        {
            return Ok(AppletActorView {
                exists: true,
                actor_id: Some(resolved.actor_id),
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

    fn test_edge(store: Arc<dyn AuthoringStore>) -> ArkretEdge {
        let config: Config = serde_json::from_value(json!({
            "bridge": {"bridge_id": "test"},
            "arkret": {
                "server_url": "https://station.example", "service_did": "did:webvh:z6mkbridge:bridge.example",
                "trust_domain": "ak:trust_domain:example.net", "applet_id": "ak:applet:01904100-0000-7000-8000-000000000001",
                "access_token": "test", "signing_key_seed_hex": "11".repeat(32),
                "verification_method_fragment": "#key-1",
                "signer_resolution_evidence_ref": format!("ak:signer_evidence:sha256:{}", "11".repeat(32)),
                "trusted_server_did": "did:webvh:z6mkstation:station.example",
                "applet_namespaces": {"actors":[],"realms":[],"handles":[]},
                "managed_actor_authoring": {"principal_endpoint":"https://ghost.example", "key_encryption_key_hex":"22".repeat(32)}
            }
        })).unwrap();
        let (sender, _) = tokio::sync::mpsc::channel(1);
        ArkretEdge::new(Arc::new(config), store, sender).unwrap()
    }

    #[derive(Default)]
    struct MemoryAuthoringStore(Mutex<BTreeMap<String, String>>);
    impl AuthoringStore for MemoryAuthoringStore {
        fn load(&self, scope: &str) -> Result<Option<String>> {
            Ok(self.0.lock().get(scope).cloned())
        }
        fn compare_exchange_batch(
            &self,
            expected: &[(String, Option<String>)],
            writes: &[(String, Option<String>)],
        ) -> Result<bool> {
            let mut entries = self.0.lock();
            if expected
                .iter()
                .any(|(key, value)| entries.get(key) != value.as_ref())
            {
                return Ok(false);
            }
            for (key, value) in writes {
                match value {
                    Some(value) => {
                        entries.insert(key.clone(), value.clone());
                    }
                    None => {
                        entries.remove(key);
                    }
                }
            }
            Ok(true)
        }
        fn entries_with_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>> {
            Ok(self
                .0
                .lock()
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect())
        }
    }

    fn ordinary_context() -> AuthContext {
        AuthContext {
            key_id: arkret::OpaqueLocalId::new("bridge-key").unwrap(),
            key_epoch: 0,
            credential_epoch: None,
            authority_refs: vec![
                arkret::SealId::new(format!("ak:seal:sha256:{}", "07".repeat(32))).unwrap(),
            ],
        }
    }
    fn message_intent(edge: &ArkretEdge, realm: &RealmId, text: &str) -> EventIntent {
        edge.service_intent::<event_spec::MessageCreate>(
            realm,
            arkret::MessageCreatePayload::with_content(
                arkret::StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9")
                    .unwrap(),
                "main",
                arkret::ContentBlock::text(text),
            ),
        )
        .unwrap()
        .with_auth_context(ordinary_context())
    }
    async fn seed_empty_scope(
        edge: &ArkretEdge,
        realm: &RealmId,
        actor: &arkret::ActorId,
    ) -> String {
        let key = scope_key(realm, actor).unwrap();
        let frontier = arkret_models_collaboration::event_sync::RealmActorFrontierView::new(
            realm.clone(),
            actor.clone(),
            0,
            vec![],
            DigestSuite::Sha256,
        )
        .unwrap();
        assert!(
            edge.journal
                .cas(&key, None, &ScopeJournal::new(frontier))
                .await
                .unwrap()
        );
        key
    }
    fn accepted_outcome(
        event: &AuthoredEvent,
        siblings: Vec<arkret::EventId>,
    ) -> arkret_models_collaboration::http_bodies::EventsSubmitOutcome {
        use arkret_models_collaboration::event_sync::RealmActorFrontierView;
        use arkret_models_collaboration::http_bodies::{EventsSubmitOutcome, EventsSubmitStatus};
        EventsSubmitOutcome {
            status: EventsSubmitStatus::Accepted,
            accepted: vec![event.event_id().clone()],
            pending_delivery_count: 0,
            ingress_receipts: vec![],
            control_proposal_acks: vec![],
            duplicate: vec![],
            rejections: vec![],
            quarantine: vec![],
            frontiers: vec![
                RealmActorFrontierView::new(
                    event.realm_id.clone(),
                    event.actor_id.clone(),
                    event.actor_seq + 1,
                    siblings,
                    event.digest_suite(),
                )
                .unwrap(),
            ],
            cursor: None,
            original_outcome: None,
            agent_membership_cascade: None,
        }
    }

    #[tokio::test]
    async fn ordinary_authoring_restarts_at_exact_frontier_and_freezes_unknown_bytes() {
        let store = Arc::new(MemoryAuthoringStore::default());
        let edge = test_edge(store.clone());
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let intent = message_intent(&edge, &realm, "first");
        let key = seed_empty_scope(&edge, &realm, intent.actor_id()).await;
        let first = edge
            .author_and_sign(&realm, "delivery-one", intent.clone())
            .await
            .unwrap();
        assert_eq!(first.actor_seq, 0);
        assert!(first.prev_refs.is_empty());
        assert!(
            edge.author_and_sign(
                &realm,
                "delivery-two",
                message_intent(&edge, &realm, "second")
            )
            .await
            .is_err()
        );
        let bytes = serde_json::to_vec(&first).unwrap();
        drop(edge);
        let edge = test_edge(store.clone());
        let retry = edge
            .author_and_sign(&realm, "delivery-one", intent)
            .await
            .unwrap();
        assert_eq!(serde_json::to_vec(&retry).unwrap(), bytes);
        assert_eq!(
            serde_json::to_vec(&edge.journal.pending_events().await.unwrap()[0]).unwrap(),
            bytes
        );
        // Acceptance with an observed concurrent sibling must position the next Event
        // over the complete set, not just the locally authored predecessor.
        let sibling = arkret::EventId::from_digest(DigestSuite::Sha256, [4; 32]);
        let mut siblings = vec![first.event_id().clone(), sibling];
        siblings.sort();
        let outcome = accepted_outcome(&first, siblings.clone());
        let (raw, mut state) = edge.journal.load(&key).await.unwrap().unwrap();
        state.frontier = publication_outcome(&first, &outcome).unwrap().unwrap();
        state
            .operations
            .entry("delivery-one".into())
            .or_insert(
                edge.journal
                    .load_operation(&key, "delivery-one")
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .outcome = Some(outcome);
        state.pending = None;
        assert!(edge.journal.cas(&key, Some(&raw), &state).await.unwrap());
        drop(edge);
        let edge = test_edge(store);
        let second = edge
            .author_and_sign(
                &realm,
                "delivery-two",
                message_intent(&edge, &realm, "second"),
            )
            .await
            .unwrap();
        assert_eq!(second.actor_seq, 1);
        assert_eq!(second.prev_refs, siblings);
        let retry = edge
            .author_and_sign(
                &realm,
                "delivery-two",
                message_intent(&edge, &realm, "second"),
            )
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_vec(&retry).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
    }

    #[tokio::test]
    async fn ordinary_frontier_scope_keeps_both_account_station_and_realm() {
        let store = Arc::new(MemoryAuthoringStore::default());
        let edge = test_edge(store);
        let realm_a =
            RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let realm_b =
            RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap();
        let principal = DidCoreId::new("ak:did_core:web:holder.example").unwrap();
        let account_a = arkret::ActorId::account(arkret::AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:a.example").unwrap(),
        ));
        let account_b = arkret::ActorId::account(arkret::AccountId::new(
            principal,
            DidCoreId::new("ak:did_core:web:b.example").unwrap(),
        ));
        let first = seed_empty_scope(&edge, &realm_a, &account_a).await;
        let second = seed_empty_scope(&edge, &realm_a, &account_b).await;
        let third = seed_empty_scope(&edge, &realm_b, &account_a).await;
        assert_ne!(first, second);
        assert_ne!(first, third);
        assert_eq!(
            edge.journal
                .store
                .entries_with_prefix("head/")
                .unwrap()
                .len(),
            3
        );
    }

    #[tokio::test]
    async fn submit_acceptance_requires_exact_event_and_complete_matching_frontier() {
        let store = Arc::new(MemoryAuthoringStore::default());
        let edge = test_edge(store);
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let intent = message_intent(&edge, &realm, "hello");
        seed_empty_scope(&edge, &realm, intent.actor_id()).await;
        let event = edge
            .author_and_sign(&realm, "delivery", intent)
            .await
            .unwrap();
        let good = accepted_outcome(&event, vec![event.event_id().clone()]);
        assert!(publication_outcome(&event, &good).unwrap().is_some());
        let mut missing = good.clone();
        missing.frontiers.clear();
        assert!(publication_outcome(&event, &missing).is_err());
        let mut wrong_id = good.clone();
        wrong_id.accepted[0] = arkret::EventId::from_digest(DigestSuite::Sha256, [8; 32]);
        assert!(publication_outcome(&event, &wrong_id).is_err());
        let mut wrong_actor = good.clone();
        wrong_actor.frontiers[0].actor_id =
            arkret::ActorId::service(DidCoreId::new("ak:did_core:web:other.example").unwrap());
        assert!(publication_outcome(&event, &wrong_actor).is_err());
        assert_eq!(edge.journal.pending_events().await.unwrap().len(), 1);
    }

    fn rejected_outcome(
        event: &AuthoredEvent,
    ) -> arkret_models_collaboration::http_bodies::EventsSubmitOutcome {
        use arkret_models_collaboration::http_bodies::{
            EventsSubmitRejectedRow, EventsSubmitStatus,
        };
        let mut outcome = accepted_outcome(event, vec![event.event_id().clone()]);
        outcome.status = EventsSubmitStatus::Partial;
        outcome.accepted.clear();
        outcome.frontiers.clear();
        outcome.rejections.push(EventsSubmitRejectedRow {
            index: Some(0),
            id: event.event_id().to_string(),
            reason_code: arkret::ReasonCode::from_wire("actor_signature_revoked"),
            detail: None,
            missing_event_ids: vec![],
            missing_seal_refs: vec![],
            missing_event_digests: vec![],
        });
        outcome
    }

    #[tokio::test]
    async fn receiver_rejection_releases_slot_without_burning_or_rewriting_old_event() {
        let store = Arc::new(MemoryAuthoringStore::default());
        let edge = test_edge(store);
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let intent = message_intent(&edge, &realm, "identical text");
        let key = seed_empty_scope(&edge, &realm, intent.actor_id()).await;
        let old = edge
            .author_and_sign(&realm, "old-key-delivery", intent)
            .await
            .unwrap();
        let old_bytes = serde_json::to_vec(&old).unwrap();
        let rejected = rejected_outcome(&old);
        assert!(publication_outcome(&old, &rejected).unwrap().is_none());
        let (raw, mut state) = edge.journal.load(&key).await.unwrap().unwrap();
        state
            .operations
            .entry("old-key-delivery".into())
            .or_insert(
                edge.journal
                    .load_operation(&key, "old-key-delivery")
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .outcome = Some(rejected);
        state.pending = None;
        assert!(edge.journal.cas(&key, Some(&raw), &state).await.unwrap());
        assert!(edge.journal.pending_events().await.unwrap().is_empty());
        let new = edge
            .author_and_sign(
                &realm,
                "new-key-delivery",
                message_intent(&edge, &realm, "identical text"),
            )
            .await
            .unwrap();
        assert_eq!(new.actor_seq, old.actor_seq);
        assert!(new.prev_refs.is_empty());
        // Different logical deliveries of the same text are not deduplicated.
        assert_ne!(new.event_id(), old.event_id());
        // A later acceptance of the old sibling must not rewrite the new frozen basis.
        let accepted = accepted_outcome(&old, vec![old.event_id().clone()]);
        let (raw, mut state) = edge.journal.load(&key).await.unwrap().unwrap();
        state
            .operations
            .entry("old-key-delivery".into())
            .or_insert(
                edge.journal
                    .load_operation(&key, "old-key-delivery")
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .outcome = Some(accepted.clone());
        state.frontier =
            merge_frontier(&state.frontier, &accepted.frontiers[0], old.digest_suite()).unwrap();
        assert!(edge.journal.cas(&key, Some(&raw), &state).await.unwrap());
        assert_eq!(edge.journal.pending_events().await.unwrap()[0], new);
        assert_eq!(
            serde_json::to_vec(
                &edge
                    .retained_publication(&realm, &old.actor_id, "old-key-delivery")
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            old_bytes
        );
    }

    #[tokio::test]
    async fn same_predecessor_bucket_limits_new_candidates_but_not_exact_retry() {
        let store = Arc::new(MemoryAuthoringStore::default());
        let edge = test_edge(store);
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let intent = message_intent(&edge, &realm, "first");
        let key = seed_empty_scope(&edge, &realm, intent.actor_id()).await;
        for index in 0..arkret_wire::event_envelope::MAX_ACTOR_SEQ_SIBLINGS {
            let operation = format!("delivery-{index}");
            let event = edge
                .author_and_sign(
                    &realm,
                    &operation,
                    message_intent(&edge, &realm, &operation),
                )
                .await
                .unwrap();
            let (raw, mut state) = edge.journal.load(&key).await.unwrap().unwrap();
            state
                .operations
                .entry(operation.clone())
                .or_insert(
                    edge.journal
                        .load_operation(&key, &operation)
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .outcome = Some(rejected_outcome(&event));
            state.pending = None;
            assert!(edge.journal.cas(&key, Some(&raw), &state).await.unwrap());
        }
        assert!(
            edge.author_and_sign(&realm, "too-many", message_intent(&edge, &realm, "extra"))
                .await
                .is_err()
        );
        assert!(
            edge.author_and_sign(
                &realm,
                "delivery-0",
                message_intent(&edge, &realm, "delivery-0")
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn durable_engine_failure_prevents_publication_and_restart_retains_original() {
        use crate::file_authoring_store::tests::{FaultBackend, fault_store};
        let backend = FaultBackend::default();
        let store = Arc::new(fault_store(backend.clone()));
        let edge = test_edge(store.clone());
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let intent = message_intent(&edge, &realm, "frozen before transport");
        let key = seed_empty_scope(&edge, &realm, intent.actor_id()).await;
        let original = edge
            .author_and_sign(&realm, "delivery", intent)
            .await
            .unwrap();
        let original_bytes = serde_json::to_vec(&original).unwrap();
        let (raw, mut state) = edge.journal.load(&key).await.unwrap().unwrap();
        let mut record = edge
            .journal
            .load_operation(&key, "delivery")
            .await
            .unwrap()
            .unwrap();
        record.outcome = Some(rejected_outcome(&original));
        state.pending = None;
        state.operations.insert("delivery".into(), record);
        backend.fail_sync();
        assert!(edge.journal.cas(&key, Some(&raw), &state).await.is_err());
        // This is the real public send path. The poisoned storage read returns
        // before Client::events_submit; it never retries from visible RAM pages.
        let error = edge.submit_event(&original).await.unwrap_err();
        assert!(error.to_string().contains("poisoned"));
        assert!(
            edge.retained_publication(&realm, &original.actor_id, "delivery")
                .await
                .is_err()
        );
        drop(edge);
        drop(store);
        backend.power_loss();
        let edge = test_edge(Arc::new(fault_store(backend)));
        let recovered = edge
            .retained_publication(&realm, &original.actor_id, "delivery")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(serde_json::to_vec(&recovered).unwrap(), original_bytes);
    }

    #[tokio::test]
    async fn delegated_intent_preserves_the_provisioned_account_station() {
        struct NoAuthoring;
        impl AuthoringStore for NoAuthoring {
            fn load(&self, _: &str) -> Result<Option<String>> {
                panic!("intent must not access authoring state")
            }
            fn compare_exchange_batch(
                &self,
                _: &[(String, Option<String>)],
                _: &[(String, Option<String>)],
            ) -> Result<bool> {
                panic!("intent must not mutate authoring state")
            }
            fn entries_with_prefix(&self, _: &str) -> Result<Vec<(String, String)>> {
                panic!("intent must not scan authoring state")
            }
        }
        let edge = test_edge(Arc::new(NoAuthoring));
        let account = arkret::AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkghost").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkstation").unwrap(),
        );
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let payload = arkret::MessageCreatePayload::with_content(
            arkret::StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9")
                .unwrap(),
            "main",
            arkret::ContentBlock::text("hello"),
        );
        let grant = "ak:grant:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let intent = edge
            .delegated_intent::<event_spec::MessageCreate>(&account, &realm, payload, grant)
            .unwrap();
        assert_eq!(intent.actor_id(), &arkret::ActorId::account(account));
        assert_eq!(
            intent.executed_by(),
            Some(&arkret::ActorId::service(edge.service_actor_id.clone()))
        );
    }

    #[test]
    fn event_fingerprint_ignores_unsigned_and_proofs() {
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let actor =
            project_did_to_core_id(&Did::new("did:webvh:z6mkfixture:alice.example").unwrap())
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

    fn test_proof(jws: &str) -> arkret::ProducerEventProof {
        arkret::ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1")
                .expect("fixture verification method is a valid DID URL"),
            event_digest: arkret::Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            signer_resolution_evidence_ref: Some(
                arkret::SignerEvidenceRef::new(format!(
                    "ak:signer_evidence:sha256:{}",
                    "11".repeat(32)
                ))
                .expect("fixture signer evidence ref"),
            ),
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: jws.to_owned(),
        }
    }
}
