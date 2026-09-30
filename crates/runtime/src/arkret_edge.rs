//! The arkret protocol-side edge (replaces the Matrix bridge's
//! `MatrixAppservice`).
//!
//! - **Outbound (app -> arkret)**: [`ArkretEdge::service_intent`] and
//!   [`ArkretEdge::delegated_intent`] build complete producer `EventIntent`s;
//!   [`ArkretEdge::author_and_sign`] derives the one content-bound identity and signs it, then
//!   [`ArkretEdge::submit_event`] hands it to the current governance Station as an
//!   `EventAdmissionSubmission` and retains the authority-signed commit reference.
//! - **Inbound (arkret → app)**: transactions pushed by the arkret server via the applet HTTP
//!   endpoints are placed into the `inbound_tx` queue by [`BridgeAppletHandler`]; after the core
//!   consumes them they are forwarded to the app adapter.
//! - **Media**: [`ArkretEdge::upload_blob`] / [`ArkretEdge::download_blob`].
//!
//! A host injects a durable [`crate::AuthoringJournal`] so retries retain the
//! exact signed Event bytes and the exact committed reference without requiring
//! diesel. The producer side holds no predecessor, position, or basis: the
//! Station's `RealmCommit` is the only ordering fact.

use std::collections::BTreeMap;
use std::sync::Arc;

use arkret::http_client::{Auth, Client};
#[cfg(any(feature = "web", test))]
use arkret::identity::public_key_material_from_binding;
#[cfg(any(feature = "web", test))]
use arkret::signatures::{EventProofBuilder, VerificationMethodDocument};
use arkret::signatures::{PublicKeyMaterial, SignEventOptions, sign_event};
use arkret::{
    AppletId, AuthoredEvent, ClientRequestOptions, Did, DidCoreId, DigestSuite,
    Ed25519PayloadSigner, Event, EventIntent, RealmId, ScopeRef, WireError, project_did_to_core_id,
};
use arkret_event_draft::{EventSpec, TypedEventDraft};
use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_models_collaboration::events_payloads::MessageRedactPayload;
#[cfg(any(feature = "web", test))]
use arkret_models_discovery::{ServiceDescribe, TransportBinding};
#[cfg(any(feature = "web", test))]
use arkret_models_integration::AppletTransactionRequestBody;
#[cfg(any(feature = "web", test))]
use arkret_models_integration::{
    AppletActorView, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome, AppletWireNamespaces,
};
use arkret_models_integration::{
    AppletAuthoringTransactionRequestBody, AppletManagedActorCommittedRequest,
};
#[cfg(any(feature = "web", test))]
use arkret_wire::ProfileId;
use arkret_wire::{
    AuthorityRejectionStatus, AuthoritySubmitOutcome, AuthorizationRef, DidUrl,
    EventAdmissionSubmission, SignalEnvelope, event_spec,
};
use serde::Serialize;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use tokio::sync::mpsc::Sender;

#[cfg(any(feature = "web", test))]
use crate::app::AppletResolver;
use crate::authoring::{
    AuthoringJournal, AuthoringStore, ManagedAuthoringIdentity, PublicationRecord,
    external_operation_key, publication_outcome, scope_key, validate_managed_authoring_completion,
    validate_prepared_ghost_signer,
};
use crate::authority::{LocalServiceManagedActorProofVerifier, validate_managed_actor_bundle};
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

/// Digest suite used for producer Event identities authored by this bridge.
///
/// Public so that every producer path in this workspace -- including the
/// managed-actor authoring unit, which is signed outside this module -- uses
/// one suite instead of each caller picking its own.
pub const PRODUCER_DIGEST_SUITE: DigestSuite = DigestSuite::Sha256;

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
    applet_id: AppletId,
    /// Immutable frozen publications and their exact committed references.
    journal: AuthoringJournal,
    /// Identity of the governance Station this edge submits to. Recorded with
    /// every observed answer so a Station replacement is visible in the journal.
    station_id: DidCoreId,
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
        Self::build(config, client, signer, service_did, journal, None)
    }

    fn build(
        config: Arc<Config>,
        client: Client,
        signer: Ed25519PayloadSigner,
        service_did: Did,
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

        let applet_id = AppletId::new(config.arkret.applet_id.as_str())?;
        let service_actor_id = project_did_to_core_id(&service_did)?;
        let station_id = project_did_to_core_id(&config.arkret.trusted_server_did)?;

        Ok(Self {
            config,
            client,
            signer,
            service_did,
            service_actor_id,
            applet_id,
            journal,
            station_id,
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

    /// The installed Applet service signing key.
    ///
    /// The four-Event managed-actor creation unit is authored by this service
    /// authority, and `arkret`'s authoring API takes the signer by reference,
    /// so the key is exposed here rather than copied. Managed-actor root keys
    /// are separate material and never travel through this accessor.
    pub fn signer(&self) -> &Ed25519PayloadSigner {
        &self.signer
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

    /// The inbound event sender (bounded), if this edge was built with one.
    pub fn inbound_sender(&self) -> Option<Sender<Event>> {
        self.inbound_tx.clone()
    }

    /// The Signal sender, if installed.
    pub fn signal_sender(&self) -> Option<Sender<SignalEnvelope>> {
        self.signal_tx.clone()
    }

    /// Current validated managed-Actor authoring material for one exact Actor
    /// in one effective security scope. The result is read from the same
    /// durable store used by the inbound completion CAS, so rebuilding the
    /// edge does not lose it.
    pub fn installed_managed_authoring(
        &self,
        effective_scope: &ScopeRef,
        actor_id: &arkret::ActorId,
    ) -> Result<Option<AppletAuthoringTransactionRequestBody>> {
        self.journal
            .load_managed_authoring(&ManagedAuthoringIdentity {
                applet_id: self.applet_id.clone(),
                actor_id: actor_id.clone(),
                effective_scope: effective_scope.clone(),
            })
    }

    /// Freeze the exact locally authored install/Ghost request and bundle that
    /// a later Station completion must echo. Returns `true` only for the first
    /// durable preparation and `false` for an exact replay.
    pub fn prepare_managed_authoring(
        &self,
        committed_request: &AppletManagedActorCommittedRequest,
        managed_actor_verification_method: &DidUrl,
        managed_actor_public_key: &PublicKeyMaterial,
    ) -> Result<bool> {
        let locally_created = match committed_request {
            AppletManagedActorCommittedRequest::Ghost(_) => true,
            AppletManagedActorCommittedRequest::Install(install) => matches!(
                install.as_ref(),
                arkret_models_integration::AppletInstallRequestBody::Create(_)
            ),
        };
        if !locally_created {
            return Err(BridgeError::App(
                "only locally authored creation requests can prepare new managed identity material"
                    .into(),
            ));
        }
        validate_prepared_ghost_signer(
            managed_actor_verification_method,
            managed_actor_public_key,
        )?;
        self.journal.prepare_managed_authoring(
            committed_request,
            managed_actor_verification_method,
            managed_actor_public_key,
        )
    }

    /// Install a managed Actor completion using the host's configured own-Station
    /// verification method and actual key. This shares the bridge HTTP verifier
    /// and atomic journal with outbound-only hosts such as Savfox.
    pub fn install_managed_authoring_completion(
        &self,
        body: &AppletAuthoringTransactionRequestBody,
        source_verification_method: &DidUrl,
        source_public_key: &PublicKeyMaterial,
    ) -> Result<()> {
        let identity = validate_managed_authoring_completion(
            body,
            &self.station_id,
            &self.applet_id,
            &self.service_actor_id,
        )
        .map_err(BridgeError::App)?;
        if self
            .journal
            .is_exact_managed_authoring_replay(&identity, body)?
        {
            return Ok(());
        }
        let attester = &body
            .authoring_context
            .managed_actor_signer_evidence
            .attester_signer_evidence;
        if &attester.verification_method != source_verification_method {
            return Err(BridgeError::App(
                "completion attester differs from configured own-Station method".into(),
            ));
        }
        verify_managed_authoring_closure(
            body,
            &self.service_actor_id,
            &self.service_verification_method()?,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: self.signer.verifying_key().to_bytes().to_vec(),
            },
            &self.journal,
            source_public_key,
        )
        .map_err(|error| BridgeError::App(error.to_string()))?;
        self.journal.install_managed_authoring(&identity, body)?;
        Ok(())
    }

    /// The complete service-actor write for `content`. Applet-originated writes
    /// carry the top-level `applet_id` in the signed envelope.
    ///
    /// A write is an [`EventIntent`] until [`Self::author_and_sign`] derives its
    /// identity: hosts fill in producer-signed members (`created_at`,
    /// `external_ref`, encrypted content) HERE, because the Event's identity is
    /// derived from them exactly once and nothing may rewrite it afterwards.
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
        self.delegated_intent_in_scope::<K>(
            actor,
            &ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            content,
            authorization_ref,
        )
    }

    /// A Circle completion authorizes that exact Circle; a Realm completion
    /// cannot substitute for its scope-specific installed authoring context.
    pub fn delegated_intent_in_scope<K>(
        &self,
        actor: &arkret::AccountId,
        scope: &ScopeRef,
        content: K::Payload,
        authorization_ref: &str,
    ) -> Result<EventIntent>
    where
        K: EventSpec,
    {
        let authorization_ref = validate_authorization_ref(authorization_ref)?;
        actor.validate()?;
        let actor_id = arkret::ActorId::account(actor.clone());
        if self.journal.is_locally_managed_actor(&actor_id)? {
            let installed = self.installed_managed_authoring(scope, &actor_id)?.ok_or_else(||
                BridgeError::Runtime("managed Actor completion remains pending; retain the original publication for retry".into()))?;
            let grant_is_installed = match &installed.authoring_context.committed_request {
                // A Ghost's creation grant only authorizes provisioning. Its
                // ordinary action-specific capability comes from the host's
                // original authorization record and the receiving Station gate.
                AppletManagedActorCommittedRequest::Ghost(_) => true,
                AppletManagedActorCommittedRequest::Install(install) => install
                    .authoring_request()
                    .basis
                    .install()
                    .is_some_and(|basis| {
                        basis.capability_grant_events.iter().any(|event| {
                            arkret_wire::GrantId::from_event_id(&event.event_id).as_str()
                                == authorization_ref.as_str()
                        })
                    }),
            };
            if !grant_is_installed {
                return Err(BridgeError::App(
                    "managed Actor authorization is outside its exact installed scope grants"
                        .into(),
                ));
            }
            let root = &installed
                .authoring_context
                .applet_service_signer_evidence
                .authenticated_signer_evidence;
            let actual = PublicKeyMaterial::Jwk {
                value: serde_json::to_value(&root.public_key_jwk)?,
            };
            if root.subject_id != self.service_actor_id
                || root.verification_method != self.service_verification_method()?
                || actual.ed25519_bytes()? != *self.signer.verifying_key().as_bytes()
            {
                return Err(BridgeError::App(
                    "managed Actor ordinary authoring requires its installed exact Service root"
                        .into(),
                ));
            }
        }
        Ok(TypedEventDraft::<K>::new(
            scope.clone(),
            arkret::ActorId::account(actor.clone()),
            content,
        )?
        .with_executed_by(arkret::ActorId::service(self.service_actor_id.clone()))
        .with_authorization_ref(authorization_ref)
        .with_applet_id(self.applet_id.clone())
        .into_intent(chrono::Utc::now())?)
    }

    /// Derive the one content-bound identity of `intent` and attach the service
    /// proof. The Event carries no predecessor, position, or basis.
    ///
    /// `operation_id` is the upstream delivery identity, stable across retries.
    /// Signed bytes are durable before this method returns.
    pub async fn author_and_sign(
        &self,
        realm_id: &RealmId,
        operation_id: &str,
        intent: EventIntent,
    ) -> Result<AuthoredEvent> {
        if operation_id.is_empty() || intent.realm_id_opt() != Some(realm_id) {
            return Err(BridgeError::App(
                "publication needs a stable operation id and exact Realm".into(),
            ));
        }
        let key = scope_key(realm_id, intent.actor_id())?;
        if let Some(record) = self.journal.load_operation(&key, operation_id).await? {
            // A transport retry reuses the frozen creation time; everything else
            // must be identical or the operation id is being reused for new
            // content, which would silently publish a different Event.
            let retry = intent.clone().with_created_at(record.intent.created_at());
            if !retry.matches_authored_event(record.authored.event()) {
                return Err(BridgeError::App(
                    "operation id is already bound to different publication content".into(),
                ));
            }
            return Ok(record.authored.clone());
        }
        // Freeze the same canonical timestamp that SDK Event authoring signs.
        // Keeping a nanosecond intent would disagree with its millisecond Event.
        let created_at = arkret::canonical::normalize_timestamp_canonical(intent.created_at());
        let intent = intent.with_created_at(created_at);
        let mut event = intent
            .clone()
            .author_with_digest_suite(PRODUCER_DIGEST_SUITE)?;
        self.sign_as_service(&mut event)?;
        let record = PublicationRecord::new(intent, event.clone());
        if self.journal.freeze(&key, operation_id, &record).await? {
            return Ok(event);
        }
        // Another writer froze this operation id first. Its bytes win, and the
        // content equality check above still applies to them.
        match self.journal.load_operation(&key, operation_id).await? {
            Some(record) => Ok(record.authored),
            None => Err(BridgeError::Runtime(
                "authoring contention; retry the same operation".into(),
            )),
        }
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

    /// Resume immutable pending Events after a restart. No re-authoring occurs.
    pub async fn retry_pending_publications(&self) -> Result<()> {
        for event in self.journal.pending_events().await? {
            if let Err(error) = self.submit_to_station(&event, false).await {
                tracing::warn!(event_id = %event.event_id(), %error, "publication remains pending");
            }
        }
        Ok(())
    }

    /// Sign `event` with the service key. The signer verifies the authored
    /// identity against its own content and fails closed on a mismatch, so
    /// there is no signed-envelope mutation after this point.
    fn sign_as_service(&self, event: &mut AuthoredEvent) -> Result<()> {
        sign_event(event, &self.signer, SignEventOptions::new())?;
        Ok(())
    }

    fn verification_method_for_actor(&self, actor: &Did) -> Result<DidUrl> {
        self.config.arkret.verification_method_for(actor)
    }

    /// Hand one exact signed Event to the current governance Station and return
    /// its event id once the Station's authority-signed commit covers it.
    ///
    /// Only a publication already frozen in the durable journal can be sent: an
    /// arbitrary signed Event cannot bypass the authoring boundary.
    pub async fn submit_event(&self, event: &AuthoredEvent) -> Result<String> {
        self.submit_to_station(event, true).await
    }

    async fn submit_to_station(
        &self,
        event: &AuthoredEvent,
        retry_rejected: bool,
    ) -> Result<String> {
        let key = scope_key(&event.realm_id, &event.actor_id)?;
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
        if original.authored.event() != event.event() {
            return Err(BridgeError::App("frozen publication bytes changed".into()));
        }
        // An accepted publication keeps its exact committed reference forever.
        if let Some(committed) = &original.committed {
            return Ok(committed.event_id.to_string());
        }
        // An explicit retry of a Station-rejected delivery becomes replayable
        // again before transport. Its original bytes stay immutable.
        if original.outcome.is_some() {
            if !retry_rejected {
                return Err(BridgeError::App(
                    "automatic replay stopped after a terminal Station rejection".into(),
                ));
            }
            if !self.journal.reopen(&key, &operation).await? {
                return Err(BridgeError::Runtime("publication retry contention".into()));
            }
        }
        let request =
            SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(event.event().clone()));
        let options = ClientRequestOptions::new().idempotency_key(event.event_id().as_str());
        let outcome = self
            .client
            .submit_to_realm_authority(&request, &options)
            .await?;
        let SelfAuthoritySubmitOutcome::Ordinary(outcome) = outcome else {
            return Err(BridgeError::Arkret(
                "ordinary Event submission returned an aggregate outcome".to_owned(),
            ));
        };
        // A retryable answer settles nothing: the frozen bytes stay replayable
        // and the pending index is left in place for the recovery loop.
        let committed = publication_outcome(event, &outcome)?;
        if !self
            .journal
            .record_outcome(
                &key,
                &operation,
                &self.station_id,
                &outcome,
                committed.as_ref(),
            )
            .await?
        {
            return Err(BridgeError::Runtime(
                "answer persistence contention; retry the exact publication".into(),
            ));
        }
        match committed {
            Some(committed) => Ok(committed.event_id.to_string()),
            None => Err(BridgeError::App(format!(
                "governance Station rejected publication {}: {}",
                event.event_id(),
                rejection_reason(&outcome)
            ))),
        }
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
    /// the caller; this derives the Event identity, signs it with the service
    /// key, and submits it to the current governance Station. Returns the new
    /// event_id.
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

    /// The configured applet id this bridge presents to arkret.
    pub fn applet_id(&self) -> &str {
        self.applet_id.as_str()
    }

    /// Plaintext media upload: returns the blob reference string.
    pub async fn upload_blob(&self, bytes: &[u8], mime: &str) -> Result<String> {
        let meta = arkret_models_collaboration::objects::blob::BlobUploadMetadata {
            realm_id: None,
            content_digest: None,
            size_bytes: bytes.len() as u64,
            media_type: Some(mime.to_owned()),
            filename: None,
            encryption: None,
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

/// The Station reason code carried by a terminal rejection.
fn rejection_reason(outcome: &AuthoritySubmitOutcome) -> &str {
    match outcome {
        AuthoritySubmitOutcome::Rejected {
            status: AuthorityRejectionStatus::Rejected,
            reason_code,
        } => reason_code.as_str(),
        _ => "unspecified",
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
    service_id: DidCoreId,
    service_verification_method: DidUrl,
    service_public_key: PublicKeyMaterial,
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
    /// Durable managed-Actor completion installation shares the edge's atomic
    /// store with frozen outbound authoring material.
    journal: AuthoringJournal,
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
        let service_id = project_did_to_core_id(&service_did)
            .map_err(|error| BridgeError::Config(error.to_string()))?;
        Ok(Self {
            applet_id: edge.applet_id.clone(),
            service_id,
            service_verification_method: edge.service_verification_method()?,
            service_public_key: PublicKeyMaterial::Ed25519Raw {
                bytes: edge.signer.verifying_key().to_bytes().to_vec(),
            },
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
            journal: edge.journal.clone(),
        })
    }

    /// Verify the part of the accepted authoring closure this runtime can prove
    /// from local material. The service leaf must name the key actually held by
    /// this process. A Ghost leaf must also match the root VM/key derived from
    /// the locally encrypted identity and frozen before handoff. The exact
    /// prepared four-Event bundle and its aggregate proof must verify under the
    /// Applet Service key held by this process. The attester leaf is rebuilt
    /// from the accepted own-Station Service binding. Create and Ghost require
    /// their locally prepared exact unit; reuse requires the original anchors.
    fn verify_local_managed_authoring_closure(
        &self,
        body: &AppletAuthoringTransactionRequestBody,
    ) -> std::result::Result<(), WireError> {
        let attester = &body
            .authoring_context
            .managed_actor_signer_evidence
            .attester_signer_evidence;
        let accepted = self
            .did_authority
            .service_verification_method(&attester.verification_method, chrono::Utc::now())
            .map_err(WireError::Protocol)?;
        if project_did_to_core_id(accepted.binding().did())? != body.source_id {
            return Err(WireError::Protocol(
                "managed Actor attester is not its own Station".into(),
            ));
        }
        let source_key = public_key_material_from_binding(&accepted, &attester.verification_method)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        verify_managed_authoring_closure(
            body,
            &self.service_id,
            &self.service_verification_method,
            &self.service_public_key,
            &self.journal,
            &source_key,
        )
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

fn verify_managed_authoring_closure(
    body: &AppletAuthoringTransactionRequestBody,
    service_id: &DidCoreId,
    service_verification_method: &DidUrl,
    service_public_key: &PublicKeyMaterial,
    journal: &AuthoringJournal,
    source_public_key: &PublicKeyMaterial,
) -> std::result::Result<(), WireError> {
    let service_evidence = &body
        .authoring_context
        .applet_service_signer_evidence
        .authenticated_signer_evidence;
    let reported_key = PublicKeyMaterial::Jwk {
        value: serde_json::to_value(&service_evidence.public_key_jwk)
            .map_err(|error| WireError::Protocol(error.to_string()))?,
    };
    let reported_key = reported_key
        .ed25519_bytes()
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    let local_key = service_public_key
        .ed25519_bytes()
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    if service_evidence.verification_method != *service_verification_method
        || reported_key != local_key
    {
        return Err(WireError::Protocol(
            "authoring completion Applet Service evidence differs from the local signing key"
                .to_owned(),
        ));
    }

    let canonical_jwk =
        |key: [u8; 32]| -> std::result::Result<arkret_wire::NonEmptyJsonObject, WireError> {
            serde_json::from_value(serde_json::json!({"kty":"OKP", "crv":"Ed25519", "x":arkret::canonical::base64url_encode(key)}))
                .map_err(|error| WireError::Protocol(error.to_string()))
        };
    let recomputed_service = arkret::build_service_signer_evidence(
        service_id.clone(),
        service_verification_method.clone(),
        canonical_jwk(local_key)?,
        service_evidence.authority_commit_id.clone(),
        service_evidence.resolved_at,
    )?;
    if recomputed_service != *service_evidence {
        return Err(WireError::Protocol(
            "Applet Service root differs from exact local material".into(),
        ));
    }

    let managed_evidence = &body
        .authoring_context
        .managed_actor_signer_evidence
        .authenticated_signer_evidence;
    if managed_evidence.authority_commit_id
        != body.authoring_context.principal_control_commit.commit_id
    {
        return Err(WireError::Protocol(
            "managed Actor signer evidence is not bound to the reported Realm head".to_owned(),
        ));
    }

    journal
        .verify_prepared_managed_signer(body)
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    let key = PublicKeyMaterial::Jwk {
        value: serde_json::to_value(&managed_evidence.public_key_jwk)
            .map_err(|error| WireError::Protocol(error.to_string()))?,
    };
    let key = key
        .ed25519_bytes()
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    let recomputed_principal = arkret::build_principal_signer_evidence(
        managed_evidence.subject_id.clone(),
        managed_evidence.verification_method.clone(),
        canonical_jwk(key)?,
        body.authoring_context
            .principal_control_commit
            .commit_id
            .clone(),
        managed_evidence.resolved_at,
    )?;
    if recomputed_principal != *managed_evidence {
        return Err(WireError::Protocol(
            "managed Principal root differs from exact prepared material".into(),
        ));
    }

    let creation = match &body.authoring_context.committed_request {
        AppletManagedActorCommittedRequest::Ghost(ghost) => {
            Some((&ghost.authoring_request, &ghost.managed_actor_bundle))
        }
        AppletManagedActorCommittedRequest::Install(install) => match install.as_ref() {
            arkret_models_integration::AppletInstallRequestBody::Create(create) => {
                Some((&create.authoring_request, &create.managed_actor_bundle))
            }
            _ => None,
        },
    };
    let verifier = LocalServiceManagedActorProofVerifier::new(
        service_id.clone(),
        service_verification_method.clone(),
        service_public_key.clone(),
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    if let Some((request, bundle)) = creation {
        validate_managed_actor_bundle(request, bundle, &verifier)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
    }

    // An ordinary producer consumes the exact own-Station result. The
    // accepted Service binding authenticates that source key; this does
    // not install independent governance trust or authorize another Realm.
    let attester = &body
        .authoring_context
        .managed_actor_signer_evidence
        .attester_signer_evidence;
    let actual = source_public_key
        .ed25519_bytes()
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    let jwk: arkret_wire::NonEmptyJsonObject = serde_json::from_value(serde_json::json!({
        "kty":"OKP", "crv":"Ed25519", "x":arkret::canonical::base64url_encode(actual),
    }))
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    let recomputed = arkret::build_service_signer_evidence(
        body.source_id.clone(),
        attester.verification_method.clone(),
        jwk,
        body.authoring_context
            .principal_control_commit
            .commit_id
            .clone(),
        attester.resolved_at,
    )?;
    if recomputed != *attester {
        return Err(WireError::Protocol(
            "managed Actor attester root differs from accepted Station material".into(),
        ));
    }
    let pcr = &body.authoring_context.principal_control_commit;
    if pcr.signature.verification_method != attester.verification_method {
        return Err(WireError::Protocol(
            "PCR Commit is signed by another Station method".into(),
        ));
    }
    arkret::signatures::detached_object::verify_detached_object_signature(
        &pcr.signature,
        &arkret::canonical::unsigned_value(pcr, &["signature"])?,
        arkret::DetachedSignatureContext::RealmCommit,
        source_public_key,
    )
    .map_err(|error| WireError::Protocol(error.to_string()))?;
    Ok(())
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
        let req = match req {
            AppletTransactionRequestBody::Authoring(body) => {
                let identity = validate_managed_authoring_completion(
                    &body,
                    &body.source_id,
                    &self.applet_id,
                    &self.service_id,
                )
                .map_err(WireError::Protocol)?;
                if self
                    .journal
                    .is_exact_managed_authoring_replay(&identity, &body)
                    .map_err(|error| WireError::Protocol(error.to_string()))?
                {
                    return Ok(AppletTransactionOutcome {
                        status: arkret_models_integration::AppletTransactionStatus::Accepted,
                        committed_event_refs: Vec::new(),
                        rejections: Vec::new(),
                        retry_after_ms: None,
                    });
                }
                self.verify_local_managed_authoring_closure(&body)?;
                self.journal
                    .install_managed_authoring(&identity, &body)
                    .map_err(|error| WireError::Protocol(error.to_string()))?;
                return Ok(AppletTransactionOutcome {
                    status: arkret_models_integration::AppletTransactionStatus::Accepted,
                    committed_event_refs: Vec::new(),
                    rejections: Vec::new(),
                    retry_after_ms: None,
                });
            }
            AppletTransactionRequestBody::Events(req) => req,
        };
        if !req.events.is_empty() {
            return Err(WireError::Protocol(
                "Station-to-Applet delivery requires full committed Event pairs".into(),
            ));
        }
        let mut delivery_refs = BTreeMap::new();
        let mut delivery_events = Vec::with_capacity(req.committed_events.len());
        for pair in req.committed_events {
            let proof = pair.event.producer_proof.as_ref().ok_or_else(|| {
                WireError::Protocol("accepted delivery lacks producer proof".into())
            })?;
            let producer_key = if let Some(key) =
                crate::authority::committed_delivery_device_key(&proof.verification_method)
                    .map_err(|error| WireError::Protocol(error.to_string()))?
            {
                key
            } else if proof.verification_method == self.service_verification_method {
                self.service_public_key.clone()
            } else {
                let accepted = self
                    .did_authority
                    .service_verification_method(&proof.verification_method, chrono::Utc::now())
                    .map_err(WireError::Protocol)?;
                public_key_material_from_binding(&accepted, &proof.verification_method)
                    .map_err(|error| WireError::Protocol(error.to_string()))?
            };
            let accepted_governance = self
                .did_authority
                .service_verification_method(
                    &pair.commit.signature.verification_method,
                    chrono::Utc::now(),
                )
                .map_err(WireError::Protocol)?;
            let governance_key = public_key_material_from_binding(
                &accepted_governance,
                &pair.commit.signature.verification_method,
            )
            .map_err(|error| WireError::Protocol(error.to_string()))?;
            let reference = crate::authority::validate_applet_committed_delivery(
                &pair,
                PRODUCER_DIGEST_SUITE,
                &producer_key,
                &governance_key,
            )
            .map_err(|error| WireError::Protocol(error.to_string()))?;
            if delivery_refs
                .get(&pair.event.event_id)
                .is_some_and(|existing| existing != &reference)
            {
                return Err(WireError::Protocol(
                    "one delivery Event has conflicting Commit coordinates".into(),
                ));
            }
            delivery_refs.insert(pair.event.event_id.clone(), reference);
            delivery_events.push(pair.event);
        }
        let event_count = delivery_events.len();
        let mut committed_event_refs = Vec::new();
        let mut rejections: Vec<arkret::AppletEventRejection> = Vec::new();
        let mut enqueue_failed = false;
        // Set when the bounded inbound queue is full: we ask the server to retry
        // the whole batch shortly (backpressure) rather than buffering without
        // limit or dropping events.
        let mut queue_full = false;

        for event in delivery_events {
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
                    committed_event_refs.push(delivery_refs[&event.event_id].clone());
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
        if let Some(tx) = self.signal_tx.as_ref() {
            for envelope in req.signals {
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
            committed_event_refs,
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
    use std::sync::Mutex;

    use arkret::{
        DidDocument, NonEmptyJsonObject, PayloadSigner, build_principal_signer_evidence,
        build_service_signer_evidence,
    };
    use arkret_models_integration::{
        AppletApprovalRequest, AppletDidMethodVersionEvidence, AppletEndpointAuth,
        AppletEndpointEntry, AppletEndpointMethod, AppletGhostActorMode,
        AppletInstallAuthoringRequestBasis, AppletInstallRequestBody,
        AppletInstallReuseRequestBody, AppletManagedActorAuthoringContext,
        AppletManagedActorAuthoringRequest, AppletManagedActorCommittedRequest,
        AppletManagedActorPurpose, AppletPackage, AppletRegistrationEpochEvidence,
        AppletServiceSignerEvidence, AppletWireNamespaces, ManagedActorPrincipalSignerEvidence,
        ReuseExistingManagedActor,
    };
    use arkret_wire::{
        Base64UrlString, CommitStreamRef, DetachedObjectSignature, DetachedSignatureAlgorithm,
        DetachedSignatureContext, EventId, PayloadSignature, RealmCommit, RealmCommitAuthorityRef,
    };

    use super::*;

    struct AlwaysFreshDedup;

    impl EventDedupStore for AlwaysFreshDedup {
        fn check_and_record(&self, _event_id: &str, _fingerprint: i64) -> Result<DedupVerdict> {
            Ok(DedupVerdict::Fresh)
        }
    }

    fn test_edge(store: Arc<dyn AuthoringStore>) -> ArkretEdge {
        let config: Config = serde_json::from_value(json!({
            "bridge": {"bridge_id": "test"},
            "arkret": {
                "server_url": "https://station.example", "service_did": "did:webvh:z6mkbridge:bridge.example",
                "trust_domain": "ak:trust_domain:example.net", "applet_id": "ak:applet:01904100-0000-7000-8000-000000000001",
                "access_token": "test", "signing_key_seed_hex": "11".repeat(32),
                "verification_method_fragment": "#key-1",
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
        fn load(&self, key: &str) -> Result<Option<String>> {
            Ok(self.0.lock().expect("store lock").get(key).cloned())
        }
        fn compare_exchange_batch(
            &self,
            expected: &[(String, Option<String>)],
            writes: &[(String, Option<String>)],
        ) -> Result<bool> {
            let mut entries = self.0.lock().expect("store lock");
            for (key, value) in expected {
                if entries.get(key) != value.as_ref() {
                    return Ok(false);
                }
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
            let entries = self.0.lock().expect("store lock");
            let mut selected: Vec<(String, String)> = entries
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            selected.sort();
            Ok(selected)
        }
    }

    struct StubPayloadSigner {
        did: Did,
        verification_method: DidUrl,
    }

    impl PayloadSigner for StubPayloadSigner {
        fn signer_did(&self) -> &Did {
            &self.did
        }

        fn verification_method_id(&self) -> &DidUrl {
            &self.verification_method
        }

        fn sign_payload(&self, canonical_bytes: &[u8]) -> arkret_wire::Result<PayloadSignature> {
            let payload_digest =
                arkret::Hash::new(arkret::canonical::sha256_digest(canonical_bytes))?;
            Ok(PayloadSignature {
                verification_method: self.verification_method.clone(),
                payload_digest: payload_digest.clone(),
                created_at: "2026-09-16T00:00:00Z".parse().unwrap(),
                jws: format!(
                    "eyJhbGciOiJFZDI1NTE5In0..{}",
                    payload_digest
                        .as_str()
                        .strip_prefix("sha256:")
                        .expect("test digest has the registered prefix")
                ),
            })
        }
    }

    fn test_jwk() -> NonEmptyJsonObject {
        NonEmptyJsonObject::new(BTreeMap::from([
            ("kty".to_owned(), json!("OKP")),
            ("crv".to_owned(), json!("Ed25519")),
            (
                "x".to_owned(),
                json!("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
            ),
        ]))
        .unwrap()
    }

    fn test_jwk_for_key(key: [u8; 32]) -> NonEmptyJsonObject {
        NonEmptyJsonObject::new(BTreeMap::from([
            ("kty".to_owned(), json!("OKP")),
            ("crv".to_owned(), json!("Ed25519")),
            (
                "x".to_owned(),
                json!(arkret::canonical::base64url_encode(key)),
            ),
        ]))
        .unwrap()
    }

    fn test_committed_ref(realm_id: &RealmId, seed: u8) -> arkret::CommittedEventRef {
        arkret::CommittedEventRef {
            event_id: EventId::from_digest(DigestSuite::Sha256, [seed; 32]),
            commit_id: arkret::RealmCommitId::from_digest([seed.wrapping_add(1); 32]),
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            stream_position: u64::from(seed),
        }
    }

    fn managed_authoring_fixture(
        edge: &ArkretEdge,
    ) -> (AppletAuthoringTransactionRequestBody, arkret::ActorId) {
        let realm_id =
            RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let managed_principal = DidCoreId::new("ak:did_core:webvh:z6mkmanagedbot").unwrap();
        let managed_actor = arkret::ActorId::account(arkret::AccountId::new(
            managed_principal.clone(),
            edge.station_id.clone(),
        ));
        let controller = DidCoreId::new("ak:did_core:webvh:z6mkcontroller").unwrap();
        let mut package = AppletPackage::new(
            "test-managed-authoring",
            edge.applet_id.clone(),
            edge.service_actor_id.clone(),
            edge.service_did.clone(),
            controller,
            "https://bridge.example",
            managed_actor.clone(),
            vec!["test".into()],
            AppletWireNamespaces::default(),
        );
        package.requested_scopes = vec!["ak.message.create".into()];
        package.endpoint_policy.endpoints.push(AppletEndpointEntry {
            method: AppletEndpointMethod::Post,
            path: "/_arkret/edge/applet/transactions".into(),
            auth: Some(AppletEndpointAuth::WebhookSignature),
            description: None,
            extra: Default::default(),
        });
        let registration_epoch_evidence = AppletRegistrationEpochEvidence::from_did_document(
            &DidDocument::new(
                edge.service_did.clone(),
                "applet-webhook",
                "z6MkrJVnaZkeF7EsnJQ9xQY4bqG9tbeFqTzL7uTVs11FwUjT",
            ),
            AppletDidMethodVersionEvidence::versioned(
                "did:webvh",
                Some("test-registration-version".into()),
                None,
            )
            .unwrap(),
        )
        .unwrap();
        package
            .stamp_registration_epoch(&registration_epoch_evidence)
            .unwrap();
        package.stamp_package_digest().unwrap();
        let requested_at = "2026-09-16T00:00:00Z".parse().unwrap();
        let scope = ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let registration_event = arkret_wire::test_support::raw_event_at(
            "ak.applet.registration",
            scope.clone(),
            edge.service_actor_id.clone(),
            edge.station_id.clone(),
            json!({"manifest": {"registration_epoch_evidence": registration_epoch_evidence}}),
            requested_at,
        )
        .unwrap();
        let grant_event = arkret_wire::test_support::raw_event_at(
            "ak.capability.grant",
            scope.clone(),
            edge.service_actor_id.clone(),
            edge.station_id.clone(),
            json!({}),
            requested_at,
        )
        .unwrap();
        let basis = AppletInstallAuthoringRequestBasis {
            schema: AppletInstallAuthoringRequestBasis::SCHEMA.to_owned(),
            purpose: AppletManagedActorPurpose::InstallBot,
            target_station_id: edge.station_id.clone(),
            install_actor_id: arkret::ActorId::service(edge.service_actor_id.clone()),
            applet_id: edge.applet_id.clone(),
            service_id: edge.service_actor_id.clone(),
            package_digest: package.package_digest.clone().unwrap(),
            effective_scope: scope,
            approval_request: AppletApprovalRequest {
                approve_actions: vec!["ak.message.create".into()],
                ghost_actor_mode: AppletGhostActorMode::Disallowed,
                delegated_native_actors_allowed: false,
                e2ee_join_allowed: false,
                widget_allowed: false,
            },
            actor_policy: None,
            e2ee_policy: None,
            widget_policy: None,
            registration_event,
            capability_grant_events: vec![grant_event],
        };
        let station_did = Did::new("did:webvh:z6mkstation:station.example").unwrap();
        let signer = StubPayloadSigner {
            did: station_did.clone(),
            verification_method: DidUrl::new(format!("{station_did}#key-1")).unwrap(),
        };
        let request = AppletManagedActorAuthoringRequest::sign(
            basis,
            arkret::Hash::new(format!("sha256:{}", "44".repeat(32))).unwrap(),
            edge.station_id.clone(),
            requested_at,
            requested_at + chrono::Duration::minutes(5),
            &signer,
        )
        .unwrap();
        let reuse = ReuseExistingManagedActor {
            actor_id: managed_actor.clone(),
            managed_actor_provision_ref: test_committed_ref(&realm_id, 1).event_id,
            pcr_genesis_ref: test_committed_ref(&realm_id, 2).event_id,
            accountability_grant_ref: test_committed_ref(&realm_id, 3).event_id,
            profile_event_ref: test_committed_ref(&realm_id, 4).event_id,
            initial_package_bot_actor_id: managed_actor.clone(),
        };
        let committed_request =
            AppletInstallRequestBody::Reuse(Box::new(AppletInstallReuseRequestBody {
                applet_package: package,
                authoring_request: request,
                reuse_existing_managed_actor: reuse,
            }));
        let commit_id = arkret::RealmCommitId::from_digest([0x2c; 32]);
        let applet_evidence = build_service_signer_evidence(
            edge.service_actor_id.clone(),
            edge.service_verification_method().unwrap(),
            test_jwk_for_key(edge.signer.verifying_key().to_bytes()),
            commit_id.clone(),
            requested_at,
        )
        .unwrap();
        let principal_evidence = build_principal_signer_evidence(
            managed_principal,
            DidUrl::new("did:webvh:z6mkmanagedbot:bot.example#key-1").unwrap(),
            test_jwk(),
            commit_id.clone(),
            requested_at,
        )
        .unwrap();
        let attester_evidence = build_service_signer_evidence(
            edge.station_id.clone(),
            signer.verification_method,
            test_jwk(),
            commit_id.clone(),
            requested_at,
        )
        .unwrap();
        (
            AppletAuthoringTransactionRequestBody {
                applet_id: edge.applet_id.clone(),
                source_id: edge.station_id.clone(),
                authoring_context: AppletManagedActorAuthoringContext {
                    committed_request: AppletManagedActorCommittedRequest::Install(Box::new(
                        committed_request,
                    )),
                    realm_stream_head: arkret::CommitStreamHead {
                        stream_ref: CommitStreamRef::Realm {
                            realm_id: realm_id.clone(),
                        },
                        stream_position: 41,
                        commit_id,
                    },
                    principal_control_commit: RealmCommit {
                        commit_id: arkret::RealmCommitId::from_digest([0x2c; 32]),
                        realm_id: realm_id.clone(),
                        stream_ref: CommitStreamRef::Realm {
                            realm_id: realm_id.clone(),
                        },
                        stream_position: 0,
                        previous_commit_ref: None,
                        event_ref: test_committed_ref(&realm_id, 2).event_id,
                        governance_generation: 0,
                        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(
                            test_committed_ref(&realm_id, 2).event_id,
                        ),
                        committed_at: requested_at,
                        signature: commit_signature(DetachedSignatureContext::RealmCommit),
                    },
                    resolution_update: None,
                    applet_service_signer_evidence: AppletServiceSignerEvidence {
                        signer_resolution_evidence_ref: applet_evidence
                            .signer_evidence_ref()
                            .unwrap(),
                        authenticated_signer_evidence: applet_evidence,
                    },
                    managed_actor_signer_evidence: ManagedActorPrincipalSignerEvidence {
                        signer_resolution_evidence_ref: principal_evidence
                            .signer_evidence_ref()
                            .unwrap(),
                        authenticated_signer_evidence: principal_evidence,
                        attester_signer_evidence: attester_evidence,
                    },
                },
            },
            managed_actor,
        )
    }

    #[test]
    fn managed_authoring_reuse_requires_original_creation_and_exact_roots() {
        let store = Arc::new(MemoryAuthoringStore::default());
        let edge = test_edge(store.clone());
        let (body, managed_actor) = managed_authoring_fixture(&edge);
        let handler = BridgeAppletHandler::new(
            &edge,
            None,
            Arc::new(AlwaysFreshDedup),
            None,
            Arc::new(DidAuthority::new(edge.config.arkret.trust_domain.clone()).unwrap()),
        )
        .unwrap();
        let identity = validate_managed_authoring_completion(
            &body,
            &edge.station_id,
            &edge.applet_id,
            &edge.service_actor_id,
        )
        .unwrap();

        assert!(
            arkret::AppletHandler::handle_transaction(
                &handler,
                "cold-reuse",
                AppletTransactionRequestBody::Authoring(Box::new(body.clone())),
            )
            .is_err(),
            "Reuse without the first Bot identity anchors must remain unresolved"
        );
        assert!(store.0.lock().unwrap().is_empty());

        let mut fake_jwk = body.clone();
        let service_evidence = &mut fake_jwk.authoring_context.applet_service_signer_evidence;
        service_evidence
            .authenticated_signer_evidence
            .public_key_jwk = test_jwk();
        service_evidence.signer_resolution_evidence_ref = service_evidence
            .authenticated_signer_evidence
            .signer_evidence_ref()
            .unwrap();
        assert!(
            arkret::AppletHandler::handle_transaction(
                &handler,
                "fake-jwk",
                AppletTransactionRequestBody::Authoring(Box::new(fake_jwk)),
            )
            .is_err()
        );
        assert!(store.0.lock().unwrap().is_empty());

        let mut fake_method = body.clone();
        let service_evidence = &mut fake_method.authoring_context.applet_service_signer_evidence;
        service_evidence
            .authenticated_signer_evidence
            .verification_method =
            DidUrl::new("did:webvh:z6mkbridge:bridge.example#other-key".to_owned()).unwrap();
        service_evidence.signer_resolution_evidence_ref = service_evidence
            .authenticated_signer_evidence
            .signer_evidence_ref()
            .unwrap();
        assert!(
            arkret::AppletHandler::handle_transaction(
                &handler,
                "fake-method",
                AppletTransactionRequestBody::Authoring(Box::new(fake_method)),
            )
            .is_err()
        );
        assert!(store.0.lock().unwrap().is_empty());

        let mut fake_commit = body.clone();
        let evidence = &mut fake_commit.authoring_context.managed_actor_signer_evidence;
        let wrong_commit = arkret::RealmCommitId::from_digest([0x7f; 32]);
        evidence.authenticated_signer_evidence.authority_commit_id = wrong_commit.clone();
        evidence.attester_signer_evidence.authority_commit_id = wrong_commit;
        evidence.signer_resolution_evidence_ref = evidence
            .authenticated_signer_evidence
            .signer_evidence_ref()
            .unwrap();
        assert!(
            arkret::AppletHandler::handle_transaction(
                &handler,
                "fake-commit",
                AppletTransactionRequestBody::Authoring(Box::new(fake_commit)),
            )
            .is_err()
        );
        assert!(store.0.lock().unwrap().is_empty());

        let mut invalid = body.clone();
        invalid
            .authoring_context
            .managed_actor_signer_evidence
            .signer_resolution_evidence_ref = arkret::SignerEvidenceRef::new(format!(
            "ak:signer_evidence:sha256:{}",
            "00".repeat(32)
        ))
        .unwrap();
        assert!(
            validate_managed_authoring_completion(
                &invalid,
                &edge.station_id,
                &edge.applet_id,
                &edge.service_actor_id,
            )
            .is_err()
        );
        assert!(
            store.0.lock().unwrap().is_empty(),
            "invalid evidence wrote state"
        );

        assert!(
            edge.journal
                .install_managed_authoring(&identity, &body)
                .is_err(),
            "authenticated delivery must not replace local authoring preparation"
        );
        assert!(store.0.lock().unwrap().is_empty());
        let managed_evidence = &body
            .authoring_context
            .managed_actor_signer_evidence
            .authenticated_signer_evidence;
        let managed_key = PublicKeyMaterial::Jwk {
            value: serde_json::to_value(&managed_evidence.public_key_jwk).unwrap(),
        };
        assert!(
            edge.journal
                .prepare_managed_authoring(
                    &body.authoring_context.committed_request,
                    &managed_evidence.verification_method,
                    &managed_key,
                )
                .unwrap()
        );
        assert!(
            !edge
                .journal
                .prepare_managed_authoring(
                    &body.authoring_context.committed_request,
                    &managed_evidence.verification_method,
                    &managed_key,
                )
                .unwrap()
        );

        let rows_after_preparation = store.0.lock().unwrap().clone();
        assert!(
            edge.journal
                .install_managed_authoring(&identity, &body)
                .is_err(),
            "preparing a Reuse request cannot manufacture its original Bot creation"
        );
        assert_eq!(*store.0.lock().unwrap(), rows_after_preparation);
        assert!(
            edge.installed_managed_authoring(&identity.effective_scope, &managed_actor)
                .unwrap()
                .is_none()
        );
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
        .with_authorization_ref(
            AuthorizationRef::new(
                arkret::GrantId::from_event_id(
                    &arkret::EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                        .unwrap(),
                )
                .to_string(),
            )
            .unwrap(),
        )
    }

    fn commit_signature(context: DetachedSignatureContext) -> DetachedObjectSignature {
        DetachedObjectSignature {
            context,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: DidUrl::new("did:webvh:z6mkstation:station.example#key-1")
                .unwrap(),
            signed_digest: arkret::Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap(),
            created_at: "2026-09-16T00:00:00Z".parse().unwrap(),
            sig: Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
        }
    }

    /// One accepted Realm-stream commit for `event` at `position`.
    fn accepted(event: &AuthoredEvent, position: u64) -> AuthoritySubmitOutcome {
        AuthoritySubmitOutcome::Accepted {
            status: arkret_wire::AuthorityCommitStatus::Committed,
            commit: RealmCommit {
                commit_id: arkret::RealmCommitId::from_digest([position as u8 + 1; 32]),
                realm_id: event.realm_id.clone(),
                stream_ref: CommitStreamRef::Realm {
                    realm_id: event.realm_id.clone(),
                },
                stream_position: position,
                previous_commit_ref: (position > 0)
                    .then(|| arkret::RealmCommitId::from_digest([position as u8; 32])),
                event_ref: event.event_id().clone(),
                governance_generation: 1,
                authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    arkret::EventId::from_digest(DigestSuite::Sha256, [7; 32]),
                ),
                committed_at: "2026-09-16T00:00:00Z".parse().unwrap(),
                signature: commit_signature(DetachedSignatureContext::RealmCommit),
            },
        }
    }

    fn rejected(reason: &str) -> AuthoritySubmitOutcome {
        AuthoritySubmitOutcome::Rejected {
            status: AuthorityRejectionStatus::Rejected,
            reason_code: reason.to_owned(),
        }
    }

    fn unavailable(reason: &str) -> AuthoritySubmitOutcome {
        AuthoritySubmitOutcome::Rejected {
            status: AuthorityRejectionStatus::RetryableUnavailable,
            reason_code: reason.to_owned(),
        }
    }

    #[tokio::test]
    async fn authoring_freezes_exact_bytes_and_a_restart_replays_them() {
        let store = Arc::new(MemoryAuthoringStore::default());
        let edge = test_edge(store.clone());
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let intent = message_intent(&edge, &realm, "first");
        let first = edge
            .author_and_sign(&realm, "delivery-one", intent.clone())
            .await
            .unwrap();
        let bytes = serde_json::to_vec(&first).unwrap();

        // A producer Event carries no predecessor and no position of its own.
        let value = serde_json::to_value(first.event()).unwrap();
        for forbidden in ["prev_refs", "actor_seq", "hlc", "auth_context", "basis"] {
            assert!(value.get(forbidden).is_none(), "{forbidden} must be absent");
        }

        // A second delivery is independent: no single-slot serialization exists
        // once ordering belongs to the Station's commit stream.
        let second = edge
            .author_and_sign(
                &realm,
                "delivery-two",
                message_intent(&edge, &realm, "second"),
            )
            .await
            .unwrap();
        assert_ne!(second.event_id(), first.event_id());

        drop(edge);
        let edge = test_edge(store);
        let retry = edge
            .author_and_sign(&realm, "delivery-one", intent.clone())
            .await
            .unwrap();
        assert_eq!(serde_json::to_vec(&retry).unwrap(), bytes);
        let pending = edge.journal.pending_events().await.unwrap();
        assert_eq!(pending.len(), 2);
        assert!(
            pending
                .iter()
                .any(|event| event.event_id() == first.event_id())
        );

        // The same operation id may not be re-used for different content.
        assert!(
            edge.author_and_sign(
                &realm,
                "delivery-one",
                message_intent(&edge, &realm, "different content")
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn journal_scope_keeps_both_account_station_and_realm() {
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
        let first = scope_key(&realm_a, &account_a).unwrap();
        let second = scope_key(&realm_a, &account_b).unwrap();
        let third = scope_key(&realm_b, &account_a).unwrap();
        assert_ne!(first, second);
        assert_ne!(first, third);
        assert_ne!(second, third);
        // A partition names storage only; it never implies an order between the
        // publications inside it.
        assert!(
            edge.journal
                .load_operation(&first, "none")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn acceptance_requires_a_commit_that_names_the_exact_event() {
        let store = Arc::new(MemoryAuthoringStore::default());
        let edge = test_edge(store);
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let intent = message_intent(&edge, &realm, "hello");
        let event = edge
            .author_and_sign(&realm, "delivery", intent)
            .await
            .unwrap();

        let good = accepted(&event, 0);
        let committed = publication_outcome(&event, &good).unwrap().unwrap();
        assert_eq!(&committed.event_id, event.event_id());
        assert_eq!(committed.stream_position, 0);
        assert_eq!(
            committed.stream_ref,
            CommitStreamRef::Realm {
                realm_id: realm.clone()
            }
        );

        let AuthoritySubmitOutcome::Accepted { status, mut commit } = good.clone() else {
            unreachable!("fixture is an acceptance")
        };
        commit.event_ref = arkret::EventId::from_digest(DigestSuite::Sha256, [8; 32]);
        assert!(
            publication_outcome(
                &event,
                &AuthoritySubmitOutcome::Accepted {
                    status,
                    commit: commit.clone()
                }
            )
            .is_err()
        );

        // A terminal rejection settles the publication; an unavailable Station
        // settles nothing and keeps the frozen bytes replayable.
        assert!(
            publication_outcome(&event, &rejected("authz_denied"))
                .unwrap()
                .is_none()
        );
        assert!(publication_outcome(&event, &unavailable("station_unavailable")).is_err());

        assert_eq!(edge.journal.pending_events().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn station_rejection_settles_without_rewriting_the_frozen_event() {
        let store = Arc::new(MemoryAuthoringStore::default());
        let edge = test_edge(store);
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let intent = message_intent(&edge, &realm, "identical text");
        let key = scope_key(&realm, intent.actor_id()).unwrap();
        let old = edge
            .author_and_sign(&realm, "old-key-delivery", intent)
            .await
            .unwrap();
        let old_bytes = serde_json::to_vec(&old).unwrap();

        let outcome = rejected("actor_signature_revoked");
        assert!(
            edge.journal
                .record_outcome(&key, "old-key-delivery", &edge.station_id, &outcome, None)
                .await
                .unwrap()
        );
        assert!(edge.journal.pending_events().await.unwrap().is_empty());

        // A later authored delivery of the same text has a different canonical
        // identity. Operation ids alone are not part of the Event preimage.
        let later_intent = message_intent(&edge, &realm, "identical text")
            .with_created_at(old.event().created_at + chrono::TimeDelta::milliseconds(1));
        let new = edge
            .author_and_sign(&realm, "new-key-delivery", later_intent)
            .await
            .unwrap();
        assert_ne!(new.event_id(), old.event_id());
        assert_eq!(edge.journal.pending_events().await.unwrap().len(), 1);

        // The rejected publication keeps its exact signed bytes for an explicit
        // replay decision.
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

        // An accepted answer for the old delivery retains its exact committed
        // reference and must not disturb the newer frozen publication.
        assert!(edge.journal.reopen(&key, "old-key-delivery").await.unwrap());
        let accepted_outcome = accepted(&old, 4);
        let committed = publication_outcome(&old, &accepted_outcome).unwrap();
        assert!(
            edge.journal
                .record_outcome(
                    &key,
                    "old-key-delivery",
                    &edge.station_id,
                    &accepted_outcome,
                    committed.as_ref(),
                )
                .await
                .unwrap()
        );
        let settled = edge
            .journal
            .load_operation(&key, "old-key-delivery")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(settled.committed.unwrap().stream_position, 4);
        assert_eq!(edge.journal.pending_events().await.unwrap()[0], new);
    }

    #[tokio::test]
    async fn durable_engine_failure_prevents_publication_and_restart_retains_original() {
        use crate::file_authoring_store::tests::{FaultBackend, fault_store};
        let backend = FaultBackend::default();
        let store = Arc::new(fault_store(backend.clone()));
        let edge = test_edge(store.clone());
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let intent = message_intent(&edge, &realm, "frozen before transport");
        let key = scope_key(&realm, intent.actor_id()).unwrap();
        let original = edge
            .author_and_sign(&realm, "delivery", intent)
            .await
            .unwrap();
        let original_bytes = serde_json::to_vec(&original).unwrap();

        backend.fail_sync();
        assert!(
            edge.journal
                .record_outcome(
                    &key,
                    "delivery",
                    &edge.station_id,
                    &rejected("actor_signature_revoked"),
                    None
                )
                .await
                .is_err()
        );
        // This is the real public send path. The poisoned storage read returns
        // before the Station request; it never retries from visible RAM pages.
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
        struct NoAuthoring {
            expected_index: String,
            reads: std::sync::atomic::AtomicUsize,
        }
        impl AuthoringStore for NoAuthoring {
            fn load(&self, key: &str) -> Result<Option<String>> {
                assert_eq!(
                    key, self.expected_index,
                    "intent may only classify the exact local Actor"
                );
                assert_eq!(
                    self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                    0
                );
                Ok(None)
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
        let account = arkret::AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkghost").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkstation").unwrap(),
        );
        let store = Arc::new(NoAuthoring {
            expected_index: format!(
                "managed-authoring/local-actor/{}",
                serde_json::to_string(&arkret::ActorId::account(account.clone())).unwrap()
            ),
            reads: std::sync::atomic::AtomicUsize::new(0),
        });
        let edge = test_edge(store.clone());
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
        assert_eq!(store.reads.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            intent.executed_by(),
            Some(&arkret::ActorId::service(edge.service_actor_id.clone()))
        );
    }

    #[test]
    fn event_fingerprint_ignores_proofs() {
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let actor =
            project_did_to_core_id(&Did::new("did:webvh:z6mkfixture:alice.example").unwrap())
                .unwrap();
        let mut first = arkret_wire::test_support::raw_event(
            "ak.message.create",
            ScopeRef::Realm { realm_id: realm },
            actor.clone(),
            actor,
            json!({ "body": "hello" }),
        )
        .unwrap();
        let mut second = first.clone();

        first.producer_proof = Some(test_proof("header.payload.signature-a"));
        second.producer_proof = Some(test_proof("header.payload.signature-b"));

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
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: jws.to_owned(),
        }
    }
}
