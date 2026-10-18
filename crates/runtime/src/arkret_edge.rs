//! The arkret protocol-side edge (replaces the Matrix bridge's
//! `MatrixAppservice`).
//!
//! - **Outbound (app -> arkret)**: [`ArkretEdge::service_intent`] builds complete Service producer
//!   `EventIntent`s; managed Account publication fails closed. [`ArkretEdge::author_and_sign`]
//!   derives the one content-bound identity and signs it, then [`ArkretEdge::submit_event`] hands
//!   it to the current governance Station as an `EventAdmissionSubmission` and retains the
//!   authority-signed commit reference.
//! - **Inbound (arkret → app)**: group content requires an accepted native managed Device. The
//!   Applet management transaction endpoint accepts authoring completion only.
//! - **Media**: [`ArkretEdge::upload_blob`] / [`ArkretEdge::download_blob`].
//!
//! A host injects a durable [`crate::AuthoringJournal`] so retries retain the
//! exact signed Event bytes and the exact committed reference without requiring
//! diesel. The producer side holds no predecessor, position, or basis: the
//! Station's `RealmCommit` is the only ordering fact.

use std::collections::BTreeMap;
use std::sync::Arc;

use arkret::http_client::Client;
#[cfg(any(feature = "web", test))]
use arkret::identity::public_key_material_from_binding;
#[cfg(any(feature = "web", test))]
use arkret::signatures::VerificationMethodDocument;
use arkret::signatures::{PublicKeyMaterial, SignEventOptions, sign_event};
use arkret::{
    ActorId, AppletId, AuthoredEvent, ClientRequestOptions, Did, DidCoreId, DigestSuite,
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
    AppletTransactionOutcome,
};
use arkret_models_integration::{
    AppletAuthoringTransactionRequestBody, AppletManagedActorCommittedRequest,
};
use arkret_wire::{
    AuthorityRejectionStatus, AuthoritySubmitOutcome, DidUrl, EventAdmissionSubmission,
    SignalEnvelope, event_spec,
};
use serde::Serialize;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use tokio::sync::mpsc::Sender;

#[cfg(any(feature = "web", test))]
use crate::app::AppletResolver;
use crate::authoring::{
    AuthoringJournal, AuthoringStore, ManagedAuthoringIdentity, ManagedAuthoringRoots,
    PublicationRecord, external_operation_key, publication_outcome, scope_key,
    validate_managed_authoring_completion, validate_prepared_ghost_signer,
};
use crate::authority::{LocalServiceManagedActorProofVerifier, validate_managed_actor_bundle};
use crate::config::Config;
#[cfg(any(feature = "web", test))]
use crate::did_binding::DidAuthority;
use crate::error::{BridgeError, Result};

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

        let http_key = ed25519_dalek::SigningKey::from_bytes(&config.signing_seed()?);
        if http_key.verifying_key() != signer.verifying_key() {
            return Err(BridgeError::Config(
                "Service HTTP key differs from the producer key".into(),
            ));
        }
        let client = client.with_service_http_signer(
            service_actor_id.clone(),
            station_id.clone(),
            arkret::http_client::HttpMessageSigner::new(
                config
                    .arkret
                    .verification_method_for(&service_did)?
                    .to_string(),
                http_key,
            ),
        );

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

    #[cfg(feature = "managed-authoring")]
    pub(crate) fn authoring_store(&self) -> Arc<dyn AuthoringStore> {
        self.journal.store.clone()
    }

    #[cfg(feature = "managed-authoring")]
    pub(crate) fn config(&self) -> &Arc<Config> {
        &self.config
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Prepare one independent Bot using the installed Service transport identity.
    /// Retain the returned exact body before admission; retries must reuse its
    /// request id, signed request and candidate rather than generating another Bot.
    pub async fn prepare_bot_provision(
        &self,
        request: &arkret_models_integration::AppletBotPreviewRequestBody,
    ) -> Result<arkret_models_integration::AppletBotProvisionRequestBody> {
        let preview = self
            .client
            .applet_bot_preview(&self.config.arkret.applet_id, request)
            .await?;
        let base = url::Url::parse(&self.config.arkret.applet_base_url)
            .map_err(|error| BridgeError::Config(format!("applet_base_url: {error}")))?;
        if base.scheme() != "https"
            || !base.username().is_empty()
            || base.password().is_some()
            || base.fragment().is_some()
        {
            return Err(BridgeError::Config(
                "Applet management base_url must be HTTPS without credentials or fragment".into(),
            ));
        }
        let authored = self
            .client
            .applet_managed_actor_author_at(
                &base,
                &arkret_models_integration::AppletManagedActorAuthorRequestBody {
                    authoring_request: preview.authoring_request.clone(),
                },
            )
            .await?;
        Ok(arkret_models_integration::AppletBotProvisionRequestBody {
            authoring_request: preview.authoring_request,
            managed_actor_bundle: authored.managed_actor_bundle,
            approval_signatures: Vec::new(),
        })
    }

    /// Admit a verified retained creation body. Review-required outcomes must be resolved
    /// through the separate management review contract before retrying admission.
    pub async fn provision_bot(
        &self,
        body: &arkret::VerifiedSubmission<arkret_models_integration::AppletBotProvisionRequestBody>,
    ) -> Result<arkret_models_integration::AppletBotProvisionOutcome> {
        let digest = body.authoring_request.canonical_digest()?;
        Ok(self
            .client
            .applet_bot_provision(&self.config.arkret.applet_id, digest.as_ref(), body)
            .await?)
    }

    /// Compose the SDK's restricted native self-operation transport for an
    /// already accepted managed Device. It grants no session or group secrets.
    pub fn managed_device_client(
        &self,
        metadata: arkret_models_integration::AppletManagedDeviceMetadata,
        device_key: ed25519_dalek::SigningKey,
    ) -> Result<Client> {
        metadata.validate()?;
        if metadata.applet_id != self.applet_id
            || metadata.account_id.station_id != self.station_id
            || device_key.verifying_key() == self.signer.verifying_key()
        {
            return Err(BridgeError::App(
                "managed Device transport identity or key is misbound".into(),
            ));
        }
        let fingerprint =
            arkret::ed25519_pubkey_to_did_key_multibase(device_key.verifying_key().as_bytes());
        Ok(self.client.clone().with_managed_device_http_signer(
            metadata,
            self.station_id.clone(),
            arkret::http_client::HttpMessageSigner::new(
                format!("did:key:{fingerprint}#{fingerprint}"),
                device_key,
            ),
        )?)
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

    /// Reuse a Station-selected Ghost only after comparing all immutable
    /// anchors to this runtime's accepted original creation evidence.
    pub fn reused_ghost_did(
        &self,
        request: &arkret_models_integration::GhostActorProvisionRequestBody,
    ) -> Result<Did> {
        self.journal.reused_ghost_did(request)
    }

    /// Freeze the exact producer creation material before Station admission.
    pub fn prepare_managed_authoring(
        &self,
        committed_request: &AppletManagedActorCommittedRequest,
        managed_actor_verification_method: &DidUrl,
        managed_actor_public_key: &PublicKeyMaterial,
    ) -> Result<bool> {
        if matches!(committed_request, AppletManagedActorCommittedRequest::Ghost(ghost)
                if ghost.managed_actor_bundle.is_none())
        {
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
            &self.service_verification_method()?,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: self.signer.verifying_key().to_bytes().to_vec(),
            },
        )
    }

    /// Reverify immutable accepted creation with the roots frozen by this
    /// host. These historical roots grant no current business authority.
    pub(crate) fn retained_managed_actor(
        &self,
        actor: &ActorId,
    ) -> Result<AppletAuthoringTransactionRequestBody> {
        retained_managed_actor(
            &self.journal,
            actor,
            &self.station_id,
            &self.applet_id,
            &self.service_actor_id,
        )
    }

    pub(crate) fn managed_actor_ids(&self) -> Result<Vec<ActorId>> {
        self.journal.managed_actor_ids()
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
            let retained = self.retained_managed_actor(&identity.actor_id)?;
            if arkret::canonical::canonical_json_bytes(&retained)?
                != arkret::canonical::canonical_json_bytes(body)?
            {
                return Err(BridgeError::Database(
                    "completion replay differs from original creation".into(),
                ));
            }
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
        let (service_method, service_key) = self.journal.prepared_service_root(body)?;
        verify_managed_authoring_closure(
            body,
            &self.service_actor_id,
            &service_method,
            &service_key,
            &self.journal,
            source_public_key,
        )
        .map_err(|error| BridgeError::App(error.to_string()))?;
        let roots = ManagedAuthoringRoots {
            completion_digest: arkret::Hash::new(arkret::canonical::canonical_sha256(body)?)?,
            service_verification_method: service_method,
            service_public_key: service_key,
            station_verification_method: source_verification_method.clone(),
            station_public_key: source_public_key.clone(),
        };
        self.journal
            .install_managed_authoring(&identity, body, &roots)?;
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

    /// Retained managed Account intent API. Provisioning supplies identity and
    /// provenance, but this Service signer cannot consume its terminal child.
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

    /// Managed Accounts require their own accepted native authoring and Device
    /// executor. The Service signer cannot consume a terminal Account child.
    pub fn delegated_intent_in_scope<K>(
        &self,
        _actor: &arkret::AccountId,
        _scope: &ScopeRef,
        _content: K::Payload,
        _authorization_ref: &str,
    ) -> Result<EventIntent>
    where
        K: EventSpec,
    {
        Err(managed_account_executor_unavailable())
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
        if intent.actor_id().as_account_id().is_some() {
            return Err(managed_account_executor_unavailable());
        }
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
        if event.actor_id.as_account_id().is_some()
            && matches!(
                event.event().actual_signer(),
                arkret::ActorId::Service { .. }
            )
        {
            return Err(managed_account_executor_unavailable());
        }
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
        let producer = arkret::ProducerVerificationContext {
            actor: arkret::ActorId::service(self.service_actor_id.clone()),
            verification_method: self.service_verification_method()?,
            public_key: PublicKeyMaterial::Ed25519Raw {
                bytes: self.signer.verifying_key().to_bytes().to_vec(),
            },
            digest_suite: arkret::DigestSuite::Sha256,
        };
        let request = arkret::VerifiedSubmission::verify(request, |_| Ok(producer.clone()))
            .map_err(|error| BridgeError::Arkret(error.to_string()))?;
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

    /// Retained API for per-user Ghost publication. It fails closed until the
    /// managed Account's native authoring and Device executor are connected.
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

    /// Retained Ghost redaction API. It fails closed until the managed
    /// Account's native authoring and Device executor are connected.
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
        let operation_id = external_operation_key(
            arkret_wire::CapabilityActionId::MESSAGE_REDACT,
            &external_ref,
        )?;
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

fn managed_account_executor_unavailable() -> BridgeError {
    BridgeError::App(
        "managed Account native authoring and Device execution are not connected; the Service signer cannot consume an Account child grant".into(),
    )
}

fn default_client(config: &Config) -> Result<Client> {
    crate::install_default_crypto_provider();
    let base = url::Url::parse(&config.arkret.server_url)
        .map_err(|e| BridgeError::Config(format!("server_url: {e}")))?;
    Client::builder(base).build().map_err(Into::into)
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
/// Signed management completion receiver. Group data belongs to managed Devices.
pub struct BridgeAppletHandler {
    applet_id: AppletId,
    service_id: DidCoreId,
    station_id: DidCoreId,
    service_did: Did,
    trust_domain: arkret::TrustDomainId,
    transport_base_url: String,
    resolver: Option<Arc<dyn AppletResolver>>,
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
    /// Build the signed management receiver from the actual Service key and
    /// durable authoring journal. Group queues are not a management capability.
    pub fn new(
        edge: &ArkretEdge,
        resolver: Option<Arc<dyn AppletResolver>>,
        did_authority: Arc<DidAuthority>,
    ) -> Result<Self> {
        let management_url = url::Url::parse(&edge.config.arkret.applet_base_url)
            .map_err(|error| BridgeError::Config(format!("applet_base_url: {error}")))?;
        if management_url.scheme() != "https"
            || management_url.host_str().is_none()
            || !management_url.username().is_empty()
            || management_url.password().is_some()
            || management_url.fragment().is_some()
        {
            return Err(BridgeError::Config(
                "applet_base_url requires HTTPS without credentials or fragment".into(),
            ));
        }
        let service_did = edge.service_did.clone();
        let service_id = project_did_to_core_id(&service_did)
            .map_err(|error| BridgeError::Config(error.to_string()))?;
        Ok(Self {
            applet_id: edge.applet_id.clone(),
            service_id,
            station_id: edge.station_id.clone(),
            service_did: service_did.clone(),
            trust_domain: edge.config.arkret.trust_domain.clone(),
            transport_base_url: management_url.to_string(),
            resolver,
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
    /// from the accepted own-Station Service binding. Bot and Ghost creation require
    /// their locally prepared exact unit; reuse requires the original anchors.
    fn verify_local_managed_authoring_closure(
        &self,
        body: &AppletAuthoringTransactionRequestBody,
    ) -> std::result::Result<ManagedAuthoringRoots, WireError> {
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
        let (service_method, service_key) = self
            .journal
            .prepared_service_root(body)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        verify_managed_authoring_closure(
            body,
            &self.service_id,
            &service_method,
            &service_key,
            &self.journal,
            &source_key,
        )?;
        Ok(ManagedAuthoringRoots {
            completion_digest: arkret::Hash::new(arkret::canonical::canonical_sha256(body)?)?,
            service_verification_method: service_method,
            service_public_key: service_key,
            station_verification_method: attester.verification_method.clone(),
            station_public_key: source_key,
        })
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

fn retained_managed_actor(
    journal: &AuthoringJournal,
    actor: &ActorId,
    station_id: &DidCoreId,
    applet_id: &AppletId,
    service_id: &DidCoreId,
) -> Result<AppletAuthoringTransactionRequestBody> {
    let (body, roots) = journal.retained_managed_actor(actor)?;
    let identity = validate_managed_authoring_completion(&body, station_id, applet_id, service_id)
        .map_err(BridgeError::Database)?;
    let (prepared_method, prepared_key) = journal.prepared_service_root(&body)?;
    if identity.actor_id != *actor
        || prepared_method != roots.service_verification_method
        || prepared_key
            .ed25519_bytes()
            .map_err(|e| BridgeError::Database(e.to_string()))?
            != roots
                .service_public_key
                .ed25519_bytes()
                .map_err(|e| BridgeError::Database(e.to_string()))?
        || roots.station_verification_method
            != body
                .authoring_context
                .managed_actor_signer_evidence
                .attester_signer_evidence
                .verification_method
    {
        return Err(BridgeError::Database(
            "retained managed Account roots are misbound".into(),
        ));
    }
    verify_managed_authoring_closure(
        &body,
        service_id,
        &roots.service_verification_method,
        &roots.service_public_key,
        journal,
        &roots.station_public_key,
    )
    .map_err(|error| BridgeError::Database(error.to_string()))?;
    Ok(body)
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
        AppletManagedActorCommittedRequest::Ghost(ghost) => ghost
            .managed_actor_bundle
            .as_ref()
            .map(|bundle| (&ghost.authoring_request, bundle)),
        AppletManagedActorCommittedRequest::Bot(bot) => {
            Some((&bot.authoring_request, &bot.managed_actor_bundle))
        }
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
        let description = ServiceDescribe::development(
            self.service_did.clone(),
            self.trust_domain.clone(),
            service_kind,
            vec![describe_bundle],
            vec![TransportBinding::HttpJson {
                base_url: self.transport_base_url.clone(),
                extension_profile_required: (),
            }],
        );
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
                    &self.station_id,
                    &self.applet_id,
                    &self.service_id,
                )
                .map_err(WireError::Protocol)?;
                if self
                    .journal
                    .is_exact_managed_authoring_replay(&identity, &body)
                    .map_err(|error| WireError::Protocol(error.to_string()))?
                {
                    let retained = retained_managed_actor(
                        &self.journal,
                        &identity.actor_id,
                        &self.station_id,
                        &self.applet_id,
                        &self.service_id,
                    )
                    .map_err(|error| WireError::Protocol(error.to_string()))?;
                    if arkret::canonical::canonical_json_bytes(&retained)?
                        != arkret::canonical::canonical_json_bytes(&body)?
                    {
                        return Err(WireError::Protocol(
                            "completion replay differs from retained original".into(),
                        ));
                    }
                    return Ok(AppletTransactionOutcome::Accepted {
                        committed_event_refs: Vec::new(),
                        rejections: Vec::new(),
                        retry_after_ms: None,
                    });
                }
                let roots = self.verify_local_managed_authoring_closure(&body)?;
                self.journal
                    .install_managed_authoring(&identity, &body, &roots)
                    .map_err(|error| WireError::Protocol(error.to_string()))?;
                return Ok(AppletTransactionOutcome::Accepted {
                    committed_event_refs: Vec::new(),
                    rejections: Vec::new(),
                    retry_after_ms: None,
                });
            }
            AppletTransactionRequestBody::Events(req) => req,
        };
        let _ = req;
        Err(WireError::Protocol(
            "Station-to-Applet Event and Signal subscriptions are prohibited; use an authorized managed Device".into(),
        ))
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

    use arkret_wire::{
        Base64UrlString, CommitStreamRef, DetachedObjectSignature, DetachedSignatureAlgorithm,
        DetachedSignatureContext, RealmCommit, RealmCommitAuthorityRef,
    };

    use super::*;

    fn test_edge(store: Arc<dyn AuthoringStore>) -> ArkretEdge {
        let config: Config = serde_json::from_value(json!({
            "bridge": {"bridge_id": "test"},
            "arkret": {
                "server_url": "https://station.example", "applet_base_url":"https://bridge.example", "service_did": "did:webvh:z6mkbridge:bridge.example",
                "trust_domain": "ak:trust_domain:example.net", "applet_id": "ak:applet:01904100-0000-7000-8000-000000000001",
                "signing_key_seed_hex": "11".repeat(32),
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

    #[test]
    fn development_descriptor_does_not_claim_unimplemented_applet_profile() {
        let edge = test_edge(Arc::new(MemoryAuthoringStore::default()));
        let handler = BridgeAppletHandler::new(
            &edge,
            None,
            Arc::new(DidAuthority::new(edge.config.arkret.trust_domain.clone()).unwrap()),
        )
        .unwrap();
        let description = arkret::AppletHandler::describe(&handler).unwrap();
        description.validate().unwrap();
        assert!(description.supported_profiles.is_empty());
        assert_eq!(description.service_kind, arkret::ServiceKind::AppletService);
    }

    #[test]
    fn managed_device_transport_rejects_service_key_and_other_station() {
        let edge = test_edge(Arc::new(MemoryAuthoringStore::default()));
        let metadata: arkret_models_integration::AppletManagedDeviceMetadata = serde_json::from_value(json!({
            "account_id": { "principal_id":"ak:did_core:webvh:z6mkbot", "station_id":edge.station_id },
            "device_id":"ak:device:01904100-0000-7000-8000-000000000003",
            "authorization_event_id":"ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "applet_id":edge.applet_id,
            "effective_scope": {"kind":"realm","realm_id":"ak:realm:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            "nonce":"AAAAAAAAAAAAAAAAAAAAAA"
        })).unwrap();
        assert!(
            edge.managed_device_client(
                metadata.clone(),
                ed25519_dalek::SigningKey::from_bytes(&[0x11; 32])
            )
            .is_err()
        );
        assert!(
            edge.managed_device_client(
                metadata.clone(),
                ed25519_dalek::SigningKey::from_bytes(&[0x23; 32])
            )
            .is_ok()
        );
        let mut wrong = metadata;
        wrong.account_id.station_id = DidCoreId::new("ak:did_core:webvh:z6mkother").unwrap();
        assert!(
            edge.managed_device_client(wrong, ed25519_dalek::SigningKey::from_bytes(&[0x23; 32]))
                .is_err()
        );
    }

    #[test]
    fn management_endpoint_never_subscribes_to_group_events_or_signals() {
        let store = Arc::new(MemoryAuthoringStore::default());
        let edge = test_edge(store.clone());
        let handler = BridgeAppletHandler::new(
            &edge,
            None,
            Arc::new(DidAuthority::new(edge.config.arkret.trust_domain.clone()).unwrap()),
        )
        .unwrap();
        let request = serde_json::from_value(json!({
            "applet_id": edge.applet_id,
            "source_id": edge.station_id,
            "events": [], "committed_events": [], "signals": []
        }))
        .unwrap();
        assert!(
            arkret::AppletHandler::handle_transaction(
                &handler,
                "group-subscription",
                AppletTransactionRequestBody::Events(request)
            )
            .is_err()
        );
        assert!(store.0.lock().unwrap().is_empty());
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
            arkret::AuthorizationRef::new(
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
                producer_signer_fact_digest: None,
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
    async fn service_signer_never_consumes_a_managed_account_child_or_replays_it() {
        let store = Arc::new(MemoryAuthoringStore::default());
        let edge = test_edge(store.clone());
        let account = arkret::AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkghost").unwrap(),
            edge.station_id.clone(),
        );
        let realm = RealmId::new("ak:realm:ATv-vc4S1M4y2UKNOZKUnGUsh_44w_q2QJ5JjDBYjZw5").unwrap();
        let payload = arkret::MessageCreatePayload::with_content(
            arkret::StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9")
                .unwrap(),
            "main",
            arkret::ContentBlock::text("legacy proxy"),
        );
        let grant = "ak:grant:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(
            edge.delegated_intent::<event_spec::MessageCreate>(
                &account,
                &realm,
                payload.clone(),
                grant,
            )
            .unwrap_err()
            .to_string()
            .contains("Service signer cannot consume")
        );
        assert!(store.0.lock().unwrap().is_empty());

        // A retained pre-migration Service proxy must not bypass the gate.
        let intent = TypedEventDraft::<event_spec::MessageCreate>::new(
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            arkret::ActorId::account(account),
            payload,
        )
        .unwrap()
        .with_executed_by(arkret::ActorId::service(edge.service_actor_id.clone()))
        .with_authorization_ref(arkret::AuthorizationRef::new(grant).unwrap())
        .with_applet_id(edge.applet_id.clone())
        .into_intent(arkret::canonical::normalize_timestamp_canonical(
            chrono::Utc::now(),
        ))
        .unwrap();
        let mut authored = intent
            .clone()
            .author_with_digest_suite(PRODUCER_DIGEST_SUITE)
            .unwrap();
        sign_event(&mut authored, &edge.signer, SignEventOptions::new()).unwrap();
        let key = scope_key(&realm, intent.actor_id()).unwrap();
        edge.journal
            .freeze(
                &key,
                "legacy-proxy",
                &PublicationRecord::new(intent.clone(), authored.clone()),
            )
            .await
            .unwrap();
        let snapshot = store.0.lock().unwrap().clone();
        assert!(
            edge.author_and_sign(&realm, "legacy-proxy", intent)
                .await
                .unwrap_err()
                .to_string()
                .contains("Service signer cannot consume")
        );
        assert!(
            edge.submit_event(&authored)
                .await
                .unwrap_err()
                .to_string()
                .contains("Service signer cannot consume")
        );
        assert_eq!(*store.0.lock().unwrap(), snapshot);
    }
}
