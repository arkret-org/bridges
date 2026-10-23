//! The arkret protocol-side edge (replaces the Matrix bridge's
//! `MatrixAppservice`).
//!
//! - **Outbound (app -> arkret)**: [`ArkretEdge::service_intent`] builds complete Service producer
//!   `EventIntent`s; Realm Actor content uses its accepted Device. [`ArkretEdge::author_and_sign`]
//!   derives the one content-bound identity and signs it, then [`ArkretEdge::submit_event`] hands
//!   it to the current governance Station as an `EventAdmissionSubmission` and retains the
//!   authority-signed commit reference.
//! - **Inbound (arkret → app)**: group content requires an accepted native managed Device. The
//!   Applet management transaction endpoint accepts authoring completion only.
//! - **Media**: native Realm Device encryption and authenticated Blob operations.
//!
//! A host injects a durable [`crate::AuthoringJournal`] so retries retain the
//! exact signed Event bytes and the exact committed reference without requiring
//! diesel. The producer side holds no predecessor, position, or basis: the
//! Station's `RealmCommit` is the only ordering fact.

use std::sync::Arc;

#[cfg(any(feature = "web", test))]
use arkret::WireError;
use arkret::http_client::Client;
#[cfg(any(feature = "web", test))]
use arkret::identity::public_key_material_from_binding;
#[cfg(any(feature = "web", test))]
use arkret::signatures::VerificationMethodDocument;
use arkret::signatures::{PublicKeyMaterial, SignEventOptions, sign_event};
use arkret::{
    ActorId, AppletId, AuthoredEvent, ClientRequestOptions, Did, DidCoreId, DigestSuite,
    Ed25519PayloadSigner, Event, EventIntent, RealmId, ScopeRef, project_did_to_core_id,
};
use arkret_event_draft::{EventSpec, TypedEventDraft};
use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
#[cfg(any(feature = "web", test))]
use arkret_models_discovery::{ServiceDescribe, TransportBinding};
#[cfg(any(feature = "web", test))]
use arkret_models_integration::{
    AppletActorView, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome,
};
use arkret_models_integration::{
    AppletAuthoringTransactionRequestBody, AppletTransactionRequestBody,
};
use arkret_wire::{
    AuthorityRejectionStatus, AuthoritySubmitOutcome, DidUrl, EventAdmissionSubmission,
    SignalEnvelope,
};
#[cfg(test)]
use serde_json::json;
use tokio::sync::mpsc::Sender;

use crate::PreparedManagedActor;
#[cfg(any(feature = "web", test))]
use crate::app::AppletResolver;
use crate::authoring::{
    AuthoringJournal, AuthoringStore, PublicationRecord, publication_outcome, scope_key,
};
use crate::config::Config;
#[cfg(any(feature = "web", test))]
use crate::did_binding::DidAuthority;
use crate::error::{BridgeError, Result};
use crate::managed_authoring::{
    ManagedAuthoringIdentity, ManagedAuthoringRoots, creation_payload,
    validate_managed_authoring_completion, validate_prepared_ghost_signer,
};

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
    pub(crate) journal: AuthoringJournal,
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
        if config.arkret.service_resolution.is_some() {
            crate::service_identity::validate(&config)?;
        }
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

    #[cfg(any(feature = "managed-authoring", feature = "web"))]
    pub(crate) fn authoring_store(&self) -> Arc<dyn AuthoringStore> {
        self.journal.store.clone()
    }

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
    ) -> Result<PreparedManagedActor> {
        let realm = request
            .effective_scope
            .realm_id_opt()
            .ok_or_else(|| BridgeError::App("Bot creation requires a Realm".into()))?;
        let route = self.realm_route(realm).await?;
        let preview = route
            .client
            .applet_bot_preview(&self.config.arkret.applet_id, request)
            .await?;
        let base = url::Url::parse(&self.config.arkret.applet_base_url)
            .map_err(|e| BridgeError::Config(e.to_string()))?;
        if base.scheme() != "https"
            || !base.username().is_empty()
            || base.password().is_some()
            || base.fragment().is_some()
        {
            return Err(BridgeError::Config(
                "Applet management URL must be HTTPS without credentials or fragment".into(),
            ));
        }
        let authored = self
            .client
            .applet_managed_actor_author_at(
                &base,
                &arkret::AppletManagedActorAuthorRequestBody {
                    authoring_request: preview.authoring_request.clone(),
                },
            )
            .await?;
        Ok(PreparedManagedActor {
            authoring_request: preview.authoring_request,
            create_event: authored.create_event,
        })
    }

    /// Submit the single frozen creation Event. Management admission remains
    /// the governance Station's existing grant/review decision.
    pub async fn provision_bot(
        &self,
        body: &PreparedManagedActor,
    ) -> Result<AuthoritySubmitOutcome> {
        self.submit_managed_creation(body).await
    }

    pub async fn submit_managed_creation(
        &self,
        body: &PreparedManagedActor,
    ) -> Result<AuthoritySubmitOutcome> {
        let candidate = creation_payload(&body.create_event)?;
        if candidate.applet_id != self.applet_id || candidate.service_id != self.service_actor_id {
            return Err(BridgeError::App(
                "creation targets another Applet Service".into(),
            ));
        }
        let route = self.realm_route(&body.create_event.realm_id).await?;
        let context = arkret::ProducerVerificationContext {
            actor: ActorId::service(self.service_actor_id.clone()),
            verification_method: self.service_verification_method()?,
            public_key: PublicKeyMaterial::Ed25519Raw {
                bytes: self.signer.verifying_key().to_bytes().to_vec(),
            },
            digest_suite: PRODUCER_DIGEST_SUITE,
        };
        let request = arkret::VerifiedSubmission::verify(
            SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(
                body.create_event.clone(),
            )),
            |_| Ok(context.clone()),
        )
        .map_err(|e| BridgeError::App(e.to_string()))?;
        let outcome = route
            .client
            .submit_to_realm_authority(
                &request,
                &ClientRequestOptions::new().idempotency_key(body.create_event.event_id.as_str()),
            )
            .await?;
        let SelfAuthoritySubmitOutcome::Ordinary(outcome) = outcome else {
            return Err(BridgeError::App(
                "creation returned an aggregate outcome".into(),
            ));
        };
        if let AuthoritySubmitOutcome::Accepted { commit, .. } = &outcome {
            let target = arkret::CommittedEventRef {
                event_id: body.create_event.event_id.clone(),
                commit_id: commit.commit_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
            };
            let query = arkret::RealmActorMaterialRequest::Event {
                actor_id: candidate.actor_id,
                request_nonce: crate::realm_governance::nonce()?,
                target,
            };
            let verified = route
                .material(&query, &ActorId::service(self.service_actor_id.clone()))
                .await?;
            let completion = AppletAuthoringTransactionRequestBody {
                applet_id: self.applet_id.clone(),
                source_id: route.authority.current_service_id().clone(),
                authoring_context: arkret::AppletManagedActorAuthoringContext {
                    material: verified.into_material(),
                },
            };
            self.install_managed_authoring_completion(&completion)
                .await?;
        }
        Ok(outcome)
    }

    /// Compose the SDK's restricted native self-operation transport for an
    /// already accepted managed Device. It grants no session or group secrets.
    pub async fn managed_device_client(
        &self,
        metadata: arkret_models_integration::AppletManagedDeviceMetadata,
        device_key: ed25519_dalek::SigningKey,
    ) -> Result<Client> {
        metadata.validate()?;
        if metadata.applet_id != self.applet_id
            || device_key.verifying_key() == self.signer.verifying_key()
        {
            return Err(BridgeError::App(
                "managed Device transport identity or key is misbound".into(),
            ));
        }
        let fingerprint =
            arkret::ed25519_pubkey_to_did_key_multibase(device_key.verifying_key().as_bytes());
        let realm = metadata
            .actor_id
            .as_realm_actor_id()
            .ok_or_else(|| BridgeError::App("managed Device requires a Realm actor".into()))?
            .realm_id
            .clone();
        let route = self.realm_route(&realm).await?;
        Ok(route.client.with_managed_device_http_signer(
            metadata,
            route.authority.current_service_id().clone(),
            arkret::http_client::HttpMessageSigner::new(
                format!("did:key:{fingerprint}#{fingerprint}"),
                device_key,
            ),
        )?)
    }

    /// The installed Applet service signing key.
    ///
    /// The Realm actor creation Event is authored by this service
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

    pub fn prepare_managed_authoring(
        &self,
        command: &PreparedManagedActor,
        root_method: &DidUrl,
        root_key: &PublicKeyMaterial,
    ) -> Result<bool> {
        validate_prepared_ghost_signer(root_method, root_key)?;
        self.journal.prepare_managed_authoring(
            command,
            root_method,
            root_key,
            &self.service_verification_method()?,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: self.signer.verifying_key().to_bytes().to_vec(),
            },
        )
    }

    /// Check an outbound creation against independently retained local custody.
    pub fn validate_prepared_creation(&self, command: &PreparedManagedActor) -> Result<()> {
        self.journal.validate_prepared_creation(command)
    }

    pub(crate) fn prepared_managed_actor(
        &self,
        body: &AppletAuthoringTransactionRequestBody,
    ) -> Result<PreparedManagedActor> {
        self.journal.prepared_command(body)
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

    /// Historical creation is shared by local authoring and accepted custody.
    /// It describes the original creator, never the current manager's identity.
    pub(crate) fn retained_actor_creation(
        &self,
        actor: &ActorId,
    ) -> Result<arkret::CommittedEventFullView> {
        let original = self.retained_managed_actor(actor)?;
        let arkret::RealmActorMaterial::Event { event, commit, .. } =
            original.authoring_context.material.result
        else {
            return Err(BridgeError::Database(
                "creation original is unavailable".into(),
            ));
        };
        Ok(arkret::CommittedEventFullView { event, commit })
    }

    /// Authenticate a pushed completion against fresh governance and the
    /// locally frozen creation. This never installs current write permission.
    pub async fn install_managed_authoring_completion(
        &self,
        body: &AppletAuthoringTransactionRequestBody,
    ) -> Result<()> {
        let verified = self.verify_managed_completion(body).await?;
        self.install_verified_managed_completion(verified)
    }

    pub(crate) async fn verify_managed_completion(
        &self,
        body: &AppletAuthoringTransactionRequestBody,
    ) -> Result<VerifiedManagedCompletion> {
        self.journal.verify_prepared_managed_signer(body)?;
        let material = &body.authoring_context.material;
        let route = self.realm_route(&material.realm_id).await?;
        let identity = validate_managed_authoring_completion(
            body,
            route.authority.current_service_id(),
            &self.applet_id,
            &self.service_actor_id,
        )?;
        let arkret::RealmActorMaterial::Event {
            event,
            commit,
            producer_signer_fact,
        } = &material.result
        else {
            return Err(BridgeError::App(
                "creation completion requires Event material".into(),
            ));
        };
        let request = arkret::RealmActorMaterialRequest::Event {
            actor_id: identity.actor_id.clone(),
            request_nonce: material.request_nonce.clone(),
            target: arkret::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: commit.commit_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
            },
        };
        route
            .verify_material(
                material.clone(),
                &request,
                &ActorId::service(self.service_actor_id.clone()),
            )
            .await?;
        // A still-live pushed object proves an earlier private read. Re-read
        // the exact acceptance with a fresh nonce so a former manager cannot
        // use a cached completion after the current manager changes. Event
        // material reads deliberately do not require an active install/grant.
        let mut current_request = request.clone();
        if let arkret::RealmActorMaterialRequest::Event { request_nonce, .. } = &mut current_request
        {
            *request_nonce = crate::realm_governance::nonce()?;
        }
        let current = route
            .material(
                &current_request,
                &ActorId::service(self.service_actor_id.clone()),
            )
            .await?;
        if arkret::canonical::canonical_json_bytes(&current.material().result)?
            != arkret::canonical::canonical_json_bytes(&material.result)?
        {
            return Err(BridgeError::App(
                "current manager read returned a different creation acceptance".into(),
            ));
        }
        let arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::Service(
            fact,
        ) = producer_signer_fact
        else {
            return Err(BridgeError::App(
                "creation completion requires its historical Service signer fact".into(),
            ));
        };
        let registration_epoch = fact.key.registration_epoch.clone();
        let issuer = route
            .authority
            .authority_service_at(commit.governance_generation)
            .ok_or_else(|| {
                BridgeError::App("creation Commit has no verified governance tenure".into())
            })?;
        let commit_key = route
            .historical_station_key(
                issuer,
                &commit.signature.verification_method,
                commit.committed_at,
            )
            .await?;
        material.validate_for_request(
            &request,
            &ActorId::service(self.service_actor_id.clone()),
            chrono::Utc::now(),
        )?;
        let (method, service_key) = self.journal.prepared_service_root(body)?;
        let roots = ManagedAuthoringRoots {
            completion_digest: arkret::Hash::new(arkret::canonical::canonical_sha256(body)?)?,
            service_verification_method: method,
            service_public_key: service_key,
            station_verification_method: material.signature.verification_method.clone(),
            station_public_key: route
                .station_key(&material.signature.verification_method, material.issued_at)?,
            commit_verification_method: commit.signature.verification_method.clone(),
            commit_public_key: commit_key,
        };
        Ok(VerifiedManagedCompletion {
            body: body.clone(),
            identity,
            roots,
            route,
            destination_id: self.service_actor_id.clone(),
            registration_epoch,
            delivery: None,
            retained_outcome: None,
        })
    }

    pub fn install_verified_managed_completion(
        &self,
        verified: VerifiedManagedCompletion,
    ) -> Result<()> {
        if verified.body.applet_id != self.applet_id
            || verified.destination_id != self.service_actor_id
        {
            return Err(BridgeError::App(
                "verified completion belongs to another receiver".into(),
            ));
        }
        self.journal.install_managed_authoring_delivery(
            &verified.identity,
            &verified.body,
            &verified.roots,
            verified.delivery.as_ref(),
        )?;
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
        if intent.actor_id() != &ActorId::service(self.service_actor_id.clone()) {
            return Err(service_actor_required());
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
        if !matches!(event.actor_id, ActorId::Service { .. })
            && matches!(
                event.event().actual_signer(),
                arkret::ActorId::Service { .. }
            )
        {
            return Err(service_actor_required());
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
        if matches!(event.actor_id, ActorId::Service { .. })
            && !matches!(event.scope_ref, ScopeRef::RealmControl { .. })
        {
            let route = self.realm_route(&event.realm_id).await?;
            let transaction =
                AppletTransactionRequestBody::Events(arkret::AppletEventTransactionRequestBody {
                    applet_id: AppletId::new(self.applet_id())?,
                    source_id: self.service_actor_id.clone(),
                    events: vec![event.event().clone()],
                    committed_events: vec![],
                    signals: vec![],
                });
            let producer = arkret::ProducerVerificationContext {
                actor: ActorId::service(self.service_actor_id.clone()),
                verification_method: self.service_verification_method()?,
                public_key: PublicKeyMaterial::Ed25519Raw {
                    bytes: self.signer.verifying_key().to_bytes().to_vec(),
                },
                digest_suite: crate::PRODUCER_DIGEST_SUITE,
            };
            let transaction =
                arkret::VerifiedSubmission::verify(transaction, |_| Ok(producer.clone()))
                    .map_err(|e| BridgeError::Arkret(e.to_string()))?;
            let outcome = route
                .client
                .applet_transaction_from_service(
                    event.event_id().as_str(),
                    &transaction,
                    &self.service_actor_id,
                    route.authority.current_service_id(),
                )
                .await?;
            let committed = crate::authoring::applet_publication_outcome(event, &outcome)?;
            if !self
                .journal
                .record_applet_outcome(
                    &key,
                    &operation,
                    route.authority.current_service_id(),
                    &outcome,
                    committed.as_ref(),
                )
                .await?
            {
                return Err(BridgeError::Runtime(
                    "Applet outcome persistence contended; retry original".into(),
                ));
            }
            return committed.map(|r| r.event_id.to_string()).ok_or_else(|| {
                BridgeError::App(format!(
                    "Applet Event {} rejected: {:?}",
                    event.event_id(),
                    outcome.rejections()
                ))
            });
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
        let route = self.realm_route(&event.realm_id).await?;
        let outcome = route
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
        if let AuthoritySubmitOutcome::Accepted { commit, .. } = &outcome {
            let keys = garth::historical_station_keys::fetch_historical_station_keys_for_commits(
                &route.client,
                &route.bundle,
                &[commit],
            )
            .await
            .map_err(|e| BridgeError::Arkret(e.to_string()))?;
            route
                .authority
                .verify_commit(commit, &keys)
                .map_err(|e| BridgeError::Arkret(e.to_string()))?;
        }
        let committed = publication_outcome(event, &outcome)?;
        if !self
            .journal
            .record_outcome(
                &key,
                &operation,
                route.authority.current_service_id(),
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

fn service_actor_required() -> BridgeError {
    BridgeError::App(
        "Service signer cannot consume another actor's authority; use the actor's accepted Device"
            .into(),
    )
}

fn default_client(config: &Config) -> Result<Client> {
    crate::install_default_crypto_provider();
    let base = url::Url::parse(&config.arkret.server_url)
        .map_err(|e| BridgeError::Config(format!("server_url: {e}")))?;
    Client::builder(base).build().map_err(Into::into)
}

#[cfg(any(feature = "web", test))]
/// Signed management completion receiver. Group data belongs to managed Devices.
pub struct BridgeAppletHandler {
    applet_id: AppletId,
    service_did: Did,
    trust_domain: arkret::TrustDomainId,
    transport_base_url: String,
    service_resolution: Option<arkret::ResolutionCommitment>,
    resolver: Option<Arc<dyn AppletResolver>>,
    /// Inbound DID **binding store** (`did-usage-and-verification.md` §6).
    ///
    /// Discovery uses configured bindings. Creation completions enter through
    /// the async governance verifier on ArkretEdge.
    did_authority: Arc<DidAuthority>,
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
        Ok(Self {
            applet_id: edge.applet_id.clone(),
            service_did: service_did.clone(),
            trust_domain: edge.config.arkret.trust_domain.clone(),
            transport_base_url: management_url.to_string(),
            service_resolution: edge
                .config
                .arkret
                .service_resolution
                .as_ref()
                .map(|_| crate::service_identity::commitment(&edge.config))
                .transpose()?,
            resolver,
            did_authority,
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

/// Opaque admission capability. Hosts cannot manufacture authority or bypass
/// freshness checks by deserializing a completion into this type.
pub struct VerifiedManagedCompletion {
    pub(crate) body: AppletAuthoringTransactionRequestBody,
    identity: ManagedAuthoringIdentity,
    roots: ManagedAuthoringRoots,
    pub(crate) route: crate::realm_governance::RealmRoute,
    pub(crate) destination_id: DidCoreId,
    pub(crate) registration_epoch: arkret::Hash,
    pub(crate) delivery: Option<arkret::AppletDeliveryAuthenticationRecord>,
    pub(crate) retained_outcome: Option<arkret::AppletTransactionOutcome>,
}

impl VerifiedManagedCompletion {
    /// Exact outcome retained atomically with the original and delivery record.
    /// It is exposed only after this request's complete fresh admission.
    pub fn retained_outcome(&self) -> Option<&arkret::AppletTransactionOutcome> {
        self.retained_outcome.as_ref()
    }

    /// Full receiver-derived authentication record, including this delivery's times.
    pub fn delivery_authentication_record(
        &self,
    ) -> Option<&arkret::AppletDeliveryAuthenticationRecord> {
        self.delivery.as_ref()
    }
}

fn retained_managed_actor(
    journal: &AuthoringJournal,
    actor: &ActorId,
    _station: &DidCoreId,
    applet: &AppletId,
    _service: &DidCoreId,
) -> Result<AppletAuthoringTransactionRequestBody> {
    let (body, roots) = journal.retained_managed_actor(actor)?;
    // Retained creation is historical evidence. Service changes preserve its signer.
    let candidate = crate::managed_authoring::creation_payload(
        match &body.authoring_context.material.result {
            arkret::RealmActorMaterial::Event { event, .. } => event,
            _ => {
                return Err(BridgeError::Database(
                    "retained creation is not an Event".into(),
                ));
            }
        },
    )?;
    let identity = validate_managed_authoring_completion(
        &body,
        &body.source_id,
        applet,
        &candidate.service_id,
    )?;
    if identity.actor_id != *actor {
        return Err(BridgeError::Database(
            "retained creation names another actor".into(),
        ));
    }
    let material = &body.authoring_context.material;
    let arkret::RealmActorMaterial::Event {
        event,
        commit,
        producer_signer_fact,
    } = &material.result
    else {
        return Err(BridgeError::Database(
            "retained creation Event is missing".into(),
        ));
    };
    if roots.station_verification_method != material.signature.verification_method
        || roots.commit_verification_method != commit.signature.verification_method
        || commit.event_ref != event.event_id
        || commit.producer_signer_fact_digest.as_ref() != Some(&producer_signer_fact.digest()?)
    {
        return Err(BridgeError::Database(
            "retained creation historical anchors differ".into(),
        ));
    }
    for (signature, unsigned, context, key) in [
        (
            &material.signature,
            arkret::canonical::unsigned_value(material, &["signature"])?,
            arkret::DetachedSignatureContext::RealmActorMaterial,
            &roots.station_public_key,
        ),
        (
            &commit.signature,
            arkret::canonical::unsigned_value(commit, &["signature"])?,
            arkret::DetachedSignatureContext::RealmCommit,
            &roots.commit_public_key,
        ),
    ] {
        arkret::signatures::detached_object::verify_detached_object_signature(
            signature, &unsigned, context, key,
        )
        .map_err(|e| BridgeError::Database(e.to_string()))?;
    }
    Ok(body)
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
        if let Some(resolution) = &self.service_resolution {
            description.service_resolution = resolution.clone();
        }
        description.validate()?;
        Ok(description)
    }

    fn handle_transaction(
        &self,
        _idempotency_key: &str,
        req: AppletTransactionRequestBody,
    ) -> std::result::Result<AppletTransactionOutcome, WireError> {
        let _ = req;
        Err(WireError::Protocol(
            "Applet transactions require the async verified Realm creation adapter; group content uses a managed Device".into(),
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
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use arkret_wire::{
        Base64UrlString, CommitStreamRef, DetachedObjectSignature, DetachedSignatureAlgorithm,
        DetachedSignatureContext, RealmCommit, RealmCommitAuthorityRef, event_spec,
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
                "applet_namespaces": {"realms":[],"handles":[]},
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

    #[tokio::test]
    async fn managed_device_transport_rejects_service_key_and_other_realm() {
        let edge = test_edge(Arc::new(MemoryAuthoringStore::default()));
        let metadata: arkret_models_integration::AppletManagedDeviceMetadata = serde_json::from_value(json!({
            "actor_id": {"kind":"realm", "realm_actor_id": {"principal_id":"ak:did_core:webvh:z6mkbot", "realm_id":"ak:realm:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
            "device_id":"ak:device:01904100-0000-7000-8000-000000000003",
            "authorization_event_id":"ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "applet_id":edge.applet_id,
            "effective_scope":{"kind":"realm","realm_id":"ak:realm:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            "nonce":"AAAAAAAAAAAAAAAAAAAAAA"
        })).unwrap();
        assert!(
            edge.managed_device_client(
                metadata.clone(),
                ed25519_dalek::SigningKey::from_bytes(&[0x11; 32])
            )
            .await
            .is_err()
        );
        let mut wrong = metadata;
        wrong.effective_scope = ScopeRef::Realm {
            realm_id: RealmId::from_event_id(&arkret::EventId::from_digest(
                DigestSuite::Sha256,
                [99; 32],
            )),
        };
        assert!(
            edge.managed_device_client(wrong, ed25519_dalek::SigningKey::from_bytes(&[0x23; 32]))
                .await
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
    async fn service_signer_never_consumes_another_actor_authority_or_replays_it() {
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
            arkret::ContentBlock::text("forged proxy"),
        );
        let grant = "ak:grant:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        // Even an internally injected proxy cannot bypass the signer gate.
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
                "forged-proxy",
                &PublicationRecord::new(intent.clone(), authored.clone()),
            )
            .await
            .unwrap();
        let snapshot = store.0.lock().unwrap().clone();
        assert!(
            edge.author_and_sign(&realm, "forged-proxy", intent)
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
