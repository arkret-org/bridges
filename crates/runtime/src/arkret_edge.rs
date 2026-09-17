//! The arkret protocol-side edge (replaces the Matrix bridge's
//! `MatrixAppservice`).
//!
//! - **Outbound (app -> arkret)**: [`ArkretEdge::service_intent`] and
//!   [`ArkretEdge::delegated_intent`] build complete producer `EventIntent`s;
//!   [`ArkretEdge::author_and_sign`] derives the one content-bound identity and signs it, then
//!   [`ArkretEdge::submit_event`] hands it to the current governance Station as an
//!   `EventCommitSubmission` and retains the authority-signed commit reference.
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

#[cfg(any(feature = "web", test))]
use arkret::WireError;
use arkret::http_client::{Auth, Client};
#[cfg(any(feature = "web", test))]
use arkret::identity::public_key_material_from_binding;
#[cfg(any(feature = "web", test))]
use arkret::signatures::{EventProofBuilder, VerificationMethodDocument};
use arkret::signatures::{SignEventOptions, sign_event};
use arkret::{
    AppletId, AuthoredEvent, ClientRequestOptions, Did, DidCoreId, DigestSuite,
    Ed25519PayloadSigner, Event, EventIntent, RealmId, ScopeRef, project_did_to_core_id,
};
use arkret_event_draft::{EventSpec, TypedEventDraft};
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
#[cfg(any(feature = "web", test))]
use arkret_wire::ProfileId;
use arkret_wire::{
    AuthorityRejectionStatus, AuthoritySubmitOutcome, AuthoritySubmitRequest, AuthorizationRef,
    DidUrl, EventCommitSubmission, SignalEnvelope, event_spec,
};
use serde::Serialize;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use tokio::sync::mpsc::Sender;

#[cfg(any(feature = "web", test))]
use crate::app::AppletResolver;
use crate::authoring::{
    AuthoringJournal, AuthoringStore, PublicationRecord, external_operation_key,
    publication_outcome, scope_key,
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
        let request = AuthoritySubmitRequest::Event(EventCommitSubmission {
            event: event.event().clone(),
        });
        let options = ClientRequestOptions::new().idempotency_key(event.event_id().as_str());
        let outcome = self
            .client
            .submit_to_realm_authority(&request, &options)
            .await?;
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
        let AppletTransactionRequestBody::Events(req) = req else {
            return Err(WireError::Protocol(
                "managed Actor authoring completion installation is not available".into(),
            ));
        };
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
            // The inbound plane receives already-committed Events; a bridge
            // never issues an authority commit of its own.
            committed_event_refs: Vec::new(),
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

    use arkret_wire::{
        Base64UrlString, CommitStreamRef, DetachedObjectSignature, DetachedSignatureAlgorithm,
        DetachedSignatureContext, RealmCommit, RealmCommitAuthorityRef,
    };

    use super::*;

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
                authority_generation: 1,
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

        // A different logical delivery of the same text is a different Event and
        // is never deduplicated against the rejected one.
        let new = edge
            .author_and_sign(
                &realm,
                "new-key-delivery",
                message_intent(&edge, &realm, "identical text"),
            )
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
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: jws.to_owned(),
        }
    }
}
