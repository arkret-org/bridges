//! Shared production Bot/Ghost Principal custody and authoring.
//!
//! One implementation backs both the canonical Applet author operation and
//! the messaging bridge's first-seen-user provisioning path. Identity keys are
//! random, encrypted at rest, and independent from the Applet service key.

use std::sync::Arc;

use arkret::canonical::{canonical_json_bytes, canonical_sha256};
use arkret::signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use arkret::{
    AppletId, AppletManagedActorAuthoringRequest, AppletManagedActorPurpose, Did, DidCoreId, Event,
    GhostPreviewRequestBody, Hash, ResolutionCommitment, ResolutionDidBindingEvidenceKind,
    ResolutionDidBindingEvidenceReceipt, ResolutionDidBindingMethodProof,
    ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence, namespace_pattern_matches,
    project_did_to_core_id,
};
#[cfg(feature = "web")]
use arkret::{AppletManagedActorAuthorOutcome, AppletManagedActorAuthorRequestBody};
use arkret_wire::DidUrl;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use chrono::Utc;
use ed25519_dalek::SigningKey;
#[cfg(feature = "web")]
use salvo::http::StatusCode;
#[cfg(feature = "web")]
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate as runtime;
use crate::managed_actor_store::{
    ManagedActorAuthoringClaim, ManagedActorIdentityRecord, ManagedActorStore,
};
use crate::{BridgeError, PreparedGhost, PreparedManagedActor, Result};

mod control;

const AUTHORING_LEASE_SECS: i64 = 30;
const AUTHORING_WAIT_ATTEMPTS: usize = 300;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedActorKeyMaterial {
    root_seed: String,
    next_root_seed: String,
}

#[derive(Clone)]
struct ManagedActorIdentity {
    actor_id: DidCoreId,
    initial_resolution: ResolutionCommitment,
    method_history_evidence: ResolutionMethodHistoryEvidence,
    root_verification_method: DidUrl,
    root_public_key: PublicKeyMaterial,
}

struct VerifiedManagedActorRoot {
    principal_id: DidCoreId,
    log_head_digest: Hash,
    did_version_id: String,
    verification_method: DidUrl,
    public_key: PublicKeyMaterial,
}

/// Durable authoring authority shared by bridge and agent hosts.
pub struct ManagedActorAuthoringService {
    edge: Arc<runtime::ArkretEdge>,
    store: Arc<ManagedActorStore>,
    config: Arc<runtime::Config>,
    principal_endpoint: url::Url,
    key_encryption_key: [u8; 32],
}

pub(crate) struct OriginalManagedController {
    pub(crate) actor_id: arkret::ActorId,
    pub(crate) signer: arkret::Ed25519PayloadSigner,
    pub(crate) signing_key: SigningKey,
    pub(crate) original: Box<arkret::AppletAuthoringTransactionRequestBody>,
}

impl ManagedActorAuthoringService {
    pub fn new(edge: Arc<runtime::ArkretEdge>) -> Result<Self> {
        let config = edge.config().clone();
        let store = Arc::new(ManagedActorStore::new(edge.authoring_store()));
        let principal_endpoint = config.arkret.managed_actor_authoring.principal_endpoint()?;
        let key_encryption_key = config.arkret.managed_actor_authoring.key_encryption_key()?;
        Ok(Self {
            edge,
            store,
            config,
            principal_endpoint,
            key_encryption_key,
        })
    }

    /// Load only this host's accepted identity and encrypted controller. The
    /// historical closure proves ownership; Station admission must still
    /// check the current controller, generation and every installation scope.
    pub(crate) async fn original_managed_controller(
        &self,
        actor: &arkret::ActorId,
    ) -> Result<OriginalManagedController> {
        let realm_actor = actor.as_realm_actor_id().ok_or_else(|| {
            BridgeError::App("managed custody requires a full Realm actor".into())
        })?;
        let edge = self.edge.clone();
        let actor_owned = actor.clone();
        let original =
            crate::run_blocking(move || edge.retained_managed_actor(&actor_owned)).await?;
        let prepared = self.edge.prepared_managed_actor(&original)?;
        let subject_key = managed_actor_subject_key(&prepared.authoring_request)?;
        let record = self
            .store
            .clone()
            .managed_actor_identity_async(subject_key.clone())
            .await?
            .ok_or_else(|| {
                BridgeError::Database("accepted Realm actor lost its native custody".into())
            })?;
        let identity = self.decode_identity(&subject_key, record.clone())?;
        let payload = crate::managed_authoring::creation_payload(&prepared.create_event)?;
        if identity.actor_id != realm_actor.principal_id
            || payload.actor_id != *actor
            || canonical_json_bytes(&identity.initial_resolution)?
                != canonical_json_bytes(&payload.initial_resolution)?
        {
            return Err(BridgeError::Database(
                "accepted Realm actor differs from native custody".into(),
            ));
        }
        let controller = self.decode_original_controller(&subject_key, &record, &identity)?;
        let did = Did::new(record.actor_did)?;
        let method = DidUrl::new(format!("{did}#managed-controller"))
            .map_err(|e| BridgeError::Database(e.into()))?;
        Ok(OriginalManagedController {
            actor_id: actor.clone(),
            signing_key: controller.clone(),
            signer: arkret::Ed25519PayloadSigner::new(controller, did, method),
            original: Box::new(original),
        })
    }

    #[cfg(feature = "web")]
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .push(
                Router::with_path("_arkret/edge/applet/managed-actors/author")
                    .hoop(crate::web::OperationSelector(
                        arkret::ServiceOperationId::EDGE_APPLET_MANAGED_ACTOR_COMMAND_AUTHOR_V1,
                    ))
                    .hoop(affix_state::inject(AuthoringWebState {
                        service: self.clone(),
                    }))
                    .post(author_managed_actor),
            )
            .push(
                Router::with_path("webvh/{local_id}/did.json")
                    .hoop(affix_state::inject(AuthoringWebState {
                        service: self.clone(),
                    }))
                    .get(published_document),
            )
            .push(
                Router::with_path("webvh/{local_id}/did.jsonl")
                    .hoop(affix_state::inject(AuthoringWebState {
                        service: self.clone(),
                    }))
                    .get(published_history),
            )
    }

    /// Read the exact public native resources retained with this host's own identity.
    /// The URL index and verified encrypted custody prevent publishing another
    /// host's document or substituting unverified storage bytes.
    pub async fn published_principal(
        &self,
        local_id: &str,
    ) -> Result<Option<(arkret::DidDocument, Vec<Value>)>> {
        if local_id.is_empty()
            || local_id.len() > 64
            || !local_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            return Ok(None);
        }
        let url = self
            .principal_endpoint
            .join(&format!("/webvh/{local_id}/did.json"))
            .map_err(|error| BridgeError::Config(format!("managed publication URL: {error}")))?;
        // Native WebVH resources always use HTTPS, including loopback DID hosts.
        let mut url = url;
        url.set_scheme("https").map_err(|_| {
            BridgeError::Config("managed publication requires an HTTPS authority".into())
        })?;
        let Some((subject, record)) = self
            .store
            .clone()
            .published_identity_async(url.to_string())
            .await?
        else {
            return Ok(None);
        };
        let identity = self.decode_identity(&subject, record)?;
        let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
            identity.method_history_evidence
        else {
            return Err(BridgeError::Database(
                "managed publication lacks native WebVH history".into(),
            ));
        };
        let log_entries = self
            .published_control_history(&subject, log_entries)
            .await?;
        let entry = log_entries
            .last()
            .ok_or_else(|| BridgeError::Database("managed publication history is empty".into()))?;
        let document = serde_json::from_value(entry["state"].clone()).map_err(|error| {
            BridgeError::Database(format!("managed publication document: {error}"))
        })?;
        Ok(Some((document, log_entries)))
    }

    /// Author or recover the exact Station-signed request using durable private custody.
    pub async fn author(&self, request: &AppletManagedActorAuthoringRequest) -> Result<Event> {
        self.validate_request(request, false).await?;
        if request
            .basis
            .ghost()
            .is_some_and(|basis| basis.existing_managed_actor.is_some())
        {
            return Err(BridgeError::App(
                "Ghost reuse does not create another creation Event".into(),
            ));
        }
        let subject_key = managed_actor_subject_key(request)?;
        let request_digest = request.canonical_digest()?.to_string();
        let request_json = String::from_utf8(canonical_json_bytes(request)?).map_err(|error| {
            BridgeError::App(format!("canonical author request is not UTF-8: {error}"))
        })?;
        if let Some(bundle_json) = self
            .store
            .clone()
            .completed_managed_actor_authoring_async(
                subject_key.clone(),
                request_digest.clone(),
                request_json.clone(),
            )
            .await?
        {
            let record = self
                .store
                .clone()
                .managed_actor_identity_async(subject_key.clone())
                .await?
                .ok_or_else(|| {
                    BridgeError::Database(
                        "completed authoring has no managed actor identity".to_owned(),
                    )
                })?;
            let identity = self.decode_identity(&subject_key, record)?;
            let bundle = serde_json::from_str(&bundle_json).map_err(|error| {
                BridgeError::Database(format!(
                    "stored managed actor creation Event is invalid: {error}"
                ))
            })?;
            self.freeze_creation(request, &bundle, &identity)?;
            return Ok(bundle);
        }
        self.validate_request(request, true).await?;
        let identity = self.identity_for(&subject_key, request).await?;
        let owner_token = random_token(24)?;

        for _ in 0..AUTHORING_WAIT_ATTEMPTS {
            match self
                .store
                .clone()
                .claim_managed_actor_authoring_async(
                    subject_key.clone(),
                    request_digest.clone(),
                    request_json.clone(),
                    owner_token.clone(),
                    AUTHORING_LEASE_SECS,
                )
                .await?
            {
                ManagedActorAuthoringClaim::Completed(bundle_json) => {
                    let bundle = serde_json::from_str(&bundle_json).map_err(|error| {
                        BridgeError::Database(format!(
                            "stored managed actor creation Event is invalid: {error}"
                        ))
                    })?;
                    self.freeze_creation(request, &bundle, &identity)?;
                    return Ok(bundle);
                }
                ManagedActorAuthoringClaim::Busy => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                ManagedActorAuthoringClaim::Acquired => {
                    let built = self.build_creation_event(request, &identity).await;
                    match built {
                        Ok(bundle) => {
                            let bundle_json = String::from_utf8(canonical_json_bytes(&bundle)?)
                                .map_err(|error| {
                                    BridgeError::App(format!(
                                        "canonical creation Event is not UTF-8: {error}"
                                    ))
                                })?;
                            self.store
                                .clone()
                                .complete_managed_actor_authoring_async(
                                    subject_key,
                                    request_digest,
                                    owner_token,
                                    bundle_json,
                                )
                                .await?;
                            self.freeze_creation(request, &bundle, &identity)?;
                            return Ok(bundle);
                        }
                        Err(error) => {
                            if let Err(abandon_error) = self
                                .store
                                .clone()
                                .abandon_managed_actor_authoring_async(
                                    subject_key,
                                    request_digest,
                                    owner_token,
                                )
                                .await
                            {
                                tracing::warn!(%abandon_error, "failed to release managed actor authoring claim");
                            }
                            return Err(error);
                        }
                    }
                }
            }
        }
        Err(BridgeError::Runtime(
            "timed out waiting for the durable managed actor authoring lease".to_owned(),
        ))
    }

    fn freeze_creation(
        &self,
        request: &AppletManagedActorAuthoringRequest,
        event: &Event,
        identity: &ManagedActorIdentity,
    ) -> Result<()> {
        self.edge.prepare_managed_authoring(
            &PreparedManagedActor {
                authoring_request: request.clone(),
                create_event: event.clone(),
            },
            &identity.root_verification_method,
            &identity.root_public_key,
        )?;
        Ok(())
    }

    async fn validate_request(
        &self,
        request: &AppletManagedActorAuthoringRequest,
        require_fresh: bool,
    ) -> Result<()> {
        request.validate_bindings().map_err(|error| {
            BridgeError::App(format!(
                "managed actor authoring request is invalid: {error}"
            ))
        })?;
        if require_fresh && request.expires_at <= Utc::now() {
            return Err(BridgeError::App(
                "managed actor authoring request has expired".to_owned(),
            ));
        }
        if request.proof.created_at > Utc::now() + chrono::Duration::seconds(30) {
            return Err(BridgeError::App(
                "managed actor authoring proof is in the future".to_owned(),
            ));
        }
        let (applet_id, service_id, target_station_id, epoch, purpose) = match &request.basis {
            arkret::AppletManagedActorAuthoringBasis::ProvisionBot(basis) => (
                &basis.applet_id,
                &basis.service_id,
                &basis.target_station_id,
                &basis.registration_epoch_evidence,
                AppletManagedActorPurpose::ProvisionBot,
            ),
            arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) => (
                &basis.applet_id,
                &basis.service_id,
                &basis.target_station_id,
                &basis.registration_epoch_evidence,
                AppletManagedActorPurpose::ProvisionGhost,
            ),
        };
        let configured_applet_id = AppletId::new(self.config.arkret.applet_id.clone())?;
        if *applet_id != configured_applet_id
            || service_id != self.edge.service_actor_id()
            || request.purpose != purpose
        {
            return Err(BridgeError::App(
                "managed actor authoring request coordinates do not match this Applet service"
                    .into(),
            ));
        }
        let realm = crate::managed_authoring::authoring_scope(request)
            .realm_id_opt()
            .ok_or_else(|| BridgeError::App("authoring requires an owning Realm".into()))?;
        let route = self.edge.realm_route(realm).await?;
        // A fresh authoring request must come from the current governor.
        // An already frozen response may replay a historical signed request.
        let public_key = if require_fresh {
            if target_station_id != route.authority.current_service_id() {
                return Err(BridgeError::App(
                    "authoring request is from a previous governor".into(),
                ));
            }
            route.station_key(&request.proof.verification_method, request.proof.created_at)?
        } else {
            route
                .historical_station_key(
                    target_station_id,
                    &request.proof.verification_method,
                    request.proof.created_at,
                )
                .await?
        };
        Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                &request.proof.jws,
                &request.proof_binding_bytes()?,
                &public_key,
            )
            .map_err(|error| {
                BridgeError::App(format!(
                    "managed actor authoring request proof is invalid: {error}"
                ))
            })?;
        let service_method = self.edge.service_verification_method()?;
        if require_fresh && !epoch.contains_signing_key(service_method.as_str()) {
            return Err(BridgeError::App(
                "Applet service signing key is outside the request registration epoch".to_owned(),
            ));
        }
        Ok(())
    }

    async fn identity_for(
        &self,
        subject_key: &str,
        request: &AppletManagedActorAuthoringRequest,
    ) -> Result<ManagedActorIdentity> {
        if let Some(record) = self
            .store
            .clone()
            .managed_actor_identity_async(subject_key.to_owned())
            .await?
        {
            return self.decode_identity(subject_key, record);
        }
        let candidate = self.generate_identity(subject_key, request)?;
        let winner = self
            .store
            .clone()
            .install_managed_actor_identity_async(subject_key.to_owned(), candidate)
            .await?;
        self.decode_identity(subject_key, winner)
    }

    fn generate_identity(
        &self,
        subject_key: &str,
        request: &AppletManagedActorAuthoringRequest,
    ) -> Result<ManagedActorIdentityRecord> {
        let mut root_seed = [0_u8; 32];
        let mut next_root_seed = [0_u8; 32];
        let mut controller_seed = [0_u8; 32];
        getrandom::fill(&mut root_seed).map_err(|error| {
            BridgeError::Runtime(format!("managed actor root RNG failed: {error}"))
        })?;
        getrandom::fill(&mut next_root_seed).map_err(|error| {
            BridgeError::Runtime(format!("managed actor next-root RNG failed: {error}"))
        })?;
        getrandom::fill(&mut controller_seed).map_err(|error| {
            BridgeError::Runtime(format!("managed actor controller RNG failed: {error}"))
        })?;
        let local_id = subject_key
            .strip_prefix("sha256:")
            .unwrap_or(subject_key)
            .chars()
            .take(32)
            .collect::<String>();
        let next_key = arkret::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&next_root_seed)
                .verifying_key()
                .as_bytes(),
        );
        let inception = arkret::webvh::prepare_realm_actor_inception(
            &arkret::webvh::RealmActorInceptionInput {
                principal_endpoint: &self.principal_endpoint,
                local_id: &local_id,
                controller_public_key: &SigningKey::from_bytes(&controller_seed)
                    .verifying_key()
                    .to_bytes(),
                version_time: request.issued_at,
                root_seed: &root_seed,
                next_root_public_key_multibase: &next_key,
            },
        )
        .map_err(|error| {
            BridgeError::App(format!("managed actor WebVH inception failed: {error}"))
        })?;
        let did = Did::new(inception.did.clone())?;
        if request.purpose == AppletManagedActorPurpose::ProvisionGhost
            && !self
                .config
                .arkret
                .applet_namespaces
                .actors
                .iter()
                .any(|entry| {
                    namespace_pattern_matches(
                        arkret::AppletNamespaceDomain::Actors,
                        &entry.pattern,
                        did.as_str(),
                    )
                })
        {
            return Err(BridgeError::Config(format!(
                "generated managed actor DID `{did}` is outside applet_namespaces.actors"
            )));
        }
        let method_history_head = canonical_sha256(&inception.log_entry)?;
        let document: arkret::DidDocument =
            serde_json::from_value(inception.log_entry["state"].clone())?;
        let document_digest =
            arkret::identity::document_canonical_digest(&document).map_err(|error| {
                BridgeError::App(format!("managed actor document digest failed: {error}"))
            })?;
        let witness_records = Vec::<Value>::new();
        let witness_proofs_digest = Hash::new(canonical_sha256(&witness_records)?)?;
        let boundary = ResolutionMethodEvidenceBoundary {
            from_method_history_head: method_history_head.clone(),
            from_version_id: inception.version_id.clone(),
            to_method_history_head: method_history_head.clone(),
            to_version_id: inception.version_id.clone(),
        };
        let method_history_evidence = ResolutionMethodHistoryEvidence::WebvhLog {
            boundary,
            evidence: ResolutionDidBindingEvidenceReceipt {
                kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                method: "webvh".to_owned(),
                document_digest,
                method_proofs: vec![ResolutionDidBindingMethodProof {
                    kind: arkret::ResolutionDidBindingMethodProofKind::WebvhLog,
                    history_head: method_history_head.clone(),
                    witnesses: Vec::new(),
                    witness_proofs_digest,
                }],
            },
            log_entries: vec![inception.log_entry],
            witness_records,
        };
        let initial_resolution = ResolutionCommitment {
            did: did.clone(),
            method_history_head,
            version_id: inception.version_id,
        };
        let encrypted_key_material = self.encrypt_key_material(
            subject_key,
            &ManagedActorKeyMaterial {
                root_seed: arkret::base64url_encode(root_seed),
                next_root_seed: arkret::base64url_encode(next_root_seed),
            },
        )?;
        Ok(ManagedActorIdentityRecord {
            actor_did: did.to_string(),
            initial_resolution_json: serde_json::to_string(&initial_resolution).map_err(
                |error| {
                    BridgeError::Runtime(format!("managed actor resolution encode failed: {error}"))
                },
            )?,
            method_history_evidence_json: serde_json::to_string(&method_history_evidence).map_err(
                |error| {
                    BridgeError::Runtime(format!(
                        "managed actor method evidence encode failed: {error}"
                    ))
                },
            )?,
            encrypted_key_material,
            encrypted_controller_material: Some(self.encrypt_key_material(
                &format!("managed-controller/v1/{subject_key}"),
                &arkret::base64url_encode(controller_seed),
            )?),
        })
    }

    fn decode_identity(
        &self,
        subject_key: &str,
        record: ManagedActorIdentityRecord,
    ) -> Result<ManagedActorIdentity> {
        // Authenticate/decrypt on every load. A deployment with the wrong key
        // must fail before replaying or issuing an identity it cannot control.
        let key_material: ManagedActorKeyMaterial =
            self.decrypt_key_material(subject_key, &record.encrypted_key_material)?;
        let did = Did::new(record.actor_did)?;
        let actor_id = project_did_to_core_id(&did)?;
        let initial_resolution =
            serde_json::from_str(&record.initial_resolution_json).map_err(|error| {
                BridgeError::Database(format!(
                    "stored managed actor resolution is invalid: {error}"
                ))
            })?;
        let method_history_evidence = serde_json::from_str(&record.method_history_evidence_json)
            .map_err(|error| {
                BridgeError::Database(format!(
                    "stored managed actor method evidence is invalid: {error}"
                ))
            })?;
        let verified_root =
            verify_managed_actor_root(&did, &method_history_evidence, &key_material)?;
        let identity = ManagedActorIdentity {
            actor_id,
            initial_resolution,
            method_history_evidence,
            root_verification_method: verified_root.verification_method,
            root_public_key: verified_root.public_key,
        };
        // The three stored columns describe one identity. A row whose actor,
        // resolution commitment and method evidence disagree cannot be used to
        // author anything, so it fails here rather than downstream.
        let boundary = identity.method_history_evidence.boundary();
        if project_did_to_core_id(&identity.initial_resolution.did)? != identity.actor_id
            || boundary.to_method_history_head != identity.initial_resolution.method_history_head
            || boundary.to_version_id != identity.initial_resolution.version_id
            || verified_root.principal_id != identity.actor_id
            || verified_root.log_head_digest.as_str()
                != identity.initial_resolution.method_history_head
            || verified_root.did_version_id != identity.initial_resolution.version_id
        {
            return Err(BridgeError::Database(
                "stored managed actor identity, resolution and method evidence disagree".into(),
            ));
        }
        Ok(identity)
    }

    fn decode_original_controller(
        &self,
        subject: &str,
        record: &ManagedActorIdentityRecord,
        identity: &ManagedActorIdentity,
    ) -> Result<SigningKey> {
        let raw = record
            .encrypted_controller_material
            .as_ref()
            .ok_or_else(|| {
                BridgeError::Database(
                    "daily controller key is unavailable; native recovery custody is independent"
                        .into(),
                )
            })?;
        let seed: String =
            self.decrypt_key_material(&format!("managed-controller/v1/{subject}"), raw)?;
        let seed = decode_managed_actor_seed("controller_seed", &seed)?;
        let native: ManagedActorKeyMaterial =
            self.decrypt_key_material(subject, &record.encrypted_key_material)?;
        if seed == decode_managed_actor_seed("root_seed", &native.root_seed)?
            || seed == decode_managed_actor_seed("next_root_seed", &native.next_root_seed)?
        {
            return Err(BridgeError::Database(
                "daily controller must not share a native update key".into(),
            ));
        }
        let key = SigningKey::from_bytes(&seed);
        let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
            &identity.method_history_evidence
        else {
            return Err(BridgeError::Database(
                "controller requires native inception".into(),
            ));
        };
        let document: arkret::DidDocument =
            serde_json::from_value(log_entries[0]["state"].clone())?;
        let method = DidUrl::new(format!(
            "{}#managed-controller",
            identity.initial_resolution.did
        ))
        .map_err(|e| BridgeError::Database(e.to_string()))?;
        arkret::identity::validate_verification_method_relationship(
            &document,
            &method,
            &identity.initial_resolution.did,
            arkret::identity::DidVerificationRelationship::AssertionMethod,
        )
        .map_err(|e| BridgeError::Database(e.to_string()))?;
        let actual =
            arkret::identity::jws::resolve_ed25519_pubkey_from_document(&document, method.as_str())
                .map_err(|e| BridgeError::Database(e.to_string()))?;
        if key.verifying_key() != actual {
            return Err(BridgeError::Database(
                "daily controller differs from retained inception".into(),
            ));
        }
        Ok(key)
    }

    pub(crate) fn encrypt_key_material<T: Serialize>(
        &self,
        subject_key: &str,
        material: &T,
    ) -> Result<String> {
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|error| {
            BridgeError::Runtime(format!("managed actor nonce RNG failed: {error}"))
        })?;
        let key = Key::from(self.key_encryption_key);
        let nonce = XNonce::from(nonce);
        let cipher = XChaCha20Poly1305::new(&key);
        let plaintext = canonical_json_bytes(material)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plaintext,
                    aad: subject_key.as_bytes(),
                },
            )
            .map_err(|_| BridgeError::Runtime("managed actor key encryption failed".to_owned()))?;
        Ok(format!(
            "v1.{}.{}",
            arkret::base64url_encode(nonce),
            arkret::base64url_encode(ciphertext)
        ))
    }

    pub(crate) fn decrypt_key_material<T: for<'de> Deserialize<'de>>(
        &self,
        subject_key: &str,
        encoded: &str,
    ) -> Result<T> {
        let mut parts = encoded.split('.');
        if parts.next() != Some("v1") {
            return Err(BridgeError::Database(
                "managed actor encrypted key material has an unknown version".to_owned(),
            ));
        }
        let nonce = arkret::base64url_decode(parts.next().unwrap_or_default())?;
        let ciphertext = arkret::base64url_decode(parts.next().unwrap_or_default())?;
        if parts.next().is_some() || nonce.len() != 24 {
            return Err(BridgeError::Database(
                "managed actor encrypted key material is malformed".to_owned(),
            ));
        }
        let key = Key::from(self.key_encryption_key);
        let cipher = XChaCha20Poly1305::new(&key);
        let nonce = XNonce::try_from(nonce.as_slice()).expect("nonce length was validated");
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: subject_key.as_bytes(),
                },
            )
            .map_err(|_| {
                BridgeError::Config(
                    "managed actor key material cannot be decrypted with the configured key"
                        .to_owned(),
                )
            })?;
        serde_json::from_slice(&plaintext).map_err(|error| {
            BridgeError::Database(format!("managed actor key plaintext is invalid: {error}"))
        })
    }

    /// Author one creation Event with independent native controller proof.
    async fn build_creation_event(
        &self,
        request: &AppletManagedActorAuthoringRequest,
        identity: &ManagedActorIdentity,
    ) -> Result<Event> {
        let subject = managed_actor_subject_key(request)?;
        let record = self
            .store
            .clone()
            .managed_actor_identity_async(subject.clone())
            .await?
            .ok_or_else(|| BridgeError::Database("authoring identity disappeared".into()))?;
        let controller = self.decode_original_controller(&subject, &record, identity)?;
        let (applet, role, registration, grant, request_id, external) = match &request.basis {
            arkret::AppletManagedActorAuthoringBasis::ProvisionBot(b) => (
                b.applet_id.clone(),
                "bot",
                b.registration_event_ref.clone(),
                b.authorization_ref.clone(),
                b.request_id.clone(),
                None,
            ),
            arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(b) => (
                b.applet_id.clone(),
                "ghost",
                b.registration_event_ref.clone(),
                b.authorization_ref.clone(),
                random_token(32)?,
                Some(&b.external_ref),
            ),
        };
        let realm = crate::managed_authoring::authoring_scope(request)
            .realm_id_opt()
            .ok_or_else(|| BridgeError::App("creation requires a Realm".into()))?;
        let method = DidUrl::new(format!(
            "{}#managed-controller",
            identity.initial_resolution.did
        ))
        .map_err(|e| BridgeError::App(e.into()))?;
        let mut value = json!({
            "schema": arkret::RealmActorCreatePayload::SCHEMA,
            "actor_id": arkret::ActorId::realm(arkret::RealmActorId { realm_id: realm.clone(), principal_id: identity.actor_id.clone() }),
            "applet_id": applet, "service_id": request.basis.service_id(), "actor_role": role,
            "request_id": request_id, "creation_scope": crate::managed_authoring::authoring_scope(request),
            "registration_ref": registration, "creation_authorization_ref": grant,
            "initial_resolution": identity.initial_resolution,
            "method_history_evidence": identity.method_history_evidence,
            "control_method_kid": method, "expires_at": arkret::canonical::format_timestamp_canonical(request.expires_at),
            "recovery": { "kind": "manager_native", "enabled": true }
        });
        if let Some(external) = external {
            value["external_ref"] = serde_json::to_value(external)?;
        }
        let transcript: arkret::RealmActorCreationTranscript =
            serde_json::from_value(value.clone())?;
        value["control_signature"] = serde_json::to_value(
            arkret::signatures::detached_object::sign_detached_object(
                &transcript,
                arkret::DetachedSignatureContext::RealmActorCreation,
                method,
                request.issued_at,
                &controller,
            )
            .map_err(|e| BridgeError::App(e.to_string()))?,
        )?;
        arkret::author_realm_actor_create(
            serde_json::from_value(value)?,
            runtime::PRODUCER_DIGEST_SUITE,
            request.issued_at,
            self.edge.signer(),
        )
        .map_err(|e| BridgeError::App(e.to_string()))
    }
}

fn verify_managed_actor_root(
    did: &Did,
    method_history_evidence: &ResolutionMethodHistoryEvidence,
    key_material: &ManagedActorKeyMaterial,
) -> Result<VerifiedManagedActorRoot> {
    let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } = method_history_evidence
    else {
        return Err(BridgeError::Database(
            "stored managed actor identity does not carry WebVH inception history".into(),
        ));
    };
    let [entry] = log_entries.as_slice() else {
        return Err(BridgeError::Database(
            "stored managed actor identity must carry exactly its WebVH inception entry".into(),
        ));
    };
    let version_time = entry
        .get("versionTime")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            BridgeError::Database("stored managed actor WebVH inception has no versionTime".into())
        })?
        .parse()
        .map_err(|error| {
            BridgeError::Database(format!(
                "stored managed actor WebVH inception versionTime is invalid: {error}"
            ))
        })?;
    let validated = arkret::webvh::validate_webvh_history_at(did, log_entries, version_time)
        .map_err(|error| {
            BridgeError::Database(format!(
                "stored managed actor WebVH inception proof is invalid: {error}"
            ))
        })?;
    let verification_method = entry
        .pointer("/proof/0/verificationMethod")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            BridgeError::Database(
                "stored managed actor WebVH inception has no root verification method".into(),
            )
        })?;
    let expected_verification_method = format!(
        "did:key:{}#{}",
        validated.active_update_key_multibase, validated.active_update_key_multibase
    );
    if verification_method != expected_verification_method {
        return Err(BridgeError::Database(
            "stored managed actor WebVH proof method differs from its active update key".into(),
        ));
    }
    let verification_method = DidUrl::new(verification_method.to_owned()).map_err(|error| {
        BridgeError::Database(format!(
            "stored managed actor root verification method is invalid: {error}"
        ))
    })?;
    let next_root_key_hash = entry
        .pointer("/parameters/nextKeyHashes/0")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            BridgeError::Database(
                "stored managed actor WebVH inception has no next-root commitment".into(),
            )
        })?;
    let root_seed = decode_managed_actor_seed("root_seed", &key_material.root_seed)?;
    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: SigningKey::from_bytes(&root_seed)
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    let validated_root_key = PublicKeyMaterial::Ed25519Multibase {
        value: validated.active_update_key_multibase,
    };
    if public_key.ed25519_bytes()? != validated_root_key.ed25519_bytes()? {
        return Err(BridgeError::Database(
            "stored managed actor root seed does not match its verified WebVH inception".into(),
        ));
    }
    let next_root_seed = decode_managed_actor_seed("next_root_seed", &key_material.next_root_seed)?;
    let next_root_multibase = arkret::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&next_root_seed)
            .verifying_key()
            .as_bytes(),
    );
    if arkret::webvh::webvh_next_key_hash(&next_root_multibase).map_err(|error| {
        BridgeError::Database(format!(
            "stored managed actor next-root key is invalid: {error}"
        ))
    })? != next_root_key_hash
    {
        return Err(BridgeError::Database(
            "stored managed actor next-root seed does not match its WebVH commitment".into(),
        ));
    }
    Ok(VerifiedManagedActorRoot {
        principal_id: project_did_to_core_id(did)?,
        log_head_digest: Hash::new(canonical_sha256(entry)?)?,
        did_version_id: validated.version_id,
        verification_method,
        public_key,
    })
}

fn decode_managed_actor_seed(name: &str, encoded: &str) -> Result<[u8; 32]> {
    let decoded = arkret::base64url_decode(encoded).map_err(|error| {
        BridgeError::Database(format!("stored managed actor {name} is invalid: {error}"))
    })?;
    decoded.try_into().map_err(|value: Vec<u8>| {
        BridgeError::Database(format!(
            "stored managed actor {name} must be 32 bytes, got {}",
            value.len()
        ))
    })
}

/// Prepare one Realm-scoped Ghost using a signed current governance basis.
/// The original creation and independent native DID custody remain unchanged
/// across a later governance handoff.
impl ManagedActorAuthoringService {
    pub async fn prepare_ghost(
        &self,
        applet_id: &AppletId,
        realm_id: &arkret::RealmId,
        external_ref: &arkret::GhostExternalTuple,
        display_name: Option<String>,
    ) -> Result<PreparedGhost> {
        self.prepare_ghost_in_scope(
            applet_id,
            &arkret::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            external_ref,
            display_name,
        )
        .await
    }

    pub async fn prepare_ghost_in_scope(
        &self,
        applet_id: &AppletId,
        scope: &arkret::ScopeRef,
        external_ref: &arkret::GhostExternalTuple,
        display_name: Option<String>,
    ) -> Result<PreparedGhost> {
        if !matches!(
            scope,
            arkret::ScopeRef::Realm { .. } | arkret::ScopeRef::Circle { .. }
        ) {
            return Err(BridgeError::App(
                "Ghost creation requires a Realm or Circle scope".into(),
            ));
        }
        let route = self.edge.realm_route(scope.realm_id()).await?;
        let preview = route
            .client
            .ghost_actor_preview(
                applet_id.as_str(),
                &GhostPreviewRequestBody {
                    effective_scope: scope.clone(),
                    external_ref: external_ref.clone(),
                    display_name,
                },
            )
            .await?;
        if let Some(existing) = preview.existing_managed_actor {
            self.validate_request(&preview.authoring_request, true)
                .await?;
            self.edge
                .reused_ghost_did(&preview.authoring_request, &existing)?;
            return Ok(PreparedGhost::Reuse {
                authoring_request: preview.authoring_request,
                existing,
            });
        }
        let create_event = self.author(&preview.authoring_request).await?;
        Ok(PreparedGhost::Create(PreparedManagedActor {
            authoring_request: preview.authoring_request,
            create_event,
        }))
    }
}

fn managed_actor_subject_key(request: &AppletManagedActorAuthoringRequest) -> Result<String> {
    let material = match &request.basis {
        arkret::AppletManagedActorAuthoringBasis::ProvisionBot(basis) => json!({
            "purpose": request.purpose, "applet_id": basis.applet_id,
            "realm_id": basis.effective_scope.realm_id_opt(), "request_id": basis.request_id,
        }),
        arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) => json!({
            "purpose": request.purpose, "applet_id": basis.applet_id,
            "realm_id": basis.effective_scope.realm_id_opt(), "external_ref": basis.external_ref,
        }),
    };
    Ok(canonical_sha256(&material)?)
}

fn random_token(bytes: usize) -> Result<String> {
    let mut value = vec![0_u8; bytes];
    getrandom::fill(&mut value)
        .map_err(|error| BridgeError::Runtime(format!("authoring token RNG failed: {error}")))?;
    Ok(arkret::base64url_encode(value))
}

#[cfg(feature = "web")]
#[derive(Clone)]
struct AuthoringWebState {
    service: Arc<ManagedActorAuthoringService>,
}

#[cfg(feature = "web")]
async fn publish_native_resource(req: &Request, depot: &Depot, res: &mut Response, history: bool) {
    let Ok(state) = depot.get_typed::<AuthoringWebState>() else {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        return;
    };
    let local_id = req.param::<String>("local_id").unwrap_or_default();
    match state.service.published_principal(&local_id).await {
        Ok(Some((document, entries))) => {
            res.headers_mut().insert(
                "cache-control",
                "no-store".parse().expect("static cache policy"),
            );
            if history {
                let mut body = Vec::new();
                for entry in entries {
                    match canonical_json_bytes(&entry) {
                        Ok(bytes) => {
                            body.extend(bytes);
                            body.push(b'\n');
                        }
                        Err(_) => {
                            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                            return;
                        }
                    }
                }
                res.headers_mut().insert(
                    "content-type",
                    "application/jsonl".parse().expect("static content type"),
                );
                if let Err(error) = res.write_body(body) {
                    tracing::error!(%error,"managed history response write failed");
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                }
            } else {
                res.render(Json(document));
            }
        }
        Ok(None) => {
            res.status_code(StatusCode::NOT_FOUND);
        }
        Err(error) => {
            tracing::error!(%error,"managed native identity publication failed");
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
}
#[cfg(feature = "web")]
#[handler]
async fn published_document(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    publish_native_resource(req, depot, res, false).await;
}
#[cfg(feature = "web")]
#[handler]
async fn published_history(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    publish_native_resource(req, depot, res, true).await;
}

#[cfg(feature = "web")]
#[handler]
async fn author_managed_actor(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<AuthoringWebState>() else {
        render_author_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "authoring_state_missing",
            "managed actor authoring state is unavailable",
        );
        return;
    };
    state.service.serve(req, res).await;
}

impl ManagedActorAuthoringService {
    /// Serve the canonical author operation after the host selects this exact Applet.
    #[cfg(feature = "web")]
    pub async fn serve(&self, req: &mut Request, res: &mut Response) {
        let body: AppletManagedActorAuthorRequestBody = match req.parse_json().await {
            Ok(body) => body,
            Err(error) => {
                render_author_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_author_request",
                    &format!("invalid managed actor author request: {error}"),
                );
                return;
            }
        };
        match self.author(&body.authoring_request).await {
            Ok(create_event) => res.render(Json(AppletManagedActorAuthorOutcome { create_event })),
            Err(error) => {
                let status = match &error {
                    BridgeError::App(message) if message.contains("expired") => StatusCode::GONE,
                    BridgeError::App(_) | BridgeError::Arkret(_) => StatusCode::BAD_REQUEST,
                    BridgeError::Config(_) | BridgeError::Database(_) | BridgeError::Runtime(_) => {
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                render_author_error(
                    res,
                    status,
                    "managed_actor_authoring_failed",
                    &error.to_string(),
                );
            }
        }
    }
}

#[cfg(feature = "web")]
fn render_author_error(res: &mut Response, status: StatusCode, code: &str, detail: &str) {
    res.status_code(status);
    res.render(Json(json!({
        "type": format!("https://arkret.org/problems/{code}"),
        "title": "Managed actor authoring failed",
        "status": status.as_u16(),
        "detail": detail,
        "code": code,
    })));
}

#[cfg(test)]
mod ghost_bundle_tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use arkret::canonical::DigestSuite;
    use arkret::webvh::{RealmActorInceptionInput, prepare_realm_actor_inception};
    use arkret::{
        AppletDidMethodVersionEvidence, AppletGhostAuthoringRequestBasis,
        AppletRegistrationEpochEvidence, DidDocument, GhostExternalTuple,
    };
    use arkret_signatures::Ed25519PayloadSigner;
    use arkret_wire::{DidUrl, EventId, GrantId, RealmId, TrustDomainId};
    use chrono::{DateTime, TimeZone};

    use super::*;
    use crate::AuthoringStore as _;

    #[derive(Default)]
    pub(super) struct RecordingAuthoringStore(Mutex<BTreeMap<String, String>>);

    impl runtime::AuthoringStore for RecordingAuthoringStore {
        fn load(&self, key: &str) -> Result<Option<String>> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }

        fn compare_exchange_batch(
            &self,
            expected: &[(String, Option<String>)],
            writes: &[(String, Option<String>)],
        ) -> Result<bool> {
            let mut rows = self.0.lock().unwrap();
            if expected
                .iter()
                .any(|(key, value)| rows.get(key) != value.as_ref())
            {
                return Ok(false);
            }
            for (key, value) in writes {
                if let Some(value) = value {
                    rows.insert(key.clone(), value.clone());
                } else {
                    rows.remove(key);
                }
            }
            Ok(true)
        }

        fn entries_with_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect())
        }
    }

    const STATION_DID: &str = "did:webvh:zstationscid:station.example";
    const SERVICE_DID: &str = "did:webvh:zservicescid:applet.example";

    fn issued_at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 17, 0, 0, 0).unwrap()
    }

    fn did(value: &str) -> Did {
        Did::new(value.to_owned()).unwrap()
    }

    fn core_id(value: &str) -> DidCoreId {
        project_did_to_core_id(&did(value)).unwrap()
    }

    fn signer(seed: u8, subject: &str) -> Ed25519PayloadSigner {
        Ed25519PayloadSigner::new(
            SigningKey::from_bytes(&[seed; 32]),
            did(subject),
            DidUrl::new(format!("{subject}#key-1")).unwrap(),
        )
    }

    fn event_id(byte: u8) -> EventId {
        EventId::from_digest(DigestSuite::Sha256, [byte; 32])
    }

    fn realm_id() -> RealmId {
        RealmId::from_event_id(&event_id(0x21))
    }

    fn registration_ref() -> EventId {
        event_id(0x44)
    }

    fn trust_domain() -> TrustDomainId {
        TrustDomainId::new("ak:trust_domain:station.example").unwrap()
    }

    pub(super) fn edge(store: Arc<dyn runtime::AuthoringStore>) -> runtime::ArkretEdge {
        let config: runtime::Config = serde_json::from_value(json!({
            "bridge": {"bridge_id": "ghost-preparation-test"},
            "arkret": {
                "server_url": "https://station.example",
                "service_did": SERVICE_DID,
                "trust_domain": trust_domain(),
                "applet_id": "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb",

                "signing_key_seed_hex": "22".repeat(32),
                "verification_method_fragment": "#key-1",
                "trusted_server_did": STATION_DID,
                "applet_namespaces": {"actors": [{"pattern":"did:webvh:*:applet.example:webvh:*","exclusive":true}], "realms": [], "handles": []},
                "managed_actor_authoring": {
                    "principal_endpoint": "https://applet.example/actors/slack",
                    "key_encryption_key_hex": "33".repeat(32)
                }
            }
        }))
        .unwrap();
        let (sender, _) = tokio::sync::mpsc::channel(1);
        runtime::ArkretEdge::new(Arc::new(config), store, sender).unwrap()
    }

    /// A real WebVH inception, prepared exactly the way `generate_identity`
    /// prepares one, so what is authored against here is the identity shape the
    /// running bridge stores rather than a hand-written stand-in.
    fn identity() -> ManagedActorIdentity {
        let next_key = arkret::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&[0x52; 32])
                .verifying_key()
                .as_bytes(),
        );
        let inception = prepare_realm_actor_inception(&RealmActorInceptionInput {
            principal_endpoint: &url::Url::parse("https://applet.example/actors/slack").unwrap(),
            local_id: "u123",
            controller_public_key: &SigningKey::from_bytes(&[0x55; 32])
                .verifying_key()
                .to_bytes(),
            version_time: issued_at(),
            root_seed: &[0x51; 32],
            next_root_public_key_multibase: &next_key,
        })
        .unwrap();
        let did_value = Did::new(inception.did.clone()).unwrap();
        let root_verification_method =
            DidUrl::new(inception.root_verification_method.clone()).unwrap();
        let root_public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&[0x51; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        let method_history_head = canonical_sha256(&inception.log_entry).unwrap();
        let document: arkret::DidDocument =
            serde_json::from_value(inception.log_entry["state"].clone()).unwrap();
        let document_digest = arkret::identity::document_canonical_digest(&document).unwrap();
        let witness_records = Vec::<Value>::new();
        let witness_proofs_digest = Hash::new(canonical_sha256(&witness_records).unwrap()).unwrap();
        ManagedActorIdentity {
            actor_id: project_did_to_core_id(&did_value).unwrap(),
            initial_resolution: ResolutionCommitment {
                did: did_value,
                method_history_head: method_history_head.clone(),
                version_id: inception.version_id.clone(),
            },
            method_history_evidence: ResolutionMethodHistoryEvidence::WebvhLog {
                boundary: ResolutionMethodEvidenceBoundary {
                    from_method_history_head: method_history_head.clone(),
                    from_version_id: inception.version_id.clone(),
                    to_method_history_head: method_history_head.clone(),
                    to_version_id: inception.version_id,
                },
                evidence: ResolutionDidBindingEvidenceReceipt {
                    kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                    method: "webvh".to_owned(),
                    document_digest,
                    method_proofs: vec![ResolutionDidBindingMethodProof {
                        kind: arkret::ResolutionDidBindingMethodProofKind::WebvhLog,
                        history_head: method_history_head,
                        witnesses: Vec::new(),
                        witness_proofs_digest,
                    }],
                },
                log_entries: vec![inception.log_entry],
                witness_records,
            },
            root_verification_method,
            root_public_key,
        }
    }

    #[test]
    fn persisted_root_material_must_match_the_verified_webvh_inception() {
        let identity = identity();
        let material = ManagedActorKeyMaterial {
            root_seed: arkret::base64url_encode([0x51; 32]),
            next_root_seed: arkret::base64url_encode([0x52; 32]),
        };
        let verified = verify_managed_actor_root(
            &identity.initial_resolution.did,
            &identity.method_history_evidence,
            &material,
        )
        .unwrap();
        assert_eq!(
            verified.verification_method,
            identity.root_verification_method
        );
        assert_eq!(
            verified.public_key.ed25519_bytes().unwrap(),
            identity.root_public_key.ed25519_bytes().unwrap()
        );

        let wrong_root = ManagedActorKeyMaterial {
            root_seed: arkret::base64url_encode([0x53; 32]),
            next_root_seed: material.next_root_seed.clone(),
        };
        assert!(
            verify_managed_actor_root(
                &identity.initial_resolution.did,
                &identity.method_history_evidence,
                &wrong_root,
            )
            .is_err()
        );
        let wrong_next_root = ManagedActorKeyMaterial {
            root_seed: material.root_seed.clone(),
            next_root_seed: arkret::base64url_encode([0x54; 32]),
        };
        assert!(
            verify_managed_actor_root(
                &identity.initial_resolution.did,
                &identity.method_history_evidence,
                &wrong_next_root,
            )
            .is_err()
        );
    }

    /// The Station-signed branch the bridge receives. The registration epoch is
    /// the Applet service's own registration, so its version identifier belongs
    /// to the service document above, not to the Ghost being provisioned.
    fn ghost_request() -> AppletManagedActorAuthoringRequest {
        let document = DidDocument::new(
            did(SERVICE_DID),
            "key-1",
            "z6MkrJVnaZkeF7EsnJQ9xQY4bqG9tbeFqTzL7uTVs11FwUjT",
        );
        let basis = AppletGhostAuthoringRequestBasis {
            schema: AppletGhostAuthoringRequestBasis::SCHEMA.to_owned(),
            purpose: AppletManagedActorPurpose::ProvisionGhost,
            target_station_id: core_id(STATION_DID),
            applet_id: AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap(),
            service_id: core_id(SERVICE_DID),
            effective_scope: arkret::ScopeRef::Realm {
                realm_id: realm_id(),
            },
            existing_managed_actor: None,
            external_ref: GhostExternalTuple {
                protocol: "slack".to_owned(),
                instance_id: "t123".to_owned(),
                external_id: "u123".to_owned(),
            },
            display_name: Some("Alice on Slack".to_owned()),
            registration_event_ref: registration_ref(),
            authorization_ref: GrantId::from_event_id(&event_id(0x33)),
            registration_epoch_evidence: AppletRegistrationEpochEvidence::from_did_document(
                &document,
                AppletDidMethodVersionEvidence::versioned(
                    "did:webvh",
                    Some("1-applet-service-registration".to_owned()),
                    None,
                )
                .unwrap(),
            )
            .unwrap(),
            package_digest: Hash::new(format!("sha256:{}", "77".repeat(32))).unwrap(),
        };
        AppletManagedActorAuthoringRequest::sign_ghost(
            basis,
            core_id(STATION_DID),
            issued_at(),
            issued_at() + chrono::Duration::minutes(2),
            &signer(0x11, STATION_DID),
        )
        .unwrap()
    }

    fn bot_request(request_id: &str) -> AppletManagedActorAuthoringRequest {
        let ghost = ghost_request();
        let basis = ghost.basis.ghost().unwrap();
        AppletManagedActorAuthoringRequest::sign_bot(
            arkret::AppletBotAuthoringRequestBasis {
                schema: arkret::AppletBotAuthoringRequestBasis::SCHEMA.into(),
                purpose: AppletManagedActorPurpose::ProvisionBot,
                target_station_id: basis.target_station_id.clone(),
                applet_id: basis.applet_id.clone(),
                service_id: basis.service_id.clone(),
                display_name: Some("Service Bot".into()),
                registration_event_ref: basis.registration_event_ref.clone(),
                authorization_ref: basis.authorization_ref.clone(),
                registration_epoch_evidence: basis.registration_epoch_evidence.clone(),
                package_digest: basis.package_digest.clone(),
                effective_scope: basis.effective_scope.clone(),
                request_id: request_id.into(),
            },
            core_id(STATION_DID),
            issued_at(),
            issued_at() + chrono::Duration::minutes(2),
            &signer(0x11, STATION_DID),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn realm_creation_preserves_independent_native_custody_and_exact_preparation() {
        let store = Arc::new(RecordingAuthoringStore::default());
        let edge = Arc::new(edge(store.clone()));
        let service = ManagedActorAuthoringService::new(edge.clone()).unwrap();
        for request in [ghost_request(), bot_request("abcdefghijklmnopqrstuv")] {
            let subject = managed_actor_subject_key(&request).unwrap();
            let identity = service.identity_for(&subject, &request).await.unwrap();
            let event = service
                .build_creation_event(&request, &identity)
                .await
                .unwrap();
            let payload = crate::managed_authoring::creation_payload(&event).unwrap();
            assert_eq!(
                payload.actor_id.as_realm_actor_id().unwrap().realm_id,
                realm_id()
            );
            assert_eq!(
                event.scope_ref,
                arkret::ScopeRef::RealmControl {
                    realm_id: realm_id()
                }
            );
            assert_ne!(
                payload.actor_id.signing_principal_id(),
                edge.service_actor_id()
            );
            assert_eq!(payload.initial_resolution, identity.initial_resolution);
            arkret::identity::verify_realm_actor_initial_resolution(&payload, event.created_at)
                .unwrap();
            crate::managed_authoring::verify_creation_service(
                &event,
                &edge.service_verification_method().unwrap(),
                &PublicKeyMaterial::Ed25519Raw {
                    bytes: edge.signer().verifying_key().to_bytes().to_vec(),
                },
            )
            .unwrap();
            service
                .freeze_creation(&request, &event, &identity)
                .unwrap();
            service
                .freeze_creation(&request, &event, &identity)
                .unwrap();
            let mut changed = event.clone();
            changed.created_at += chrono::Duration::seconds(1);
            assert!(
                service
                    .freeze_creation(&request, &changed, &identity)
                    .is_err()
            );
            let reopened =
                ManagedActorAuthoringService::new(Arc::new(edge_from_store(store.clone())))
                    .unwrap();
            let retained = reopened.identity_for(&subject, &request).await.unwrap();
            assert_eq!(identity.initial_resolution, retained.initial_resolution);
            assert_eq!(
                identity.root_verification_method,
                retained.root_verification_method
            );
            let record = service
                .store
                .clone()
                .managed_actor_identity_async(subject.clone())
                .await
                .unwrap()
                .unwrap();
            let mut wrong = reopened;
            wrong.key_encryption_key = [99; 32];
            assert!(wrong.decode_identity(&subject, record.clone()).is_err());
            assert!(service.decode_identity("another-subject", record).is_err());
            let local_id = subject
                .strip_prefix("sha256:")
                .unwrap()
                .chars()
                .take(32)
                .collect::<String>();
            let (document, history) = service
                .published_principal(&local_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(document.id, payload.initial_resolution.did);
            assert_eq!(history.len(), 1);
            let state = serde_json::to_value(document).unwrap();
            assert!(
                state.get("arkret").is_none(),
                "Realm actors must not acquire Account/PCR bindings"
            );
            let mut record = service
                .store
                .clone()
                .managed_actor_identity_async(subject.clone())
                .await
                .unwrap()
                .unwrap();
            service
                .decode_original_controller(&subject, &record, &identity)
                .unwrap();
            let native_ciphertext = record.encrypted_key_material.clone();
            let original_daily = record.encrypted_controller_material.clone();
            record.encrypted_controller_material = Some(
                service
                    .encrypt_key_material(
                        &format!("managed-controller/v1/{subject}"),
                        &arkret::base64url_encode([0x66; 32]),
                    )
                    .unwrap(),
            );
            assert!(
                service
                    .decode_original_controller(&subject, &record, &identity)
                    .is_err()
            );
            assert!(service.decode_identity(&subject, record.clone()).is_ok());
            record.encrypted_controller_material = original_daily;
            let storage_key = format!("managed-identity/v1/{subject}");
            let before = store.load(&storage_key).unwrap();
            record.encrypted_controller_material = None;
            assert!(
                store
                    .compare_exchange_batch(
                        &[(storage_key.clone(), before)],
                        &[(storage_key, Some(serde_json::to_string(&record).unwrap()))],
                    )
                    .unwrap()
            );
            assert_eq!(record.encrypted_key_material, native_ciphertext);
            assert!(
                service
                    .decode_original_controller(&subject, &record, &identity)
                    .is_err()
            );
            assert!(service.decode_identity(&subject, record).is_ok());
            let (_, still_public) = service
                .published_principal(&local_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                still_public, history,
                "losing the daily key must not disable native publication"
            );
        }
    }

    fn edge_from_store(store: Arc<dyn runtime::AuthoringStore>) -> runtime::ArkretEdge {
        edge(store)
    }

    #[test]
    fn custody_is_partitioned_by_realm_applet_and_subject_not_governor_or_circle() {
        let original = ghost_request();
        let original_key = managed_actor_subject_key(&original).unwrap();
        let mut moved = original.clone();
        let arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) = &mut moved.basis
        else {
            unreachable!()
        };
        basis.target_station_id = core_id("did:webvh:znewstation:new.example");
        basis.effective_scope = arkret::ScopeRef::Circle {
            realm_id: realm_id(),
            circle_id: arkret::CircleId::from_event_id(&event_id(66)),
        };
        assert_eq!(original_key, managed_actor_subject_key(&moved).unwrap());
        let arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) = &mut moved.basis
        else {
            unreachable!()
        };
        basis.effective_scope = arkret::ScopeRef::Realm {
            realm_id: arkret::RealmId::from_event_id(&event_id(67)),
        };
        assert_ne!(original_key, managed_actor_subject_key(&moved).unwrap());
        let mut different = original.clone();
        let arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) = &mut different.basis
        else {
            unreachable!()
        };
        basis.external_ref.external_id.push('2');
        assert_ne!(original_key, managed_actor_subject_key(&different).unwrap());
        let mut different = original;
        let arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) = &mut different.basis
        else {
            unreachable!()
        };
        basis.applet_id = AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbc").unwrap();
        assert_ne!(original_key, managed_actor_subject_key(&different).unwrap());
        let bot = bot_request("abcdefghijklmnopqrstuv");
        let other_bot = bot_request("abcdefghijklmnopqrstuw");
        assert_ne!(
            managed_actor_subject_key(&bot).unwrap(),
            managed_actor_subject_key(&other_bot).unwrap()
        );
    }

    #[tokio::test]
    async fn authoring_rejects_other_applet_before_governance_lookup() {
        let service = ManagedActorAuthoringService::new(Arc::new(edge(Arc::new(
            RecordingAuthoringStore::default(),
        ))))
        .unwrap();
        let mut request = ghost_request();
        let arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) = &mut request.basis
        else {
            unreachable!()
        };
        basis.applet_id = AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbc").unwrap();
        assert!(service.author(&request).await.is_err());
        assert!(
            service
                .store
                .clone()
                .managed_actor_identity_async(managed_actor_subject_key(&request).unwrap())
                .await
                .unwrap()
                .is_none()
        );
    }
}
