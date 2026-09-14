//! Production Applet-managed Ghost identity authoring.
//!
//! One implementation backs both the canonical Applet author operation and
//! the messaging bridge's first-seen-user provisioning path. Identity keys are
//! random, encrypted at rest, and independent from the Applet service key.

use std::sync::Arc;

use arkret::canonical::{canonical_json_bytes, canonical_sha256};
use arkret::signatures::Ed25519DetachedJwsVerifier;
use arkret::{
    AppletId, AppletManagedActorAuthorOutcome, AppletManagedActorAuthorRequestBody,
    AppletManagedActorAuthoringBundle, AppletManagedActorAuthoringRequest,
    AppletManagedActorPurpose, Did, DidCoreId, GenesisSalt, GhostActorProvisionRequestBody,
    GhostPreviewRequestBody, Hash, ResolutionCommitment, ResolutionDidBindingEvidenceKind,
    ResolutionDidBindingEvidenceReceipt, ResolutionDidBindingMethodProof,
    ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence, SecurityClass,
    TrustDomainId, namespace_pattern_matches, project_did_to_core_id,
};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::ghost::{GhostProvisionAuthoringRequest, GhostProvisionRequestProvider};
use crate::store::{ManagedActorAuthoringClaim, ManagedActorIdentityRecord, MessageStore};
use crate::{BridgeError, Result, runtime};

const AUTHORING_LEASE_SECS: i64 = 30;
const AUTHORING_WAIT_ATTEMPTS: usize = 300;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedActorKeyMaterial {
    root_seed: String,
    next_root_seed: String,
}

struct ManagedActorIdentity {
    actor_id: DidCoreId,
    initial_resolution: ResolutionCommitment,
    method_history_evidence: ResolutionMethodHistoryEvidence,
}

/// Durable production authoring authority installed by every messaging bridge.
pub(crate) struct ManagedActorAuthoringService {
    edge: Arc<runtime::ArkretEdge>,
    store: Arc<MessageStore>,
    config: Arc<runtime::Config>,
    principal_endpoint: url::Url,
    key_encryption_key: [u8; 32],
    expected_station_id: DidCoreId,
}

impl ManagedActorAuthoringService {
    pub(crate) fn new(
        edge: Arc<runtime::ArkretEdge>,
        store: Arc<MessageStore>,
        config: Arc<runtime::Config>,
    ) -> Result<Self> {
        let principal_endpoint = config.arkret.managed_actor_authoring.principal_endpoint()?;
        let key_encryption_key = config.arkret.managed_actor_authoring.key_encryption_key()?;
        if config.arkret.applet_namespaces.actors.is_empty() {
            return Err(BridgeError::Config(
                "applet_namespaces.actors must contain the installed managed-actor namespace"
                    .to_owned(),
            ));
        }
        let expected_station_id = project_did_to_core_id(&config.arkret.trusted_server_did)?;
        Ok(Self {
            edge,
            store,
            config,
            principal_endpoint,
            key_encryption_key,
            expected_station_id,
        })
    }

    pub(crate) fn router(self: &Arc<Self>) -> Router {
        Router::with_path("_arkret/edge/applet/managed-actors/author")
            .hoop(affix_state::inject(AuthoringWebState {
                service: self.clone(),
            }))
            .post(author_managed_actor)
    }

    async fn author(
        &self,
        request: &AppletManagedActorAuthoringRequest,
    ) -> Result<AppletManagedActorAuthoringBundle> {
        self.validate_request(request, false)?;
        request.basis.ghost().ok_or_else(|| {
            BridgeError::App(
                "this running Applet service authors provision_ghost requests; install_bot uses the package build authority"
                    .to_owned(),
            )
        })?;
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
            let _ = self.decode_identity(&subject_key, record)?;
            return serde_json::from_str(&bundle_json).map_err(|error| {
                BridgeError::Database(format!(
                    "stored managed actor authoring bundle is invalid: {error}"
                ))
            });
        }
        self.validate_request(request, true)?;
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
                            "stored managed actor authoring bundle is invalid: {error}"
                        ))
                    })?;
                    return Ok(bundle);
                }
                ManagedActorAuthoringClaim::Busy => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                ManagedActorAuthoringClaim::Acquired => {
                    let built = self.build_ghost_bundle(request, &identity).await;
                    match built {
                        Ok(bundle) => {
                            let bundle_json = String::from_utf8(canonical_json_bytes(&bundle)?)
                                .map_err(|error| {
                                    BridgeError::App(format!(
                                        "canonical authoring bundle is not UTF-8: {error}"
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

    fn validate_request(
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
        let basis = request.basis.ghost().ok_or_else(|| {
            BridgeError::App("managed actor request is not a Ghost authoring branch".to_owned())
        })?;
        let configured_applet_id = AppletId::new(self.config.arkret.applet_id.clone())?;
        if basis.applet_id != configured_applet_id
            || basis.service_id != *self.edge.service_actor_id()
            || basis.target_station_id != self.expected_station_id
            || request.purpose != AppletManagedActorPurpose::ProvisionGhost
        {
            return Err(BridgeError::App(
                "managed actor authoring request coordinates do not match this Applet service"
                    .to_owned(),
            ));
        }
        let trusted = self
            .config
            .arkret
            .trusted_verification_methods
            .iter()
            .find(|candidate| {
                candidate.verification_method == request.proof.verification_method.as_str()
            })
            .ok_or_else(|| {
                BridgeError::App(
                    "managed actor authoring request is not signed by a configured Station key"
                        .to_owned(),
                )
            })?;
        if !request
            .proof
            .verification_method
            .as_str()
            .starts_with(&format!("{}#", self.config.arkret.trusted_server_did))
        {
            return Err(BridgeError::App(
                "managed actor authoring proof key is outside the trusted Station DID".to_owned(),
            ));
        }
        Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                &request.proof.jws,
                &request.proof_binding_bytes()?,
                &trusted.public_key,
            )
            .map_err(|error| {
                BridgeError::App(format!(
                    "managed actor authoring request proof is invalid: {error}"
                ))
            })?;
        let service_method = self.edge.service_verification_method()?;
        if !basis
            .registration_epoch_evidence
            .contains_signing_key(service_method.as_str())
        {
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
        getrandom::fill(&mut root_seed).map_err(|error| {
            BridgeError::Runtime(format!("managed actor root RNG failed: {error}"))
        })?;
        getrandom::fill(&mut next_root_seed).map_err(|error| {
            BridgeError::Runtime(format!("managed actor next-root RNG failed: {error}"))
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
        let inception =
            arkret::webvh::prepare_agent_inception(&arkret::webvh::AgentInceptionInput {
                principal_endpoint: &self.principal_endpoint,
                local_id: &local_id,
                controller_principal_id: request.basis.service_id(),
                version_time: request.issued_at,
                root_seed: &root_seed,
                next_root_public_key_multibase: &next_key,
            })
            .map_err(|error| {
                BridgeError::App(format!("managed actor WebVH inception failed: {error}"))
            })?;
        let did = Did::new(inception.did.clone())?;
        if !self
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
        let document_digest = Hash::new(canonical_sha256(&inception.log_entry["state"])?)?;
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
        })
    }

    fn decode_identity(
        &self,
        subject_key: &str,
        record: ManagedActorIdentityRecord,
    ) -> Result<ManagedActorIdentity> {
        // Authenticate/decrypt on every load. A deployment with the wrong key
        // must fail before replaying or issuing an identity it cannot control.
        let _: ManagedActorKeyMaterial =
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
        Ok(ManagedActorIdentity {
            actor_id,
            initial_resolution,
            method_history_evidence,
        })
    }

    fn encrypt_key_material(
        &self,
        subject_key: &str,
        material: &ManagedActorKeyMaterial,
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

    fn decrypt_key_material<T: for<'de> Deserialize<'de>>(
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

    async fn build_ghost_bundle(
        &self,
        request: &AppletManagedActorAuthoringRequest,
        identity: &ManagedActorIdentity,
    ) -> Result<AppletManagedActorAuthoringBundle> {
        let basis = request.basis.ghost().expect("request validated as Ghost");
        let realm_id = basis.realm_id.clone();
        let service_id = basis.service_id.clone();
        let frontier_selector = arkret::EventsFrontierSelector::RealmActor {
            realm_id: realm_id.clone(),
            actor_id: arkret::ActorId::service(service_id.clone()),
        };
        let frontier = self
            .edge
            .client()
            .events_frontier(&frontier_selector)
            .await?
            .frontier;
        let arkret::EventsFrontierView::RealmActor(frontier) = frontier else {
            return Err(BridgeError::Arkret(
                "Station returned the wrong service actor frontier variant".to_owned(),
            ));
        };
        let (seal_basis, data_basis, digest_suite) =
            self.edge.realm_authoring_basis(&realm_id).await?;

        let mut genesis_salt = [0_u8; 32];
        getrandom::fill(&mut genesis_salt)
            .map_err(|error| BridgeError::Runtime(format!("PCR salt RNG failed: {error}")))?;
        self.edge.author_managed_actor_bundle(
            request,
            arkret::AppletManagedActorBundleAuthoringInput {
                actor_id: identity.actor_id.clone(),
                initial_resolution: identity.initial_resolution.clone(),
                method_history_evidence: identity.method_history_evidence.clone(),
                service_actor_seq: frontier.next_actor_seq,
                service_prev_refs: frontier.frontier_event_ids,
                signer_resolution_evidence_ref: self
                    .config
                    .arkret
                    .signer_resolution_evidence_ref
                    .clone(),
                seal_basis,
                data_basis,
                digest_suite,
                trust_domain: TrustDomainId::new(self.config.arkret.trust_domain.to_string())?,
                security_class: SecurityClass::HighAssurance,
                genesis_salt: GenesisSalt::new(arkret::base64url_encode(genesis_salt))?,
                bot_display_name: "Applet Bot".to_owned(),
            },
        )
    }
}

#[async_trait::async_trait]
impl GhostProvisionRequestProvider for ManagedActorAuthoringService {
    async fn author_request(
        &self,
        request: &GhostProvisionAuthoringRequest,
    ) -> Result<GhostActorProvisionRequestBody> {
        let preview = self
            .edge
            .client()
            .ghost_actor_preview(
                request.applet_id.as_str(),
                &GhostPreviewRequestBody {
                    realm_id: request.realm_id.clone(),
                    external_ref: request.external_ref.clone(),
                    display_name: request.display_name.clone(),
                },
            )
            .await?;
        let managed_actor_bundle = self.author(&preview.authoring_request).await?;
        Ok(GhostActorProvisionRequestBody {
            authoring_request: preview.authoring_request,
            managed_actor_bundle,
        })
    }
}

fn managed_actor_subject_key(request: &AppletManagedActorAuthoringRequest) -> Result<String> {
    let basis = request.basis.ghost().ok_or_else(|| {
        BridgeError::App("managed actor subject requires a Ghost basis".to_owned())
    })?;
    Ok(canonical_sha256(&json!({
        "purpose": request.purpose,
        "applet_id": basis.applet_id,
        "target_station_id": basis.target_station_id,
        "external_ref": basis.external_ref,
    }))?)
}

fn random_token(bytes: usize) -> Result<String> {
    let mut value = vec![0_u8; bytes];
    getrandom::fill(&mut value)
        .map_err(|error| BridgeError::Runtime(format!("authoring token RNG failed: {error}")))?;
    Ok(arkret::base64url_encode(value))
}

#[derive(Clone)]
struct AuthoringWebState {
    service: Arc<ManagedActorAuthoringService>,
}

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
    match state.service.author(&body.authoring_request).await {
        Ok(managed_actor_bundle) => res.render(Json(AppletManagedActorAuthorOutcome {
            managed_actor_bundle,
        })),
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
