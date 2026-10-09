//! Production Applet-managed Ghost identity authoring.
//!
//! One implementation backs both the canonical Applet author operation and
//! the messaging bridge's first-seen-user provisioning path. Identity keys are
//! random, encrypted at rest, and independent from the Applet service key.

use std::sync::Arc;

use arkret::canonical::{canonical_json_bytes, canonical_sha256};
use arkret::signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use arkret::{
    AppletId, AppletManagedActorAuthorOutcome, AppletManagedActorAuthorRequestBody,
    AppletManagedActorAuthoringBundle, AppletManagedActorAuthoringRequest,
    AppletManagedActorBundleAuthoringInput, AppletManagedActorCommittedRequest,
    AppletManagedActorPurpose, Did, DidCoreId, GenesisSalt, GhostActorProvisionRequestBody,
    GhostPreviewRequestBody, Hash, ResolutionCommitment, ResolutionDidBindingEvidenceKind,
    ResolutionDidBindingEvidenceReceipt, ResolutionDidBindingMethodProof,
    ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
    author_applet_managed_actor_bundle, namespace_pattern_matches, project_did_to_core_id,
};
use arkret_wire::{DidUrl, Discoverability, HistoryAccess, JoinRule, SecurityClass};
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
        if request
            .basis
            .ghost()
            .is_some_and(|basis| basis.existing_managed_actor.is_some())
        {
            return Err(BridgeError::App(
                "Ghost reuse does not create another authoring bundle".into(),
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
                    "stored managed actor authoring bundle is invalid: {error}"
                ))
            })?;
            self.freeze_creation(request, &bundle, &identity)?;
            return Ok(bundle);
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
                    self.freeze_creation(request, &bundle, &identity)?;
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
        bundle: &AppletManagedActorAuthoringBundle,
        identity: &ManagedActorIdentity,
    ) -> Result<()> {
        let committed = match request.purpose {
            AppletManagedActorPurpose::ProvisionBot => AppletManagedActorCommittedRequest::Bot(
                Box::new(arkret::AppletBotProvisionRequestBody {
                    authoring_request: request.clone(),
                    managed_actor_bundle: bundle.clone(),
                    approval_signatures: Vec::new(),
                }),
            ),
            AppletManagedActorPurpose::ProvisionGhost => AppletManagedActorCommittedRequest::Ghost(
                Box::new(GhostActorProvisionRequestBody {
                    authoring_request: request.clone(),
                    managed_actor_bundle: Some(bundle.clone()),
                    approval_signatures: Vec::new(),
                    existing_managed_actor: None,
                }),
            ),
            AppletManagedActorPurpose::InstallService => {
                return Err(BridgeError::App(
                    "Service installation has no managed identity".into(),
                ));
            }
        };
        self.edge.prepare_managed_authoring(
            &committed,
            &identity.root_verification_method,
            &identity.root_public_key,
        )?;
        Ok(())
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
            || *target_station_id != self.expected_station_id
            || request.purpose != purpose
        {
            return Err(BridgeError::App(
                "managed actor authoring request coordinates do not match this Applet service"
                    .into(),
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
        if !epoch.contains_signing_key(service_method.as_str()) {
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

    /// Author the closed four-Event Applet-managed actor creation unit.
    ///
    /// The unit is a producer-side protocol object: `provision`, PCR genesis,
    /// accountability grant and profile are cross-bound to each other and to
    /// the authoring request by `extensions/applet-integration.md` §9.1, and
    /// `identity/key-management.md` §3.6.3 requires the unified
    /// `arkret-rust-sdk` authoring API to produce it.
    ///
    /// The cross-binding rules live in the SDK's producer-side constructor, so
    /// this calls it rather than assembling them a second time here. The
    /// bridge contributes only what that API deliberately keeps outside the
    /// signed request: the independently held managed-actor identity, the
    /// accepted registration coordinate, and the PCR genesis parameters of its
    /// own deployment.
    ///
    /// `registration_ref` is echoed from the signed Ghost basis. The SDK
    /// rejects any other value, and taking it from configuration or from the
    /// live registration read would let an authoring request be answered
    /// against a registration it did not name.
    ///
    /// The control Realm belongs to one principal, so it is closed, secret and
    /// `since_join`; `models/realm-and-space.md` section 4 fixes
    /// `history_access = since_join` for every PCR, and a control Realm that
    /// anyone could join or discover would not be a control Realm. The genesis
    /// salt is generated once here and travels inside the bundle the store
    /// persists, so a retry replays the same salt and cannot create a second
    /// PCR for the same Ghost.
    async fn build_ghost_bundle(
        &self,
        request: &AppletManagedActorAuthoringRequest,
        identity: &ManagedActorIdentity,
    ) -> Result<AppletManagedActorAuthoringBundle> {
        let input = ghost_bundle_authoring_input(
            request,
            identity,
            self.config.arkret.trust_domain.clone(),
        )?;
        author_applet_managed_actor_bundle(request, input, self.edge.signer()).map_err(|error| {
            BridgeError::Arkret(format!("managed actor bundle authoring failed: {error}"))
        })
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
    arkret::webvh::validate_agent_did_document_profile(
        did.as_str(),
        &validated.document,
        &[validated.active_update_key_multibase.as_str()],
    )
    .map_err(|error| {
        BridgeError::Database(format!(
            "stored managed actor Agent DID profile is invalid: {error}"
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

/// The authoring inputs the SDK's API deliberately keeps outside the signed
/// request, assembled for the Ghost branch.
///
/// `registration_ref` is echoed from the signed basis. The SDK rejects any
/// other value, and taking it from configuration or from a live registration
/// read would let an authoring request be answered against a registration it
/// did not name.
///
/// The control Realm belongs to one principal, so it is closed, secret and
/// `since_join`: `models/realm-and-space.md` fixes `history_access =
/// since_join` for every PCR, and a control Realm anyone could join or
/// discover would not be a control Realm. `security_class` matches the other
/// PCR authoring paths in the SDK.
///
/// The genesis salt is generated once here and travels inside the bundle the
/// store persists, so a retry replays the same salt instead of creating a
/// second PCR for the same Ghost.
fn ghost_bundle_authoring_input(
    request: &AppletManagedActorAuthoringRequest,
    identity: &ManagedActorIdentity,
    trust_domain: arkret::TrustDomainId,
) -> Result<AppletManagedActorBundleAuthoringInput> {
    let (registration_ref, display_name) = match &request.basis {
        arkret::AppletManagedActorAuthoringBasis::ProvisionBot(basis) => (
            &basis.registration_event_ref,
            basis.display_name.clone().unwrap_or_default(),
        ),
        arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) => {
            (&basis.registration_event_ref, String::new())
        }
    };
    let genesis_salt = GenesisSalt::generate().map_err(|error| {
        BridgeError::Runtime(format!("managed actor PCR genesis salt: {error}"))
    })?;
    Ok(AppletManagedActorBundleAuthoringInput {
        actor_id: identity.actor_id.clone(),
        initial_resolution: identity.initial_resolution.clone(),
        method_history_evidence: identity.method_history_evidence.clone(),
        registration_ref: registration_ref.clone(),
        digest_suite: runtime::PRODUCER_DIGEST_SUITE,
        genesis_salt,
        trust_domain,
        security_class: SecurityClass::HighAssurance,
        initial_join_rule: JoinRule::Closed,
        initial_history_access: HistoryAccess::SinceJoin,
        initial_discoverability: Discoverability::Secret,
        bot_display_name: display_name,
    })
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
                    effective_scope: arkret::ScopeRef::Realm {
                        realm_id: request.realm_id.clone(),
                    },
                    external_ref: request.external_ref.clone(),
                    display_name: request.display_name.clone(),
                },
            )
            .await?;
        if let Some(existing) = preview.existing_managed_actor {
            self.validate_request(&preview.authoring_request, true)?;
            let request = GhostActorProvisionRequestBody {
                authoring_request: preview.authoring_request,
                managed_actor_bundle: None,
                approval_signatures: Vec::new(),
                existing_managed_actor: Some(existing),
            };
            self.edge.reused_ghost_did(&request)?;
            return Ok(request);
        }
        let subject_key = managed_actor_subject_key(&preview.authoring_request)?;
        let managed_actor_bundle = self.author(&preview.authoring_request).await?;
        let identity_record = self
            .store
            .clone()
            .managed_actor_identity_async(subject_key.clone())
            .await?
            .ok_or_else(|| {
                BridgeError::Database(
                    "completed Ghost authoring has no managed actor identity".to_owned(),
                )
            })?;
        let identity = self.decode_identity(&subject_key, identity_record)?;
        let committed_request = GhostActorProvisionRequestBody {
            authoring_request: preview.authoring_request,
            managed_actor_bundle: Some(managed_actor_bundle),
            approval_signatures: Vec::new(),
            existing_managed_actor: None,
        };
        // Freeze the exact producer-authored Ghost unit before returning it to
        // the caller that submits it to the Station. A completion can only echo
        // these durable bytes; retries of the already-completed authoring lease
        // reach the same call and therefore prove the same preparation again.
        prepare_ghost_completion(&self.edge, &committed_request, &identity)?;
        Ok(committed_request)
    }
}

fn prepare_ghost_completion(
    edge: &runtime::ArkretEdge,
    committed_request: &GhostActorProvisionRequestBody,
    identity: &ManagedActorIdentity,
) -> Result<()> {
    edge.prepare_managed_authoring(
        &AppletManagedActorCommittedRequest::Ghost(Box::new(committed_request.clone())),
        &identity.root_verification_method,
        &identity.root_public_key,
    )?;
    Ok(())
}

fn managed_actor_subject_key(request: &AppletManagedActorAuthoringRequest) -> Result<String> {
    let material = match &request.basis {
        arkret::AppletManagedActorAuthoringBasis::ProvisionBot(basis) => json!({
            "purpose": request.purpose, "applet_id": basis.applet_id,
            "target_station_id": basis.target_station_id,
            "effective_scope": basis.effective_scope, "request_id": basis.request_id,
        }),
        arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) => json!({
            "purpose": request.purpose, "applet_id": basis.applet_id,
            "target_station_id": basis.target_station_id,
            "effective_scope": basis.effective_scope, "external_ref": basis.external_ref,
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

#[cfg(test)]
mod ghost_bundle_tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use arkret::canonical::DigestSuite;
    use arkret::webvh::{AgentInceptionInput, prepare_agent_inception};
    use arkret::{
        AppletDidMethodVersionEvidence, AppletGhostAuthoringRequestBasis,
        AppletRegistrationEpochEvidence, DidDocument, GhostExternalTuple,
        applet_managed_actor_unit_event_kinds, applet_managed_actor_unit_submissions,
    };
    use arkret_signatures::Ed25519PayloadSigner;
    use arkret_wire::{DidUrl, EventId, GrantId, RealmId, TrustDomainId};
    use chrono::{DateTime, TimeZone};

    use super::*;

    #[derive(Default)]
    struct RecordingAuthoringStore(Mutex<BTreeMap<String, String>>);

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

    fn edge(store: Arc<dyn runtime::AuthoringStore>) -> runtime::ArkretEdge {
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
                "applet_namespaces": {"actors": [], "realms": [], "handles": []},
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
        let inception = prepare_agent_inception(&AgentInceptionInput {
            principal_endpoint: &url::Url::parse("https://applet.example/actors/slack").unwrap(),
            local_id: "u123",
            controller_principal_id: &core_id(SERVICE_DID),
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
        let document_digest =
            Hash::new(canonical_sha256(&inception.log_entry["state"]).unwrap()).unwrap();
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
            root_seed: material.root_seed,
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

    /// The first-seen external user path has to end in the four cross-bound
    /// Events, not in a fail-closed error. This authors one for real and puts it
    /// through the same verifier the receiving Station runs.
    #[test]
    fn a_ghost_authoring_request_produces_the_four_event_unit() {
        let identity = identity();
        let request = ghost_request();
        let input = ghost_bundle_authoring_input(&request, &identity, trust_domain()).unwrap();

        let bundle =
            author_applet_managed_actor_bundle(&request, input, &signer(0x22, SERVICE_DID))
                .expect("the bridge must be able to author a Ghost creation unit");

        bundle
            .validate_bindings(&request)
            .expect("the authored unit must satisfy the receiving Station's verifier");

        let submissions = applet_managed_actor_unit_submissions(&bundle, &request)
            .expect("the unit must be carried as four ordered submissions");
        let kinds: Vec<_> = submissions
            .iter()
            .map(|submission| submission.event.kind.clone())
            .collect();
        assert_eq!(kinds, applet_managed_actor_unit_event_kinds().to_vec());
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

    #[test]
    fn independent_bot_request_ids_and_scopes_partition_identity_custody() {
        let first = bot_request("bot-a");
        let second = bot_request("bot-b");
        assert_ne!(
            managed_actor_subject_key(&first).unwrap(),
            managed_actor_subject_key(&second).unwrap()
        );
        assert_eq!(
            managed_actor_subject_key(&first).unwrap(),
            managed_actor_subject_key(&first).unwrap()
        );
        let mut scope = first.clone();
        let arkret::AppletManagedActorAuthoringBasis::ProvisionBot(basis) = &mut scope.basis else {
            unreachable!()
        };
        basis.effective_scope = arkret::ScopeRef::Circle {
            realm_id: realm_id(),
            circle_id: arkret::CircleId::from_event_id(&event_id(0x72)),
        };
        assert_ne!(
            managed_actor_subject_key(&first).unwrap(),
            managed_actor_subject_key(&scope).unwrap()
        );
        let identity = identity();
        let bundle = author_applet_managed_actor_bundle(
            &first,
            ghost_bundle_authoring_input(&first, &identity, trust_domain()).unwrap(),
            &signer(0x22, SERVICE_DID),
        )
        .unwrap();
        bundle.validate_bindings(&first).unwrap();
        let payload: arkret::AppletManagedActorProvisionPayload = serde_json::from_value(
            serde_json::to_value(&bundle.managed_actor_provision_event.payload).unwrap(),
        )
        .unwrap();
        assert_eq!(payload.actor_role, arkret::AppletManagedActorRole::Bot);
        assert!(payload.external_ref.is_none());
    }

    #[test]
    fn ghost_custody_and_preparation_keys_include_the_full_scope() {
        let first = ghost_request();
        let mut circle = first.clone();
        let arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) = &mut circle.basis
        else {
            unreachable!()
        };
        basis.effective_scope = arkret::ScopeRef::Circle {
            realm_id: realm_id(),
            circle_id: arkret::CircleId::from_event_id(&event_id(0x72)),
        };
        assert_ne!(
            managed_actor_subject_key(&first).unwrap(),
            managed_actor_subject_key(&circle).unwrap()
        );
    }

    #[tokio::test]
    async fn real_ghost_completion_installs_and_restarts_with_exact_roots() {
        let identity = identity();
        let request = ghost_request();
        let bundle = author_applet_managed_actor_bundle(
            &request,
            ghost_bundle_authoring_input(&request, &identity, trust_domain()).unwrap(),
            &signer(0x22, SERVICE_DID),
        )
        .unwrap();
        let committed = GhostActorProvisionRequestBody {
            authoring_request: request,
            managed_actor_bundle: Some(bundle),
            approval_signatures: Vec::new(),
            existing_managed_actor: None,
        };
        let store = Arc::new(RecordingAuthoringStore::default());
        let runtime_edge = edge(store.clone());
        prepare_ghost_completion(&runtime_edge, &committed, &identity).unwrap();
        let commit_id = arkret::RealmCommitId::from_digest([0x81; 32]);
        let pcr_commit_id = arkret::RealmCommitId::from_digest([0x82; 32]);
        let jwk = |bytes: [u8; 32]| -> arkret_wire::NonEmptyJsonObject {
            serde_json::from_value(
                json!({"kty":"OKP", "crv":"Ed25519", "x":arkret::base64url_encode(bytes)}),
            )
            .unwrap()
        };
        let service = arkret::build_service_signer_evidence(
            core_id(SERVICE_DID),
            DidUrl::new(format!("{SERVICE_DID}#key-1")).unwrap(),
            jwk(signer(0x22, SERVICE_DID).verifying_key().to_bytes()),
            commit_id.clone(),
            issued_at(),
        )
        .unwrap();
        let source_method = DidUrl::new(format!("{STATION_DID}#key-1")).unwrap();
        let source_key = PublicKeyMaterial::Ed25519Raw {
            bytes: signer(0x11, STATION_DID)
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        let genesis = &committed
            .managed_actor_bundle
            .as_ref()
            .unwrap()
            .pcr_genesis_event;
        let mut pcr_commit = arkret::RealmCommit {
            commit_id: pcr_commit_id,
            realm_id: genesis.realm_id.clone(),
            stream_ref: arkret::CommitStreamRef::Realm {
                realm_id: genesis.realm_id.clone(),
            },
            stream_position: 0,
            previous_commit_ref: None,
            event_ref: genesis.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                genesis.event_id.clone(),
            ),
            committed_at: issued_at(),
            producer_signer_fact_digest: None,
            signature: arkret::signatures::detached_object::sign_detached_object(
                &json!({}),
                arkret::DetachedSignatureContext::RealmCommit,
                source_method.clone(),
                issued_at(),
                &ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]),
            )
            .unwrap(),
        };
        pcr_commit.commit_id = arkret::RealmCommitId::from_digest(arkret::canonical::sha256_bytes(
            &arkret::canonical::canonical_json_bytes(
                &arkret::canonical::unsigned_value(&pcr_commit, &["commit_id", "signature"])
                    .unwrap(),
            )
            .unwrap(),
        ));
        pcr_commit.signature = arkret::signatures::detached_object::sign_detached_object(
            &arkret::canonical::unsigned_value(&pcr_commit, &["signature"]).unwrap(),
            arkret::DetachedSignatureContext::RealmCommit,
            source_method.clone(),
            issued_at(),
            &ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]),
        )
        .unwrap();
        let pcr_commit_id = pcr_commit.commit_id.clone();
        let principal = arkret::build_principal_signer_evidence(
            identity.actor_id.clone(),
            identity.root_verification_method.clone(),
            jwk(identity.root_public_key.ed25519_bytes().unwrap()),
            pcr_commit_id.clone(),
            issued_at(),
        )
        .unwrap();
        let attester = arkret::build_service_signer_evidence(
            core_id(STATION_DID),
            source_method.clone(),
            jwk(source_key.ed25519_bytes().unwrap()),
            pcr_commit_id.clone(),
            issued_at(),
        )
        .unwrap();
        let initial_resolution_event = genesis.clone();
        let body = arkret::AppletAuthoringTransactionRequestBody {
            applet_id: AppletId::new(runtime_edge.applet_id()).unwrap(),
            source_id: core_id(STATION_DID),
            authoring_context: arkret::AppletManagedActorAuthoringContext {
                committed_request: AppletManagedActorCommittedRequest::Ghost(Box::new(
                    committed.clone(),
                )),
                realm_stream_head: arkret::CommitStreamHead {
                    stream_ref: arkret::CommitStreamRef::Realm {
                        realm_id: realm_id(),
                    },
                    stream_position: 12,
                    commit_id,
                },
                principal_control_commit: pcr_commit,
                resolution_update: None,
                applet_service_signer_evidence: arkret::AppletServiceSignerEvidence {
                    signer_resolution_evidence_ref: service.signer_evidence_ref().unwrap(),
                    authenticated_signer_evidence: service,
                },
                managed_actor_signer_evidence: arkret::ManagedActorPrincipalSignerEvidence {
                    signer_resolution_evidence_ref: principal.signer_evidence_ref().unwrap(),
                    authenticated_signer_evidence: principal,
                    attester_signer_evidence: attester,
                },
            },
        };
        let prepared_rows = store.0.lock().unwrap().clone();
        // An unimplemented rotation must not bypass the first-install PCR
        // anchor checks or mutate the durable locally prepared identity.
        let mut unsupported_update = serde_json::to_value(&body).unwrap();
        unsupported_update["authoring_context"]["resolution_update"] = serde_json::json!({
            "resolution_event": initial_resolution_event,
            "commits": [body.authoring_context.principal_control_commit.clone()],
            "method_history_evidence": identity.method_history_evidence,
            "attester_resolution": arkret::AuthenticatedServiceResolution {
                service_id: core_id(STATION_DID),
                service_kind: "station".to_owned(),
                method_history_evidence: identity.method_history_evidence.clone(),
                normalized_did_document: DidDocument::new(
                    did(STATION_DID), "key-1",
                    "z6MkrJVnaZkeF7EsnJQ9xQY4bqG9tbeFqTzL7uTVs11FwUjT",
                ),
            },
        });
        let unsupported_update = serde_json::from_value(unsupported_update).unwrap();
        let error = runtime_edge
            .install_managed_authoring_completion(&unsupported_update, &source_method, &source_key)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unavailable native rotation installer")
        );
        assert_eq!(*store.0.lock().unwrap(), prepared_rows);
        let wrong_key = PublicKeyMaterial::Ed25519Raw {
            bytes: signer(0x12, STATION_DID)
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        assert!(
            runtime_edge
                .install_managed_authoring_completion(&body, &source_method, &wrong_key)
                .is_err()
        );
        assert_eq!(*store.0.lock().unwrap(), prepared_rows);
        runtime_edge
            .install_managed_authoring_completion(&body, &source_method, &source_key)
            .unwrap();
        let creation = committed.managed_actor_bundle.as_ref().unwrap();
        let anchors = arkret::ExistingManagedActor {
            ghost_actor_id: arkret::ActorId::account(arkret::AccountId::new(
                identity.actor_id.clone(),
                core_id(STATION_DID),
            )),
            managed_actor_provision_ref: creation.managed_actor_provision_event.event_id.clone(),
            principal_control_realm_id: creation.pcr_genesis_event.realm_id.clone(),
            profile_event_ref: creation.profile_event.event_id.clone(),
            accountability_grant_ref: creation.accountability_grant_event.event_id.clone(),
        };
        let mut reuse_basis = committed.authoring_request.basis.ghost().unwrap().clone();
        reuse_basis.effective_scope = arkret::ScopeRef::Circle {
            realm_id: realm_id(),
            circle_id: arkret::CircleId::from_event_id(&event_id(0x73)),
        };
        reuse_basis.existing_managed_actor = Some(anchors.clone());
        let reuse_request = AppletManagedActorAuthoringRequest::sign_ghost(
            reuse_basis,
            core_id(STATION_DID),
            issued_at(),
            issued_at() + chrono::Duration::minutes(2),
            &signer(0x11, STATION_DID),
        )
        .unwrap();
        let mut reuse = GhostActorProvisionRequestBody {
            authoring_request: reuse_request,
            managed_actor_bundle: None,
            approval_signatures: Vec::new(),
            existing_managed_actor: Some(anchors),
        };
        assert_eq!(
            runtime_edge.reused_ghost_did(&reuse).unwrap(),
            identity.initial_resolution.did
        );
        assert!(
            runtime_edge
                .prepare_managed_authoring(
                    &AppletManagedActorCommittedRequest::Ghost(Box::new(reuse.clone())),
                    &identity.root_verification_method,
                    &identity.root_public_key
                )
                .is_err()
        );
        reuse
            .existing_managed_actor
            .as_mut()
            .unwrap()
            .profile_event_ref = event_id(0x79);
        assert!(runtime_edge.reused_ghost_did(&reuse).is_err());
        let installed_rows = store.0.lock().unwrap().clone();
        runtime_edge
            .install_managed_authoring_completion(&body, &source_method, &source_key)
            .unwrap();
        assert_eq!(*store.0.lock().unwrap(), installed_rows);
        drop(runtime_edge);
        let restarted = edge(store.clone());
        let actor = arkret::ActorId::account(arkret::AccountId::new(
            identity.actor_id,
            core_id(STATION_DID),
        ));
        let retained = restarted
            .installed_managed_authoring(
                &arkret::ScopeRef::Realm {
                    realm_id: realm_id(),
                },
                &actor,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            arkret::canonical::canonical_json_bytes(&retained).unwrap(),
            arkret::canonical::canonical_json_bytes(&body).unwrap()
        );
        let payload = arkret::MessageCreatePayload::with_content(
            arkret::StrandId::from_event_id(&event_id(0x92)),
            "main",
            arkret::ContentBlock::text("offline after restart"),
        );
        let authorization = match &body.authoring_context.committed_request {
            AppletManagedActorCommittedRequest::Ghost(ghost) => ghost
                .authoring_request
                .basis
                .ghost()
                .unwrap()
                .authorization_ref
                .to_string(),
            _ => unreachable!(),
        };
        let account = actor.as_account_id().unwrap();
        assert!(
            restarted
                .delegated_intent::<arkret_wire::event_spec::MessageCreate>(
                    account,
                    &realm_id(),
                    payload.clone(),
                    ""
                )
                .is_err()
        );
        assert!(
            restarted
                .delegated_intent::<arkret_wire::event_spec::MessageCreate>(
                    account,
                    &RealmId::from_event_id(&event_id(0x94)),
                    payload.clone(),
                    &authorization
                )
                .is_ok()
        );
        let intent = restarted
            .delegated_intent::<arkret_wire::event_spec::MessageCreate>(
                account,
                &realm_id(),
                payload,
                &authorization,
            )
            .unwrap();
        let frozen = restarted
            .author_and_sign(&realm_id(), "offline-operation", intent.clone())
            .await
            .unwrap();
        let exact_retry = restarted
            .author_and_sign(&realm_id(), "offline-operation", intent)
            .await
            .unwrap();
        assert_eq!(frozen.event(), exact_retry.event());
        let installed_rows = store.0.lock().unwrap().clone();
        let mut conflict = body.clone();
        conflict.authoring_context.realm_stream_head.stream_position += 1;
        assert!(
            restarted
                .install_managed_authoring_completion(&conflict, &source_method, &source_key)
                .is_err()
        );
        assert_eq!(*store.0.lock().unwrap(), installed_rows);
    }

    #[test]
    fn production_ghost_result_freezes_the_exact_committed_request() {
        let request = ghost_request();
        let identity = identity();
        let bundle = author_applet_managed_actor_bundle(
            &request,
            ghost_bundle_authoring_input(&request, &identity, trust_domain()).unwrap(),
            &signer(0x22, SERVICE_DID),
        )
        .unwrap();
        let committed = GhostActorProvisionRequestBody {
            authoring_request: request,
            managed_actor_bundle: Some(bundle),
            approval_signatures: Vec::new(),
            existing_managed_actor: None,
        };
        let store = Arc::new(RecordingAuthoringStore::default());
        let runtime_edge = edge(store.clone());

        prepare_ghost_completion(&runtime_edge, &committed, &identity).unwrap();
        prepare_ghost_completion(&runtime_edge, &committed, &identity).unwrap();

        drop(runtime_edge);
        let restarted = edge(store.clone());
        prepare_ghost_completion(&restarted, &committed, &identity).unwrap();
        let rows_before_mismatch = store.0.lock().unwrap().clone();

        let wrong_method = DidUrl::new("did:key:z6Mkwrong#z6Mkwrong".to_owned()).unwrap();
        assert!(
            restarted
                .prepare_managed_authoring(
                    &AppletManagedActorCommittedRequest::Ghost(Box::new(committed.clone())),
                    &wrong_method,
                    &identity.root_public_key,
                )
                .is_err()
        );
        let wrong_key = PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&[0x61; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        assert!(
            restarted
                .prepare_managed_authoring(
                    &AppletManagedActorCommittedRequest::Ghost(Box::new(committed.clone())),
                    &identity.root_verification_method,
                    &wrong_key,
                )
                .is_err()
        );
        assert_eq!(
            *store.0.lock().unwrap(),
            rows_before_mismatch,
            "VM/key mismatches must not mutate the durable preparation"
        );

        let service_signer = signer(0x22, SERVICE_DID);
        let verifier = runtime::LocalServiceManagedActorProofVerifier::new(
            core_id(SERVICE_DID),
            DidUrl::new(format!("{SERVICE_DID}#key-1")).unwrap(),
            PublicKeyMaterial::Ed25519Raw {
                bytes: service_signer.verifying_key().to_bytes().to_vec(),
            },
        )
        .unwrap();
        runtime::validate_managed_actor_bundle(
            &committed.authoring_request,
            committed.managed_actor_bundle.as_ref().unwrap(),
            &verifier,
        )
        .unwrap();
        let wrong_local_key = runtime::LocalServiceManagedActorProofVerifier::new(
            core_id(SERVICE_DID),
            DidUrl::new(format!("{SERVICE_DID}#key-1")).unwrap(),
            PublicKeyMaterial::Ed25519Raw {
                bytes: SigningKey::from_bytes(&[0x23; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            },
        )
        .unwrap();
        assert!(
            runtime::validate_managed_actor_bundle(
                &committed.authoring_request,
                committed.managed_actor_bundle.as_ref().unwrap(),
                &wrong_local_key,
            )
            .is_err()
        );

        let mut wrong_event_proof = committed.clone();
        wrong_event_proof
            .managed_actor_bundle
            .as_mut()
            .unwrap()
            .profile_event
            .producer_proof
            .as_mut()
            .unwrap()
            .jws = "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned();
        assert!(
            runtime::validate_managed_actor_bundle(
                &wrong_event_proof.authoring_request,
                &wrong_event_proof.managed_actor_bundle.as_ref().unwrap(),
                &verifier,
            )
            .is_err()
        );
        let mut wrong_ref = committed.clone();
        wrong_ref
            .managed_actor_bundle
            .as_mut()
            .unwrap()
            .pcr_genesis_event
            .semantic_refs
            .clear();
        assert!(
            runtime::validate_managed_actor_bundle(
                &wrong_ref.authoring_request,
                &wrong_ref.managed_actor_bundle.as_ref().unwrap(),
                &verifier,
            )
            .is_err()
        );
        let mut wrong_executor = committed.clone();
        wrong_executor
            .managed_actor_bundle
            .as_mut()
            .unwrap()
            .profile_event
            .executed_by = Some(arkret::ActorId::service(core_id(STATION_DID)));
        assert!(
            runtime::validate_managed_actor_bundle(
                &wrong_executor.authoring_request,
                &wrong_executor.managed_actor_bundle.as_ref().unwrap(),
                &verifier,
            )
            .is_err()
        );
        let mut wrong_bundle_proof = committed.clone();
        wrong_bundle_proof
            .managed_actor_bundle
            .as_mut()
            .unwrap()
            .proof
            .jws = "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned();
        assert!(
            runtime::validate_managed_actor_bundle(
                &wrong_bundle_proof.authoring_request,
                &wrong_bundle_proof.managed_actor_bundle.as_ref().unwrap(),
                &verifier,
            )
            .is_err()
        );
        assert_eq!(
            *store.0.lock().unwrap(),
            rows_before_mismatch,
            "producer proof and content/ref failures must not mutate preparation"
        );

        let rows = store.0.lock().unwrap();
        assert_eq!(
            rows.len(),
            2,
            "exact retry must reuse one preparation and its actor index"
        );
        let preparation_rows: Vec<_> = rows
            .iter()
            .filter(|(key, _)| key.starts_with("managed-authoring/prepared/"))
            .collect();
        assert_eq!(preparation_rows.len(), 1);
        let actor = committed
            .managed_actor_provision_payload()
            .unwrap()
            .actor_id;
        let actor_key = format!(
            "managed-authoring/local-actor/{}",
            serde_json::to_string(&actor).unwrap()
        );
        assert_eq!(
            serde_json::from_str::<arkret::ActorId>(&rows[&actor_key]).unwrap(),
            actor
        );
        let prepared_raw = preparation_rows[0].1;
        let prepared: Value = serde_json::from_str(prepared_raw).unwrap();
        assert_eq!(
            prepared["managed_actor_verification_method"],
            identity.root_verification_method.as_str()
        );
        let prepared_key: PublicKeyMaterial =
            serde_json::from_value(prepared["managed_actor_public_key"].clone()).unwrap();
        assert_eq!(
            prepared_key.ed25519_bytes().unwrap(),
            identity.root_public_key.ed25519_bytes().unwrap()
        );
        assert!(prepared_raw.contains(&committed.authoring_request.schema));
        assert!(
            !prepared_raw.contains("root_seed") && !prepared_raw.contains("next_root_seed"),
            "the private preparation stores only verified public signer facts"
        );
    }

    /// The signed basis is the only source of the registration coordinate, and
    /// a Principal Control Realm is fixed at closed / since_join / secret.
    #[test]
    fn the_authoring_input_follows_the_signed_basis_and_the_pcr_rules() {
        let identity = identity();
        let request = ghost_request();
        let input = ghost_bundle_authoring_input(&request, &identity, trust_domain()).unwrap();

        assert_eq!(input.registration_ref, registration_ref());
        assert_eq!(input.actor_id, identity.actor_id);
        assert_eq!(input.initial_join_rule, JoinRule::Closed);
        assert_eq!(input.initial_history_access, HistoryAccess::SinceJoin);
        assert_eq!(input.initial_discoverability, Discoverability::Secret);
        assert_eq!(input.security_class, SecurityClass::HighAssurance);
    }

    /// Two authoring runs must not share a genesis salt, or two Ghosts would
    /// address one Principal Control Realm. `GenesisSalt` withholds `Debug` so
    /// the salt cannot reach a log, which rules out `assert_ne!` here.
    #[test]
    fn each_authoring_run_draws_its_own_genesis_salt() {
        let identity = identity();
        let request = ghost_request();
        let first = ghost_bundle_authoring_input(&request, &identity, trust_domain()).unwrap();
        let second = ghost_bundle_authoring_input(&request, &identity, trust_domain()).unwrap();
        assert!(
            first.genesis_salt != second.genesis_salt,
            "each create intent draws its own genesis salt"
        );
    }
}
