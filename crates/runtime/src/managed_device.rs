//! Durable native managed Device authoring over the host's existing private store.

use std::sync::Arc;

use arkret::canonical::{canonical_json_bytes, canonical_sha256};
use arkret::http_client::Client;
use arkret::signatures::{
    Ed25519PayloadSigner, EventSigner as _, PublicKeyMaterial, SignEventOptions, sign_event,
};
use arkret::{
    AccountId, ActorId, AppletManagedDeviceMetadata, AuthoredEvent, DeviceId, Did,
    EventAdmissionSubmission, RealmCommit, ScopeRef,
};
use arkret_event_draft::TypedEventDraft;
use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_models_collaboration::events_payloads::{
    AppletManagedDeviceScopes, DeviceAuthorizationBindingKind, DeviceAuthorizationScopes,
    DeviceAuthorizePayload, DeviceOrPrincipalRef, SignatureMaterial,
};
use arkret_wire::{
    AuthorityRejectionStatus, AuthoritySubmitOutcome, DetachedSignatureContext, event_spec,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};

use crate::managed_actor_authoring::ManagedActorAuthoringService;
use crate::{ArkretEdge, AuthoringStore, BridgeError, Result, run_blocking};

mod mls;

/// A local durable operation plan, not another protocol authorization carrier.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialManagedDevicePlan {
    pub operation_id: String,
    pub account_id: AccountId,
    pub scopes: AppletManagedDeviceScopes,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRecord {
    plan: InitialManagedDevicePlan,
    principal_did: Did,
    device_seed: String,
    hpke_private_key: String,
    authorization: AuthoredEvent,
    controller_public_key: PublicKeyMaterial,
    original_pcr_commit: RealmCommit,
    outcome: Option<AuthoritySubmitOutcome>,
    accepted_station_key: Option<PublicKeyMaterial>,
    #[serde(default)]
    mls: mls::ManagedMlsState,
}

/// A real accepted Device. Current business permission remains Station-owned.
pub struct ManagedDevice {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub authorization_event_id: arkret::EventId,
    pub authorization_commit: RealmCommit,
    client: Client,
    signer: Ed25519PayloadSigner,
    operation_id: String,
    effective_scope: ScopeRef,
}

impl ManagedDevice {
    pub fn client(&self) -> &Client {
        &self.client
    }
    pub fn signer(&self) -> &Ed25519PayloadSigner {
        &self.signer
    }
}

pub struct ManagedDeviceRuntime {
    edge: Arc<ArkretEdge>,
    authoring: Arc<ManagedActorAuthoringService>,
    store: Arc<dyn AuthoringStore>,
}

fn invalid(detail: impl Into<String>) -> BridgeError {
    BridgeError::Database(detail.into())
}
fn key(plan: &InitialManagedDevicePlan) -> Result<String> {
    Ok(format!(
        "managed-device/v1/{}",
        canonical_sha256(&(&plan.account_id, &plan.operation_id))?
    ))
}
fn nonempty(raw: impl Into<String>) -> Result<arkret_wire::NonEmptyString> {
    arkret_wire::NonEmptyString::new(raw).map_err(invalid)
}
fn seed(raw: &str) -> Result<[u8; 32]> {
    arkret::base64url_decode(raw)?
        .try_into()
        .map_err(|_| invalid("managed Device signing seed is not 32 bytes"))
}
fn payload(record: &DeviceRecord) -> Result<DeviceAuthorizePayload> {
    Ok(serde_json::from_value(serde_json::to_value(
        &record.authorization.payload,
    )?)?)
}

impl ManagedDeviceRuntime {
    pub fn new(edge: Arc<ArkretEdge>) -> Result<Self> {
        Ok(Self {
            authoring: Arc::new(ManagedActorAuthoringService::new(edge.clone())?),
            store: edge.authoring_store(),
            edge,
        })
    }

    pub async fn bootstrap_if_configured(edge: Arc<ArkretEdge>) -> Result<Vec<ManagedDevice>> {
        if edge
            .config()
            .arkret
            .managed_actor_authoring
            .device
            .is_none()
        {
            return Ok(Vec::new());
        }
        Self::new(edge)?.bootstrap_configured_devices().await
    }

    /// Bootstrap only explicitly configured actions in each creation's exact
    /// scope. Existing operations recover their stored plan without widening.
    pub async fn bootstrap_configured_devices(&self) -> Result<Vec<ManagedDevice>> {
        let Some(config) = &self.edge.config().arkret.managed_actor_authoring.device else {
            return Ok(Vec::new());
        };
        if config.actions.is_empty() || config.lifetime_seconds == 0 {
            return Err(BridgeError::Config(
                "managed Device bootstrap needs explicit actions and a finite lifetime".into(),
            ));
        }
        if config.mls && !(1..=1000).contains(&config.key_package_inventory_target) {
            return Err(BridgeError::Config(
                "MLS inventory target must be 1..=1000".into(),
            ));
        }
        let seconds: i64 = config.lifetime_seconds.try_into().map_err(|_| {
            BridgeError::Config("managed Device lifetime exceeds the clock range".into())
        })?;
        let lifetime = chrono::TimeDelta::try_seconds(seconds).ok_or_else(|| {
            BridgeError::Config("managed Device lifetime exceeds the clock range".into())
        })?;
        let mut actions = config.actions.clone();
        actions.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        actions.dedup();
        let edge = self.edge.clone();
        let actors = run_blocking(move || edge.managed_actor_ids()).await?;
        let mut devices = Vec::new();
        for actor in actors {
            match self.bootstrap_actor(&actor, &actions, lifetime).await {
                Ok(device) => {
                    if config.mls
                        && let Err(error) = self
                            .maintain_mls_key_packages(&device, config.key_package_inventory_target)
                            .await
                    {
                        tracing::warn!(account = %actor, %error, "native MLS publication remains pending")
                    }
                    devices.push(device);
                }
                Err(error) => {
                    tracing::warn!(account = %actor, %error, "managed Device bootstrap remains unavailable for this Account")
                }
            }
        }
        Ok(devices)
    }

    async fn bootstrap_actor(
        &self,
        actor: &ActorId,
        actions: &[arkret_wire::CapabilityActionId],
        lifetime: chrono::TimeDelta,
    ) -> Result<ManagedDevice> {
        let account_id = actor
            .as_account_id()
            .ok_or_else(|| invalid("managed creation has no full Account"))?
            .clone();
        let edge = self.edge.clone();
        let actor = actor.clone();
        let original = run_blocking(move || edge.retained_managed_actor(&actor)).await?;
        let request = match &original.authoring_context.committed_request {
            arkret::AppletManagedActorCommittedRequest::Bot(bot) => &bot.authoring_request,
            arkret::AppletManagedActorCommittedRequest::Ghost(ghost) => &ghost.authoring_request,
        };
        let scope = match &request.basis {
            arkret::AppletManagedActorAuthoringBasis::ProvisionBot(basis) => {
                basis.effective_scope.clone()
            }
            arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(basis) => {
                basis.effective_scope.clone()
            }
        };
        let operation_id = format!(
            "initial-device/{}",
            original
                .authoring_context
                .principal_control_commit
                .event_ref
        );
        if let Some(device) = self
            .recover_initial_device(&account_id, &operation_id, &scope)
            .await?
        {
            return Ok(device);
        }
        let now = arkret::canonical::normalize_timestamp_canonical(Utc::now());
        let expires_at = now.checked_add_signed(lifetime).ok_or_else(|| {
            BridgeError::Config("managed Device expiry exceeds the clock range".into())
        })?;
        let scopes = AppletManagedDeviceScopes::new(vec![
            arkret_models_collaboration::events_payloads::AppletManagedDeviceScope {
                effective_scope: scope.clone(),
                actions: actions.to_vec(),
            },
        ])?;
        self.authorize_initial_device(
            InitialManagedDevicePlan {
                operation_id,
                account_id,
                scopes,
                not_before: now,
                expires_at,
            },
            &scope,
        )
        .await
    }

    /// Recover the stored plan and its exact signed authorization. A host must
    /// not recompute a new expiry or scope while recovering the same operation.
    pub async fn recover_initial_device(
        &self,
        account_id: &AccountId,
        operation_id: &str,
        effective_scope: &ScopeRef,
    ) -> Result<Option<ManagedDevice>> {
        let operation_key = format!(
            "managed-device/v1/{}",
            canonical_sha256(&(account_id, operation_id))?
        );
        let Some(raw) = self.read(&operation_key).await? else {
            return Ok(None);
        };
        let record: DeviceRecord = self.authoring.decrypt_key_material(&operation_key, &raw)?;
        if record.plan.account_id != *account_id || record.plan.operation_id != operation_id {
            return Err(invalid(
                "recovered Device operation belongs to another Account or operation",
            ));
        }
        self.validate(&record)?;
        self.authorize_initial_device(record.plan, effective_scope)
            .await
            .map(Some)
    }

    async fn read(&self, operation_key: &str) -> Result<Option<String>> {
        let store = self.store.clone();
        let operation_key = operation_key.to_owned();
        run_blocking(move || store.load(&operation_key)).await
    }

    async fn cas(
        &self,
        operation_key: &str,
        previous: Option<String>,
        next: String,
    ) -> Result<bool> {
        let store = self.store.clone();
        let operation_key = operation_key.to_owned();
        run_blocking(move || {
            store.compare_exchange_batch(
                &[(operation_key.clone(), previous)],
                &[(operation_key, Some(next))],
            )
        })
        .await
    }

    fn decode(
        &self,
        operation_key: &str,
        raw: &str,
        plan: &InitialManagedDevicePlan,
    ) -> Result<DeviceRecord> {
        let record: DeviceRecord = self.authoring.decrypt_key_material(operation_key, raw)?;
        if canonical_json_bytes(&record.plan)? != canonical_json_bytes(plan)? {
            return Err(invalid(
                "managed Device operation was already bound to another plan",
            ));
        }
        self.validate(&record)?;
        Ok(record)
    }

    fn validate(&self, record: &DeviceRecord) -> Result<()> {
        let p = payload(record)?;
        let key = SigningKey::from_bytes(&seed(&record.device_seed)?);
        let hpke = arkret::base64url_decode(&record.hpke_private_key)?;
        let hpke_public =
            arkret::crypto::hpke::x25519_public_key(&hpke).map_err(|e| invalid(e.to_string()))?;
        let device_did = format!(
            "did:key:{}",
            arkret::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
        );
        let Some(DeviceAuthorizationScopes::AppletManaged(scopes)) = &p.scopes else {
            return Err(invalid("managed Device lost its exact scope/action pairs"));
        };
        if record.authorization.actor_id != ActorId::account(record.plan.account_id.clone())
            || arkret::project_did_to_core_id(&record.principal_did)?
                != record.plan.account_id.principal_id
            || record.plan.account_id.station_id
                != arkret::project_did_to_core_id(&self.edge.config().arkret.trusted_server_did)?
            || p.device_public_key_did.as_str() != device_did
            || p.hpke_key.as_str() != arkret::identity_root::x25519_public_multikey(&hpke_public)
            || p.authorization_binding_kind
                != DeviceAuthorizationBindingKind::AppletManagedDelegation
            || !matches!(&p.authorized_by, DeviceOrPrincipalRef::Principal(id) if id == &record.plan.account_id.principal_id)
            || p.device_key_algorithm.as_str() != "Ed25519"
            || p.recovery_session_id.is_some()
            || p.pairing_challenge_transcript_digest.is_some()
            || p.authorized_generation_ref != 1
            || p.applet_id.as_ref().map(|id| id.as_str()) != Some(self.edge.applet_id())
            || canonical_json_bytes(scopes)? != canonical_json_bytes(&record.plan.scopes)?
            || p.not_before != record.plan.not_before
            || p.expires_at != Some(Some(record.plan.expires_at))
            || record.authorization.realm_id != record.original_pcr_commit.realm_id
            || record.authorization.kind != arkret::EventKind::DeviceAuthorize
            || record.authorization.executed_by.is_some()
            || record
                .authorization
                .producer_proof
                .as_ref()
                .map(|proof| proof.verification_method.as_str())
                != Some(format!("{}#managed-controller", record.principal_did).as_str())
        {
            return Err(invalid(
                "managed Device private custody differs from its original authorization",
            ));
        }
        let pbytes = p.device_possession_signature_input(&record.plan.account_id)?;
        let SignatureMaterial::NonEmptyString(signature) = &p.device_signature else {
            return Err(invalid(
                "Device possession signature is not a raw Ed25519 signature",
            ));
        };
        let signature = arkret::base64url_decode(signature.as_str())?;
        let signature =
            ed25519_dalek::Signature::from_slice(&signature).map_err(|e| invalid(e.to_string()))?;
        key.verifying_key()
            .verify_strict(&pbytes, &signature)
            .map_err(|e| invalid(e.to_string()))?;
        arkret::signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            record
                .authorization
                .producer_proof
                .as_ref()
                .ok_or_else(|| invalid("managed Device authorizer proof is absent"))?,
            &arkret::signatures::EventProofBuilder::new()
                .envelope_bytes(record.authorization.event())?,
            &record.authorization.actor_id,
            &record.controller_public_key,
            crate::PRODUCER_DIGEST_SUITE,
        )
        .map_err(|e| invalid(e.to_string()))?;
        if let Some(AuthoritySubmitOutcome::Accepted { commit, .. }) = &record.outcome {
            let station_key = record.accepted_station_key.as_ref().ok_or_else(|| {
                invalid("managed Device accepted outcome lost its original Station key")
            })?;
            self.verify_commit(record, commit, station_key)?;
        } else if record.accepted_station_key.is_some() {
            return Err(invalid("unaccepted managed Device has an acceptance key"));
        }
        Ok(())
    }

    fn verify_commit(
        &self,
        record: &DeviceRecord,
        commit: &RealmCommit,
        station_key: &PublicKeyMaterial,
    ) -> Result<()> {
        commit.validate_content_address()?;
        let station_did =
            arkret::verification_method_did(commit.signature.verification_method.as_str())
                .map_err(|e| invalid(e.to_string()))?;
        if arkret::project_did_to_core_id(&station_did)? != record.plan.account_id.station_id
            || commit.event_ref != *record.authorization.event_id()
            || commit.stream_ref != record.original_pcr_commit.stream_ref
            || commit.stream_position <= record.original_pcr_commit.stream_position
            || commit.governance_generation != record.original_pcr_commit.governance_generation
            || commit.authority_ref != record.original_pcr_commit.authority_ref
        {
            return Err(invalid(
                "managed Device acceptance differs from its original PCR authority",
            ));
        }
        arkret::signatures::detached_object::verify_detached_object_signature(
            &commit.signature,
            &arkret::canonical::unsigned_value(commit, &["signature"])?,
            DetachedSignatureContext::RealmCommit,
            station_key,
        )
        .map_err(|e| invalid(e.to_string()))
    }

    async fn prepare(
        &self,
        plan: &InitialManagedDevicePlan,
        operation_key: &str,
    ) -> Result<String> {
        if let Some(raw) = self.read(operation_key).await? {
            self.decode(operation_key, &raw, plan)?;
            return Ok(raw);
        }
        if plan.expires_at <= Utc::now() {
            return Err(BridgeError::App(
                "new managed Device authorization already expired".into(),
            ));
        }
        let controller = self
            .authoring
            .original_managed_controller(&plan.account_id)
            .await?;
        if controller.account_id != plan.account_id {
            return Err(invalid("controller returned another managed Account"));
        }
        let mut signing_seed = [0u8; 32];
        getrandom::fill(&mut signing_seed).map_err(|e| BridgeError::Runtime(e.to_string()))?;
        let device_key = SigningKey::from_bytes(&signing_seed);
        if device_key.verifying_key() == controller.signer.verifying_key()
            || device_key.verifying_key() == self.edge.signer().verifying_key()
        {
            return Err(invalid("managed Device key is not independent"));
        }
        let hpke = arkret::crypto::hpke::generate_x25519_keypair()
            .map_err(|e| BridgeError::Runtime(e.to_string()))?;
        let now = arkret::canonical::normalize_timestamp_canonical(Utc::now());
        let device_id = DeviceId::new_v7_at(
            now.timestamp_millis()
                .try_into()
                .map_err(|_| invalid("Device clock predates UUID epoch"))?,
        );
        let mut p = DeviceAuthorizePayload {
            device_id,
            device_public_key_did: nonempty(format!(
                "did:key:{}",
                arkret::ed25519_pubkey_to_did_key_multibase(device_key.verifying_key().as_bytes())
            ))?,
            hpke_key: nonempty(arkret::identity_root::x25519_public_multikey(
                hpke.public_key(),
            ))?,
            algorithms: vec![nonempty(
                arkret_wire::HPKE_SUITE_X25519_CHACHA20POLY1305_V1,
            )?],
            device_key_algorithm: nonempty("Ed25519")?,
            authorized_by: DeviceOrPrincipalRef::Principal(plan.account_id.principal_id.clone()),
            scopes: Some(DeviceAuthorizationScopes::AppletManaged(
                plan.scopes.clone(),
            )),
            not_before: plan.not_before,
            expires_at: Some(Some(plan.expires_at)),
            authorization_binding_kind: DeviceAuthorizationBindingKind::AppletManagedDelegation,
            authorized_generation_ref: 1,
            device_signature: SignatureMaterial::NonEmptyString(nonempty("AA")?),
            recovery_session_id: None,
            pairing_challenge_transcript_digest: None,
            applet_id: Some(arkret::AppletId::new(self.edge.applet_id())?),
        };
        p.device_signature =
            SignatureMaterial::NonEmptyString(nonempty(arkret::base64url_encode(
                device_key
                    .sign(&p.device_possession_signature_input(&plan.account_id)?)
                    .to_bytes(),
            ))?);
        let mut authorization = TypedEventDraft::<event_spec::DeviceAuthorize>::new(
            ScopeRef::Realm {
                realm_id: controller.principal_control_realm,
            },
            ActorId::account(plan.account_id.clone()),
            p,
        )
        .map_err(|e| invalid(e.to_string()))?
        .author_with_digest_suite(now, crate::PRODUCER_DIGEST_SUITE)
        .map_err(|e| invalid(e.to_string()))?;
        sign_event(
            &mut authorization,
            &controller.signer,
            SignEventOptions::new().with_created_at(now),
        )?;
        let principal_did =
            arkret::verification_method_did(controller.signer.verification_method())
                .map_err(|e| invalid(e.to_string()))?;
        let record = DeviceRecord {
            plan: plan.clone(),
            principal_did,
            device_seed: arkret::base64url_encode(signing_seed),
            hpke_private_key: arkret::base64url_encode(hpke.private_key()),
            authorization,
            controller_public_key: PublicKeyMaterial::Ed25519Raw {
                bytes: controller.signer.verifying_key().to_bytes().to_vec(),
            },
            original_pcr_commit: controller
                .original
                .authoring_context
                .principal_control_commit
                .clone(),
            outcome: None,
            accepted_station_key: None,
            mls: mls::ManagedMlsState::default(),
        };
        self.validate(&record)?;
        let next = self
            .authoring
            .encrypt_key_material(operation_key, &record)?;
        if self.cas(operation_key, None, next.clone()).await? {
            return Ok(next);
        }
        let winner = self
            .read(operation_key)
            .await?
            .ok_or_else(|| invalid("concurrent Device preparation disappeared"))?;
        self.decode(operation_key, &winner, plan)?;
        Ok(winner)
    }

    /// Freeze private material before the first request. Network or persistence
    /// failures leave the exact pending original available for cold recovery.
    /// This initial-generation API never performs recovery or expands a Device.
    pub async fn authorize_initial_device(
        &self,
        mut plan: InitialManagedDevicePlan,
        effective_scope: &ScopeRef,
    ) -> Result<ManagedDevice> {
        plan.not_before = arkret::canonical::normalize_timestamp_canonical(plan.not_before);
        plan.expires_at = arkret::canonical::normalize_timestamp_canonical(plan.expires_at);
        if plan.operation_id.is_empty()
            || plan.operation_id.len() > 128
            || plan.expires_at <= plan.not_before
            || !plan.scopes.contains_scope(effective_scope)
        {
            return Err(BridgeError::App(
                "invalid initial managed Device plan".into(),
            ));
        }
        let controller = self
            .authoring
            .original_managed_controller(&plan.account_id)
            .await?;
        let operation_key = key(&plan)?;
        let previous = self.prepare(&plan, &operation_key).await?;
        let mut record = self.decode(&operation_key, &previous, &plan)?;
        if record.original_pcr_commit
            != controller
                .original
                .authoring_context
                .principal_control_commit
            || record
                .controller_public_key
                .ed25519_bytes()
                .map_err(|e| invalid(e.to_string()))?
                != controller.signer.verifying_key().to_bytes()
            || record
                .authorization
                .producer_proof
                .as_ref()
                .map(|p| p.verification_method.as_str())
                != Some(controller.signer.verification_method())
        {
            return Err(invalid(
                "Device custody differs from the retained managed creation",
            ));
        }
        if record.outcome.is_none() {
            let request = SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(
                record.authorization.event().clone(),
            ));
            let producer = arkret::ProducerVerificationContext {
                actor: ActorId::account(plan.account_id.clone()),
                verification_method: arkret::DidUrl::new(
                    controller.signer.verification_method().to_owned(),
                )
                .map_err(|e| invalid(e.to_string()))?,
                public_key: PublicKeyMaterial::Ed25519Raw {
                    bytes: controller.signer.verifying_key().to_bytes().to_vec(),
                },
                digest_suite: crate::PRODUCER_DIGEST_SUITE,
            };
            let request = arkret::VerifiedSubmission::verify(request, |_| Ok(producer.clone()))
                .map_err(|e| invalid(e.to_string()))?;
            let options = arkret::ClientRequestOptions::new()
                .idempotency_key(record.authorization.event_id().as_str());
            let answer = self
                .edge
                .client()
                .submit_to_realm_authority(&request, &options)
                .await?;
            let SelfAuthoritySubmitOutcome::Ordinary(outcome) = answer else {
                return Err(invalid("Device authorize returned an aggregate outcome"));
            };
            match &outcome {
                AuthoritySubmitOutcome::Accepted { commit, .. } => {
                    let trusted = self
                        .edge
                        .config()
                        .arkret
                        .trusted_verification_methods
                        .iter()
                        .find(|key| {
                            key.verification_method == commit.signature.verification_method.as_str()
                        })
                        .ok_or_else(|| {
                            invalid("Device acceptance has no trusted own-Station signer")
                        })?;
                    self.verify_commit(&record, commit, &trusted.public_key)?;
                    record.accepted_station_key = Some(trusted.public_key.clone());
                }
                AuthoritySubmitOutcome::Rejected {
                    status: AuthorityRejectionStatus::RetryableUnavailable,
                    reason_code,
                } => {
                    return Err(BridgeError::Runtime(format!(
                        "Device authorization remains pending: {reason_code}"
                    )));
                }
                AuthoritySubmitOutcome::Rejected { .. } => {}
            }
            record.outcome = Some(outcome);
            let next = self
                .authoring
                .encrypt_key_material(&operation_key, &record)?;
            if !self.cas(&operation_key, Some(previous), next).await? {
                let winner = self
                    .read(&operation_key)
                    .await?
                    .ok_or_else(|| invalid("Device outcome disappeared"))?;
                let winner = self.decode(&operation_key, &winner, &plan)?;
                match (&record.outcome, &winner.outcome) {
                    (
                        Some(AuthoritySubmitOutcome::Accepted { commit: first, .. }),
                        Some(AuthoritySubmitOutcome::Accepted { commit: second, .. }),
                    ) if first == second => {
                        record = winner;
                    }
                    _ => {
                        return Err(BridgeError::Runtime(
                            "Device outcome persistence contended; retry the same plan".into(),
                        ));
                    }
                }
            }
        }
        let Some(AuthoritySubmitOutcome::Accepted { commit, .. }) = record.outcome.clone() else {
            return Err(BridgeError::App(
                "initial managed Device authorization was rejected".into(),
            ));
        };
        let p = payload(&record)?;
        let now = Utc::now();
        if now < p.not_before || now >= plan.expires_at {
            return Err(BridgeError::App(
                "managed Device authorization is outside its lifetime".into(),
            ));
        }
        let device_key = SigningKey::from_bytes(&seed(&record.device_seed)?);
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|e| BridgeError::Runtime(e.to_string()))?;
        let metadata = AppletManagedDeviceMetadata {
            account_id: plan.account_id.clone(),
            device_id: p.device_id.clone(),
            authorization_event_id: record.authorization.event_id().clone(),
            applet_id: p
                .applet_id
                .ok_or_else(|| invalid("accepted Device lost Applet identity"))?,
            effective_scope: effective_scope.clone(),
            nonce: arkret::base64url_encode(nonce),
        };
        let client = self
            .edge
            .managed_device_client(metadata, device_key.clone())?;
        let method = arkret::DidUrl::new(format!("{}#{}", record.principal_did, p.device_id))
            .map_err(invalid)?;
        Ok(ManagedDevice {
            operation_id: plan.operation_id.clone(),
            effective_scope: effective_scope.clone(),
            account_id: plan.account_id,
            device_id: p.device_id,
            authorization_event_id: record.authorization.event_id().clone(),
            authorization_commit: commit,
            signer: Ed25519PayloadSigner::new(device_key, record.principal_did, method),
            client,
        })
    }
}
