//! Durable native managed Device authoring over the host's existing private store.

use std::sync::Arc;

use arkret::canonical::{canonical_json_bytes, canonical_sha256};
use arkret::http_client::Client;
use arkret::signatures::{
    Ed25519PayloadSigner, EventSigner as _, PublicKeyMaterial, SignEventOptions, sign_event,
};
use arkret::{
    ActorId, AppletManagedDeviceMetadata, AuthoredEvent, DeviceId, Did, EventAdmissionSubmission,
    RealmCommit, ScopeRef,
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

mod attachment;
mod authorization;
mod business;
mod content;
mod control;
mod inbox;
mod installation_source;
mod manager;
mod mls;
pub use crate::managed_actor_authoring::{ManagementTransferOffer, ManagementTransferPlan};
mod portal;
mod processing;
mod read_source;
mod recovery;
mod revocation;
mod status;
mod stream;
mod worker;
pub use content::{NativeContent, NativeContentRecipient, NativeContentSink};
pub use inbox::ManagedQueueProgress;
pub use processing::{
    NativeReplyClaim, NativeReplyPreparation, NativeReplyTicket, PendingNativeReply,
};
pub use read_source::ManagedDeviceReader;
pub use stream::ManagedStreamProgress;
pub use worker::ManagedDeviceWorkers;

/// A local durable operation plan, not another protocol authorization carrier.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialManagedDevicePlan {
    pub operation_id: String,
    pub actor_id: ActorId,
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
    controller_method: arkret::DidUrl,
    controller_public_key: PublicKeyMaterial,
    creation_commit: RealmCommit,
    outcome: Option<AuthoritySubmitOutcome>,
    accepted_station_key: Option<PublicKeyMaterial>,
    #[serde(default)]
    mls: mls::ManagedMlsState,
}

/// A real accepted Device. Current business permission remains Station-owned.
pub struct ManagedDevice {
    pub actor_id: ActorId,
    pub device_id: DeviceId,
    pub authorization_event_id: arkret::EventId,
    pub authorization_commit: RealmCommit,
    pub governance_generation: u64,
    pub governance_station: arkret::DidCoreId,
    client: Client,
    signer: Ed25519PayloadSigner,
    operation_id: String,
    effective_scope: ScopeRef,
}

impl ManagedDevice {
    pub fn effective_scope(&self) -> &ScopeRef {
        &self.effective_scope
    }

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

struct ManagedControlState {
    control: arkret::RealmActorControlValue,
    revision: arkret::CurrentRevision,
    reference: arkret::CommittedEventRef,
    generation: u64,
}

fn invalid(detail: impl Into<String>) -> BridgeError {
    BridgeError::Database(detail.into())
}
fn key(plan: &InitialManagedDevicePlan) -> Result<String> {
    Ok(format!(
        "managed-device/v1/{}",
        canonical_sha256(&(&plan.actor_id, &plan.operation_id))?
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
    async fn control_state(&self, actor: &ActorId) -> Result<ManagedControlState> {
        let id = actor
            .as_realm_actor_id()
            .ok_or_else(|| invalid("Realm actor required"))?;
        let route = self.edge.realm_route(&id.realm_id).await?;
        let control_selector = arkret::CurrentSelector::RealmActorControl {
            actor_id: actor.clone(),
        };
        let manager_selector = arkret::CurrentSelector::RealmActorManager {
            actor_id: actor.clone(),
        };
        let generation_selector = arkret::CurrentSelector::RealmActorDeviceGeneration {
            actor_id: actor.clone(),
        };
        let request = arkret::RealmActorMaterialRequest::Current {
            actor_id: actor.clone(),
            request_nonce: crate::realm_governance::nonce()?,
            selectors: vec![
                control_selector.clone(),
                manager_selector.clone(),
                generation_selector.clone(),
            ],
        };
        let verified = route
            .material(
                &request,
                &ActorId::service(self.edge.service_actor_id().clone()),
            )
            .await?;
        let arkret::RealmActorMaterialResult::Current { entries } = &verified.material().result
        else {
            return Err(invalid("current control query returned another purpose"));
        };
        let row = |target: &arkret::CurrentSelector| -> Result<(
            &arkret::CurrentRevision,
            &serde_json::Value,
            &arkret::CommittedEventRef,
        )> {
            entries
                .iter()
                .find_map(|entry| match entry {
                    arkret::RealmActorMaterialCurrentEntry::Present {
                        row:
                            arkret::TypedCurrentRow::Value {
                                selector,
                                revision,
                                value,
                                ..
                            },
                        source_ref,
                    } if selector == target => Some((revision, value, source_ref)),
                    _ => None,
                })
                .ok_or_else(|| invalid("required current Realm control row missing"))
        };
        let (revision, control, reference) = row(&control_selector)?;
        let control: arkret::RealmActorControlValue = serde_json::from_value(control.clone())?;
        let manager: arkret::RealmActorManagerValue =
            serde_json::from_value(row(&manager_selector)?.1.clone())?;
        let generation: arkret::RealmActorDeviceGenerationValue =
            serde_json::from_value(row(&generation_selector)?.1.clone())?;
        if manager.service_id != *self.edge.service_actor_id()
            || generation.current_device_generation_ref == 0
        {
            return Err(invalid("Applet is no longer this Realm actor's manager"));
        }
        if reference.event_id.as_str() != control.resolution.resolution_event_ref {
            return Err(invalid(
                "control source differs from accepted resolution writer",
            ));
        }
        Ok(ManagedControlState {
            reference: reference.clone(),
            control,
            revision: revision.clone(),
            generation: generation.current_device_generation_ref,
        })
    }

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
        config.validate()?;
        let seconds: i64 = config.lifetime_seconds.try_into().map_err(|_| {
            BridgeError::Config("managed Device lifetime exceeds the clock range".into())
        })?;
        let lifetime = chrono::TimeDelta::try_seconds(seconds).ok_or_else(|| {
            BridgeError::Config("managed Device lifetime exceeds the clock range".into())
        })?;
        let mut actions = config.actions.clone();
        actions.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        actions.dedup();
        let actors = self.authoring.managed_actor_ids().await?;
        use futures::StreamExt as _;
        let mut devices = futures::stream::iter(actors)
            .map(|actor| {
                let actions = &actions;
                async move {
                    let device = match self.bootstrap_actor(&actor, actions, lifetime).await {
                        Ok(device) => device,
                        Err(error) => {
                            tracing::warn!(account = %actor, %error, "managed Device bootstrap remains unavailable for this Account");
                            return None;
                        }
                    };
                    if config.mls && let Err(error) = self.maintain_mls_key_packages(&device, config.key_package_inventory_target).await {
                        tracing::warn!(account = %actor, %error, "native MLS publication remains pending");
                    }
                    Some(device)
                }
            })
            .buffer_unordered(8)
            .filter_map(|device| async move { device })
            .collect::<Vec<_>>()
            .await;
        devices.sort_by(|left, right| {
            (&left.actor_id, &left.device_id).cmp(&(&right.actor_id, &right.device_id))
        });
        Ok(devices)
    }

    async fn bootstrap_actor(
        &self,
        actor: &ActorId,
        actions: &[arkret_wire::CapabilityActionId],
        lifetime: chrono::TimeDelta,
    ) -> Result<ManagedDevice> {
        if actor.as_realm_actor_id().is_none() {
            return Err(invalid("managed creation requires a Realm actor"));
        }
        let actor_id = actor.clone();
        let original = self.authoring.managed_creation(actor).await?;
        let creation = &original.event;
        let scope = crate::managed_authoring::creation_payload(creation)?.creation_scope;
        let current = self.control_state(actor).await?;
        // A manager change or recovery retires the old generation without erasing
        // its Device/MLS custody. Bootstrap a separate authorization for this cut.
        let operation_id = format!(
            "initial-device/{}/{}",
            creation.event_id, current.generation
        );
        if let Some(device) = self
            .recover_initial_device(&actor_id, &operation_id, &scope)
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
                actor_id,
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
        actor_id: &ActorId,
        operation_id: &str,
        effective_scope: &ScopeRef,
    ) -> Result<Option<ManagedDevice>> {
        if self.is_retired_device(actor_id, operation_id).await? {
            return Err(invalid("this Device operation was permanently retired"));
        }
        let operation_key = format!(
            "managed-device/v1/{}",
            canonical_sha256(&(actor_id, operation_id))?
        );
        let Some(raw) = self.read(&operation_key).await? else {
            return Ok(None);
        };
        let record: DeviceRecord = self.decrypt_device_record(&operation_key, &raw).await?;
        if record.plan.actor_id != *actor_id || record.plan.operation_id != operation_id {
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

    async fn decrypt_device_record(&self, key: &str, raw: &str) -> Result<DeviceRecord> {
        // Deep private MLS/stream records must not consume the caller's poll
        // stack or block its executor during authenticated decryption/decoding.
        let authoring = self.authoring.clone();
        let key = key.to_owned();
        let raw = raw.to_owned();
        run_blocking(move || authoring.decrypt_key_material(&key, &raw)).await
    }

    async fn decode(
        &self,
        operation_key: &str,
        raw: &str,
        plan: &InitialManagedDevicePlan,
    ) -> Result<DeviceRecord> {
        let record: DeviceRecord = self.decrypt_device_record(operation_key, raw).await?;
        if canonical_json_bytes(&record.plan)? != canonical_json_bytes(plan)? {
            return Err(invalid(
                "managed Device operation was already bound to another plan",
            ));
        }
        self.validate(&record)?;
        Ok(record)
    }

    fn validate(&self, record: &DeviceRecord) -> Result<()> {
        arkret::RealmActorDeviceAuthorizationValue::from_event(record.authorization.event())?;
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
        if record.authorization.actor_id != record.plan.actor_id.clone()
            || arkret::project_did_to_core_id(&record.principal_did)?
                != *record.plan.actor_id.signing_principal_id()
            || p.device_public_key_did.as_str() != device_did
            || p.hpke_key.as_str() != arkret::identity_root::x25519_public_multikey(&hpke_public)
            || p.authorization_binding_kind
                != DeviceAuthorizationBindingKind::RealmManagedDelegation
            || !matches!(&p.authorized_by, DeviceOrPrincipalRef::Principal(id) if id == record.plan.actor_id.signing_principal_id())
            || p.device_key_algorithm.as_str() != "Ed25519"
            || p.recovery_session_id.is_some()
            || p.pairing_challenge_transcript_digest.is_some()
            || p.authorized_generation_ref == 0
            || p.expected_control_revision.is_none()
            || p.expected_device_revision != Some(None)
            || p.applet_id.as_ref().map(|id| id.as_str()) != Some(self.edge.applet_id())
            || canonical_json_bytes(scopes)? != canonical_json_bytes(&record.plan.scopes)?
            || p.not_before != record.plan.not_before
            || p.expires_at != Some(Some(record.plan.expires_at))
            || record.authorization.realm_id != record.creation_commit.realm_id
            || record.authorization.scope_ref
                != (ScopeRef::RealmControl {
                    realm_id: record.creation_commit.realm_id.clone(),
                })
            || record.authorization.kind != arkret::EventKind::DeviceAuthorize
            || record.authorization.executed_by.is_some()
            || record
                .authorization
                .producer_proof
                .as_ref()
                .map(|proof| proof.verification_method.as_str())
                != Some(record.controller_method.as_str())
            || arkret::verification_method_did(record.controller_method.as_str())
                .map_err(|e| invalid(e.to_string()))?
                != record.principal_did
        {
            return Err(invalid(
                "managed Device private custody differs from its original authorization",
            ));
        }
        let pbytes = p.realm_device_possession_signature_input(&record.plan.actor_id)?;
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
        if commit.event_ref != *record.authorization.event_id()
            || commit.stream_ref != record.creation_commit.stream_ref
            || commit.stream_position <= record.creation_commit.stream_position
        {
            return Err(invalid(
                "managed Device acceptance differs from its original Realm control stream",
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
        if self
            .is_retired_device(&plan.actor_id, &plan.operation_id)
            .await?
        {
            return Err(invalid("this Device operation was permanently retired"));
        }
        if let Some(raw) = self.read(operation_key).await? {
            self.decode(operation_key, &raw, plan).await?;
            return Ok(raw);
        }
        if plan.expires_at <= Utc::now() {
            return Err(BridgeError::App(
                "new managed Device authorization already expired".into(),
            ));
        }
        let control = self.control_state(&plan.actor_id).await?;
        let controller = self
            .authoring
            .managed_controller(&plan.actor_id, &control.control.control_method_kid)
            .await?;
        if controller.actor_id != plan.actor_id {
            return Err(invalid("controller returned another managed Account"));
        }
        if control.control.control_method_kid.as_str() != controller.signer.verification_method()
            || control.control.resolution.did
                != arkret::verification_method_did(controller.signer.verification_method())
                    .map_err(|e| invalid(e.to_string()))?
        {
            return Err(invalid(
                "local controller differs from current Realm control",
            ));
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
            authorized_by: DeviceOrPrincipalRef::Principal(
                plan.actor_id.signing_principal_id().clone(),
            ),
            scopes: Some(DeviceAuthorizationScopes::AppletManaged(
                plan.scopes.clone(),
            )),
            not_before: plan.not_before,
            expires_at: Some(Some(plan.expires_at)),
            authorization_binding_kind: DeviceAuthorizationBindingKind::RealmManagedDelegation,
            authorized_generation_ref: control.generation,
            expected_control_revision: Some(control.revision.clone()),
            expected_device_revision: Some(None),
            device_signature: SignatureMaterial::NonEmptyString(nonempty("AA")?),
            recovery_session_id: None,
            pairing_challenge_transcript_digest: None,
            applet_id: Some(arkret::AppletId::new(self.edge.applet_id())?),
        };
        p.device_signature =
            SignatureMaterial::NonEmptyString(nonempty(arkret::base64url_encode(
                device_key
                    .sign(&p.realm_device_possession_signature_input(&plan.actor_id)?)
                    .to_bytes(),
            ))?);
        let mut authorization = TypedEventDraft::<event_spec::DeviceAuthorize>::new(
            ScopeRef::RealmControl {
                realm_id: plan
                    .actor_id
                    .as_realm_actor_id()
                    .ok_or_else(|| invalid("Realm actor required"))?
                    .realm_id
                    .clone(),
            },
            plan.actor_id.clone(),
            p,
        )
        .map_err(|e| invalid(e.to_string()))?
        .with_applet_id(arkret::AppletId::new(self.edge.applet_id())?)
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
            controller_method: control.control.control_method_kid.clone(),
            controller_public_key: PublicKeyMaterial::Ed25519Raw {
                bytes: controller.signer.verifying_key().to_bytes().to_vec(),
            },
            creation_commit: controller.original.commit.clone(),
            outcome: None,
            accepted_station_key: None,
            mls: mls::ManagedMlsState::default(),
        };
        self.validate(&record)?;
        let next = self
            .authoring
            .encrypt_key_material(operation_key, &record)?;
        let tombstone = revocation::retirement_key(&plan.actor_id, &plan.operation_id)?;
        let store = self.store.clone();
        let insertion_key = operation_key.to_owned();
        let inserted_value = next.clone();
        if run_blocking(move || {
            store.compare_exchange_batch(
                &[(insertion_key.clone(), None), (tombstone, None)],
                &[(insertion_key, Some(inserted_value))],
            )
        })
        .await?
        {
            return Ok(next);
        }
        let winner = self
            .read(operation_key)
            .await?
            .ok_or_else(|| invalid("concurrent Device preparation disappeared"))?;
        self.decode(operation_key, &winner, plan).await?;
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
        let operation_key = key(&plan)?;
        let mut previous = self.prepare(&plan, &operation_key).await?;
        let mut record = self.decode(&operation_key, &previous, &plan).await?;
        if record.outcome.is_none() {
            self.recover_authorization_outcome(&operation_key, &mut previous, &mut record)
                .await?;
        }
        let control = self.control_state(&plan.actor_id).await?;
        let auth_payload = payload(&record)?;
        if control.generation != auth_payload.authorized_generation_ref {
            return Err(invalid("managed Device generation has been retired"));
        }
        if record.outcome.is_none() {
            let controller = self
                .authoring
                .managed_controller(&plan.actor_id, &record.controller_method)
                .await?;
            let request = SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(
                record.authorization.event().clone(),
            ));
            let producer = arkret::ProducerVerificationContext {
                actor: plan.actor_id.clone(),
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
            if auth_payload.expected_control_revision.as_ref() != Some(&control.revision)
                || control.control.control_method_kid.as_str()
                    != controller.signer.verification_method()
            {
                return Err(invalid(
                    "pending authorization cannot replace its original control cut",
                ));
            }
            let realm = plan
                .actor_id
                .as_realm_actor_id()
                .ok_or_else(|| invalid("Realm actor required"))?
                .realm_id
                .clone();
            let route = self.edge.realm_route(&realm).await?;
            let client = route.client.clone().with_realm_actor_control_http_signer(
                arkret::RealmActorControlHttpMetadata {
                    actor_id: plan.actor_id.clone(),
                    control_ref: control.reference.clone(),
                    nonce: crate::realm_governance::nonce()?,
                },
                route.authority.current_service_id().clone(),
                arkret::http_client::HttpMessageSigner::new(
                    controller.signer.verification_method().to_owned(),
                    controller.signing_key.clone(),
                ),
            )?;
            let answer = client.submit_to_realm_authority(&request, &options).await?;
            let SelfAuthoritySubmitOutcome::Ordinary(outcome) = answer else {
                return Err(invalid("Device authorize returned an aggregate outcome"));
            };
            match &outcome {
                AuthoritySubmitOutcome::Accepted { commit, .. } => {
                    let keys =
                        garth::historical_station_keys::fetch_historical_station_keys_for_commits(
                            &route.client,
                            &route.bundle,
                            &[commit],
                        )
                        .await
                        .map_err(|e| invalid(e.to_string()))?;
                    route
                        .authority
                        .verify_commit(commit, &keys)
                        .map_err(|e| invalid(e.to_string()))?;
                    let issuer = route
                        .authority
                        .authority_service_at(commit.governance_generation)
                        .ok_or_else(|| invalid("Device Commit has no legal governance tenure"))?;
                    let key = route
                        .historical_station_key(
                            issuer,
                            &commit.signature.verification_method,
                            commit.committed_at,
                        )
                        .await?;
                    self.verify_commit(&record, commit, &key)?;
                    record.accepted_station_key = Some(key);
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
                let winner = self.decode(&operation_key, &winner, &plan).await?;
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
            actor_id: plan.actor_id.clone(),
            device_id: p.device_id.clone(),
            authorization_event_id: record.authorization.event_id().clone(),
            applet_id: p
                .applet_id
                .ok_or_else(|| invalid("accepted Device lost Applet identity"))?,
            effective_scope: effective_scope.clone(),
            nonce: arkret::base64url_encode(nonce),
        };
        let realm = plan
            .actor_id
            .as_realm_actor_id()
            .ok_or_else(|| invalid("Realm actor required"))?
            .realm_id
            .clone();
        let route = self.edge.realm_route(&realm).await?;
        let key_method = format!(
            "did:key:{}",
            arkret::ed25519_pubkey_to_did_key_multibase(device_key.verifying_key().as_bytes())
        );
        let fragment = key_method
            .strip_prefix("did:key:")
            .ok_or_else(|| invalid("Device key fingerprint missing"))?;
        let client = route.client.clone().with_managed_device_http_signer(
            metadata,
            route.authority.current_service_id().clone(),
            arkret::http_client::HttpMessageSigner::new(
                format!("{key_method}#{fragment}"),
                device_key.clone(),
            ),
        )?;
        let method = arkret::DidUrl::new(format!("{}#{}", record.principal_did, p.device_id))
            .map_err(invalid)?;
        Ok(ManagedDevice {
            operation_id: plan.operation_id.clone(),
            effective_scope: effective_scope.clone(),
            actor_id: plan.actor_id,
            device_id: p.device_id,
            authorization_event_id: record.authorization.event_id().clone(),
            authorization_commit: commit,
            governance_generation: route.authority.current_generation(),
            governance_station: route.authority.current_service_id().clone(),
            signer: Ed25519PayloadSigner::new(device_key, record.principal_did, method),
            client,
        })
    }
}
