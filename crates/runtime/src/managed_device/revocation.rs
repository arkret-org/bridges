//! Original control-signed revoke requests and authenticated terminal outcomes.
use arkret::{
    CommittedEventRef, Hash, RealmActorDeviceRevokeState, RealmActorMaterialOutcome,
    RealmActorMaterialRequest, RealmActorMaterialResult, RealmActorOperationOutcome,
};
use arkret_models_collaboration::events_payloads::DeviceRevokePayload;

use super::*;

const PREFIX: &str = "managed-device-revocation/v1/";
const RETIRED_PREFIX: &str = "managed-retired-device/v1/";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetiredDevice {
    authorization: AuthoredEvent,
    authorization_commit: RealmCommit,
    terminal: RealmActorMaterialOutcome,
}

pub(super) fn retirement_key(actor: &ActorId, device_operation: &str) -> Result<String> {
    Ok(format!(
        "{RETIRED_PREFIX}{}",
        canonical_sha256(&(actor, device_operation))?
    ))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Revocation {
    operation: String,
    reason: Option<String>,
    device_operation: String,
    authorization: AuthoredEvent,
    authorization_commit: RealmCommit,
    event: AuthoredEvent,
    control_ref: CommittedEventRef,
    controller_key: PublicKeyMaterial,
    proposal: Option<RealmCommit>,
    material: Option<RealmActorMaterialOutcome>,
}

fn reference(event: &AuthoredEvent, commit: &RealmCommit) -> CommittedEventRef {
    CommittedEventRef {
        event_id: event.event_id().clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    }
}

fn storage_key(actor: &ActorId, operation: &str) -> Result<String> {
    Ok(format!(
        "{PREFIX}{}",
        canonical_sha256(&(actor, operation))?
    ))
}

impl Revocation {
    fn request(&self) -> SelfAuthoritySubmitRequest {
        SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(self.event.event().clone()))
    }

    fn validate(&self) -> Result<DeviceAuthorizePayload> {
        self.authorization.verify_identity()?;
        self.event.verify_identity()?;
        let authorization: DeviceAuthorizePayload =
            serde_json::from_value(serde_json::to_value(&self.authorization.payload)?)?;
        let revoke: DeviceRevokePayload =
            serde_json::from_value(serde_json::to_value(&self.event.payload)?)?;
        if self.operation.is_empty()
            || self.event.kind != arkret::EventKind::DeviceRevoke
            || self.authorization.kind != arkret::EventKind::DeviceAuthorize
            || self.event.actor_id != self.authorization.actor_id
            || self.event.scope_ref != self.authorization.scope_ref
            || !matches!(self.event.scope_ref, ScopeRef::RealmControl { .. })
            || self.event.executed_by.is_some()
            || revoke.device_id != authorization.device_id
            || self.authorization_commit.event_ref != *self.authorization.event_id()
        {
            return Err(invalid(
                "revoke custody differs from the exact original Device",
            ));
        }
        let producer = arkret::ProducerVerificationContext {
            actor: self.event.actor_id.clone(),
            verification_method: self
                .event
                .producer_proof
                .as_ref()
                .ok_or_else(|| invalid("revoke original has no producer proof"))?
                .verification_method
                .clone(),
            public_key: self.controller_key.clone(),
            digest_suite: crate::PRODUCER_DIGEST_SUITE,
        };
        arkret::VerifiedSubmission::verify(self.request(), |_| Ok(producer.clone()))
            .map_err(|error| invalid(error.to_string()))?;
        Ok(authorization)
    }

    fn state(&self) -> Result<Option<RealmActorDeviceRevokeState>> {
        let authorization = self.validate()?;
        let Some(material) = &self.material else {
            return Ok(None);
        };
        let RealmActorMaterialResult::Outcome {
            target_request_digest,
            outcome:
                RealmActorOperationOutcome::DeviceRevoke {
                    proposal_ref,
                    device_id,
                    authorization_ref,
                    authorized_generation_ref,
                    state,
                    ..
                },
        } = &material.result
        else {
            return Err(invalid("revoke material has another result branch"));
        };
        let proposal = self
            .proposal
            .as_ref()
            .ok_or_else(|| invalid("revoke material has no accepted proposal"))?;
        if target_request_digest.as_str() != canonical_sha256(&self.request())?
            || proposal_ref != &reference(&self.event, proposal)
            || device_id != &authorization.device_id
            || authorization_ref != &reference(&self.authorization, &self.authorization_commit)
            || *authorized_generation_ref != authorization.authorized_generation_ref
        {
            return Err(invalid(
                "revoke result binds another request or authorization",
            ));
        }
        Ok(Some(*state))
    }
}

impl ManagedDeviceRuntime {
    pub(super) async fn is_retired_device(&self, actor: &ActorId, operation: &str) -> Result<bool> {
        let key = retirement_key(actor, operation)?;
        let Some(raw) = self.read(&key).await? else {
            return Ok(false);
        };
        let retired: RetiredDevice = self.authoring.decrypt_key_material(&key, &raw)?;
        retired.authorization.verify_identity()?;
        let authorization: DeviceAuthorizePayload =
            serde_json::from_value(serde_json::to_value(&retired.authorization.payload)?)?;
        let RealmActorMaterialResult::Outcome {
            outcome:
                RealmActorOperationOutcome::DeviceRevoke {
                    authorization_ref,
                    device_id,
                    authorized_generation_ref,
                    state: RealmActorDeviceRevokeState::Accepted,
                    decided_at: Some(_),
                    ..
                },
            ..
        } = &retired.terminal.result
        else {
            return Err(invalid("retired Device has no accepted terminal evidence"));
        };
        if &retired.authorization.actor_id != actor
            || &retired.terminal.actor_id != actor
            || retired.authorization.kind != arkret::EventKind::DeviceAuthorize
            || authorization_ref
                != &reference(&retired.authorization, &retired.authorization_commit)
            || device_id != &authorization.device_id
            || *authorized_generation_ref != authorization.authorized_generation_ref
        {
            return Err(invalid(
                "retired Device tombstone binds another authorization",
            ));
        }
        Ok(true)
    }

    /// Freeze one original controller-signed proposal before contacting the
    /// governor. A committed proposal is not a final revocation decision.
    pub async fn revoke_device(
        &self,
        device: &ManagedDevice,
        operation: &str,
        reason: Option<String>,
    ) -> Result<RealmActorDeviceRevokeState> {
        if operation.is_empty() || operation.len() > 128 {
            return Err(invalid(
                "revoke requires a bounded stable operation identity",
            ));
        }
        let key = storage_key(&device.actor_id, operation)?;
        if self.read(&key).await?.is_none() {
            let (_, _, custody) = self.accepted_device_record(device).await?;
            let current = self.control_state(&device.actor_id).await?;
            let controller = self
                .authoring
                .managed_controller(&device.actor_id, &current.control.control_method_kid)
                .await?;
            if current.control.control_method_kid.as_str()
                != controller.signer.verification_method()
            {
                return Err(invalid(
                    "local controller no longer controls this Realm actor",
                ));
            }
            let at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
            let payload: DeviceRevokePayload = serde_json::from_value(serde_json::json!({
                "device_id":device.device_id,
                "revoked_by":device.actor_id.signing_principal_id(),
                "revoked_at":at,
                "reason":reason,
            }))?;
            let intent = TypedEventDraft::<event_spec::DeviceRevoke>::new(
                ScopeRef::RealmControl {
                    realm_id: device.effective_scope.realm_id().clone(),
                },
                device.actor_id.clone(),
                payload,
            )?
            .with_applet_id(
                crate::managed_authoring::creation_payload(&controller.original.event)?.applet_id,
            )
            .into_intent(at)?;
            let mut event = intent.author_with_digest_suite(crate::PRODUCER_DIGEST_SUITE)?;
            sign_event(
                &mut event,
                &controller.signer,
                SignEventOptions::new().with_created_at(at),
            )?;
            let saved = Revocation {
                operation: operation.into(),
                reason: reason.clone(),
                device_operation: device.operation_id.clone(),
                authorization: custody.authorization,
                authorization_commit: device.authorization_commit.clone(),
                event,
                control_ref: current.reference,
                controller_key: PublicKeyMaterial::Ed25519Raw {
                    bytes: controller.signer.verifying_key().to_bytes().to_vec(),
                },
                proposal: None,
                material: None,
            };
            saved.validate()?;
            let encrypted = self.authoring.encrypt_key_material(&key, &saved)?;
            self.cas(&key, None, encrypted).await?;
        }
        let raw = self
            .read(&key)
            .await?
            .ok_or_else(|| invalid("revoke intent disappeared"))?;
        let saved: Revocation = self.authoring.decrypt_key_material(&key, &raw)?;
        if saved.operation != operation
            || saved.reason != reason
            || saved.device_operation != device.operation_id
            || saved.authorization.event_id() != &device.authorization_event_id
        {
            return Err(invalid(
                "revoke operation was already frozen for another intent",
            ));
        }
        self.resume_revocation(&key).await
    }

    async fn resume_revocation(&self, key: &str) -> Result<RealmActorDeviceRevokeState> {
        for _ in 0..8 {
            let raw = self
                .read(key)
                .await?
                .ok_or_else(|| invalid("revoke intent missing"))?;
            let mut saved: Revocation = self.authoring.decrypt_key_material(key, &raw)?;
            saved.validate()?;
            if storage_key(&saved.event.actor_id, &saved.operation)? != key {
                return Err(invalid(
                    "revoke storage key differs from its original intent",
                ));
            }
            if let Some(
                state @ (RealmActorDeviceRevokeState::Accepted
                | RealmActorDeviceRevokeState::Rejected),
            ) = saved.state()?
            {
                return Ok(state);
            }
            let route = self
                .edge
                .realm_route(saved.event.scope_ref.realm_id())
                .await?;
            if saved.proposal.is_none() {
                // The governor may have accepted the original before the host
                // persisted its response. Recover through the managing Service,
                // which does not need the original controller to remain current.
                let query = RealmActorMaterialRequest::Outcome {
                    actor_id: saved.event.actor_id.clone(),
                    request_nonce: crate::realm_governance::nonce()?,
                    target_request_digest: Hash::new(canonical_sha256(&saved.request())?)?,
                };
                let requester = ActorId::service(self.edge.service_actor_id().clone());
                let material = route.material(&query, &requester).await?;
                match &material.material().result {
                    RealmActorMaterialResult::Outcome {
                        outcome: RealmActorOperationOutcome::DeviceRevoke { proposal_ref, .. },
                        ..
                    } => {
                        let original = route
                            .material(
                                &RealmActorMaterialRequest::Event {
                                    actor_id: saved.event.actor_id.clone(),
                                    request_nonce: crate::realm_governance::nonce()?,
                                    target: proposal_ref.clone(),
                                },
                                &requester,
                            )
                            .await?;
                        let RealmActorMaterialResult::Event { event, commit, .. } =
                            &original.material().result
                        else {
                            return Err(invalid("revoke recovery has no accepted original"));
                        };
                        if canonical_sha256(event)? != canonical_sha256(saved.event.event())? {
                            return Err(invalid("revoke recovery returned another original"));
                        }
                        saved.proposal = Some(commit.clone());
                        saved.material = Some(material.material().clone());
                        let state = saved
                            .state()?
                            .ok_or_else(|| invalid("recovered revoke outcome missing"))?;
                        let encrypted = self.authoring.encrypt_key_material(key, &saved)?;
                        if self.cas(key, Some(raw), encrypted).await? {
                            return Ok(state);
                        }
                        continue;
                    }
                    RealmActorMaterialResult::Outcome {
                        outcome:
                            RealmActorOperationOutcome::Status {
                                status: arkret::RealmActorOperationStatus::Unknown,
                            },
                        ..
                    } => {}
                    _ => {
                        return Err(invalid(
                            "revoke original has an unexpected registered outcome",
                        ));
                    }
                }
                let current = self.control_state(&saved.event.actor_id).await?;
                let controller = self
                    .authoring
                    .managed_controller(&saved.event.actor_id, &current.control.control_method_kid)
                    .await?;
                let client = route.client.clone().with_realm_actor_control_http_signer(
                    arkret::RealmActorControlHttpMetadata {
                        actor_id: saved.event.actor_id.clone(),
                        control_ref: current.reference,
                        nonce: crate::realm_governance::nonce()?,
                    },
                    route.authority.current_service_id().clone(),
                    arkret::http_client::HttpMessageSigner::new(
                        controller.signer.verification_method().to_owned(),
                        controller.signing_key,
                    ),
                )?;
                let producer = arkret::ProducerVerificationContext {
                    actor: saved.event.actor_id.clone(),
                    verification_method: saved
                        .event
                        .producer_proof
                        .as_ref()
                        .ok_or_else(|| invalid("revoke proof missing"))?
                        .verification_method
                        .clone(),
                    public_key: saved.controller_key.clone(),
                    digest_suite: crate::PRODUCER_DIGEST_SUITE,
                };
                let request =
                    arkret::VerifiedSubmission::verify(saved.request(), |_| Ok(producer.clone()))
                        .map_err(|error| invalid(error.to_string()))?;
                let SelfAuthoritySubmitOutcome::Ordinary(outcome) = client
                    .submit_to_realm_authority(
                        &request,
                        &arkret::ClientRequestOptions::new()
                            .idempotency_key(saved.event.event_id().as_str()),
                    )
                    .await?
                else {
                    return Err(invalid("revoke proposal returned an aggregate result"));
                };
                crate::authoring::publication_outcome(&saved.event, &outcome)?;
                let AuthoritySubmitOutcome::Accepted { commit, .. } = outcome else {
                    return Err(invalid("governor did not accept the revoke proposal"));
                };
                let keys =
                    garth::historical_station_keys::fetch_historical_station_keys_for_commits(
                        &route.client,
                        &route.bundle,
                        &[&commit],
                    )
                    .await
                    .map_err(|error| invalid(error.to_string()))?;
                route
                    .authority
                    .verify_commit(&commit, &keys)
                    .map_err(|error| invalid(error.to_string()))?;
                saved.proposal = Some(commit);
                let encrypted = self.authoring.encrypt_key_material(key, &saved)?;
                if !self.cas(key, Some(raw), encrypted).await? {
                    continue;
                }
                // Persist proposal acceptance separately from the fresh query.
                continue;
            }
            let request = RealmActorMaterialRequest::Outcome {
                actor_id: saved.event.actor_id.clone(),
                request_nonce: crate::realm_governance::nonce()?,
                target_request_digest: Hash::new(canonical_sha256(&saved.request())?)?,
            };
            let verified = route
                .material(
                    &request,
                    &ActorId::service(self.edge.service_actor_id().clone()),
                )
                .await?;
            saved.material = Some(verified.material().clone());
            let state = saved
                .state()?
                .ok_or_else(|| invalid("revoke outcome missing"))?;
            let encrypted = self.authoring.encrypt_key_material(key, &saved)?;
            if self.cas(key, Some(raw), encrypted).await? {
                return Ok(state);
            }
        }
        Err(invalid(
            "revoke outcome custody contended; resume its original intent",
        ))
    }

    /// Host recovery resumes exact proposals and queries. It never turns a
    /// pending proposal into permission to destroy the Device's private keys.
    pub async fn reconcile_device_revocations(&self) -> Result<Vec<(ActorId, DeviceId)>> {
        let store = self.store.clone();
        let entries = run_blocking(move || store.entries_with_prefix(PREFIX)).await?;
        let mut fenced = Vec::new();
        for (key, raw) in entries {
            let saved: Revocation = self.authoring.decrypt_key_material(&key, &raw)?;
            let authorization = saved.validate()?;
            match self.resume_revocation(&key).await {
                Ok(RealmActorDeviceRevokeState::Rejected) => {}
                Ok(RealmActorDeviceRevokeState::Accepted) => {
                    fenced.push((saved.event.actor_id.clone(), authorization.device_id));
                    // This branch reconstructs only an already accepted original
                    // for cleanup, including after expiry or host restart.
                    if let Err(error) = self.resume_revoked_custody(&saved).await {
                        tracing::warn!(%error, "revoked private Device cleanup remains pending");
                    }
                }
                Ok(_) => fenced.push((saved.event.actor_id.clone(), authorization.device_id)),
                Err(error) => {
                    // Unknown outcome cannot resurrect an already proposed Device.
                    fenced.push((saved.event.actor_id.clone(), authorization.device_id));
                    tracing::warn!(%error, "native revoke original remains pending");
                }
            }
        }
        Ok(fenced)
    }

    async fn resume_revoked_custody(&self, saved: &Revocation) -> Result<()> {
        let actor = &saved.event.actor_id;
        let key = format!(
            "managed-device/v1/{}",
            canonical_sha256(&(actor, &saved.device_operation))?
        );
        let Some(raw) = self.read(&key).await? else {
            if !self
                .is_retired_device(actor, &saved.device_operation)
                .await?
            {
                return Err(invalid(
                    "revoked Device custody disappeared without a tombstone",
                ));
            }
            self.erase_retired_attachment_checkpoints(actor, &saved.validate()?.device_id)
                .await?;
            return Ok(());
        };
        let record: DeviceRecord = self.decrypt_device_record(&key, &raw).await?;
        self.validate(&record)?;
        if record.authorization != saved.authorization
            || !matches!(&record.outcome, Some(AuthoritySubmitOutcome::Accepted { commit, .. })
                if commit == &saved.authorization_commit)
        {
            return Err(invalid(
                "retired custody differs from its original authorization",
            ));
        }
        let p = payload(&record)?;
        for scope in record
            .plan
            .scopes
            .entries()
            .iter()
            .map(|entry| entry.effective_scope.clone())
        {
            let route = self.edge.realm_route(scope.realm_id()).await?;
            let signing_key = SigningKey::from_bytes(&seed(&record.device_seed)?);
            let fingerprint =
                arkret::ed25519_pubkey_to_did_key_multibase(signing_key.verifying_key().as_bytes());
            let client = route.client.clone().with_managed_device_http_signer(
                AppletManagedDeviceMetadata {
                    actor_id: actor.clone(),
                    device_id: p.device_id.clone(),
                    authorization_event_id: saved.authorization.event_id().clone(),
                    applet_id: p
                        .applet_id
                        .clone()
                        .ok_or_else(|| invalid("retired Device Applet missing"))?,
                    effective_scope: scope.clone(),
                    nonce: crate::realm_governance::nonce()?,
                },
                route.authority.current_service_id().clone(),
                arkret::http_client::HttpMessageSigner::new(
                    format!("did:key:{fingerprint}#{fingerprint}"),
                    signing_key.clone(),
                ),
            )?;
            let device = ManagedDevice {
                actor_id: actor.clone(),
                device_id: p.device_id.clone(),
                authorization_event_id: saved.authorization.event_id().clone(),
                authorization_commit: saved.authorization_commit.clone(),
                governance_generation: route.authority.current_generation(),
                governance_station: route.authority.current_service_id().clone(),
                client,
                signer: Ed25519PayloadSigner::new(
                    signing_key,
                    record.principal_did.clone(),
                    arkret::DidUrl::new(format!("{}#{}", record.principal_did, p.device_id))
                        .map_err(invalid)?,
                ),
                operation_id: saved.device_operation.clone(),
                effective_scope: scope,
            };
            if self.erase_revoked_device(&device).await? {
                break;
            }
        }
        Ok(())
    }

    async fn erase_retired_attachment_checkpoints(
        &self,
        actor: &ActorId,
        device_id: &DeviceId,
    ) -> Result<bool> {
        let entries = self
            .attachment_checkpoints_for_device(actor, device_id)
            .await?;
        let expected: Vec<_> = entries
            .iter()
            .map(|(key, value)| (key.clone(), Some(value.clone())))
            .collect();
        let writes: Vec<_> = entries.into_iter().map(|(key, _)| (key, None)).collect();
        let store = self.store.clone();
        run_blocking(move || store.compare_exchange_batch(&expected, &writes)).await
    }

    /// Erase private Device/MLS custody only after an authenticated accepted
    /// terminal result, with all locally received queue work already settled.
    /// Keep the exact public originals and a tombstone so bootstrap cannot
    /// silently recreate this operation with fresh keys.
    pub async fn erase_revoked_device(&self, device: &ManagedDevice) -> Result<bool> {
        let tombstone_key = retirement_key(&device.actor_id, &device.operation_id)?;
        if self
            .is_retired_device(&device.actor_id, &device.operation_id)
            .await?
        {
            return self
                .erase_retired_attachment_checkpoints(&device.actor_id, &device.device_id)
                .await;
        }
        let store = self.store.clone();
        let entries = run_blocking(move || store.entries_with_prefix(PREFIX)).await?;
        let mut terminal = None;
        for (key, raw) in entries {
            let saved: Revocation = self.authoring.decrypt_key_material(&key, &raw)?;
            if saved.event.actor_id == device.actor_id
                && saved.device_operation == device.operation_id
                && saved.authorization.event_id() == &device.authorization_event_id
                && saved.state()? == Some(RealmActorDeviceRevokeState::Accepted)
            {
                terminal = saved.material;
                break;
            }
        }
        let Some(terminal) = terminal else {
            return Ok(false);
        };
        self.drain_durable_welcome_consumes(device).await?;
        self.complete_durable_recipient_page(device).await?;
        if self.has_pending_recipient_work(device).await? {
            return Ok(false);
        }
        let (key, previous, record) = self.accepted_device_record(device).await?;
        // Recheck after the final versioned read: a concurrent reader may
        // have installed a page after the earlier cleanup observation.
        if super::inbox::has_pending_work(&record) {
            return Ok(false);
        }
        let retired = RetiredDevice {
            authorization: record.authorization,
            authorization_commit: device.authorization_commit.clone(),
            terminal,
        };
        let tombstone = self
            .authoring
            .encrypt_key_material(&tombstone_key, &retired)?;
        let expected = vec![(key.clone(), Some(previous)), (tombstone_key.clone(), None)];
        let writes = vec![(key, None), (tombstone_key, Some(tombstone))];
        let store = self.store.clone();
        if !run_blocking(move || store.compare_exchange_batch(&expected, &writes)).await? {
            return Ok(false);
        }
        // The tombstone prevents any late reader from adding another private
        // checkpoint. Re-scan after it commits to cover earlier racing writes.
        self.erase_retired_attachment_checkpoints(&device.actor_id, &device.device_id)
            .await
    }
}
