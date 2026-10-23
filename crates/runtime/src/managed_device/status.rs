//! Durable owner-gate changes use the existing control-signed Event contract.
use arkret::{
    RealmActorMaterial, RealmActorMaterialRequest, RealmActorOperationOutcome,
    RealmActorOperationStatus, RealmActorStatusSetPayload, RealmActorStatusSetPayloadGate,
    RealmActorStatusSetPayloadState,
};

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerStatusIntent {
    operation_id: String,
    event: AuthoredEvent,
    controller_key: PublicKeyMaterial,
    accepted: Option<arkret::RealmActorMaterialOutcome>,
}

impl OwnerStatusIntent {
    fn request(&self) -> SelfAuthoritySubmitRequest {
        SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(self.event.event().clone()))
    }

    fn verify(
        &self,
        actor: &ActorId,
        operation_id: &str,
        state: RealmActorStatusSetPayloadState,
    ) -> Result<()> {
        let payload: RealmActorStatusSetPayload =
            serde_json::from_value(serde_json::to_value(&self.event.payload)?)?;
        if self.operation_id != operation_id
            || self.event.kind != arkret::EventKind::RealmActorStatusSet
            || self.event.actor_id != *actor
            || payload.target_actor_id != *actor
            || payload.gate != RealmActorStatusSetPayloadGate::Owner
            || payload.state != state
            || self.event.executed_by.is_some()
            || !matches!(&self.event.scope_ref, ScopeRef::RealmControl { realm_id }
                if actor.as_realm_actor_id().is_some_and(|id| &id.realm_id == realm_id))
        {
            return Err(invalid("owner operation is frozen for another intent"));
        }
        self.event.verify_identity()?;
        let proof = self
            .event
            .producer_proof
            .as_ref()
            .ok_or_else(|| invalid("owner operation has no original signature"))?;
        let producer = arkret::ProducerVerificationContext {
            actor: actor.clone(),
            verification_method: proof.verification_method.clone(),
            public_key: self.controller_key.clone(),
            digest_suite: crate::PRODUCER_DIGEST_SUITE,
        };
        arkret::VerifiedSubmission::verify(self.request(), |_| Ok(producer.clone()))
            .map_err(|error| invalid(error.to_string()))?;
        Ok(())
    }

    fn receipt(&self) -> Result<Option<RealmCommit>> {
        let Some(material) = &self.accepted else {
            return Ok(None);
        };
        let RealmActorMaterial::Event { event, commit, .. } = &material.result else {
            return Err(invalid("owner receipt has no exact original"));
        };
        if event != self.event.event()
            || commit.event_ref != *self.event.event_id()
            || commit.stream_ref
                != (arkret::CommitStreamRef::RealmControl {
                    realm_id: self.event.realm_id.clone(),
                })
            || material.actor_id != self.event.actor_id
        {
            return Err(invalid("owner receipt differs from the retained original"));
        }
        Ok(Some(commit.clone()))
    }
}

impl ManagedDeviceRuntime {
    /// Explicitly change only the owner gate. Recovery never calls this implicitly.
    /// Reusing an operation ID replays the original even after later gate changes.
    pub async fn set_owner_status(
        &self,
        actor: &ActorId,
        operation_id: &str,
        state: RealmActorStatusSetPayloadState,
    ) -> Result<RealmCommit> {
        if operation_id.is_empty() || operation_id.len() > 128 {
            return Err(invalid("owner status requires a bounded operation ID"));
        }
        let id = actor
            .as_realm_actor_id()
            .ok_or_else(|| invalid("Realm actor required"))?;
        let key = format!(
            "managed-owner-status/v1/{}",
            canonical_sha256(&(actor, operation_id))?
        );
        if self.read(&key).await?.is_none() {
            let route = self.edge.realm_route(&id.realm_id).await?;
            let selector = arkret::CurrentSelector::RealmActorStatus {
                actor_id: actor.clone(),
                gate: arkret::RealmActorStatusGate::Owner,
            };
            let material = route
                .material(
                    &RealmActorMaterialRequest::Current {
                        actor_id: actor.clone(),
                        request_nonce: crate::realm_governance::nonce()?,
                        selectors: vec![selector.clone()],
                    },
                    &ActorId::service(self.edge.service_actor_id().clone()),
                )
                .await?;
            let RealmActorMaterial::Current { entries } = &material.material().result else {
                return Err(invalid("owner status query returned another purpose"));
            };
            let revision = entries
                .iter()
                .find_map(|entry| match entry {
                    arkret::RealmActorMaterialCurrentEntry::Present {
                        row:
                            arkret::TypedCurrentRow::Value {
                                selector: actual,
                                revision,
                                ..
                            },
                        ..
                    } if actual == &selector => Some(revision.clone()),
                    _ => None,
                })
                .ok_or_else(|| invalid("owner status current is missing"))?;
            let current = self.control_state(actor).await?;
            let controller = self
                .authoring
                .managed_controller(actor, &current.control.control_method_kid)
                .await?;
            let at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
            let mut event = TypedEventDraft::<event_spec::RealmActorStatusSet>::new(
                ScopeRef::RealmControl {
                    realm_id: id.realm_id.clone(),
                },
                actor.clone(),
                RealmActorStatusSetPayload {
                    target_actor_id: actor.clone(),
                    gate: RealmActorStatusSetPayloadGate::Owner,
                    expected_revision: revision,
                    state,
                },
            )?
            .with_applet_id(
                crate::managed_authoring::creation_payload(&controller.original.event)?.applet_id,
            )
            .into_intent(at)?
            .author_with_digest_suite(crate::PRODUCER_DIGEST_SUITE)?;
            sign_event(
                &mut event,
                &controller.signer,
                SignEventOptions::new().with_created_at(at),
            )?;
            let intent = OwnerStatusIntent {
                operation_id: operation_id.into(),
                event,
                controller_key: PublicKeyMaterial::Ed25519Raw {
                    bytes: controller.signing_key.verifying_key().to_bytes().to_vec(),
                },
                accepted: None,
            };
            intent.verify(actor, operation_id, state)?;
            let encrypted = self.authoring.encrypt_key_material(&key, &intent)?;
            self.cas(&key, None, encrypted).await?;
        }
        for _ in 0..8 {
            let raw = self
                .read(&key)
                .await?
                .ok_or_else(|| invalid("owner intent disappeared"))?;
            let mut intent: OwnerStatusIntent = self.authoring.decrypt_key_material(&key, &raw)?;
            intent.verify(actor, operation_id, state)?;
            if let Some(commit) = intent.receipt()? {
                return Ok(commit);
            }
            let route = self.edge.realm_route(&id.realm_id).await?;
            let requester = ActorId::service(self.edge.service_actor_id().clone());
            let digest = arkret::Hash::new(canonical_sha256(&intent.request())?)?;
            let outcome = route
                .material(
                    &RealmActorMaterialRequest::Outcome {
                        actor_id: actor.clone(),
                        request_nonce: crate::realm_governance::nonce()?,
                        target_request_digest: digest.clone(),
                    },
                    &requester,
                )
                .await?;
            let RealmActorMaterial::Outcome {
                target_request_digest,
                outcome,
            } = &outcome.material().result
            else {
                return Err(invalid("owner result has another material purpose"));
            };
            if target_request_digest != &digest {
                return Err(invalid("owner result has another request digest"));
            }
            let result = match outcome {
                RealmActorOperationOutcome::Submitted(result) => result.clone(),
                RealmActorOperationOutcome::Status {
                    status: RealmActorOperationStatus::Unknown,
                } => {
                    let current = self.control_state(actor).await?;
                    let controller = self
                        .authoring
                        .managed_controller(actor, &current.control.control_method_kid)
                        .await?;
                    let client = route.client.clone().with_realm_actor_control_http_signer(
                        arkret::RealmActorControlHttpMetadata {
                            actor_id: actor.clone(),
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
                        actor: actor.clone(),
                        verification_method: intent
                            .event
                            .producer_proof
                            .as_ref()
                            .ok_or_else(|| invalid("owner operation has no proof"))?
                            .verification_method
                            .clone(),
                        public_key: intent.controller_key.clone(),
                        digest_suite: crate::PRODUCER_DIGEST_SUITE,
                    };
                    let request = arkret::VerifiedSubmission::verify(intent.request(), |_| {
                        Ok(producer.clone())
                    })
                    .map_err(|error| invalid(error.to_string()))?;
                    let SelfAuthoritySubmitOutcome::Ordinary(result) = client
                        .submit_to_realm_authority(
                            &request,
                            &arkret::ClientRequestOptions::new()
                                .idempotency_key(intent.event.event_id().as_str()),
                        )
                        .await?
                    else {
                        return Err(invalid("owner result is an unexpected aggregate"));
                    };
                    result
                }
                _ => return Err(invalid("owner original has an unexpected outcome")),
            };
            let AuthoritySubmitOutcome::Accepted { commit, .. } = result else {
                return Err(invalid(
                    "owner operation is not accepted; retain its original",
                ));
            };
            let material = route
                .material(
                    &RealmActorMaterialRequest::Event {
                        actor_id: actor.clone(),
                        request_nonce: crate::realm_governance::nonce()?,
                        target: arkret::CommittedEventRef {
                            event_id: intent.event.event_id().clone(),
                            commit_id: commit.commit_id.clone(),
                            stream_ref: commit.stream_ref.clone(),
                            stream_position: commit.stream_position,
                        },
                    },
                    &requester,
                )
                .await?;
            intent.accepted = Some(material.material().clone());
            if intent.receipt()?.as_ref() != Some(&commit) {
                return Err(invalid("owner original Commit differs"));
            }
            let encrypted = self.authoring.encrypt_key_material(&key, &intent)?;
            if self.cas(&key, Some(raw), encrypted).await? {
                return Ok(commit);
            }
        }
        Err(invalid(
            "owner status custody contended; retry the same operation",
        ))
    }
}
