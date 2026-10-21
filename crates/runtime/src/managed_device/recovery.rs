//! Service-authorized recovery without the unavailable daily control key.
use super::*;

impl ManagedDeviceRuntime {
    /// Retain one native recovery plan, obtain the original begin receipt,
    /// publish that plan, then finish the same identity's control reset.
    pub async fn recover_control(
        &self,
        actor: &ActorId,
        operation_id: &str,
    ) -> Result<RealmCommit> {
        let mut prepared = match self
            .authoring
            .retained_recovery(actor, operation_id)
            .await?
        {
            Some(prepared) => prepared,
            None => {
                let realm = actor
                    .as_realm_actor_id()
                    .ok_or_else(|| invalid("recovery requires a Realm actor"))?;
                let route = self.edge.realm_route(&realm.realm_id).await?;
                let selectors = vec![
                    arkret::CurrentSelector::RealmActorIdentity {
                        actor_id: actor.clone(),
                    },
                    arkret::CurrentSelector::RealmActorControl {
                        actor_id: actor.clone(),
                    },
                    arkret::CurrentSelector::RealmActorManager {
                        actor_id: actor.clone(),
                    },
                    arkret::CurrentSelector::RealmActorRecovery {
                        actor_id: actor.clone(),
                    },
                    arkret::CurrentSelector::RealmActorDeviceGeneration {
                        actor_id: actor.clone(),
                    },
                    arkret::CurrentSelector::RealmActorStatus {
                        actor_id: actor.clone(),
                        gate: arkret::RealmActorStatusGate::Owner,
                    },
                    arkret::CurrentSelector::RealmActorStatus {
                        actor_id: actor.clone(),
                        gate: arkret::RealmActorStatusGate::Governance,
                    },
                ];
                let current = route
                    .material(
                        &arkret::RealmActorMaterialRequest::Current {
                            actor_id: actor.clone(),
                            request_nonce: crate::realm_governance::nonce()?,
                            selectors,
                        },
                        &ActorId::service(self.edge.service_actor_id().clone()),
                    )
                    .await?;
                self.authoring
                    .prepare_recovery(actor, operation_id, &current)
                    .await?
            }
        };
        if let Some((commit, key)) = &prepared.reset_receipt {
            self.authoring
                .accept_recovery_reset(&prepared, commit, key)
                .await?;
            return Ok(commit.clone());
        }
        if prepared.terminal.is_some() {
            return Err(invalid("this recovery operation is permanently terminal"));
        }
        let outcome = self.recovery_outcome(actor, &prepared.begin).await?;
        let arkret::RealmActorMaterialResult::Outcome { outcome: state, .. } =
            &outcome.material().result
        else {
            return Err(invalid("recovery begin returned another material purpose"));
        };
        let begin_ref =
            match state {
                arkret::RealmActorOperationOutcome::Recovery {
                    begin_ref,
                    state: arkret::RealmActorRecoveryState::Pending,
                    ..
                } => begin_ref.clone(),
                arkret::RealmActorOperationOutcome::Recovery {
                    state:
                        arkret::RealmActorRecoveryState::Cancelled
                        | arkret::RealmActorRecoveryState::Superseded,
                    ..
                } => {
                    self.authoring
                        .record_recovery_terminal(&prepared, &outcome)
                        .await?;
                    return Err(invalid("the governance Station terminated this recovery"));
                }
                arkret::RealmActorOperationOutcome::Recovery {
                    state: arkret::RealmActorRecoveryState::Completed,
                    terminal_ref: Some(target),
                    ..
                } => {
                    let reset = prepared.reset.as_ref().ok_or_else(|| {
                        invalid("completed recovery has no retained reset original")
                    })?;
                    let (commit, key) = self.recovery_original(actor, reset, target).await?;
                    self.authoring
                        .accept_recovery_reset(&prepared, &commit, &key)
                        .await?;
                    return Ok(commit);
                }
                arkret::RealmActorOperationOutcome::Submitted(
                    AuthoritySubmitOutcome::Accepted { commit, .. },
                ) => recovery_reference(commit),
                arkret::RealmActorOperationOutcome::Status {
                    status: arkret::RealmActorOperationStatus::Unknown,
                } => {
                    let outcome = self.submit_recovery_original(&prepared.begin).await?;
                    let AuthoritySubmitOutcome::Accepted { commit, .. } = outcome else {
                        return Err(invalid(
                            "recovery begin has not been accepted; retain the exact original",
                        ));
                    };
                    recovery_reference(&commit)
                }
                _ => return Err(invalid("unexpected recovery begin outcome")),
            };
        if prepared.begin_receipt.is_none() {
            let (commit, key) = self
                .recovery_original(actor, &prepared.begin, &begin_ref)
                .await?;
            prepared = self
                .authoring
                .accept_recovery_begin(&prepared, &commit, &key)
                .await?;
        } else if prepared
            .begin_receipt
            .as_ref()
            .is_none_or(|(commit, _)| recovery_reference(commit) != begin_ref)
        {
            return Err(invalid("recovery begin receipt fork"));
        }
        let reset = prepared
            .reset
            .as_ref()
            .ok_or_else(|| invalid("accepted begin did not retain its reset"))?;
        let outcome = self.recovery_outcome(actor, reset).await?;
        let arkret::RealmActorMaterialResult::Outcome { outcome, .. } = &outcome.material().result
        else {
            return Err(invalid("recovery reset returned another material purpose"));
        };
        let commit = match outcome {
            arkret::RealmActorOperationOutcome::Submitted(AuthoritySubmitOutcome::Accepted {
                commit,
                ..
            }) => commit.clone(),
            arkret::RealmActorOperationOutcome::Status {
                status: arkret::RealmActorOperationStatus::Unknown,
            } => {
                let outcome = self.submit_recovery_original(reset).await?;
                let AuthoritySubmitOutcome::Accepted { commit, .. } = outcome else {
                    return Err(invalid(
                        "recovery reset has not been accepted; retain its exact original",
                    ));
                };
                commit
            }
            _ => return Err(invalid("unexpected recovery reset outcome")),
        };
        let (commit, key) = self
            .recovery_original(actor, reset, &recovery_reference(&commit))
            .await?;
        self.authoring
            .accept_recovery_reset(&prepared, &commit, &key)
            .await?;
        Ok(commit)
    }

    async fn recovery_outcome(
        &self,
        actor: &ActorId,
        event: &AuthoredEvent,
    ) -> Result<arkret::identity::VerifiedRealmActorMaterial> {
        let request =
            SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(event.event().clone()));
        let route = self.edge.realm_route(&event.realm_id).await?;
        route
            .material(
                &arkret::RealmActorMaterialRequest::Outcome {
                    actor_id: actor.clone(),
                    request_nonce: crate::realm_governance::nonce()?,
                    target_request_digest: arkret::Hash::new(canonical_sha256(&request)?)?,
                },
                &ActorId::service(self.edge.service_actor_id().clone()),
            )
            .await
    }

    async fn submit_recovery_original(
        &self,
        event: &AuthoredEvent,
    ) -> Result<AuthoritySubmitOutcome> {
        if !matches!(
            event.kind,
            arkret::EventKind::RealmActorRecoveryBegin | arkret::EventKind::RealmActorControlReset
        ) || event.actor_id != ActorId::service(self.edge.service_actor_id().clone())
            || event.authorization_ref.is_some()
            || event.executed_by.is_some()
        {
            return Err(invalid(
                "independent recovery requires the real managing Service original",
            ));
        }
        let request =
            SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(event.event().clone()));
        let producer = arkret::ProducerVerificationContext {
            actor: ActorId::service(self.edge.service_actor_id().clone()),
            verification_method: self.edge.service_verification_method()?,
            public_key: PublicKeyMaterial::Ed25519Raw {
                bytes: self.edge.signer().verifying_key().to_bytes().to_vec(),
            },
            digest_suite: crate::PRODUCER_DIGEST_SUITE,
        };
        let request = arkret::VerifiedSubmission::verify(request, |_| Ok(producer.clone()))
            .map_err(|e| invalid(e.to_string()))?;
        let route = self.edge.realm_route(&event.realm_id).await?;
        let result = route
            .client
            .submit_to_realm_authority(
                &request,
                &arkret::ClientRequestOptions::new().idempotency_key(event.event_id().as_str()),
            )
            .await?;
        let SelfAuthoritySubmitOutcome::Ordinary(outcome) = result else {
            return Err(invalid("recovery returned an aggregate response"));
        };
        Ok(outcome)
    }

    async fn recovery_original(
        &self,
        actor: &ActorId,
        expected: &AuthoredEvent,
        target: &arkret::CommittedEventRef,
    ) -> Result<(RealmCommit, PublicKeyMaterial)> {
        if target.event_id != *expected.event_id() {
            return Err(invalid("recovery outcome refers to another original"));
        }
        let route = self.edge.realm_route(&expected.realm_id).await?;
        let result = route
            .material(
                &arkret::RealmActorMaterialRequest::Event {
                    actor_id: actor.clone(),
                    request_nonce: crate::realm_governance::nonce()?,
                    target: target.clone(),
                },
                &ActorId::service(self.edge.service_actor_id().clone()),
            )
            .await?;
        let arkret::RealmActorMaterialResult::Event { event, commit, .. } =
            &result.material().result
        else {
            return Err(invalid("recovery original unavailable"));
        };
        if event != expected.event() || recovery_reference(commit) != *target {
            return Err(invalid("recovery original differs from frozen plan"));
        }
        let issuer = route
            .authority
            .authority_service_at(commit.governance_generation)
            .ok_or_else(|| invalid("recovery receipt has no legal governance tenure"))?;
        let key = route
            .historical_station_key(
                issuer,
                &commit.signature.verification_method,
                commit.committed_at,
            )
            .await?;
        Ok((commit.clone(), key))
    }
}
fn recovery_reference(commit: &RealmCommit) -> arkret::CommittedEventRef {
    arkret::CommittedEventRef {
        event_id: commit.event_ref.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    }
}
