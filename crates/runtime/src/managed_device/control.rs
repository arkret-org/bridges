//! Normal control rotation using the managed Service's exact outcome recovery.
use super::*;

impl ManagedDeviceRuntime {
    /// Freeze and publish a native successor, then obtain the original acceptance.
    /// An unknown result retains the same signed Event and both control keys.
    pub async fn rotate_control(&self, actor: &ActorId, operation_id: &str) -> Result<RealmCommit> {
        if operation_id.is_empty() || operation_id.len() > 128 {
            return Err(invalid("control rotation requires a bounded operation ID"));
        }
        let digest = canonical_sha256(&(actor, operation_id))?;
        let activate = format!("activate:{digest}");
        let retire = format!("retire:{digest}");
        self.control_transition(actor, &activate, None).await?;
        let prepared = self
            .authoring
            .retained_control_rotation(actor, &activate)
            .await?
            .ok_or_else(|| invalid("accepted control rotation disappeared"))?;
        let payload: arkret::RealmActorControlUpdatePayload =
            serde_json::from_value(serde_json::to_value(&prepared.event.payload)?)?;
        // WebVH successor timestamps have one-second precision. Waiting here
        // leaves the accepted phase durable and recoverable across shutdown.
        let previous = payload.next_method_signature.created_at;
        let wait = previous.timestamp() + 1 - Utc::now().timestamp();
        if wait > 2 {
            return Err(invalid(
                "local clock precedes the retained control operation",
            ));
        }
        if wait > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(wait as u64)).await;
        }
        self.control_transition(actor, &retire, Some(&payload.next_control_method_kid))
            .await
    }

    /// Move this subject's native publication without changing its Realm Actor ID.
    /// The configured principal publisher must already serve the target authority.
    pub async fn relocate_control(
        &self,
        actor: &ActorId,
        operation_id: &str,
        target_did: &arkret::Did,
    ) -> Result<RealmCommit> {
        if operation_id.is_empty() || operation_id.len() > 128 {
            return Err(invalid(
                "control relocation requires a bounded operation ID",
            ));
        }
        let operation = format!("relocate:{}", canonical_sha256(&(actor, operation_id))?);
        self.control_transition_at(actor, &operation, None, Some(target_did))
            .await
    }

    pub(super) async fn control_transition(
        &self,
        actor: &ActorId,
        operation_id: &str,
        retire_method: Option<&arkret::DidUrl>,
    ) -> Result<RealmCommit> {
        self.control_transition_at(actor, operation_id, retire_method, None)
            .await
    }

    async fn control_transition_at(
        &self,
        actor: &ActorId,
        operation_id: &str,
        retire_method: Option<&arkret::DidUrl>,
        target_did: Option<&arkret::Did>,
    ) -> Result<RealmCommit> {
        let prepared = match self
            .authoring
            .retained_control_rotation(actor, operation_id)
            .await?
        {
            Some(prepared) => prepared,
            None => {
                let current = self.control_state(actor).await?;
                if retire_method.is_some_and(|method| method != &current.control.control_method_kid)
                {
                    return Err(invalid(
                        "another control change superseded this rotation; do not retire its methods",
                    ));
                }
                self.authoring
                    .prepare_control_update(
                        actor,
                        operation_id,
                        &current.control,
                        &current.reference,
                        retire_method.is_some(),
                        target_did,
                    )
                    .await?
            }
        };
        if let Some(target) = target_did {
            let payload: arkret::RealmActorControlUpdatePayload =
                serde_json::from_value(serde_json::to_value(&prepared.event.payload)?)?;
            if payload.next_resolution.did != *target {
                return Err(invalid("relocation retry names another target address"));
            }
        }
        if prepared.is_closed() {
            return Err(invalid("this control operation is permanently closed"));
        }
        if let Some((commit, key)) = &prepared.outcome {
            self.authoring
                .accept_control_rotation(&prepared, commit, key)
                .await?;
            return Ok(commit.clone());
        }
        let request = SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(
            prepared.event.event().clone(),
        ));
        let digest = arkret::Hash::new(canonical_sha256(&request)?)?;
        let route = self
            .edge
            .realm_route(prepared.event.scope_ref.realm_id())
            .await?;
        let requester = ActorId::service(self.edge.service_actor_id().clone());
        let result = route
            .material(
                &arkret::RealmActorMaterialRequest::Outcome {
                    actor_id: actor.clone(),
                    request_nonce: crate::realm_governance::nonce()?,
                    target_request_digest: digest.clone(),
                },
                &requester,
            )
            .await?;
        let arkret::RealmActorMaterial::Outcome {
            target_request_digest,
            outcome,
        } = &result.material().result
        else {
            return Err(invalid(
                "control recovery returned another material purpose",
            ));
        };
        if target_request_digest != &digest {
            return Err(invalid("control recovery request mismatch"));
        }
        let outcome = match outcome {
            arkret::RealmActorOperationOutcome::Submitted(AuthoritySubmitOutcome::Rejected {
                ..
            }) => {
                self.authoring
                    .record_control_rejection(&prepared, &result)
                    .await?;
                return Err(invalid(
                    "the governance Station rejected this control operation",
                ));
            }
            arkret::RealmActorOperationOutcome::Submitted(outcome) => outcome.clone(),
            arkret::RealmActorOperationOutcome::Status {
                status: arkret::RealmActorOperationStatus::Unknown,
            } => {
                let current = self.control_state(actor).await?;
                if current.reference != prepared.previous_reference
                    || current.control != prepared.previous_control
                {
                    return Err(invalid(
                        "control changed; recover the original outcome before proceeding",
                    ));
                }
                let controller = self
                    .authoring
                    .managed_controller(actor, &current.control.control_method_kid)
                    .await?;
                let producer = arkret::ProducerVerificationContext {
                    actor: actor.clone(),
                    verification_method: current.control.control_method_kid.clone(),
                    public_key: PublicKeyMaterial::Ed25519Raw {
                        bytes: controller.signing_key.verifying_key().to_bytes().to_vec(),
                    },
                    digest_suite: crate::PRODUCER_DIGEST_SUITE,
                };
                let request = arkret::VerifiedSubmission::verify(request, |_| Ok(producer.clone()))
                    .map_err(|e| invalid(e.to_string()))?;
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
                let options = arkret::ClientRequestOptions::new()
                    .idempotency_key(prepared.event.event_id().as_str());
                let SelfAuthoritySubmitOutcome::Ordinary(outcome) =
                    client.submit_to_realm_authority(&request, &options).await?
                else {
                    return Err(invalid("control update returned an aggregate outcome"));
                };
                outcome
            }
            _ => {
                return Err(invalid(
                    "control rotation has an unexpected terminal outcome",
                ));
            }
        };
        let AuthoritySubmitOutcome::Accepted { commit, .. } = outcome else {
            return Err(invalid(
                "control rotation has not been accepted; retain its original",
            ));
        };
        let original = route
            .material(
                &arkret::RealmActorMaterialRequest::Event {
                    actor_id: actor.clone(),
                    request_nonce: crate::realm_governance::nonce()?,
                    target: arkret::CommittedEventRef {
                        event_id: prepared.event.event_id().clone(),
                        commit_id: commit.commit_id.clone(),
                        stream_ref: commit.stream_ref.clone(),
                        stream_position: commit.stream_position,
                    },
                },
                &requester,
            )
            .await?;
        let arkret::RealmActorMaterial::Event {
            event,
            commit: actual,
            ..
        } = &original.material().result
        else {
            return Err(invalid("control acceptance original is unavailable"));
        };
        if event != prepared.event.event() || actual != &commit {
            return Err(invalid(
                "control acceptance does not cover the frozen original",
            ));
        }
        let issuer = route
            .authority
            .authority_service_at(commit.governance_generation)
            .ok_or_else(|| invalid("control receipt has no legal governance tenure"))?;
        let key = route
            .historical_station_key(
                issuer,
                &commit.signature.verification_method,
                commit.committed_at,
            )
            .await?;
        self.authoring
            .accept_control_rotation(&prepared, &commit, &key)
            .await?;
        Ok(commit)
    }
}
