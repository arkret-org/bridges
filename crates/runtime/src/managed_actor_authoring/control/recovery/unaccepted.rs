//! A local closure proof is separate from canonical recovery lifecycle states.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UnacceptedRecoveryProof {
    advanced_current: RealmActorMaterialResponseBody,
    subsequent_unknown: RealmActorMaterialResponseBody,
}

impl ManagedActorAuthoringService {
    pub(crate) async fn close_unaccepted_recovery(
        &self,
        prepared: &PreparedRecovery,
        current: &arkret::identity::VerifiedRealmActorMaterial,
        outcome: &arkret::identity::VerifiedRealmActorMaterial,
    ) -> Result<()> {
        let current = current.material();
        let outcome = outcome.material();
        validate_closure(prepared, current, outcome, self.edge.service_actor_id())?;
        let subject = self.custody_subject(&prepared.actor_id).await?;
        let raw = self
            .control_raw(&subject)
            .await?
            .ok_or_else(|| invalid("recovery intent disappeared"))?;
        let mut custody: ControlCustody = self.decrypt_key_material(&key(&subject), &raw)?;
        let retained = custody
            .recoveries
            .get_mut(&prepared.operation_id)
            .ok_or_else(|| invalid("recovery intent disappeared"))?;
        if retained.begin != prepared.begin
            || retained.begin_receipt.is_some()
            || retained.reset.is_some()
            || retained.terminal.is_some()
        {
            return Err(invalid("accepted recovery cannot be closed as unaccepted"));
        }
        if retained.closed_without_acceptance() {
            return Ok(());
        }
        retained.unaccepted_proof = Some(UnacceptedRecoveryProof {
            advanced_current: current.clone(),
            subsequent_unknown: outcome.clone(),
        });
        self.save_control(&subject, Some(raw), &custody).await
    }
}

fn validate_closure(
    prepared: &PreparedRecovery,
    current: &RealmActorMaterialResponseBody,
    outcome: &RealmActorMaterialResponseBody,
    service: &arkret::DidCoreId,
) -> Result<()> {
    if prepared.begin_receipt.is_some()
        || prepared.reset.is_some()
        || prepared.terminal.is_some()
        || [current, outcome].iter().any(|material| {
            material.actor_id != prepared.actor_id
                || material.requester_actor_id != ActorId::service(service.clone())
        })
    {
        return Err(invalid(
            "unaccepted recovery proof has another subject or an accepted begin",
        ));
    }
    let request =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
            arkret::EventAdmissionSubmission::new(prepared.begin.event().clone()),
        );
    let RealmActorMaterial::RequestStatus {
        target_request_digest,
        request_status:
            arkret::RealmActorRequestStatus::Status {
                status: arkret::RealmActorOperationStatus::Unknown,
            },
    } = &outcome.material
    else {
        return Err(invalid(
            "only an exact unknown outcome can close an unaccepted intent",
        ));
    };
    let (Some(fence), Some(after)) = (&current.control_stream_head, &outcome.control_stream_head)
    else {
        return Err(invalid(
            "unaccepted recovery requires both private cut heads",
        ));
    };
    if target_request_digest.as_str() != canonical_sha256(&request)?
        || after.stream_ref != fence.stream_ref
        || after.stream_position < fence.stream_position
        || (after.stream_position == fence.stream_position && after.commit_id != fence.commit_id)
        || outcome.governance_generation < current.governance_generation
    {
        return Err(invalid(
            "unknown outcome must follow the irreversible current fence",
        ));
    }
    let begin: arkret::RealmActorRecoveryBeginPayload =
        serde_json::from_value(serde_json::to_value(&prepared.begin.payload)?)?;
    let actor = &prepared.actor_id;
    let expected = [
        (
            CurrentSelector::RealmActorControl {
                actor_id: actor.clone(),
            },
            begin.expected_control_revision,
        ),
        (
            CurrentSelector::RealmActorManager {
                actor_id: actor.clone(),
            },
            CurrentRevision {
                commit_id: begin.manager_ref.commit_id,
                stream_position: begin.manager_ref.stream_position,
            },
        ),
        (
            CurrentSelector::RealmActorRecovery {
                actor_id: actor.clone(),
            },
            CurrentRevision {
                commit_id: begin.recovery_ref.commit_id,
                stream_position: begin.recovery_ref.stream_position,
            },
        ),
        (
            CurrentSelector::RealmActorDeviceGeneration {
                actor_id: actor.clone(),
            },
            begin.expected_device_generation_revision,
        ),
        (
            CurrentSelector::RealmActorStatus {
                actor_id: actor.clone(),
                gate: arkret::RealmActorStatusGate::Owner,
            },
            begin.expected_owner_status_revision,
        ),
        (
            CurrentSelector::RealmActorStatus {
                actor_id: actor.clone(),
                gate: arkret::RealmActorStatusGate::Governance,
            },
            begin.expected_governance_status_revision,
        ),
    ];
    let mut advanced = false;
    for (selector, before) in expected {
        let (revision, ..) = row(current, &selector)?;
        if revision.stream_position < before.stream_position
            || (revision.stream_position == before.stream_position
                && revision.commit_id != before.commit_id)
        {
            return Err(invalid(
                "current proof regresses or forks a required recovery revision",
            ));
        }
        advanced |= revision.stream_position > before.stream_position;
    }
    if !advanced {
        return Err(invalid(
            "unknown alone does not prove the original can no longer be accepted",
        ));
    }
    Ok(())
}
