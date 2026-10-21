//! Local terminal evidence never invents an accepted or rejected protocol Event.
use arkret::{CurrentSelector, RealmActorMaterialOutcome, RealmActorMaterialResult};

use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ControlClosure {
    Unaccepted {
        advanced_current: RealmActorMaterialOutcome,
        subsequent_unknown: RealmActorMaterialOutcome,
    },
    Rejected {
        outcome: RealmActorMaterialOutcome,
    },
}

impl ManagedActorAuthoringService {
    pub(crate) async fn pending_control_rotations(
        &self,
        actor: &ActorId,
    ) -> Result<Vec<PreparedControlRotation>> {
        let subject = self.custody_subject(actor).await?;
        let Some(raw) = self.control_raw(&subject).await? else {
            return Ok(vec![]);
        };
        let custody: ControlCustody = self.decrypt_key_material(&key(&subject), &raw)?;
        if custody.actor_id != *actor {
            return Err(invalid("control custody belongs to another actor"));
        }
        Ok(custody
            .operations
            .into_values()
            .filter(|op| !op.is_finished())
            .collect())
    }

    pub(crate) async fn close_unaccepted_control(
        &self,
        prepared: &PreparedControlRotation,
        current: &arkret::identity::VerifiedRealmActorMaterial,
        outcome: &arkret::identity::VerifiedRealmActorMaterial,
    ) -> Result<()> {
        let current = current.material();
        let outcome = outcome.material();
        self.require_control_outcome(prepared, outcome)?;
        if current.actor_id != prepared.actor_id
            || current.requester_actor_id != outcome.requester_actor_id
            || !matches!(
                &outcome.result,
                RealmActorMaterialResult::Outcome {
                    outcome: arkret::RealmActorOperationOutcome::Status {
                        status: arkret::RealmActorOperationStatus::Unknown
                    },
                    ..
                }
            )
        {
            return Err(invalid(
                "unaccepted control requires the same subject and an exact unknown",
            ));
        }
        let selector = CurrentSelector::RealmActorControl {
            actor_id: prepared.actor_id.clone(),
        };
        let (revision, _, source) = recovery::row(current, &selector)?;
        let before = &prepared.previous_reference;
        let (Some(fence), Some(after)) =
            (&current.control_stream_head, &outcome.control_stream_head)
        else {
            return Err(invalid(
                "unaccepted control proof requires both private cut heads",
            ));
        };
        if revision.stream_position <= before.stream_position
            || source.stream_ref != before.stream_ref
            || fence.stream_ref != before.stream_ref
            || fence.stream_position < revision.stream_position
            || after.stream_ref != fence.stream_ref
            || after.stream_position < fence.stream_position
            || (after.stream_position == fence.stream_position
                && after.commit_id != fence.commit_id)
            || outcome.governance_generation < current.governance_generation
        {
            return Err(invalid(
                "unknown requires an irreversible control CAS fence and a subsequent cut",
            ));
        }
        self.save_control_closure(
            prepared,
            ControlClosure::Unaccepted {
                advanced_current: current.clone(),
                subsequent_unknown: outcome.clone(),
            },
        )
        .await
    }

    pub(crate) async fn record_control_rejection(
        &self,
        prepared: &PreparedControlRotation,
        outcome: &arkret::identity::VerifiedRealmActorMaterial,
    ) -> Result<()> {
        let outcome = outcome.material();
        self.require_control_outcome(prepared, outcome)?;
        if !matches!(
            &outcome.result,
            RealmActorMaterialResult::Outcome {
                outcome: arkret::RealmActorOperationOutcome::Submitted(
                    arkret::AuthoritySubmitOutcome::Rejected { .. }
                ),
                ..
            }
        ) {
            return Err(invalid(
                "control rejection requires its exact signed ledger outcome",
            ));
        }
        self.save_control_closure(
            prepared,
            ControlClosure::Rejected {
                outcome: outcome.clone(),
            },
        )
        .await
    }

    fn require_control_outcome(
        &self,
        prepared: &PreparedControlRotation,
        outcome: &RealmActorMaterialOutcome,
    ) -> Result<()> {
        let request =
            arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
                arkret::EventAdmissionSubmission::new(prepared.event.event().clone()),
            );
        if prepared.outcome.is_some()
            || outcome.actor_id != prepared.actor_id
            || outcome.requester_actor_id != ActorId::service(self.edge.service_actor_id().clone())
            || !matches!(&outcome.result, RealmActorMaterialResult::Outcome { target_request_digest, .. }
                if target_request_digest.as_str() == canonical_sha256(&request)?)
        {
            return Err(invalid(
                "control closure differs from the retained original or requester",
            ));
        }
        Ok(())
    }

    async fn save_control_closure(
        &self,
        prepared: &PreparedControlRotation,
        proof: ControlClosure,
    ) -> Result<()> {
        let subject = self.custody_subject(&prepared.actor_id).await?;
        let raw = self
            .control_raw(&subject)
            .await?
            .ok_or_else(|| invalid("control intent disappeared"))?;
        let mut custody: ControlCustody = self.decrypt_key_material(&key(&subject), &raw)?;
        if custody.actor_id != prepared.actor_id {
            return Err(invalid("control custody belongs to another actor"));
        }
        let retained = custody
            .operations
            .get_mut(&prepared.operation_id)
            .ok_or_else(|| invalid("control intent disappeared"))?;
        if retained.event != prepared.event || retained.outcome.is_some() {
            return Err(invalid(
                "accepted or replaced control cannot close as unaccepted",
            ));
        }
        if retained.is_closed() {
            return Ok(());
        }
        retained.closure = Some(proof);
        self.save_control(&subject, Some(raw), &custody).await
    }
}
