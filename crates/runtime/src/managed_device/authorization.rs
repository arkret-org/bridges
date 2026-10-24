//! Recover an already accepted authorization before considering a new write.
use super::*;

impl ManagedDeviceRuntime {
    pub(super) async fn recover_authorization_outcome(
        &self,
        storage_key: &str,
        previous: &mut String,
        record: &mut DeviceRecord,
    ) -> Result<()> {
        let actor = &record.plan.actor_id;
        let request = SelfAuthoritySubmitRequestBody::Event(EventAdmissionSubmission::new(
            record.authorization.event().clone(),
        ));
        let digest = arkret::Hash::new(canonical_sha256(&request)?)?;
        let route = self
            .edge
            .realm_route(record.authorization.scope_ref.realm_id())
            .await?;
        let requester = ActorId::service(self.edge.service_actor_id().clone());
        let verified = route
            .material(
                &arkret::RealmActorMaterialRequestBody::RequestStatus {
                    actor_id: actor.clone(),
                    request_nonce: crate::realm_governance::nonce()?,
                    target_request_digest: digest.clone(),
                },
                &requester,
            )
            .await?;
        let arkret::RealmActorMaterial::RequestStatus {
            target_request_digest,
            request_status: outcome,
        } = &verified.material().material
        else {
            return Err(invalid("Device recovery returned another material purpose"));
        };
        if target_request_digest != &digest {
            return Err(invalid("Device recovery returned another request identity"));
        }
        let outcome = match outcome {
            arkret::RealmActorRequestStatus::Submitted(outcome) => outcome.clone(),
            arkret::RealmActorRequestStatus::Status {
                status: arkret::RealmActorOperationStatus::Unknown,
            } => return Ok(()),
            _ => {
                return Err(invalid(
                    "Device authorization has an unexpected registered outcome",
                ));
            }
        };
        let AuthoritySubmitResponseBody::Accepted { commit, .. } = &outcome else {
            // A refusal must not erase an original or be interpreted as a
            // successful authorization. Unknown retains the same retry unit.
            return Err(invalid("Device authorization is not accepted"));
        };
        let original = route
            .material(
                &arkret::RealmActorMaterialRequestBody::Event {
                    actor_id: actor.clone(),
                    request_nonce: crate::realm_governance::nonce()?,
                    target: arkret::CommittedEventRef {
                        event_id: record.authorization.event_id().clone(),
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
            commit: original_commit,
            ..
        } = &original.material().material
        else {
            return Err(invalid("Device recovery has no accepted original"));
        };
        if event != record.authorization.event() || original_commit != commit {
            return Err(invalid(
                "Device recovery differs from the frozen authorization",
            ));
        }
        let issuer = route
            .authority
            .authority_service_at(commit.governance_generation)
            .ok_or_else(|| invalid("Device recovery has no legal governance tenure"))?;
        let station_key = route
            .historical_station_key(
                issuer,
                &commit.signature.verification_method,
                commit.committed_at,
            )
            .await?;
        self.verify_commit(record, commit, &station_key)?;
        record.outcome = Some(outcome);
        record.accepted_station_key = Some(station_key);
        let encrypted = self.authoring.encrypt_key_material(storage_key, record)?;
        if self
            .cas(storage_key, Some(previous.clone()), encrypted.clone())
            .await?
        {
            *previous = encrypted;
            return Ok(());
        }
        let raw = self
            .read(storage_key)
            .await?
            .ok_or_else(|| invalid("Device authorization vanished during recovery"))?;
        let winner = self.decode(storage_key, &raw, &record.plan).await?;
        match (&record.outcome, &winner.outcome) {
            (
                Some(AuthoritySubmitResponseBody::Accepted {
                    commit: expected, ..
                }),
                Some(AuthoritySubmitResponseBody::Accepted { commit: actual, .. }),
            ) if expected == actual => {
                *record = winner;
                *previous = raw;
                Ok(())
            }
            _ => Err(invalid(
                "Device authorization recovery contended; retry the original",
            )),
        }
    }
}
