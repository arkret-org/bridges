//! Durable recovery plans remain private until their begin Event is accepted.
use arkret::{
    CommittedEventRef, CurrentSelector, RealmActorDeviceGenerationValue, RealmActorManagerValue,
    RealmActorMaterialCurrentEntry, RealmActorMaterialOutcome, RealmActorMaterialResult,
    RealmActorRecoveryState, RealmActorRecoveryValue, TypedCurrentRow,
};

use super::*;

mod unaccepted;
use unaccepted::UnacceptedRecoveryProof;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedRecovery {
    pub(crate) operation_id: String,
    pub(crate) actor_id: ActorId,
    pub(crate) begin: AuthoredEvent,
    next_root_seed: String,
    controller_seed: String,
    pub(crate) publication: arkret::AppletManagedActorMethodHistoryEvidence,
    pub(crate) begin_receipt: Option<(RealmCommit, PublicKeyMaterial)>,
    pub(crate) reset: Option<AuthoredEvent>,
    pub(crate) reset_receipt: Option<(RealmCommit, PublicKeyMaterial)>,
    pub(crate) terminal: Option<RealmActorRecoveryState>,
    terminal_material: Option<RealmActorMaterialOutcome>,
    unaccepted_proof: Option<UnacceptedRecoveryProof>,
}

impl PreparedRecovery {
    pub(crate) fn closed_without_acceptance(&self) -> bool {
        self.unaccepted_proof.is_some()
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.terminal.is_some() || self.closed_without_acceptance()
    }
}

pub(crate) fn row<'a>(
    cut: &'a RealmActorMaterialOutcome,
    selector: &CurrentSelector,
) -> Result<(&'a CurrentRevision, &'a Value, &'a CommittedEventRef)> {
    let RealmActorMaterialResult::Current { entries } = &cut.result else {
        return Err(invalid("recovery requires a verified current cut"));
    };
    entries
        .iter()
        .find_map(|entry| match entry {
            RealmActorMaterialCurrentEntry::Present {
                row:
                    TypedCurrentRow::Value {
                        selector: found,
                        revision,
                        value,
                        ..
                    },
                source_ref,
            } if found == selector => Some((revision, value, source_ref)),
            _ => None,
        })
        .ok_or_else(|| invalid("required recovery current source is unavailable"))
}

impl ManagedActorAuthoringService {
    pub(crate) async fn retained_recovery(
        &self,
        actor: &ActorId,
        operation: &str,
    ) -> Result<Option<PreparedRecovery>> {
        let subject = self.custody_subject(actor).await?;
        let Some(raw) = self.control_raw(&subject).await? else {
            return Ok(None);
        };
        let custody: ControlCustody = self.decrypt_key_material(&key(&subject), &raw)?;
        if custody.actor_id != *actor {
            return Err(invalid("recovery custody belongs to another actor"));
        }
        Ok(custody.recoveries.get(operation).cloned())
    }

    pub(crate) async fn prepare_recovery(
        &self,
        actor: &ActorId,
        operation: &str,
        verified: &arkret::identity::VerifiedRealmActorMaterial,
        replaces: Option<&CommittedEventRef>,
    ) -> Result<PreparedRecovery> {
        if operation.is_empty() || operation.len() > 128 {
            return Err(invalid("recovery operation ID must be bounded"));
        }
        let cut = verified.material();
        if cut.actor_id != *actor
            || cut.requester_actor_id != ActorId::service(self.edge.service_actor_id().clone())
        {
            return Err(invalid("recovery cut belongs to another actor or Service"));
        }
        let subject = self.custody_subject(actor).await?;
        let before = self.control_raw(&subject).await?;
        let mut custody: ControlCustody = if let Some(raw) = &before {
            self.decrypt_key_material(&key(&subject), raw)?
        } else {
            let record = self
                .store
                .clone()
                .managed_actor_identity_async(subject.clone())
                .await?
                .ok_or_else(|| invalid("native recovery custody is missing"))?;
            let identity = self.decode_identity(&subject, record.clone())?;
            if identity.actor_id != *actor.signing_principal_id() {
                return Err(invalid("native recovery principal differs"));
            }
            let native: ManagedActorKeyMaterial =
                self.decrypt_key_material(&subject, &record.encrypted_key_material)?;
            let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
                identity.method_history_evidence
            else {
                return Err(invalid("native recovery requires retained WebVH history"));
            };
            ControlCustody {
                actor_id: actor.clone(),
                log_entries,
                next_root_seed: native.next_root_seed,
                controllers: BTreeMap::new(),
                operations: BTreeMap::new(),
                recoveries: BTreeMap::new(),
            }
        };
        if custody.actor_id != *actor {
            return Err(invalid("recovery actor differs"));
        }
        if let Some(retained) = custody.recoveries.get(operation) {
            return Ok(retained.clone());
        }
        if custody
            .operations
            .values()
            .any(|operation| operation.outcome.is_none())
            || custody.recoveries.values().any(|operation| {
                !operation.is_finished()
                    && replaces.is_none_or(|target| operation.begin.event_id() != &target.event_id)
            })
        {
            return Err(invalid(
                "resolve the outstanding native control operation before recovery",
            ));
        }
        let prepared = prepare(&custody, actor, operation, cut, &self.edge, replaces)?;
        custody
            .recoveries
            .insert(operation.to_owned(), prepared.clone());
        self.save_control(&subject, before, &custody).await?;
        Ok(prepared)
    }

    pub(crate) async fn accept_recovery_begin(
        &self,
        prepared: &PreparedRecovery,
        commit: &RealmCommit,
        station_key: &PublicKeyMaterial,
    ) -> Result<PreparedRecovery> {
        verify_receipt(&prepared.begin, commit, station_key)?;
        let subject = self.custody_subject(&prepared.actor_id).await?;
        let raw = self
            .control_raw(&subject)
            .await?
            .ok_or_else(|| invalid("recovery plan disappeared"))?;
        let mut custody: ControlCustody = self.decrypt_key_material(&key(&subject), &raw)?;
        let retained = custody
            .recoveries
            .get_mut(&prepared.operation_id)
            .ok_or_else(|| invalid("recovery plan disappeared"))?;
        if retained.begin != prepared.begin {
            return Err(invalid("recovery original changed"));
        }
        if let Some((prior, key)) = &retained.begin_receipt {
            if prior != commit || key != station_key {
                return Err(invalid("recovery acceptance fork"));
            }
            return Ok(retained.clone());
        }
        if retained.is_finished() {
            return Err(invalid("terminal recovery cannot be published"));
        }
        let begin: arkret::RealmActorRecoveryBeginPayload =
            serde_json::from_value(serde_json::to_value(&retained.begin.payload)?)?;
        let begin_ref = reference(commit);
        let revision = CurrentRevision {
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        };
        let reset = arkret::RealmActorControlResetPayload {
            target_actor_id: prepared.actor_id.clone(),
            recovery_begin_ref: begin_ref,
            expected_recovery_revision: revision.clone(),
            expected_manager_revision: CurrentRevision {
                commit_id: begin.manager_ref.commit_id.clone(),
                stream_position: begin.manager_ref.stream_position,
            },
            expected_control_revision: begin.expected_control_revision.clone(),
            expected_device_generation_revision: revision,
            published_method_history_evidence: retained.publication.clone(),
        };
        let at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
        let mut event = arkret_event_draft::TypedEventDraft::<
            arkret_wire::event_spec::RealmActorControlReset,
        >::new(
            prepared.begin.scope_ref.clone(),
            ActorId::service(self.edge.service_actor_id().clone()),
            reset,
        )?
        .with_applet_id(AppletId::new(self.edge.applet_id())?)
        .into_intent(at)?
        .author_with_digest_suite(crate::PRODUCER_DIGEST_SUITE)?;
        sign_event(
            &mut event,
            self.edge.signer(),
            SignEventOptions::new().with_created_at(at),
        )?;
        retained.begin_receipt = Some((commit.clone(), station_key.clone()));
        retained.reset = Some(event);
        let result = retained.clone();
        // Publication, successor update custody and the exact reset request
        // become visible together, only after the verified begin receipt.
        custody.log_entries = begin.method_history_evidence.log_entries;
        custody.next_root_seed = retained.next_root_seed.clone();
        custody.controllers.insert(
            begin.next_control_method_kid.to_string(),
            retained.controller_seed.clone(),
        );
        if let Some(replaces) = &begin.replaces_recovery_ref {
            for prior in custody.recoveries.values_mut() {
                if prior.begin.event_id() != &replaces.event_id {
                    continue;
                }
                if prior.is_finished()
                    || prior
                        .begin_receipt
                        .as_ref()
                        .is_some_and(|(commit, _)| reference(commit) != *replaces)
                {
                    return Err(invalid("replacement contradicts its prior recovery"));
                }
                // The verified replacement begin commits supersession atomically.
                // Its retained original and receipt are the proof for this state.
                prior.terminal = Some(RealmActorRecoveryState::Superseded);
            }
        }
        self.save_control(&subject, Some(raw), &custody).await?;
        Ok(result)
    }

    pub(crate) async fn record_recovery_terminal(
        &self,
        prepared: &PreparedRecovery,
        verified: &arkret::identity::VerifiedRealmActorMaterial,
    ) -> Result<()> {
        let material = verified.material();
        let request =
            arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
                arkret::EventAdmissionSubmission::new(prepared.begin.event().clone()),
            );
        let arkret::RealmActorMaterialResult::Outcome {
            target_request_digest,
            outcome:
                arkret::RealmActorOperationOutcome::Recovery {
                    begin_ref, state, ..
                },
        } = &material.result
        else {
            return Err(invalid(
                "terminal recovery requires the exact signed outcome",
            ));
        };
        if !matches!(
            state,
            RealmActorRecoveryState::Cancelled | RealmActorRecoveryState::Superseded
        ) || begin_ref.event_id != *prepared.begin.event_id()
            || material.actor_id != prepared.actor_id
            || material.requester_actor_id != ActorId::service(self.edge.service_actor_id().clone())
            || target_request_digest.as_str() != canonical_sha256(&request)?
        {
            return Err(invalid(
                "terminal recovery outcome differs from the retained operation",
            ));
        }
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
            || retained.reset_receipt.is_some()
            || retained.closed_without_acceptance()
            || retained.terminal.is_some_and(|prior| prior != *state)
        {
            return Err(invalid(
                "terminal recovery contradicts its durable original",
            ));
        }
        retained.terminal = Some(*state);
        retained.terminal_material = Some(material.clone());
        self.save_control(&subject, Some(raw), &custody).await
    }

    pub(crate) async fn accept_recovery_reset(
        &self,
        prepared: &PreparedRecovery,
        commit: &RealmCommit,
        station_key: &PublicKeyMaterial,
    ) -> Result<()> {
        let reset = prepared
            .reset
            .as_ref()
            .ok_or_else(|| invalid("recovery reset was never prepared"))?;
        verify_receipt(reset, commit, station_key)?;
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
        if retained.reset.as_ref() != Some(reset) || retained.begin_receipt.is_none() {
            return Err(invalid("reset differs from accepted begin"));
        }
        if let Some((prior, key)) = &retained.reset_receipt {
            if prior != commit || key != station_key {
                return Err(invalid("reset acceptance fork"));
            }
            return Ok(());
        }
        retained.reset_receipt = Some((commit.clone(), station_key.clone()));
        retained.terminal = Some(RealmActorRecoveryState::Completed);
        let begin: arkret::RealmActorRecoveryBeginPayload =
            serde_json::from_value(serde_json::to_value(&retained.begin.payload)?)?;
        custody
            .controllers
            .retain(|method, _| method == begin.next_control_method_kid.as_str());
        self.save_control(&subject, Some(raw), &custody).await
    }
}

fn reference(commit: &RealmCommit) -> CommittedEventRef {
    CommittedEventRef {
        event_id: commit.event_ref.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    }
}
fn verify_receipt(
    event: &AuthoredEvent,
    commit: &RealmCommit,
    key: &PublicKeyMaterial,
) -> Result<()> {
    commit.validate_content_address()?;
    if commit.event_ref != *event.event_id()
        || commit.stream_ref
            != (arkret::CommitStreamRef::RealmControl {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(invalid("recovery receipt differs from the frozen original"));
    }
    arkret::signatures::detached_object::verify_detached_object_signature(
        &commit.signature,
        &arkret::canonical::unsigned_value(commit, &["signature"])?,
        arkret::DetachedSignatureContext::RealmCommit,
        key,
    )
    .map_err(|e| invalid(e.to_string()))
}

fn prepare(
    custody: &ControlCustody,
    actor: &ActorId,
    operation: &str,
    cut: &RealmActorMaterialOutcome,
    edge: &crate::ArkretEdge,
    replaces: Option<&CommittedEventRef>,
) -> Result<PreparedRecovery> {
    let (_, identity, _) = row(
        cut,
        &CurrentSelector::RealmActorIdentity {
            actor_id: actor.clone(),
        },
    )?;
    if identity["applet_id"] != json!(edge.applet_id()) {
        return Err(invalid("recovery target belongs to another Applet"));
    }
    let (control_revision, control, _) = row(
        cut,
        &CurrentSelector::RealmActorControl {
            actor_id: actor.clone(),
        },
    )?;
    let control: RealmActorControlValue = serde_json::from_value(control.clone())?;
    let (_, manager, manager_ref) = row(
        cut,
        &CurrentSelector::RealmActorManager {
            actor_id: actor.clone(),
        },
    )?;
    let manager: RealmActorManagerValue = serde_json::from_value(manager.clone())?;
    let (_, recovery, recovery_ref) = row(
        cut,
        &CurrentSelector::RealmActorRecovery {
            actor_id: actor.clone(),
        },
    )?;
    let recovery: RealmActorRecoveryValue = serde_json::from_value(recovery.clone())?;
    let (owner_revision, owner, _) = row(
        cut,
        &CurrentSelector::RealmActorStatus {
            actor_id: actor.clone(),
            gate: arkret::RealmActorStatusGate::Owner,
        },
    )?;
    let (governance_revision, governance, _) = row(
        cut,
        &CurrentSelector::RealmActorStatus {
            actor_id: actor.clone(),
            gate: arkret::RealmActorStatusGate::Governance,
        },
    )?;
    let (generation_revision, generation, _) = row(
        cut,
        &CurrentSelector::RealmActorDeviceGeneration {
            actor_id: actor.clone(),
        },
    )?;
    let generation: RealmActorDeviceGenerationValue = serde_json::from_value(generation.clone())?;
    if manager.service_id != *edge.service_actor_id()
        || !recovery.enabled
        || recovery.pending.as_ref().map(|pending| &pending.begin_ref) != replaces
        || owner == "retired"
        || governance == "retired"
    {
        return Err(invalid(
            "recovery current manager, permission, pending intent or retirement prevents a new plan",
        ));
    }
    let at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
    let previous = custody
        .log_entries
        .last()
        .ok_or_else(|| invalid("native recovery history is empty"))?;
    let previous_at: chrono::DateTime<Utc> = previous["versionTime"]
        .as_str()
        .ok_or_else(|| invalid("native history timestamp missing"))?
        .parse()
        .map_err(|_| invalid("native history timestamp invalid"))?;
    if at.timestamp() <= previous_at.timestamp() {
        return Err(invalid(
            "wait until the next native log second before preparing recovery",
        ));
    }
    let mut controller = [0; 32];
    let mut next = [0; 32];
    getrandom::fill(&mut controller).map_err(|e| invalid(e.to_string()))?;
    getrandom::fill(&mut next).map_err(|e| invalid(e.to_string()))?;
    let signing = SigningKey::from_bytes(&controller);
    let did = &control.resolution.did;
    let public = arkret::ed25519_pubkey_to_did_key_multibase(signing.verifying_key().as_bytes());
    let method = DidUrl::new(format!("{did}#control-{public}")).map_err(invalid)?;
    let mut state = previous["state"].clone();
    state["verificationMethod"] =
        json!([{"id":method,"type":"Multikey","controller":did,"publicKeyMultibase":public}]);
    state["assertionMethod"] = json!([method]);
    state["authentication"] = json!([method]);
    let rotation = arkret::webvh::prepare_service_rotation(&arkret::webvh::ServiceRotationInput {
        did: did.as_str(),
        previous_entries: &custody.log_entries,
        state: &state,
        current_update_seed: &decode_managed_actor_seed("next_root_seed", &custody.next_root_seed)?,
        next_update_public_key_multibase: &arkret::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&next).verifying_key().as_bytes(),
        ),
        version_time: at,
    })
    .map_err(|e| invalid(e.to_string()))?;
    let mut entries = custody.log_entries.clone();
    entries.push(rotation.log_entry);
    let head = canonical_sha256(entries.last().expect("successor appended"))?;
    let resolution = ResolutionCommitment {
        did: did.clone(),
        method_history_head: head.clone(),
        version_id: rotation.version_id.clone(),
    };
    let applet = AppletId::new(edge.applet_id())?;
    let unsigned = arkret::RealmActorRecoveryAcceptanceTranscriptPayloadWithoutControlSignature {
        target_actor_id: actor.clone(),
        request_id: crate::realm_governance::nonce()?,
        manager_ref: manager_ref.clone(),
        recovery_ref: recovery_ref.clone(),
        expected_control_revision: control_revision.clone(),
        expected_owner_status_revision: owner_revision.clone(),
        expected_governance_status_revision: governance_revision.clone(),
        expected_device_generation_revision: generation_revision.clone(),
        expected_generation: generation.current_device_generation_ref,
        new_generation: generation
            .current_device_generation_ref
            .checked_add(1)
            .ok_or_else(|| invalid("device generation exhausted"))?,
        replaces_recovery_ref: replaces.cloned(),
        next_resolution: resolution,
        method_history_evidence: arkret::RealmActorWebvhRecoveryPlan {
            log_entries: entries.clone(),
            witness_records: vec![],
        },
        next_control_method_kid: method.clone(),
        expires_at: at + chrono::Duration::minutes(5),
    };
    let transcript = arkret::RealmActorRecoveryAcceptanceTranscript {
        applet_id: applet.clone(),
        service_id: edge.service_actor_id().clone(),
        payload_without_control_signature: unsigned,
    };
    let signature = arkret::signatures::detached_object::sign_detached_object(
        &transcript,
        arkret::DetachedSignatureContext::RealmActorRecoveryAcceptance,
        method,
        at,
        &signing,
    )
    .map_err(|e| invalid(e.to_string()))?;
    let mut value = serde_json::to_value(&transcript.payload_without_control_signature)?;
    value["control_signature"] = serde_json::to_value(signature)?;
    let payload: arkret::RealmActorRecoveryBeginPayload = serde_json::from_value(value)?;
    arkret::identity::verify_realm_actor_recovery_plan(
        &applet,
        edge.service_actor_id(),
        &control.resolution,
        &control.control_method_kid,
        &payload,
        at,
        at,
    )
    .map_err(|e| invalid(e.to_string()))?;
    let document: arkret::DidDocument = serde_json::from_value(state)?;
    let published = ResolutionMethodHistoryEvidence::WebvhLog {
        boundary: ResolutionMethodEvidenceBoundary {
            from_method_history_head: canonical_sha256(&entries[0])?,
            from_version_id: entries[0]["versionId"]
                .as_str()
                .ok_or_else(|| invalid("native inception version missing"))?
                .into(),
            to_method_history_head: head.clone(),
            to_version_id: rotation.version_id,
        },
        evidence: ResolutionDidBindingEvidenceReceipt {
            kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
            method: "webvh".into(),
            document_digest: arkret::identity::document_canonical_digest(&document)
                .map_err(|e| invalid(e.to_string()))?,
            method_proofs: vec![ResolutionDidBindingMethodProof {
                kind: arkret::ResolutionDidBindingMethodProofKind::WebvhLog,
                history_head: head,
                witnesses: vec![],
                witness_proofs_digest: Hash::new(canonical_sha256(&Vec::<Value>::new())?)?,
            }],
        },
        log_entries: entries,
        witness_records: vec![],
    };
    let publication = serde_json::from_value(serde_json::to_value(published)?)?;
    let realm = actor
        .as_realm_actor_id()
        .ok_or_else(|| invalid("recovery requires Realm actor"))?
        .realm_id
        .clone();
    let mut begin = arkret_event_draft::TypedEventDraft::<
        arkret_wire::event_spec::RealmActorRecoveryBegin,
    >::new(
        arkret::ScopeRef::RealmControl { realm_id: realm },
        ActorId::service(edge.service_actor_id().clone()),
        payload,
    )?
    .with_applet_id(applet)
    .into_intent(at)?
    .author_with_digest_suite(crate::PRODUCER_DIGEST_SUITE)?;
    sign_event(
        &mut begin,
        edge.signer(),
        SignEventOptions::new().with_created_at(at),
    )?;
    Ok(PreparedRecovery {
        operation_id: operation.to_owned(),
        actor_id: actor.clone(),
        begin,
        next_root_seed: arkret::base64url_encode(next),
        controller_seed: arkret::base64url_encode(controller),
        publication,
        begin_receipt: None,
        reset: None,
        reset_receipt: None,
        terminal: None,
        terminal_material: None,
        unaccepted_proof: None,
    })
}
