//! Local custody coordination for the existing manager-change protocol.
//! Service replacement requires retained Applet data and keys before public coordination.
use arkret::{CommittedEventFullView, CommittedEventRef, RealmActorMaterial};

use super::*;

/// Explicit operator intent. This is local orchestration, not a protocol endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementTransferPlan {
    pub operation_id: String,
    pub actor_id: ActorId,
    pub new_service_id: DidCoreId,
    pub new_registration_ref: arkret::EventId,
    pub management_authorization_ref: arkret::GrantId,
}

/// Public operational key offer; this is not a new network wire contract.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementTransferOffer {
    pub(crate) plan: ManagementTransferPlan,
    did: Did,
    method: DidUrl,
    controller_public: String,
    update_public: String,
    next_update_public: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Incoming {
    offer: ManagementTransferOffer,
    controller_seed: String,
    update_seed: String,
    next_update_seed: String,
    acceptance: Option<(
        arkret::RealmActorControlAcceptanceTranscript,
        arkret::DetachedObjectSignature,
    )>,
    log_entries: Option<Vec<Value>>,
    creation: Option<CommittedEventFullView>,
    manager_event: Option<AuthoredEvent>,
    control_ref: Option<CommittedEventRef>,
    receipt: Option<CommittedEventFullView>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Outgoing {
    offer: ManagementTransferOffer,
    subject: String,
    previous_control: RealmActorControlValue,
    previous_reference: CommittedEventRef,
    previous_raw: Option<String>,
    next_root_seed: String,
    transcript: arkret::RealmActorControlAcceptanceTranscript,
    frozen: bool,
    release: Option<Vec<Value>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferredOrigin {
    pub(super) subject: String,
    service_id: DidCoreId,
    creation: CommittedEventFullView,
    manager: CommittedEventFullView,
}

fn transfer_key(plan: &ManagementTransferPlan, side: &str) -> Result<String> {
    if plan.operation_id.is_empty()
        || plan.operation_id.len() > 128
        || plan.actor_id.as_realm_actor_id().is_none()
    {
        return Err(invalid(
            "management transfer requires a Realm actor and bounded operation ID",
        ));
    }
    Ok(format!(
        "managed-manager-transfer/v1/{side}/{}",
        canonical_sha256(&(&plan.actor_id, &plan.operation_id))?
    ))
}
fn origin_key(actor: &ActorId) -> Result<String> {
    Ok(format!(
        "managed-manager-origin/v1/{}",
        canonical_sha256(actor)?
    ))
}
fn public(seed: &[u8; 32]) -> String {
    arkret::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(seed).verifying_key().as_bytes(),
    )
}
fn random_seed() -> Result<[u8; 32]> {
    let mut seed = [0; 32];
    getrandom::fill(&mut seed).map_err(|e| invalid(e.to_string()))?;
    Ok(seed)
}

pub(crate) fn continuous_publication(
    previous: Option<(arkret::DidDocument, Vec<Value>)>,
    next: (arkret::DidDocument, Vec<Value>),
) -> Result<(arkret::DidDocument, Vec<Value>)> {
    let Some(previous) = previous else {
        return Ok(next);
    };
    let common = previous.1.len().min(next.1.len());
    if previous.1[..common] != next.1[..common] {
        return Err(invalid(
            "native publication contains conflicting retained branches",
        ));
    }
    Ok(if next.1.len() > previous.1.len() {
        next
    } else {
        previous
    })
}
pub(crate) fn revision(reference: &CommittedEventRef) -> CurrentRevision {
    CurrentRevision {
        commit_id: reference.commit_id.clone(),
        stream_position: reference.stream_position,
    }
}
pub(crate) fn reference(commit: &RealmCommit) -> CommittedEventRef {
    CommittedEventRef {
        event_id: commit.event_ref.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    }
}

pub(crate) async fn next_native_time(entries: &[Value]) -> Result<chrono::DateTime<Utc>> {
    let previous: chrono::DateTime<Utc> = entries
        .last()
        .and_then(|e| e["versionTime"].as_str())
        .ok_or_else(|| invalid("native transfer history time missing"))?
        .parse()
        .map_err(|_| invalid("native transfer history time invalid"))?;
    let wait = previous.timestamp() + 1 - Utc::now().timestamp();
    if wait > 2 {
        return Err(invalid("local clock precedes native transfer history"));
    }
    if wait > 0 {
        tokio::time::sleep(std::time::Duration::from_secs(wait as u64)).await;
    }
    Ok(arkret::canonical::normalize_timestamp_canonical(Utc::now()))
}

fn native_material(
    did: &Did,
    entries: &[Value],
) -> Result<(
    ResolutionCommitment,
    arkret::AppletManagedActorMethodHistoryEvidence,
)> {
    let first = entries
        .first()
        .ok_or_else(|| invalid("empty native transfer history"))?;
    let last = entries.last().expect("nonempty history");
    let version = |entry: &Value| -> Result<String> {
        Ok(entry["versionId"]
            .as_str()
            .ok_or_else(|| invalid("native transfer version missing"))?
            .to_owned())
    };
    let head = canonical_sha256(last)?;
    let document: arkret::DidDocument = serde_json::from_value(last["state"].clone())?;
    let witnesses = Vec::<Value>::new();
    let evidence = ResolutionMethodHistoryEvidence::WebvhLog {
        boundary: ResolutionMethodEvidenceBoundary {
            from_method_history_head: canonical_sha256(first)?,
            from_version_id: version(first)?,
            to_method_history_head: head.clone(),
            to_version_id: version(last)?,
        },
        evidence: ResolutionDidBindingEvidenceReceipt {
            kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
            method: "webvh".into(),
            document_digest: arkret::identity::document_canonical_digest(&document)
                .map_err(|e| invalid(e.to_string()))?,
            method_proofs: vec![ResolutionDidBindingMethodProof {
                kind: arkret::ResolutionDidBindingMethodProofKind::WebvhLog,
                history_head: head.clone(),
                witnesses: vec![],
                witness_proofs_digest: Hash::new(canonical_sha256(&witnesses)?)?,
            }],
        },
        log_entries: entries.to_vec(),
        witness_records: witnesses,
    };
    Ok((
        ResolutionCommitment {
            did: did.clone(),
            method_history_head: head,
            version_id: version(last)?,
        },
        serde_json::from_value(serde_json::to_value(evidence)?)?,
    ))
}

impl ManagedActorAuthoringService {
    async fn transfer_load<T: for<'de> Deserialize<'de>>(
        &self,
        key: &str,
    ) -> Result<Option<(String, T)>> {
        let store = self.edge.authoring_store();
        let owned = key.to_owned();
        let Some(raw) = crate::run_blocking(move || store.load(&owned)).await? else {
            return Ok(None);
        };
        let value = self.decrypt_key_material(key, &raw)?;
        Ok(Some((raw, value)))
    }
    async fn transfer_save<T: Serialize>(
        &self,
        key: &str,
        before: Option<String>,
        value: &T,
    ) -> Result<()> {
        let store = self.edge.authoring_store();
        let encrypted = self.encrypt_key_material(key, value)?;
        let key = key.to_owned();
        if !crate::run_blocking(move || {
            store.compare_exchange_batch(&[(key.clone(), before)], &[(key, Some(encrypted))])
        })
        .await?
        {
            return Err(invalid(
                "management transfer changed concurrently; retry the same intent",
            ));
        }
        Ok(())
    }

    pub(crate) async fn transferred_origin(
        &self,
        actor: &ActorId,
    ) -> Result<Option<TransferredOrigin>> {
        let Some((_, origin)) = self
            .transfer_load::<TransferredOrigin>(&origin_key(actor)?)
            .await?
        else {
            return Ok(None);
        };
        let creation = crate::managed_authoring::creation_payload(&origin.creation.event)?;
        let payload: arkret::RealmActorManagerChangePayload =
            serde_json::from_value(serde_json::to_value(&origin.manager.event.payload)?)?;
        if creation.actor_id != *actor
            || creation.applet_id.as_str() != self.edge.applet_id()
            || origin.manager.event.actor_id != *actor
            || payload.new_service_id != origin.service_id
            || origin.manager.commit.event_ref != origin.manager.event.event_id
        {
            return Err(invalid(
                "transferred origin differs from accepted actor or local Service",
            ));
        }
        Ok(Some(origin))
    }
    pub(crate) async fn managed_creation(&self, actor: &ActorId) -> Result<CommittedEventFullView> {
        if let Some(origin) = self.transferred_origin(actor).await? {
            return Ok(origin.creation);
        }
        let edge = self.edge.clone();
        let actor = actor.clone();
        crate::run_blocking(move || edge.retained_actor_creation(&actor)).await
    }
    pub(crate) async fn managed_actor_ids(&self) -> Result<Vec<ActorId>> {
        let edge = self.edge.clone();
        let candidates = crate::run_blocking(move || edge.managed_actor_ids()).await?;
        let mut actors = Vec::new();
        for actor in candidates {
            let local = if let Some(origin) = self.transferred_origin(&actor).await? {
                origin.service_id == *self.edge.service_actor_id()
            } else {
                crate::managed_authoring::creation_payload(
                    &self.managed_creation(&actor).await?.event,
                )?
                .service_id
                    == *self.edge.service_actor_id()
            };
            if local {
                actors.push(actor);
            }
        }
        actors.sort();
        actors.dedup();
        Ok(actors)
    }

    pub(crate) async fn prepare_manager_offer(
        &self,
        plan: &ManagementTransferPlan,
        did: &Did,
    ) -> Result<ManagementTransferOffer> {
        // The receiver must retain the accepted original and decrypt the original
        // native/controller custody. A public-record-only handover is out of scope.
        let original = self.original_managed_controller(&plan.actor_id).await?;
        let candidate = crate::managed_authoring::creation_payload(&original.original.event)?;
        if candidate.applet_id.as_str() != self.edge.applet_id() {
            return Err(invalid("Service replacement cannot change Applet identity"));
        }
        let key = transfer_key(plan, "incoming")?;
        if plan.new_service_id != *self.edge.service_actor_id()
            || project_did_to_core_id(did)? != *plan.actor_id.signing_principal_id()
        {
            return Err(invalid(
                "management offer targets another Service or principal",
            ));
        }
        if let Some((_, incoming)) = self.transfer_load::<Incoming>(&key).await? {
            if incoming.offer.plan != *plan || incoming.offer.did != *did {
                return Err(invalid("management operation already binds another intent"));
            }
            return Ok(incoming.offer);
        }
        let controller = random_seed()?;
        let update = random_seed()?;
        let next = random_seed()?;
        let offer = ManagementTransferOffer {
            plan: plan.clone(),
            did: did.clone(),
            method: DidUrl::new(format!("{did}#control-{}", public(&controller)))
                .map_err(invalid)?,
            controller_public: public(&controller),
            update_public: public(&update),
            next_update_public: public(&next),
        };
        self.transfer_save(
            &key,
            None,
            &Incoming {
                offer: offer.clone(),
                controller_seed: arkret::base64url_encode(controller),
                update_seed: arkret::base64url_encode(update),
                next_update_seed: arkret::base64url_encode(next),
                acceptance: None,
                log_entries: None,
                creation: None,
                manager_event: None,
                control_ref: None,
                receipt: None,
            },
        )
        .await?;
        Ok(offer)
    }

    async fn incoming(&self, plan: &ManagementTransferPlan) -> Result<(String, Incoming)> {
        let result = self
            .transfer_load::<Incoming>(&transfer_key(plan, "incoming")?)
            .await?
            .ok_or_else(|| invalid("management receiving custody missing"))?;
        if result.1.offer.plan != *plan || plan.new_service_id != *self.edge.service_actor_id() {
            return Err(invalid("management receiving intent mismatch"));
        }
        Ok(result)
    }
    async fn outgoing(&self, plan: &ManagementTransferPlan) -> Result<(String, Outgoing)> {
        let result = self
            .transfer_load::<Outgoing>(&transfer_key(plan, "outgoing")?)
            .await?
            .ok_or_else(|| invalid("management releasing custody missing"))?;
        if result.1.offer.plan != *plan {
            return Err(invalid("management releasing intent mismatch"));
        }
        Ok(result)
    }

    pub(crate) async fn prepare_manager_control(
        &self,
        offer: &ManagementTransferOffer,
        current: &RealmActorControlValue,
        reference: &CommittedEventRef,
    ) -> Result<arkret::RealmActorControlAcceptanceTranscript> {
        let plan = &offer.plan;
        let storage_key = transfer_key(plan, "outgoing")?;
        if let Some((_, saved)) = self.transfer_load::<Outgoing>(&storage_key).await? {
            if saved.offer != *offer {
                return Err(invalid("outgoing transfer offer changed"));
            }
            return Ok(saved.transcript);
        }
        if offer.did != current.resolution.did
            || plan.new_service_id == *self.edge.service_actor_id()
        {
            return Err(invalid(
                "manager transfer must preserve DID and change Service",
            ));
        }
        let subject = self.custody_subject(&plan.actor_id).await?;
        let before = self.control_raw(&subject).await?;
        let custody = self
            .load_control_custody(&plan.actor_id, &subject, before.as_deref())
            .await?;
        if custody.operations.values().any(|op| !op.is_finished())
            || custody.recoveries.values().any(|op| !op.is_finished())
        {
            return Err(invalid(
                "finish outstanding control operations before manager transfer",
            ));
        }
        let at = next_native_time(&custody.log_entries).await?;
        let mut entries = custody.log_entries.clone();
        let mut state = entries
            .last()
            .ok_or_else(|| invalid("native history missing"))?["state"]
            .clone();
        state["verificationMethod"].as_array_mut().ok_or_else(|| invalid("native methods missing"))?.push(
            json!({"id":offer.method,"type":"Multikey","controller":offer.did,"publicKeyMultibase":offer.controller_public}));
        for relation in ["assertionMethod", "authentication"] {
            state[relation]
                .as_array_mut()
                .ok_or_else(|| invalid("native relationship missing"))?
                .push(json!(offer.method));
        }
        let next = random_seed()?;
        let rotation =
            arkret::webvh::prepare_service_rotation(&arkret::webvh::ServiceRotationInput {
                did: offer.did.as_str(),
                previous_entries: &entries,
                state: &state,
                current_update_seed: &decode_managed_actor_seed(
                    "native transfer key",
                    &custody.next_root_seed,
                )?,
                next_update_public_key_multibase: &public(&next),
                version_time: at,
            })
            .map_err(|e| invalid(e.to_string()))?;
        entries.push(rotation.log_entry);
        let (next_resolution, method_history_evidence) = native_material(&offer.did, &entries)?;
        let transcript = arkret::RealmActorControlAcceptanceTranscript {
            actor_id: plan.actor_id.clone(),
            expected_revision: revision(reference),
            next_resolution,
            method_history_evidence,
            next_control_method_kid: offer.method.clone(),
        };
        self.transfer_save(
            &storage_key,
            None,
            &Outgoing {
                offer: offer.clone(),
                subject,
                previous_control: current.clone(),
                previous_reference: reference.clone(),
                previous_raw: before,
                next_root_seed: arkret::base64url_encode(next),
                transcript: transcript.clone(),
                frozen: false,
                release: None,
            },
        )
        .await?;
        Ok(transcript)
    }

    async fn load_control_custody(
        &self,
        actor: &ActorId,
        subject: &str,
        raw: Option<&str>,
    ) -> Result<ControlCustody> {
        if let Some(raw) = raw {
            return self.decrypt_key_material(&key(subject), raw);
        }
        let record = self
            .store
            .clone()
            .managed_actor_identity_async(subject.to_owned())
            .await?
            .ok_or_else(|| invalid("native control inception missing"))?;
        let identity = self.decode_identity(subject, record.clone())?;
        let material: ManagedActorKeyMaterial =
            self.decrypt_key_material(subject, &record.encrypted_key_material)?;
        let controller = self.original_managed_controller(actor).await?;
        let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
            identity.method_history_evidence
        else {
            return Err(invalid("native manager transfer requires WebVH custody"));
        };
        Ok(ControlCustody {
            actor_id: actor.clone(),
            log_entries,
            next_root_seed: material.next_root_seed,
            controllers: BTreeMap::from([(
                controller.signer.verification_method().to_owned(),
                arkret::base64url_encode(controller.signing_key.to_bytes()),
            )]),
            operations: BTreeMap::new(),
            recoveries: BTreeMap::new(),
        })
    }

    pub(crate) async fn sign_manager_control(
        &self,
        plan: &ManagementTransferPlan,
        transcript: &arkret::RealmActorControlAcceptanceTranscript,
    ) -> Result<arkret::DetachedObjectSignature> {
        let (raw, mut incoming) = self.incoming(plan).await?;
        if let Some((original, signature)) = incoming.acceptance {
            if original != *transcript {
                return Err(invalid(
                    "receiving control acceptance already signed another original",
                ));
            }
            return Ok(signature);
        }
        if transcript.actor_id != plan.actor_id
            || transcript.next_resolution.did != incoming.offer.did
            || transcript.next_control_method_kid != incoming.offer.method
        {
            return Err(invalid("control acceptance differs from receiving offer"));
        }
        let (_, entries, _) = transcript.method_history_evidence.webvh_material();
        let at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
        let document = arkret::identity::verify_realm_actor_native_history(
            &plan.actor_id,
            &transcript.next_resolution,
            entries,
            &incoming.offer.method,
            at,
        )
        .map_err(|e| invalid(e.to_string()))?;
        let signing = SigningKey::from_bytes(&decode_managed_actor_seed(
            "receiving controller",
            &incoming.controller_seed,
        )?);
        if arkret::identity::public_key_material_from_document(&document, &incoming.offer.method)
            .map_err(|e| invalid(e.to_string()))?
            != (PublicKeyMaterial::Ed25519Raw {
                bytes: signing.verifying_key().to_bytes().to_vec(),
            })
        {
            return Err(invalid(
                "native offer does not contain receiving controller",
            ));
        }
        let signature = arkret::signatures::detached_object::sign_detached_object(
            transcript,
            arkret::DetachedSignatureContext::RealmActorControlAcceptance,
            incoming.offer.method.clone(),
            at,
            &signing,
        )
        .map_err(|e| invalid(e.to_string()))?;
        incoming.acceptance = Some((transcript.clone(), signature.clone()));
        self.transfer_save(&transfer_key(plan, "incoming")?, Some(raw), &incoming)
            .await?;
        Ok(signature)
    }

    pub(crate) async fn freeze_manager_control(
        &self,
        plan: &ManagementTransferPlan,
        signature: &arkret::DetachedObjectSignature,
    ) -> Result<String> {
        let operation = format!(
            "manager:{}",
            canonical_sha256(&(&plan.actor_id, &plan.operation_id))?
        );
        let (out_raw, mut outgoing) = self.outgoing(plan).await?;
        if outgoing.frozen {
            return Ok(operation);
        }
        let before = self.control_raw(&outgoing.subject).await?;
        if before != outgoing.previous_raw {
            return Err(invalid(
                "native custody changed while preparing manager transfer",
            ));
        }
        let mut custody = self
            .load_control_custody(&plan.actor_id, &outgoing.subject, before.as_deref())
            .await?;
        let transcript = &outgoing.transcript;
        let payload = arkret::RealmActorControlUpdatePayload {
            expected_revision: transcript.expected_revision.clone(),
            next_resolution: transcript.next_resolution.clone(),
            method_history_evidence: transcript.method_history_evidence.clone(),
            next_control_method_kid: transcript.next_control_method_kid.clone(),
            next_method_signature: signature.clone(),
        };
        let at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
        arkret::identity::verify_realm_actor_control_successor(
            &plan.actor_id,
            &outgoing.previous_control.resolution,
            &outgoing.previous_control.control_method_kid,
            &payload,
            at,
        )
        .map_err(|e| invalid(e.to_string()))?;
        let controller = self
            .managed_controller(
                &plan.actor_id,
                &outgoing.previous_control.control_method_kid,
            )
            .await?;
        let mut event = arkret_event_draft::TypedEventDraft::<
            arkret_wire::event_spec::RealmActorControlUpdate,
        >::new(
            arkret::ScopeRef::RealmControl {
                realm_id: plan
                    .actor_id
                    .as_realm_actor_id()
                    .expect("validated actor")
                    .realm_id
                    .clone(),
            },
            plan.actor_id.clone(),
            payload,
        )?
        .with_applet_id(AppletId::new(self.edge.applet_id())?)
        .into_intent(at)?
        .author_with_digest_suite(crate::PRODUCER_DIGEST_SUITE)?;
        sign_event(
            &mut event,
            &controller.signer,
            SignEventOptions::new().with_created_at(at),
        )?;
        custody.operations.insert(
            operation.clone(),
            PreparedControlRotation {
                operation_id: operation.clone(),
                actor_id: plan.actor_id.clone(),
                previous_control: outgoing.previous_control.clone(),
                previous_reference: outgoing.previous_reference.clone(),
                event,
                outcome: None,
                closure: None,
            },
        );
        custody.log_entries = transcript
            .method_history_evidence
            .webvh_material()
            .1
            .to_vec();
        custody.next_root_seed = outgoing.next_root_seed.clone();
        outgoing.frozen = true;
        let control_key = key(&outgoing.subject);
        let out_key = transfer_key(plan, "outgoing")?;
        let writes = vec![
            (
                control_key.clone(),
                Some(self.encrypt_key_material(&control_key, &custody)?),
            ),
            (
                out_key.clone(),
                Some(self.encrypt_key_material(&out_key, &outgoing)?),
            ),
        ];
        let store = self.edge.authoring_store();
        if !crate::run_blocking(move || {
            store
                .compare_exchange_batch(&[(control_key, before), (out_key, Some(out_raw))], &writes)
        })
        .await?
        {
            return Err(invalid("manager control publication changed concurrently"));
        }
        Ok(operation)
    }

    pub(crate) async fn release_manager_native(
        &self,
        plan: &ManagementTransferPlan,
        accepted: &RealmCommit,
    ) -> Result<Vec<Value>> {
        let (out_raw, mut outgoing) = self.outgoing(plan).await?;
        if let Some(entries) = outgoing.release {
            return Ok(entries);
        }
        let before = self
            .control_raw(&outgoing.subject)
            .await?
            .ok_or_else(|| invalid("manager control custody missing"))?;
        let mut custody: ControlCustody =
            self.decrypt_key_material(&key(&outgoing.subject), &before)?;
        if !custody.operations.values().any(|op| {
            op.event.event_id() == &accepted.event_ref
                && op.outcome.as_ref().is_some_and(|(c, _)| c == accepted)
        }) {
            return Err(invalid(
                "native release requires the accepted receiving control original",
            ));
        }
        if custody.log_entries
            != outgoing
                .transcript
                .method_history_evidence
                .webvh_material()
                .1
        {
            return Err(invalid("native custody advanced before management release"));
        }
        let at = next_native_time(&custody.log_entries).await?;
        let mut state =
            custody.log_entries.last().expect("accepted native history")["state"].clone();
        state["verificationMethod"]
            .as_array_mut()
            .ok_or_else(|| invalid("native methods missing"))?
            .retain(|method| method["id"] == json!(outgoing.offer.method));
        state["assertionMethod"] = json!([outgoing.offer.method]);
        state["authentication"] = json!([outgoing.offer.method]);
        let rotation =
            arkret::webvh::prepare_service_rotation(&arkret::webvh::ServiceRotationInput {
                did: outgoing.offer.did.as_str(),
                previous_entries: &custody.log_entries,
                state: &state,
                current_update_seed: &decode_managed_actor_seed(
                    "releasing update key",
                    &custody.next_root_seed,
                )?,
                next_update_public_key_multibase: &outgoing.offer.update_public,
                version_time: at,
            })
            .map_err(|e| invalid(e.to_string()))?;
        custody.log_entries.push(rotation.log_entry);
        // No longer possess the next native key. Never retain a placeholder key
        // capable of silently returning this identity to the old manager.
        custody.next_root_seed.clear();
        outgoing.release = Some(custody.log_entries.clone());
        let out_key = transfer_key(plan, "outgoing")?;
        let control_key = key(&outgoing.subject);
        let writes = vec![
            (
                out_key.clone(),
                Some(self.encrypt_key_material(&out_key, &outgoing)?),
            ),
            (
                control_key.clone(),
                Some(self.encrypt_key_material(&control_key, &custody)?),
            ),
        ];
        let store = self.edge.authoring_store();
        if !crate::run_blocking(move || {
            store.compare_exchange_batch(
                &[(out_key, Some(out_raw)), (control_key, Some(before))],
                &writes,
            )
        })
        .await?
        {
            return Err(invalid("native release changed concurrently"));
        }
        Ok(custody.log_entries)
    }

    pub(crate) async fn receive_manager_native(
        &self,
        plan: &ManagementTransferPlan,
        release: &[Value],
    ) -> Result<()> {
        let (raw, mut incoming) = self.incoming(plan).await?;
        if let Some(entries) = &incoming.log_entries {
            if entries.len() != release.len() + 1 || entries[..release.len()] != *release {
                return Err(invalid("native release original changed"));
            }
            return Ok(());
        }
        let (acceptance, _) = incoming
            .acceptance
            .as_ref()
            .ok_or_else(|| invalid("receiving control acceptance missing"))?;
        let original = acceptance.method_history_evidence.webvh_material().1;
        if release.len() != original.len() + 1 || release[..original.len()] != *original {
            return Err(invalid(
                "native release does not extend the exact accepted control offer",
            ));
        }
        let at = next_native_time(release).await?;
        let rotation =
            arkret::webvh::prepare_service_rotation(&arkret::webvh::ServiceRotationInput {
                did: incoming.offer.did.as_str(),
                previous_entries: release,
                state: &release.last().expect("validated release")["state"],
                current_update_seed: &decode_managed_actor_seed(
                    "receiving update key",
                    &incoming.update_seed,
                )?,
                next_update_public_key_multibase: &incoming.offer.next_update_public,
                version_time: at,
            })
            .map_err(|e| invalid(e.to_string()))?;
        let mut entries = release.to_vec();
        entries.push(rotation.log_entry);
        let (resolution, _) = native_material(&incoming.offer.did, &entries)?;
        arkret::identity::verify_realm_actor_native_history(
            &plan.actor_id,
            &resolution,
            &entries,
            &incoming.offer.method,
            at,
        )
        .map_err(|e| invalid(e.to_string()))?;
        incoming.log_entries = Some(entries);
        self.transfer_save(&transfer_key(plan, "incoming")?, Some(raw), &incoming)
            .await
    }

    pub(crate) async fn incoming_controller(
        &self,
        plan: &ManagementTransferPlan,
    ) -> Result<(SigningKey, DidUrl)> {
        let (_, incoming) = self.incoming(plan).await?;
        Ok((
            SigningKey::from_bytes(&decode_managed_actor_seed(
                "receiving controller",
                &incoming.controller_seed,
            )?),
            incoming.offer.method,
        ))
    }

    pub(crate) async fn retained_manager_event(
        &self,
        plan: &ManagementTransferPlan,
    ) -> Result<Option<(AuthoredEvent, CommittedEventRef)>> {
        let (_, incoming) = self.incoming(plan).await?;
        Ok(incoming.manager_event.zip(incoming.control_ref))
    }
    pub(crate) async fn retained_manager_receipt(
        &self,
        plan: &ManagementTransferPlan,
    ) -> Result<Option<CommittedEventFullView>> {
        Ok(self.incoming(plan).await?.1.receipt)
    }

    pub(crate) async fn prepare_manager_event(
        &self,
        plan: &ManagementTransferPlan,
        current: &arkret::identity::VerifiedRealmActorMaterial,
        creation: &arkret::identity::VerifiedRealmActorMaterial,
    ) -> Result<AuthoredEvent> {
        let (raw, mut incoming) = self.incoming(plan).await?;
        if let Some(event) = incoming.manager_event {
            return Ok(event);
        }
        let cut = current.material();
        if cut.actor_id != plan.actor_id
            || cut.requester_actor_id != plan.actor_id
            || creation.material().actor_id != plan.actor_id
        {
            return Err(invalid(
                "management current or creation belongs to another actor",
            ));
        }
        let RealmActorMaterial::Event {
            event: created,
            commit,
            ..
        } = &creation.material().result
        else {
            return Err(invalid("management creation original missing"));
        };
        let payload = crate::managed_authoring::creation_payload(created)?;
        if payload.actor_id != plan.actor_id || payload.applet_id.as_str() != self.edge.applet_id()
        {
            return Err(invalid("management creation differs from actor or Applet"));
        }
        let actor_id = plan.actor_id.clone();
        let (_, control, control_ref) = recovery::row(
            cut,
            &arkret::CurrentSelector::RealmActorControl {
                actor_id: actor_id.clone(),
            },
        )?;
        let control: RealmActorControlValue = serde_json::from_value(control.clone())?;
        let (manager_revision, ..) = recovery::row(
            cut,
            &arkret::CurrentSelector::RealmActorManager {
                actor_id: actor_id.clone(),
            },
        )?;
        let (generation_revision, generation, _) = recovery::row(
            cut,
            &arkret::CurrentSelector::RealmActorDeviceGeneration {
                actor_id: actor_id.clone(),
            },
        )?;
        let generation: arkret::RealmActorDeviceGenerationValue =
            serde_json::from_value(generation.clone())?;
        if control.control_method_kid != incoming.offer.method
            || control.resolution.did != incoming.offer.did
        {
            return Err(invalid("receiving controller is not currently accepted"));
        }
        let entries = incoming
            .log_entries
            .as_ref()
            .ok_or_else(|| invalid("receiving native custody not finalized"))?;
        let (next_resolution, method_history_evidence) =
            native_material(&incoming.offer.did, entries)?;
        let at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
        let transcript = arkret::RealmActorManagerAcceptanceTranscript {
            actor_id: actor_id.clone(),
            applet_id: payload.applet_id,
            expected_manager_revision: manager_revision.clone(),
            expected_control_revision: revision(control_ref),
            expected_device_generation_revision: generation_revision.clone(),
            expected_generation: generation.current_device_generation_ref,
            new_generation: generation
                .current_device_generation_ref
                .checked_add(1)
                .ok_or_else(|| invalid("device generation exhausted"))?,
            new_service_id: plan.new_service_id.clone(),
            new_registration_ref: plan.new_registration_ref.clone(),
            management_authorization_ref: plan.management_authorization_ref.clone(),
            next_resolution,
            method_history_evidence,
        };
        let signature = arkret::signatures::detached_object::sign_detached_object(
            &transcript,
            arkret::DetachedSignatureContext::RealmActorManagerAcceptance,
            self.edge.service_verification_method()?,
            at,
            &SigningKey::from_bytes(&self.config.signing_seed()?),
        )
        .map_err(|e| invalid(e.to_string()))?;
        let mut value = serde_json::to_value(&transcript)?;
        let object = value.as_object_mut().expect("typed transcript object");
        object.remove("actor_id");
        object.remove("applet_id");
        object.insert(
            "new_service_signature".into(),
            serde_json::to_value(signature)?,
        );
        let payload: arkret::RealmActorManagerChangePayload = serde_json::from_value(value)?;
        let mut event = arkret_event_draft::TypedEventDraft::<
            arkret_wire::event_spec::RealmActorManagerChange,
        >::new(
            arkret::ScopeRef::RealmControl {
                realm_id: actor_id
                    .as_realm_actor_id()
                    .expect("validated actor")
                    .realm_id
                    .clone(),
            },
            actor_id,
            payload,
        )?
        .with_applet_id(transcript.applet_id)
        .into_intent(at)?
        .author_with_digest_suite(crate::PRODUCER_DIGEST_SUITE)?;
        let signer = arkret::Ed25519PayloadSigner::new(
            SigningKey::from_bytes(&decode_managed_actor_seed(
                "receiving controller",
                &incoming.controller_seed,
            )?),
            incoming.offer.did.clone(),
            incoming.offer.method.clone(),
        );
        sign_event(
            &mut event,
            &signer,
            SignEventOptions::new().with_created_at(at),
        )?;
        incoming.manager_event = Some(event.clone());
        incoming.control_ref = Some(control_ref.clone());
        incoming.creation = Some(CommittedEventFullView {
            event: created.clone(),
            commit: commit.clone(),
        });
        self.transfer_save(&transfer_key(plan, "incoming")?, Some(raw), &incoming)
            .await?;
        Ok(event)
    }

    pub(crate) async fn accept_manager_event(
        &self,
        plan: &ManagementTransferPlan,
        verified: &arkret::identity::VerifiedRealmActorMaterial,
    ) -> Result<RealmCommit> {
        let (raw, mut incoming) = self.incoming(plan).await?;
        let RealmActorMaterial::Event { event, commit, .. } = &verified.material().result else {
            return Err(invalid("manager acceptance original missing"));
        };
        if verified.material().actor_id != plan.actor_id
            || incoming
                .manager_event
                .as_ref()
                .is_none_or(|original| original.event() != event)
        {
            return Err(invalid(
                "manager acceptance differs from the frozen original",
            ));
        }
        let full = CommittedEventFullView {
            event: event.clone(),
            commit: commit.clone(),
        };
        if let Some(original) = incoming.receipt {
            if original != full {
                return Err(invalid("manager acceptance fork"));
            }
            return Ok(commit.clone());
        }
        let subject = transfer_key(plan, "incoming")?;
        let origin = TransferredOrigin {
            subject: subject.clone(),
            service_id: plan.new_service_id.clone(),
            creation: incoming
                .creation
                .clone()
                .ok_or_else(|| invalid("manager creation custody missing"))?,
            manager: full.clone(),
        };
        let custody = ControlCustody {
            actor_id: plan.actor_id.clone(),
            log_entries: incoming
                .log_entries
                .clone()
                .ok_or_else(|| invalid("manager native custody missing"))?,
            next_root_seed: incoming.next_update_seed.clone(),
            controllers: BTreeMap::from([(
                incoming.offer.method.to_string(),
                incoming.controller_seed.clone(),
            )]),
            operations: BTreeMap::new(),
            recoveries: BTreeMap::new(),
        };
        incoming.receipt = Some(full);
        incoming.controller_seed.clear();
        incoming.update_seed.clear();
        incoming.next_update_seed.clear();
        let origin_key = origin_key(&plan.actor_id)?;
        let control_key = key(&subject);
        let store = self.edge.authoring_store();
        let previous_origin = {
            let store = store.clone();
            let key = origin_key.clone();
            crate::run_blocking(move || store.load(&key)).await?
        };
        if let Some(raw) = &previous_origin {
            let previous: TransferredOrigin = self.decrypt_key_material(&origin_key, raw)?;
            if previous.manager.commit.stream_ref != commit.stream_ref
                || previous.manager.commit.stream_position >= commit.stream_position
            {
                return Err(invalid(
                    "historical manager receipt cannot replace newer local custody",
                ));
            }
        }
        let writes = vec![
            (
                subject.clone(),
                Some(self.encrypt_key_material(&subject, &incoming)?),
            ),
            (
                origin_key.clone(),
                Some(self.encrypt_key_material(&origin_key, &origin)?),
            ),
            (
                control_key.clone(),
                Some(self.encrypt_key_material(&control_key, &custody)?),
            ),
        ];
        if !crate::run_blocking(move || {
            store.compare_exchange_batch(
                &[
                    (subject, Some(raw)),
                    (origin_key, previous_origin),
                    (control_key, None),
                ],
                &writes,
            )
        })
        .await?
        {
            return Err(invalid("manager custody acceptance changed concurrently"));
        }
        Ok(commit.clone())
    }

    pub(crate) async fn published_transferred_principal(
        &self,
        url: &str,
    ) -> Result<Option<(arkret::DidDocument, Vec<Value>)>> {
        let store = self.edge.authoring_store();
        let rows = crate::run_blocking(move || {
            store.entries_with_prefix("managed-manager-transfer/v1/incoming/")
        })
        .await?;
        let mut found = None;
        for (key, raw) in rows {
            let incoming: Incoming = self.decrypt_key_material(&key, &raw)?;
            let Some(entries) = incoming.log_entries else {
                continue;
            };
            let native_url = arkret::identity::DidWebvhResolver::document_url(&incoming.offer.did)
                .map_err(|e| invalid(e.to_string()))?;
            // Compare the stable native resource, never the new Service endpoint.
            if native_url != url {
                continue;
            }
            let entries = if incoming.receipt.is_some() {
                self.published_control_history(&key, entries).await?
            } else {
                entries
            };
            found = Some(continuous_publication(
                found,
                (
                    serde_json::from_value(
                        entries.last().expect("retained native history")["state"].clone(),
                    )?,
                    entries,
                ),
            )?);
        }
        Ok(found)
    }
}
