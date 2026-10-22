//! Encrypted native control custody; publication and the frozen request share one CAS.
use std::collections::BTreeMap;

use arkret::signatures::{EventSigner as _, SignEventOptions, sign_event};
use arkret::{ActorId, AuthoredEvent, CurrentRevision, RealmActorControlValue, RealmCommit};

use super::*;

pub(crate) mod manager;
mod recovery;
use recovery::PreparedRecovery;
mod unaccepted;
use unaccepted::ControlClosure;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedControlRotation {
    pub(crate) operation_id: String,
    pub(crate) actor_id: ActorId,
    pub(crate) previous_control: RealmActorControlValue,
    pub(crate) previous_reference: arkret::CommittedEventRef,
    pub(crate) event: AuthoredEvent,
    pub(crate) outcome: Option<(RealmCommit, PublicKeyMaterial)>,
    closure: Option<ControlClosure>,
}

impl PreparedControlRotation {
    pub(crate) fn is_closed(&self) -> bool {
        self.closure.is_some()
    }

    fn is_finished(&self) -> bool {
        self.outcome.is_some() || self.is_closed()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlCustody {
    actor_id: ActorId,
    log_entries: Vec<Value>,
    next_root_seed: String,
    controllers: BTreeMap<String, String>,
    operations: BTreeMap<String, PreparedControlRotation>,
    recoveries: BTreeMap<String, PreparedRecovery>,
}

fn invalid(message: impl Into<String>) -> BridgeError {
    BridgeError::Database(message.into())
}
fn key(subject: &str) -> String {
    format!("managed-control/v1/{subject}")
}

impl ManagedActorAuthoringService {
    async fn custody_subject(&self, actor: &ActorId) -> Result<String> {
        if let Some(origin) = self.transferred_origin(actor).await? {
            return Ok(origin.subject);
        }
        let edge = self.edge.clone();
        let actor = actor.clone();
        let original = crate::run_blocking(move || edge.retained_managed_actor(&actor)).await?;
        managed_actor_subject_key(
            &self
                .edge
                .prepared_managed_actor(&original)?
                .authoring_request,
        )
    }

    async fn control_raw(&self, subject: &str) -> Result<Option<String>> {
        let store = self.edge.authoring_store();
        let key = key(subject);
        crate::run_blocking(move || store.load(&key)).await
    }

    async fn save_control(
        &self,
        subject: &str,
        previous: Option<String>,
        next: &ControlCustody,
    ) -> Result<()> {
        let store = self.edge.authoring_store();
        let control_key = key(subject);
        let encrypted = self.encrypt_key_material(&control_key, next)?;
        let did: Did = serde_json::from_value(
            next.log_entries
                .last()
                .ok_or_else(|| invalid("control publication history is empty"))?["state"]["id"]
                .clone(),
        )?;
        let url = arkret::identity::DidWebvhResolver::document_url(&did)
            .map_err(|error| invalid(error.to_string()))?;
        let publication_key = format!("managed-control-publication/v1/{}", canonical_sha256(&url)?);
        let publication_store = store.clone();
        let lookup = publication_key.clone();
        let publication_before =
            crate::run_blocking(move || publication_store.load(&lookup)).await?;
        if let Some(raw) = &publication_before {
            let (owner, published): (String, Did) =
                self.decrypt_key_material(&publication_key, raw)?;
            if published != did {
                return Err(invalid("native publication address belongs to another DID"));
            }
            if owner != subject {
                let previous_raw = self
                    .control_raw(&owner)
                    .await?
                    .ok_or_else(|| invalid("previous publisher custody is unavailable"))?;
                let previous_owner: ControlCustody =
                    self.decrypt_key_material(&key(&owner), &previous_raw)?;
                if previous_owner.actor_id != next.actor_id
                    || !next.log_entries.starts_with(&previous_owner.log_entries)
                {
                    return Err(invalid(
                        "native publication does not extend the retained subject",
                    ));
                }
            }
        }
        let publication = self.encrypt_key_material(&publication_key, &(subject, &did))?;
        if !crate::run_blocking(move || {
            store.compare_exchange_batch(
                &[
                    (control_key.clone(), previous),
                    (publication_key.clone(), publication_before),
                ],
                &[
                    (control_key, Some(encrypted)),
                    (publication_key, Some(publication)),
                ],
            )
        })
        .await?
        {
            return Err(invalid(
                "control custody changed concurrently; retry the same operation",
            ));
        }
        Ok(())
    }

    pub(super) async fn published_control_history(
        &self,
        subject: &str,
        inception: Vec<Value>,
    ) -> Result<Vec<Value>> {
        let Some(raw) = self.control_raw(subject).await? else {
            return Ok(inception);
        };
        let custody: ControlCustody = self.decrypt_key_material(&key(subject), &raw)?;
        if custody.log_entries.first() != inception.first() {
            return Err(invalid(
                "control history does not extend the retained inception",
            ));
        }
        Ok(custody.log_entries)
    }

    pub(super) async fn published_control_principal(
        &self,
        url: &str,
    ) -> Result<Option<(arkret::DidDocument, Vec<Value>)>> {
        let index = format!("managed-control-publication/v1/{}", canonical_sha256(&url)?);
        let store = self.edge.authoring_store();
        let raw = crate::run_blocking(move || store.load(&index).map(|raw| (index, raw))).await?;
        let Some(value) = raw.1 else {
            return Ok(None);
        };
        let (subject, did): (String, Did) = self.decrypt_key_material(&raw.0, &value)?;
        let Some(raw) = self.control_raw(&subject).await? else {
            return Err(invalid("publication has no durable control custody"));
        };
        let custody: ControlCustody = self.decrypt_key_material(&key(&subject), &raw)?;
        let latest: Did = serde_json::from_value(
            custody
                .log_entries
                .last()
                .ok_or_else(|| invalid("published native history is empty"))?["state"]["id"]
                .clone(),
        )?;
        if latest != did {
            return Ok(None);
        }
        if project_did_to_core_id(&did)? != *custody.actor_id.signing_principal_id()
            || arkret::identity::DidWebvhResolver::document_url(&did)
                .map_err(|error| invalid(error.to_string()))?
                != url
        {
            return Err(invalid(
                "publication address differs from retained identity",
            ));
        }
        arkret::identity::verify_did_webvh_v1_chain(&did, &custody.log_entries)
            .map_err(|error| invalid(error.to_string()))?;
        let document =
            serde_json::from_value(custody.log_entries.last().unwrap()["state"].clone())?;
        Ok(Some((document, custody.log_entries)))
    }

    /// Select only the key named by an independently verified current control row.
    pub(crate) async fn managed_controller(
        &self,
        actor: &ActorId,
        method: &DidUrl,
    ) -> Result<ManagedController> {
        let subject = self.custody_subject(actor).await?;
        let Some(raw) = self.control_raw(&subject).await? else {
            let original = self.original_managed_controller(actor).await?;
            if original.signer.verification_method() != method.as_str() {
                return Err(invalid("current controller has no retained custody"));
            }
            return Ok(original);
        };
        let custody: ControlCustody = self.decrypt_key_material(&key(&subject), &raw)?;
        if custody.actor_id != *actor {
            return Err(invalid("control custody belongs to another Realm actor"));
        }
        let Some(seed) = custody.controllers.get(method.as_str()) else {
            let original = self.original_managed_controller(actor).await?;
            if original.signer.verification_method() != method.as_str() {
                return Err(invalid("current control method key is unavailable"));
            }
            return Ok(original);
        };
        let signing = SigningKey::from_bytes(&decode_managed_actor_seed("controller", seed)?);
        let did =
            arkret::verification_method_did(method.as_str()).map_err(|e| invalid(e.to_string()))?;
        if project_did_to_core_id(&did)? != *actor.signing_principal_id() {
            return Err(invalid("control method belongs to another principal"));
        }
        let original = self.managed_creation(actor).await?;
        Ok(ManagedController {
            actor_id: actor.clone(),
            signer: arkret::Ed25519PayloadSigner::new(signing.clone(), did, method.clone()),
            signing_key: signing,
            original: Box::new(original),
        })
    }

    pub(crate) async fn retained_control_rotation(
        &self,
        actor: &ActorId,
        operation_id: &str,
    ) -> Result<Option<PreparedControlRotation>> {
        let subject = self.custody_subject(actor).await?;
        let Some(raw) = self.control_raw(&subject).await? else {
            return Ok(None);
        };
        let custody: ControlCustody = self.decrypt_key_material(&key(&subject), &raw)?;
        if custody.actor_id != *actor {
            return Err(invalid("control operation belongs to another Realm actor"));
        }
        Ok(custody.operations.get(operation_id).cloned())
    }

    pub(crate) async fn prepare_control_rotation(
        &self,
        actor: &ActorId,
        operation_id: &str,
        current: &RealmActorControlValue,
        reference: &arkret::CommittedEventRef,
        retire_previous: bool,
    ) -> Result<PreparedControlRotation> {
        self.prepare_control_update(
            actor,
            operation_id,
            current,
            reference,
            retire_previous,
            None,
        )
        .await
    }

    pub(crate) async fn prepare_control_update(
        &self,
        actor: &ActorId,
        operation_id: &str,
        current: &RealmActorControlValue,
        reference: &arkret::CommittedEventRef,
        retire_previous: bool,
        target_did: Option<&Did>,
    ) -> Result<PreparedControlRotation> {
        if let Some(target) = target_did {
            let url: url::Url = arkret::identity::DidWebvhResolver::document_url(target)
                .map_err(|error| invalid(error.to_string()))?
                .parse()
                .map_err(|error| invalid(format!("relocation URL: {error}")))?;
            let segments: Vec<_> = url
                .path_segments()
                .ok_or_else(|| invalid("relocation path missing"))?
                .collect();
            if url.origin() != self.principal_endpoint.origin()
                || segments.len() != 3
                || segments[0] != "webvh"
                || segments[2] != "did.json"
                || segments[1].is_empty()
                || segments[1].len() > 64
                || !segments[1]
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
            {
                return Err(invalid(
                    "relocation target is outside this configured native publisher",
                ));
            }
        }
        if operation_id.is_empty() || operation_id.len() > 128 {
            return Err(invalid("control rotation requires a bounded operation ID"));
        }
        let subject = self.custody_subject(actor).await?;
        let before = self.control_raw(&subject).await?;
        let controller = self
            .managed_controller(actor, &current.control_method_kid)
            .await?;
        let mut custody = if let Some(raw) = &before {
            self.decrypt_key_material::<ControlCustody>(&key(&subject), raw)?
        } else {
            let record = self
                .store
                .clone()
                .managed_actor_identity_async(subject.clone())
                .await?
                .ok_or_else(|| invalid("control inception custody missing"))?;
            let identity = self.decode_identity(&subject, record.clone())?;
            let material: ManagedActorKeyMaterial =
                self.decrypt_key_material(&subject, &record.encrypted_key_material)?;
            let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
                identity.method_history_evidence
            else {
                return Err(invalid("control rotation requires native WebVH custody"));
            };
            ControlCustody {
                actor_id: actor.clone(),
                log_entries,
                next_root_seed: material.next_root_seed,
                controllers: BTreeMap::from([(
                    controller.signer.verification_method().to_owned(),
                    arkret::base64url_encode(controller.signing_key.to_bytes()),
                )]),
                operations: BTreeMap::new(),
                recoveries: BTreeMap::new(),
            }
        };
        if custody.actor_id != *actor {
            return Err(invalid("control custody actor mismatch"));
        }
        if let Some(prepared) = custody.operations.get(operation_id) {
            return Ok(prepared.clone());
        }
        if custody
            .operations
            .values()
            .any(|operation| !operation.is_finished())
            || custody
                .recoveries
                .values()
                .any(|operation| !operation.is_finished())
        {
            return Err(invalid(
                "recover the outstanding control operation before another rotation",
            ));
        }
        let creation = crate::managed_authoring::creation_payload(&controller.original.event)?;
        let prepared = prepare_successor(
            &mut custody,
            actor,
            operation_id,
            current,
            reference,
            &controller.signer,
            creation.applet_id,
            arkret::canonical::normalize_timestamp_canonical(Utc::now()),
            retire_previous,
            target_did,
        )?;
        // The public log reader only observes this row after the complete original
        // and both new private keys have reached the same durable commit.
        self.save_control(&subject, before, &custody).await?;
        Ok(prepared)
    }

    pub(crate) async fn accept_control_rotation(
        &self,
        prepared: &PreparedControlRotation,
        commit: &RealmCommit,
        station_key: &PublicKeyMaterial,
    ) -> Result<()> {
        commit.validate_content_address()?;
        if commit.event_ref != *prepared.event.event_id()
            || commit.stream_ref != prepared.previous_reference.stream_ref
            || commit.stream_position <= prepared.previous_reference.stream_position
        {
            return Err(invalid(
                "control acceptance differs from the frozen original",
            ));
        }
        arkret::signatures::detached_object::verify_detached_object_signature(
            &commit.signature,
            &arkret::canonical::unsigned_value(commit, &["signature"])?,
            arkret::DetachedSignatureContext::RealmCommit,
            station_key,
        )
        .map_err(|e| invalid(e.to_string()))?;
        let subject = self.custody_subject(&prepared.actor_id).await?;
        let raw = self
            .control_raw(&subject)
            .await?
            .ok_or_else(|| invalid("control intent vanished"))?;
        let mut custody: ControlCustody = self.decrypt_key_material(&key(&subject), &raw)?;
        let operation = custody
            .operations
            .get_mut(&prepared.operation_id)
            .ok_or_else(|| invalid("control operation vanished"))?;
        if operation.event != prepared.event {
            return Err(invalid("control original changed"));
        }
        if operation.is_closed() {
            return Err(invalid(
                "closed control intent cannot acquire an acceptance",
            ));
        }
        if let Some((prior, prior_key)) = &operation.outcome {
            if prior != commit || prior_key != station_key {
                return Err(invalid("control acceptance fork"));
            }
            return Ok(());
        }
        operation.outcome = Some((commit.clone(), station_key.clone()));
        self.save_control(&subject, Some(raw), &custody).await
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_successor(
    custody: &mut ControlCustody,
    actor: &ActorId,
    operation_id: &str,
    current: &RealmActorControlValue,
    reference: &arkret::CommittedEventRef,
    controller: &arkret::Ed25519PayloadSigner,
    applet_id: AppletId,
    at: chrono::DateTime<Utc>,
    retire_previous: bool,
    target_did: Option<&Did>,
) -> Result<PreparedControlRotation> {
    if retire_previous && target_did.is_some() {
        return Err(invalid(
            "relocation and old-method retirement are separate accepted steps",
        ));
    }
    let did = target_did.unwrap_or(&current.resolution.did);
    let last = custody
        .log_entries
        .last()
        .ok_or_else(|| invalid("control history is empty"))?;
    let previous_at: chrono::DateTime<Utc> = last["versionTime"]
        .as_str()
        .ok_or_else(|| invalid("control history time missing"))?
        .parse()
        .map_err(|_| invalid("control history time invalid"))?;
    if at.timestamp() <= previous_at.timestamp() {
        return Err(invalid(
            "control rotation must wait for the next native log second",
        ));
    }
    let mut next_seed = [0_u8; 32];
    let mut next_root = [0_u8; 32];
    if retire_previous {
        next_seed = decode_managed_actor_seed(
            "current_controller",
            custody
                .controllers
                .get(current.control_method_kid.as_str())
                .ok_or_else(|| invalid("accepted controller has no retained key"))?,
        )?;
    } else {
        getrandom::fill(&mut next_seed).map_err(|e| invalid(e.to_string()))?;
    }
    getrandom::fill(&mut next_root).map_err(|e| invalid(e.to_string()))?;
    let signing = SigningKey::from_bytes(&next_seed);
    let public = arkret::ed25519_pubkey_to_did_key_multibase(signing.verifying_key().as_bytes());
    let method = if retire_previous {
        current.control_method_kid.clone()
    } else {
        DidUrl::new(format!("{did}#control-{public}")).map_err(invalid)?
    };
    let mut state = last["state"].clone();
    if target_did.is_some() {
        state["id"] = json!(did);
        let mut aliases = state["alsoKnownAs"].as_array().cloned().unwrap_or_default();
        aliases.retain(|alias| alias != &json!(did));
        if !aliases.contains(&json!(current.resolution.did)) {
            aliases.push(json!(current.resolution.did));
        }
        state["alsoKnownAs"] = json!(aliases);
        for method in state["verificationMethod"]
            .as_array_mut()
            .ok_or_else(|| invalid("relocation document methods missing"))?
        {
            if method["controller"] == json!(current.resolution.did) {
                method["controller"] = json!(did);
            }
        }
    }
    if retire_previous {
        let obsolete = |value: &Value| {
            let id = value
                .as_str()
                .or_else(|| value.get("id").and_then(Value::as_str));
            id.is_some_and(|id| id != method.as_str() && custody.controllers.contains_key(id))
        };
        for relation in ["verificationMethod", "assertionMethod", "authentication"] {
            state[relation]
                .as_array_mut()
                .ok_or_else(|| invalid("control document methods missing"))?
                .retain(|value| !obsolete(value));
        }
    } else {
        state["verificationMethod"]
            .as_array_mut()
            .ok_or_else(|| invalid("control document methods missing"))?
            .push(
                json!({"id":method,"type":"Multikey","controller":did,"publicKeyMultibase":public}),
            );
        for relation in ["assertionMethod", "authentication"] {
            state[relation]
                .as_array_mut()
                .ok_or_else(|| invalid("control document relationship missing"))?
                .push(json!(method));
        }
    }
    let update_seed = decode_managed_actor_seed("next_root_seed", &custody.next_root_seed)?;
    let next_public = arkret::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&next_root)
            .verifying_key()
            .as_bytes(),
    );
    let (entry, version_id) = if target_did.is_some() {
        let next = arkret::webvh::prepare_webvh_relocation(&arkret::webvh::WebvhRelocationInput {
            current_did: current.resolution.did.as_str(),
            target_did: did.as_str(),
            previous_entries: &custody.log_entries,
            version_time: at,
            current_update_seed: &update_seed,
            next_update_public_key_multibase: &next_public,
            state: &state,
        })
        .map_err(|error| invalid(error.to_string()))?;
        (next.log_entry, next.version_id)
    } else {
        let next = arkret::webvh::prepare_service_rotation(&arkret::webvh::ServiceRotationInput {
            did: did.as_str(),
            previous_entries: &custody.log_entries,
            state: &state,
            current_update_seed: &update_seed,
            next_update_public_key_multibase: &next_public,
            version_time: at,
        })
        .map_err(|error| invalid(error.to_string()))?;
        (next.log_entry, next.version_id)
    };
    custody.log_entries.push(entry);
    let head = canonical_sha256(custody.log_entries.last().expect("appended native entry"))?;
    let document: arkret::DidDocument = serde_json::from_value(state)?;
    let witnesses = Vec::<Value>::new();
    let evidence = ResolutionMethodHistoryEvidence::WebvhLog {
        boundary: ResolutionMethodEvidenceBoundary {
            from_method_history_head: canonical_sha256(&custody.log_entries[0])?,
            from_version_id: custody.log_entries[0]["versionId"]
                .as_str()
                .ok_or_else(|| invalid("native inception version missing"))?
                .to_owned(),
            to_method_history_head: head.clone(),
            to_version_id: version_id.clone(),
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
        log_entries: custody.log_entries.clone(),
        witness_records: witnesses,
    };
    let transcript = arkret::RealmActorControlAcceptanceTranscript {
        actor_id: actor.clone(),
        expected_revision: CurrentRevision {
            commit_id: reference.commit_id.clone(),
            stream_position: reference.stream_position,
        },
        next_resolution: ResolutionCommitment {
            did: did.clone(),
            method_history_head: head,
            version_id,
        },
        method_history_evidence: serde_json::from_value(serde_json::to_value(evidence)?)?,
        next_control_method_kid: method.clone(),
    };
    let signature = arkret::signatures::detached_object::sign_detached_object(
        &transcript,
        arkret::DetachedSignatureContext::RealmActorControlAcceptance,
        method.clone(),
        at,
        &signing,
    )
    .map_err(|e| invalid(e.to_string()))?;
    let payload = arkret::RealmActorControlUpdatePayload {
        expected_revision: transcript.expected_revision,
        next_resolution: transcript.next_resolution,
        method_history_evidence: transcript.method_history_evidence,
        next_control_method_kid: method.clone(),
        next_method_signature: signature,
    };
    arkret::identity::verify_realm_actor_control_successor(
        actor,
        &current.resolution,
        &current.control_method_kid,
        &payload,
        at,
    )
    .map_err(|e| invalid(e.to_string()))?;
    let mut event = arkret_event_draft::TypedEventDraft::<
        arkret_wire::event_spec::RealmActorControlUpdate,
    >::new(
        arkret::ScopeRef::RealmControl {
            realm_id: reference.stream_ref.realm_id().clone(),
        },
        actor.clone(),
        payload,
    )?
    .with_applet_id(applet_id)
    .into_intent(at)?
    .author_with_digest_suite(crate::PRODUCER_DIGEST_SUITE)?;
    sign_event(
        &mut event,
        controller,
        SignEventOptions::new().with_created_at(at),
    )?;
    let prepared = PreparedControlRotation {
        operation_id: operation_id.to_owned(),
        actor_id: actor.clone(),
        previous_control: current.clone(),
        previous_reference: reference.clone(),
        event,
        outcome: None,
        closure: None,
    };
    custody.next_root_seed = arkret::base64url_encode(next_root);
    custody
        .controllers
        .insert(method.to_string(), arkret::base64url_encode(next_seed));
    custody
        .operations
        .insert(operation_id.to_owned(), prepared.clone());
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthoringStore;

    #[tokio::test]
    async fn native_rotation_publishes_only_with_encrypted_original_and_keys() {
        let store = Arc::new(super::super::ghost_bundle_tests::RecordingAuthoringStore::default());
        let edge = Arc::new(super::super::ghost_bundle_tests::edge(store.clone()));
        let service = ManagedActorAuthoringService::new(edge.clone()).unwrap();
        let at = "2026-10-01T00:00:00Z"
            .parse::<chrono::DateTime<Utc>>()
            .unwrap();
        let root = [11; 32];
        let next = [12; 32];
        let control = SigningKey::from_bytes(&[13; 32]);
        let inception = arkret::webvh::prepare_realm_actor_inception(
            &arkret::webvh::RealmActorInceptionInput {
                principal_endpoint: &url::Url::parse("https://applet.example/actors/slack")
                    .unwrap(),
                local_id: "control-test",
                controller_public_key: &control.verifying_key().to_bytes(),
                version_time: at,
                root_seed: &root,
                next_root_public_key_multibase: &arkret::ed25519_pubkey_to_did_key_multibase(
                    SigningKey::from_bytes(&next).verifying_key().as_bytes(),
                ),
            },
        )
        .unwrap();
        let did = Did::new(inception.did.clone()).unwrap();
        let method = DidUrl::new(format!("{did}#managed-controller")).unwrap();
        let event = arkret::EventId::from_digest(crate::PRODUCER_DIGEST_SUITE, [1; 32]);
        let realm = arkret::RealmId::from_event_id(&event);
        let actor = ActorId::realm(arkret::RealmActorId {
            realm_id: realm.clone(),
            principal_id: project_did_to_core_id(&did).unwrap(),
        });
        let reference = arkret::CommittedEventRef {
            event_id: event.clone(),
            commit_id: arkret::RealmCommitId::from_digest([2; 32]),
            stream_ref: arkret::CommitStreamRef::RealmControl { realm_id: realm },
            stream_position: 2,
        };
        let current = RealmActorControlValue {
            resolution: arkret::PrincipalResolutionProjection {
                did: did.clone(),
                method_history_head: canonical_sha256(&inception.log_entry).unwrap(),
                version_id: inception.version_id,
                resolution_event_ref: event.to_string(),
                updated_at: at,
            },
            control_method_kid: method.clone(),
        };
        let original = vec![inception.log_entry];
        let mut custody = ControlCustody {
            actor_id: actor.clone(),
            log_entries: original.clone(),
            next_root_seed: arkret::base64url_encode(next),
            controllers: BTreeMap::from([(method.to_string(), arkret::base64url_encode([13; 32]))]),
            operations: BTreeMap::new(),
            recoveries: BTreeMap::new(),
        };
        let signer = arkret::Ed25519PayloadSigner::new(control, did.clone(), method.clone());
        let applet = AppletId::new(edge.applet_id()).unwrap();
        let prepared = prepare_successor(
            &mut custody,
            &actor,
            "rotate",
            &current,
            &reference,
            &signer,
            applet,
            at + chrono::Duration::seconds(1),
            false,
            None,
        )
        .unwrap();
        let payload: arkret::RealmActorControlUpdatePayload =
            serde_json::from_value(serde_json::to_value(&prepared.event.payload).unwrap()).unwrap();
        assert_ne!(payload.next_control_method_kid, method);
        arkret::identity::verify_realm_actor_control_successor(
            &actor,
            &current.resolution,
            &method,
            &payload,
            at + chrono::Duration::seconds(1),
        )
        .unwrap();
        assert_eq!(
            service
                .published_control_history("subject", original.clone())
                .await
                .unwrap(),
            original,
            "preparing private bytes must not publish the new native head"
        );
        service
            .save_control("subject", None, &custody)
            .await
            .unwrap();
        assert!(
            service
                .save_control("subject", None, &custody)
                .await
                .is_err(),
            "another writer cannot replace committed custody"
        );
        let raw = store.load(&key("subject")).unwrap().unwrap();
        assert!(!raw.contains(&custody.next_root_seed));
        assert!(!raw.contains(prepared.event.event_id().as_str()));
        drop(service);
        let reopened = ManagedActorAuthoringService::new(edge).unwrap();
        let mut restored: ControlCustody = reopened
            .decrypt_key_material(&key("subject"), &raw)
            .unwrap();
        assert_eq!(restored.operations["rotate"].event, prepared.event);
        let published = reopened
            .published_control_history("subject", original.clone())
            .await
            .unwrap();
        assert_eq!(published, restored.log_entries);
        assert_eq!(published.len(), 2);
        let next_seed = decode_managed_actor_seed(
            "controller",
            &restored.controllers[payload.next_control_method_kid.as_str()],
        )
        .unwrap();
        let next_key = SigningKey::from_bytes(&next_seed);
        arkret::signatures::detached_object::verify_detached_object_signature(
            &payload.next_method_signature,
            &arkret::RealmActorControlAcceptanceTranscript {
                actor_id: actor.clone(),
                expected_revision: payload.expected_revision.clone(),
                next_resolution: payload.next_resolution.clone(),
                method_history_evidence: payload.method_history_evidence.clone(),
                next_control_method_kid: payload.next_control_method_kid.clone(),
            },
            arkret::DetachedSignatureContext::RealmActorControlAcceptance,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: next_key.verifying_key().to_bytes().to_vec(),
            },
        )
        .unwrap();
        let state = &published.last().unwrap()["state"];
        assert!(
            state["authentication"]
                .as_array()
                .unwrap()
                .contains(&json!(method)),
            "unknown Station acceptance must retain the old authenticating method"
        );
        let accepted = RealmActorControlValue {
            resolution: arkret::PrincipalResolutionProjection {
                did: did.clone(),
                method_history_head: payload.next_resolution.method_history_head,
                version_id: payload.next_resolution.version_id,
                resolution_event_ref: prepared.event.event_id().to_string(),
                updated_at: at + chrono::Duration::seconds(1),
            },
            control_method_kid: payload.next_control_method_kid.clone(),
        };
        let accepted_reference = arkret::CommittedEventRef {
            event_id: prepared.event.event_id().clone(),
            commit_id: arkret::RealmCommitId::from_digest([3; 32]),
            stream_position: 3,
            ..reference
        };
        let signer = arkret::Ed25519PayloadSigner::new(
            next_key,
            did,
            payload.next_control_method_kid.clone(),
        );
        let retired = prepare_successor(
            &mut restored,
            &actor,
            "retire",
            &accepted,
            &accepted_reference,
            &signer,
            AppletId::new(reopened.edge.applet_id()).unwrap(),
            at + chrono::Duration::seconds(2),
            true,
            None,
        )
        .unwrap();
        let cleanup: arkret::RealmActorControlUpdatePayload =
            serde_json::from_value(serde_json::to_value(&retired.event.payload).unwrap()).unwrap();
        assert_eq!(
            cleanup.next_control_method_kid, accepted.control_method_kid,
            "retirement must be a same-method successor, not another controller rotation"
        );
        let state = &restored.log_entries.last().unwrap()["state"];
        assert!(
            !state["authentication"]
                .as_array()
                .unwrap()
                .contains(&json!(method))
        );
        assert!(
            state["authentication"]
                .as_array()
                .unwrap()
                .contains(&json!(accepted.control_method_kid))
        );
        assert_eq!(restored.log_entries.len(), 3);
        assert_eq!(
            reopened
                .published_control_history("subject", original)
                .await
                .unwrap()
                .len(),
            2,
            "uncommitted retirement must not change the public log"
        );
        let old_entries = restored.log_entries.clone();
        let old_did = accepted.resolution.did.clone();
        let target = Did::new(format!(
            "did:webvh:{}:relocated.example:webvh:subject",
            old_did.as_str().split(':').nth(2).unwrap()
        ))
        .unwrap();
        let current = RealmActorControlValue {
            resolution: arkret::PrincipalResolutionProjection {
                did: old_did.clone(),
                method_history_head: cleanup.next_resolution.method_history_head,
                version_id: cleanup.next_resolution.version_id,
                resolution_event_ref: retired.event.event_id().to_string(),
                updated_at: at + chrono::Duration::seconds(2),
            },
            control_method_kid: accepted.control_method_kid.clone(),
        };
        let reference = arkret::CommittedEventRef {
            event_id: retired.event.event_id().clone(),
            commit_id: arkret::RealmCommitId::from_digest([4; 32]),
            stream_position: 4,
            ..accepted_reference
        };
        let moved = prepare_successor(
            &mut restored,
            &actor,
            "move",
            &current,
            &reference,
            &signer,
            AppletId::new(reopened.edge.applet_id()).unwrap(),
            at + chrono::Duration::seconds(3),
            false,
            Some(&target),
        )
        .unwrap();
        let moved_payload: arkret::RealmActorControlUpdatePayload =
            serde_json::from_value(serde_json::to_value(&moved.event.payload).unwrap()).unwrap();
        assert_eq!(moved_payload.next_resolution.did, target);
        assert_eq!(&restored.log_entries[..3], old_entries.as_slice());
        assert_eq!(
            project_did_to_core_id(&target).unwrap(),
            *actor.signing_principal_id()
        );
        let url = arkret::identity::DidWebvhResolver::document_url(&target).unwrap();
        assert!(
            reopened
                .published_control_principal(&url)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            reopened
                .save_control("subject", None, &restored)
                .await
                .is_err()
        );
        assert!(
            reopened
                .published_control_principal(&url)
                .await
                .unwrap()
                .is_none()
        );
        reopened
            .save_control("subject", Some(raw), &restored)
            .await
            .unwrap();
        let (published, log) = reopened
            .published_control_principal(&url)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(published.id, target);
        assert_eq!(log, restored.log_entries);
        let old_url = arkret::identity::DidWebvhResolver::document_url(&old_did).unwrap();
        assert!(
            reopened
                .published_control_principal(&old_url)
                .await
                .unwrap()
                .is_none()
        );
    }
}
