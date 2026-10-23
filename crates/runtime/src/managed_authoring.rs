//! Local custody preparation and immutable accepted Realm creation journal.
//! These records are host storage, never additional protocol wire carriers.
use arkret::canonical::{canonical_json_bytes, canonical_sha256};
use arkret::signatures::PublicKeyMaterial;
use arkret::{
    ActorId, AppletAuthoringTransactionRequestBody, AppletId, AppletManagedActorAuthoringRequest,
    DidUrl, Event, Hash, RealmActorCreatePayload, RealmActorMaterial, ScopeRef,
};
use serde::{Deserialize, Serialize};

use crate::{AuthoringJournal, BridgeError, Result};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedManagedActor {
    pub authoring_request: AppletManagedActorAuthoringRequest,
    pub create_event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum PreparedGhost {
    Create(Box<PreparedManagedActor>),
    Reuse {
        authoring_request: Box<AppletManagedActorAuthoringRequest>,
        existing: Box<arkret::ExistingManagedActor>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedAuthoringIdentity {
    pub applet_id: AppletId,
    pub actor_id: ActorId,
    pub effective_scope: ScopeRef,
}

pub(crate) enum ManagedDeliveryAdmission {
    New,
    Accepted(arkret::AppletTransactionOutcome),
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagedAuthoringInstall {
    Installed,
    ExactReplay,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preparation {
    command: PreparedManagedActor,
    managed_actor_verification_method: DidUrl,
    managed_actor_public_key: PublicKeyMaterial,
    service_verification_method: DidUrl,
    service_public_key: PublicKeyMaterial,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedAuthoringRoots {
    pub completion_digest: Hash,
    pub service_verification_method: DidUrl,
    pub service_public_key: PublicKeyMaterial,
    pub station_verification_method: DidUrl,
    pub station_public_key: PublicKeyMaterial,
    pub commit_verification_method: DidUrl,
    pub commit_public_key: PublicKeyMaterial,
}

fn invalid(message: impl std::fmt::Display) -> BridgeError {
    BridgeError::App(message.to_string())
}
fn original_key(actor: &ActorId) -> Result<String> {
    Ok(format!(
        "managed-authoring/original/{}",
        serde_json::to_string(actor)?
    ))
}
fn roots_key(actor: &ActorId) -> Result<String> {
    Ok(format!(
        "managed-authoring/original-roots/{}",
        serde_json::to_string(actor)?
    ))
}
fn preparation_key(event: &arkret::EventId) -> String {
    format!("managed-authoring/prepared/{event}")
}
fn encoded<T: Serialize>(value: &T) -> Result<String> {
    String::from_utf8(canonical_json_bytes(value)?).map_err(invalid)
}
pub(crate) fn authoring_scope(request: &AppletManagedActorAuthoringRequest) -> &ScopeRef {
    match &request.basis {
        arkret::AppletManagedActorAuthoringBasis::ProvisionBot(b) => &b.effective_scope,
        arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(b) => &b.effective_scope,
    }
}

pub(crate) fn creation_event(body: &AppletAuthoringTransactionRequestBody) -> Result<&Event> {
    match &body.authoring_context.material.result {
        RealmActorMaterial::Event { event, .. }
            if event.kind == arkret_wire::event_kind_str::REALM_ACTOR_CREATE =>
        {
            Ok(event)
        }
        _ => Err(invalid(
            "completion requires the exact accepted Realm actor creation",
        )),
    }
}
pub(crate) fn creation_payload(event: &Event) -> Result<RealmActorCreatePayload> {
    if event.kind != arkret_wire::event_kind_str::REALM_ACTOR_CREATE {
        return Err(invalid("expected Realm actor creation"));
    }
    let payload: RealmActorCreatePayload =
        serde_json::from_value(serde_json::to_value(&event.payload)?)?;
    payload.validate()?;
    Ok(payload)
}

pub(crate) fn validate_managed_authoring_completion(
    body: &AppletAuthoringTransactionRequestBody,
    source: &arkret::DidCoreId,
    applet: &AppletId,
    service: &arkret::DidCoreId,
) -> Result<ManagedAuthoringIdentity> {
    body.authoring_context.validate()?;
    let event = creation_event(body)?;
    let payload = creation_payload(event)?;
    let material = &body.authoring_context.material;
    if &body.source_id != source
        || &body.applet_id != applet
        || &payload.applet_id != applet
        || &payload.service_id != service
        || material.actor_id != payload.actor_id
        || material.requester_actor_id != ActorId::service(service.clone())
        || event.actor_id != ActorId::service(service.clone())
        || event.applet_id.as_ref() != Some(applet)
        || event.scope_ref
            != (ScopeRef::RealmControl {
                realm_id: material.realm_id.clone(),
            })
    {
        return Err(invalid("managed creation completion coordinates differ"));
    }
    Ok(ManagedAuthoringIdentity {
        applet_id: applet.clone(),
        actor_id: payload.actor_id,
        effective_scope: payload.creation_scope,
    })
}

pub(crate) fn validate_prepared_ghost_signer(
    method: &DidUrl,
    public_key: &PublicKeyMaterial,
) -> Result<[u8; 32]> {
    let bytes = public_key.ed25519_bytes().map_err(invalid)?;
    let multibase = arkret::ed25519_pubkey_to_did_key_multibase(&bytes);
    if method.as_str() != format!("did:key:{multibase}#{multibase}") {
        return Err(invalid(
            "custody root method differs from its exact public key",
        ));
    }
    Ok(bytes)
}

fn validate_prepared_root(
    candidate: &RealmActorCreatePayload,
    method: &DidUrl,
    key: &PublicKeyMaterial,
) -> Result<()> {
    validate_prepared_ghost_signer(method, key)?;
    let entries = candidate.method_history_evidence.webvh_material().1;
    if entries
        .first()
        .and_then(|entry| entry.pointer("/proof/0/verificationMethod"))
        .and_then(serde_json::Value::as_str)
        != Some(method.as_str())
    {
        return Err(invalid(
            "frozen custody root differs from the verified native inception",
        ));
    }
    Ok(())
}

impl AuthoringJournal {
    pub(crate) fn prepare_managed_authoring(
        &self,
        command: &PreparedManagedActor,
        root_method: &DidUrl,
        root_key: &PublicKeyMaterial,
        service_method: &DidUrl,
        service_key: &PublicKeyMaterial,
    ) -> Result<bool> {
        command.authoring_request.validate_bindings()?;
        let payload = creation_payload(&command.create_event)?;
        arkret::identity::verify_realm_actor_initial_resolution(
            &payload,
            command.create_event.created_at,
        )
        .map_err(invalid)?;
        validate_prepared_root(&payload, root_method, root_key)?;
        let basis = &command.authoring_request.basis;
        let (applet, scope, registration, grant, epoch) = match basis {
            arkret::AppletManagedActorAuthoringBasis::ProvisionBot(b) => {
                if payload.request_id != b.request_id
                    || payload.actor_role != arkret::RealmActorCreatePayloadActorRole::Bot
                {
                    return Err(invalid("Bot preparation differs from its request"));
                }
                (
                    &b.applet_id,
                    &b.effective_scope,
                    &b.registration_event_ref,
                    &b.authorization_ref,
                    &b.registration_epoch_evidence,
                )
            }
            arkret::AppletManagedActorAuthoringBasis::ProvisionGhost(b) => {
                let external = payload
                    .external_ref
                    .as_ref()
                    .ok_or_else(|| invalid("Ghost external mapping missing"))?;
                if b.existing_managed_actor.is_some()
                    || external.protocol != b.external_ref.protocol
                    || external.instance_id != b.external_ref.instance_id
                    || external.external_id != b.external_ref.external_id
                {
                    return Err(invalid("Ghost preparation differs from its mapping"));
                }
                (
                    &b.applet_id,
                    &b.effective_scope,
                    &b.registration_event_ref,
                    &b.authorization_ref,
                    &b.registration_epoch_evidence,
                )
            }
        };
        if &payload.applet_id != applet
            || &payload.creation_scope != scope
            || &payload.registration_ref != registration
            || &payload.creation_authorization_ref != grant
            || &payload.service_id != basis.service_id()
            || payload.expires_at != command.authoring_request.expires_at
        {
            return Err(invalid(
                "creation differs from the signed preparation request",
            ));
        }
        let key = preparation_key(&command.create_event.event_id);
        let mut preparation = Preparation {
            command: command.clone(),
            managed_actor_verification_method: root_method.clone(),
            managed_actor_public_key: root_key.clone(),
            service_verification_method: service_method.clone(),
            service_public_key: service_key.clone(),
        };
        if let Some(prior) = self.store.load(&key)? {
            let frozen: Preparation = serde_json::from_str(&prior)?;
            preparation.service_verification_method = frozen.service_verification_method;
            preparation.service_public_key = frozen.service_public_key;
            return if prior == encoded(&preparation)? {
                Ok(false)
            } else {
                Err(invalid(
                    "creation Event already has different frozen custody",
                ))
            };
        }
        if !epoch.contains_signing_key(service_method.as_str()) {
            return Err(invalid(
                "Service key is outside the signed registration epoch",
            ));
        }
        verify_creation_service(&command.create_event, service_method, service_key)?;
        if self.store.compare_exchange_batch(
            &[(key.clone(), None)],
            &[(key, Some(encoded(&preparation)?))],
        )? {
            Ok(true)
        } else {
            Err(invalid(
                "creation preparation contended; retry exact command",
            ))
        }
    }

    pub(crate) fn validate_prepared_creation(&self, command: &PreparedManagedActor) -> Result<()> {
        let raw = self
            .store
            .load(&preparation_key(&command.create_event.event_id))?
            .ok_or_else(|| invalid("creation has no locally frozen custody"))?;
        let prepared: Preparation = serde_json::from_str(&raw)?;
        if canonical_json_bytes(&prepared.command)? != canonical_json_bytes(command)? {
            return Err(invalid("creation differs from frozen custody"));
        }
        verify_creation_service(
            &command.create_event,
            &prepared.service_verification_method,
            &prepared.service_public_key,
        )
    }

    fn preparation(&self, body: &AppletAuthoringTransactionRequestBody) -> Result<Preparation> {
        let event = creation_event(body)?;
        let raw = self
            .store
            .load(&preparation_key(&event.event_id))?
            .ok_or_else(|| invalid("creation has no locally frozen custody"))?;
        let prepared: Preparation = serde_json::from_str(&raw)?;
        if canonical_json_bytes(&prepared.command.create_event)? != canonical_json_bytes(event)? {
            return Err(invalid("accepted creation differs from local frozen Event"));
        }
        Ok(prepared)
    }
    pub(crate) fn prepared_command(
        &self,
        body: &AppletAuthoringTransactionRequestBody,
    ) -> Result<PreparedManagedActor> {
        Ok(self.preparation(body)?.command)
    }
    pub(crate) fn prepared_service_root(
        &self,
        body: &AppletAuthoringTransactionRequestBody,
    ) -> Result<(DidUrl, PublicKeyMaterial)> {
        let prepared = self.preparation(body)?;
        verify_creation_service(
            &prepared.command.create_event,
            &prepared.service_verification_method,
            &prepared.service_public_key,
        )?;
        Ok((
            prepared.service_verification_method,
            prepared.service_public_key,
        ))
    }
    pub(crate) fn verify_prepared_managed_signer(
        &self,
        body: &AppletAuthoringTransactionRequestBody,
    ) -> Result<()> {
        let prepared = self.preparation(body)?;
        let candidate = creation_payload(&prepared.command.create_event)?;
        validate_prepared_root(
            &candidate,
            &prepared.managed_actor_verification_method,
            &prepared.managed_actor_public_key,
        )?;
        arkret::identity::verify_realm_actor_initial_resolution(
            &candidate,
            prepared.command.create_event.created_at,
        )
        .map_err(invalid)?;
        self.prepared_service_root(body)?;
        Ok(())
    }
    pub(crate) fn retained_managed_actor(
        &self,
        actor: &ActorId,
    ) -> Result<(AppletAuthoringTransactionRequestBody, ManagedAuthoringRoots)> {
        let body: AppletAuthoringTransactionRequestBody = serde_json::from_str(
            &self
                .store
                .load(&original_key(actor)?)?
                .ok_or_else(|| invalid("Realm actor has no accepted local creation"))?,
        )?;
        let roots: ManagedAuthoringRoots = serde_json::from_str(
            &self
                .store
                .load(&roots_key(actor)?)?
                .ok_or_else(|| invalid("Realm actor lost its original verification roots"))?,
        )?;
        if canonical_sha256(&body)? != roots.completion_digest.as_str() {
            return Err(invalid("retained creation root binding changed"));
        }
        self.verify_prepared_managed_signer(&body)?;
        Ok((body, roots))
    }
    pub(crate) fn managed_actor_ids(&self) -> Result<Vec<ActorId>> {
        self.store
            .entries_with_prefix("managed-authoring/original/")?
            .into_iter()
            .map(|(key, _)| {
                let actor: ActorId = serde_json::from_str(
                    key.strip_prefix("managed-authoring/original/")
                        .ok_or_else(|| invalid("creation index escaped its prefix"))?,
                )?;
                if actor.as_realm_actor_id().is_none() {
                    return Err(invalid("managed index requires full Realm ActorId"));
                }
                Ok(actor)
            })
            .collect()
    }

    /// Fresh signed envelopes may differ after handoff. The accepted Event,
    /// original Commit and historical signer fact must stay byte-identical.
    pub(crate) fn install_managed_authoring_delivery(
        &self,
        identity: &ManagedAuthoringIdentity,
        body: &AppletAuthoringTransactionRequestBody,
        roots: &ManagedAuthoringRoots,
        delivery: Option<&arkret::AppletDeliveryAuthenticationRecord>,
    ) -> Result<ManagedAuthoringInstall> {
        self.verify_prepared_managed_signer(body)?;
        let key = original_key(&identity.actor_id)?;
        let original = self.store.load(&key)?;
        let replay = original.is_some();
        let mut expected = vec![(key.clone(), original.clone())];
        let mut writes = Vec::new();
        if replay {
            let (prior, _) = self.retained_managed_actor(&identity.actor_id)?;
            if canonical_json_bytes(&prior.authoring_context.material.result)?
                != canonical_json_bytes(&body.authoring_context.material.result)?
            {
                return Err(invalid(
                    "creation completion conflicts with its immutable acceptance",
                ));
            }
        } else if canonical_sha256(body)? != roots.completion_digest.as_str() {
            return Err(invalid("verification roots cover a different completion"));
        } else {
            let root_key = roots_key(&identity.actor_id)?;
            expected.push((root_key.clone(), None));
            writes.extend([
                (key, Some(encoded(body)?)),
                (root_key, Some(encoded(roots)?)),
            ]);
        }
        if let Some(record) = delivery {
            let receipt_key = delivery_key(record)?;
            let prior = self.store.load(&receipt_key)?;
            if delivery_receipt_conflicts(
                prior.as_deref(),
                &Hash::new(canonical_sha256(body)?)?,
                record,
            )? {
                return Err(invalid(
                    "duplicate_conflict: completion differs from its durable delivery receipt",
                ));
            }
            expected.push((receipt_key.clone(), prior.clone()));
            if prior.is_none() {
                writes.push((
                    receipt_key,
                    Some(encoded(&ManagedDeliveryReceipt {
                        canonical_body_digest: Hash::new(canonical_sha256(body)?)?,
                        stable_digest: record.stable_digest().map_err(invalid)?,
                        record: record.clone(),
                        outcome: completion_outcome(),
                    })?),
                ));
            }
            // Keep each verified signature's complete record; times never
            // participate in the stable idempotency identity.
            let audit_key = format!(
                "managed-authoring/delivery-audit/{}",
                canonical_sha256(record)?
            );
            let prior_audit = self.store.load(&audit_key)?;
            expected.push((audit_key.clone(), prior_audit));
            writes.push((audit_key, Some(encoded(record)?)));
        }
        if writes.is_empty() || self.store.compare_exchange_batch(&expected, &writes)? {
            Ok(if replay {
                ManagedAuthoringInstall::ExactReplay
            } else {
                ManagedAuthoringInstall::Installed
            })
        } else {
            Err(invalid(
                "creation installation contended; retry exact completion",
            ))
        }
    }

    pub(crate) fn managed_delivery_admission(
        &self,
        body: &AppletAuthoringTransactionRequestBody,
        record: &arkret::AppletDeliveryAuthenticationRecord,
    ) -> Result<ManagedDeliveryAdmission> {
        let Some(raw) = self.store.load(&delivery_key(record)?)? else {
            return Ok(ManagedDeliveryAdmission::New);
        };
        if delivery_receipt_conflicts(Some(&raw), &Hash::new(canonical_sha256(body)?)?, record)? {
            return Ok(ManagedDeliveryAdmission::Conflict);
        }
        let receipt: ManagedDeliveryReceipt = serde_json::from_str(&raw)?;
        Ok(ManagedDeliveryAdmission::Accepted(receipt.outcome))
    }
    pub(crate) fn load_managed_authoring(
        &self,
        identity: &ManagedAuthoringIdentity,
    ) -> Result<Option<AppletAuthoringTransactionRequestBody>> {
        if self
            .store
            .load(&original_key(&identity.actor_id)?)?
            .is_none()
        {
            return Ok(None);
        }
        let (body, _) = self.retained_managed_actor(&identity.actor_id)?;
        if body.applet_id != identity.applet_id
            || identity.actor_id.as_realm_actor_id().map(|id| &id.realm_id)
                != identity.effective_scope.realm_id_opt()
        {
            return Err(invalid(
                "local creation requested for another Applet or Realm",
            ));
        }
        Ok(Some(body))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedDeliveryReceipt {
    canonical_body_digest: Hash,
    stable_digest: Hash,
    record: arkret::AppletDeliveryAuthenticationRecord,
    outcome: arkret::AppletTransactionOutcome,
}

fn delivery_receipt_conflicts(
    raw: Option<&str>,
    body_digest: &Hash,
    record: &arkret::AppletDeliveryAuthenticationRecord,
) -> Result<bool> {
    let Some(raw) = raw else {
        return Ok(false);
    };
    let prior: ManagedDeliveryReceipt = serde_json::from_str(raw)?;
    Ok(
        prior.stable_digest != prior.record.stable_digest().map_err(invalid)?
            || prior.stable_digest != record.stable_digest().map_err(invalid)?
            || prior.canonical_body_digest != *body_digest
            || prior.outcome != completion_outcome(),
    )
}

fn completion_outcome() -> arkret::AppletTransactionOutcome {
    arkret::AppletTransactionOutcome::Accepted {
        committed_event_refs: Vec::new(),
        rejections: Vec::new(),
        retry_after_ms: None,
    }
}

fn delivery_key(record: &arkret::AppletDeliveryAuthenticationRecord) -> Result<String> {
    Ok(format!(
        "managed-authoring/delivery/{}",
        encoded(&(
            record.operation_id,
            record.direction,
            &record.source_id,
            &record.destination_id,
            &record.idempotency_key,
        ))?
    ))
}

pub(crate) fn verify_creation_service(
    event: &Event,
    method: &DidUrl,
    key: &PublicKeyMaterial,
) -> Result<()> {
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| invalid("creation producer proof missing"))?;
    if proof.verification_method != *method || event.executed_by.is_some() {
        return Err(invalid(
            "creation Service signer differs from frozen custody",
        ));
    }
    let bytes = canonical_json_bytes(&event.digest_payload()?)?;
    arkret::signatures::verify_ed25519_detached_jws_proof(proof, &bytes, &event.actor_id, key)
        .map_err(invalid)
}

#[cfg(test)]
mod delivery_receipt_tests {
    use super::*;
    use crate::{AuthoringStore, FileAuthoringStore};

    fn record() -> arkret::AppletDeliveryAuthenticationRecord {
        serde_json::from_value(serde_json::json!({
            "operation_id":"ak.edge.applet.command.transaction.v1", "direction":"node_to_applet",
            "source_id":"ak:did_core:webvh:zstation", "destination_id":"ak:did_core:webvh:zapplet",
            "signature_label":"sig1", "verification_method":"did:webvh:zstation:station.example#key-1",
            "verification_key_digest":format!("sha256:{}", "1".repeat(64)), "signature_algorithm":"ed25519",
            "registration_epoch":format!("sha256:{}", "2".repeat(64)), "idempotency_key":"completion-1",
            "content_digest":"sha-256=:Zm94:", "covered_components":["@method","content-digest","idempotency-key"],
            "created":1800000000, "expires":1800000300
        })).unwrap()
    }

    #[test]
    fn cold_delivery_receipt_keeps_full_times_and_rejects_changed_body_or_authority() {
        let directory = std::env::temp_dir().join(format!(
            "bridge-delivery-receipt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("journal.redb");
        let first = record();
        let body_digest = Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap();
        let key = delivery_key(&first).unwrap();
        let receipt = ManagedDeliveryReceipt {
            canonical_body_digest: body_digest.clone(),
            stable_digest: first.stable_digest().unwrap(),
            record: first.clone(),
            outcome: completion_outcome(),
        };
        {
            let store = FileAuthoringStore::new(path.clone()).unwrap();
            assert!(
                store
                    .compare_exchange_batch(
                        &[(key.clone(), None)],
                        &[(key.clone(), Some(encoded(&receipt).unwrap()))]
                    )
                    .unwrap()
            );
        }
        {
            let reopened = FileAuthoringStore::new(path).unwrap();
            let raw = reopened.load(&key).unwrap().unwrap();
            let restored: ManagedDeliveryReceipt = serde_json::from_str(&raw).unwrap();
            assert_eq!(restored.record, first);
            let mut retry = first.clone();
            retry.created += 20;
            retry.expires += 20;
            assert!(!delivery_receipt_conflicts(Some(&raw), &body_digest, &retry).unwrap());
            assert!(
                delivery_receipt_conflicts(
                    Some(&raw),
                    &Hash::new(format!("sha256:{}", "4".repeat(64))).unwrap(),
                    &retry
                )
                .unwrap()
            );
            retry.registration_epoch = Hash::new(format!("sha256:{}", "5".repeat(64))).unwrap();
            assert!(delivery_receipt_conflicts(Some(&raw), &body_digest, &retry).unwrap());
            retry = first.clone();
            retry.verification_key_digest =
                Hash::new(format!("sha256:{}", "6".repeat(64))).unwrap();
            assert!(delivery_receipt_conflicts(Some(&raw), &body_digest, &retry).unwrap());
            assert_eq!(restored.outcome, completion_outcome());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn receipt_identity_is_closed_and_retained_digest_corruption_fails_closed() {
        let first = record();
        let digest = Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap();
        let mut receipt = ManagedDeliveryReceipt {
            canonical_body_digest: digest.clone(),
            stable_digest: Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap(),
            record: first.clone(),
            outcome: completion_outcome(),
        };
        assert!(
            delivery_receipt_conflicts(Some(&encoded(&receipt).unwrap()), &digest, &first).unwrap()
        );
        receipt.stable_digest = first.stable_digest().unwrap();
        let mut other = first.clone();
        other.destination_id = arkret::DidCoreId::new("ak:did_core:webvh:zother").unwrap();
        assert_ne!(delivery_key(&first).unwrap(), delivery_key(&other).unwrap());
        assert!(
            !delivery_receipt_conflicts(Some(&encoded(&receipt).unwrap()), &digest, &first)
                .unwrap()
        );
    }
}
