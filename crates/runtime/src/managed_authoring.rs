//! Local custody preparation and immutable accepted Realm creation journal.
//! These records are host storage, never additional protocol wire carriers.
use arkret::canonical::{canonical_json_bytes, canonical_sha256};
use arkret::signatures::PublicKeyMaterial;
use arkret::{
    ActorId, AppletAuthoringTransactionRequestBody, AppletId, AppletManagedActorAuthoringRequest,
    Did, DidUrl, Event, Hash, RealmActorCreatePayload, RealmActorMaterialResult, ScopeRef,
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
    Create(PreparedManagedActor),
    Reuse {
        authoring_request: AppletManagedActorAuthoringRequest,
        existing: arkret::ExistingManagedActor,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct ManagedAuthoringIdentity {
    pub applet_id: AppletId,
    pub actor_id: ActorId,
    pub effective_scope: ScopeRef,
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
        RealmActorMaterialResult::Event { event, .. }
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
    pub(crate) fn install_managed_authoring(
        &self,
        identity: &ManagedAuthoringIdentity,
        body: &AppletAuthoringTransactionRequestBody,
        roots: &ManagedAuthoringRoots,
    ) -> Result<ManagedAuthoringInstall> {
        self.verify_prepared_managed_signer(body)?;
        let key = original_key(&identity.actor_id)?;
        if self.store.load(&key)?.is_some() {
            let (prior, _) = self.retained_managed_actor(&identity.actor_id)?;
            if canonical_json_bytes(&prior.authoring_context.material.result)?
                != canonical_json_bytes(&body.authoring_context.material.result)?
            {
                return Err(invalid(
                    "creation completion conflicts with its immutable acceptance",
                ));
            }
            return Ok(ManagedAuthoringInstall::ExactReplay);
        }
        if canonical_sha256(body)? != roots.completion_digest.as_str() {
            return Err(invalid("verification roots cover a different completion"));
        }
        let root_key = roots_key(&identity.actor_id)?;
        if self.store.compare_exchange_batch(
            &[(key.clone(), None), (root_key.clone(), None)],
            &[
                (key, Some(encoded(body)?)),
                (root_key, Some(encoded(roots)?)),
            ],
        )? {
            Ok(ManagedAuthoringInstall::Installed)
        } else {
            Err(invalid(
                "creation installation contended; retry exact completion",
            ))
        }
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
    pub(crate) fn reused_ghost_did(
        &self,
        request: &AppletManagedActorAuthoringRequest,
        existing: &arkret::ExistingManagedActor,
    ) -> Result<Did> {
        let basis = request
            .basis
            .ghost()
            .ok_or_else(|| invalid("Ghost reuse requires a Ghost basis"))?;
        let (body, _) = self.retained_managed_actor(&existing.ghost_actor_id)?;
        let RealmActorMaterialResult::Event { event, commit, .. } =
            &body.authoring_context.material.result
        else {
            return Err(invalid("original creation material missing"));
        };
        let payload = creation_payload(event)?;
        let expected = arkret::CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: commit.commit_id.clone(),
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
        };
        let external = payload
            .external_ref
            .ok_or_else(|| invalid("reuse target is not a Ghost"))?;
        if payload.applet_id != basis.applet_id
            || payload.service_id != basis.service_id
            || payload.actor_id != existing.ghost_actor_id
            || expected != existing.creation_ref
            || existing
                .ghost_actor_id
                .as_realm_actor_id()
                .map(|id| &id.realm_id)
                != basis.effective_scope.realm_id_opt()
            || external.protocol != basis.external_ref.protocol
            || external.instance_id != basis.external_ref.instance_id
            || external.external_id != basis.external_ref.external_id
        {
            return Err(invalid(
                "Ghost reuse differs from the original Realm identity and mapping",
            ));
        }
        Ok(payload.initial_resolution.did)
    }
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
