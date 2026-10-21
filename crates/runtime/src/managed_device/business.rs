//! Native Realm Device publication, with the send ratchet and original bytes
//! committed in the same encrypted custody CAS before network submission.
use arkret_event_draft::EventSpec;
use arkret_models_collaboration::events_payloads::{
    CapabilityGrantCreateBody, CapabilityGrantPayload, MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE,
    MESSAGE_METADATA_MLS_CONTENT_TYPE, MessageCreatePayload, MessageRedactPayload,
    StrandCreatePayload,
};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilityGrant, CapabilitySubject, GrantConstraintEffect, GrantConstraintKind,
    GrantConstraintSubkind, IssuerAuthorityRef, ManagedActorRole,
};

use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedPublication {
    input_digest: String,
    device_operation_id: String,
    event: AuthoredEvent,
    outcome: Option<AuthoritySubmitOutcome>,
    commit_key: Option<PublicKeyMaterial>,
}

struct ContentIntent<P> {
    operation: String,
    digest: String,
    at: chrono::DateTime<Utc>,
    content: P,
    external: serde_json::Map<String, serde_json::Value>,
    encrypt: bool,
}

/// Reject only resource scopes known to be disjoint. More specific objects
/// still need the Station's resource/ancestry evaluator; they are not widened
/// into a Realm or Circle selector here.
fn parent_scope_candidate(grant: &CapabilityGrant, scope: &ScopeRef) -> bool {
    grant.resources.iter().any(|resource| {
        if resource.realm_id.as_ref() != Some(scope.realm_id()) {
            return false;
        }
        match resource.kind {
            arkret::ResourceSelectorKind::Circle => matches!(scope,
                ScopeRef::Circle { circle_id, .. } if resource.circle_id.as_ref() == Some(circle_id)),
            arkret::ResourceSelectorKind::Realm => {
                matches!(scope, ScopeRef::Realm { .. })
                    || resource.match_scope == Some(arkret::ResourceMatchScope::RealmWide)
            }
            _ => true,
        }
    })
}

impl ManagedDeviceRuntime {
    /// Bootstrap only the explicitly configured Device scopes and finite window.
    pub async fn device_for_actor(&self, actor: &ActorId) -> Result<ManagedDevice> {
        let config = self
            .edge
            .config()
            .arkret
            .managed_actor_authoring
            .device
            .as_ref()
            .ok_or_else(|| {
                BridgeError::Config("native managed Device configuration is required".into())
            })?;
        config.validate()?;
        let seconds = i64::try_from(config.lifetime_seconds)
            .map_err(|_| invalid("Device lifetime overflow"))?;
        let lifetime = chrono::TimeDelta::try_seconds(seconds)
            .ok_or_else(|| invalid("Device lifetime overflow"))?;
        let mut actions = config.actions.clone();
        actions.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        actions.dedup();
        self.bootstrap_actor(actor, &actions, lifetime).await
    }

    async fn service_grants(&self, device: &ManagedDevice) -> Result<Vec<CapabilityGrant>> {
        let route = self
            .edge
            .realm_route(device.effective_scope.realm_id())
            .await?;
        let service = ActorId::service(self.edge.service_actor_id().clone());
        let list = route
            .client
            .effective_grants(device.effective_scope.realm_id(), &service)
            .await?;
        let mut grants: Vec<_> = list
            .grants
            .into_iter()
            .map(|row| row.grant)
            .filter(|grant| {
                matches!(&grant.subject, CapabilitySubject::Actor(actor) if actor == &service)
                    && grant.realm_id.as_ref() == Some(device.effective_scope.realm_id())
            })
            .collect();
        grants.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(grants)
    }

    /// Select only an actual Service parent; the governing Station validates
    /// its current installation, role, narrowing, quotas and approval constraints.
    pub(super) async fn terminal_child(
        &self,
        device: &ManagedDevice,
        action: &str,
    ) -> Result<arkret::GrantId> {
        let original = self.edge.retained_managed_actor(&device.actor_id)?;
        let creation = crate::managed_authoring::creation_payload(
            crate::managed_authoring::creation_event(&original)?,
        )?;
        let role = match creation.actor_role {
            arkret::RealmActorCreatePayloadActorRole::Bot => ManagedActorRole::Bot,
            arkret::RealmActorCreatePayloadActorRole::Ghost => ManagedActorRole::Ghost,
        };
        let service = ActorId::service(self.edge.service_actor_id().clone());
        let parent = self
            .service_grants(device)
            .await?
            .into_iter()
            .find(|grant| {
                parent_scope_candidate(grant, &device.effective_scope)
                    && grant.actions.iter().any(|item| item == action)
                    && grant.constraints.iter().any(|c| {
                        c.constraint_kind == GrantConstraintKind::AuthorityControl
                            && c.constraint_subkind.is_none()
                            && c.effect == GrantConstraintEffect::Allow
                            && c.allowed_managed_actor_roles.contains(&role)
                    })
                    && grant
                        .constraints
                        .iter()
                        .filter(|c| {
                            c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
                                && c.applet_id.as_ref() == Some(&creation.applet_id)
                                && c.executed_by.as_ref() == Some(&service)
                        })
                        .count()
                        == 1
            })
            .ok_or_else(|| {
                BridgeError::App(format!(
                    "no current approved Service parent covers {action}"
                ))
            })?;
        let operation = format!("managed-child/{}/{action}/{}", device.actor_id, parent.id);
        if let Some(event) = self
            .edge
            .retained_publication(device.effective_scope.realm_id(), &service, &operation)
            .await?
        {
            self.edge.submit_event(&event).await?;
            return Ok(arkret::GrantId::from_event_id(event.event_id()));
        }
        let mut constraints = parent.constraints.clone();
        for c in &mut constraints {
            if c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority) {
                c.executed_by = Some(device.actor_id.clone());
            } else if c.constraint_kind == GrantConstraintKind::AuthorityControl
                && c.constraint_subkind.is_none()
                && c.effect == GrantConstraintEffect::Allow
            {
                c.allowed_managed_actor_roles.clear();
                c.max_authority_depth = Some(0);
                c.authority_regrant_allowed = Some(false);
            }
        }
        let at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
        let body = CapabilityGrantPayload {
            grant: CapabilityGrantCreateBody {
                schema: parent.schema,
                realm_id: parent.realm_id,
                issuer_id: service.clone(),
                subject: CapabilitySubject::Actor(device.actor_id.clone()),
                actions: vec![action.to_owned()],
                resources: parent.resources,
                constraints,
                issued_at: at,
                issuer_authority_refs: vec![IssuerAuthorityRef::Grant {
                    grant_id: parent.id.clone(),
                }],
            },
        };
        let intent = TypedEventDraft::<event_spec::CapabilityGrant>::new(
            device.effective_scope.clone(),
            service,
            body,
        )?
        .with_applet_id(creation.applet_id)
        .with_authorization_ref(parent.id.into())
        .into_intent(at)?;
        let event = self
            .edge
            .author_and_sign(device.effective_scope.realm_id(), &operation, intent)
            .await?;
        self.edge.submit_event(&event).await?;
        Ok(arkret::GrantId::from_event_id(event.event_id()))
    }

    /// Subject-only Realm membership still uses the existing join rules and
    /// management gate. An approval-required outcome remains pending at the host.
    pub async fn ensure_realm_membership(&self, device: &ManagedDevice) -> Result<()> {
        if let ScopeRef::Circle {
            realm_id,
            circle_id,
        } = &device.effective_scope
        {
            // A Circle-only Device cannot author a Realm membership write.
            // Existing admission is established through the exact scoped
            // current projection; this read never admits a new member.
            let reader = self.open_reader(device).await?;
            let response = reader.client().snapshot_head(realm_id).await?;
            let snapshot =
                garth::own_station_results::consume_own_station_device_snapshot(&response)
                    .map_err(|e| invalid(e.to_string()))?;
            let joined = snapshot.current_state_entries.iter().any(|row| {
                let arkret::TypedCurrentRow::Value {
                    selector, value, ..
                } = row;
                matches!(selector, arkret::CurrentSelector::CircleMemberState {
                    circle_id: actual, member_actor_id,
                } if actual == circle_id && member_actor_id == &device.actor_id)
                    && serde_json::to_value(value).is_ok_and(|value| value["membership"] == "join")
            });
            return if joined {
                Ok(())
            } else {
                Err(BridgeError::App(
                    "Circle membership admission is not yet accepted".into(),
                ))
            };
        }
        if !matches!(device.effective_scope, ScopeRef::Realm { .. }) {
            return Err(invalid("managed membership requires a Realm or Circle"));
        }
        let body = serde_json::from_value(
            serde_json::json!({"member_id":device.actor_id,"membership":"join"}),
        )?;
        let digest = canonical_sha256(&(&device.actor_id, "realm-self-join"))?;
        if let Some(event) = self
            .retained_device_publication(device, "realm-self-join", &digest)
            .await?
        {
            self.submit_device_original(device, "realm-self-join", event)
                .await?;
            return Ok(());
        }
        let installation_source = self.subject_installation_source(device).await?;
        let intent = TypedEventDraft::<event_spec::MemberState>::new(
            device.effective_scope.clone(),
            device.actor_id.clone(),
            body,
        )?
        .with_applet_id(arkret::AppletId::new(
            self.edge.config().arkret.applet_id.clone(),
        )?)
        .with_authorization_ref(installation_source.into())
        .into_intent(Utc::now())?;
        let event = self
            .freeze_device_intent(device, "realm-self-join", &digest, intent)
            .await?;
        self.submit_device_original(device, "realm-self-join", event)
            .await?;
        Ok(())
    }

    /// Join the Circle with the subject's own Device, using the accepted
    /// parent join as its exact dependency. Both installations and all
    /// existing membership permissions remain independently required. Before
    /// joining a parent scope different from the identity's creation scope,
    /// retain that scope's actual SDK install response with
    /// [`Self::remember_installation_outcome`]; no grant-list discovery fallback
    /// can establish membership in an installation aggregate.
    pub async fn join_circle_after_realm_join(
        &self,
        device: &ManagedDevice,
        parent_device: &ManagedDevice,
    ) -> Result<()> {
        let ScopeRef::Circle {
            realm_id,
            circle_id,
        } = &device.effective_scope
        else {
            return Err(invalid("Circle membership requires a Circle Device"));
        };
        if device.actor_id != parent_device.actor_id
            || parent_device.effective_scope
                != (ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                })
        {
            return Err(invalid(
                "Circle parent join belongs to another subject or Realm",
            ));
        }
        self.ensure_realm_membership(parent_device).await?;
        let (_, _, saved) = self
            .publication(
                &parent_device.actor_id,
                &parent_device.effective_scope,
                "realm-self-join",
            )
            .await?
            .ok_or_else(|| invalid("accepted parent join is unavailable"))?;
        if Self::accepted_publication(&saved)?.is_none() {
            return Err(invalid("parent membership is not yet accepted"));
        }
        let Some(AuthoritySubmitOutcome::Accepted { commit, .. }) = saved.outcome else {
            return Err(invalid("parent membership has no accepted Commit"));
        };
        let revision = arkret::CurrentRevision {
            commit_id: commit.commit_id,
            stream_position: commit.stream_position,
        };
        let digest = canonical_sha256(&(&device.actor_id, &device.effective_scope, &revision))?;
        if let Some(event) = self
            .retained_device_publication(device, "circle-self-join", &digest)
            .await?
        {
            self.submit_device_original(device, "circle-self-join", event)
                .await?;
            return Ok(());
        }
        let child = self.terminal_child(device, "ak.circle.member.add").await?;
        let body = serde_json::from_value(serde_json::json!({
            "circle_id": circle_id, "member_id": device.actor_id,
            "membership": "join", "parent_membership_revision": revision,
        }))?;
        let intent = TypedEventDraft::<event_spec::CircleMemberState>::new(
            device.effective_scope.clone(),
            device.actor_id.clone(),
            body,
        )?
        .with_applet_id(arkret::AppletId::new(
            self.edge.config().arkret.applet_id.clone(),
        )?)
        .with_authorization_ref(child.into())
        .into_intent(Utc::now())?;
        let event = self
            .freeze_device_intent(device, "circle-self-join", &digest, intent)
            .await?;
        self.submit_device_original(device, "circle-self-join", event)
            .await?;
        Ok(())
    }

    fn publication_key(actor: &ActorId, scope: &ScopeRef, operation: &str) -> Result<String> {
        Ok(format!(
            "managed-publication/v1/{}",
            canonical_sha256(&(actor, scope, operation))?
        ))
    }

    async fn publication(
        &self,
        actor: &ActorId,
        scope: &ScopeRef,
        operation: &str,
    ) -> Result<Option<(String, String, ManagedPublication)>> {
        let key = Self::publication_key(actor, scope, operation)?;
        let Some(raw) = self.read(&key).await? else {
            return Ok(None);
        };
        let record: ManagedPublication = self.authoring.decrypt_key_material(&key, &raw)?;
        record.event.verify_identity()?;
        if &record.event.actor_id != actor
            || &record.event.scope_ref != scope
            || record.event.executed_by.is_some()
        {
            return Err(invalid(
                "publication index differs from its original actor or scope",
            ));
        }
        Ok(Some((key, raw, record)))
    }

    fn accepted_publication(saved: &ManagedPublication) -> Result<Option<String>> {
        let Some(AuthoritySubmitOutcome::Accepted { commit, .. }) = &saved.outcome else {
            return Ok(None);
        };
        arkret::signatures::detached_object::verify_detached_object_signature(
            &commit.signature,
            &arkret::canonical::unsigned_value(commit, &["signature"])?,
            DetachedSignatureContext::RealmCommit,
            saved
                .commit_key
                .as_ref()
                .ok_or_else(|| invalid("publication Commit key missing"))?,
        )
        .map_err(|e| invalid(e.to_string()))?;
        crate::authoring::publication_outcome(&saved.event, saved.outcome.as_ref().unwrap())?;
        Ok(Some(saved.event.event_id().to_string()))
    }

    async fn retained_device_publication(
        &self,
        device: &ManagedDevice,
        operation: &str,
        digest: &str,
    ) -> Result<Option<AuthoredEvent>> {
        match self
            .publication(&device.actor_id, &device.effective_scope, operation)
            .await?
        {
            Some((_, _, saved))
                if saved.input_digest == digest
                    && saved.device_operation_id == device.operation_id =>
            {
                Ok(Some(saved.event))
            }
            Some(_) => Err(invalid(
                "delivery identity already binds different content or Device",
            )),
            None => Ok(None),
        }
    }

    /// Atomically freeze original ciphertext with the advanced private send
    /// ratchet. The publication is indexed separately so each send is bounded
    /// by current group state, rather than rewriting all previous messages.
    async fn freeze_publication(
        &self,
        device: &ManagedDevice,
        operation: &str,
        digest: &str,
        event: &AuthoredEvent,
        device_key: String,
        previous: String,
        record: &DeviceRecord,
    ) -> Result<bool> {
        let publication_key =
            Self::publication_key(&device.actor_id, &device.effective_scope, operation)?;
        let publication = ManagedPublication {
            input_digest: digest.into(),
            device_operation_id: device.operation_id.clone(),
            event: event.clone(),
            outcome: None,
            commit_key: None,
        };
        let encrypted_publication = self
            .authoring
            .encrypt_key_material(&publication_key, &publication)?;
        let encrypted_device = self.authoring.encrypt_key_material(&device_key, record)?;
        let event_key = Self::publication_event_key(event.event_id())?;
        let store = self.store.clone();
        run_blocking(move || {
            store.compare_exchange_batch(
                &[
                    (device_key.clone(), Some(previous)),
                    (publication_key.clone(), None),
                    (event_key.clone(), None),
                ],
                &[
                    (device_key, Some(encrypted_device)),
                    (event_key, Some(publication_key.clone())),
                    (publication_key, Some(encrypted_publication)),
                ],
            )
        })
        .await
    }

    fn publication_event_key(id: &arkret::EventId) -> Result<String> {
        Ok(format!(
            "managed-publication-event/v1/{}",
            canonical_sha256(id)?
        ))
    }

    pub(super) async fn is_local_publication(&self, event: &arkret::Event) -> Result<bool> {
        let Some(key) = self
            .read(&Self::publication_event_key(&event.event_id)?)
            .await?
        else {
            return Ok(false);
        };
        let raw = self
            .read(&key)
            .await?
            .ok_or_else(|| invalid("publication index has no original"))?;
        let saved: ManagedPublication = self.authoring.decrypt_key_material(&key, &raw)?;
        if saved.event.event() != event {
            return Err(invalid("publication index has different original bytes"));
        }
        Ok(true)
    }

    /// A withdrawn local send has already advanced this Device's send ratchet.
    /// Only its exact accepted Commit may advance the stream without opening
    /// content again. This never returns plaintext or acknowledges remote work.
    pub(super) async fn already_applied_local_content(
        &self,
        device: &ManagedDevice,
        commit: &RealmCommit,
    ) -> Result<bool> {
        let Some(key) = self
            .read(&Self::publication_event_key(&commit.event_ref)?)
            .await?
        else {
            return Ok(false);
        };
        let raw = self
            .read(&key)
            .await?
            .ok_or_else(|| invalid("local publication index has no original"))?;
        let saved: ManagedPublication = self.authoring.decrypt_key_material(&key, &raw)?;
        saved.event.verify_identity()?;
        if saved.event.event_id() != &commit.event_ref {
            return Err(invalid("local publication index names another Event"));
        }
        if saved.event.actor_id != device.actor_id
            || saved.event.scope_ref != device.effective_scope
            || saved.device_operation_id != device.operation_id
            || !matches!(
                saved.event.kind,
                arkret::EventKind::MessageCreate
                    | arkret::EventKind::MessageRedact
                    | arkret::EventKind::StrandCreate
            )
        {
            return Ok(false);
        }
        if Self::accepted_publication(&saved)?.is_none() {
            return Ok(false);
        }
        let Some(AuthoritySubmitOutcome::Accepted {
            commit: retained, ..
        }) = &saved.outcome
        else {
            return Ok(false);
        };
        if retained != commit {
            return Err(invalid("local content has a different accepted Commit"));
        }
        Ok(true)
    }

    fn sign_device_intent(
        &self,
        device: &ManagedDevice,
        intent: arkret::EventIntent,
    ) -> Result<AuthoredEvent> {
        if intent.actor_id() != &device.actor_id
            || intent.realm_id_opt() != Some(device.effective_scope.realm_id())
        {
            return Err(invalid("Device intent belongs to another actor or Realm"));
        }
        let at = arkret::canonical::normalize_timestamp_canonical(intent.created_at());
        let mut event = intent
            .with_created_at(at)
            .author_with_digest_suite(crate::PRODUCER_DIGEST_SUITE)?;
        sign_event(
            &mut event,
            device.signer(),
            SignEventOptions::new().with_created_at(at),
        )?;
        Ok(event)
    }

    async fn freeze_device_intent(
        &self,
        device: &ManagedDevice,
        operation: &str,
        digest: &str,
        intent: arkret::EventIntent,
    ) -> Result<AuthoredEvent> {
        for _ in 0..8 {
            if let Some(event) = self
                .retained_device_publication(device, operation, digest)
                .await?
            {
                return Ok(event);
            }
            let (key, previous, record) = self.accepted_device_record(device).await?;
            let event = self.sign_device_intent(device, intent.clone())?;
            if self
                .freeze_publication(device, operation, digest, &event, key, previous, &record)
                .await?
            {
                return Ok(event);
            }
        }
        Err(invalid("Device publication custody contended"))
    }

    async fn submit_device_original(
        &self,
        device: &ManagedDevice,
        operation: &str,
        event: AuthoredEvent,
    ) -> Result<String> {
        let (_, _, saved) = self
            .publication(&device.actor_id, &device.effective_scope, operation)
            .await?
            .ok_or_else(|| invalid("Device publication missing"))?;
        if saved.device_operation_id != device.operation_id {
            return Err(invalid(
                "publication belongs to another Device authorization",
            ));
        }
        if saved.event != event {
            return Err(invalid("Device publication bytes changed"));
        }
        event.verify_identity()?;
        if event.actor_id != device.actor_id
            || event.scope_ref != device.effective_scope
            || event.executed_by.is_some()
            || event
                .producer_proof
                .as_ref()
                .map(|p| p.verification_method.as_str())
                != Some(device.signer().verification_method())
        {
            return Err(invalid("frozen publication differs from its native Device"));
        }
        if let Some(event_id) = Self::accepted_publication(&saved)? {
            return Ok(event_id);
        }
        self.accepted_device_record(device).await?;
        let producer = arkret::ProducerVerificationContext {
            actor: device.actor_id.clone(),
            verification_method: arkret::DidUrl::new(device.signer().verification_method())
                .map_err(invalid)?,
            public_key: PublicKeyMaterial::Ed25519Raw {
                bytes: device.signer().verifying_key().to_bytes().to_vec(),
            },
            digest_suite: crate::PRODUCER_DIGEST_SUITE,
        };
        let request = arkret::VerifiedSubmission::verify(
            SelfAuthoritySubmitRequest::Event(EventAdmissionSubmission::new(event.event().clone())),
            |_| Ok(producer.clone()),
        )
        .map_err(|e| invalid(e.to_string()))?;
        let SelfAuthoritySubmitOutcome::Ordinary(outcome) = device
            .client()
            .submit_to_realm_authority(
                &request,
                &arkret::ClientRequestOptions::new().idempotency_key(event.event_id().as_str()),
            )
            .await?
        else {
            return Err(invalid("Device Event returned aggregate result"));
        };
        let mut key = None;
        if let AuthoritySubmitOutcome::Accepted { commit, .. } = &outcome {
            let route = self
                .edge
                .realm_route(device.effective_scope.realm_id())
                .await?;
            let keys = garth::historical_station_keys::fetch_historical_station_keys_for_commits(
                &route.client,
                &route.bundle,
                &[commit],
            )
            .await
            .map_err(|e| invalid(e.to_string()))?;
            route
                .authority
                .verify_commit(commit, &keys)
                .map_err(|e| invalid(e.to_string()))?;
            let issuer = route
                .authority
                .authority_service_at(commit.governance_generation)
                .ok_or_else(|| invalid("publication has no lawful issuer"))?;
            key = Some(
                route
                    .historical_station_key(
                        issuer,
                        &commit.signature.verification_method,
                        commit.committed_at,
                    )
                    .await?,
            );
        }
        let committed = crate::authoring::publication_outcome(&event, &outcome)?;
        for _ in 0..8 {
            let (storage_key, previous, mut saved) = self
                .publication(&device.actor_id, &device.effective_scope, operation)
                .await?
                .ok_or_else(|| invalid("publication vanished"))?;
            if saved.event != event {
                return Err(invalid("original publication changed"));
            }
            if let Some(AuthoritySubmitOutcome::Accepted { commit, .. }) = &saved.outcome {
                if committed
                    .as_ref()
                    .is_some_and(|r| r.commit_id != commit.commit_id)
                {
                    return Err(invalid("publication accepted twice"));
                }
                return Ok(event.event_id().to_string());
            }
            saved.outcome = Some(outcome.clone());
            saved.commit_key = key.clone();
            let encrypted = self.authoring.encrypt_key_material(&storage_key, &saved)?;
            if self.cas(&storage_key, Some(previous), encrypted).await? {
                return committed.map(|r| r.event_id.to_string()).ok_or_else(|| {
                    BridgeError::App(
                        "governance Station did not accept the Device publication".into(),
                    )
                });
            }
        }
        Err(invalid("Device outcome persistence contended"))
    }

    pub async fn submit_message<E: Serialize>(
        &self,
        actor: &ActorId,
        scope: &ScopeRef,
        payload: MessageCreatePayload,
        external: E,
    ) -> Result<String> {
        if let Some(content) = &payload.content {
            let value = content.to_value()?;
            arkret_models_collaboration::events_payloads::validate_content_block(&value)
                .map_err(|error| invalid(error.to_string()))?;
            arkret_models_collaboration::events_payloads::validate_mentions_in_realm(
                &value,
                scope.realm_id(),
            )
            .map_err(|error| invalid(error.to_string()))?;
        }
        self.submit_content::<event_spec::MessageCreate, _>(actor, scope, payload, external, true)
            .await
    }
    pub async fn submit_redaction<E: Serialize>(
        &self,
        actor: &ActorId,
        scope: &ScopeRef,
        payload: MessageRedactPayload,
        external: E,
    ) -> Result<String> {
        self.submit_content::<event_spec::MessageRedact, _>(actor, scope, payload, external, false)
            .await
    }

    /// A portal's title follows the same native MLS custody as message content.
    /// Its location remains in the original signed envelope for discovery.
    pub async fn submit_portal_strand<E: Serialize>(
        &self,
        actor: &ActorId,
        scope: &ScopeRef,
        title: &str,
        external: E,
    ) -> Result<arkret::StrandId> {
        let mut object = arkret_models_collaboration::objects::strand::Strand::new_create(
            scope.realm_id().clone(),
            title,
            actor.clone(),
        );
        if let ScopeRef::Circle { circle_id, .. } = scope {
            object.scope_circle_id = Some(circle_id.clone());
        }
        object.tracks.clear();
        object.tracks.insert(
            "discussion".into(),
            arkret::StrandTrack::discussion_primary(),
        );
        let id = self
            .submit_content::<event_spec::StrandCreate, _>(
                actor,
                scope,
                StrandCreatePayload { object },
                external,
                true,
            )
            .await?;
        Ok(arkret::StrandId::from_event_id(&arkret::EventId::new(id)?))
    }

    async fn submit_content<K: EventSpec, E: Serialize>(
        &self,
        actor: &ActorId,
        scope: &ScopeRef,
        content: K::Payload,
        external: E,
        encrypt: bool,
    ) -> Result<String> {
        let external = serde_json::to_value(external)?;
        let external_map = external
            .as_object()
            .ok_or_else(|| invalid("external provenance must be an object"))?
            .clone();
        let operation = format!(
            "content/{}",
            canonical_sha256(&(actor, scope, K::KIND, &external))?
        );
        let saved = self.publication(actor, scope, &operation).await?;
        // A create embeds its timestamp in the payload. Recover that one
        // producer input before comparing a retry, just as for the envelope.
        let at = saved.as_ref().map_or_else(
            || arkret::canonical::normalize_timestamp_canonical(Utc::now()),
            |(_, _, saved)| saved.event.created_at,
        );
        let content = if K::KIND == arkret::EventKind::StrandCreate {
            let mut strand: StrandCreatePayload =
                serde_json::from_value(serde_json::to_value(&content)?)?;
            strand.object.created_at = at;
            serde_json::from_value(serde_json::to_value(strand)?)?
        } else {
            content
        };
        let digest = canonical_sha256(&(actor, scope, K::KIND, &content, &external))?;
        if let Some((_, _, saved)) = saved {
            if saved.input_digest != digest {
                return Err(invalid("delivery identity already binds different content"));
            }
            if let Some(id) = Self::accepted_publication(&saved)? {
                return Ok(id);
            }
            let original = self
                .recover_initial_device(actor, &saved.device_operation_id, scope)
                .await?
                .ok_or_else(|| {
                    invalid("pending publication's original Device custody is unavailable")
                })?;
            return self
                .submit_device_original(&original, &operation, saved.event)
                .await;
        }
        let device = self.device_for_actor(actor).await?;
        self.submit_new_content::<K>(
            actor,
            scope,
            &device,
            ContentIntent {
                operation,
                digest,
                at,
                content,
                external: external_map,
                encrypt,
            },
        )
        .await
    }

    // Keep device bootstrap outside the larger encryption/publication frame.
    // Both phases retain the original current gates and durable send ordering.
    async fn submit_new_content<K: EventSpec>(
        &self,
        actor: &ActorId,
        scope: &ScopeRef,
        device: &ManagedDevice,
        intent: ContentIntent<K::Payload>,
    ) -> Result<String> {
        let ContentIntent {
            operation,
            digest,
            at,
            content,
            external: external_map,
            encrypt,
        } = intent;
        if &device.effective_scope != scope {
            return Err(invalid("content scope differs from Device original"));
        }
        if let Some(event) = self
            .retained_device_publication(device, &operation, &digest)
            .await?
        {
            return self.submit_device_original(device, &operation, event).await;
        }
        self.ensure_realm_membership(device).await?;
        let child = self.terminal_child(device, K::KIND.as_str()).await?;
        let reader = self.open_reader(device).await?;
        if encrypt {
            let target = self
                .edge
                .config()
                .arkret
                .managed_actor_authoring
                .device
                .as_ref()
                .map_or(8, |c| c.key_package_inventory_target);
            self.maintain_mls_key_packages(device, target).await?;
            self.poll_welcome_queue(device, &reader).await?;
            self.poll_content_stream(device, &reader).await?;
        }
        for _ in 0..8 {
            if let Some(event) = self
                .retained_device_publication(device, &operation, &digest)
                .await?
            {
                return self.submit_device_original(device, &operation, event).await;
            }
            let (key, previous, mut record) = self.accepted_device_record(device).await?;
            let mut value = serde_json::to_value(&content)?;
            if encrypt {
                let mut group =
                    super::inbox::restore_group(&record, &device)?.ok_or_else(|| {
                        BridgeError::App(
                            "managed Device is waiting for an accepted MLS Welcome".into(),
                        )
                    })?;
                let base = super::inbox::accepted_group_original(&record, &device)?
                    .ok_or_else(|| invalid("MLS original missing"))?;
                // A durable plaintext delivery awaiting its consumer's ACK is
                // not an MLS transition. Sending still requires fresh public
                // coordinates matching the installed private GroupContext.
                self.verify_current_content_send(device, &reader, &record, &group, &base)
                    .await?;
                let mut seal = |content_type: &str, bytes: &[u8]| -> Result<_> {
                    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
                        "1.0",
                        content_type,
                        arkret::EncryptedPayloadScheme::MlsRfc9420,
                        scope.clone(),
                        K::KIND_STR,
                        group.epoch(),
                        base.event.event_id.clone(),
                        group
                            .local_content_sender_domain()
                            .map_err(|e| invalid(e.to_string()))?,
                        arkret::EventContentRoutingContext::None,
                    )?;
                    let encrypted = group
                        .encrypt_payload(header, bytes)
                        .map_err(|e| invalid(e.to_string()))?;
                    arkret::mls::encrypted_envelope_from_payload(&encrypted)
                        .map_err(|e| invalid(e.to_string()))
                };
                value = match K::KIND {
                    arkret::EventKind::MessageCreate => {
                        let mut message: MessageCreatePayload = serde_json::from_value(value)?;
                        if message.encrypted_content.is_some()
                            || message.encrypted_metadata.is_some()
                        {
                            return Err(invalid("host must supply plaintext for native MLS"));
                        }
                        let plaintext = message
                            .content
                            .take()
                            .ok_or_else(|| invalid("message content missing"))?;
                        message.encrypted_content = Some(seal(
                            MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE,
                            &canonical_json_bytes(&plaintext)?,
                        )?);
                        if let Some(metadata) = message.metadata.take() {
                            message.encrypted_metadata = Some(seal(
                                MESSAGE_METADATA_MLS_CONTENT_TYPE,
                                &canonical_json_bytes(&metadata)?,
                            )?);
                        }
                        serde_json::to_value(message)?
                    }
                    arkret::EventKind::StrandCreate => {
                        let mut strand: StrandCreatePayload = serde_json::from_value(value)?;
                        if strand.object.encrypted_metadata.is_some()
                            || strand.object.content.is_some()
                            || strand.object.encrypted_content.is_some()
                        {
                            return Err(invalid("portal create requires plaintext metadata only"));
                        }
                        let metadata = strand
                            .object
                            .metadata
                            .take()
                            .ok_or_else(|| invalid("portal metadata missing"))?;
                        strand.object.encrypted_metadata = Some(seal(
                            "application/vnd.arkret.strand-metadata+json",
                            &canonical_json_bytes(&metadata)?,
                        )?);
                        serde_json::to_value(strand)?
                    }
                    _ => return Err(invalid("unsupported native content encryption")),
                };
                super::inbox::refresh_group_private_state(
                    &mut record,
                    device,
                    group
                        .export_state_record()
                        .map_err(|e| invalid(e.to_string()))?,
                )?;
            }
            let typed: K::Payload = serde_json::from_value(value)?;
            let intent = TypedEventDraft::<K>::new(scope.clone(), actor.clone(), typed)?
                .with_applet_id(arkret::AppletId::new(
                    self.edge.config().arkret.applet_id.clone(),
                )?)
                .with_authorization_ref(child.clone().into())
                .into_intent(at)?
                .with_external_ref(
                    external_map
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                );
            let event = self.sign_device_intent(device, intent)?;
            reader.check_device(device)?;
            if self
                .freeze_publication(device, &operation, &digest, &event, key, previous, &record)
                .await?
            {
                return self.submit_device_original(device, &operation, event).await;
            }
        }
        Err(invalid("native content send custody contended"))
    }
}

#[cfg(test)]
mod source_selection_tests;
