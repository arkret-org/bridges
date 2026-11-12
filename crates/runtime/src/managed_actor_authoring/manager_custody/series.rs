//! Manager maintenance uses the standing Service lane, never a Device grant.

use arkret::identity::VerifiedRealmActorMaterial;
use arkret::{
    ActorId, CommittedEventRef, CurrentSelector, CurrentState, RealmActorMaterial, ScopeRef,
};
use arkret_models_integration::{RealmActorArchiveInventoryManifest, RealmActorManagerValue};

use super::*;
use crate::realm_governance::{RealmRoute, invalid};

fn current_row<'a>(
    cut: &'a VerifiedRealmActorMaterial,
    selector: &CurrentSelector,
) -> Result<Option<(&'a Value, &'a CommittedEventRef)>> {
    let RealmActorMaterial::Current { entries, .. } = &cut.material().material else {
        return Err(invalid("manager material is not the requested current cut"));
    };
    for entry in entries {
        match entry {
            arkret::RealmActorMaterialCurrentEntry::Present {
                current_state:
                    CurrentState::Value {
                        selector: found,
                        value,
                        ..
                    },
                source_ref,
            } if found == selector => return Ok(Some((value, source_ref))),
            arkret::RealmActorMaterialCurrentEntry::NeverWritten { selector: found }
                if found == selector =>
            {
                return Ok(None);
            }
            _ => {}
        }
    }
    Err(invalid(
        "manager material omitted an exact requested selector",
    ))
}

impl ManagedActorManagerService {
    pub(super) async fn bind_creation_archive_key(
        &self,
        actor: &ActorId,
        recipient: &arkret_models_integration::RealmActorArchiveRecipientEntry,
    ) -> Result<()> {
        if recipient.declaration.event.kind != arkret::EventKind::RealmActorCreate {
            return Ok(());
        }
        let payload = crate::managed_authoring::creation_payload(&recipient.declaration.event)?;
        if payload.service_id != *self.authoring.edge.service_actor_id() {
            return Ok(());
        }
        let local = self.authoring.edge.retained_managed_actor(actor)?;
        let prepared = self.authoring.edge.prepared_managed_actor(&local)?;
        if canonical_json_bytes(&prepared.create_event)?
            != canonical_json_bytes(&recipient.declaration.event)?
        {
            return Err(invalid(
                "archive creation differs from local exact candidate",
            ));
        }
        let subject_digest = managed_actor_subject_key(&prepared.authoring_request)?;
        let raw =
            arkret::base64url_decode(&recipient.content_backup_recipient.public_key_base64url)?;
        let public: [u8; 32] = raw.as_slice().try_into().map_err(invalid)?;
        let subject = actor
            .as_realm_actor_id()
            .ok_or_else(|| invalid("native archive actor required"))?
            .clone();
        let reference = recipient.recipient_ref.clone();
        let vault = self.vault.clone();
        crate::run_blocking(move || {
            vault.accept_candidate_recipient(&subject, &subject_digest, &reference, &public)
        })
        .await
    }

    pub(super) async fn maintain_actor_backup_series(&self, actor: &ActorId) -> Result<usize> {
        use arkret_models_integration::RealmActorArchiveInventoryEntry;
        let original = self.authoring.managed_creation(actor).await?;
        let creation = crate::managed_authoring::creation_payload(&original.event)?;
        let inventory = self.archive_inventory(actor).await?;
        let mut scopes = BTreeMap::new();
        scopes.insert(
            canonical_json_bytes(&creation.creation_scope)?,
            creation.creation_scope,
        );
        let devices =
            crate::managed_device::ManagedDeviceRuntime::new(self.authoring.edge.clone())?;
        for scope in devices.retained_authorized_scopes(actor).await? {
            scopes.insert(canonical_json_bytes(&scope)?, scope);
        }
        for entry in &inventory.entries {
            let scope = match entry {
                RealmActorArchiveInventoryEntry::Series(entry) => Some(&entry.effective_scope),
                RealmActorArchiveInventoryEntry::Backup(entry) => entry
                    .backup
                    .contents
                    .first()
                    .and_then(|content| content.root_context.as_ref())
                    .map(|context| &context.effective_scope),
                _ => None,
            };
            if let Some(scope) = scope {
                scopes.insert(canonical_json_bytes(scope)?, scope.clone());
            }
        }
        for scope in scopes.values() {
            self.maintain_backup_series(actor, scope).await?;
        }
        Ok(scopes.len())
    }

    pub async fn maintain_known_backup_series(&self) -> Result<usize> {
        let mut count = 0;
        for actor in self.authoring.managed_actor_ids().await? {
            match self.maintain_actor_backup_series(&actor).await {
                Ok(scopes) => count += scopes,
                Err(error) => {
                    tracing::warn!(%actor, %error, "manager archive scope maintenance remains pending")
                }
            }
        }
        Ok(count)
    }

    /// Select only an explicitly known scope using actual manager Service
    /// maintenance. An accepted historical Recovery ref never forces rotation.
    pub async fn maintain_backup_series(
        &self,
        actor: &ActorId,
        scope: &ScopeRef,
    ) -> Result<arkret_models_collaboration::RealmActorKeyBackupActiveSeriesValue> {
        use arkret_models_collaboration::events_payloads::{
            KeyBackupActiveSeries, UnsignedRealmActorKeyBackupActiveSeries,
        };
        use arkret_models_integration::{RealmActorArchiveInventoryEntry, RealmActorRecoveryValue};
        use ed25519_dalek::Signer as _;
        let subject = actor
            .as_realm_actor_id()
            .ok_or_else(|| invalid("native actor required"))?;
        let (route, current, manager_ref) = self.archive_current(actor, Some(scope)).await?;
        let (recovery, recovery_ref) = current_row(
            &current,
            &CurrentSelector::RealmActorRecovery {
                actor_id: actor.clone(),
            },
        )?
        .ok_or_else(|| invalid("native Recovery current is unavailable"))?;
        let recovery: RealmActorRecoveryValue = serde_json::from_value(recovery.clone())?;
        if recovery.pending.is_some() {
            return Err(invalid("native recovery is pending"));
        }
        let selector = CurrentSelector::RealmActorKeyBackupActiveSeries {
            actor_id: actor.clone(),
            effective_scope: scope.clone(),
            backup_kind: arkret::RealmActorBackupKind::SecretStorage,
        };
        let selected = current_row(&current, &selector)?
            .map(|(value, _)| {
                serde_json::from_value::<
                    arkret_models_collaboration::RealmActorKeyBackupActiveSeriesValue,
                >(value.clone())
            })
            .transpose()?;
        let inventory = self.inventory_on_route(actor, &route, &manager_ref).await?;
        let recipient = inventory
            .entries
            .iter()
            .find_map(|entry| match entry {
                RealmActorArchiveInventoryEntry::Recipient(entry)
                    if entry.recipient_ref == recovery.content_backup_recipient_ref =>
                {
                    Some(entry)
                }
                _ => None,
            })
            .ok_or_else(|| invalid("inventory lacks current original recipient"))?;
        if recipient.content_backup_recipient != recovery.content_backup_recipient {
            return Err(invalid("recipient original differs from current Recovery"));
        }
        let raw =
            arkret::base64url_decode(&recovery.content_backup_recipient.public_key_base64url)?;
        let public: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| invalid("invalid native archive key"))?;
        self.bind_creation_archive_key(actor, recipient).await?;
        let vault = self.vault.clone();
        let owner = subject.clone();
        let reference = recovery.content_backup_recipient_ref.clone();
        crate::run_blocking(move || {
            vault.with_accepted_key(&owner, &reference, |private| {
                if arkret::crypto::hpke::x25519_public_key(private).map_err(invalid)? != public {
                    return Err(invalid(
                        "manager has no matching durable current archive key",
                    ));
                }
                Ok(())
            })
        })
        .await?;
        let previous = selected
            .as_ref()
            .map(|selected| {
                inventory
                    .entries
                    .iter()
                    .find_map(|entry| match entry {
                        RealmActorArchiveInventoryEntry::Series(entry)
                            if entry.effective_scope == *scope
                                && entry.record.active_series_id == selected.active_series_id
                                && entry.record.series_pointer_version
                                    == selected.series_pointer_version
                                && entry.record.manager_ref.as_ref()
                                    == Some(&selected.manager_ref)
                                && entry.record.recovery_ref.as_ref()
                                    == Some(&selected.recovery_ref)
                                && entry.record.recipient_ref.as_ref()
                                    == Some(&selected.recipient_ref) =>
                        {
                            Some(&entry.record)
                        }
                        _ => None,
                    })
                    .ok_or_else(|| {
                        invalid("selected series has no independently verified original")
                    })
            })
            .transpose()?;
        if selected.is_none() && inventory.entries.iter().any(|entry|
            matches!(entry, RealmActorArchiveInventoryEntry::Series(entry) if entry.effective_scope == *scope)) {
            return Err(invalid("historical scoped series cannot lose its current pointer"));
        }
        if let Some(selected) = &selected {
            if selected.manager_ref == manager_ref
                && selected.recipient_ref == recovery.content_backup_recipient_ref
            {
                return Ok(selected.clone());
            }
        }
        let version = previous.map_or(Ok(1), |record| {
            record
                .series_pointer_version
                .checked_add(1)
                .ok_or_else(|| invalid("native series version exhausted"))
        })?;
        let mut previous_ids = previous
            .map(|record| record.previous_series_ids.clone())
            .unwrap_or_default();
        if let Some(record) = previous {
            previous_ids.push(record.active_series_id.clone());
        }
        let operation = format!(
            "manager-series/v1/{}",
            canonical_sha256(&(
                actor,
                scope,
                &manager_ref,
                recovery_ref,
                &recovery.content_backup_recipient_ref,
                version,
            ))?
        );
        let vault = self.vault.clone();
        let key = operation.clone();
        let stored = crate::run_blocking(move || vault.read_record(&key)).await?;
        let record: KeyBackupActiveSeries = if let Some(stored) = stored {
            serde_json::from_slice(stored.as_slice())?
        } else {
            let now = arkret::canonical::normalize_timestamp_canonical(Utc::now());
            let series_id = arkret::BackupSeriesId::new(format!(
                "ak:backup_series:{}",
                arkret_identifiers::uuid_v7_at(now.timestamp_millis().max(0) as u64)
            ))?;
            let signing = SigningKey::from_bytes(&self.authoring.config.signing_seed()?);
            let unsigned = UnsignedRealmActorKeyBackupActiveSeries::new(
                subject.clone(),
                scope.clone(),
                series_id,
                version,
                previous_ids.clone(),
                manager_ref.clone(),
                recovery_ref.clone(),
                recovery.content_backup_recipient_ref.clone(),
                now,
                self.authoring.edge.service_verification_method()?,
            )?;
            let record = unsigned.clone().attach_signature(
                arkret::Base64UrlString::new(arkret::base64url_encode(
                    signing.sign(&unsigned.signing_payload_bytes()?).to_bytes(),
                ))
                .map_err(invalid)?,
            )?;
            let bytes = canonical_json_bytes(&record)?;
            let vault = self.vault.clone();
            let key = operation.clone();
            crate::run_blocking(move || {
                vault.compare_exchange_record(&key, None, &bytes)?;
                vault
                    .read_record(&key)?
                    .ok_or_else(|| invalid("frozen manager series disappeared"))
            })
            .await
            .and_then(|stored| {
                serde_json::from_slice(stored.as_slice()).map_err(BridgeError::from)
            })?
        };
        if record.actor_id != *actor
            || record.effective_scope.as_ref() != Some(scope)
            || record.manager_ref.as_ref() != Some(&manager_ref)
            || record.recovery_ref.as_ref() != Some(recovery_ref)
            || record.recipient_ref.as_ref() != Some(&recovery.content_backup_recipient_ref)
            || record.series_pointer_version != version
            || record.previous_series_ids != previous_ids
        {
            return Err(invalid(
                "frozen manager series differs from its exact authority cut",
            ));
        }
        let intent = arkret_event_draft::TypedEventDraft::<
            arkret_wire::event_spec::KeyBackupActiveSeries,
        >::new(
            ScopeRef::RealmControl {
                realm_id: subject.realm_id.clone(),
            },
            ActorId::service(self.authoring.edge.service_actor_id().clone()),
            record.clone(),
        )?
        .with_applet_id(arkret::AppletId::new(self.authoring.edge.applet_id())?)
        .into_intent(record.issued_at)?;
        let authored = self
            .authoring
            .edge
            .author_and_sign(&subject.realm_id, &operation, intent)
            .await?;
        self.authoring.edge.submit_event(&authored).await?;
        let (_, accepted, manager) = self.archive_current(actor, Some(scope)).await?;
        let (value, _) = current_row(&accepted, &selector)?
            .ok_or_else(|| invalid("accepted native series is unavailable"))?;
        let value: arkret_models_collaboration::RealmActorKeyBackupActiveSeriesValue =
            serde_json::from_value(value.clone())?;
        if value.active_series_id != record.active_series_id
            || value.series_pointer_version != version
            || value.manager_ref != manager
            || record.recovery_ref.as_ref() != Some(&value.recovery_ref)
            || record.recipient_ref.as_ref() != Some(&value.recipient_ref)
        {
            return Err(invalid(
                "accepted manager series differs from its frozen selection",
            ));
        }
        Ok(value)
    }

    async fn archive_current(
        &self,
        actor: &ActorId,
        scope: Option<&ScopeRef>,
    ) -> Result<(RealmRoute, VerifiedRealmActorMaterial, CommittedEventRef)> {
        let subject = actor
            .as_realm_actor_id()
            .ok_or_else(|| invalid("native archive requires a Realm actor"))?;
        let route = self.authoring.edge.realm_route(&subject.realm_id).await?;
        let selector = CurrentSelector::RealmActorManager {
            actor_id: actor.clone(),
        };
        let mut selectors = vec![
            selector.clone(),
            CurrentSelector::RealmActorRecovery {
                actor_id: actor.clone(),
            },
        ];
        if let Some(scope) = scope {
            arkret_models_crypto::validate_realm_actor_backup_scope(subject, scope)?;
            selectors.push(CurrentSelector::RealmActorKeyBackupActiveSeries {
                actor_id: actor.clone(),
                effective_scope: scope.clone(),
                backup_kind: arkret::RealmActorBackupKind::SecretStorage,
            });
        }
        let material = route
            .material(
                &arkret::RealmActorMaterialRequestBody::Current {
                    actor_id: actor.clone(),
                    request_nonce: crate::realm_governance::nonce()?,
                    selectors,
                },
                &ActorId::service(self.authoring.edge.service_actor_id().clone()),
            )
            .await?;
        let (manager, reference) = current_row(&material, &selector)?
            .ok_or_else(|| invalid("native manager is unavailable"))?;
        let manager: RealmActorManagerValue = serde_json::from_value(manager.clone())?;
        if manager.service_id != *self.authoring.edge.service_actor_id()
            || manager.binding_ref != *reference
        {
            return Err(invalid(
                "this Service is not the current exact actor manager",
            ));
        }
        let reference = reference.clone();
        Ok((route, material, reference))
    }

    async fn inventory_on_route(
        &self,
        actor: &ActorId,
        route: &RealmRoute,
        manager: &CommittedEventRef,
    ) -> Result<RealmActorArchiveInventoryManifest> {
        let subject = actor
            .as_realm_actor_id()
            .ok_or_else(|| invalid("native actor required"))?;
        let mut query = arkret_models_crypto::RealmActorArchiveInventoryQuery::new(subject.clone());
        let mut cut = None;
        let mut entries = Vec::new();
        let mut cursors = std::collections::BTreeSet::new();
        loop {
            let page = route
                .client
                .realm_actor_backup_archive_inventory(&query)
                .await?;
            let observed = (page.archive_revision, page.inventory_digest.clone());
            if page.manager_ref != *manager
                || cut.as_ref().is_some_and(|previous| previous != &observed)
            {
                return Err(invalid("native inventory changed its complete frozen cut"));
            }
            if page.has_more && page.entries.is_empty() {
                return Err(invalid(
                    "native inventory did not advance its page boundary",
                ));
            }
            cut = Some(observed);
            entries.extend(page.entries);
            match page.next_cursor {
                Some(cursor) => {
                    if !cursors.insert(cursor.as_str().to_owned()) {
                        return Err(invalid("native inventory repeated a cursor"));
                    }
                    query.cursor = Some(cursor);
                }
                None => break,
            }
        }
        let (archive_revision, expected_digest) =
            cut.ok_or_else(|| invalid("inventory omitted its empty cut"))?;
        let manifest = RealmActorArchiveInventoryManifest {
            realm_actor_id: subject.clone(),
            manager_ref: manager.clone(),
            archive_revision,
            entries,
        };
        if manifest.inventory_digest()? != expected_digest {
            return Err(invalid("native inventory full-manifest digest differs"));
        }
        arkret::identity::verify_realm_actor_archive_inventory(
            &manifest,
            &route.authority,
            &route.keys,
        )
        .map_err(|error| invalid(error.to_string()))?;
        Ok(manifest)
    }

    pub async fn archive_inventory(
        &self,
        actor: &ActorId,
    ) -> Result<RealmActorArchiveInventoryManifest> {
        let (route, _, manager) = self.archive_current(actor, None).await?;
        self.inventory_on_route(actor, &route, &manager).await
    }
}
