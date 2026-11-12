//! Local history recovery consumes actual current Device disclosure. It never
//! installs an MLS checkpoint or exposes a plaintext-root network endpoint.

use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_models_crypto::artifacts_keys::SecretStorageEntry;
use arkret_models_integration::RealmActorArchiveInventoryEntry;

use super::*;
use crate::realm_governance::invalid;

impl ManagedActorManagerService {
    pub async fn restore_history_for_event(
        &self,
        device: &crate::managed_device::ManagedDevice,
        event_id: &arkret::EventId,
    ) -> Result<usize> {
        let runtime =
            crate::managed_device::ManagedDeviceRuntime::new(self.authoring.edge.clone())?;
        let reader = runtime.open_reader(device).await?;
        let disclosed = reader.client().committed_event_get(event_id).await?;
        let disclosed = garth::own_station_results::consume_own_station_device_event(
            reader.client(),
            event_id,
            disclosed,
        )
        .await
        .map_err(invalid)?;
        let original = disclosed.full().map_err(invalid)?;
        let scope = device.effective_scope();
        if original.event.scope_ref != *scope {
            return Err(invalid("history recovery changed its exact Device scope"));
        }
        let mut needed = Vec::new();
        for carrier in original.event.event_content_envelopes()? {
            let arkret_models_crypto::EncryptedEnvelopeEncryptionContext::EpochContent {
                root_ref,
                epoch,
                group_state_ref,
                ..
            } = carrier.envelope.encryption_context;
            let identity = (root_ref, epoch, group_state_ref);
            if !needed.contains(&identity) {
                needed.push(identity);
            }
        }
        if needed.is_empty() {
            return Ok(0);
        }
        let inventory = self.archive_inventory(&device.actor_id).await?;
        let manager_ref = inventory.manager_ref.clone();
        let route = Arc::new(
            self.authoring
                .edge
                .realm_route(&inventory.realm_actor_id.realm_id)
                .await?,
        );
        let mut roots = Vec::new();
        for entry in inventory.entries {
            let RealmActorArchiveInventoryEntry::Backup(entry) = entry else {
                continue;
            };
            let Some(index) = entry.backup.contents.first() else {
                return Err(invalid("archive root index is missing"));
            };
            let Some(context) = &index.root_context else {
                return Err(invalid("archive root context is missing"));
            };
            let Some(reference) = &index.root_ref else {
                return Err(invalid("archive root commitment is missing"));
            };
            if context.effective_scope != *scope
                || !needed.contains(&(
                    reference.clone(),
                    context.epoch,
                    context.group_state_ref.clone(),
                ))
            {
                continue;
            }
            let owner = inventory.realm_actor_id.clone();
            let vault = self.vault.clone();
            let route = route.clone();
            let packet_roots = crate::run_blocking(move || {
                vault.with_accepted_key(
                    &owner,
                    &entry.native_source.admission.recipient_ref,
                    |private| {
                        arkret::crypto::content_history::open_content_root_backup(
                            &entry.backup,
                            private,
                            |_, _| {
                                arkret::identity::verify_realm_actor_content_backup_source(
                                    &entry.backup,
                                    &entry.native_source,
                                    &route.authority,
                                )
                                .map_err(|error| arkret::crypto::Error::Protocol(error.to_string()))
                            },
                        )
                        .map_err(invalid)
                    },
                )
            })
            .await?;
            for item in packet_roots.items {
                let SecretStorageEntry::ContentRoot(root) = item else {
                    return Err(invalid("native archive contains another secret class"));
                };
                if !roots
                    .iter()
                    .any(|existing: &arkret_models_crypto::ContentRootBackupEntry| {
                        existing.root_ref == root.root_ref
                    })
                {
                    roots.push(root);
                }
            }
        }
        if needed
            .iter()
            .any(|(reference, ..)| !roots.iter().any(|root| &root.root_ref == reference))
        {
            return Err(invalid(
                "manager archive lacks a sufficient root for the disclosed historical Event",
            ));
        }
        // Recheck current manager and actual history disclosure after archive
        // work. These fresh reads enforce generation, consent and history floor;
        // no caller-provided boolean or cached journal substitutes for them.
        if self.archive_inventory(&device.actor_id).await?.manager_ref != manager_ref {
            return Err(invalid("manager changed during local history recovery"));
        }
        let refreshed = reader.client().committed_event_get(event_id).await?;
        let refreshed = garth::own_station_results::consume_own_station_device_event(
            reader.client(),
            event_id,
            refreshed,
        )
        .await
        .map_err(invalid)?;
        if canonical_json_bytes(refreshed.full().map_err(invalid)?)?
            != canonical_json_bytes(disclosed.full().map_err(invalid)?)?
        {
            return Err(invalid(
                "history recovery disclosure changed its exact accepted original",
            ));
        }
        for root in &roots {
            runtime.retain_history_root(device, &reader, root).await?;
        }
        refreshed.full().map_err(invalid)?;
        Ok(roots.len())
    }
}
