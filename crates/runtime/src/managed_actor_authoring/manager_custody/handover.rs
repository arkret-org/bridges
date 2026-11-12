//! Private archive transfer is durable before the public manager acceptance.

use arkret_models_integration::{
    RealmActorArchiveInventoryEntry, RealmActorArchiveInventoryManifest,
    RealmActorContentBackupHandoverConfirmation, RealmActorContentBackupHandoverOffer,
    RealmActorContentBackupHandoverOfferSignatureInput, RealmActorContentBackupHandoverPlaintext,
    RealmActorContentBackupPrivateRecipientKey, RealmActorContentBackupSealedHandover,
};

use super::*;
use crate::realm_governance::invalid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IncomingArchiveOffer {
    plan: ManagementTransferPlan,
    offer: RealmActorContentBackupHandoverOffer,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedArchive {
    sealed_digest: Hash,
    sealed: RealmActorContentBackupSealedHandover,
    #[serde(with = "arkret::canonical::serde_helpers::canonical_timestamp")]
    imported_at: chrono::DateTime<Utc>,
    plaintext: RealmActorContentBackupHandoverPlaintext,
}

/// Local proof produced only after SDK HPKE/source validation and physical
/// manager-vault import. It is not a wire DTO or a deserializable capability.
pub(crate) struct ArchiveCustodyAcceptance {
    pub(crate) realm_actor_id: arkret::RealmActorId,
    pub(crate) manager_ref: arkret::CommittedEventRef,
    pub(crate) new_service_id: DidCoreId,
    pub(crate) next_content_backup_recipient:
        arkret_models_crypto::RealmActorContentBackupRecipient,
    pub(crate) inventory_digest: Hash,
    pub(crate) handover_digest: Hash,
}

fn transfer_intent(plan: &ManagementTransferPlan) -> Result<String> {
    Ok(format!(
        "manager-archive-transfer/v1/{}",
        canonical_sha256(plan)?
    ))
}

impl ManagedActorManagerService {
    async fn recover_archive_acceptance(
        &self,
        plan: &ManagementTransferPlan,
    ) -> Result<ArchiveCustodyAcceptance> {
        let key = format!("{}/import", transfer_intent(plan)?);
        let vault = self.vault.clone();
        let record = crate::run_blocking(move || vault.read_record(&key))
            .await?
            .ok_or_else(|| invalid("receiving manager has no durable archive import"))?;
        let record: ImportedArchive = serde_json::from_slice(record.as_slice())?;
        if record.sealed_digest.as_str() != canonical_sha256(&record.sealed)? {
            return Err(invalid(
                "durable archive import changed its sealed original",
            ));
        }
        let confirmation = self.import_archive_transfer(plan, &record.sealed).await?;
        let offer = record.sealed.offer;
        Ok(ArchiveCustodyAcceptance {
            realm_actor_id: offer.realm_actor_id,
            manager_ref: offer.manager_ref,
            new_service_id: offer.new_service_id,
            next_content_backup_recipient: offer.next_content_backup_recipient,
            inventory_digest: confirmation.inventory_digest,
            handover_digest: confirmation.handover_digest,
        })
    }

    /// The operator's existing private management channel carries a sealed
    /// archive; the receiving manager actually opens and durably imports it.
    /// No archive capability is installed into either daily Device runtime.
    pub async fn prepare_management_transfer_to(
        &self,
        receiving: &Self,
        plan: &ManagementTransferPlan,
    ) -> Result<()> {
        if self.authoring.edge.applet_id() != receiving.authoring.edge.applet_id() {
            return Err(invalid("management transfer must retain the Applet"));
        }
        if receiving
            .authoring
            .retained_manager_event(plan)
            .await
            .is_ok_and(|event| event.is_some())
        {
            receiving.recover_archive_acceptance(plan).await?;
            return Ok(());
        }
        let sender = crate::managed_device::ManagedDeviceRuntime::new(self.authoring.edge.clone())?;
        let receiver =
            crate::managed_device::ManagedDeviceRuntime::new(receiving.authoring.edge.clone())?;
        sender.management_source_current(&plan.actor_id).await?;
        self.maintain_actor_backup_series(&plan.actor_id).await?;
        let creation = self.authoring.managed_creation(&plan.actor_id).await?;
        let did = crate::managed_authoring::creation_payload(&creation.event)?
            .initial_resolution
            .did;
        let inventory = self.archive_inventory(&plan.actor_id).await?;
        let archive = self
            .transfer_archive_to(receiving, plan, &did, inventory)
            .await?;
        let offer = receiver
            .management_transfer_offer(plan, &did, &archive.next_content_backup_recipient)
            .await?;
        let proposal = sender.management_control_transcript(&offer).await?;
        let signature = receiver
            .sign_management_control_transcript(plan, &proposal)
            .await?;
        let commit = sender.submit_management_control(plan, &signature).await?;
        let release = sender.release_management_native(plan, &commit).await?;
        receiver
            .prepare_management_acceptance(
                plan,
                &release,
                &crate::managed_actor_authoring::control::manager::reference(&commit),
                &crate::managed_actor_authoring::control::manager::reference(&creation.commit),
                &archive,
            )
            .await
    }

    pub async fn complete_management_transfer(
        &self,
        plan: &ManagementTransferPlan,
    ) -> Result<arkret::RealmCommit> {
        let archive = self.recover_archive_acceptance(plan).await?;
        let runtime =
            crate::managed_device::ManagedDeviceRuntime::new(self.authoring.edge.clone())?;
        let commit = runtime.complete_management_transfer(plan).await?;
        let reference = crate::managed_actor_authoring::control::manager::reference(&commit);
        let intent = transfer_intent(plan)?;
        let vault = self.vault.clone();
        let actor = archive.realm_actor_id;
        let public =
            arkret::base64url_decode(&archive.next_content_backup_recipient.public_key_base64url)?;
        let public: [u8; 32] = public.as_slice().try_into().map_err(invalid)?;
        crate::run_blocking(move || vault.accept_recipient(&actor, &intent, &reference, &public))
            .await?;
        // Series maintenance is allowed while the actor remains paused. This
        // does not claim that old MLS leaves or epochs have been secured.
        self.maintain_actor_backup_series(&plan.actor_id).await?;
        Ok(commit)
    }

    fn service_document_at(&self, at: chrono::DateTime<Utc>) -> Result<arkret::DidDocument> {
        let resolution = crate::service_identity::validate(&self.authoring.config)?;
        arkret::identity::authenticated_service_document_at(
            resolution,
            self.authoring.edge.service_actor_id(),
            at,
        )
        .map_err(invalid)
    }

    async fn archive_transfer_offer(
        &self,
        plan: &ManagementTransferPlan,
        did: &Did,
        inventory: &RealmActorArchiveInventoryManifest,
    ) -> Result<RealmActorContentBackupHandoverOffer> {
        if plan.actor_id.as_realm_actor_id() != Some(&inventory.realm_actor_id)
            || plan.new_service_id != *self.authoring.edge.service_actor_id()
            || project_did_to_core_id(did)? != inventory.realm_actor_id.principal_id
        {
            return Err(invalid(
                "private archive offer targets another principal or Service",
            ));
        }
        let intent = transfer_intent(plan)?;
        let key = format!("{intent}/offer");
        let vault = self.vault.clone();
        let lookup = key.clone();
        let existing = crate::run_blocking(move || vault.read_record(&lookup)).await?;
        if let Some(existing) = existing {
            let record: IncomingArchiveOffer = serde_json::from_slice(existing.as_slice())?;
            if record.plan != *plan
                || record.offer.inventory_digest != inventory.inventory_digest()?
                || record.offer.archive_revision != inventory.archive_revision
                || record.offer.manager_ref != inventory.manager_ref
            {
                return Err(invalid(
                    "archive offer already freezes a different complete inventory cut",
                ));
            }
            return Ok(record.offer);
        }
        let owner = inventory.realm_actor_id.clone();
        let vault = self.vault.clone();
        let prepared = intent.clone();
        let public =
            crate::run_blocking(move || vault.prepare_recipient(&owner, &prepared)).await?;
        let encoded = arkret::base64url_encode(public);
        if inventory.entries.iter().any(|entry| matches!(entry,
            RealmActorArchiveInventoryEntry::Recipient(entry) if entry.content_backup_recipient.public_key_base64url == encoded)) {
            return Err(invalid("future archive recipient must be fresh"));
        }
        let at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
        let descriptor = arkret_models_crypto::RealmActorContentBackupRecipient {
            key_agreement_ref: DidUrl::new(format!("{did}#content-backup"))?,
            hpke_suite: arkret_models_crypto::ContentBackupRecipientHpkeSuite::AkHpkeX25519AeadChacha20poly1305V1,
            public_key_base64url: encoded,
        };
        let offer = arkret::identity::sign_realm_actor_backup_handover_offer(
            RealmActorContentBackupHandoverOfferSignatureInput {
                realm_actor_id: inventory.realm_actor_id.clone(),
                manager_ref: inventory.manager_ref.clone(),
                new_service_id: plan.new_service_id.clone(),
                next_content_backup_recipient: descriptor,
                inventory_digest: inventory.inventory_digest()?,
                archive_revision: inventory.archive_revision,
                expires_at: at + chrono::Duration::minutes(10),
                nonce: crate::realm_governance::nonce()?,
            },
            self.authoring.edge.service_verification_method()?,
            at,
            &SigningKey::from_bytes(&self.authoring.config.signing_seed()?),
        )
        .map_err(invalid)?;
        arkret::identity::verify_realm_actor_backup_handover_offer(
            &offer,
            &self.service_document_at(at)?,
            at,
        )
        .map_err(invalid)?;
        let bytes = arkret::KeyBytes::new(canonical_json_bytes(&IncomingArchiveOffer {
            plan: plan.clone(),
            offer,
        })?);
        let vault = self.vault.clone();
        crate::run_blocking(move || {
            vault.compare_exchange_record(&key, None, bytes.as_slice())?;
            let winner = vault
                .read_record(&key)?
                .ok_or_else(|| invalid("archive offer disappeared"))?;
            let winner: IncomingArchiveOffer = serde_json::from_slice(winner.as_slice())?;
            Ok(winner.offer)
        })
        .await
    }

    async fn import_archive_transfer(
        &self,
        plan: &ManagementTransferPlan,
        sealed: &RealmActorContentBackupSealedHandover,
    ) -> Result<RealmActorContentBackupHandoverConfirmation> {
        let intent = transfer_intent(plan)?;
        let key = format!("{intent}/import");
        let sealed_digest = Hash::new(canonical_sha256(sealed)?)?;
        let owner = sealed.offer.realm_actor_id.clone();
        if plan.actor_id.as_realm_actor_id() != Some(&owner)
            || sealed.offer.new_service_id != plan.new_service_id
        {
            return Err(invalid("archive import belongs to another manager plan"));
        }
        let vault = self.vault.clone();
        let private_owner = owner.clone();
        let private_intent = intent;
        let private = crate::run_blocking(move || {
            vault.with_prepared_key(&private_owner, &private_intent, |key| {
                let bytes: [u8; 32] = key.try_into().map_err(invalid)?;
                Ok(arkret_models_crypto::SecretBytes::new(bytes))
            })
        })
        .await?;
        let route = self.authoring.edge.realm_route(&owner.realm_id).await?;
        let offer_document = self.service_document_at(sealed.offer.signature.created_at)?;
        let confirmed_at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
        let confirmation_document = self.service_document_at(confirmed_at)?;
        let method = self.authoring.edge.service_verification_method()?;
        let signing = SigningKey::from_bytes(&self.authoring.config.signing_seed()?);
        let sealed = sealed.clone();
        let vault = self.vault.clone();
        crate::run_blocking(move || {
            let context = arkret::identity::RealmActorBackupHandoverImportContext {
                offer_original_document: &offer_document,
                confirmation_current_document: &confirmation_document,
                confirmation_method: method,
                confirmation_signing_key: &signing,
                confirmed_at,
            };
            arkret::identity::import_realm_actor_backup_handover(
                &sealed,
                &private,
                &route.authority,
                &route.keys,
                &context,
                |identity| {
                    let prior = vault.read_record(&key).map_err(|error| {
                        arkret::identity::IdentityError::Protocol(error.to_string())
                    })?;
                    let Some(prior) = prior else { return Ok(None) };
                    let prior: ImportedArchive = serde_json::from_slice(prior.as_slice())?;
                    if prior.sealed_digest != identity.sealed_digest
                        || prior.sealed_digest.as_str() != canonical_sha256(&prior.sealed)?
                        || prior.plaintext.inventory_manifest.realm_actor_id != identity.realm_actor_id
                        || prior.plaintext.offer_digest != identity.offer_digest
                        || prior.plaintext.inventory_manifest.inventory_digest()? != identity.inventory_digest
                        || canonical_sha256(&prior.plaintext)? != identity.handover_digest.as_str()
                    {
                        return Err(arkret::identity::IdentityError::Protocol(
                            "durable import does not bind the exact sealed archive and plaintext cut".into(),
                        ));
                    }
                    Ok(Some(prior.imported_at))
                },
                |_, plaintext, imported_at| {
                    let record = ImportedArchive {
                        sealed_digest: sealed_digest.clone(),
                        sealed: sealed.clone(),
                        imported_at,
                        plaintext: plaintext.clone(),
                    };
                    let bytes =
                        arkret::KeyBytes::new(canonical_json_bytes(&record).map_err(|error| {
                            arkret::identity::IdentityError::Protocol(error.to_string())
                        })?);
                    vault
                        .import_recipient_keys(
                            &owner,
                            &plaintext.recipient_keys,
                            &key,
                            bytes.as_slice(),
                        )
                        .map_err(|error| {
                            arkret::identity::IdentityError::Protocol(error.to_string())
                        })
                },
            )
            .map_err(invalid)
        })
        .await
    }

    pub(crate) async fn transfer_archive_to(
        &self,
        receiving: &Self,
        plan: &ManagementTransferPlan,
        did: &Did,
        inventory: RealmActorArchiveInventoryManifest,
    ) -> Result<ArchiveCustodyAcceptance> {
        if self.authoring.edge.applet_id() != receiving.authoring.edge.applet_id() {
            return Err(invalid("private archive transfer cannot change the Applet"));
        }
        let offer = receiving
            .archive_transfer_offer(plan, did, &inventory)
            .await?;
        let checkpoint_key = format!("{}/checkpoint", transfer_intent(plan)?);
        let vault = self.vault.clone();
        let lookup = checkpoint_key.clone();
        let checkpoint = crate::run_blocking(move || vault.read_record(&lookup)).await?;
        let pending = if let Some(checkpoint) = checkpoint {
            arkret::identity::PendingRealmActorBackupHandover::resume_private_checkpoint(
                &checkpoint,
            )
            .map_err(invalid)?
        } else {
            let mut keys = Vec::new();
            for entry in &inventory.entries {
                if let RealmActorArchiveInventoryEntry::Recipient(entry) = entry {
                    self.bind_creation_archive_key(&plan.actor_id, entry)
                        .await?;
                    let vault = self.vault.clone();
                    let actor = inventory.realm_actor_id.clone();
                    let entry = entry.clone();
                    keys.push(
                        crate::run_blocking(move || {
                            vault.with_accepted_key(&actor, &entry.recipient_ref, |private| {
                                Ok(RealmActorContentBackupPrivateRecipientKey {
                                    recipient_ref: entry.recipient_ref.clone(),
                                    content_backup_recipient: entry
                                        .content_backup_recipient
                                        .clone(),
                                    private_key_base64url: arkret_models_crypto::SecretBytes::new(
                                        private.try_into().map_err(invalid)?,
                                    ),
                                })
                            })
                        })
                        .await?,
                    );
                }
            }
            let document = receiving.service_document_at(offer.signature.created_at)?;
            let offer = offer.clone();
            let pending = crate::run_blocking(move || {
                arkret::identity::seal_realm_actor_backup_handover(
                    offer,
                    &document,
                    inventory,
                    keys,
                    Utc::now(),
                )
                .map_err(invalid)
            })
            .await?;
            let checkpoint = pending.export_private_checkpoint().map_err(invalid)?;
            let vault = self.vault.clone();
            let key = checkpoint_key;
            crate::run_blocking(move || {
                vault.compare_exchange_record(&key, None, checkpoint.as_slice())?;
                let winner = vault
                    .read_record(&key)?
                    .ok_or_else(|| invalid("sealed archive checkpoint disappeared"))?;
                arkret::identity::PendingRealmActorBackupHandover::resume_private_checkpoint(
                    &winner,
                )
                .map_err(invalid)
            })
            .await?
        };
        if canonical_json_bytes(&pending.sealed().offer)? != canonical_json_bytes(&offer)? {
            return Err(invalid(
                "sealed handover changed its frozen receiving offer",
            ));
        }
        let confirmation = receiving
            .import_archive_transfer(plan, pending.sealed())
            .await?;
        pending
            .verify_confirmation(
                &confirmation,
                &receiving.service_document_at(confirmation.signature.created_at)?,
            )
            .map_err(invalid)?;
        Ok(ArchiveCustodyAcceptance {
            realm_actor_id: offer.realm_actor_id,
            manager_ref: offer.manager_ref,
            new_service_id: offer.new_service_id,
            next_content_backup_recipient: offer.next_content_backup_recipient,
            inventory_digest: confirmation.inventory_digest,
            handover_digest: confirmation.handover_digest,
        })
    }
}
