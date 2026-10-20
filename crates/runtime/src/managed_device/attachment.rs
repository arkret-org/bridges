//! Exact-epoch attachment custody. Only ciphertext reaches Blob storage.
use arkret::crypto::blob_aead;
use arkret::mls::ArkretMlsGroup;
use arkret::{
    AttachmentContentKeyContext, EncryptedAttachment, EncryptedAttachmentGroupStateRef,
    EncryptedAttachmentKeyAlgorithm, EncryptedAttachmentKeyRef,
};
use arkret_models_collaboration::objects::blob::{
    BlobStorageEncryption, BlobStorageEncryptionScheme, BlobUploadMetadata,
};

use super::*;

pub(super) const MAX_ATTACHMENT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenAttachment {
    input_digest: String,
    device_operation_id: String,
    descriptor: EncryptedAttachment,
    #[serde(with = "private_bytes")]
    ciphertext: Vec<u8>,
}

pub(super) mod private_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&arkret::base64url_encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let bytes = arkret::base64url_decode(&encoded).map_err(serde::de::Error::custom)?;
        if arkret::base64url_encode(&bytes) != encoded {
            return Err(serde::de::Error::custom("noncanonical private bytes"));
        }
        Ok(bytes)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentCheckpoint {
    accepted: arkret::CommittedEventFullView,
    state: arkret::MlsGroupStateRecord,
}

impl ManagedDeviceRuntime {
    pub(super) async fn attachment_checkpoints_for_device(
        &self,
        actor: &ActorId,
        device_id: &DeviceId,
    ) -> Result<Vec<(String, String)>> {
        let store = self.store.clone();
        let entries =
            run_blocking(move || store.entries_with_prefix("managed-attachment-checkpoint/v1/"))
                .await?;
        let mut selected = Vec::new();
        for (key, raw) in entries {
            let checkpoint: AttachmentCheckpoint =
                self.authoring.decrypt_key_material(&key, &raw)?;
            if &checkpoint.state.actor_id == actor
                && checkpoint.state.endpoint
                    == arkret::MlsEndpointIdentity::human_device(
                        actor.signing_principal_id().clone(),
                        device_id.clone(),
                    )
            {
                selected.push((key, raw));
            }
        }
        Ok(selected)
    }

    fn attachment_checkpoint_key(
        device: &ManagedDevice,
        reference: &arkret::EventId,
    ) -> Result<String> {
        Ok(format!(
            "managed-attachment-checkpoint/v1/{}",
            canonical_sha256(&(
                &device.actor_id,
                &device.authorization_event_id,
                &device.effective_scope,
                reference
            ))?
        ))
    }

    /// Preserve the verified exporter epoch before advancing its receive state.
    /// This private checkpoint never grants history access on its own.
    pub(super) async fn retain_attachment_checkpoint(
        &self,
        device: &ManagedDevice,
        accepted: &arkret::CommittedEventFullView,
        group: &ArkretMlsGroup,
    ) -> Result<()> {
        group
            .verify_installed_historical_base(accepted, &accepted.event.event_id)
            .map_err(|e| invalid(e.to_string()))?;
        let key = Self::attachment_checkpoint_key(device, &accepted.event.event_id)?;
        if self.read(&key).await?.is_none() {
            let checkpoint = AttachmentCheckpoint {
                accepted: accepted.clone(),
                state: group
                    .export_state_record()
                    .map_err(|e| invalid(e.to_string()))?,
            };
            let encrypted = self.authoring.encrypt_key_material(&key, &checkpoint)?;
            let tombstone =
                super::revocation::retirement_key(&device.actor_id, &device.operation_id)?;
            let store = self.store.clone();
            let inserted = run_blocking(move || {
                store.compare_exchange_batch(
                    &[(key.clone(), None), (tombstone, None)],
                    &[(key, Some(encrypted))],
                )
            })
            .await?;
            if !inserted
                && self
                    .is_retired_device(&device.actor_id, &device.operation_id)
                    .await?
            {
                return Err(invalid(
                    "retired Device cannot retain new private checkpoints",
                ));
            }
        }
        Ok(())
    }

    pub async fn upload_attachment(
        &self,
        actor: &ActorId,
        scope: &ScopeRef,
        operation: &str,
        bytes: &[u8],
        mime: &str,
    ) -> Result<EncryptedAttachment> {
        if bytes.len() > MAX_ATTACHMENT_BYTES || mime.trim().is_empty() || operation.is_empty() {
            return Err(invalid(
                "attachment exceeds local budget or lacks its stable identity/MIME",
            ));
        }
        let device = self.device_for_actor(actor).await?;
        if &device.effective_scope != scope {
            return Err(invalid("attachment scope differs from its Device"));
        }
        let reader = self.open_reader(&device).await?;
        self.ensure_realm_membership(&device).await?;
        let key = format!(
            "managed-attachment/v1/{}",
            canonical_sha256(&(actor, scope, operation))?
        );
        let digest = canonical_sha256(&(mime, canonical_sha256(&bytes)?))?;
        let saved = if let Some(raw) = self.read(&key).await? {
            self.authoring
                .decrypt_key_material::<FrozenAttachment>(&key, &raw)?
        } else {
            let target = self
                .edge
                .config()
                .arkret
                .managed_actor_authoring
                .device
                .as_ref()
                .map_or(8, |config| config.key_package_inventory_target);
            self.maintain_mls_key_packages(&device, target).await?;
            self.poll_welcome_queue(&device, &reader).await?;
            let progress = self.poll_content_stream(&device, &reader).await?;
            if progress.pending_events != 0 {
                return Err(invalid("attachment waits for preceding verified content"));
            }
            let (_, _, record) = self.accepted_device_record(&device).await?;
            let mut group = super::inbox::restore_group(&record, &device)?
                .ok_or_else(|| invalid("attachment awaits accepted MLS Welcome"))?;
            let accepted = super::inbox::accepted_group_original(&record, &device)?
                .ok_or_else(|| invalid("attachment has no accepted MLS base"))?;
            let genesis = self
                .install_received_roster(&device, &reader, &accepted, &mut group)
                .await?;
            self.retain_attachment_checkpoint(&device, &accepted, &group)
                .await?;
            let context = AttachmentContentKeyContext {
                effective_scope: scope.clone(),
                genesis_event_ref: genesis,
                epoch: group.epoch(),
                scheme: blob_aead::SCHEME_STREAM.into(),
                encryption_algorithm: blob_aead::ALG_STREAM_XCHACHA.into(),
                content_key_salt: blob_aead::fresh_content_key_salt()
                    .map_err(|e| invalid(e.to_string()))?,
            };
            let secret = arkret::mls::derive_attachment_content_key(&group, &context)
                .map_err(|e| invalid(e.to_string()))?;
            let params = blob_aead::StreamEncryptParams {
                key_ref: EncryptedAttachmentKeyRef {
                    algorithm: EncryptedAttachmentKeyAlgorithm::Mls,
                    group_state_ref: EncryptedAttachmentGroupStateRef::Event(
                        accepted.event.event_id.clone(),
                    ),
                },
                content_key_salt: context.content_key_salt,
                digest_suite: crate::PRODUCER_DIGEST_SUITE,
                media_type: mime.into(),
                segment_bytes: 64 * 1024,
            };
            let resolver = |reference: &EncryptedAttachmentGroupStateRef| {
                reference
                    .event_id()
                    .ok()
                    .filter(|id| id == &accepted.event.event_id)
                    .map(|_| group.epoch())
            };
            let (ciphertext, descriptor) =
                blob_aead::encrypt_stream(bytes, &secret, &params, &resolver)
                    .map_err(|e| invalid(e.to_string()))?;
            let frozen = FrozenAttachment {
                input_digest: digest.clone(),
                device_operation_id: device.operation_id.clone(),
                descriptor,
                ciphertext,
            };
            let encrypted = self.authoring.encrypt_key_material(&key, &frozen)?;
            reader.check_device(&device)?;
            self.cas(&key, None, encrypted).await?;
            let raw = self
                .read(&key)
                .await?
                .ok_or_else(|| invalid("attachment custody disappeared"))?;
            self.authoring
                .decrypt_key_material::<FrozenAttachment>(&key, &raw)?
        };
        if saved.input_digest != digest || saved.device_operation_id != device.operation_id {
            return Err(invalid(
                "attachment delivery identity already binds different bytes or Device",
            ));
        }
        let metadata = BlobUploadMetadata {
            realm_id: Some(scope.realm_id().clone()),
            content_digest: None,
            size_bytes: saved.ciphertext.len() as u64,
            media_type: Some("application/octet-stream".into()),
            filename: None,
            encryption: Some(BlobStorageEncryption {
                scheme: BlobStorageEncryptionScheme::StreamV1,
            }),
        };
        reader.check_device(&device)?;
        let uploaded = device
            .client()
            .blob_upload_bytes(&metadata, saved.ciphertext)
            .await?;
        reader.check_device(&device)?;
        if &uploaded.blob_ref != saved.descriptor.blob_ref()
            || uploaded.size_bytes != metadata.size_bytes
        {
            return Err(invalid("Blob upload result differs from frozen ciphertext"));
        }
        Ok(saved.descriptor)
    }

    pub(super) async fn decrypt_attachment(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
        descriptor: &EncryptedAttachment,
        accepted: &arkret::CommittedEventFullView,
        current_group: &ArkretMlsGroup,
    ) -> Result<Vec<u8>> {
        if descriptor.size_bytes() > MAX_ATTACHMENT_BYTES as u64 {
            return Err(invalid("attachment exceeds local plaintext budget"));
        }
        let reference = descriptor.key_ref().group_state_ref.event_id()?;
        let (original, mut group) = if reference == accepted.event.event_id {
            (
                accepted.clone(),
                ArkretMlsGroup::restore_from_state_record(
                    &current_group
                        .export_state_record()
                        .map_err(|e| invalid(e.to_string()))?,
                )
                .map_err(|e| invalid(e.to_string()))?,
            )
        } else {
            let key = Self::attachment_checkpoint_key(device, &reference)?;
            let raw = self
                .read(&key)
                .await?
                .ok_or_else(|| invalid("authorized attachment epoch is unavailable"))?;
            let saved: AttachmentCheckpoint = self.authoring.decrypt_key_material(&key, &raw)?;
            let group = ArkretMlsGroup::restore_from_state_record(&saved.state)
                .map_err(|e| invalid(e.to_string()))?;
            (saved.accepted, group)
        };
        if group.scope() != &device.effective_scope || group.local_actor_id() != &device.actor_id {
            return Err(invalid(
                "attachment checkpoint belongs to another scope or actor",
            ));
        }
        group
            .verify_installed_historical_base(&original, &reference)
            .map_err(|e| invalid(e.to_string()))?;
        let read = garth::own_station_results::consume_own_station_device_event(
            reader.client(),
            &reference,
            reader.client().committed_event_get(&reference).await?,
        )
        .await
        .map_err(|e| invalid(e.to_string()))?;
        if read.full().map_err(|e| invalid(e.to_string()))? != &original {
            return Err(invalid(
                "attachment checkpoint differs from authorized original",
            ));
        }
        let genesis = self
            .install_received_roster(device, reader, &original, &mut group)
            .await?;
        let context =
            descriptor.content_key_context(device.effective_scope.clone(), genesis, group.epoch());
        let secret = arkret::mls::derive_attachment_content_key(&group, &context)
            .map_err(|e| invalid(e.to_string()))?;
        let ciphertext = self
            .read_attachment_ciphertext(device, reader, descriptor)
            .await?;
        let resolver = |r: &EncryptedAttachmentGroupStateRef| {
            r.event_id()
                .ok()
                .filter(|id| id == &reference)
                .map(|_| group.epoch())
        };
        let plaintext = blob_aead::decrypt_stream(&ciphertext, descriptor, &secret, &resolver)
            .map_err(|e| invalid(e.to_string()))?;
        read.full().map_err(|e| invalid(e.to_string()))?;
        reader.check_device(device)?;
        Ok(plaintext)
    }

    pub(super) async fn read_attachment_ciphertext(
        &self,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
        descriptor: &EncryptedAttachment,
    ) -> Result<Vec<u8>> {
        reader.check_device(device)?;
        let options = arkret::http_client::BlobDownloadOptions::new()
            .max_bytes(MAX_ATTACHMENT_BYTES + 128 * 1024);
        let bytes = device
            .client()
            .blob_download_bytes(descriptor.blob_ref(), &options)
            .await?;
        reader.check_device(device)?;
        Ok(bytes)
    }
}
