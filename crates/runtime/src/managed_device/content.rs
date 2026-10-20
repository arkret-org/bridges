//! Private content delivery retains the signed original separately from plaintext.
use arkret::EventPayloadExt as _;
use arkret::mls::ArkretMlsGroup;
use arkret_models_collaboration::events_payloads::{
    MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE, MESSAGE_METADATA_MLS_CONTENT_TYPE, MessageCreatePayload,
};

use super::*;

/// A local decrypted view, never a rewritten or newly signed protocol Event.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeContent {
    original: arkret::CommittedEventFullView,
    message: Option<MessageCreatePayload>,
    attachments: Vec<NativeAttachment>,
    pub(super) attachments_opened: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeAttachment {
    pub(super) descriptor: arkret::EncryptedAttachment,
    #[serde(with = "super::attachment::private_bytes")]
    plaintext: Vec<u8>,
}

impl NativeContent {
    pub fn original(&self) -> &arkret::CommittedEventFullView {
        &self.original
    }

    pub fn message(&self) -> Option<&MessageCreatePayload> {
        self.message.as_ref()
    }

    pub fn attachment_bytes(&self, reference: &str) -> Option<&[u8]> {
        self.attachments
            .iter()
            .find(|item| item.descriptor.blob_ref().as_str() == reference)
            .map(|item| item.plaintext.as_slice())
    }

    pub(super) fn attachments(&self) -> &[NativeAttachment] {
        &self.attachments
    }
    pub(super) fn without_attachment_bytes(&self) -> Self {
        let mut view = self.clone();
        view.attachments.clear();
        view
    }

    pub(super) async fn open_attachments(
        &mut self,
        runtime: &ManagedDeviceRuntime,
        device: &ManagedDevice,
        reader: &ManagedDeviceReader,
        accepted: &arkret::CommittedEventFullView,
        group: &ArkretMlsGroup,
    ) -> Result<()> {
        if self.attachments_opened {
            return Ok(());
        }
        let Some(content) = self
            .message
            .as_ref()
            .and_then(|message| message.content.as_ref())
        else {
            self.attachments_opened = true;
            return Ok(());
        };
        let mut blocks = vec![content];
        let mut descriptors = std::collections::BTreeMap::new();
        let mut total = 0u64;
        while let Some(block) = blocks.pop() {
            blocks.extend(block.parts.iter());
            if block.blob_ref().is_some() && block.rendered_encrypted_attachment()?.is_none() {
                return Err(invalid("MLS media has no encrypted attachment descriptor"));
            }
            if let Some(descriptor) = block.rendered_encrypted_attachment()? {
                if let Some(prior) =
                    descriptors.insert(descriptor.blob_ref().clone(), descriptor.clone())
                {
                    if prior != descriptor {
                        return Err(invalid("attachment reference has conflicting descriptors"));
                    }
                } else {
                    total = total
                        .checked_add(descriptor.size_bytes())
                        .ok_or_else(|| invalid("attachment size overflow"))?;
                    if total > super::attachment::MAX_ATTACHMENT_BYTES as u64 {
                        return Err(invalid("message attachments exceed local delivery budget"));
                    }
                }
            }
        }
        for descriptor in descriptors.into_values() {
            let plaintext = runtime
                .decrypt_attachment(device, reader, &descriptor, accepted, group)
                .await?;
            self.attachments.push(NativeAttachment {
                descriptor,
                plaintext,
            });
        }
        self.attachments_opened = true;
        Ok(())
    }

    pub(super) fn decrypt(
        original: &arkret::CommittedEventFullView,
        accepted: &arkret::CommittedEventFullView,
        group: &mut ArkretMlsGroup,
    ) -> Result<Option<Self>> {
        let event = &original.event;
        let message = if event.kind == arkret::EventKind::MessageCreate {
            let mut message = event.as_message_create()?;
            if message.content.is_some() || message.metadata.is_some() {
                return Err(invalid(
                    "activated MLS stream contains plaintext message data",
                ));
            }
            let sender = String::from_utf8(arkret::mls_basic_credential_identity(&event.actor_id)?)
                .map_err(|e| invalid(e.to_string()))?;
            let mut open =
                |envelope: &arkret::EncryptedEnvelope, content_type: &str| -> Result<Vec<u8>> {
                    if envelope.content_type != content_type
                        || envelope.encryption_context.epoch() != group.epoch()
                        || envelope.encryption_context.group_state_ref() != &accepted.event.event_id
                    {
                        return Err(invalid("message differs from its exact accepted MLS base"));
                    }
                    let header = envelope.reconstruct_pre_encryption_header(
                        arkret::EncryptedPayloadScheme::MlsRfc9420,
                        event.scope_ref.clone(),
                        event.kind.as_str(),
                        &sender,
                        None,
                    )?;
                    let payload = arkret::mls::encrypted_envelope_to_payload_with_verified_header(
                        envelope, header,
                    )
                    .map_err(|e| invalid(e.to_string()))?;
                    group
                        .decrypt_payload(&payload)
                        .map_err(|e| invalid(e.to_string()))
                };
            let encrypted = message
                .encrypted_content
                .take()
                .ok_or_else(|| invalid("activated MLS message has no encrypted content"))?;
            let content_bytes = open(&encrypted, MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE)?;
            let metadata_bytes = message
                .encrypted_metadata
                .take()
                .map(|encrypted| open(&encrypted, MESSAGE_METADATA_MLS_CONTENT_TYPE))
                .transpose()?;
            // Authenticate every envelope before classifying plaintext. The
            // caller persists this receive ratchet even when application data
            // is rejected; cryptographic failures still return an error.
            let decoded = (|| -> Result<MessageCreatePayload> {
                message.content = Some(serde_json::from_slice(&content_bytes)?);
                let content = message.content.as_ref().expect("just decoded").to_value()?;
                arkret_models_collaboration::events_payloads::validate_content_block(&content)
                    .map_err(|error| invalid(error.to_string()))?;
                arkret_models_collaboration::events_payloads::validate_mentions_in_realm(
                    &content,
                    &event.realm_id,
                )
                .map_err(|error| invalid(error.to_string()))?;
                message.metadata = metadata_bytes
                    .as_deref()
                    .map(serde_json::from_slice)
                    .transpose()?;
                Ok(message)
            })();
            let Ok(message) = decoded else {
                return Ok(None);
            };
            Some(message)
        } else if event.kind == arkret::EventKind::MessageRedact {
            None
        } else {
            return Err(invalid("native message delivery has another Event kind"));
        };
        Ok(Some(Self {
            original: original.clone(),
            message,
            attachments: Vec::new(),
            attachments_opened: false,
        }))
    }
}

/// Return success only once the external adapter has durably recorded delivery.
/// Failure retains the exact decrypted item for restart and retry.
#[async_trait::async_trait]
pub trait NativeContentSink: Send + Sync + 'static {
    /// Local adapter demand, never a protocol permission or an implicit grant.
    fn requires_attachments(&self) -> bool {
        false
    }
    async fn deliver(&self, content: &NativeContent) -> Result<()>;
}
