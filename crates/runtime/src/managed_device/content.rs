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
}

impl NativeContent {
    pub fn original(&self) -> &arkret::CommittedEventFullView {
        &self.original
    }

    pub fn message(&self) -> Option<&MessageCreatePayload> {
        self.message.as_ref()
    }

    pub(super) fn decrypt(
        original: &arkret::CommittedEventFullView,
        accepted: &arkret::CommittedEventFullView,
        group: &mut ArkretMlsGroup,
    ) -> Result<Self> {
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
            message.content = Some(serde_json::from_slice(&open(
                &encrypted,
                MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE,
            )?)?);
            if let Some(encrypted) = message.encrypted_metadata.take() {
                message.metadata = Some(serde_json::from_slice(&open(
                    &encrypted,
                    MESSAGE_METADATA_MLS_CONTENT_TYPE,
                )?)?);
            }
            Some(message)
        } else if event.kind == arkret::EventKind::MessageRedact {
            None
        } else {
            return Err(invalid("native message delivery has another Event kind"));
        };
        Ok(Self {
            original: original.clone(),
            message,
        })
    }
}

/// Return success only once the external adapter has durably recorded delivery.
/// Failure retains the exact decrypted item for restart and retry.
#[async_trait::async_trait]
pub trait NativeContentSink: Send + Sync + 'static {
    async fn deliver(&self, content: &NativeContent) -> Result<()>;
}
