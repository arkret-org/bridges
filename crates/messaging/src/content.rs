//! Spec-shaped `ck.message.create` payload assembly and parsing.
//!
//! Builds the authoritative `message_create_payload` from app-side messages and
//! extracts displayable text / media back out of arkret-shaped content blocks
//! (`zh/models/content-types.md`).

use arkret::{
    BlobRef, CONTENT_KIND_AUDIO, CONTENT_KIND_FILE, CONTENT_KIND_IMAGE, CONTENT_KIND_VIDEO,
    ContentBlock, ContentBlockMediaAttachment, MessageCreatePayload, StrandId,
};
use arkret_bridge_runtime::{BridgeError, Result};
use serde_json::{Value, json};

use crate::PORTAL_STRAND_TRACK;
use crate::types::Attachment;

/// Build the spec `content_block` for plain text
/// (`zh/models/content-types.md` §4.1: `{ "kind": "ck.content.text", "body" }`).
pub fn text_content_block(body: &str) -> Result<ContentBlock> {
    Ok(ContentBlock::text(body))
}

/// Map a MIME type to the spec media content kind
/// (`zh/models/content-types.md` §4.2–§4.5).
pub(crate) fn media_content_kind(media_type: Option<&str>) -> &'static str {
    match media_type.and_then(|mime| mime.split('/').next()) {
        Some("image") => CONTENT_KIND_IMAGE,
        Some("video") => CONTENT_KIND_VIDEO,
        Some("audio") => CONTENT_KIND_AUDIO,
        _ => CONTENT_KIND_FILE,
    }
}

/// Build the spec media `content_block` (`zh/models/content-types.md` §4.2–§4.5:
/// `blob_ref` / `mime_type` / `size_bytes` / `filename` as block fields; the
/// payload-level `blob_refs[]` listing is added by the submit path). Note the
/// schema explicitly forbids the field name `size` — byte counts are
/// `size_bytes`.
pub fn media_content_block(att: &Attachment) -> Result<ContentBlock> {
    let blob = BlobRef::new(att.blob_ref.clone())
        .map_err(|e| BridgeError::App(format!("invalid blob_ref: {e}")))?;
    let kind = media_content_kind(att.media_type.as_deref());
    let filename = att
        .filename
        .clone()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "attachment".to_owned());
    let body = if att.caption.is_empty() {
        filename.clone()
    } else {
        att.caption.clone()
    };
    let mut block = ContentBlock::new(kind, body)
        .with_field("blob_ref", Value::String(blob.as_str().to_owned()));
    if let Some(mime) = &att.media_type {
        block = block.with_field("mime_type", Value::String(mime.clone()));
    }
    // `filename` is MUST for ck.content.file and harmless elsewhere.
    block = block.with_field("filename", Value::String(filename));
    if let Some(size) = att.size {
        block = block.with_field("size_bytes", json!(size));
    }
    Ok(block)
}

/// Assemble the authoritative `ck.message.create` payload
/// (`event-payload.schema.json#/$defs/message_create_payload`, closed schema:
/// required `strand_id` + `track_name`, body in `content`, media listed in
/// `blob_refs[]`).
pub(crate) fn build_message_create_payload(
    strand_id: &str,
    content: ContentBlock,
    blob_refs: Vec<String>,
) -> Result<MessageCreatePayload> {
    let strand_id = StrandId::new(strand_id.to_owned())?;
    let content = content
        .to_value()
        .map_err(|e| BridgeError::App(e.to_string()))?;
    let mut payload = MessageCreatePayload::with_content(strand_id, PORTAL_STRAND_TRACK, content);
    payload.blob_refs = blob_refs;
    Ok(payload)
}

/// Extract displayable plain text from a typed `ck.message.create` payload.
/// E2EE `encrypted_content` yields an empty string; this bridge does not join
/// MLS groups.
pub fn extract_plain_body(payload: &MessageCreatePayload) -> Result<String> {
    payload.plain_body().map_err(BridgeError::from)
}

/// The `strand_id` carried by a typed `ck.message.create` payload.
pub fn extract_strand_id(payload: &MessageCreatePayload) -> &str {
    payload.strand_id.as_str()
}

/// Extract a media attachment from a typed `ck.message.create` payload.
pub fn extract_attachment(payload: &MessageCreatePayload) -> Result<Option<Attachment>> {
    Ok(payload
        .first_media_attachment()?
        .map(attachment_from_sdk_media))
}

fn attachment_from_sdk_media(media: ContentBlockMediaAttachment) -> Attachment {
    Attachment {
        blob_ref: media.blob_ref,
        media_type: media.mime_type,
        filename: media.filename,
        size: media.size_bytes,
        caption: media.caption,
    }
}
