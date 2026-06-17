//! Spec-shaped `ck.message.create` payload assembly and parsing.
//!
//! Builds the authoritative `message_create_payload` from app-side messages and
//! extracts displayable text / media back out of cokret-shaped content blocks
//! (`zh/models/content-types.md`).

use cokret::{BlobRef, ContentBlock, MessageCreatePayload, StrandId};
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::{Value, json};

use crate::PORTAL_STRAND_TRACK;
use crate::types::Attachment;

const MEDIA_CONTENT_KINDS: [&str; 4] = [
    "ck.content.image",
    "ck.content.video",
    "ck.content.audio",
    "ck.content.file",
];

/// Build the spec `content_block` for plain text
/// (`zh/models/content-types.md` §4.1: `{ "kind": "ck.content.text", "body" }`).
pub fn text_content_block(body: &str) -> Result<Value> {
    ContentBlock::text(body)
        .to_value()
        .map_err(|e| BridgeError::App(e.to_string()))
}

/// Map a MIME type to the spec media content kind
/// (`zh/models/content-types.md` §4.2–§4.5).
pub(crate) fn media_content_kind(media_type: Option<&str>) -> &'static str {
    match media_type.and_then(|mime| mime.split('/').next()) {
        Some("image") => "ck.content.image",
        Some("video") => "ck.content.video",
        Some("audio") => "ck.content.audio",
        _ => "ck.content.file",
    }
}

/// Build the spec media `content_block` (`zh/models/content-types.md` §4.2–§4.5:
/// `blob_ref` / `mime_type` / `size_bytes` / `filename` as block fields; the
/// payload-level `blob_refs[]` listing is added by the submit path). Note the
/// schema explicitly forbids the field name `size` — byte counts are
/// `size_bytes`.
pub fn media_content_block(att: &Attachment) -> Result<Value> {
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
    block
        .to_value()
        .map_err(|e| BridgeError::App(e.to_string()))
}

/// Assemble the authoritative `ck.message.create` payload
/// (`event-payload.schema.json#/$defs/message_create_payload`, closed schema:
/// required `strand_id` + `track_name`, body in `content`, media listed in
/// `blob_refs[]`).
pub(crate) fn build_message_create_payload(
    strand_id: &str,
    content: Value,
    blob_refs: Vec<String>,
) -> Result<Value> {
    let strand_id = StrandId::new(strand_id.to_owned())?;
    let mut payload = MessageCreatePayload::with_content(strand_id, PORTAL_STRAND_TRACK, content);
    payload.blob_refs = blob_refs;
    payload
        .to_value()
        .map_err(|e| BridgeError::App(e.to_string()))
}

/// Extract displayable plain text from a spec-shaped `ck.message.create`
/// payload: the `content_block` lives in `payload.content` and its `body` is
/// the required plain-text fallback (E2EE `encrypted_content` yields an empty
/// string — this bridge does not join MLS groups).
pub fn extract_plain_body(payload: &Value) -> String {
    payload
        .pointer("/content/body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The `strand_id` carried by a `ck.message.create` payload, if present.
pub fn extract_strand_id(payload: &Value) -> Option<&str> {
    payload.get("strand_id").and_then(Value::as_str)
}

/// Locate the media block inside a `content_block`: the block itself when it is
/// a media kind, or the first media part of a `ck.content.composite`.
fn media_block(content: &Value) -> Option<&Value> {
    let kind = content.get("kind").and_then(Value::as_str)?;
    if MEDIA_CONTENT_KINDS.contains(&kind) {
        return Some(content);
    }
    if kind == "ck.content.composite" {
        return content
            .get("parts")
            .and_then(Value::as_array)?
            .iter()
            .find(|part| {
                part.get("kind")
                    .and_then(Value::as_str)
                    .is_some_and(|k| MEDIA_CONTENT_KINDS.contains(&k))
            });
    }
    None
}

/// Extract a media attachment from a spec-shaped `ck.message.create` payload:
/// reads the media `content_block` fields (`blob_ref` / `mime_type` /
/// `filename` / `size_bytes`), falling back to the payload-level `blob_refs[]`
/// for the blob reference.
pub fn extract_attachment(payload: &Value) -> Option<Attachment> {
    let content = payload.get("content")?;
    let block = media_block(content)?;
    let blob_ref = block
        .get("blob_ref")
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("blob_refs")
                .and_then(Value::as_array)
                .and_then(|refs| refs.first())
                .and_then(Value::as_str)
        })?
        .to_owned();
    Some(Attachment {
        blob_ref,
        media_type: block
            .get("mime_type")
            .and_then(Value::as_str)
            .map(str::to_owned),
        filename: block
            .get("filename")
            .and_then(Value::as_str)
            .map(str::to_owned),
        size: block.get("size_bytes").and_then(Value::as_u64),
        caption: content
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}
