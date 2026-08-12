use arkret::{ContentBlockKind, MessageCreatePayload};
use serde_json::json;

use crate::content::{
    build_message_create_payload, extract_attachment, extract_plain_body, extract_strand_id,
    media_content_block, media_content_kind, text_content_block,
};
use crate::ghost::{assert_ghost_suffix_method, location_matches};
use crate::types::{AppDeleteOutcome, AppDeleteReason, Attachment};
use crate::{
    EXTERNAL_REF_SCHEMA, PORTAL_STRAND_TRACK, json_scalar_id_string,
    redaction_payload_for_app_delete,
};

const STRAND_ID: &str = "ak:strand:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH";

#[test]
fn json_scalar_id_string_accepts_string_and_integer_ids() {
    assert_eq!(
        json_scalar_id_string(&json!(" msg-1 ")).as_deref(),
        Some("msg-1")
    );
    assert_eq!(json_scalar_id_string(&json!(42)).as_deref(), Some("42"));
    assert_eq!(
        json_scalar_id_string(&json!(9007199254740993u64)).as_deref(),
        Some("9007199254740993")
    );
}

#[test]
fn json_scalar_id_string_rejects_empty_or_non_scalar_ids() {
    assert!(json_scalar_id_string(&json!("   ")).is_none());
    assert!(json_scalar_id_string(&json!(null)).is_none());
    assert!(json_scalar_id_string(&json!({"id": "nested"})).is_none());
}

#[test]
fn ghost_suffix_method_is_webvh_only() {
    use arkret::DidFullId;

    // Workspace-wide rule: bridge service identities are did:webvh only.
    let webvh = DidFullId::new("did:webvh:bridge.example").unwrap();
    assert!(assert_ghost_suffix_method(&webvh).is_ok());
    // Negative fixtures: did:web (not an accepted alias) and did:key (no
    // path-structured suffix form) are both rejected fail-closed.
    let web = DidFullId::new("did:web:bridge.example").unwrap();
    assert!(assert_ghost_suffix_method(&web).is_err());
    let key = DidFullId::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
    assert!(assert_ghost_suffix_method(&key).is_err());
}

fn media_attachment() -> Attachment {
    Attachment {
        blob_ref: format!("ak:blob:sha256:{}", "a".repeat(64)),
        media_type: Some("image/png".to_owned()),
        filename: Some("shot.png".to_owned()),
        size: Some(2048),
        caption: "look at this".to_owned(),
    }
}

#[test]
fn text_payload_matches_message_create_schema_shape() {
    let content = text_content_block("hello").unwrap();
    let payload =
        serde_json::to_value(build_message_create_payload(STRAND_ID, content, Vec::new()).unwrap())
            .unwrap();
    assert_eq!(payload["strand_id"], STRAND_ID);
    assert_eq!(payload["track_name"], PORTAL_STRAND_TRACK);
    assert_eq!(payload["content"]["kind"], "ak.content.text");
    assert_eq!(payload["content"]["body"], "hello");
    // Closed-schema hygiene: no stray top-level body / media fields.
    assert!(payload.get("body").is_none());
    assert!(payload.get("blob").is_none());
    assert!(payload.get("blob_refs").is_none());
}

#[test]
fn media_payload_uses_blob_refs_and_forbidden_field_names_are_absent() {
    let att = media_attachment();
    let content = media_content_block(&att).unwrap();
    let payload = serde_json::to_value(
        build_message_create_payload(STRAND_ID, content, vec![att.blob_ref.clone()]).unwrap(),
    )
    .unwrap();
    assert_eq!(payload["content"]["kind"], "ak.content.image");
    assert_eq!(payload["content"]["body"], "look at this");
    assert_eq!(payload["content"]["blob_ref"], att.blob_ref);
    assert_eq!(payload["content"]["mime_type"], "image/png");
    assert_eq!(payload["content"]["size_bytes"], 2048);
    // content_block schema forbids `size` (byte counts are `size_bytes`)
    // and removed flat fields must not leak into the payload.
    assert!(payload["content"].get("size").is_none());
    assert!(payload["content"].get("mimetype").is_none());
    assert_eq!(payload["blob_refs"][0], att.blob_ref);
    assert!(payload.get("blob").is_none());
}

#[test]
fn media_kind_follows_mime_category_and_file_requires_filename() {
    assert_eq!(
        media_content_kind(Some("video/mp4")),
        ContentBlockKind::Video
    );
    assert_eq!(
        media_content_kind(Some("audio/ogg")),
        ContentBlockKind::Audio
    );
    assert_eq!(
        media_content_kind(Some("application/pdf")),
        ContentBlockKind::File
    );
    assert_eq!(media_content_kind(None), ContentBlockKind::File);

    let mut att = media_attachment();
    att.media_type = Some("application/pdf".to_owned());
    att.filename = None;
    let block = media_content_block(&att).unwrap().to_value().unwrap();
    // `filename` is MUST for ak.content.file even when upstream gave none.
    assert!(
        block["filename"]
            .as_str()
            .is_some_and(|name| !name.is_empty())
    );
}

#[test]
fn extraction_reads_spec_shaped_payloads() {
    let att = media_attachment();
    let content = media_content_block(&att).unwrap();
    let payload =
        build_message_create_payload(STRAND_ID, content, vec![att.blob_ref.clone()]).unwrap();

    assert_eq!(extract_plain_body(&payload).unwrap(), "look at this");
    assert_eq!(extract_strand_id(&payload), STRAND_ID);
    let extracted = extract_attachment(&payload).unwrap().expect("attachment");
    assert_eq!(extracted.blob_ref, att.blob_ref);
    assert_eq!(extracted.media_type.as_deref(), Some("image/png"));
    assert_eq!(extracted.filename.as_deref(), Some("shot.png"));
    assert_eq!(extracted.size, Some(2048));
    assert_eq!(extracted.caption, "look at this");
}

#[test]
fn extraction_handles_composite_payloads() {
    let composite = serde_json::from_value::<MessageCreatePayload>(json!({
        "strand_id": STRAND_ID,
        "track_name": "discussion",
        "content": {
            "kind": "ak.content.composite",
            "body": "caption text",
            "parts": [
                { "kind": "ak.content.text", "body": "caption text" },
                {
                    "kind": "ak.content.file",
                    "body": "spec.pdf",
                    "blob_ref": format!("ak:blob:sha256:{}", "b".repeat(64)),
                    "mime_type": "application/pdf",
                    "filename": "spec.pdf",
                    "size_bytes": 7
                }
            ]
        }
    }))
    .unwrap();
    let extracted = extract_attachment(&composite).unwrap().expect("attachment");
    assert_eq!(extracted.filename.as_deref(), Some("spec.pdf"));
    assert_eq!(extracted.size, Some(7));
}

#[test]
fn location_match_requires_protocol_network_and_location() {
    let location = json!({
        "schema": EXTERNAL_REF_SCHEMA,
        "protocol": "discord",
        "network_id": "tenant-1",
        "location_id": "chan-1",
    });
    assert!(location_matches(Some(&location), &location));
    let mut other = location.clone();
    other["location_id"] = json!("chan-2");
    assert!(!location_matches(Some(&other), &location));
    assert!(!location_matches(None, &location));
}

#[test]
fn app_delete_recall_builds_message_redact_payload() {
    let target_event_id = "ak:event:AcuTkvesoi9I-a82lRObr46_TuorpNOfeSLt8XCCajYY";
    let payload = redaction_payload_for_app_delete(target_event_id, AppDeleteReason::UserDeleted)
        .expect("redaction payload result")
        .expect("redaction payload");
    let payload = serde_json::to_value(payload).unwrap();
    assert_eq!(payload["target_event_id"], target_event_id);
    assert_eq!(payload["reason"], "external_user_delete");
    assert!(payload.get("message_id").is_none());
    assert!(payload.get("reason_code").is_none());
}

#[test]
fn app_delete_expiry_is_not_a_redaction() {
    assert!(
        redaction_payload_for_app_delete(
            "ak:event:AcuTkvesoi9I-a82lRObr46_TuorpNOfeSLt8XCCajYY",
            AppDeleteReason::DisappearingExpiry,
        )
        .expect("redaction payload result")
        .is_none()
    );
    assert_eq!(
        AppDeleteReason::DisappearingExpiry.ignored_reason_code(),
        "app_delete_disappearing_expiry_not_redaction"
    );
    assert_eq!(
        AppDeleteOutcome::Ignored {
            reason_code: AppDeleteReason::RetentionExpiry.ignored_reason_code(),
        },
        AppDeleteOutcome::Ignored {
            reason_code: "app_delete_retention_expiry_not_redaction",
        }
    );
}
