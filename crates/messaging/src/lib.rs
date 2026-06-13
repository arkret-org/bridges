//! Messaging helper layer for chat/social Cokret Applet bridges.
//!
//! This crate sits on top of `cokret-bridge-runtime`. It owns the
//! message-shaped contract shared by the social bridge adapters:
//!
//! - app channel/message/user mapping tables (location ↔ `(realm_id, flow_id)` per
//!   applet-integration §10.1),
//! - spec-shaped `ck.message.create` payload assembly (`{flow_id, track_name, content, blob_refs}`)
//!   and parsing,
//! - portal flow acquisition/creation (`ck.flow.create`),
//! - `MessageBridge` and `run_message_bridge`,
//! - `external_ref` provenance for upstream channel/user/message ids.

mod models;
mod schema;
pub mod webhook;

use std::sync::Arc;

use async_trait::async_trait;
use cokret::http_client::ClientRequestOptions;
use cokret::{
    AppletBridgeErrorBuilder, AppletBridgeErrorVisibility, AppletId, BlobRef, ContentBlock, Did,
    Event, FlowCreateObject, FlowId, FlowTrackConfig, GhostActorProvisionOutcome,
    GhostActorProvisionRequestBody, MessageCreatePayload, ObjectCreatePayload, RealmId,
};
use cokret_bridge_runtime::app::{
    AppletResolver, BridgeApp, BridgeContext, ResolvedActor, ResolvedRealm,
};
use cokret_bridge_runtime::db::DatabaseManager;
use cokret_bridge_runtime::{BridgeError, Result, redact_sensitive_url_values};
use diesel::prelude::*;
use diesel_migrations::{EmbeddedMigrations, embed_migrations};
use futures::StreamExt;
use serde_json::{Value, json};

/// Embedded migrations for the messaging-owned mapping tables (`room_mappings`,
/// `message_mappings`, `user_mappings`). The backend dialect is selected at
/// compile time, matching the runtime's active connection feature.
#[cfg(feature = "sqlite")]
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");
#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/postgres");
#[cfg(all(feature = "mysql", not(feature = "sqlite"), not(feature = "postgres")))]
const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/mysql");

pub use cokret_bridge_runtime as runtime;
pub use models::{MessageMapping, RoomMapping, UserMapping};
use models::{NewMessageMapping, NewRoomMapping, NewUserMapping};
pub use runtime::salvo;

// Not a `ck.`-prefixed id: the `ck.` namespace is reserved for spec-registered
// protocol objects/operations/schemas. This is a bridge-private (applet-side)
// provenance schema id, so it uses a reverse-domain product prefix to avoid
// colliding with any future spec-defined messaging external_ref schema.
const EXTERNAL_REF_SCHEMA: &str = "org.cokret.bridge.external_ref.messaging.v1";
const MESSAGE_MAPPING_KEY_SEPARATOR: char = '\u{1f}';

/// The inbound (cokret → app) event kinds this messaging bridge consumes, used
/// for capability enforcement (BRG-01-009): the runtime rejects any pushed event
/// whose kind is not listed. `MessageAdapter::on_cokret_event` handles exactly
/// message creation and redaction.
const BRIDGE_HANDLED_EVENT_KINDS: [&str; 2] = ["ck.message.create", "ck.message.redact"];

/// The flow track bridged messages write into. applet-integration §10.1: 桥接
/// 消息默认写入 `discussion`;v1 的 `message_create_payload.track_name` 在
/// schema 中即 const `"discussion"`。
const PORTAL_FLOW_TRACK: &str = "discussion";

/// Page size for the §10.1 step-2 projection scan over realm history.
const PORTAL_FLOW_SCAN_PAGE_LIMIT: u32 = 200;
/// Page cap for the §10.1 step-2 projection scan (bounds startup cost on large
/// realms; a fresh portal realm resolves in one page).
const PORTAL_FLOW_SCAN_MAX_PAGES: usize = 25;

/// An inbound message from an external app into Cokret.
#[derive(Clone, Debug)]
pub struct InboundAppMessage {
    pub app_channel: String,
    pub app_user: String,
    pub app_message_id: String,
    pub body: String,
}

/// An outbound message from Cokret to an external app.
#[derive(Clone, Debug)]
pub struct OutboundAppMessage {
    pub app_channel: String,
    pub sender_display: String,
    pub body: String,
    pub reply_to: Option<String>,
    /// Present when the cokret event carried media; the adapter may download it
    /// via [`MessageContext::download_blob`] and re-send to the app.
    pub attachment: Option<Attachment>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SenderRenderStyle {
    Plain,
    MarkdownItalic,
    MarkdownBold,
}

impl OutboundAppMessage {
    pub fn rendered_body(&self, style: SenderRenderStyle) -> String {
        match style {
            SenderRenderStyle::Plain => format!("{}: {}", self.sender_display, self.body),
            SenderRenderStyle::MarkdownItalic => {
                format!("*{}*: {}", self.sender_display, self.body)
            }
            SenderRenderStyle::MarkdownBold => {
                format!("**{}**: {}", self.sender_display, self.body)
            }
        }
    }
}

/// The app-side message reference returned after the adapter sends.
#[derive(Clone, Debug)]
pub struct AppMessageRef {
    pub app_message_id: String,
}

/// A media attachment that already resides in cokret blob storage (referenced by
/// `blob_ref`). Inbound: the adapter downloads app media, uploads it via
/// [`MessageContext::upload_blob`], then submits with [`MessageContext::submit_media_message`].
/// Outbound: extracted from a `ck.message.create` media payload and handed to the
/// adapter, which downloads via [`MessageContext::download_blob`] and re-sends.
#[derive(Clone, Debug)]
pub struct Attachment {
    pub blob_ref: String,
    pub media_type: Option<String>,
    pub filename: Option<String>,
    pub size: Option<u64>,
    /// Caption / display text for the media event (may be empty).
    pub caption: String,
}

pub struct DownloadedMedia {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
}

pub const MAX_EXTERNAL_MEDIA_BYTES: usize = 32 * 1024 * 1024;

/// Build the spec `content_block` for plain text
/// (`zh/models/content-types.md` §4.1: `{ "kind": "ck.content.text", "body" }`).
pub fn text_content_block(body: &str) -> Result<Value> {
    ContentBlock::text(body)
        .to_value()
        .map_err(|e| BridgeError::App(e.to_string()))
}

/// Map a MIME type to the spec media content kind
/// (`zh/models/content-types.md` §4.2–§4.5).
fn media_content_kind(media_type: Option<&str>) -> &'static str {
    match media_type.and_then(|mime| mime.split('/').next()) {
        Some("image") => "ck.content.image",
        Some("video") => "ck.content.video",
        Some("audio") => "ck.content.audio",
        _ => "ck.content.file",
    }
}

const MEDIA_CONTENT_KINDS: [&str; 4] = [
    "ck.content.image",
    "ck.content.video",
    "ck.content.audio",
    "ck.content.file",
];

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
/// required `flow_id` + `track_name`, body in `content`, media listed in
/// `blob_refs[]`).
fn build_message_create_payload(
    flow_id: &str,
    content: Value,
    blob_refs: Vec<String>,
) -> Result<Value> {
    let flow_id = FlowId::new(flow_id.to_owned())?;
    let mut payload = MessageCreatePayload::with_content(flow_id, PORTAL_FLOW_TRACK, content);
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

/// The `flow_id` carried by a `ck.message.create` payload, if present.
pub fn extract_flow_id(payload: &Value) -> Option<&str> {
    payload.get("flow_id").and_then(Value::as_str)
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

/// Channel/message/user mapping store persisted through the runtime database.
pub struct MessageStore {
    db: Arc<DatabaseManager>,
}

impl MessageStore {
    pub fn new(db: Arc<DatabaseManager>) -> Result<Self> {
        db.run_migrations(MIGRATIONS)?;
        Ok(Self { db })
    }

    pub fn upsert_room(
        &self,
        app_channel: &str,
        realm_id: &str,
        alias: Option<&str>,
    ) -> Result<()> {
        use schema::room_mappings::dsl;

        let mut conn = self.db.conn()?;
        let exists = dsl::room_mappings
            .filter(dsl::app_channel_id.eq(app_channel))
            .first::<RoomMapping>(&mut conn)
            .optional()?;
        if let Some(existing) = exists {
            // A realm change invalidates the cached portal flow (the flow
            // belongs to the previous realm); it is re-resolved lazily.
            let portal_flow_id = if existing.cokret_realm_id == realm_id {
                existing.portal_flow_id.clone()
            } else {
                None
            };
            diesel::update(dsl::room_mappings.filter(dsl::id.eq(existing.id)))
                .set((
                    dsl::cokret_realm_id.eq(realm_id),
                    dsl::portal_alias.eq(alias),
                    dsl::portal_flow_id.eq(portal_flow_id),
                ))
                .execute(&mut conn)?;
        } else {
            diesel::insert_into(dsl::room_mappings)
                .values(NewRoomMapping {
                    app_channel_id: app_channel,
                    cokret_realm_id: realm_id,
                    portal_alias: alias,
                    portal_flow_id: None,
                    created_at: now_ts(),
                })
                .execute(&mut conn)?;
        }
        Ok(())
    }

    /// The full portal mapping row for an app channel (realm + cached portal
    /// flow, applet-integration §10.1).
    pub fn portal_for_channel(&self, app_channel: &str) -> Result<Option<RoomMapping>> {
        use schema::room_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::room_mappings
            .filter(dsl::app_channel_id.eq(app_channel))
            .first::<RoomMapping>(&mut conn)
            .optional()?)
    }

    /// Persist the resolved portal flow for an app channel (§10.1 step 1 cache).
    pub fn set_channel_portal_flow(&self, app_channel: &str, flow_id: &str) -> Result<()> {
        use schema::room_mappings::dsl;

        let mut conn = self.db.conn()?;
        diesel::update(dsl::room_mappings.filter(dsl::app_channel_id.eq(app_channel)))
            .set(dsl::portal_flow_id.eq(Some(flow_id)))
            .execute(&mut conn)?;
        Ok(())
    }

    /// The portal mapping row for a realm (cokret → app direction).
    pub fn room_for_realm(&self, realm_id: &str) -> Result<Option<RoomMapping>> {
        use schema::room_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::room_mappings
            .filter(dsl::cokret_realm_id.eq(realm_id))
            .first::<RoomMapping>(&mut conn)
            .optional()?)
    }

    pub fn record_message(
        &self,
        app_channel: &str,
        app_message_id: &str,
        normalized_sender: &str,
        cokret_event_id: &str,
        realm_id: &str,
    ) -> Result<()> {
        use schema::message_mappings::dsl;

        if app_channel.trim().is_empty() {
            return Err(BridgeError::App("app_channel must not be empty".into()));
        }
        if app_message_id.trim().is_empty() {
            return Err(BridgeError::App("app_message_id must not be empty".into()));
        }
        if normalized_sender.trim().is_empty() {
            return Err(BridgeError::App(
                "normalized_sender must not be empty".into(),
            ));
        }

        let mut conn = self.db.conn()?;
        let exists = dsl::message_mappings
            .filter(dsl::app_channel_id.eq(app_channel))
            .filter(dsl::app_message_id.eq(app_message_id))
            .filter(dsl::normalized_sender.eq(normalized_sender))
            .first::<MessageMapping>(&mut conn)
            .optional()?;
        if let Some(existing) = exists {
            diesel::update(dsl::message_mappings.filter(dsl::id.eq(existing.id)))
                .set((
                    dsl::cokret_event_id.eq(cokret_event_id),
                    dsl::cokret_realm_id.eq(realm_id),
                ))
                .execute(&mut conn)?;
        } else {
            diesel::insert_into(dsl::message_mappings)
                .values(NewMessageMapping {
                    app_channel_id: app_channel,
                    app_message_id,
                    normalized_sender,
                    cokret_event_id,
                    cokret_realm_id: realm_id,
                    created_at: now_ts(),
                })
                .execute(&mut conn)?;
        }
        Ok(())
    }

    /// Dedup lookup keyed by the §16 minimum key set: protocol/tenant/channel
    /// (folded into `app_channel`), external event id, and normalized sender.
    pub fn event_for_channel_message(
        &self,
        app_channel: &str,
        app_message_id: &str,
        normalized_sender: &str,
    ) -> Result<Option<String>> {
        use schema::message_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::message_mappings
            .filter(dsl::app_channel_id.eq(app_channel))
            .filter(dsl::app_message_id.eq(app_message_id))
            .filter(dsl::normalized_sender.eq(normalized_sender))
            .select(dsl::cokret_event_id)
            .first::<String>(&mut conn)
            .optional()?)
    }

    pub fn app_message_for_event(&self, cokret_event_id: &str) -> Result<Option<String>> {
        use schema::message_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::message_mappings
            .filter(dsl::cokret_event_id.eq(cokret_event_id))
            .select(dsl::app_message_id)
            .first::<String>(&mut conn)
            .optional()?)
    }

    // The argument list mirrors the user_mappings row shape one-to-one; a
    // params struct would only restate the same fields.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_user(
        &self,
        protocol: &str,
        tenant: &str,
        external_user_id: &str,
        actor_id: &str,
        profile_event_ref: &str,
        accountability_grant_ref: &str,
        authorization_ref: &str,
        display: Option<&str>,
    ) -> Result<()> {
        use schema::user_mappings::dsl;

        let mut conn = self.db.conn()?;
        // Ghost provisioning races: the same external user can first appear on two
        // channels concurrently (BRG-02-004). The serial domain key is the channel,
        // but the user mapping's unique key is (protocol, tenant, external_user_id),
        // so both racers can reach `insert` and one would hit a UNIQUE violation.
        // Try insert first; on a conflict, fall back to update by the conflict key
        // (an atomic upsert in effect, portable across sqlite/postgres/mysql and
        // matching the existing dedup-store pattern). The losing racer then re-reads
        // the winner's mapping (via `ghost_actor_for_app_user`) and continues
        // submitting rather than failing the message.
        let inserted = diesel::insert_into(dsl::user_mappings)
            .values(NewUserMapping {
                protocol,
                tenant,
                external_user_id,
                cokret_actor_id: actor_id,
                profile_event_ref,
                accountability_grant_ref,
                authorization_ref,
                display_name: display,
                created_at: now_ts(),
            })
            .execute(&mut conn);
        match inserted {
            Ok(_) => Ok(()),
            Err(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => {
                diesel::update(
                    dsl::user_mappings
                        .filter(dsl::protocol.eq(protocol))
                        .filter(dsl::tenant.eq(tenant))
                        .filter(dsl::external_user_id.eq(external_user_id)),
                )
                .set((
                    dsl::cokret_actor_id.eq(actor_id),
                    dsl::profile_event_ref.eq(profile_event_ref),
                    dsl::accountability_grant_ref.eq(accountability_grant_ref),
                    dsl::authorization_ref.eq(authorization_ref),
                    dsl::display_name.eq(display),
                ))
                .execute(&mut conn)?;
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }

    pub fn ghost_actor_for_app_user(
        &self,
        protocol: &str,
        tenant: &str,
        external_user_id: &str,
    ) -> Result<Option<UserMapping>> {
        use schema::user_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::user_mappings
            .filter(dsl::protocol.eq(protocol))
            .filter(dsl::tenant.eq(tenant))
            .filter(dsl::external_user_id.eq(external_user_id))
            .first::<UserMapping>(&mut conn)
            .optional()?)
    }

    /// Reverse lookup for ghost resolution: find the user row by cokret actor DID.
    pub fn user_by_actor(&self, actor_id: &str) -> Result<Option<UserMapping>> {
        use schema::user_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::user_mappings
            .filter(dsl::cokret_actor_id.eq(actor_id))
            .first::<UserMapping>(&mut conn)
            .optional()?)
    }

    /// Reverse lookup for portal resolution: find the room row by cokret realm
    /// id or by portal alias.
    pub fn room_by_realm_or_alias(&self, key: &str) -> Result<Option<RoomMapping>> {
        use schema::room_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::room_mappings
            .filter(dsl::cokret_realm_id.eq(key).or(dsl::portal_alias.eq(key)))
            .first::<RoomMapping>(&mut conn)
            .optional()?)
    }
}

/// DB-backed [`AppletResolver`] answering the cokret server's actor/realm probes
/// from the messaging mapping tables.
struct MessageResolver {
    store: Arc<MessageStore>,
}

impl AppletResolver for MessageResolver {
    fn resolve_actor(&self, actor_id: &str) -> Option<ResolvedActor> {
        let row = self.store.user_by_actor(actor_id).ok().flatten()?;
        Some(ResolvedActor {
            actor_id: row.cokret_actor_id,
            display_name: row.display_name,
            external_ref: json!({
                "protocol": row.protocol,
                "tenant": row.tenant,
                "external_user_id": row.external_user_id,
            }),
        })
    }

    fn resolve_realm(&self, realm_id_or_alias: &str) -> Option<ResolvedRealm> {
        let row = self
            .store
            .room_by_realm_or_alias(realm_id_or_alias)
            .ok()
            .flatten()?;
        Some(ResolvedRealm {
            realm_id: row.cokret_realm_id,
            title: row.portal_alias,
            external_ref: json!({ "app_channel": row.app_channel_id }),
        })
    }
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

fn normalized_external_id(value: &str) -> String {
    value.trim().to_owned()
}

fn bridge_protocol(config: &runtime::Config) -> String {
    normalized_external_id(&config.bridge.bridge_id)
}

fn bridge_tenant(config: &runtime::Config) -> String {
    config
        .bridge
        .tenant_id
        .as_deref()
        .map(normalized_external_id)
        .filter(|tenant| !tenant.is_empty())
        .unwrap_or_else(|| normalized_external_id(&config.cokret.service_did))
}

fn requested_ghost_actor_id_for_user(
    config: &runtime::Config,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
) -> Result<String> {
    if protocol.trim().is_empty() {
        return Err(BridgeError::App("bridge protocol must not be empty".into()));
    }
    if tenant.trim().is_empty() {
        return Err(BridgeError::App("bridge tenant must not be empty".into()));
    }
    if external_user_id.trim().is_empty() {
        return Err(BridgeError::App(
            "inbound app_user is required for ghost actor mapping".into(),
        ));
    }
    let material =
        [protocol, tenant, external_user_id].join(&MESSAGE_MAPPING_KEY_SEPARATOR.to_string());
    let encoded = cokret::base64url_encode(material.as_bytes());
    let did = format!(
        "{}:ghost:u{encoded}",
        config.cokret.service_did.trim_end_matches(':')
    );
    Did::new(did.clone())?;
    Ok(did)
}

/// The spec-registered ghost provision binding: `ck.self.applet.ghost.command.provision`
/// = `POST /_cokret/self/applets/{applet_id}/ghosts/provision`
/// (applet-integration §9.1, `operation-registry.json`, openapi).
fn ghost_actor_provision_path(applet_id: &str) -> Result<String> {
    if applet_id.trim().is_empty() || applet_id.contains('/') {
        return Err(BridgeError::Config(
            "cokret.applet_id must be a non-empty path-safe ck:applet id".into(),
        ));
    }
    Ok(format!(
        "/_cokret/self/applets/{applet_id}/ghosts/provision"
    ))
}

/// Deterministic `Idempotency-Key` for ghost provisioning (required header per
/// the openapi binding; §9.1 keys server-side idempotency on
/// `(applet_id, protocol, tenant, external_user_id)`, so retries of the same
/// external user reuse the same key). Hashed to satisfy the 128-char bound.
fn ghost_provision_idempotency_key(
    applet_id: &str,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let material = [applet_id, protocol, tenant, external_user_id]
        .join(&MESSAGE_MAPPING_KEY_SEPARATOR.to_string());
    format!(
        "ghost-provision-{}",
        hex::encode(Sha256::digest(material.as_bytes()))
    )
}

fn external_ref_for_user(
    config: &runtime::Config,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
) -> Value {
    json!({
        "protocol": protocol,
        "tenant": tenant,
        "external_user_id": external_user_id,
        "source": config.bridge.bridge_id.clone(),
    })
}

async fn provision_ghost_actor(
    edge: &runtime::CokretEdge,
    config: &runtime::Config,
    protocol: &str,
    tenant: &str,
    external_user_id: &str,
    display_name: Option<&str>,
    realm_id: &str,
) -> Result<GhostActorProvisionOutcome> {
    let ghost_actor_id = Did::new(requested_ghost_actor_id_for_user(
        config,
        protocol,
        tenant,
        external_user_id,
    )?)?;
    let mut request = GhostActorProvisionRequestBody::new(
        AppletId::new(config.cokret.applet_id.clone())?,
        edge.service_did().clone(),
        ghost_actor_id.clone(),
        protocol,
        tenant,
        external_user_id,
        RealmId::new(realm_id.to_owned())?,
        external_ref_for_user(config, protocol, tenant, external_user_id),
    );
    if let Some(display_name) = display_name {
        request = request.with_display_name(display_name);
    }
    let path = ghost_actor_provision_path(&config.cokret.applet_id)?;
    let options = ClientRequestOptions::new().idempotency_key(ghost_provision_idempotency_key(
        &config.cokret.applet_id,
        protocol,
        tenant,
        external_user_id,
    ));
    let response: GhostActorProvisionOutcome = edge
        .client()
        .post_with_options(&path, &request, &options)
        .await?;
    validate_ghost_provision_response(&ghost_actor_id, response)
}

fn validate_ghost_provision_response(
    requested_actor: &Did,
    response: GhostActorProvisionOutcome,
) -> Result<GhostActorProvisionOutcome> {
    if &response.ghost_actor_id != requested_actor {
        return Err(BridgeError::Cokret(format!(
            "ghost provisioning returned actor {} but requested {}",
            response.ghost_actor_id, requested_actor
        )));
    }
    require_nonempty_ref("profile_event_ref", &response.profile_event_ref)?;
    require_nonempty_ref(
        "accountability_grant_ref",
        &response.accountability_grant_ref,
    )?;
    require_nonempty_ref("authorization_ref", &response.authorization_ref)?;
    Ok(response)
}

fn require_nonempty_ref(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(BridgeError::Cokret(format!(
            "ghost provisioning response requires {label}"
        )));
    }
    Ok(())
}

/// Map a `BridgeError` variant to a stable, plaintext-free `error_code` for the
/// `ck.applet.bridge_error` payload (§16: the code is a coarse class, not the
/// underlying message text, so it never leaks external content).
fn bridge_error_code(error: &BridgeError) -> &'static str {
    match error {
        BridgeError::Cokret(_) => "cokret_unavailable",
        BridgeError::Database(_) => "bridge_storage_error",
        BridgeError::Runtime(_) => "bridge_runtime_error",
        BridgeError::App(_) => "app_adapter_error",
        BridgeError::Config(_) => "bridge_misconfigured",
        BridgeError::Other(_) => "bridge_internal_error",
    }
}

fn message_mapping_channel_key(config: &runtime::Config, app_channel: &str) -> String {
    [
        bridge_protocol(config),
        bridge_tenant(config),
        normalized_external_id(app_channel),
    ]
    .join(&MESSAGE_MAPPING_KEY_SEPARATOR.to_string())
}

fn external_ref_for_message(config: &runtime::Config, msg: &InboundAppMessage) -> Value {
    let protocol = bridge_protocol(config);
    let tenant = bridge_tenant(config);
    let external_channel = normalized_external_id(&msg.app_channel);
    let external_event_id = normalized_external_id(&msg.app_message_id);
    let normalized_sender = normalized_external_id(&msg.app_user);

    json!({
        "schema": EXTERNAL_REF_SCHEMA,
        "protocol": protocol,
        "tenant": tenant,
        "external_channel": external_channel,
        "external_event_id": external_event_id,
        "normalized_sender": normalized_sender,
        "source": config.bridge.bridge_id.clone(),
        "app_channel": msg.app_channel.clone(),
        "app_user": msg.app_user.clone(),
        "app_message_id": msg.app_message_id.clone(),
    })
}

/// The external location reference identifying one app channel, in the §10.1
/// match vocabulary (`protocol` / `network_id` / `location_id`).
fn portal_location_ref(config: &runtime::Config, app_channel: &str) -> Value {
    json!({
        "schema": EXTERNAL_REF_SCHEMA,
        "protocol": bridge_protocol(config),
        "network_id": bridge_tenant(config),
        "location_id": normalized_external_id(app_channel),
    })
}

/// §10.1 location equivalence: protocol / network_id / location_id equality.
fn location_matches(candidate: Option<&Value>, location: &Value) -> bool {
    let Some(candidate) = candidate else {
        return false;
    };
    ["protocol", "network_id", "location_id"]
        .iter()
        .all(|key| candidate.get(*key) == location.get(*key))
}

/// §10.1 step 2: scan the portal realm's history (a projection over regular
/// event reads) for an existing portal flow whose recorded external location
/// matches. Concurrent/retried creates resolve to the earliest flow in
/// effective (HLC) order, per the §10.1 create-idempotency rule.
///
/// The location is matched against the flow object's signed
/// `metadata.fields.external_ref` (covered by the event digest). The spec's
/// envelope-top-level signed `external_ref` is not yet representable in the SDK
/// `Event` model, so flow creation mirrors the location into the signed flow
/// metadata (see [`create_portal_flow`]).
async fn find_existing_portal_flow(
    edge: &runtime::CokretEdge,
    realm_id: &str,
    location: &Value,
) -> Result<Option<String>> {
    let mut cursor: Option<String> = None;
    // (hlc, event_id, flow_id) — keep the earliest in effective order.
    let mut earliest: Option<(String, String, String)> = None;
    for _ in 0..PORTAL_FLOW_SCAN_MAX_PAGES {
        let page = edge
            .client()
            .events_query(
                realm_id,
                cursor.as_deref(),
                None,
                None,
                Some(PORTAL_FLOW_SCAN_PAGE_LIMIT),
            )
            .await?;
        for event in &page.events {
            if event.kind.as_str() != "ck.flow.create" {
                continue;
            }
            let Some(object) = event.content.get("object") else {
                continue;
            };
            if !location_matches(object.pointer("/metadata/fields/external_ref"), location) {
                continue;
            }
            let Some(flow_id) = object.get("id").and_then(Value::as_str) else {
                continue;
            };
            let key = (event.hlc.to_string(), event.event_id.to_string());
            if earliest.as_ref().is_none_or(|(hlc, event_id, _)| {
                (key.0.as_str(), key.1.as_str()) < (hlc.as_str(), event_id.as_str())
            }) {
                earliest = Some((key.0, key.1, flow_id.to_owned()));
            }
        }
        if page.events.is_empty() {
            break;
        }
        match page.prev_cursor {
            Some(prev) => cursor = Some(prev),
            None => break,
        }
    }
    Ok(earliest.map(|(_, _, flow_id)| flow_id))
}

/// §10.1 step 3: create the portal flow by submitting `ck.flow.create` under
/// the bridge's own signable identity (the service actor), recording the
/// external location in the signed flow metadata, and return the new flow id.
async fn create_portal_flow(
    edge: &runtime::CokretEdge,
    app_channel: &str,
    alias: Option<&str>,
    realm_id: &str,
    location: &Value,
) -> Result<String> {
    let realm = RealmId::new(realm_id.to_owned())?;
    let flow_id = FlowId::new(cokret::new_prefixed_uuid7("ck:flow:"))?;
    let title = alias
        .filter(|alias| !alias.trim().is_empty())
        .unwrap_or(app_channel);
    let flow = FlowCreateObject::new(flow_id.clone(), realm.clone(), edge.service_did().clone())
        .with_metadata_title(title)
        .with_metadata_field("external_ref", location.clone())
        .with_track(PORTAL_FLOW_TRACK, FlowTrackConfig::discussion_primary());
    let flow_created_at = flow.created_at;
    let payload = ObjectCreatePayload::new(flow)
        .to_value()
        .map_err(|e| BridgeError::App(e.to_string()))?;
    let mut event = edge.mint_event("ck.flow.create", &realm, payload)?;
    // flow_create_payload semantic validation requires object.created_by ==
    // actor_id (both are the service DID here) and object.created_at == the
    // envelope created_at.
    event.created_at = flow_created_at;
    // §10.1 asks for a signed envelope top-level external_ref recording the
    // location; the SDK Event model cannot carry that field yet, so the signed
    // copy lives in the flow metadata above and unsigned only carries a hint.
    event
        .unsigned
        .insert("external_ref".to_owned(), location.clone());
    edge.resign_event(&mut event)?;
    edge.submit_event(&event).await?;
    Ok(flow_id.to_string())
}

fn host_allowed(host: &str, allowed_hosts: &[&str]) -> bool {
    allowed_hosts.iter().any(|allowed| {
        host.eq_ignore_ascii_case(allowed)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", allowed.to_ascii_lowercase()))
    })
}

/// Runtime context handed to a [`MessageBridge`].
pub struct MessageContext {
    inner: Arc<BridgeContext>,
    store: Arc<MessageStore>,
    pub http: reqwest::Client,
}

impl MessageContext {
    fn new(inner: Arc<BridgeContext>, store: Arc<MessageStore>) -> Self {
        let http = inner.http.clone();
        Self { inner, store, http }
    }

    pub fn store(&self) -> &MessageStore {
        &self.store
    }

    pub fn core(&self) -> &Arc<BridgeContext> {
        &self.inner
    }

    /// Emit a `ck.applet.bridge_error` Event for a failed inbound (app → cokret)
    /// submission so the failure is durable and visible to realm admins, rather
    /// than only logged (applet-integration §14 SHOULD, §16 bindings;
    /// `ck.profile.applet_bridge.v1` "bridge error event visibility" test item).
    ///
    /// Per §16 the bridge MUST NOT inline unauthorized external plaintext: the
    /// payload binds only the external `protocol`/`network_id`/`location_id` and
    /// the external event id (used as `failed_transaction_ref`) — never the
    /// message body. When the app channel has no realm mapping yet (provisioning
    /// or mapping gap) there is no realm to bind the error to, so emission is
    /// skipped (the failure is still logged by the caller). This is best-effort:
    /// a failure to emit the bridge error must not mask the original failure.
    pub async fn report_inbound_bridge_error(
        &self,
        msg: &InboundAppMessage,
        error: &BridgeError,
        retriable: bool,
    ) {
        // §16: no realm to bind to ⇒ nothing durable to emit. (Provisioning /
        // mapping-gap failures fall here; the caller already logged them.)
        let realm_id = match self.store.portal_for_channel(&msg.app_channel) {
            Ok(Some(row)) => row.cokret_realm_id,
            Ok(None) => return,
            Err(lookup_err) => {
                tracing::warn!(error = %lookup_err, "bridge_error realm lookup failed; skipping emit");
                return;
            }
        };
        if let Err(emit_err) = self
            .emit_bridge_error(&realm_id, msg, error, retriable)
            .await
        {
            tracing::warn!(error = %emit_err, "failed to emit ck.applet.bridge_error event");
        }
    }

    async fn emit_bridge_error(
        &self,
        realm_id: &str,
        msg: &InboundAppMessage,
        error: &BridgeError,
        retriable: bool,
    ) -> Result<()> {
        let edge = &self.inner.edge;
        let realm = RealmId::new(realm_id.to_owned())?;
        // `failed_transaction_ref` points at the source external event, never the
        // body. external_ref carries only network coordinates (no plaintext).
        let failed_ref = normalized_external_id(&msg.app_message_id);
        let external_ref = portal_location_ref(&self.inner.config, &msg.app_channel);
        let builder = AppletBridgeErrorBuilder::new(
            realm,
            edge.applet_id().to_owned(),
            edge.service_did().clone(),
            failed_ref,
            "inbound_submit_failed",
            bridge_error_code(error),
            retriable,
            AppletBridgeErrorVisibility::RealmAdmins,
        )
        .with_external_ref(external_ref);
        edge.submit_bridge_error(builder).await?;
        Ok(())
    }

    /// Upload bytes to cokret blob storage, returning the blob_ref string.
    pub async fn upload_blob(&self, bytes: &[u8], mime: &str) -> Result<String> {
        self.inner.edge.upload_blob(bytes, mime).await
    }

    /// Download a cokret blob by its blob_ref string.
    pub async fn download_blob(&self, blob_ref: &str) -> Result<Vec<u8>> {
        self.inner.edge.download_blob(blob_ref).await
    }

    /// Download app-hosted media with HTTPS, host allow-list and a hard byte
    /// cap. Use this for all inbound media fetches before uploading to Cokret blob
    /// storage.
    pub async fn download_external_media(
        &self,
        url: &str,
        bearer_token: Option<&str>,
        allowed_hosts: &[&str],
    ) -> Result<DownloadedMedia> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|err| BridgeError::App(format!("media URL parse failed: {err}")))?;
        if parsed.scheme() != "https" {
            return Err(BridgeError::App(
                "media download URL must use https".to_owned(),
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| BridgeError::App("media download URL has no host".to_owned()))?;
        if !host_allowed(host, allowed_hosts) {
            return Err(BridgeError::App(format!(
                "media download host {host} is not allow-listed"
            )));
        }

        let mut request = self.http.get(parsed);
        if let Some(token) = bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(|err| {
            BridgeError::App(format!(
                "media download failed: {}",
                redact_sensitive_url_values(err.to_string())
            ))
        })?;
        let response = response.error_for_status().map_err(|err| {
            BridgeError::App(format!(
                "media download status failed: {}",
                redact_sensitive_url_values(err.to_string())
            ))
        })?;
        if let Some(size) = response.content_length()
            && size > MAX_EXTERNAL_MEDIA_BYTES as u64
        {
            return Err(BridgeError::App(format!(
                "media download is {size} bytes; limit is {MAX_EXTERNAL_MEDIA_BYTES} bytes"
            )));
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        let mut bytes = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|err| {
                BridgeError::App(format!(
                    "media download read failed: {}",
                    redact_sensitive_url_values(err.to_string())
                ))
            })?;
            if bytes.len() + chunk.len() > MAX_EXTERNAL_MEDIA_BYTES {
                return Err(BridgeError::App(format!(
                    "media download exceeded {MAX_EXTERNAL_MEDIA_BYTES} bytes"
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(DownloadedMedia {
            bytes,
            content_type,
        })
    }

    /// Resolve the portal flow for an app channel following the §10.1
    /// acquisition order: persisted mapping → projection scan over the portal
    /// realm (match by external location) → `ck.flow.create`. The result is
    /// cached in the room mapping. Serialized per channel so concurrent first
    /// messages cannot double-create.
    pub async fn ensure_portal_flow(&self, app_channel: &str, realm_id: &str) -> Result<String> {
        let channel_key = message_mapping_channel_key(&self.inner.config, app_channel);
        let queue_key = format!("portal_flow{MESSAGE_MAPPING_KEY_SEPARATOR}{channel_key}");
        self.inner
            .queue
            .run(&queue_key, || {
                let edge = self.inner.edge.clone();
                let store = self.store.clone();
                let config = self.inner.config.clone();
                let app_channel = app_channel.to_owned();
                let realm_id = realm_id.to_owned();
                async move {
                    // §10.1 step 1: the persisted location ↔ (realm_id, flow_id)
                    // mapping.
                    let row = store.portal_for_channel(&app_channel)?;
                    let alias = row.as_ref().and_then(|row| row.portal_alias.clone());
                    if let Some(row) = row
                        && row.cokret_realm_id == realm_id
                        && let Some(flow_id) = row
                            .portal_flow_id
                            .filter(|flow_id| !flow_id.trim().is_empty())
                    {
                        return Ok::<String, BridgeError>(flow_id);
                    }
                    let location = portal_location_ref(&config, &app_channel);
                    // §10.1 step 2: look for an existing portal flow.
                    let flow_id =
                        match find_existing_portal_flow(&edge, &realm_id, &location).await? {
                            Some(flow_id) => flow_id,
                            // §10.1 step 3: create it.
                            None => {
                                create_portal_flow(
                                    &edge,
                                    &app_channel,
                                    alias.as_deref(),
                                    &realm_id,
                                    &location,
                                )
                                .await?
                            }
                        };
                    store.set_channel_portal_flow(&app_channel, &flow_id)?;
                    Ok(flow_id)
                }
            })
            .await
    }

    /// Submit an inbound text message as a `ck.message.create` event.
    pub async fn submit_app_message(&self, msg: InboundAppMessage) -> Result<String> {
        let content = text_content_block(&msg.body)?;
        self.submit_content(&msg, content, Vec::new()).await
    }

    /// Submit an inbound media message. The `attachment` must already reference a
    /// blob uploaded via [`MessageContext::upload_blob`]; `msg.body` becomes the
    /// caption when non-empty.
    pub async fn submit_media_message(
        &self,
        msg: InboundAppMessage,
        mut attachment: Attachment,
    ) -> Result<String> {
        if attachment.caption.is_empty() {
            attachment.caption = msg.body.clone();
        }
        let content = media_content_block(&attachment)?;
        self.submit_content(&msg, content, vec![attachment.blob_ref.clone()])
            .await
    }

    /// Shared submit path: resolve the portal `(realm_id, flow_id)`, assemble
    /// the spec `message_create_payload`, attach provenance, submit on the
    /// per-channel serial queue, and record the message mapping.
    async fn submit_content(
        &self,
        msg: &InboundAppMessage,
        content: Value,
        blob_refs: Vec<String>,
    ) -> Result<String> {
        let external_event_id = normalized_external_id(&msg.app_message_id);
        if external_event_id.is_empty() {
            return Err(BridgeError::App(
                "inbound app_message_id is required for external event deduplication".into(),
            ));
        }

        let realm = self
            .store
            .portal_for_channel(&msg.app_channel)?
            .map(|row| row.cokret_realm_id)
            .ok_or_else(|| {
                BridgeError::App(format!(
                    "channel {} has no realm mapping; create an explicit room mapping",
                    msg.app_channel
                ))
            })?;
        // §10.1: the mapping unit for an external location is (realm_id,
        // flow_id) — resolve the portal flow before submitting.
        let flow_id = self.ensure_portal_flow(&msg.app_channel, &realm).await?;
        let payload = build_message_create_payload(&flow_id, content, blob_refs)?;

        let protocol = bridge_protocol(&self.inner.config);
        let tenant = bridge_tenant(&self.inner.config);
        let external_user_id = normalized_external_id(&msg.app_user);
        if external_user_id.is_empty() {
            return Err(BridgeError::App(
                "inbound app_user is required for ghost actor mapping".into(),
            ));
        }

        let mapping_channel_key = message_mapping_channel_key(&self.inner.config, &msg.app_channel);
        let event_id = self
            .inner
            .queue
            .run(&mapping_channel_key, || {
                let edge = self.inner.edge.clone();
                let store = self.store.clone();
                let config = self.inner.config.clone();
                let external_ref = external_ref_for_message(&config, msg);
                let mapping_channel_key = mapping_channel_key.clone();
                let external_event_id = external_event_id.clone();
                let protocol = protocol.clone();
                let tenant = tenant.clone();
                let external_user_id = external_user_id.clone();
                let realm_for_submit = realm.clone();
                let realm_for_record = realm.clone();
                async move {
                    if let Some(existing_event_id) = store.event_for_channel_message(
                        &mapping_channel_key,
                        &external_event_id,
                        &external_user_id,
                    )? {
                        return Ok::<String, BridgeError>(existing_event_id);
                    }
                    let mapping = match store.ghost_actor_for_app_user(
                        &protocol,
                        &tenant,
                        &external_user_id,
                    )? {
                        Some(mapping) => mapping,
                        None => {
                            let provisioned = provision_ghost_actor(
                                &edge,
                                &config,
                                &protocol,
                                &tenant,
                                &external_user_id,
                                Some(&external_user_id),
                                &realm_for_submit,
                            )
                            .await?;
                            let actor_id = provisioned.ghost_actor_id.to_string();
                            let display_name = provisioned
                                .display_name
                                .as_deref()
                                .or(Some(external_user_id.as_str()));
                            store.upsert_user(
                                &protocol,
                                &tenant,
                                &external_user_id,
                                &actor_id,
                                &provisioned.profile_event_ref,
                                &provisioned.accountability_grant_ref,
                                &provisioned.authorization_ref,
                                display_name,
                            )?;
                            store
                                .ghost_actor_for_app_user(&protocol, &tenant, &external_user_id)?
                                .ok_or_else(|| {
                                    BridgeError::Database(
                                        "ghost actor provisioning row was not persisted".into(),
                                    )
                                })?
                        }
                    };
                    require_nonempty_ref("profile_event_ref", &mapping.profile_event_ref)?;
                    require_nonempty_ref(
                        "accountability_grant_ref",
                        &mapping.accountability_grant_ref,
                    )?;
                    require_nonempty_ref("authorization_ref", &mapping.authorization_ref)?;
                    let actor = Did::new(mapping.cokret_actor_id)?;
                    let event_id = edge
                        .submit_with_external_ref_as(
                            &actor,
                            &realm_for_submit,
                            "ck.message.create",
                            payload,
                            external_ref,
                            &mapping.authorization_ref,
                        )
                        .await?;
                    store.record_message(
                        &mapping_channel_key,
                        &external_event_id,
                        &external_user_id,
                        &event_id,
                        &realm_for_record,
                    )?;
                    Ok::<String, BridgeError>(event_id)
                }
            })
            .await?;
        Ok(event_id)
    }
}

#[async_trait]
pub trait MessageBridge: Send + Sync + 'static {
    fn name(&self) -> &str;

    /// The app-side receive loop. Pure webhook bridges (whose inbound path is the
    /// salvo `webhook_router`) can rely on the default keep-alive loop and only
    /// need to override `webhook_router`. Gateway / long-poll bridges (Discord,
    /// Telegram, Slack, Zulip) override this with their own connection loop.
    async fn run(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Result<()> {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef>;

    async fn redact_in_app(&self, _ctx: Arc<MessageContext>, _app_message_id: &str) -> Result<()> {
        Ok(())
    }

    /// Handle an ephemeral payload (typing/presence/receipts) pushed alongside
    /// events. Raw JSON until a typed schema is defined; defaults to a no-op.
    async fn on_ephemeral(&self, _ctx: Arc<MessageContext>, _ephemeral: Value) -> Result<()> {
        Ok(())
    }

    fn webhook_router(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        None
    }
}

struct MessageAdapter<M: MessageBridge> {
    user: Arc<M>,
    ctx: Arc<MessageContext>,
}

fn sender_display_for_event(store: &MessageStore, event: &Event) -> Result<String> {
    let actor_id = event.actor_id.to_string();
    let mut display = match store.user_by_actor(&actor_id)? {
        Some(row) => row
            .display_name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(row.external_user_id),
        None => actor_id,
    };
    if let Some(executed_by) = event.executed_by.as_ref()
        && executed_by != &event.actor_id
    {
        display = format!("{display} via {executed_by}");
    }
    Ok(display)
}

#[async_trait]
impl<M: MessageBridge> BridgeApp for MessageAdapter<M> {
    fn name(&self) -> &str {
        self.user.name()
    }

    async fn run(self: Arc<Self>, _ctx: Arc<BridgeContext>) -> Result<()> {
        self.user.clone().run(self.ctx.clone()).await
    }

    async fn on_cokret_event(&self, _ctx: Arc<BridgeContext>, event: Event) -> Result<()> {
        // Deletion forwarding (cokret -> app): a `ck.message.redact` that targets
        // an event we previously bridged is mapped to an app-side deletion via the
        // adapter's `redact_in_app`. Honors the `disable_deletion_forwarding`
        // switch.
        if event.kind == "ck.message.redact" {
            if self.ctx.core().config.bridge.disable_deletion_forwarding {
                return Ok(());
            }
            let Some(target) = event.redacts.as_ref() else {
                return Ok(());
            };
            let Some(app_message_id) = self.ctx.store.app_message_for_event(target.as_ref())?
            else {
                return Ok(());
            };
            self.user
                .redact_in_app(self.ctx.clone(), &app_message_id)
                .await?;
            return Ok(());
        }
        if event.kind != "ck.message.create" {
            return Ok(());
        }
        // Loop prevention: skip events this bridge itself submitted (app ->
        // cokret), which the server echoes back. Only signature-covered fields
        // are consulted (applet-integration §8: `unsigned.external_ref` is a
        // discardable hint and MUST NOT be a security-decision input): every
        // event this bridge submits either carries `executed_by = service_did`
        // (delegated ghost events) or is authored by the service actor itself.
        // Both checks are independent of local DB state, so a server push
        // racing ahead of our own mapping write cannot bypass them.
        if event.executed_by.as_ref() == Some(self.ctx.core().edge.service_did()) {
            return Ok(());
        }
        if &event.actor_id == self.ctx.core().edge.service_did() {
            return Ok(());
        }
        let event_id = event.event_id.to_string();
        if self.ctx.store.app_message_for_event(&event_id)?.is_some() {
            return Ok(());
        }
        let realm_id = event.realm_id.to_string();
        let Some(room) = self.ctx.store.room_for_realm(&realm_id)? else {
            tracing::debug!(realm = %realm_id, "realm has no channel mapping, dropping");
            return Ok(());
        };
        let channel = room.app_channel_id.clone();
        // §10.1: the external location maps to (realm_id, flow_id), not the
        // bare realm — only messages on the portal flow cross the bridge.
        let portal_flow = match room.portal_flow_id.filter(|f| !f.trim().is_empty()) {
            Some(flow_id) => flow_id,
            None => self.ctx.ensure_portal_flow(&channel, &realm_id).await?,
        };
        if extract_flow_id(&event.content) != Some(portal_flow.as_str()) {
            tracing::debug!(
                realm = %realm_id,
                portal_flow = %portal_flow,
                "message is not on the portal flow, dropping"
            );
            return Ok(());
        }
        let body = extract_plain_body(&event.content);
        let attachment = extract_attachment(&event.content);
        let sender_display = sender_display_for_event(&self.ctx.store, &event)?;
        let out = OutboundAppMessage {
            app_channel: channel.clone(),
            sender_display,
            body,
            reply_to: None,
            attachment,
        };
        let app_ref = self.user.send_to_app(self.ctx.clone(), out).await?;
        let mapping_channel_key = message_mapping_channel_key(&self.ctx.core().config, &channel);
        let app_message_id = normalized_external_id(&app_ref.app_message_id);
        if app_message_id.is_empty() {
            tracing::debug!(
                realm = %realm_id,
                app_channel = %channel,
                "adapter returned no app message id; outbound mapping not recorded"
            );
        } else {
            self.ctx.store.record_message(
                &mapping_channel_key,
                &app_message_id,
                event.actor_id.as_ref(),
                event.event_id.as_ref(),
                &realm_id,
            )?;
        }
        Ok(())
    }

    async fn on_ephemeral(&self, _ctx: Arc<BridgeContext>, ephemeral: Value) -> Result<()> {
        self.user.on_ephemeral(self.ctx.clone(), ephemeral).await
    }

    fn webhook_router(self: Arc<Self>, _ctx: Arc<BridgeContext>) -> Option<salvo::Router> {
        self.user.clone().webhook_router(self.ctx.clone())
    }
}

pub async fn run_message_bridge<M, F>(config: runtime::Config, factory: F) -> Result<()>
where
    M: MessageBridge,
    F: FnOnce(Arc<MessageContext>) -> Result<M>,
{
    runtime::run_bridge(config, move |core_ctx: Arc<BridgeContext>| {
        let store = Arc::new(MessageStore::new(core_ctx.db.clone())?);
        // Apply any static channel↔realm mappings from configuration so a bridge
        // is operable out of the box without hand-written SQL (see `upsert_room`).
        for mapping in &core_ctx.config.mappings {
            store.upsert_room(
                &mapping.app_channel,
                &mapping.realm_id,
                mapping.alias.as_deref(),
            )?;
        }
        // Install DB-backed actor/realm resolution before the web service starts.
        core_ctx.set_resolver(Arc::new(MessageResolver {
            store: store.clone(),
        }));
        // Declare the inbound event kinds this messaging bridge consumes so the
        // applet handler rejects anything else as `capability_unsupported`
        // (BRG-01-009). `MessageAdapter::on_cokret_event` handles exactly these.
        core_ctx.set_handled_event_kinds(BRIDGE_HANDLED_EVENT_KINDS);
        let ctx = Arc::new(MessageContext::new(core_ctx, store));
        let user = Arc::new(factory(ctx.clone())?);
        Ok(MessageAdapter { user, ctx })
    })
    .await
}

/// Unified executable entry point for message-bridge binaries.
///
/// Factors out the per-bridge `main.rs` boilerplate: CLI parsing (a single
/// `--config` flag), [`runtime::Config::load`], logging init, strongly typed
/// `config.app` deserialization into `C`, and [`run_message_bridge`]. A bridge
/// binary reduces to its `AppConfig` definition plus a factory closure:
///
/// ```ignore
/// #[derive(serde::Deserialize)]
/// struct AppConfig { bot_token: String }
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     cokret_bridge_messaging::bridge_main("cokret <-> Example bridge", |app: AppConfig, _ctx| {
///         Ok(ExampleApp::new(app.bot_token))
///     })
///     .await
/// }
/// ```
pub async fn bridge_main<C, M, F>(about: &str, factory: F) -> anyhow::Result<()>
where
    C: serde::de::DeserializeOwned,
    M: MessageBridge,
    F: FnOnce(C, Arc<MessageContext>) -> Result<M>,
{
    // Use the invoked binary name (e.g. `cokret-bridge-slack`) for help/version
    // output instead of hardcoding one shared name here.
    let bin_name = std::env::args()
        .next()
        .as_deref()
        .map(std::path::Path::new)
        .and_then(|p| p.file_stem())
        .and_then(|s| s.to_str())
        .unwrap_or("cokret-bridge")
        .to_owned();
    let matches = clap::Command::new(bin_name)
        .version(env!("CARGO_PKG_VERSION"))
        .about(about.to_owned())
        .arg(
            clap::Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path (.yaml)")
                .default_value("config.yaml"),
        )
        .get_matches();
    let config_path = matches
        .get_one::<String>("config")
        .expect("config has a default value");

    let config = runtime::Config::load(config_path)?;
    runtime::logging::init(&config.logging);

    // `config.app` defaults to JSON null when the section is omitted; map that
    // to an empty object so serde reports each missing field by name.
    let app = match config.app.clone() {
        Value::Null => json!({}),
        value => value,
    };
    let app_config: C =
        serde_json::from_value(app).map_err(|e| anyhow::anyhow!("config.app is invalid: {e}"))?;

    run_message_bridge(config, move |ctx| factory(app_config, ctx)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOW_ID: &str = "ck:flow:01904100-0000-7000-8000-000000000001";

    fn media_attachment() -> Attachment {
        Attachment {
            blob_ref: format!("ck:blob:sha256:{}", "a".repeat(64)),
            media_type: Some("image/png".to_owned()),
            filename: Some("shot.png".to_owned()),
            size: Some(2048),
            caption: "look at this".to_owned(),
        }
    }

    #[test]
    fn text_payload_matches_message_create_schema_shape() {
        let content = text_content_block("hello").unwrap();
        let payload = build_message_create_payload(FLOW_ID, content, Vec::new()).unwrap();
        assert_eq!(payload["flow_id"], FLOW_ID);
        assert_eq!(payload["track_name"], PORTAL_FLOW_TRACK);
        assert_eq!(payload["content"]["kind"], "ck.content.text");
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
        let payload =
            build_message_create_payload(FLOW_ID, content, vec![att.blob_ref.clone()]).unwrap();
        assert_eq!(payload["content"]["kind"], "ck.content.image");
        assert_eq!(payload["content"]["body"], "look at this");
        assert_eq!(payload["content"]["blob_ref"], att.blob_ref);
        assert_eq!(payload["content"]["mime_type"], "image/png");
        assert_eq!(payload["content"]["size_bytes"], 2048);
        // content_block schema forbids `size` (byte counts are `size_bytes`)
        // and the legacy flat fields must not leak into the payload.
        assert!(payload["content"].get("size").is_none());
        assert!(payload["content"].get("mimetype").is_none());
        assert_eq!(payload["blob_refs"][0], att.blob_ref);
        assert!(payload.get("blob").is_none());
    }

    #[test]
    fn media_kind_follows_mime_category_and_file_requires_filename() {
        assert_eq!(media_content_kind(Some("video/mp4")), "ck.content.video");
        assert_eq!(media_content_kind(Some("audio/ogg")), "ck.content.audio");
        assert_eq!(
            media_content_kind(Some("application/pdf")),
            "ck.content.file"
        );
        assert_eq!(media_content_kind(None), "ck.content.file");

        let mut att = media_attachment();
        att.media_type = Some("application/pdf".to_owned());
        att.filename = None;
        let block = media_content_block(&att).unwrap();
        // `filename` is MUST for ck.content.file even when upstream gave none.
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
            build_message_create_payload(FLOW_ID, content, vec![att.blob_ref.clone()]).unwrap();

        assert_eq!(extract_plain_body(&payload), "look at this");
        assert_eq!(extract_flow_id(&payload), Some(FLOW_ID));
        let extracted = extract_attachment(&payload).expect("attachment");
        assert_eq!(extracted.blob_ref, att.blob_ref);
        assert_eq!(extracted.media_type.as_deref(), Some("image/png"));
        assert_eq!(extracted.filename.as_deref(), Some("shot.png"));
        assert_eq!(extracted.size, Some(2048));
        assert_eq!(extracted.caption, "look at this");
    }

    #[test]
    fn extraction_handles_composite_and_legacy_shapes() {
        let composite = json!({
            "flow_id": FLOW_ID,
            "track_name": "discussion",
            "content": {
                "kind": "ck.content.composite",
                "body": "caption text",
                "parts": [
                    { "kind": "ck.content.text", "body": "caption text" },
                    {
                        "kind": "ck.content.file",
                        "body": "spec.pdf",
                        "blob_ref": format!("ck:blob:sha256:{}", "b".repeat(64)),
                        "mime_type": "application/pdf",
                        "filename": "spec.pdf",
                        "size_bytes": 7
                    }
                ]
            }
        });
        let extracted = extract_attachment(&composite).expect("attachment");
        assert_eq!(extracted.filename.as_deref(), Some("spec.pdf"));
        assert_eq!(extracted.size, Some(7));

        // The pre-spec flat shape (`{body}` as the whole payload) no longer
        // parses — the misaligned legacy read paths are gone.
        let legacy = json!({ "body": "hello" });
        assert_eq!(extract_plain_body(&legacy), "");
        assert!(extract_attachment(&legacy).is_none());
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
}
