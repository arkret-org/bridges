//! Messaging helper layer for chat/social Cokret Applet bridges.
//!
//! This crate sits on top of `cokret-bridge-runtime`. It owns the
//! message-shaped contract shared by the social bridge adapters:
//!
//! - app channel/message/user mapping tables,
//! - `ck.message.create` conversion,
//! - `MessageBridge` and `run_message_bridge`,
//! - signed `external_ref` provenance for upstream channel/user/message ids.

mod models;
mod schema;
pub mod webhook;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use cokret::events::{MediaContent, TextMessageContent};
use cokret::{BlobRef, Did, Event};
use cokret_bridge_runtime::app::{
    AppletResolver, BridgeApp, BridgeContext, ResolvedActor, ResolvedRealm,
};
use cokret_bridge_runtime::db::DatabaseManager;
use cokret_bridge_runtime::{BridgeError, Result};
use diesel::prelude::*;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub use cokret_bridge_runtime as runtime;
pub use models::{MessageMapping, RoomMapping, UserMapping};
pub use runtime::salvo;

use models::{NewMessageMapping, NewRoomMapping, NewUserMapping};

const EXTERNAL_REF_SCHEMA: &str = "ck.external_ref.messaging.v1";
const GHOST_ACTOR_PROVISION_REQUEST_SCHEMA: &str = "ck.applet.ghost_actor.provision_request.v1";
const MESSAGE_MAPPING_KEY_SEPARATOR: char = '\u{1f}';

/// An inbound message from an external app into Cokret.
#[derive(Clone, Debug)]
pub struct InboundAppMessage {
    pub app_channel: String,
    pub app_user: String,
    pub app_message_id: String,
    pub body: String,
}

#[derive(Clone, Debug, Serialize)]
struct GhostActorProvisionRequest {
    schema: &'static str,
    applet_id: String,
    service_did: Did,
    ghost_actor_did: Did,
    protocol: String,
    tenant: String,
    external_user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    realm_id: String,
    external_ref: Value,
}

#[derive(Clone, Debug, Deserialize)]
struct GhostActorProvisionResponse {
    ghost_actor_did: Did,
    profile_event_ref: String,
    accountability_grant_ref: String,
    authorization_ref: String,
    #[serde(default)]
    display_name: Option<String>,
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

/// Build a canonical `ck.message.create` text content (`{ "body": ... }`,
/// matching the SDK's [`TextMessageContent`]).
pub fn default_text_payload(body: &str) -> Value {
    serde_json::to_value(TextMessageContent::plain(body))
        .unwrap_or_else(|_| json!({ "body": body }))
}

/// Build a canonical media content (`{ "body", "blob", "mimetype", "filename",
/// "size" }`, matching the SDK's [`MediaContent`]).
pub fn media_message_payload(att: &Attachment) -> Result<Value> {
    let blob = BlobRef::new(att.blob_ref.clone())
        .map_err(|e| BridgeError::App(format!("invalid blob_ref: {e}")))?;
    let body = if att.caption.is_empty() {
        att.filename.clone().unwrap_or_default()
    } else {
        att.caption.clone()
    };
    let content = MediaContent {
        body,
        blob,
        mimetype: att.media_type.clone(),
        filename: att.filename.clone(),
        size: att.size,
        info: BTreeMap::new(),
        relates_to: None,
    };
    serde_json::to_value(content).map_err(|e| BridgeError::App(e.to_string()))
}

/// Extract displayable plain text from a Cokret message payload. Deserializes
/// the SDK's [`TextMessageContent`] (binding the canonical wire shape), falling
/// back to a raw `body` lookup for non-conforming payloads.
pub fn extract_plain_body(payload: &Value) -> String {
    if let Ok(content) = serde_json::from_value::<TextMessageContent>(payload.clone()) {
        return content.body;
    }
    payload
        .get("body")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Extract a media attachment from a Cokret message payload, if it carries a
/// `blob` reference. Deserializes the SDK's [`MediaContent`] so the inbound and
/// outbound directions stay bound to the same canonical wire type (symmetric
/// with [`media_message_payload`]); structural drift surfaces as a failed parse
/// rather than silently-missing fields.
pub fn extract_attachment(payload: &Value) -> Option<Attachment> {
    let content = serde_json::from_value::<MediaContent>(payload.clone()).ok()?;
    Some(Attachment {
        blob_ref: content.blob.as_str().to_owned(),
        media_type: content.mimetype,
        filename: content.filename,
        size: content.size,
        caption: content.body,
    })
}

/// Channel/message/user mapping store persisted through the runtime database.
pub struct MessageStore {
    db: Arc<DatabaseManager>,
}

impl MessageStore {
    pub fn new(db: Arc<DatabaseManager>) -> Result<Self> {
        db.run_migrations(schema_sql())?;
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
            diesel::update(dsl::room_mappings.filter(dsl::id.eq(existing.id)))
                .set((
                    dsl::cokret_realm_id.eq(realm_id),
                    dsl::portal_alias.eq(alias),
                ))
                .execute(&mut conn)?;
        } else {
            diesel::insert_into(dsl::room_mappings)
                .values(NewRoomMapping {
                    app_channel_id: app_channel,
                    cokret_realm_id: realm_id,
                    portal_alias: alias,
                    created_at: now_ts(),
                })
                .execute(&mut conn)?;
        }
        Ok(())
    }

    pub fn realm_for_channel(&self, app_channel: &str) -> Result<Option<String>> {
        use schema::room_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::room_mappings
            .filter(dsl::app_channel_id.eq(app_channel))
            .select(dsl::cokret_realm_id)
            .first::<String>(&mut conn)
            .optional()?)
    }

    pub fn channel_for_realm(&self, realm_id: &str) -> Result<Option<String>> {
        use schema::room_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::room_mappings
            .filter(dsl::cokret_realm_id.eq(realm_id))
            .select(dsl::app_channel_id)
            .first::<String>(&mut conn)
            .optional()?)
    }

    pub fn record_message(
        &self,
        app_channel: &str,
        app_message_id: &str,
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

        let mut conn = self.db.conn()?;
        let exists = dsl::message_mappings
            .filter(dsl::app_channel_id.eq(app_channel))
            .filter(dsl::app_message_id.eq(app_message_id))
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
                    cokret_event_id,
                    cokret_realm_id: realm_id,
                    created_at: now_ts(),
                })
                .execute(&mut conn)?;
        }
        Ok(())
    }

    pub fn event_for_app_message(&self, app_message_id: &str) -> Result<Option<String>> {
        use schema::message_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::message_mappings
            .filter(dsl::app_message_id.eq(app_message_id))
            .select(dsl::cokret_event_id)
            .first::<String>(&mut conn)
            .optional()?)
    }

    pub fn event_for_channel_message(
        &self,
        app_channel: &str,
        app_message_id: &str,
    ) -> Result<Option<String>> {
        use schema::message_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::message_mappings
            .filter(dsl::app_channel_id.eq(app_channel))
            .filter(dsl::app_message_id.eq(app_message_id))
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

    pub fn upsert_user(
        &self,
        protocol: &str,
        tenant: &str,
        external_user_id: &str,
        actor_did: &str,
        profile_event_ref: &str,
        accountability_grant_ref: &str,
        authorization_ref: &str,
        display: Option<&str>,
    ) -> Result<()> {
        use schema::user_mappings::dsl;

        let mut conn = self.db.conn()?;
        let exists = dsl::user_mappings
            .filter(dsl::protocol.eq(protocol))
            .filter(dsl::tenant.eq(tenant))
            .filter(dsl::external_user_id.eq(external_user_id))
            .first::<UserMapping>(&mut conn)
            .optional()?;
        if let Some(existing) = exists {
            diesel::update(dsl::user_mappings.filter(dsl::id.eq(existing.id)))
                .set((
                    dsl::cokret_actor_did.eq(actor_did),
                    dsl::profile_event_ref.eq(profile_event_ref),
                    dsl::accountability_grant_ref.eq(accountability_grant_ref),
                    dsl::authorization_ref.eq(authorization_ref),
                    dsl::display_name.eq(display),
                ))
                .execute(&mut conn)?;
        } else {
            diesel::insert_into(dsl::user_mappings)
                .values(NewUserMapping {
                    protocol,
                    tenant,
                    external_user_id,
                    cokret_actor_did: actor_did,
                    profile_event_ref,
                    accountability_grant_ref,
                    authorization_ref,
                    display_name: display,
                    created_at: now_ts(),
                })
                .execute(&mut conn)?;
        }
        Ok(())
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
    pub fn user_by_actor(&self, actor_did: &str) -> Result<Option<UserMapping>> {
        use schema::user_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::user_mappings
            .filter(dsl::cokret_actor_did.eq(actor_did))
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
            actor_id: row.cokret_actor_did,
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

fn requested_ghost_actor_did_for_user(
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
) -> Result<GhostActorProvisionResponse> {
    let ghost_actor_did = Did::new(requested_ghost_actor_did_for_user(
        config,
        protocol,
        tenant,
        external_user_id,
    )?)?;
    let request = GhostActorProvisionRequest {
        schema: GHOST_ACTOR_PROVISION_REQUEST_SCHEMA,
        applet_id: config.cokret.applet_id.clone(),
        service_did: edge.service_did().clone(),
        ghost_actor_did: ghost_actor_did.clone(),
        protocol: protocol.to_owned(),
        tenant: tenant.to_owned(),
        external_user_id: external_user_id.to_owned(),
        display_name: display_name.map(str::to_owned),
        realm_id: realm_id.to_owned(),
        external_ref: external_ref_for_user(config, protocol, tenant, external_user_id),
    };
    let path = ghost_actor_provision_path(&config.cokret.applet_id)?;
    let response: GhostActorProvisionResponse = edge.client().post(&path, &request).await?;
    validate_ghost_provision_response(&ghost_actor_did, response)
}

fn validate_ghost_provision_response(
    requested_actor: &Did,
    response: GhostActorProvisionResponse,
) -> Result<GhostActorProvisionResponse> {
    if &response.ghost_actor_did != requested_actor {
        return Err(BridgeError::Cokret(format!(
            "ghost provisioning returned actor {} but requested {}",
            response.ghost_actor_did, requested_actor
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

fn host_allowed(host: &str, allowed_hosts: &[&str]) -> bool {
    allowed_hosts.iter().any(|allowed| {
        host.eq_ignore_ascii_case(allowed)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", allowed.to_ascii_lowercase()))
    })
}

#[cfg(feature = "sqlite")]
fn schema_sql() -> &'static [&'static str] {
    &[
        "CREATE TABLE IF NOT EXISTS room_mappings (\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            app_channel_id TEXT NOT NULL UNIQUE,\
            cokret_realm_id TEXT NOT NULL UNIQUE,\
            portal_alias TEXT,\
            created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS message_mappings (\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            app_channel_id TEXT NOT NULL,\
            app_message_id TEXT NOT NULL,\
            cokret_event_id TEXT NOT NULL UNIQUE,\
            cokret_realm_id TEXT NOT NULL,\
            created_at BIGINT NOT NULL,\
            UNIQUE(app_channel_id, app_message_id))",
        "CREATE TABLE IF NOT EXISTS user_mappings (\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\
            protocol TEXT NOT NULL,\
            tenant TEXT NOT NULL,\
            external_user_id TEXT NOT NULL,\
            cokret_actor_did TEXT NOT NULL UNIQUE,\
            profile_event_ref TEXT NOT NULL,\
            accountability_grant_ref TEXT NOT NULL,\
            authorization_ref TEXT NOT NULL,\
            display_name TEXT,\
            created_at BIGINT NOT NULL,\
            UNIQUE(protocol, tenant, external_user_id))",
    ]
}

#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
fn schema_sql() -> &'static [&'static str] {
    &[
        "CREATE TABLE IF NOT EXISTS room_mappings (\
            id BIGSERIAL PRIMARY KEY,\
            app_channel_id TEXT NOT NULL UNIQUE,\
            cokret_realm_id TEXT NOT NULL UNIQUE,\
            portal_alias TEXT,\
            created_at BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS message_mappings (\
            id BIGSERIAL PRIMARY KEY,\
            app_channel_id TEXT NOT NULL,\
            app_message_id TEXT NOT NULL,\
            cokret_event_id TEXT NOT NULL UNIQUE,\
            cokret_realm_id TEXT NOT NULL,\
            created_at BIGINT NOT NULL,\
            UNIQUE(app_channel_id, app_message_id))",
        "CREATE TABLE IF NOT EXISTS user_mappings (\
            id BIGSERIAL PRIMARY KEY,\
            protocol TEXT NOT NULL,\
            tenant TEXT NOT NULL,\
            external_user_id TEXT NOT NULL,\
            cokret_actor_did TEXT NOT NULL UNIQUE,\
            profile_event_ref TEXT NOT NULL,\
            accountability_grant_ref TEXT NOT NULL,\
            authorization_ref TEXT NOT NULL,\
            display_name TEXT,\
            created_at BIGINT NOT NULL,\
            UNIQUE(protocol, tenant, external_user_id))",
    ]
}

#[cfg(all(feature = "mysql", not(feature = "sqlite"), not(feature = "postgres")))]
fn schema_sql() -> &'static [&'static str] {
    &[
        "CREATE TABLE IF NOT EXISTS room_mappings (\
            id BIGINT AUTO_INCREMENT PRIMARY KEY,\
            app_channel_id TEXT NOT NULL,\
            cokret_realm_id TEXT NOT NULL,\
            portal_alias TEXT,\
            created_at BIGINT NOT NULL,\
            UNIQUE KEY room_app_channel_id_unique (app_channel_id(191)),\
            UNIQUE KEY room_cokret_realm_id_unique (cokret_realm_id(191)))",
        "CREATE TABLE IF NOT EXISTS message_mappings (\
            id BIGINT AUTO_INCREMENT PRIMARY KEY,\
            app_channel_id TEXT NOT NULL,\
            app_message_id TEXT NOT NULL,\
            cokret_event_id TEXT NOT NULL,\
            cokret_realm_id TEXT NOT NULL,\
            created_at BIGINT NOT NULL,\
            UNIQUE KEY message_app_id_unique (app_channel_id(191), app_message_id(191)),\
            UNIQUE KEY message_cokret_event_id_unique (cokret_event_id(191)))",
        "CREATE TABLE IF NOT EXISTS user_mappings (\
            id BIGINT AUTO_INCREMENT PRIMARY KEY,\
            protocol TEXT NOT NULL,\
            tenant TEXT NOT NULL,\
            external_user_id TEXT NOT NULL,\
            cokret_actor_did TEXT NOT NULL,\
            profile_event_ref TEXT NOT NULL,\
            accountability_grant_ref TEXT NOT NULL,\
            authorization_ref TEXT NOT NULL,\
            display_name TEXT,\
            created_at BIGINT NOT NULL,\
            UNIQUE KEY user_protocol_tenant_external_id_unique \
                (protocol(64), tenant(191), external_user_id(191)),\
            UNIQUE KEY user_cokret_actor_did_unique (cokret_actor_did(191)))",
    ]
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
        let response = request
            .send()
            .await
            .map_err(|err| BridgeError::App(format!("media download failed: {err}")))?;
        let response = response
            .error_for_status()
            .map_err(|err| BridgeError::App(format!("media download status failed: {err}")))?;
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
            let chunk = chunk
                .map_err(|err| BridgeError::App(format!("media download read failed: {err}")))?;
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

    /// Submit an inbound text message as a `ck.message.create` event.
    pub async fn submit_app_message(&self, msg: InboundAppMessage) -> Result<String> {
        let payload = default_text_payload(&msg.body);
        self.submit_content(&msg, payload).await
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
        let payload = media_message_payload(&attachment)?;
        self.submit_content(&msg, payload).await
    }

    /// Shared submit path: resolve realm, attach signed provenance, submit on the
    /// per-channel serial queue, and record the message mapping.
    async fn submit_content(&self, msg: &InboundAppMessage, payload: Value) -> Result<String> {
        let external_event_id = normalized_external_id(&msg.app_message_id);
        if external_event_id.is_empty() {
            return Err(BridgeError::App(
                "inbound app_message_id is required for external event deduplication".into(),
            ));
        }

        let realm = self
            .store
            .realm_for_channel(&msg.app_channel)?
            .ok_or_else(|| {
                BridgeError::App(format!(
                    "channel {} has no realm mapping; create an explicit room mapping",
                    msg.app_channel
                ))
            })?;

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
                    if let Some(existing_event_id) =
                        store.event_for_channel_message(&mapping_channel_key, &external_event_id)?
                    {
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
                            let actor_did = provisioned.ghost_actor_did.to_string();
                            let display_name = provisioned
                                .display_name
                                .as_deref()
                                .or(Some(external_user_id.as_str()));
                            store.upsert_user(
                                &protocol,
                                &tenant,
                                &external_user_id,
                                &actor_did,
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
                    let actor = Did::new(mapping.cokret_actor_did)?;
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

    async fn run(self: Arc<Self>, ctx: Arc<MessageContext>) -> Result<()>;

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
    let actor_did = event.actor_id.to_string();
    let mut display = match store.user_by_actor(&actor_did)? {
        Some(row) => row
            .display_name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or(row.external_user_id),
        None => actor_did,
    };
    if let Some(executed_by) = event.executed_by.as_ref() {
        if executed_by != &event.actor_id {
            display = format!("{display} via {executed_by}");
        }
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
        if event.kind != "ck.message.create" {
            return Ok(());
        }
        // Skip events this bridge itself submitted (app -> cokret), which the
        // server echoes back, to avoid an outbound loop back into the app.
        let our_id = &self.ctx.core().config.bridge.bridge_id;
        let originated_here = event
            .unsigned
            .get("external_ref")
            .and_then(|r| r.get("source"))
            .and_then(Value::as_str)
            == Some(our_id.as_str());
        if originated_here {
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
        let Some(channel) = self.ctx.store.channel_for_realm(&realm_id)? else {
            tracing::debug!(realm = %realm_id, "realm has no channel mapping, dropping");
            return Ok(());
        };
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
                &event.event_id.to_string(),
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
        // Install DB-backed actor/realm resolution before the web service starts.
        core_ctx.set_resolver(Arc::new(MessageResolver {
            store: store.clone(),
        }));
        let ctx = Arc::new(MessageContext::new(core_ctx, store));
        let user = Arc::new(factory(ctx.clone())?);
        Ok(MessageAdapter { user, ctx })
    })
    .await
}

pub async fn submit_inbound(ctx: Arc<MessageContext>, label: &str, inbound: InboundAppMessage) {
    if let Err(e) = ctx.submit_app_message(inbound).await {
        tracing::warn!(error = %e, bridge = label, "app -> cokret submission failed");
    }
}
