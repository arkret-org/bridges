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

use std::sync::Arc;

use async_trait::async_trait;
use cokret::Event;
use cokret_bridge_runtime::app::{BridgeApp, BridgeContext};
use cokret_bridge_runtime::db::DatabaseManager;
use cokret_bridge_runtime::{BridgeError, Result};
use diesel::prelude::*;
use serde_json::{Value, json};

pub use cokret_bridge_runtime as runtime;
pub use models::{MessageMapping, RoomMapping, UserMapping};
pub use runtime::salvo;

use models::{NewMessageMapping, NewRoomMapping, NewUserMapping};

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
}

/// The app-side message reference returned after the adapter sends.
#[derive(Clone, Debug)]
pub struct AppMessageRef {
    pub app_message_id: String,
}

/// Build a minimal `ck.message.create` text payload.
pub fn default_text_payload(body: &str) -> Value {
    json!({ "object": { "kind": "message", "body": body, "format": "text" } })
}

/// Extract displayable plain text from a Cokret message payload.
pub fn extract_plain_body(payload: &Value) -> String {
    payload
        .get("object")
        .and_then(|o| o.get("body"))
        .and_then(Value::as_str)
        .or_else(|| payload.get("body").and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned()
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
        app_user: &str,
        actor_did: &str,
        display: Option<&str>,
    ) -> Result<()> {
        use schema::user_mappings::dsl;

        let mut conn = self.db.conn()?;
        let exists = dsl::user_mappings
            .filter(dsl::app_user_id.eq(app_user))
            .first::<UserMapping>(&mut conn)
            .optional()?;
        if let Some(existing) = exists {
            diesel::update(dsl::user_mappings.filter(dsl::id.eq(existing.id)))
                .set((
                    dsl::cokret_actor_did.eq(actor_did),
                    dsl::display_name.eq(display),
                ))
                .execute(&mut conn)?;
        } else {
            diesel::insert_into(dsl::user_mappings)
                .values(NewUserMapping {
                    app_user_id: app_user,
                    cokret_actor_did: actor_did,
                    display_name: display,
                    created_at: now_ts(),
                })
                .execute(&mut conn)?;
        }
        Ok(())
    }

    pub fn actor_for_app_user(&self, app_user: &str) -> Result<Option<String>> {
        use schema::user_mappings::dsl;

        let mut conn = self.db.conn()?;
        Ok(dsl::user_mappings
            .filter(dsl::app_user_id.eq(app_user))
            .select(dsl::cokret_actor_did)
            .first::<String>(&mut conn)
            .optional()?)
    }
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
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
            app_user_id TEXT NOT NULL UNIQUE,\
            cokret_actor_did TEXT NOT NULL,\
            display_name TEXT,\
            created_at BIGINT NOT NULL)",
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
            app_user_id TEXT NOT NULL UNIQUE,\
            cokret_actor_did TEXT NOT NULL,\
            display_name TEXT,\
            created_at BIGINT NOT NULL)",
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
            app_user_id TEXT NOT NULL,\
            cokret_actor_did TEXT NOT NULL,\
            display_name TEXT,\
            created_at BIGINT NOT NULL,\
            UNIQUE KEY user_app_user_id_unique (app_user_id(191)))",
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

    pub async fn submit_app_message(&self, msg: InboundAppMessage) -> Result<String> {
        let realm = self
            .store
            .realm_for_channel(&msg.app_channel)?
            .or_else(|| self.inner.config.cokret.default_realm_id.clone())
            .ok_or_else(|| {
                BridgeError::App(format!("channel {} has no realm mapping", msg.app_channel))
            })?;

        let payload = default_text_payload(&msg.body);
        let external_ref = json!({
            "source": self.inner.config.bridge.bridge_id.clone(),
            "app_channel": msg.app_channel.clone(),
            "app_user": msg.app_user.clone(),
            "app_message_id": msg.app_message_id.clone(),
        });
        let realm_for_record = realm.clone();
        let event_id = self
            .inner
            .queue
            .run(&msg.app_channel, || {
                let edge = self.inner.edge.clone();
                async move {
                    edge.submit_with_external_ref(
                        &realm,
                        "ck.message.create",
                        payload,
                        external_ref,
                    )
                    .await
                }
            })
            .await?;

        self.store.record_message(
            &msg.app_channel,
            &msg.app_message_id,
            &event_id,
            &realm_for_record,
        )?;
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

    fn webhook_router(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        None
    }
}

struct MessageAdapter<M: MessageBridge> {
    user: Arc<M>,
    ctx: Arc<MessageContext>,
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
        let realm_id = event.realm_id.to_string();
        let Some(channel) = self.ctx.store.channel_for_realm(&realm_id)? else {
            tracing::debug!(realm = %realm_id, "realm has no channel mapping, dropping");
            return Ok(());
        };
        let body = extract_plain_body(&event.content);
        let out = OutboundAppMessage {
            app_channel: channel.clone(),
            sender_display: event.actor_id.to_string(),
            body,
            reply_to: None,
        };
        let app_ref = self.user.send_to_app(self.ctx.clone(), out).await?;
        self.ctx.store.record_message(
            &channel,
            &app_ref.app_message_id,
            &event.event_id.to_string(),
            &realm_id,
        )?;
        Ok(())
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
