//! Feishu / Lark adapter (reqwest).
//!
//! - Inbound (Feishu -> cokret): Feishu events are pushed via
//!   `/webhooks/feishu`.
//! - Outbound (cokret -> Feishu): [`MessageBridge::send_to_app`] uses `ctx.http`
//!   `POST https://open.feishu.cn/open-apis/im/v1/messages`, which first exchanges
//!   app_id/app_secret for a `tenant_access_token`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cokret_bridge_messaging::salvo::{self, affix_state, prelude::*};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage, webhook,
};
use cokret_bridge_runtime::cache::TokenCache;
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::{Value, json};

const FEISHU_BASE: &str = "https://open.feishu.cn/open-apis";
/// Fallback validity (seconds) when the API omits `expire`.
const FEISHU_TOKEN_FALLBACK_SECS: u64 = 7000;

/// Feishu bridge adapter.
pub struct FeishuApp {
    app_id: String,
    app_secret: String,
    /// Event-subscription Verification Token. Inbound callbacks (challenge and
    /// events) MUST carry this token; compared in constant time (fail closed).
    verification_token: String,
    /// Event-subscription Encrypt Key. When set, Feishu encrypts the callback
    /// body (`{"encrypt": "..."}`). AES-decryption is not implemented here, so
    /// encrypted mode is rejected (fail closed) rather than silently passed.
    encrypt_key: Option<String>,
    token_cache: TokenCache,
}

impl FeishuApp {
    pub fn new(
        app_id: impl Into<String>,
        app_secret: impl Into<String>,
        verification_token: impl Into<String>,
        encrypt_key: Option<String>,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            app_secret: app_secret.into(),
            verification_token: verification_token.into(),
            encrypt_key: encrypt_key.filter(|k| !k.is_empty()),
            token_cache: TokenCache::new(),
        }
    }

    /// Returns a `tenant_access_token`, served from the cache until it nears the
    /// vendor-reported expiry, then re-fetched via app_id/app_secret.
    async fn tenant_access_token(&self, ctx: &Arc<MessageContext>) -> Result<String> {
        self.token_cache
            .get_or_try_refresh(|| async {
                let url = format!("{FEISHU_BASE}/auth/v3/tenant_access_token/internal");
                let resp = ctx
                    .http
                    .post(&url)
                    .json(&json!({
                        "app_id": self.app_id,
                        "app_secret": self.app_secret,
                    }))
                    .send()
                    .await
                    .map_err(|e| BridgeError::App(format!("Feishu token request failed: {e}")))?;

                let body: Value = resp
                    .json()
                    .await
                    .map_err(|e| BridgeError::App(format!("Feishu token parse failed: {e}")))?;

                if body.get("code").and_then(|v| v.as_i64()) != Some(0) {
                    return Err(BridgeError::App(format!(
                        "Feishu token returned an error: {body}"
                    )));
                }
                let token = body
                    .get("tenant_access_token")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_owned())
                    .ok_or_else(|| BridgeError::App(format!("Feishu token is missing: {body}")))?;
                let ttl = body
                    .get("expire")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(FEISHU_TOKEN_FALLBACK_SECS);
                Ok((token, Duration::from_secs(ttl)))
            })
            .await
    }
}

#[async_trait]
impl MessageBridge for FeishuApp {
    fn name(&self) -> &str {
        "feishu"
    }

    async fn run(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Result<()> {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let token = self.tenant_access_token(&ctx).await?;

        // app_channel can be plain chat_id or prefixed as `open_id/<id>`,
        // `user_id/<id>`, `union_id/<id>`, or `chat_id/<id>`.
        let (receive_id_type, receive_id) = receive_id_parts(&msg.app_channel);
        let url = format!("{FEISHU_BASE}/im/v1/messages?receive_id_type={receive_id_type}");
        let text = format!("{}: {}", msg.sender_display, msg.body);
        // For Feishu text messages, content is a "JSON string".
        let content = json!({ "text": text }).to_string();

        let resp = ctx
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&json!({
                "receive_id": receive_id,
                "msg_type": "text",
                "content": content,
            }))
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("Feishu send failed: {e}")))?;

        let body: Value = resp
            .json()
            .await
            .map_err(|e| BridgeError::App(format!("Feishu send response parse failed: {e}")))?;

        if body.get("code").and_then(|v| v.as_i64()) != Some(0) {
            return Err(BridgeError::App(format!(
                "Feishu send returned an error: {body}"
            )));
        }
        let message_id = body
            .get("data")
            .and_then(|d| d.get("message_id"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        Ok(AppMessageRef {
            app_message_id: message_id,
        })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        let verification_token = self.verification_token.clone();
        let encrypted_mode = self.encrypt_key.is_some();
        Some(
            salvo::Router::with_path("webhooks/feishu")
                .hoop(affix_state::inject(FeishuWebhookState {
                    ctx,
                    verification_token,
                    encrypted_mode,
                }))
                .post(feishu_delivery),
        )
    }
}

fn receive_id_parts(channel: &str) -> (&str, &str) {
    for kind in ["open_id", "user_id", "union_id", "chat_id"] {
        if let Some(rest) = channel.strip_prefix(&format!("{kind}/")) {
            return (kind, rest);
        }
    }
    ("chat_id", channel)
}

#[derive(Clone)]
struct FeishuWebhookState {
    ctx: Arc<MessageContext>,
    /// Event-subscription Verification Token (constant-time compared).
    verification_token: String,
    /// Whether an Encrypt Key is configured (encrypted callback mode).
    encrypted_mode: bool,
}

/// Read the verification token carried by a Feishu callback. v2 events nest it
/// under `header.token`; the v1 challenge and v1 events carry a top-level
/// `token`.
fn feishu_callback_token(body: &Value) -> &str {
    webhook::str_at(body, "/header/token")
        .or_else(|| body.get("token").and_then(Value::as_str))
        .unwrap_or_default()
}

#[handler]
async fn feishu_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<FeishuWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    // Fail closed: a Verification Token MUST be configured.
    if state.verification_token.is_empty() {
        webhook::unauthorized(res, "Feishu verification_token not configured");
        return;
    }
    let Some(body) = webhook::json_body(req, res).await else {
        return;
    };
    // Encrypted callback mode is not supported here; reject rather than pass an
    // unverified payload. Configure plaintext mode (no Encrypt Key) to use this
    // bridge.
    if state.encrypted_mode || body.get("encrypt").is_some() {
        webhook::unauthorized(res, "Feishu encrypted callback mode not supported");
        return;
    }
    // Authenticate the callback by its Verification Token (plaintext mode).
    let provided = feishu_callback_token(&body);
    if !webhook::constant_time_eq(provided.as_bytes(), state.verification_token.as_bytes()) {
        webhook::unauthorized(res, "Feishu verification token mismatch");
        return;
    }
    if let Some(challenge) = body.get("challenge").and_then(Value::as_str) {
        webhook::ok_json(res, json!({ "challenge": challenge }));
        return;
    }

    let event = body.get("event").unwrap_or(&body);
    if webhook::str_at(event, "/message/message_type") != Some("text") {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let content_raw = webhook::str_at(event, "/message/content").unwrap_or_default();
    let text = webhook::body_text_from_json_string(content_raw, "text");
    let channel = webhook::string_at(event, "/message/chat_id").unwrap_or_default();
    let user = webhook::first_string_at(
        event,
        &[
            "/sender/sender_id/open_id",
            "/sender/sender_id/user_id",
            "/sender/sender_id/union_id",
        ],
    )
    .unwrap_or_default();
    let message_id = webhook::string_at(event, "/message/message_id").unwrap_or_default();
    webhook::submit(
        state.ctx.clone(),
        "feishu",
        InboundAppMessage {
            app_channel: channel,
            app_user: user,
            app_message_id: message_id,
            body: text,
        },
    )
    .await;
    webhook::ok_json(res, json!({ "ok": true }));
}
