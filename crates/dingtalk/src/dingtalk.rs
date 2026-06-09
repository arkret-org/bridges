//! DingTalk adapter (reqwest HTTP).
//!
//! - Inbound (DingTalk -> cokret): DingTalk callback messages are accepted at
//!   `/webhooks/dingtalk`.
//! - Outbound (cokret -> DingTalk): [`MessageBridge::send_to_app`] uses `ctx.http` (reqwest)
//!   to POST the DingTalk enterprise robot message-sending API.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cokret_bridge_messaging::salvo::{self, affix_state, prelude::*};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle, webhook,
};
use cokret_bridge_runtime::cache::TokenCache;
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::{Value, json};

/// Fallback validity (seconds) when the API omits `expireIn`.
const DINGTALK_TOKEN_FALLBACK_SECS: u64 = 7000;

/// DingTalk bridge adapter.
pub struct DingTalkApp {
    /// Enterprise internal app AppKey.
    app_key: String,
    /// Enterprise internal app AppSecret.
    app_secret: String,
    /// Robot code (robotCode).
    robot_code: String,
    token_cache: TokenCache,
}

impl DingTalkApp {
    pub fn new(
        app_key: impl Into<String>,
        app_secret: impl Into<String>,
        robot_code: impl Into<String>,
    ) -> Self {
        Self {
            app_key: app_key.into(),
            app_secret: app_secret.into(),
            robot_code: robot_code.into(),
            token_cache: TokenCache::new(),
        }
    }

    /// Returns an access_token, served from the cache until it nears the
    /// vendor-reported expiry, then re-fetched via AppKey/AppSecret.
    async fn fetch_access_token(&self, ctx: &Arc<MessageContext>) -> Result<String> {
        self.token_cache
            .get_or_try_refresh(|| async {
                // DingTalk's new API for obtaining an access_token.
                let resp = ctx
                    .http
                    .post("https://api.dingtalk.com/v1.0/oauth2/accessToken")
                    .json(&json!({
                        "appKey": self.app_key,
                        "appSecret": self.app_secret,
                    }))
                    .send()
                    .await
                    .map_err(|e| {
                        BridgeError::App(format!("DingTalk access_token request failed: {e}"))
                    })?;

                let value: Value = resp.json().await.map_err(|e| {
                    BridgeError::App(format!("DingTalk access_token response parse failed: {e}"))
                })?;

                let token = value
                    .get("accessToken")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_owned())
                    .ok_or_else(|| {
                        BridgeError::App(format!("DingTalk access_token is missing: {value}"))
                    })?;
                let ttl = value
                    .get("expireIn")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(DINGTALK_TOKEN_FALLBACK_SECS);
                Ok((token, Duration::from_secs(ttl)))
            })
            .await
    }
}

#[async_trait]
impl MessageBridge for DingTalkApp {
    fn name(&self) -> &str {
        "dingtalk"
    }

    async fn run(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let access_token = self.fetch_access_token(&ctx).await?;

        let text = msg.rendered_body(SenderRenderStyle::Plain);

        // DingTalk enterprise robot group message API; app_channel is treated as openConversationId.
        // msgParam must be a JSON string.
        let body = json!({
            "robotCode": self.robot_code,
            "openConversationId": msg.app_channel,
            "msgKey": "sampleText",
            "msgParam": json!({ "content": text }).to_string(),
        });

        let resp = ctx
            .http
            .post("https://api.dingtalk.com/v1.0/robot/groupMessages/send")
            .header("x-acs-dingtalk-access-token", access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("DingTalk send failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(BridgeError::App(format!(
                "DingTalk send returned non-2xx: {status} {detail}"
            )));
        }

        let value: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| BridgeError::App(format!("DingTalk send response parse failed: {e}")))?;

        // DingTalk returns processQueryKey as the message tracking identifier; falls back to the conversation id when missing.
        let app_message_id = value
            .get("processQueryKey")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .unwrap_or_else(|| msg.app_channel.clone());

        Ok(AppMessageRef { app_message_id })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        let app_secret = self.app_secret.clone();
        Some(
            salvo::Router::with_path("webhooks/dingtalk")
                .hoop(affix_state::inject(DingTalkWebhookState {
                    ctx,
                    app_secret,
                }))
                .post(dingtalk_delivery),
        )
    }
}

/// DingTalk outgoing-robot callbacks accept a `timestamp` whose skew from now
/// must stay within this window (milliseconds).
const DINGTALK_TIMESTAMP_WINDOW_MS: i64 = 5 * 60 * 1000;

#[derive(Clone)]
struct DingTalkWebhookState {
    ctx: Arc<MessageContext>,
    /// Enterprise app AppSecret, used for outgoing-callback signature checks.
    app_secret: String,
}

/// Verify a DingTalk outgoing-robot callback: `sign` header equals
/// `base64(HMAC-SHA256(app_secret, "{timestamp}\n{app_secret}"))`, with the
/// `timestamp` constrained to a freshness window.
fn dingtalk_signature_ok(app_secret: &str, timestamp: &str, sign: &str) -> bool {
    let Ok(ts) = timestamp.parse::<i64>() else {
        return false;
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    if (now_ms - ts).abs() > DINGTALK_TIMESTAMP_WINDOW_MS {
        return false;
    }
    let string_to_sign = format!("{timestamp}\n{app_secret}");
    webhook::verify_hmac_sha256(
        app_secret.as_bytes(),
        string_to_sign.as_bytes(),
        sign,
        webhook::SigEncoding::Base64,
    )
}

#[handler]
async fn dingtalk_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<DingTalkWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    // Fail closed: verify the `timestamp` + `sign` headers before any handling
    // (including the URL-verification challenge).
    if state.app_secret.is_empty() {
        webhook::unauthorized(res, "DingTalk app_secret not configured");
        return;
    }
    let timestamp = req.header::<String>("timestamp").unwrap_or_default();
    let sign = req.header::<String>("sign").unwrap_or_default();
    if !dingtalk_signature_ok(&state.app_secret, &timestamp, &sign) {
        webhook::unauthorized(res, "DingTalk signature mismatch");
        return;
    }
    let Some(body) = webhook::json_body(req, res).await else {
        return;
    };
    if let Some(challenge) = body.get("challenge").and_then(Value::as_str) {
        webhook::ok_json(res, json!({ "challenge": challenge }));
        return;
    }

    let text = webhook::first_string_at(
        &body,
        &[
            "/text/content",
            "/text",
            "/content",
            "/message/text",
            "/message/content",
        ],
    )
    .unwrap_or_default();
    if text.is_empty() {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let channel = webhook::first_string_at(
        &body,
        &[
            "/openConversationId",
            "/conversationId",
            "/conversation_id",
            "/chatbotCorpId",
        ],
    )
    .unwrap_or_default();
    let user = webhook::first_string_at(
        &body,
        &[
            "/senderStaffId",
            "/senderId",
            "/userId",
            "/openId",
            "/senderNick",
        ],
    )
    .unwrap_or_default();
    let Some(message_id) =
        webhook::first_non_empty_string_at(&body, &["/msgId", "/messageId", "/eventId"])
    else {
        webhook::bad_request(res, "DingTalk message id missing");
        return;
    };
    webhook::submit(
        state.ctx.clone(),
        "dingtalk",
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
