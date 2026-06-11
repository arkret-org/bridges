//! QQ adapter (OneBot HTTP API / QQ official bot, pure reqwest).
//!
//! - Inbound (QQ -> cokret): OneBot HTTP reports are accepted at
//!   `/webhooks/qq`.
//! - Outbound (cokret → QQ): [`MessageBridge::send_to_app`] uses `ctx.http` to POST to
//!   OneBot `send_msg` (or the official `/channels/{id}/messages`).

use std::sync::Arc;

use async_trait::async_trait;
use cokret_bridge_messaging::salvo::{self, affix_state, prelude::*};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle, webhook,
};
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::{Value, json};

/// QQ bridge adapter.
pub struct QqApp {
    /// OneBot HTTP API base, e.g. `http://127.0.0.1:5700`.
    onebot_url: String,
    /// OneBot `access_token` (optional, used as Bearer auth).
    access_token: Option<String>,
    /// OneBot HTTP POST signing secret. Inbound events carry
    /// `X-Signature: sha1=<HMAC-SHA1(secret, raw_body)>`; required (fail closed).
    signing_secret: String,
}

impl QqApp {
    pub fn new(
        onebot_url: impl Into<String>,
        access_token: Option<String>,
        signing_secret: impl Into<String>,
    ) -> Self {
        Self {
            onebot_url: onebot_url.into(),
            access_token,
            signing_secret: signing_secret.into(),
        }
    }
}

#[async_trait]
impl MessageBridge for QqApp {
    fn name(&self) -> &str {
        "qq"
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        // OneBot v11 send_msg: app_channel is the QQ group number.
        let group_id: i64 = msg.app_channel.parse().map_err(|_| {
            BridgeError::App(format!("invalid QQ group number: {}", msg.app_channel))
        })?;

        let url = format!("{}/send_msg", self.onebot_url.trim_end_matches('/'));
        let body = msg.rendered_body(SenderRenderStyle::Plain);
        let payload = json!({
            "message_type": "group",
            "group_id": group_id,
            "message": body,
        });

        let mut req = ctx.http.post(&url).json(&payload);
        if let Some(token) = &self.access_token {
            req = req.bearer_auth(token);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("QQ send request failed: {e}")))?;
        let status = resp.status();
        let value: serde_json::Value = resp.json().await.map_err(|e| {
            BridgeError::App(format!("QQ response parse failed (status={status}): {e}"))
        })?;
        if !status.is_success() {
            return Err(BridgeError::App(format!(
                "QQ send failed status={status}: {value}"
            )));
        }

        // OneBot send_msg returns data.message_id on success.
        let message_id = value
            .get("data")
            .and_then(|d| d.get("message_id"))
            .map(|id| id.to_string())
            .unwrap_or_default();
        Ok(AppMessageRef {
            app_message_id: message_id,
        })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        let signing_secret = self.signing_secret.clone();
        Some(
            salvo::Router::with_path("webhooks/qq")
                .hoop(affix_state::inject(QqWebhookState {
                    ctx,
                    signing_secret,
                }))
                .post(qq_delivery),
        )
    }
}

#[derive(Clone)]
struct QqWebhookState {
    ctx: Arc<MessageContext>,
    signing_secret: String,
}

#[handler]
async fn qq_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<QqWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    // Fail closed: OneBot HTTP POST events MUST carry a valid
    // `X-Signature: sha1=<HMAC-SHA1(signing_secret, raw_body)>`.
    if state.signing_secret.is_empty() {
        webhook::unauthorized(res, "QQ signing_secret not configured");
        return;
    }
    let Some(raw) = webhook::raw_body(req, res).await else {
        return;
    };
    let header = req.header::<String>("x-signature").unwrap_or_default();
    let Some(provided) = header.strip_prefix("sha1=") else {
        webhook::unauthorized(res, "QQ X-Signature missing or malformed");
        return;
    };
    if !webhook::verify_hmac_sha1(
        state.signing_secret.as_bytes(),
        &raw,
        provided,
        webhook::SigEncoding::Hex,
    ) {
        webhook::unauthorized(res, "QQ X-Signature mismatch");
        return;
    }
    let body: Value = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(err) => {
            webhook::bad_request(res, format!("invalid QQ JSON body: {err}"));
            return;
        }
    };
    if body.get("post_type").and_then(Value::as_str) != Some("message") {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let text = webhook::first_string_at(&body, &["/raw_message", "/message"]).unwrap_or_default();
    if text.is_empty() {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let user = body
        .get("user_id")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let channel = if let Some(group_id) = body.get("group_id") {
        group_id.to_string()
    } else {
        format!("private/{user}")
    };
    let Some(message_id) = body.get("message_id").and_then(json_id_string) else {
        webhook::bad_request(res, "QQ message_id missing");
        return;
    };
    webhook::submit(
        state.ctx.clone(),
        "qq",
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

fn json_id_string(value: &Value) -> Option<String> {
    if let Some(s) = value.as_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    } else if let Some(n) = value.as_i64() {
        Some(n.to_string())
    } else if let Some(n) = value.as_u64() {
        Some(n.to_string())
    } else {
        None
    }
}
