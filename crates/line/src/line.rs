//! LINE adapter (LINE Messaging API, reqwest HTTP).
//!
//! - Inbound (LINE -> cokret): the Messaging API pushes signed events via
//!   `/webhooks/line`.
//! - Outbound (cokret → LINE): [`MessageBridge::send_to_app`] uses `ctx.http`
//!   (reqwest) to POST `https://api.line.me/v2/bot/message/push`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use cokret_bridge_messaging::salvo::{self, affix_state, prelude::*};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage, webhook,
};
use cokret_bridge_runtime::{BridgeError, Result};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

/// LINE bridge adapter.
pub struct LineApp {
    /// Push message token (Bearer).
    channel_access_token: String,
    /// Webhook signature verification secret.
    channel_secret: String,
}

impl LineApp {
    pub fn new(channel_access_token: impl Into<String>, channel_secret: impl Into<String>) -> Self {
        Self {
            channel_access_token: channel_access_token.into(),
            channel_secret: channel_secret.into(),
        }
    }
}

#[async_trait]
impl MessageBridge for LineApp {
    fn name(&self) -> &str {
        "line"
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
        // Prefix the text with the sender, matching the discord template style.
        let text = format!("{}: {}", msg.sender_display, msg.body);

        // app_channel is treated as the push target ID (userId / groupId / roomId).
        let body = json!({
            "to": msg.app_channel,
            "messages": [
                {
                    "type": "text",
                    "text": text,
                }
            ],
        });

        let resp = ctx
            .http
            .post("https://api.line.me/v2/bot/message/push")
            .bearer_auth(&self.channel_access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("LINE send failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(BridgeError::App(format!(
                "LINE send returned non-2xx: {status} {detail}"
            )));
        }

        // The LINE push endpoint's successful response body contains no message id; read the
        // x-line-request-id header as a tracing identifier, falling back to the target id if missing.
        let app_message_id = resp
            .headers()
            .get("x-line-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned())
            .unwrap_or_else(|| msg.app_channel.clone());

        Ok(AppMessageRef { app_message_id })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        Some(
            salvo::Router::with_path("webhooks/line")
                .hoop(affix_state::inject(LineWebhookState { app: self, ctx }))
                .post(line_delivery),
        )
    }
}

#[derive(Clone)]
struct LineWebhookState {
    app: Arc<LineApp>,
    ctx: Arc<MessageContext>,
}

#[handler]
async fn line_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<LineWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let signature = req.header::<String>("x-line-signature").unwrap_or_default();
    let payload = match req.payload().await {
        Ok(bytes) => bytes.to_vec(),
        Err(err) => {
            webhook::bad_request(res, format!("failed to read LINE payload: {err}"));
            return;
        }
    };
    if !verify_line_signature(&state.app.channel_secret, &payload, &signature) {
        webhook::unauthorized(res, "LINE signature mismatch");
        return;
    }
    let body: Value = match serde_json::from_slice(&payload) {
        Ok(value) => value,
        Err(err) => {
            webhook::bad_request(res, format!("invalid LINE JSON body: {err}"));
            return;
        }
    };

    for event in body
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if webhook::str_at(event, "/type") != Some("message")
            || webhook::str_at(event, "/message/type") != Some("text")
        {
            continue;
        }
        let Some(text) = webhook::str_at(event, "/message/text") else {
            continue;
        };
        let channel = webhook::first_string_at(
            event,
            &["/source/groupId", "/source/roomId", "/source/userId"],
        )
        .unwrap_or_default();
        let user = webhook::string_at(event, "/source/userId").unwrap_or_else(|| channel.clone());
        let message_id = webhook::first_string_at(event, &["/message/id", "/webhookEventId"])
            .or_else(|| event.get("timestamp").map(|v| v.to_string()))
            .unwrap_or_default();

        webhook::submit(
            state.ctx.clone(),
            "line",
            InboundAppMessage {
                app_channel: channel,
                app_user: user,
                app_message_id: message_id,
                body: text.to_owned(),
            },
        )
        .await;
    }
    webhook::ok_json(res, json!({ "ok": true }));
}

fn verify_line_signature(secret: &str, payload: &[u8], signature: &str) -> bool {
    type HmacSha256 = Hmac<Sha256>;

    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(payload);
    let expected = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    expected == signature
}
