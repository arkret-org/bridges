//! iMessage adapter (via HTTP gateways such as BlueBubbles / AirMessage, pure reqwest).
//!
//! - Inbound (iMessage -> cokret): gateway JSON callbacks are accepted at
//!   `/webhooks/imessage`.
//! - Outbound (cokret → iMessage): [`MessageBridge::send_to_app`] uses `ctx.http` to POST
//!   the gateway's send endpoint (using BlueBubbles `/api/v1/message/text` as an example).

use std::sync::Arc;

use async_trait::async_trait;
use cokret_bridge_messaging::salvo::{self, affix_state, prelude::*};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage, webhook,
};
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::json;

/// iMessage bridge adapter.
pub struct IMessageApp {
    /// Gateway base, e.g. BlueBubbles' `http://127.0.0.1:1234`.
    gateway_url: String,
    /// Gateway access password (BlueBubbles uses it as the `?guid=` query parameter).
    password: Option<String>,
}

impl IMessageApp {
    pub fn new(gateway_url: impl Into<String>, password: Option<String>) -> Self {
        Self {
            gateway_url: gateway_url.into(),
            password,
        }
    }
}

#[async_trait]
impl MessageBridge for IMessageApp {
    fn name(&self) -> &str {
        "imessage"
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
        // Uses BlueBubbles' text send endpoint: POST /api/v1/message/text.
        // app_channel is the chat guid (e.g. iMessage;-;+15551234567).
        let base = self.gateway_url.trim_end_matches('/');
        let mut url = format!("{base}/api/v1/message/text");
        if let Some(pw) = &self.password {
            // BlueBubbles authenticates via the guid query parameter.
            url.push_str(&format!("?guid={pw}"));
        }

        let body = format!("{}: {}", msg.sender_display, msg.body);
        let payload = json!({
            "chatGuid": msg.app_channel,
            "message": body,
            "method": "apple-script",
        });

        let resp = ctx
            .http
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("iMessage gateway send request failed: {e}")))?;

        let status = resp.status();
        let value: serde_json::Value = resp.json().await.map_err(|e| {
            BridgeError::App(format!(
                "iMessage gateway response parse failed (status={status}): {e}"
            ))
        })?;
        if !status.is_success() {
            return Err(BridgeError::App(format!(
                "iMessage gateway send failed status={status}: {value}"
            )));
        }

        // BlueBubbles returns data.guid as the message identifier on success.
        let message_id = value
            .get("data")
            .and_then(|d| d.get("guid"))
            .and_then(|g| g.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(AppMessageRef {
            app_message_id: message_id,
        })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        Some(
            salvo::Router::with_path("webhooks/imessage")
                .hoop(affix_state::inject(IMessageWebhookState { ctx }))
                .post(imessage_delivery),
        )
    }
}

#[derive(Clone)]
struct IMessageWebhookState {
    ctx: Arc<MessageContext>,
}

#[handler]
async fn imessage_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<IMessageWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let Some(body) = webhook::json_body(req, res).await else {
        return;
    };
    let text =
        webhook::first_string_at(&body, &["/data/text", "/data/message", "/text", "/message"])
            .unwrap_or_default();
    if text.is_empty() {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let channel = webhook::first_string_at(
        &body,
        &[
            "/data/chatGuid",
            "/chatGuid",
            "/data/chat/guid",
            "/chat/guid",
        ],
    )
    .unwrap_or_default();
    let user = webhook::first_string_at(
        &body,
        &[
            "/data/handle/address",
            "/handle/address",
            "/from",
            "/sender",
        ],
    )
    .unwrap_or_default();
    let message_id =
        webhook::first_string_at(&body, &["/data/guid", "/guid", "/id"]).unwrap_or_default();
    webhook::submit(
        state.ctx.clone(),
        "imessage",
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
