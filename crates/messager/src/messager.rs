//! Messenger adapter (Facebook Graph API, pure reqwest).
//!
//! - Inbound (Messenger -> cokret): Facebook pushes `messages` events via
//!   `/webhooks/messenger`.
//! - Outbound (cokret → Messenger): [`MessageBridge::send_to_app`] uses `ctx.http` to POST
//!   `https://graph.facebook.com/v20.0/me/messages` (Bearer page_access_token).

use std::sync::Arc;

use async_trait::async_trait;
use cokret_bridge_messaging::salvo::{self, affix_state, prelude::*};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage, webhook,
};
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::{Value, json};

/// Graph API send endpoint.
const SEND_API: &str = "https://graph.facebook.com/v20.0/me/messages";

/// Messenger bridge adapter.
pub struct MessagerApp {
    /// Page access token (Bearer auth, used for sending).
    page_access_token: String,
    /// Webhook verification token (the value compared against `hub.verify_token` in the GET verification handshake).
    verify_token: Option<String>,
}

impl MessagerApp {
    pub fn new(page_access_token: impl Into<String>, verify_token: Option<String>) -> Self {
        Self {
            page_access_token: page_access_token.into(),
            verify_token,
        }
    }
}

#[async_trait]
impl MessageBridge for MessagerApp {
    fn name(&self) -> &str {
        "messager"
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
        // app_channel is the PSID (Page-Scoped User ID), used as recipient.id.
        let body = format!("{}: {}", msg.sender_display, msg.body);
        let payload = json!({
            "recipient": { "id": msg.app_channel },
            "messaging_type": "RESPONSE",
            "message": { "text": body },
        });

        let resp = ctx
            .http
            .post(SEND_API)
            .bearer_auth(&self.page_access_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("Messenger send request failed: {e}")))?;

        let status = resp.status();
        let value: serde_json::Value = resp.json().await.map_err(|e| {
            BridgeError::App(format!(
                "Messenger response parse failed (status={status}): {e}"
            ))
        })?;
        if !status.is_success() {
            return Err(BridgeError::App(format!(
                "Messenger send failed status={status}: {value}"
            )));
        }

        // The Graph API returns message_id on success.
        let message_id = value
            .get("message_id")
            .and_then(|m| m.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(AppMessageRef {
            app_message_id: message_id,
        })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        Some(
            salvo::Router::with_path("webhooks/messenger")
                .hoop(affix_state::inject(MessengerWebhookState {
                    app: self,
                    ctx,
                }))
                .get(messenger_verify)
                .post(messenger_delivery),
        )
    }
}

#[derive(Clone)]
struct MessengerWebhookState {
    app: Arc<MessagerApp>,
    ctx: Arc<MessageContext>,
}

#[handler]
async fn messenger_verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<MessengerWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let mode = req.query::<String>("hub.mode").unwrap_or_default();
    let token = req.query::<String>("hub.verify_token").unwrap_or_default();
    let challenge = req.query::<String>("hub.challenge").unwrap_or_default();
    if mode == "subscribe" && state.app.verify_token.as_deref() == Some(token.as_str()) {
        webhook::ok_text(res, challenge);
    } else {
        webhook::unauthorized(res, "Messenger verify token mismatch");
    }
}

#[handler]
async fn messenger_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<MessengerWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let Some(body) = webhook::json_body(req, res).await else {
        return;
    };

    for entry in body
        .get("entry")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for event in entry
            .get("messaging")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(text) = webhook::str_at(event, "/message/text") else {
                continue;
            };
            let user = webhook::string_at(event, "/sender/id").unwrap_or_default();
            let message_id = webhook::string_at(event, "/message/mid")
                .or_else(|| event.get("timestamp").map(|v| v.to_string()))
                .unwrap_or_default();
            webhook::submit(
                state.ctx.clone(),
                "messenger",
                InboundAppMessage {
                    app_channel: user.clone(),
                    app_user: user,
                    app_message_id: message_id,
                    body: text.to_owned(),
                },
            )
            .await;
        }
    }
    webhook::ok_json(res, json!({ "ok": true }));
}
