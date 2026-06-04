//! WhatsApp adapter (WhatsApp Cloud API, reqwest HTTP).
//!
//! - Inbound (WhatsApp -> cokret): the Cloud API pushes messages via
//!   `/webhooks/whatsapp` (GET verification + POST delivery).
//! - Outbound (cokret → WhatsApp): [`MessageBridge::send_to_app`] uses `ctx.http`
//!   (reqwest) to POST `https://graph.facebook.com/v20.0/{phone_number_id}/messages`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cokret_bridge_messaging::salvo::{self, affix_state, prelude::*};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage, webhook,
};
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::{Value, json};

/// Graph API version.
const GRAPH_API_VERSION: &str = "v20.0";

/// WhatsApp bridge adapter.
pub struct WhatsAppApp {
    /// Sender phone number ID (outbound URL path segment).
    phone_number_id: String,
    /// Cloud API token (Bearer).
    access_token: String,
    /// Webhook verification echo token.
    verify_token: String,
}

impl WhatsAppApp {
    pub fn new(
        phone_number_id: impl Into<String>,
        access_token: impl Into<String>,
        verify_token: impl Into<String>,
    ) -> Self {
        Self {
            phone_number_id: phone_number_id.into(),
            access_token: access_token.into(),
            verify_token: verify_token.into(),
        }
    }
}

#[async_trait]
impl MessageBridge for WhatsAppApp {
    fn name(&self) -> &str {
        "whatsapp"
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
        let url = format!(
            "https://graph.facebook.com/{GRAPH_API_VERSION}/{}/messages",
            self.phone_number_id
        );

        // Prefix the text with the sender, matching the discord template style.
        let text = format!("{}: {}", msg.sender_display, msg.body);

        // app_channel is treated as the recipient WhatsApp number (E.164, without +).
        let body = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": msg.app_channel,
            "type": "text",
            "text": {
                "preview_url": false,
                "body": text,
            },
        });

        let resp = ctx
            .http
            .post(&url)
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("WhatsApp send failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(BridgeError::App(format!(
                "WhatsApp send returned non-2xx: {status} {detail}"
            )));
        }

        let value: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| BridgeError::App(format!("WhatsApp send response parse failed: {e}")))?;

        // Return messages[0].id as the app-side message identifier; fall back to the recipient number if missing.
        let app_message_id = value
            .get("messages")
            .and_then(|m| m.get(0))
            .and_then(|m| m.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .unwrap_or_else(|| msg.app_channel.clone());

        Ok(AppMessageRef { app_message_id })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        Some(
            salvo::Router::with_path("webhooks/whatsapp")
                .hoop(affix_state::inject(WhatsAppWebhookState { app: self, ctx }))
                .get(whatsapp_verify)
                .post(whatsapp_delivery),
        )
    }
}

#[derive(Clone)]
struct WhatsAppWebhookState {
    app: Arc<WhatsAppApp>,
    ctx: Arc<MessageContext>,
}

#[handler]
async fn whatsapp_verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<WhatsAppWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let mode = req.query::<String>("hub.mode").unwrap_or_default();
    let token = req.query::<String>("hub.verify_token").unwrap_or_default();
    let challenge = req.query::<String>("hub.challenge").unwrap_or_default();
    if mode == "subscribe" && token == state.app.verify_token {
        webhook::ok_text(res, challenge);
    } else {
        webhook::unauthorized(res, "WhatsApp verify token mismatch");
    }
}

#[handler]
async fn whatsapp_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<WhatsAppWebhookState>() else {
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
        for change in entry
            .get("changes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let value = change.get("value").unwrap_or(change);
            for message in value
                .get("messages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(text) = webhook::str_at(message, "/text/body") else {
                    continue;
                };
                let from = webhook::string_at(message, "/from").unwrap_or_default();
                let message_id = webhook::string_at(message, "/id")
                    .or_else(|| webhook::string_at(message, "/timestamp"))
                    .unwrap_or_default();
                webhook::submit(
                    state.ctx.clone(),
                    "whatsapp",
                    InboundAppMessage {
                        app_channel: from.clone(),
                        app_user: from,
                        app_message_id: message_id,
                        body: text.to_owned(),
                    },
                )
                .await;
            }
        }
    }
    webhook::ok_json(res, json!({ "ok": true }));
}
