//! Google Chat adapter (Google Chat REST API, pure reqwest).
//!
//! - Inbound (Google Chat -> cokret): Google Chat pushes message events via
//!   `/webhooks/googlechat`.
//! - Outbound (cokret → Google Chat): [`MessageBridge::send_to_app`] uses `ctx.http` to POST
//!   `https://chat.googleapis.com/v1/{space}/messages`.

use std::sync::Arc;

use async_trait::async_trait;
use cokret_bridge_messaging::salvo::{self, affix_state, prelude::*};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage, webhook,
};
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::{Value, json};

/// Google Chat API base.
const CHAT_API_BASE: &str = "https://chat.googleapis.com/v1";

/// Google Chat bridge adapter.
pub struct GoogleChatApp {
    /// Ready OAuth2 access token (scope: chat.bot, etc.).
    access_token: String,
}

impl GoogleChatApp {
    pub fn new(access_token: impl Into<String>) -> Self {
        Self {
            access_token: access_token.into(),
        }
    }

    /// Obtain the OAuth2 access_token used to call the Chat API.
    fn bearer_token(&self) -> String {
        self.access_token.clone()
    }
}

#[async_trait]
impl MessageBridge for GoogleChatApp {
    fn name(&self) -> &str {
        "googlechat"
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
        // app_channel is the space resource name, like `spaces/AAAAAAAAAAA`.
        let space = msg.app_channel.trim_matches('/');
        let url = format!("{CHAT_API_BASE}/{space}/messages");
        let body = format!("{}: {}", msg.sender_display, msg.body);
        let payload = json!({ "text": body });

        let token = self.bearer_token();
        let resp = ctx
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("Google Chat send request failed: {e}")))?;

        let status = resp.status();
        let value: serde_json::Value = resp.json().await.map_err(|e| {
            BridgeError::App(format!(
                "Google Chat response parse failed (status={status}): {e}"
            ))
        })?;
        if !status.is_success() {
            return Err(BridgeError::App(format!(
                "Google Chat send failed status={status}: {value}"
            )));
        }

        // The message resource name returned on success looks like spaces/AAA/messages/BBB.CCC.
        let message_id = value
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(AppMessageRef {
            app_message_id: message_id,
        })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        Some(
            salvo::Router::with_path("webhooks/googlechat")
                .hoop(affix_state::inject(GoogleChatWebhookState { ctx }))
                .post(googlechat_delivery),
        )
    }
}

#[derive(Clone)]
struct GoogleChatWebhookState {
    ctx: Arc<MessageContext>,
}

#[handler]
async fn googlechat_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<GoogleChatWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let Some(body) = webhook::json_body(req, res).await else {
        return;
    };
    if body.get("type").and_then(Value::as_str) != Some("MESSAGE") {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let message = body.get("message").unwrap_or(&body);
    let Some(text) = webhook::str_at(message, "/text") else {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    };
    let channel = webhook::first_string_at(message, &["/space/name", "/thread/name"])
        .or_else(|| webhook::string_at(&body, "/space/name"))
        .unwrap_or_default();
    let user = webhook::first_string_at(&body, &["/user/name", "/sender/name"]).unwrap_or_default();
    let Some(message_id) = webhook::non_empty_string_at(message, "/name") else {
        webhook::bad_request(res, "Google Chat message name missing");
        return;
    };
    webhook::submit(
        state.ctx.clone(),
        "googlechat",
        InboundAppMessage {
            app_channel: channel,
            app_user: user,
            app_message_id: message_id,
            body: text.to_owned(),
        },
    )
    .await;
    webhook::ok_json(res, json!({ "ok": true }));
}
