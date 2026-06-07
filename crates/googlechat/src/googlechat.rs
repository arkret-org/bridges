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
    AppMessageRef, MessageBridge, MessageContext, OutboundAppMessage, webhook,
};
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::json;

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

    fn webhook_router(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        Some(
            salvo::Router::with_path("webhooks/googlechat")
                .hoop(affix_state::inject(GoogleChatWebhookState))
                .post(googlechat_delivery),
        )
    }
}

#[derive(Clone)]
struct GoogleChatWebhookState;

#[handler]
async fn googlechat_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(_state) = depot.obtain::<GoogleChatWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let authorization = req.header::<String>("authorization").unwrap_or_default();
    if !authorization.starts_with("Bearer ") {
        webhook::unauthorized(res, "Google Chat bearer JWT is required");
        return;
    }
    webhook::unauthorized(
        res,
        "Google Chat inbound JWT verification is not configured; refusing unverified delivery",
    );
}
