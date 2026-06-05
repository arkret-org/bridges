//! Microsoft Teams adapter (Bot Framework).
//!
//! - Outbound (cokret → Teams): [`MessageBridge::send_to_app`] first uses
//!   client_credentials to fetch an access token from AAD, then uses `ctx.http` to
//!   POST to the Bot Framework
//!   `{serviceUrl}/v3/conversations/{conversationId}/activities`.
//! - Inbound (Teams → cokret): the Bot Framework POSTs an Activity to the bot's
//!   `/api/messages` via an HTTPS webhook.

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

/// Fallback validity (seconds) when AAD omits `expires_in`.
const TEAMS_TOKEN_FALLBACK_SECS: u64 = 3600;

/// Microsoft Teams bridge adapter.
pub struct TeamsApp {
    /// Bot Framework / AAD application (client) ID.
    app_id: String,
    /// Application secret (client secret).
    app_password: String,
    /// Bot Framework serviceUrl base address (used to assemble the outbound activities endpoint).
    service_url: String,
    token_cache: TokenCache,
}

impl TeamsApp {
    pub fn new(
        app_id: impl Into<String>,
        app_password: impl Into<String>,
        service_url: impl Into<String>,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            app_password: app_password.into(),
            service_url: service_url.into(),
            token_cache: TokenCache::new(),
        }
    }

    /// Returns a Bot Framework access token, served from the cache until it
    /// nears the AAD-reported expiry, then re-fetched via client_credentials.
    async fn fetch_access_token(&self, ctx: &MessageContext) -> Result<String> {
        self.token_cache
            .get_or_try_refresh(|| async {
                // The Bot Framework botframework.com multi-tenant login endpoint.
                const TOKEN_URL: &str =
                    "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token";
                let params = [
                    ("grant_type", "client_credentials"),
                    ("client_id", self.app_id.as_str()),
                    ("client_secret", self.app_password.as_str()),
                    ("scope", "https://api.botframework.com/.default"),
                ];
                let resp: Value = ctx
                    .http
                    .post(TOKEN_URL)
                    .form(&params)
                    .send()
                    .await
                    .map_err(|e| BridgeError::App(format!("Teams token request failed: {e}")))?
                    .json()
                    .await
                    .map_err(|e| BridgeError::App(format!("Teams token parse failed: {e}")))?;

                let token = resp
                    .get("access_token")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        BridgeError::App(format!(
                            "Teams token response has no access_token: {resp}"
                        ))
                    })?;
                let ttl = resp
                    .get("expires_in")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(TEAMS_TOKEN_FALLBACK_SECS);
                Ok((token, Duration::from_secs(ttl)))
            })
            .await
    }
}

#[async_trait]
impl MessageBridge for TeamsApp {
    fn name(&self) -> &str {
        "teams"
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
        let token = self.fetch_access_token(&ctx).await?;

        // app_channel is treated as the Bot Framework conversationId.
        // activities endpoint: {serviceUrl}/v3/conversations/{conversationId}/activities
        let base = self.service_url.trim_end_matches('/');
        let url = format!("{base}/v3/conversations/{}/activities", msg.app_channel);

        let body = format!("**{}**: {}", msg.sender_display, msg.body);
        let activity = json!({
            "type": "message",
            "text": body,
        });

        let resp = ctx
            .http
            .post(&url)
            .bearer_auth(&token)
            .json(&activity)
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("Teams send request failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(BridgeError::App(format!(
                "Teams send failed ({status}): {text}"
            )));
        }

        // Bot Framework returns { "id": "<activityId>" }.
        let out: Value = resp
            .json()
            .await
            .map_err(|e| BridgeError::App(format!("Teams send response parse failed: {e}")))?;
        let id = out
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Ok(AppMessageRef { app_message_id: id })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        let state = TeamsWebhookState { ctx };
        Some(
            salvo::Router::new()
                .push(
                    salvo::Router::with_path("api/messages")
                        .hoop(affix_state::inject(state.clone()))
                        .post(teams_delivery),
                )
                .push(
                    salvo::Router::with_path("webhooks/teams")
                        .hoop(affix_state::inject(state))
                        .post(teams_delivery),
                ),
        )
    }
}

#[derive(Clone)]
struct TeamsWebhookState {
    ctx: Arc<MessageContext>,
}

#[handler]
async fn teams_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<TeamsWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let Some(body) = webhook::json_body(req, res).await else {
        return;
    };
    if body.get("type").and_then(Value::as_str) != Some("message") {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let text = webhook::str_at(&body, "/text").unwrap_or_default();
    if text.is_empty() {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let channel = webhook::string_at(&body, "/conversation/id").unwrap_or_default();
    let user = webhook::string_at(&body, "/from/id").unwrap_or_default();
    let Some(message_id) = webhook::first_non_empty_string_at(&body, &["/id", "/replyToId"]) else {
        webhook::bad_request(res, "Teams activity id missing");
        return;
    };
    webhook::submit(
        state.ctx.clone(),
        "teams",
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
