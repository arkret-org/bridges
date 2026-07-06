//! Microsoft Teams adapter (Bot Framework).
//!
//! - Outbound (cokret → Teams): [`MessageBridge::send_to_app`] first uses client_credentials to
//!   fetch an access token from AAD, then uses `ctx.http` to POST to the Bot Framework
//!   `{serviceUrl}/v3/conversations/{conversationId}/activities`.
//! - Inbound (Teams → cokret): the Bot Framework POSTs an Activity to the bot's `/api/messages` via
//!   an HTTPS webhook.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cokret_bridge_messaging::runtime::cache::TokenCache;
use cokret_bridge_messaging::runtime::{BridgeError, Result};
use cokret_bridge_messaging::salvo::prelude::*;
use cokret_bridge_messaging::salvo::{self, affix_state};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle, send_json_expect_status, webhook,
};
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
    inbound_jwt: Arc<webhook::JwtVerifier>,
    token_cache: TokenCache,
}

impl TeamsApp {
    pub fn new(
        app_id: impl Into<String>,
        app_password: impl Into<String>,
        service_url: impl Into<String>,
        inbound_jwt: Arc<webhook::JwtVerifier>,
        token_cache: TokenCache,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            app_password: app_password.into(),
            service_url: service_url.into(),
            inbound_jwt,
            token_cache,
        }
    }

    /// Returns a Bot Framework access token, served from the cache until it
    /// nears the AAD-reported expiry, then re-fetched via client_credentials.
    async fn access_token(&self, ctx: &MessageContext) -> Result<String> {
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
                let resp =
                    send_json_expect_status(ctx.http.post(TOKEN_URL).form(&params), "Teams token")
                        .await?;

                let token = resp
                    .get("access_token")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        BridgeError::App("Teams token response has no access_token".to_owned())
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

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let token = self.access_token(&ctx).await?;

        // app_channel is treated as the Bot Framework conversationId.
        // activities endpoint: {serviceUrl}/v3/conversations/{conversationId}/activities
        let base = self.service_url.trim_end_matches('/');
        let url = format!("{base}/v3/conversations/{}/activities", msg.app_channel);

        let body = msg.rendered_body(SenderRenderStyle::MarkdownBold);
        let activity = json!({
            "type": "message",
            "text": body,
        });

        let out = send_json_expect_status(
            ctx.http.post(&url).bearer_auth(&token).json(&activity),
            "Teams send",
        )
        .await?;

        // Bot Framework returns { "id": "<activityId>" }.
        let id = out
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Ok(AppMessageRef { app_message_id: id })
    }

    fn expects_webhook_inbound(&self) -> bool {
        true
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        let replay = ctx.replay_window(TEAMS_REPLAY_TTL);
        let state = TeamsWebhookState {
            ctx,
            inbound_jwt: self.inbound_jwt.clone(),
            replay,
        };
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

/// Replay/dedupe TTL keyed on the Bot Framework activity `id` (contract G-4,
/// extended to every verification scheme without a per-body nonce): the Bearer
/// JWT does not bind the request body, so a captured request could otherwise
/// be replayed verbatim for the whole token lifetime (~1h). The TTL covers
/// that lifetime with margin.
const TEAMS_REPLAY_TTL: Duration = Duration::from_secs(2 * 60 * 60);

#[derive(Clone)]
struct TeamsWebhookState {
    ctx: Arc<MessageContext>,
    inbound_jwt: Arc<webhook::JwtVerifier>,
    /// Durable replay guard keyed on the activity id; a captured, validly
    /// authenticated delivery is accepted at most once inside the window.
    replay: Arc<webhook::ReplayWindow>,
}

#[handler]
async fn teams_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<TeamsWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let authorization = req.header::<String>("authorization");
    let claims = match state
        .inbound_jwt
        .verify_authorization(authorization.as_deref())
        .await
    {
        Ok(claims) => claims,
        Err(error) => {
            webhook::unauthorized(res, format!("Teams JWT rejected: {error}"));
            return;
        }
    };
    let Some(body) = webhook::json_body(req, res).await else {
        return;
    };
    // Bot Framework auth: the token's `serviceUrl` claim MUST be present and
    // MUST match the activity's serviceUrl. Bot Framework normally issues
    // service tokens with this claim; a token without it cannot be bound to
    // the activity, so it is rejected (fail closed) — accepting it would let a
    // stolen-but-valid token be replayed against a forged activity routed to a
    // different service URL.
    let Some(token_service_url) = claims.get("serviceUrl").and_then(Value::as_str) else {
        webhook::unauthorized(res, "Teams JWT is missing the serviceUrl claim");
        return;
    };
    let activity_service_url = body.get("serviceUrl").and_then(Value::as_str);
    if activity_service_url != Some(token_service_url) {
        webhook::unauthorized(
            res,
            "Teams activity serviceUrl does not match the JWT claim",
        );
        return;
    }
    let inbound = match teams_inbound_activity(&body) {
        Ok(Some(inbound)) => inbound,
        Ok(None) => {
            webhook::ok_json(res, json!({ "ok": true }));
            return;
        }
        Err(message) => {
            webhook::bad_request(res, message);
            return;
        }
    };
    // Replay/dedupe on the stable activity id (contract G-4): the JWT does not
    // bind the body, so a captured request replays verbatim inside the token
    // lifetime without this guard. Record only after the submit is accepted so
    // a transient failure stays recoverable by platform redelivery.
    let replay_key = format!("teams:{}", inbound.app_message_id);
    if state.replay.contains(&replay_key) {
        tracing::debug!(activity_id = %inbound.app_message_id, "Teams activity replayed; skipping");
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let outcome = webhook::submit(state.ctx.clone(), "teams", inbound).await;
    if outcome == webhook::SubmitOutcome::Accepted {
        state.replay.check_and_record(replay_key);
    }
    webhook::respond_submit(res, outcome);
}

fn teams_inbound_activity(
    body: &Value,
) -> std::result::Result<Option<InboundAppMessage>, &'static str> {
    if body.get("type").and_then(Value::as_str) != Some("message") {
        return Ok(None);
    }
    let text = webhook::str_at(body, "/text").unwrap_or_default();
    if text.is_empty() {
        return Ok(None);
    }
    let Some(message_id) = webhook::first_non_empty_string_at(body, &["/id", "/replyToId"]) else {
        return Err("Teams activity id missing");
    };
    Ok(Some(InboundAppMessage {
        app_channel: webhook::string_at(body, "/conversation/id").unwrap_or_default(),
        app_user: webhook::string_at(body, "/from/id").unwrap_or_default(),
        app_message_id: message_id,
        body: text.to_owned(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teams_inbound_activity_extracts_message() {
        let body = json!({
            "type": "message",
            "id": "activity-id",
            "conversation": {"id": "conversation-id"},
            "from": {"id": "user-id"},
            "text": "hello"
        });
        let inbound = teams_inbound_activity(&body).unwrap().expect("message");
        assert_eq!(inbound.app_channel, "conversation-id");
        assert_eq!(inbound.app_user, "user-id");
        assert_eq!(inbound.app_message_id, "activity-id");
        assert_eq!(inbound.body, "hello");
    }

    #[test]
    fn teams_inbound_activity_accepts_reply_to_id_fallback() {
        let body = json!({
            "type": "message",
            "replyToId": "reply-id",
            "conversation": {"id": "conversation-id"},
            "from": {"id": "user-id"},
            "text": "reply"
        });
        let inbound = teams_inbound_activity(&body).unwrap().expect("message");
        assert_eq!(inbound.app_message_id, "reply-id");
    }

    #[test]
    fn teams_inbound_activity_skips_non_message_and_requires_id() {
        assert!(
            teams_inbound_activity(&json!({
                "type": "conversationUpdate",
                "id": "activity-id"
            }))
            .unwrap()
            .is_none()
        );
        assert!(
            teams_inbound_activity(&json!({
                "type": "message",
                "text": ""
            }))
            .unwrap()
            .is_none()
        );
        assert!(
            teams_inbound_activity(&json!({
                "type": "message",
                "text": "no id"
            }))
            .is_err()
        );
    }
}
