//! Microsoft Teams adapter (Bot Framework).
//!
//! - Outbound (arkret → Teams): message creation and deletion use the Bot Framework Connector
//!   activity endpoints after fetching an AAD client-credentials access token.
//! - Inbound (Teams → arkret): the Bot Framework POSTs an Activity to the bot's `/api/messages` via
//!   an HTTPS webhook.

use std::sync::Arc;
use std::time::Duration;

use arkret_bridge_messaging::runtime::cache::TokenCache;
use arkret_bridge_messaging::runtime::{BridgeError, Result, redact_sensitive_url_values};
use arkret_bridge_messaging::salvo::prelude::*;
use arkret_bridge_messaging::salvo::{self, affix_state};
use arkret_bridge_messaging::{
    AppDeleteReason, AppMessageRef, InboundAppDelete, InboundAppMessage, MessageBridge,
    MessageContext, OutboundAppMessage, SenderRenderStyle, VendorTokenCheck, fetch_vendor_token,
    send_json_expect_status, webhook,
};
use async_trait::async_trait;
use serde_json::{Value, json};

/// Fallback validity (seconds) when AAD omits `expires_in`.
const TEAMS_TOKEN_FALLBACK: Duration = Duration::from_secs(3600);

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
            .get_or_try_refresh(|| {
                // The Bot Framework botframework.com multi-tenant login endpoint.
                const TOKEN_URL: &str =
                    "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token";
                let parameters = [
                    ("grant_type", "client_credentials"),
                    ("client_id", self.app_id.as_str()),
                    ("client_secret", self.app_password.as_str()),
                    ("scope", "https://api.botframework.com/.default"),
                ];
                fetch_vendor_token(
                    ctx.http.post(TOKEN_URL).form(&parameters),
                    "Teams token",
                    VendorTokenCheck::HttpStatus,
                    "/access_token",
                    "/expires_in",
                    TEAMS_TOKEN_FALLBACK,
                )
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
        let url = teams_activity_url(&self.service_url, &msg.app_channel, None)?;

        let body = msg.rendered_body(SenderRenderStyle::MarkdownBold);
        let activity = json!({
            "type": "message",
            "text": body,
        });

        let out = send_json_expect_status(
            ctx.http.post(url).bearer_auth(&token).json(&activity),
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

    async fn redact_in_app(
        &self,
        ctx: Arc<MessageContext>,
        app_channel: &str,
        app_message_id: &str,
    ) -> Result<()> {
        if app_channel.trim().is_empty() || app_message_id.trim().is_empty() {
            return Err(BridgeError::App(
                "Teams deletion requires conversation and activity ids".to_owned(),
            ));
        }
        let token = self.access_token(&ctx).await?;
        let url = teams_activity_url(&self.service_url, app_channel, Some(app_message_id))?;
        let response = ctx
            .http
            .delete(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|error| {
                BridgeError::App(format!(
                    "Teams delete request failed: {}",
                    redact_sensitive_url_values(error.to_string())
                ))
            })?;
        let status = response.status();
        if matches!(status.as_u16(), 404 | 410) {
            // Deletion is replay-safe: a prior successful attempt may have
            // removed the activity before its Arkret delivery was acknowledged.
            return Ok(());
        }
        if !status.is_success() {
            let detail: String = response
                .text()
                .await
                .unwrap_or_default()
                .chars()
                .take(2_048)
                .collect();
            return Err(BridgeError::App(format!(
                "Teams delete failed status={status}: {}",
                redact_sensitive_url_values(detail)
            )));
        }
        Ok(())
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
    let Some(state) = webhook::require_state::<TeamsWebhookState>(depot, res) else {
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
    let delete = match teams_inbound_delete(&body) {
        Ok(delete) => delete,
        Err(message) => {
            webhook::bad_request(res, message);
            return;
        }
    };
    if let Some(delete) = delete {
        let replay_key = format!(
            "teams:message-delete:{}",
            delete
                .source_event_id
                .as_deref()
                .unwrap_or(&delete.app_message_id)
        );
        match state.replay.check_and_record(replay_key.clone()).await {
            Ok(webhook::ReplayGuardVerdict::Fresh) => {}
            Ok(webhook::ReplayGuardVerdict::Replay) => {
                webhook::ok_json(res, json!({ "ok": true }));
                return;
            }
            Err(error) => {
                webhook::replay_guard_unavailable(res, &error);
                return;
            }
        }
        match state.ctx.submit_app_delete(delete).await {
            Ok(_) => webhook::ok_json(res, json!({ "ok": true })),
            Err(error) if error.is_retriable() => {
                state.replay.forget(replay_key).await;
                webhook::submission_retry(res);
            }
            Err(error) => {
                tracing::warn!(error = %error, "Teams delete bridging failed permanently");
                webhook::ok_json(res, json!({ "ok": true }));
            }
        }
        return;
    }
    let inbound = match teams_inbound_activity(&body) {
        Ok(Some(inbound)) => inbound,
        Ok(None) => {
            if let Some((channel, user, message_id, media_kind)) = teams_unsupported_media(&body) {
                state
                    .ctx
                    .report_unsupported_inbound_media(
                        "teams", channel, user, message_id, media_kind,
                    )
                    .await;
            }
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
    // lifetime without this guard.
    let replay_key = format!("teams:{}", inbound.app_message_id);
    let outcome = webhook::submit_deduped(
        state.ctx.clone(),
        "teams",
        &state.replay,
        replay_key,
        inbound,
    )
    .await;
    webhook::respond_submit(res, outcome);
}

fn teams_activity_url(
    service_url: &str,
    conversation_id: &str,
    activity_id: Option<&str>,
) -> Result<url::Url> {
    let mut url = url::Url::parse(service_url)
        .map_err(|error| BridgeError::App(format!("invalid Teams service URL: {error}")))?;
    let mut segments = url.path_segments_mut().map_err(|_| {
        BridgeError::App("Teams service URL cannot be used as an API base".to_owned())
    })?;
    segments
        .pop_if_empty()
        .extend(["v3", "conversations", conversation_id, "activities"]);
    if let Some(activity_id) = activity_id {
        segments.push(activity_id);
    }
    drop(segments);
    Ok(url)
}

fn teams_inbound_delete(
    body: &Value,
) -> std::result::Result<Option<InboundAppDelete>, &'static str> {
    if body.get("type").and_then(Value::as_str) != Some("messageDelete") {
        return Ok(None);
    }
    let Some(app_message_id) = webhook::non_empty_string_at(body, "/replyToId") else {
        return Err("Teams messageDelete replyToId missing");
    };
    let Some(app_channel) = webhook::non_empty_string_at(body, "/conversation/id") else {
        return Err("Teams messageDelete conversation id missing");
    };
    let Some(app_user) = webhook::non_empty_string_at(body, "/from/id") else {
        return Err("Teams messageDelete sender id missing");
    };
    Ok(Some(InboundAppDelete {
        app_channel,
        app_user,
        app_message_id,
        source_event_id: webhook::non_empty_string_at(body, "/id"),
        reason: AppDeleteReason::AppRecall,
    }))
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

fn teams_unsupported_media(body: &Value) -> Option<(String, String, String, &'static str)> {
    if body.get("type").and_then(Value::as_str) != Some("message") {
        return None;
    }
    let has_attachments = body
        .get("attachments")
        .and_then(Value::as_array)
        .is_some_and(|attachments| !attachments.is_empty());
    if !has_attachments
        || !webhook::str_at(body, "/text")
            .unwrap_or_default()
            .is_empty()
    {
        return None;
    }
    let message_id = webhook::first_non_empty_string_at(body, &["/id", "/replyToId"])?;
    Some((
        webhook::string_at(body, "/conversation/id").unwrap_or_default(),
        webhook::string_at(body, "/from/id").unwrap_or_default(),
        message_id,
        "attachments",
    ))
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
    fn teams_message_delete_maps_reply_target_and_actor() {
        let body = json!({
            "type": "messageDelete",
            "id": "delete-activity-id",
            "replyToId": "deleted-activity-id",
            "conversation": {"id": "conversation-id"},
            "from": {"id": "user-id"}
        });
        let delete = teams_inbound_delete(&body)
            .unwrap()
            .expect("message delete");
        assert_eq!(delete.app_channel, "conversation-id");
        assert_eq!(delete.app_user, "user-id");
        assert_eq!(delete.app_message_id, "deleted-activity-id");
        assert_eq!(
            delete.source_event_id.as_deref(),
            Some("delete-activity-id")
        );
        assert_eq!(delete.reason, AppDeleteReason::AppRecall);
    }

    #[test]
    fn teams_message_delete_requires_target_conversation_and_actor() {
        for body in [
            json!({
                "type": "messageDelete",
                "conversation": {"id": "conversation-id"},
                "from": {"id": "user-id"}
            }),
            json!({
                "type": "messageDelete",
                "replyToId": "deleted-activity-id",
                "from": {"id": "user-id"}
            }),
            json!({
                "type": "messageDelete",
                "replyToId": "deleted-activity-id",
                "conversation": {"id": "conversation-id"}
            }),
        ] {
            assert!(teams_inbound_delete(&body).is_err());
        }
    }

    #[test]
    fn teams_activity_url_targets_connector_delete_endpoint() {
        assert_eq!(
            teams_activity_url(
                "https://smba.trafficmanager.net/amer/",
                "conversation-id",
                Some("activity-id")
            )
            .unwrap()
            .as_str(),
            "https://smba.trafficmanager.net/amer/v3/conversations/conversation-id/activities/activity-id"
        );
    }

    #[test]
    fn teams_activity_url_encodes_path_segments() {
        assert_eq!(
            teams_activity_url(
                "https://smba.trafficmanager.net/amer",
                "conversation/with space",
                Some("activity/with space")
            )
            .unwrap()
            .as_str(),
            "https://smba.trafficmanager.net/amer/v3/conversations/conversation%2Fwith%20space/activities/activity%2Fwith%20space"
        );
    }

    #[test]
    fn teams_unsupported_media_extracts_attachment_message() {
        let body = json!({
            "type": "message",
            "id": "activity-id",
            "conversation": {"id": "conversation-id"},
            "from": {"id": "user-id"},
            "attachments": [{"contentType": "image/png"}]
        });
        let media = teams_unsupported_media(&body).expect("unsupported media");
        assert_eq!(media.0, "conversation-id");
        assert_eq!(media.1, "user-id");
        assert_eq!(media.2, "activity-id");
        assert_eq!(media.3, "attachments");
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
