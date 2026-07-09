//! QQ adapter (OneBot HTTP API / QQ official bot, pure reqwest).
//!
//! - Inbound (QQ -> cokret): OneBot HTTP reports are accepted at `/webhooks/qq`.
//! - Outbound (cokret → QQ): [`MessageBridge::send_to_app`] uses `ctx.http` to POST to OneBot
//!   `send_msg` (or the official `/channels/{id}/messages`).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cokret_bridge_messaging::runtime::{BridgeError, Result};
use cokret_bridge_messaging::salvo::prelude::*;
use cokret_bridge_messaging::salvo::{self, affix_state};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle, json_scalar_id_string, send_json_expect, webhook,
};
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
        let target = qq_target_from_app_channel(&msg.app_channel)?;

        let url = format!("{}/send_msg", self.onebot_url.trim_end_matches('/'));
        let body = msg.rendered_body(SenderRenderStyle::Plain);
        let payload = match target {
            QqTarget::Group(group_id) => json!({
                "message_type": "group",
                "group_id": group_id,
                "message": body,
            }),
            QqTarget::Private(user_id) => json!({
                "message_type": "private",
                "user_id": user_id,
                "message": body,
            }),
        };

        let mut req = ctx.http.post(&url).json(&payload);
        if let Some(token) = &self.access_token {
            req = req.bearer_auth(token);
        }

        let value = send_json_expect(req, "QQ send", qq_send_ok).await?;

        // OneBot send_msg returns data.message_id on success.
        let message_id = value
            .get("data")
            .and_then(|d| d.get("message_id"))
            .and_then(json_scalar_id_string)
            .unwrap_or_default();
        Ok(AppMessageRef {
            app_message_id: message_id,
        })
    }

    fn expects_webhook_inbound(&self) -> bool {
        true
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        let signing_secret = self.signing_secret.clone();
        if signing_secret.trim().is_empty() {
            return None;
        }
        let replay = ctx.replay_window(QQ_REPLAY_TTL);
        Some(
            salvo::Router::with_path("webhooks/qq")
                .hoop(affix_state::inject(QqWebhookState {
                    ctx,
                    signing_secret,
                    replay,
                }))
                .post(qq_delivery),
        )
    }
}

/// In-handler bounded replay window for QQ (OneBot). The OneBot signature
/// (`HMAC-SHA1(signing_secret, raw_body)`) covers the body but carries no
/// timestamp/nonce, so a captured `(body, signature)` pair would otherwise
/// verify forever; the bridge contract (G-4) mandates a bounded replay/dedupe
/// guard keyed on the stable platform message id.
const QQ_REPLAY_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QqTarget {
    Group(i64),
    Private(i64),
}

fn qq_target_from_app_channel(app_channel: &str) -> Result<QqTarget> {
    if let Some(user) = app_channel.strip_prefix("private/") {
        let user_id = user
            .parse()
            .map_err(|_| BridgeError::App(format!("invalid QQ private user id: {app_channel}")))?;
        return Ok(QqTarget::Private(user_id));
    }
    let group_id = app_channel
        .parse()
        .map_err(|_| BridgeError::App(format!("invalid QQ group number: {app_channel}")))?;
    Ok(QqTarget::Group(group_id))
}

#[derive(Clone)]
struct QqWebhookState {
    ctx: Arc<MessageContext>,
    signing_secret: String,
    /// Bounded replay guard keyed on the platform `message_id`; a captured,
    /// validly signed event is accepted at most once inside the window.
    replay: Arc<webhook::ReplayWindow>,
}

#[handler]
async fn qq_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<QqWebhookState>() else {
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
    // Bounded replay/dedupe (BRG-SEC-001 / contract G-4): the OneBot signature
    // does not bind a timestamp, so a captured event would replay forever.
    // Record only after submit is accepted so transient failures can be
    // recovered by platform redelivery.
    let replay_key = format!("qq:{message_id}");
    if state.replay.contains(&replay_key).await {
        // Replayed event already accepted in the window; ack idempotently.
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let outcome = webhook::submit(
        state.ctx.clone(),
        "qq",
        InboundAppMessage {
            app_channel: channel,
            app_user: user,
            app_message_id: message_id.clone(),
            body: text,
        },
    )
    .await;
    if outcome == webhook::SubmitOutcome::Accepted {
        state.replay.check_and_record(replay_key).await;
    }
    webhook::respond_submit(res, outcome);
}

fn qq_send_ok(value: &Value) -> bool {
    value.get("retcode").and_then(Value::as_i64) == Some(0)
}

fn json_id_string(value: &Value) -> Option<String> {
    json_scalar_id_string(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_channel_parses_group_and_private_targets() {
        assert_eq!(
            qq_target_from_app_channel("12345").unwrap(),
            QqTarget::Group(12345)
        );
        assert_eq!(
            qq_target_from_app_channel("private/67890").unwrap(),
            QqTarget::Private(67890)
        );
        assert!(qq_target_from_app_channel("private/not-a-number").is_err());
    }

    #[test]
    fn json_id_string_accepts_string_and_integer_ids() {
        assert_eq!(json_id_string(&json!(" msg-1 ")).as_deref(), Some("msg-1"));
        assert_eq!(json_id_string(&json!(42)).as_deref(), Some("42"));
        assert_eq!(
            json_id_string(&json!(9007199254740993u64)).as_deref(),
            Some("9007199254740993")
        );
    }

    #[test]
    fn json_id_string_rejects_empty_or_non_scalar_ids() {
        assert!(json_id_string(&json!("   ")).is_none());
        assert!(json_id_string(&json!(null)).is_none());
        assert!(json_id_string(&json!({"id": "nested"})).is_none());
    }

    #[test]
    fn qq_send_ok_requires_success_retcode() {
        assert!(qq_send_ok(&json!({"status": "ok", "retcode": 0})));
        assert!(!qq_send_ok(&json!({"status": "failed", "retcode": 100})));
        assert!(!qq_send_ok(&json!({"status": "ok"})));
    }
}
