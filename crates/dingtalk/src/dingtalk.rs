//! DingTalk adapter (reqwest HTTP).
//!
//! - Inbound (DingTalk -> arkret): DingTalk callback messages are accepted at `/webhooks/dingtalk`.
//! - Outbound (arkret -> DingTalk): [`MessageBridge::send_to_app`] uses `ctx.http` (reqwest) to
//!   POST the DingTalk enterprise robot message-sending API.

use std::sync::Arc;
use std::time::Duration;

use arkret_bridge_messaging::runtime::Result;
use arkret_bridge_messaging::runtime::cache::TokenCache;
use arkret_bridge_messaging::salvo::prelude::*;
use arkret_bridge_messaging::salvo::{self, affix_state};
use arkret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle, VendorTokenCheck, fetch_vendor_token, non_empty_owned,
    send_json_expect_status, webhook,
};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

/// Fallback validity (seconds) when the API omits `expireIn`.
const DINGTALK_TOKEN_FALLBACK: Duration = Duration::from_secs(7000);

/// DingTalk bridge adapter.
pub struct DingTalkApp {
    /// Enterprise internal app AppKey.
    app_key: String,
    /// Enterprise internal app AppSecret.
    app_secret: String,
    /// Robot code (robotCode).
    robot_code: String,
    /// Local HMAC secret used by a trusted ingress proxy to sign the exact
    /// callback body. DingTalk's outgoing-robot `sign` does not cover body.
    webhook_body_hmac_secret: String,
    token_cache: TokenCache,
}

impl DingTalkApp {
    pub fn new(
        app_key: impl Into<String>,
        app_secret: impl Into<String>,
        robot_code: impl Into<String>,
        webhook_body_hmac_secret: impl Into<String>,
        token_cache: TokenCache,
    ) -> Self {
        Self {
            app_key: app_key.into(),
            app_secret: app_secret.into(),
            robot_code: robot_code.into(),
            webhook_body_hmac_secret: webhook_body_hmac_secret.into(),
            token_cache,
        }
    }

    /// Returns an access_token, served from the shared persistent cache until
    /// it nears the vendor-reported expiry, then re-fetched via
    /// AppKey/AppSecret.
    async fn access_token(&self, ctx: &Arc<MessageContext>) -> Result<String> {
        self.token_cache
            .get_or_try_refresh(|| {
                // DingTalk's new API for obtaining an access_token.
                let request = ctx
                    .http
                    .post("https://api.dingtalk.com/v1.0/oauth2/accessToken")
                    .json(&json!({
                        "appKey": self.app_key,
                        "appSecret": self.app_secret,
                    }));
                fetch_vendor_token(
                    request,
                    "DingTalk access_token",
                    VendorTokenCheck::HttpStatus,
                    "/accessToken",
                    "/expireIn",
                    DINGTALK_TOKEN_FALLBACK,
                )
            })
            .await
    }
}

#[async_trait]
impl MessageBridge for DingTalkApp {
    fn name(&self) -> &str {
        "dingtalk"
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let access_token = self.access_token(&ctx).await?;

        let text = msg.rendered_body(SenderRenderStyle::Plain);

        // DingTalk enterprise robot group message API; app_channel is treated as
        // openConversationId. msgParam must be a JSON string.
        let body = json!({
            "robotCode": self.robot_code,
            "openConversationId": msg.app_channel,
            "msgKey": "sampleText",
            "msgParam": json!({ "content": text }).to_string(),
        });

        let value = send_json_expect_status(
            ctx.http
                .post("https://api.dingtalk.com/v1.0/robot/groupMessages/send")
                .header("x-acs-dingtalk-access-token", access_token)
                .json(&body),
            "DingTalk send",
        )
        .await?;

        // DingTalk returns processQueryKey as the message tracking identifier.
        // Return the empty string when absent rather than falling back to the
        // conversation id: a non-message-id value would pollute the message
        // mapping (messaging skips recording an empty id).
        let app_message_id = value
            .get("processQueryKey")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .unwrap_or_default();

        Ok(AppMessageRef { app_message_id })
    }

    fn expects_webhook_inbound(&self) -> bool {
        true
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        let app_secret = self.app_secret.clone();
        let body_hmac_secret = self.webhook_body_hmac_secret.clone();
        if app_secret.trim().is_empty() || body_hmac_secret.trim().is_empty() {
            return None;
        }
        // BRG-SEC-002: `dingtalk_body_signature_ok` uses `unix_timestamp_is_fresh`
        // (|now-ts| <= window), so the acceptance window spans 2*window
        // (past+future). The replay TTL must cover that whole window or a captured
        // body+signature could be replayed in the off-window gap.
        let replay_window = ctx.replay_window(2 * DINGTALK_BODY_SIGNATURE_WINDOW);
        Some(
            salvo::Router::with_path("webhooks/dingtalk")
                .hoop(affix_state::inject(DingTalkWebhookState {
                    ctx,
                    app_secret,
                    body_hmac_secret,
                    replay_window,
                }))
                .post(dingtalk_delivery),
        )
    }
}

/// DingTalk outgoing-robot callbacks accept a `timestamp` whose skew from now
/// must stay within this window (milliseconds). The vendor signature does not
/// cover body bytes, so the bridge keeps this narrow and requires a second
/// local body HMAC before any message side effect.
const DINGTALK_TIMESTAMP_WINDOW_MS: i64 = 60 * 1000;
const DINGTALK_BODY_SIGNATURE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct DingTalkWebhookState {
    ctx: Arc<MessageContext>,
    /// Enterprise app AppSecret, used for outgoing-callback signature checks.
    app_secret: String,
    /// Secret for `x-arkret-signature-256`, generated by a trusted ingress proxy
    /// over `x-arkret-timestamp || "\n" || raw_body`.
    body_hmac_secret: String,
    replay_window: Arc<webhook::ReplayWindow>,
}

/// Verify a DingTalk outgoing-robot callback: `sign` header equals
/// `base64(HMAC-SHA256(app_secret, "{timestamp}\n{app_secret}"))`, with the
/// `timestamp` constrained to a freshness window.
fn dingtalk_signature_ok(app_secret: &str, timestamp: &str, sign: &str) -> bool {
    if !webhook::unix_timestamp_millis_is_fresh(
        timestamp,
        Duration::from_millis(DINGTALK_TIMESTAMP_WINDOW_MS as u64),
    ) {
        return false;
    }
    let string_to_sign = format!("{timestamp}\n{app_secret}");
    webhook::verify_hmac_sha256(
        app_secret.as_bytes(),
        string_to_sign.as_bytes(),
        sign,
        webhook::SigEncoding::Base64,
    )
}

fn dingtalk_body_signature_ok(secret: &str, timestamp: &str, raw: &[u8], signature: &str) -> bool {
    webhook::unix_timestamp_is_fresh(timestamp, DINGTALK_BODY_SIGNATURE_WINDOW)
        && webhook::verify_timestamped_hmac_sha256(
            secret.as_bytes(),
            timestamp,
            raw,
            signature,
            webhook::SigEncoding::Hex,
        )
}

#[derive(Debug, Deserialize)]
struct DingTalkInboundPayload {
    #[serde(default)]
    challenge: Option<String>,
    #[serde(default)]
    text: Option<DingTalkTextField>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    message: Option<DingTalkMessageField>,
    #[serde(default, rename = "openConversationId")]
    open_conversation_id: Option<String>,
    #[serde(default, rename = "conversationId")]
    conversation_id_camel: Option<String>,
    #[serde(default)]
    conversation_id: Option<String>,
    #[serde(default, rename = "chatbotCorpId")]
    chatbot_corp_id: Option<String>,
    #[serde(default, rename = "senderStaffId")]
    sender_staff_id: Option<String>,
    #[serde(default, rename = "senderId")]
    sender_id: Option<String>,
    #[serde(default, rename = "userId")]
    user_id: Option<String>,
    #[serde(default, rename = "openId")]
    open_id: Option<String>,
    #[serde(default, rename = "msgId")]
    msg_id: Option<String>,
    #[serde(default, rename = "messageId")]
    message_id: Option<String>,
    #[serde(default, rename = "eventId")]
    event_id: Option<String>,
    #[serde(default, rename = "msgtype")]
    msg_type_lower: Option<String>,
    #[serde(default, rename = "msgType")]
    msg_type_camel: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DingTalkTextField {
    Object { content: Option<String> },
    String(String),
}

#[derive(Debug, Deserialize)]
struct DingTalkMessageField {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    content: Option<String>,
}

impl DingTalkTextField {
    fn content(&self) -> Option<String> {
        match self {
            Self::Object { content } => non_empty_owned(content.clone()),
            Self::String(value) => non_empty_owned(Some(value.clone())),
        }
    }
}

impl DingTalkMessageField {
    fn text(&self) -> Option<String> {
        non_empty_owned(self.text.clone()).or_else(|| non_empty_owned(self.content.clone()))
    }
}

impl DingTalkInboundPayload {
    fn text_body(&self) -> Option<String> {
        self.text
            .as_ref()
            .and_then(DingTalkTextField::content)
            .or_else(|| non_empty_owned(self.content.clone()))
            .or_else(|| self.message.as_ref().and_then(DingTalkMessageField::text))
    }

    fn message_id(&self) -> Option<String> {
        non_empty_owned(self.msg_id.clone())
            .or_else(|| non_empty_owned(self.message_id.clone()))
            .or_else(|| non_empty_owned(self.event_id.clone()))
    }

    fn app_channel(&self) -> String {
        non_empty_owned(self.open_conversation_id.clone())
            .or_else(|| non_empty_owned(self.conversation_id_camel.clone()))
            .or_else(|| non_empty_owned(self.conversation_id.clone()))
            .or_else(|| non_empty_owned(self.chatbot_corp_id.clone()))
            .unwrap_or_default()
    }

    fn app_user(&self) -> String {
        non_empty_owned(self.sender_staff_id.clone())
            .or_else(|| non_empty_owned(self.sender_id.clone()))
            .or_else(|| non_empty_owned(self.user_id.clone()))
            .or_else(|| non_empty_owned(self.open_id.clone()))
            .unwrap_or_default()
    }

    fn unsupported_media_ref(&self) -> Option<(String, String, String, String)> {
        if self.text_body().is_some() {
            return None;
        }
        let msg_type = non_empty_owned(self.msg_type_lower.clone())
            .or_else(|| non_empty_owned(self.msg_type_camel.clone()))?;
        if msg_type == "text" {
            return None;
        }
        Some((
            self.app_channel(),
            self.app_user(),
            self.message_id()?,
            msg_type,
        ))
    }

    fn to_inbound_message(&self) -> std::result::Result<Option<InboundAppMessage>, &'static str> {
        let text = self.text_body();
        let Some(text) = text else {
            return Ok(None);
        };
        let Some(message_id) = self.message_id() else {
            return Err("DingTalk message id missing");
        };
        Ok(Some(InboundAppMessage {
            app_channel: self.app_channel(),
            app_user: self.app_user(),
            app_message_id: message_id,
            body: text,
        }))
    }
}

fn dingtalk_inbound_payload(body: Value) -> std::result::Result<DingTalkInboundPayload, String> {
    serde_json::from_value(body).map_err(|err| format!("invalid DingTalk callback shape: {err}"))
}

#[handler]
async fn dingtalk_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = webhook::require_state::<DingTalkWebhookState>(depot, res) else {
        return;
    };
    // Fail closed: verify the `timestamp` + `sign` headers before any handling
    // (including the URL-verification challenge).
    if state.app_secret.is_empty() {
        webhook::unauthorized(res, "DingTalk app_secret not configured");
        return;
    }
    let timestamp = req.header::<String>("timestamp").unwrap_or_default();
    let sign = req.header::<String>("sign").unwrap_or_default();
    if !dingtalk_signature_ok(&state.app_secret, &timestamp, &sign) {
        webhook::unauthorized(res, "DingTalk signature mismatch");
        return;
    }
    let Some(raw) = webhook::raw_body(req, res).await else {
        return;
    };
    let body = match serde_json::from_slice::<Value>(&raw) {
        Ok(body) => body,
        Err(err) => {
            webhook::bad_request(res, format!("invalid DingTalk webhook JSON body: {err}"));
            return;
        }
    };
    // BRG-REL-002: enforce the injected body HMAC (which actually covers the raw
    // body) BEFORE any handling — including the URL-verification challenge echo.
    // The vendor `sign` header verified above only covers `timestamp\napp_secret`
    // and does not bind the body, so letting a `challenge` field short-circuit
    // ahead of this guard would echo attacker-controlled content authenticated
    // only by a body-blind signature. The contract requires the body HMAC to
    // gate the entire inbound surface; fail closed when it is missing.
    if state.body_hmac_secret.trim().is_empty() {
        webhook::unauthorized(res, "DingTalk body HMAC secret not configured");
        return;
    }
    let body_timestamp = req
        .header::<String>("x-arkret-timestamp")
        .unwrap_or_default();
    let body_signature = req
        .header::<String>("x-arkret-signature-256")
        .unwrap_or_default();
    if !dingtalk_body_signature_ok(
        &state.body_hmac_secret,
        &body_timestamp,
        &raw,
        &body_signature,
    ) {
        webhook::unauthorized(res, "DingTalk body signature mismatch");
        return;
    }
    match state
        .replay_window
        .check_and_record(format!("{body_timestamp}\u{1f}{body_signature}"))
        .await
    {
        Ok(webhook::ReplayGuardVerdict::Fresh) => {}
        Ok(webhook::ReplayGuardVerdict::Replay) => {
            webhook::unauthorized(res, "DingTalk callback replay");
            return;
        }
        Err(error) => {
            webhook::replay_guard_unavailable(res, &error);
            return;
        }
    }
    let payload = match dingtalk_inbound_payload(body) {
        Ok(payload) => payload,
        Err(message) => {
            webhook::bad_request(res, message);
            return;
        }
    };

    // The challenge echo now runs only after the body HMAC + replay guards pass.
    if let Some(challenge) = payload.challenge.as_deref() {
        webhook::ok_json(res, json!({ "challenge": challenge }));
        return;
    }

    let inbound = match payload.to_inbound_message() {
        Ok(Some(inbound)) => inbound,
        Ok(None) => {
            if let Some((channel, user, message_id, media_kind)) = payload.unsupported_media_ref() {
                state
                    .ctx
                    .report_unsupported_inbound_media(
                        "dingtalk", channel, user, message_id, media_kind,
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
    let outcome = webhook::submit(state.ctx.clone(), "dingtalk", inbound).await;
    webhook::respond_submit(res, outcome);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dingtalk_inbound_message_extracts_stable_fields() {
        let payload = dingtalk_inbound_payload(json!({
            "text": { "content": "hello" },
            "openConversationId": "conv-1",
            "senderStaffId": "staff-1",
            "msgId": "msg-1"
        }))
        .unwrap();
        let inbound = payload.to_inbound_message().unwrap().expect("message");
        assert_eq!(inbound.app_channel, "conv-1");
        assert_eq!(inbound.app_user, "staff-1");
        assert_eq!(inbound.app_message_id, "msg-1");
        assert_eq!(inbound.body, "hello");
    }

    #[test]
    fn dingtalk_inbound_message_does_not_use_sender_nick_as_user_id() {
        let payload = dingtalk_inbound_payload(json!({
            "text": "hello",
            "senderNick": "Alice",
            "msgId": "msg-1"
        }))
        .unwrap();
        let inbound = payload.to_inbound_message().unwrap().expect("message");
        assert_eq!(inbound.app_user, "");
    }

    #[test]
    fn dingtalk_unsupported_media_extracts_msgtype() {
        let payload = dingtalk_inbound_payload(json!({
            "msgtype": "picture",
            "openConversationId": "conv-1",
            "senderStaffId": "staff-1",
            "msgId": "msg-1"
        }))
        .unwrap();
        let media = payload.unsupported_media_ref().expect("unsupported media");
        assert_eq!(media.0, "conv-1");
        assert_eq!(media.1, "staff-1");
        assert_eq!(media.2, "msg-1");
        assert_eq!(media.3, "picture");
    }

    #[test]
    fn dingtalk_signature_rejects_malformed_or_stale_timestamp() {
        assert!(!dingtalk_signature_ok(
            "secret",
            "not-a-timestamp",
            "anything"
        ));
        assert!(!dingtalk_signature_ok("secret", "0", "anything"));
    }

    #[test]
    fn dingtalk_body_signature_rejects_stale_or_tampered_body() {
        assert!(!dingtalk_body_signature_ok(
            "secret",
            "0",
            br#"{"hello":"world"}"#,
            "d3d89618b58441bc1f9fbbcaae8435ebd7a6eebbf9fb96c3b87302a69f0d6ed9"
        ));
        assert!(!webhook::verify_timestamped_hmac_sha256(
            b"secret",
            "1700000000",
            br#"{"hello":"tampered"}"#,
            "d3d89618b58441bc1f9fbbcaae8435ebd7a6eebbf9fb96c3b87302a69f0d6ed9",
            webhook::SigEncoding::Hex
        ));
    }
}
