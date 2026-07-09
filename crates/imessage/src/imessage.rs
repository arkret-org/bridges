//! iMessage adapter (via HTTP gateways such as BlueBubbles / AirMessage, pure reqwest).
//!
//! - Inbound (iMessage -> arkret): gateway JSON callbacks are accepted at `/webhooks/imessage`.
//! - Outbound (arkret → iMessage): [`MessageBridge::send_to_app`] uses `ctx.http` to POST the
//!   gateway's send endpoint (using BlueBubbles `/api/v1/message/text` as an example).

use std::sync::Arc;
use std::time::Duration;

use arkret_bridge_messaging::runtime::Result;
use arkret_bridge_messaging::salvo::prelude::*;
use arkret_bridge_messaging::salvo::{self, affix_state};
use arkret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle, send_json_expect_status, webhook,
};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};

/// iMessage bridge adapter.
pub struct IMessageApp {
    /// Gateway base, e.g. BlueBubbles' `http://127.0.0.1:1234`.
    gateway_url: String,
    /// Gateway access password (BlueBubbles uses it as the `?guid=` query parameter).
    password: Option<String>,
    /// HMAC secret required on inbound webhook calls. When `None`, inbound
    /// webhooks are rejected fail-closed.
    webhook_secret: String,
}

impl IMessageApp {
    pub fn new(
        gateway_url: impl Into<String>,
        password: Option<String>,
        webhook_secret: impl Into<String>,
    ) -> Self {
        Self {
            gateway_url: gateway_url.into(),
            password,
            webhook_secret: webhook_secret.into(),
        }
    }
}

#[async_trait]
impl MessageBridge for IMessageApp {
    fn name(&self) -> &str {
        "imessage"
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

        let body = msg.rendered_body(SenderRenderStyle::Plain);
        let payload = json!({
            "chatGuid": msg.app_channel,
            "message": body,
            "method": "apple-script",
        });

        // The shared helper redacts sensitive URL values (the BlueBubbles
        // `?guid=<password>` may be echoed in error bodies) and truncates the
        // error body (BRG-DRY-01; the old hand-rolled branch here leaked the
        // unredacted body).
        let value =
            send_json_expect_status(ctx.http.post(&url).json(&payload), "iMessage gateway send")
                .await?;

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

    fn expects_webhook_inbound(&self) -> bool {
        true
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        let secret = self.webhook_secret.clone();
        if secret.trim().is_empty() {
            return None;
        }
        // BRG-SEC-002: `unix_timestamp_is_fresh` accepts |now-ts| <= skew, so the
        // acceptance window spans 2*skew (past+future). The replay TTL must cover
        // that full window or a captured delivery could be replayed in the
        // off-window gap.
        let replay = ctx.replay_window(2 * IMESSAGE_DELIVERY_MAX_SKEW);
        Some(
            salvo::Router::with_path("webhooks/imessage")
                .hoop(affix_state::inject(IMessageWebhookState {
                    ctx,
                    secret,
                    replay,
                }))
                .post(imessage_delivery),
        )
    }
}

const IMESSAGE_DELIVERY_MAX_SKEW: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
struct IMessageWebhookState {
    ctx: Arc<MessageContext>,
    secret: String,
    replay: Arc<webhook::ReplayWindow>,
}

#[handler]
async fn imessage_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = webhook::require_state::<IMessageWebhookState>(depot, res) else {
        return;
    };
    // Fail closed: a webhook HMAC secret MUST be configured, and each inbound
    // delivery MUST authenticate the exact raw body bytes plus timestamp.
    if state.secret.trim().is_empty() {
        webhook::unauthorized(res, "iMessage webhook secret not configured");
        return;
    }
    let Some(raw) = webhook::raw_body(req, res).await else {
        return;
    };
    let timestamp = req
        .header::<String>("x-arkret-timestamp")
        .unwrap_or_default();
    if !webhook::unix_timestamp_is_fresh(&timestamp, IMESSAGE_DELIVERY_MAX_SKEW) {
        webhook::unauthorized(res, "iMessage webhook timestamp is stale or invalid");
        return;
    }
    let signature = req
        .header::<String>("x-arkret-signature-256")
        .unwrap_or_default();
    if !webhook::verify_timestamped_hmac_sha256(
        state.secret.as_bytes(),
        &timestamp,
        &raw,
        &signature,
        webhook::SigEncoding::Hex,
    ) {
        webhook::unauthorized(res, "iMessage webhook signature mismatch");
        return;
    }
    if !state
        .replay
        .check_and_record(format!("{timestamp}\u{1f}{signature}"))
        .await
    {
        webhook::unauthorized(res, "iMessage webhook replay");
        return;
    }
    let body = match serde_json::from_slice::<Value>(&raw) {
        Ok(body) => body,
        Err(err) => {
            webhook::bad_request(res, format!("invalid iMessage webhook JSON body: {err}"));
            return;
        }
    };
    let inbound = match imessage_inbound_message(&body) {
        Ok(Some(inbound)) => inbound,
        Ok(None) => {
            if let Ok(Some((channel, user, message_id, media_kind))) =
                imessage_unsupported_media(&body)
            {
                state
                    .ctx
                    .report_unsupported_inbound_media(
                        "imessage", channel, user, message_id, media_kind,
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
    let outcome = webhook::submit(state.ctx.clone(), "imessage", inbound).await;
    webhook::respond_submit(res, outcome);
}

#[derive(Debug, Deserialize)]
struct IMessageWebhookPayload {
    #[serde(default)]
    data: Option<IMessageWebhookData>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    guid: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "chatGuid")]
    chat_guid_camel: Option<String>,
    #[serde(default)]
    chat_guid: Option<String>,
    #[serde(default)]
    chat: Option<IMessageChatRef>,
    #[serde(default)]
    handle: Option<IMessageHandleRef>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    sender: Option<String>,
    #[serde(default)]
    attachment: Option<Value>,
    #[serde(default)]
    attachments: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct IMessageWebhookData {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    guid: Option<String>,
    #[serde(default, rename = "chatGuid")]
    chat_guid_camel: Option<String>,
    #[serde(default)]
    chat_guid: Option<String>,
    #[serde(default)]
    chat: Option<IMessageChatRef>,
    #[serde(default)]
    handle: Option<IMessageHandleRef>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    sender: Option<String>,
    #[serde(default)]
    attachment: Option<Value>,
    #[serde(default)]
    attachments: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct IMessageChatRef {
    #[serde(default)]
    guid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IMessageHandleRef {
    #[serde(default)]
    address: Option<String>,
}

fn imessage_non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

impl IMessageWebhookPayload {
    fn text_body(&self) -> Option<String> {
        self.data
            .as_ref()
            .and_then(|data| imessage_non_empty(data.text.clone()))
            .or_else(|| {
                self.data
                    .as_ref()
                    .and_then(|data| imessage_non_empty(data.message.clone()))
            })
            .or_else(|| imessage_non_empty(self.text.clone()))
            .or_else(|| imessage_non_empty(self.message.clone()))
    }

    fn message_id(&self) -> Option<String> {
        self.data
            .as_ref()
            .and_then(|data| imessage_non_empty(data.guid.clone()))
            .or_else(|| imessage_non_empty(self.guid.clone()))
            .or_else(|| imessage_non_empty(self.id.clone()))
    }

    fn app_channel(&self) -> String {
        self.data
            .as_ref()
            .and_then(|data| imessage_non_empty(data.chat_guid_camel.clone()))
            .or_else(|| {
                self.data
                    .as_ref()
                    .and_then(|data| imessage_non_empty(data.chat_guid.clone()))
            })
            .or_else(|| imessage_non_empty(self.chat_guid_camel.clone()))
            .or_else(|| imessage_non_empty(self.chat_guid.clone()))
            .or_else(|| {
                self.data
                    .as_ref()
                    .and_then(|data| data.chat.as_ref())
                    .and_then(|chat| imessage_non_empty(chat.guid.clone()))
            })
            .or_else(|| {
                self.chat
                    .as_ref()
                    .and_then(|chat| imessage_non_empty(chat.guid.clone()))
            })
            .unwrap_or_default()
    }

    fn app_user(&self) -> String {
        self.data
            .as_ref()
            .and_then(|data| data.handle.as_ref())
            .and_then(|handle| imessage_non_empty(handle.address.clone()))
            .or_else(|| {
                self.handle
                    .as_ref()
                    .and_then(|handle| imessage_non_empty(handle.address.clone()))
            })
            .or_else(|| {
                self.data
                    .as_ref()
                    .and_then(|data| imessage_non_empty(data.from.clone()))
            })
            .or_else(|| {
                self.data
                    .as_ref()
                    .and_then(|data| imessage_non_empty(data.sender.clone()))
            })
            .or_else(|| imessage_non_empty(self.from.clone()))
            .or_else(|| imessage_non_empty(self.sender.clone()))
            .unwrap_or_default()
    }

    fn has_attachment(&self) -> bool {
        fn populated(value: Option<&Value>) -> bool {
            match value {
                Some(Value::Array(items)) => !items.is_empty(),
                Some(Value::Null) | None => false,
                Some(_) => true,
            }
        }

        populated(self.attachment.as_ref())
            || populated(self.attachments.as_ref())
            || self.data.as_ref().is_some_and(|data| {
                populated(data.attachment.as_ref()) || populated(data.attachments.as_ref())
            })
    }

    fn unsupported_media_ref(&self) -> Option<(String, String, String, &'static str)> {
        if self.text_body().is_some() || !self.has_attachment() {
            return None;
        }
        Some((
            self.app_channel(),
            self.app_user(),
            self.message_id()?,
            "attachments",
        ))
    }

    fn into_inbound_message(&self) -> std::result::Result<Option<InboundAppMessage>, &'static str> {
        let Some(text) = self.text_body() else {
            return Ok(None);
        };
        let Some(message_id) = self.message_id() else {
            return Err("iMessage message id missing");
        };
        Ok(Some(InboundAppMessage {
            app_channel: self.app_channel(),
            app_user: self.app_user(),
            app_message_id: message_id,
            body: text,
        }))
    }
}

fn imessage_inbound_message(
    body: &Value,
) -> std::result::Result<Option<InboundAppMessage>, &'static str> {
    serde_json::from_value::<IMessageWebhookPayload>(body.clone())
        .map_err(|_| "invalid iMessage callback shape")?
        .into_inbound_message()
}

fn imessage_unsupported_media(
    body: &Value,
) -> std::result::Result<Option<(String, String, String, &'static str)>, &'static str> {
    Ok(
        serde_json::from_value::<IMessageWebhookPayload>(body.clone())
            .map_err(|_| "invalid iMessage callback shape")?
            .unsupported_media_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imessage_inbound_message_extracts_bluebubbles_shape() {
        let body = json!({
            "data": {
                "text": "hello",
                "guid": "msg-guid",
                "chatGuid": "iMessage;-;+15551234567",
                "handle": {"address": "+15559876543"}
            }
        });
        let inbound = imessage_inbound_message(&body).unwrap().expect("message");
        assert_eq!(inbound.app_channel, "iMessage;-;+15551234567");
        assert_eq!(inbound.app_user, "+15559876543");
        assert_eq!(inbound.app_message_id, "msg-guid");
        assert_eq!(inbound.body, "hello");
    }

    #[test]
    fn imessage_inbound_message_accepts_flat_gateway_shape() {
        let body = json!({
            "message": "hi",
            "id": "flat-id",
            "chat": {"guid": "chat-guid"},
            "sender": "alice"
        });
        let inbound = imessage_inbound_message(&body).unwrap().expect("message");
        assert_eq!(inbound.app_channel, "chat-guid");
        assert_eq!(inbound.app_user, "alice");
        assert_eq!(inbound.app_message_id, "flat-id");
        assert_eq!(inbound.body, "hi");
    }

    #[test]
    fn imessage_unsupported_media_extracts_attachment_shape() {
        let body = json!({
            "data": {
                "guid": "msg-guid",
                "chatGuid": "chat-guid",
                "handle": {"address": "+15559876543"},
                "attachments": [{"guid": "attachment-guid"}]
            }
        });
        let media = imessage_unsupported_media(&body)
            .unwrap()
            .expect("unsupported media");
        assert_eq!(media.0, "chat-guid");
        assert_eq!(media.1, "+15559876543");
        assert_eq!(media.2, "msg-guid");
        assert_eq!(media.3, "attachments");
    }

    #[test]
    fn imessage_inbound_message_skips_empty_text_or_missing_id() {
        assert!(
            imessage_inbound_message(&json!({"data": {"text": "", "guid": "id"}}))
                .unwrap()
                .is_none()
        );
        assert!(imessage_inbound_message(&json!({"data": {"text": "hello"}})).is_err());
    }

    #[test]
    fn imessage_timestamped_signature_binds_body() {
        assert!(webhook::verify_timestamped_hmac_sha256(
            b"secret",
            "1700000000",
            br#"{"hello":"world"}"#,
            "d3d89618b58441bc1f9fbbcaae8435ebd7a6eebbf9fb96c3b87302a69f0d6ed9",
            webhook::SigEncoding::Hex
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
