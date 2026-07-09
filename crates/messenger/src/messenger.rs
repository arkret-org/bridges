//! Messenger adapter (Facebook Graph API, pure reqwest).
//!
//! - Inbound (Messenger -> cokret): Facebook pushes `messages` events via `/webhooks/messenger`.
//! - Outbound (cokret → Messenger): [`MessageBridge::send_to_app`] uses `ctx.http` to POST `https://graph.facebook.com/v20.0/me/messages`
//!   (Bearer page_access_token).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cokret_bridge_messaging::runtime::Result;
use cokret_bridge_messaging::salvo::prelude::*;
use cokret_bridge_messaging::salvo::{self, affix_state};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle, send_json_expect_status, webhook,
};
use serde_json::{Value, json};

/// Messenger bridge adapter.
pub struct MessengerApp {
    /// Page access token (Bearer auth, used for sending).
    page_access_token: String,
    /// Webhook verification token (the value compared against `hub.verify_token`
    /// in the GET verification handshake). Required (parity with WhatsApp): a
    /// missing value would otherwise make the handshake fail at callback time
    /// rather than at startup.
    verify_token: String,
    /// Meta app secret used to verify the `X-Hub-Signature-256` of each POST
    /// delivery (HMAC-SHA256 over the raw request body).
    app_secret: String,
    /// Meta Graph API version segment (e.g. `v20.0`), configurable so an
    /// operator can roll to a newer version without a code release. Mirrors the
    /// WhatsApp bridge (version no longer inlined in the endpoint literal).
    graph_api_version: String,
}

impl MessengerApp {
    pub fn new(
        page_access_token: impl Into<String>,
        verify_token: impl Into<String>,
        app_secret: impl Into<String>,
        graph_api_version: impl Into<String>,
    ) -> Self {
        Self {
            page_access_token: page_access_token.into(),
            verify_token: verify_token.into(),
            app_secret: app_secret.into(),
            graph_api_version: graph_api_version.into(),
        }
    }

    /// The Graph API send endpoint for the configured version.
    fn send_api(&self) -> String {
        format!(
            "https://graph.facebook.com/{}/me/messages",
            self.graph_api_version
        )
    }
}

#[async_trait]
impl MessageBridge for MessengerApp {
    fn name(&self) -> &str {
        "messenger"
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        // app_channel is the PSID (Page-Scoped User ID), used as recipient.id.
        let body = msg.rendered_body(SenderRenderStyle::Plain);
        let payload = json!({
            "recipient": { "id": msg.app_channel },
            "messaging_type": "RESPONSE",
            "message": { "text": body },
        });

        let value = send_json_expect_status(
            ctx.http
                .post(self.send_api())
                .bearer_auth(&self.page_access_token)
                .json(&payload),
            "Messenger send",
        )
        .await?;

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

    fn expects_webhook_inbound(&self) -> bool {
        true
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        if self.verify_token.trim().is_empty() || self.app_secret.trim().is_empty() {
            return None;
        }
        let replay = ctx.replay_window(MESSENGER_REPLAY_TTL);
        Some(
            salvo::Router::with_path("webhooks/messenger")
                .hoop(affix_state::inject(MessengerWebhookState {
                    app: self,
                    ctx,
                    replay,
                }))
                .get(messenger_verify)
                .post(messenger_delivery),
        )
    }
}

/// In-handler bounded replay window for Messenger. The Meta signature
/// (`HMAC-SHA256(app_secret, raw_body)`) covers the body but carries no
/// timestamp/nonce, so a captured `(body, signature)` pair would otherwise
/// verify forever; the bridge contract (G-4) mandates a bounded replay/dedupe
/// guard keyed on the stable platform message id. The TTL covers Meta's
/// redelivery window with margin.
const MESSENGER_REPLAY_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone)]
struct MessengerWebhookState {
    app: Arc<MessengerApp>,
    ctx: Arc<MessageContext>,
    /// Bounded replay guard keyed on the platform `message.mid`; a captured,
    /// validly signed event is accepted at most once inside the window.
    replay: Arc<webhook::ReplayWindow>,
}

#[handler]
async fn messenger_verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<MessengerWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    webhook::meta_hub_verify(req, res, &state.app.verify_token);
}

#[handler]
async fn messenger_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<MessengerWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let Some((_raw, body)) = webhook::meta_signed_json_body(req, res, &state.app.app_secret).await
    else {
        return;
    };

    // Respond 5xx if any message hit a transient failure so Meta redelivers the
    // batch; inbound dedup keeps the replay idempotent.
    let mut retry = false;
    for inbound in messenger_inbound_messages(&body) {
        // Bounded replay/dedupe (BRG-SEC-001 / contract G-4): the Meta signature
        // does not bind a timestamp, so a captured event would replay forever.
        let replay_key = format!("messenger:{}", inbound.app_message_id);
        let outcome = webhook::submit_deduped(
            state.ctx.clone(),
            "messenger",
            &state.replay,
            replay_key,
            inbound,
        )
        .await;
        retry |= outcome == webhook::SubmitOutcome::Retry;
    }
    for (channel, user, message_id, media_kind) in messenger_unsupported_media(&body) {
        let replay_key = format!("messenger:media:{message_id}");
        if state.replay.check_and_record(replay_key).await {
            state
                .ctx
                .report_unsupported_inbound_media(
                    "messenger",
                    channel,
                    user,
                    message_id,
                    media_kind,
                )
                .await;
        }
    }
    if retry {
        webhook::submission_retry(res);
    } else {
        webhook::ok_json(res, json!({ "ok": true }));
    }
}

fn messenger_inbound_messages(body: &Value) -> Vec<InboundAppMessage> {
    let mut out = Vec::new();
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
            if event
                .pointer("/message/is_echo")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            let Some(text) = webhook::str_at(event, "/message/text") else {
                continue;
            };
            let user = webhook::string_at(event, "/sender/id").unwrap_or_default();
            let Some(message_id) = webhook::non_empty_string_at(event, "/message/mid") else {
                tracing::warn!("Messenger event missing message.mid; skipping");
                continue;
            };
            out.push(InboundAppMessage {
                app_channel: user.clone(),
                app_user: user,
                app_message_id: message_id,
                body: text.to_owned(),
            });
        }
    }
    out
}

fn messenger_unsupported_media(body: &Value) -> Vec<(String, String, String, &'static str)> {
    let mut out = Vec::new();
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
            if event
                .pointer("/message/is_echo")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            let has_attachments = event
                .pointer("/message/attachments")
                .and_then(Value::as_array)
                .is_some_and(|attachments| !attachments.is_empty());
            if !has_attachments {
                continue;
            }
            let Some(message_id) = webhook::non_empty_string_at(event, "/message/mid") else {
                tracing::warn!("Messenger media event missing message.mid; skipping audit");
                continue;
            };
            let user = webhook::string_at(event, "/sender/id").unwrap_or_default();
            out.push((user.clone(), user, message_id, "attachments"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messenger_inbound_messages_extracts_text_events() {
        let body = json!({
            "entry": [{
                "messaging": [{
                    "sender": {"id": "PSID1"},
                    "message": {"mid": "m_1", "text": "hi"}
                }]
            }]
        });
        let messages = messenger_inbound_messages(&body);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].app_channel, "PSID1");
        assert_eq!(messages[0].app_user, "PSID1");
        assert_eq!(messages[0].app_message_id, "m_1");
        assert_eq!(messages[0].body, "hi");
    }

    #[test]
    fn messenger_inbound_messages_skips_non_text_and_missing_ids() {
        let body = json!({
            "entry": [{
                "messaging": [
                    {"sender": {"id": "PSID1"}, "message": {"attachments": []}},
                    {"sender": {"id": "PSID2"}, "message": {"text": "no id"}}
                ]
            }]
        });
        assert!(messenger_inbound_messages(&body).is_empty());
    }

    #[test]
    fn messenger_inbound_messages_skips_echo_events() {
        let body = json!({
            "entry": [{
                "messaging": [{
                    "sender": {"id": "PAGE_ID"},
                    "message": {"mid": "m_echo", "text": "sent by the page", "is_echo": true}
                }]
            }]
        });

        assert!(messenger_inbound_messages(&body).is_empty());
    }

    #[test]
    fn messenger_unsupported_media_extracts_attachment_events() {
        let body = json!({
            "entry": [{
                "messaging": [{
                    "sender": {"id": "PSID1"},
                    "message": {"mid": "m_1", "attachments": [{"type": "image"}]}
                }]
            }]
        });
        let media = messenger_unsupported_media(&body);
        assert_eq!(
            media,
            vec![("PSID1".into(), "PSID1".into(), "m_1".into(), "attachments")]
        );
    }
}
