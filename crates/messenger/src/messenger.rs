//! Messenger adapter (Facebook Graph API, pure reqwest).
//!
//! - Inbound (Messenger -> arkret): Facebook pushes `messages` events via `/webhooks/messenger`.
//! - Outbound (arkret → Messenger): [`MessageBridge::send_to_app`] uses `ctx.http` to POST `https://graph.facebook.com/v20.0/me/messages`
//!   (Bearer page_access_token).

use std::sync::Arc;
use std::time::Duration;

use arkret_bridge_messaging::runtime::Result;
use arkret_bridge_messaging::salvo::prelude::*;
use arkret_bridge_messaging::salvo::{self, affix_state};
use arkret_bridge_messaging::{
    AppMessageRef, ExternalMediaRequest, InboundAppMessage, MessageBridge, MessageContext,
    OutboundAppMessage, SenderRenderStyle, send_json_expect_status, webhook,
};
use async_trait::async_trait;
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
    let Some(state) = webhook::require_state::<MessengerWebhookState>(depot, res) else {
        return;
    };
    webhook::meta_hub_verify(req, res, &state.app.verify_token);
}

#[handler]
async fn messenger_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = webhook::require_state::<MessengerWebhookState>(depot, res) else {
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
    for media in messenger_media(&body) {
        let replay_key = format!("messenger:media:{}", media.message_id);
        match state.replay.check_and_record(replay_key.clone()).await {
            Ok(webhook::ReplayGuardVerdict::Fresh) => {}
            Ok(webhook::ReplayGuardVerdict::Replay) => continue,
            Err(error) => {
                tracing::error!(%error, "Messenger replay guard storage unavailable");
                retry = true;
                continue;
            }
        }
        let inbound = InboundAppMessage {
            app_channel: media.channel,
            app_user: media.user,
            app_message_id: media.message_id.clone(),
            body: String::new(),
        };
        if let Err(error) = state
            .ctx
            .forward_external_media(
                "messenger",
                inbound,
                ExternalMediaRequest {
                    url: &media.url,
                    authorization: None,
                    allowed_hosts: &["fbcdn.net", "fbsbx.com"],
                    mime_hint: media.mime,
                    filename: media.filename,
                },
            )
            .await
            && error.is_retriable()
        {
            retry = true;
            state.replay.forget(replay_key).await;
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

#[derive(Debug, Eq, PartialEq)]
struct MessengerMedia {
    channel: String,
    user: String,
    message_id: String,
    url: String,
    mime: Option<String>,
    filename: Option<String>,
}

fn messenger_media(body: &Value) -> Vec<MessengerMedia> {
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
            let Some(attachments) = event
                .pointer("/message/attachments")
                .and_then(Value::as_array)
            else {
                continue;
            };
            let Some(message_id) = webhook::non_empty_string_at(event, "/message/mid") else {
                tracing::warn!("Messenger media event missing message.mid; skipping audit");
                continue;
            };
            let user = webhook::string_at(event, "/sender/id").unwrap_or_default();
            for (index, attachment) in attachments.iter().enumerate() {
                let Some(url) = webhook::non_empty_string_at(attachment, "/payload/url") else {
                    continue;
                };
                let kind = webhook::string_at(attachment, "/type").unwrap_or_default();
                out.push(MessengerMedia {
                    channel: user.clone(),
                    user: user.clone(),
                    message_id: format!("{message_id}:{index}"),
                    url,
                    mime: messenger_attachment_mime(&kind),
                    filename: None,
                });
            }
        }
    }
    out
}

fn messenger_attachment_mime(kind: &str) -> Option<String> {
    match kind {
        "image" => Some("image/jpeg".to_owned()),
        "audio" => Some("audio/mpeg".to_owned()),
        "video" => Some("video/mp4".to_owned()),
        _ => None,
    }
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
    fn messenger_media_extracts_downloadable_attachment_events() {
        let body = json!({
            "entry": [{
                "messaging": [{
                    "sender": {"id": "PSID1"},
                    "message": {"mid": "m_1", "attachments": [{
                        "type": "image",
                        "payload": {"url": "https://lookaside.fbsbx.com/image.jpg"}
                    }]}
                }]
            }]
        });
        let media = messenger_media(&body);
        assert_eq!(
            media,
            vec![MessengerMedia {
                channel: "PSID1".into(),
                user: "PSID1".into(),
                message_id: "m_1:0".into(),
                url: "https://lookaside.fbsbx.com/image.jpg".into(),
                mime: Some("image/jpeg".into()),
                filename: None,
            }]
        );
    }
}
