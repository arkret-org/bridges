//! Slack adapter (socket mode + Web API).
//!
//! - Inbound (Slack → cokret): a socket mode WebSocket long-lived read loop parses `message` events
//!   and then calls [`MessageContext::submit_app_message`].
//! - Outbound (cokret → Slack): [`MessageBridge::send_to_app`] uses `ctx.http` to POST `https://slack.com/api/chat.postMessage`.
//!
//! Socket mode connection strand: first POST `app_token` (`xapp-`) to
//! `https://slack.com/api/apps.connections.open` to obtain a one-time wss URL, then
//! connect via tokio-tungstenite; after the server pushes an envelope, reply with a
//! `{"envelope_id":..}` ack.

use std::sync::Arc;

use async_trait::async_trait;
use cokret_bridge_messaging::runtime::{BridgeError, Result, redact_sensitive_url_values};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle,
};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message as WsMessage;

const APPS_CONNECTIONS_OPEN: &str = "https://slack.com/api/apps.connections.open";
const CHAT_POST_MESSAGE: &str = "https://slack.com/api/chat.postMessage";

/// Slack bridge adapter.
pub struct SlackApp {
    /// `xoxb-` Web API token.
    bot_token: String,
    /// `xapp-` socket mode token.
    app_token: String,
}

impl SlackApp {
    pub fn new(bot_token: impl Into<String>, app_token: impl Into<String>) -> Self {
        Self {
            bot_token: bot_token.into(),
            app_token: app_token.into(),
        }
    }

    /// Call `apps.connections.open` to obtain a one-time socket mode wss URL.
    async fn open_socket_url(&self, ctx: &MessageContext) -> Result<String> {
        let resp: Value = ctx
            .http
            .post(APPS_CONNECTIONS_OPEN)
            .bearer_auth(&self.app_token)
            .send()
            .await
            .map_err(|e| {
                BridgeError::App(format!(
                    "Slack apps.connections.open request failed: {}",
                    redact_sensitive_url_values(e.to_string())
                ))
            })?
            .json()
            .await
            .map_err(|e| {
                BridgeError::App(format!(
                    "Slack apps.connections.open parse failed: {}",
                    redact_sensitive_url_values(e.to_string())
                ))
            })?;

        if resp.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(BridgeError::App(format!(
                "Slack apps.connections.open returned an error: {}",
                redact_sensitive_url_values(resp.to_string())
            )));
        }
        resp.get("url")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| BridgeError::App("Slack apps.connections.open is missing url".into()))
    }

    /// Handle a single socket mode envelope. Returns whether the envelope may be
    /// acked back to Slack. Retriable submit failures deliberately withhold the
    /// ack so Slack redelivers the envelope instead of silently dropping it.
    async fn handle_envelope(ctx: &Arc<MessageContext>, envelope: &Value) -> bool {
        // Only care about the events_api type whose inner event is a message.
        let event = envelope.pointer("/payload/event");
        let Some(event) = event else { return true };
        let Some(inbound) = slack_inbound_message(event) else {
            return true;
        };
        if let Err(e) = ctx.submit_app_message(inbound.clone()).await {
            let retriable = e.is_retriable();
            tracing::warn!(error = %e, retriable, "Slack → cokret submission failed");
            ctx.report_inbound_bridge_error(&inbound, &e, retriable)
                .await;
            return !retriable;
        }
        true
    }
}

fn slack_inbound_message(event: &Value) -> Option<InboundAppMessage> {
    if event.get("type").and_then(Value::as_str) != Some("message") {
        return None;
    }
    // Ignore the bot itself and subtype messages (edits, joins, etc.) to avoid loops.
    if event.get("bot_id").is_some() || event.get("subtype").is_some() {
        return None;
    }
    let channel = event.get("channel").and_then(Value::as_str)?;
    let text = event.get("text").and_then(Value::as_str)?;
    let user = event
        .get("user")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let ts = event.get("ts").and_then(Value::as_str).unwrap_or_default();
    Some(InboundAppMessage {
        app_channel: channel.to_owned(),
        app_user: user.to_owned(),
        app_message_id: ts.to_owned(),
        body: text.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slack_inbound_message_extracts_text_event() {
        let event = json!({
            "type": "message",
            "channel": "C123",
            "user": "U456",
            "text": "hello",
            "ts": "1700000000.123"
        });
        let inbound = slack_inbound_message(&event).expect("message");
        assert_eq!(inbound.app_channel, "C123");
        assert_eq!(inbound.app_user, "U456");
        assert_eq!(inbound.app_message_id, "1700000000.123");
        assert_eq!(inbound.body, "hello");
    }

    #[test]
    fn slack_inbound_message_ignores_bot_and_subtype_events() {
        assert!(
            slack_inbound_message(&json!({
                "type": "message",
                "bot_id": "B1",
                "channel": "C123",
                "text": "loop"
            }))
            .is_none()
        );
        assert!(
            slack_inbound_message(&json!({
                "type": "message",
                "subtype": "message_changed",
                "channel": "C123",
                "text": "edited"
            }))
            .is_none()
        );
        assert!(
            slack_inbound_message(&json!({
                "type": "reaction_added",
                "channel": "C123",
                "text": "ignored"
            }))
            .is_none()
        );
    }
}

#[async_trait]
impl MessageBridge for SlackApp {
    fn name(&self) -> &str {
        "slack"
    }

    async fn run(self: Arc<Self>, ctx: Arc<MessageContext>) -> Result<()> {
        // Reconnect loop: obtain a fresh wss URL and reconnect each time.
        loop {
            let url = match self.open_socket_url(&ctx).await {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to fetch Slack socket URL, retrying in 30s");
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    continue;
                }
            };

            let (ws, _) = match tokio_tungstenite::connect_async(&url).await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "Slack socket connection failed, retrying in 30s");
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    continue;
                }
            };
            tracing::info!("Slack socket mode connected");

            let (mut write, mut read) = ws.split();
            while let Some(frame) = read.next().await {
                let frame = match frame {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(error = %e, "Slack socket read error, reconnecting");
                        break;
                    }
                };
                let WsMessage::Text(txt) = frame else {
                    continue;
                };
                let Ok(envelope) = serde_json::from_str::<Value>(&txt) else {
                    continue;
                };

                // Handle events_api pushes before acking. For retriable submit
                // failures we withhold the ack, letting Slack redeliver.
                let should_ack =
                    if envelope.get("type").and_then(Value::as_str) == Some("events_api") {
                        Self::handle_envelope(&ctx, &envelope).await
                    } else {
                        true
                    };

                // Socket mode requires an ack for every accepted envelope that
                // carries an envelope_id.
                if should_ack
                    && let Some(envelope_id) = envelope.get("envelope_id").and_then(Value::as_str)
                {
                    let ack = json!({ "envelope_id": envelope_id }).to_string();
                    if let Err(e) = write.send(WsMessage::text(ack)).await {
                        tracing::warn!(error = %e, "Slack socket ack failed, reconnecting");
                        break;
                    }
                }
            }

            tracing::warn!("Slack socket disconnected, reconnecting in 5s");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let body = msg.rendered_body(SenderRenderStyle::MarkdownItalic);
        let payload = json!({
            "channel": msg.app_channel,
            "text": body,
        });
        let resp: Value = ctx
            .http
            .post(CHAT_POST_MESSAGE)
            .bearer_auth(&self.bot_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                BridgeError::App(format!(
                    "Slack chat.postMessage request failed: {}",
                    redact_sensitive_url_values(e.to_string())
                ))
            })?
            .json()
            .await
            .map_err(|e| {
                BridgeError::App(format!(
                    "Slack chat.postMessage parse failed: {}",
                    redact_sensitive_url_values(e.to_string())
                ))
            })?;

        if resp.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(BridgeError::App(format!(
                "Slack chat.postMessage returned an error: {}",
                redact_sensitive_url_values(resp.to_string())
            )));
        }
        // The returned ts serves as the app-side message identifier.
        let ts = resp
            .get("ts")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Ok(AppMessageRef { app_message_id: ts })
    }
}
