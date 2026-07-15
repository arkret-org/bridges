//! Slack adapter (socket mode + Web API).
//!
//! - Inbound (Slack → arkret): a socket mode WebSocket long-lived read loop parses `message` events
//!   and then calls [`MessageContext::submit_app_message`].
//! - Outbound (arkret → Slack): [`MessageBridge::send_to_app`] uses `ctx.http` to POST `https://slack.com/api/chat.postMessage`.
//!
//! Socket mode connection strand: first POST `app_token` (`xapp-`) to
//! `https://slack.com/api/apps.connections.open` to obtain a one-time wss URL, then
//! connect via tokio-tungstenite; after the server pushes an envelope, reply with a
//! `{"envelope_id":..}` ack.

use std::sync::Arc;

use arkret_bridge_messaging::runtime::{BridgeError, Result, jittered_delay};
use arkret_bridge_messaging::{
    AppMessageRef, ExternalMediaRequest, InboundAppMessage, InboundMediaAuthorization,
    MessageBridge, MessageContext, OutboundAppMessage, SenderRenderStyle, send_json_expect,
};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message as WsMessage;

const APPS_CONNECTIONS_OPEN: &str = "https://slack.com/api/apps.connections.open";
const CHAT_POST_MESSAGE: &str = "https://slack.com/api/chat.postMessage";

/// Idle read window before the socket-mode loop probes the connection with a
/// keep-alive Ping. Slack pings clients roughly every ~30s; this is longer so a
/// healthy connection never trips it, while a wedged (TCP half-open) connection
/// is detected within two windows instead of blocking forever.
const SOCKET_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Base reconnect delay after a failed connect / URL fetch.
const RECONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(30);
/// Base delay after a clean disconnect before reconnecting.
const DISCONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);

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
        let resp = send_json_expect(
            ctx.http
                .post(APPS_CONNECTIONS_OPEN)
                .bearer_auth(&self.app_token),
            "Slack apps.connections.open",
            slack_ok,
        )
        .await?;
        resp.get("url")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| BridgeError::App("Slack apps.connections.open is missing url".into()))
    }

    /// Handle a single socket mode envelope. Returns whether the envelope may be
    /// acked back to Slack. Retriable submit failures deliberately withhold the
    /// ack so Slack redelivers the envelope instead of silently dropping it.
    async fn handle_envelope(&self, ctx: &Arc<MessageContext>, envelope: &Value) -> bool {
        // Only care about the events_api type whose inner event is a message.
        let event = envelope.pointer("/payload/event");
        let Some(event) = event else { return true };
        let media = slack_media(event);
        if !media.is_empty() {
            let mut accepted = true;
            for item in media {
                let inbound = InboundAppMessage {
                    app_channel: item.channel,
                    app_user: item.user,
                    app_message_id: item.id,
                    body: item.caption,
                };
                if let Err(error) = ctx
                    .forward_external_media(
                        "slack",
                        inbound,
                        ExternalMediaRequest {
                            url: &item.url,
                            authorization: Some(InboundMediaAuthorization::Bearer(
                                self.bot_token.clone(),
                            )),
                            allowed_hosts: &["files.slack.com"],
                            mime_hint: item.mime,
                            filename: item.filename,
                        },
                    )
                    .await
                {
                    accepted &= !error.is_retriable();
                }
            }
            return accepted;
        }
        let Some(inbound) = slack_inbound_message(event) else {
            return true;
        };
        if let Err(e) = ctx.submit_app_message(inbound.clone()).await {
            let retriable = ctx.report_inbound_failure("slack", &inbound, &e).await;
            return !retriable;
        }
        true
    }
}

/// Slack Web API success flag: top-level `ok == true`.
fn slack_ok(resp: &Value) -> bool {
    resp.get("ok").and_then(Value::as_bool) == Some(true)
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

struct SlackMedia {
    channel: String,
    user: String,
    id: String,
    caption: String,
    url: String,
    mime: Option<String>,
    filename: Option<String>,
}

fn slack_media(event: &Value) -> Vec<SlackMedia> {
    if event.get("type").and_then(Value::as_str) != Some("message") {
        return Vec::new();
    }
    // Ignore the bot itself and subtype messages (edits, joins, etc.) to avoid loops.
    if event.get("bot_id").is_some() || event.get("subtype").is_some() {
        return Vec::new();
    }
    let Some(files) = event.get("files").and_then(Value::as_array) else {
        return Vec::new();
    };
    let Some(channel) = event.get("channel").and_then(Value::as_str) else {
        return Vec::new();
    };
    let user = event
        .get("user")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let caption = event
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default();
    files
        .iter()
        .filter_map(|file| {
            Some(SlackMedia {
                channel: channel.to_owned(),
                user: user.to_owned(),
                id: file.get("id")?.as_str()?.to_owned(),
                caption: caption.to_owned(),
                url: file.get("url_private_download")?.as_str()?.to_owned(),
                mime: file
                    .get("mimetype")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                filename: file.get("name").and_then(Value::as_str).map(str::to_owned),
            })
        })
        .collect()
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

    #[test]
    fn slack_media_extracts_downloadable_file_event() {
        let event = json!({
            "type": "message",
            "channel": "C123",
            "user": "U456",
            "ts": "1700000000.123",
            "text": "caption",
            "files": [{
                "id": "F1",
                "name": "report.pdf",
                "mimetype": "application/pdf",
                "url_private_download": "https://files.slack.com/files-pri/T-F/report.pdf"
            }]
        });
        let media = slack_media(&event);
        assert_eq!(media.len(), 1);
        assert_eq!(media[0].channel, "C123");
        assert_eq!(media[0].user, "U456");
        assert_eq!(media[0].id, "F1");
        assert_eq!(media[0].caption, "caption");
        assert_eq!(media[0].mime.as_deref(), Some("application/pdf"));
        assert_eq!(media[0].filename.as_deref(), Some("report.pdf"));
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
                    tracing::warn!(error = %e, "failed to fetch Slack socket URL, retrying");
                    tokio::time::sleep(jittered_delay(RECONNECT_BACKOFF)).await;
                    continue;
                }
            };

            let (ws, _) = match tokio_tungstenite::connect_async(&url).await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(error = %e, "Slack socket connection failed, retrying");
                    tokio::time::sleep(jittered_delay(RECONNECT_BACKOFF)).await;
                    continue;
                }
            };
            tracing::info!("Slack socket mode connected");

            let (mut write, mut read) = ws.split();
            // Half-open detection: bound each read with a timeout. On the first
            // idle window send a keep-alive Ping; a second consecutive idle
            // window with no frame at all (the Pong never came) means the TCP
            // connection is wedged, so reconnect instead of blocking forever.
            let mut awaiting_pong = false;
            loop {
                let frame = match tokio::time::timeout(SOCKET_READ_TIMEOUT, read.next()).await {
                    Ok(Some(Ok(frame))) => frame,
                    Ok(Some(Err(e))) => {
                        tracing::warn!(error = %e, "Slack socket read error, reconnecting");
                        break;
                    }
                    Ok(None) => {
                        tracing::warn!("Slack socket stream ended, reconnecting");
                        break;
                    }
                    Err(_) => {
                        if awaiting_pong {
                            tracing::warn!(
                                "Slack socket idle past heartbeat with no response, reconnecting"
                            );
                            break;
                        }
                        awaiting_pong = true;
                        if let Err(e) = write.send(WsMessage::Ping(Vec::<u8>::new().into())).await {
                            tracing::warn!(error = %e, "Slack socket ping failed, reconnecting");
                            break;
                        }
                        continue;
                    }
                };
                // Any inbound frame proves the connection is live.
                awaiting_pong = false;
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
                        self.handle_envelope(&ctx, &envelope).await
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

            tracing::warn!("Slack socket disconnected, reconnecting shortly");
            tokio::time::sleep(jittered_delay(DISCONNECT_BACKOFF)).await;
        }
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let body = msg.rendered_body(SenderRenderStyle::SingleAsterisk);
        let payload = json!({
            "channel": msg.app_channel,
            "text": body,
        });
        let resp = send_json_expect(
            ctx.http
                .post(CHAT_POST_MESSAGE)
                .bearer_auth(&self.bot_token)
                .json(&payload),
            "Slack chat.postMessage",
            slack_ok,
        )
        .await?;
        // The returned ts serves as the app-side message identifier.
        let ts = resp
            .get("ts")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Ok(AppMessageRef { app_message_id: ts })
    }
}
