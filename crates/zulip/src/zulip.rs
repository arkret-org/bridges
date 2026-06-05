//! Zulip adapter (event queue long-polling).
//!
//! - Inbound (Zulip -> cokret): `run` uses reqwest to call Zulip `register` to
//!   create an event queue, then loops `GET /api/v1/events` long-polling to pull
//!   new messages -> [`MessageContext::submit_app_message`].
//! - Outbound (cokret -> Zulip): [`MessageBridge::send_to_app`] uses `ctx.http` to POST
//!   `{site}/api/v1/messages` (HTTP basic auth: bot_email + api_key).
//!
//! Note: tokio-tungstenite is already listed as a dependency (Zulip may later switch
//! to ws push); the current receive path goes through the official event queue
//! long-polling REST interface, which better fits Zulip's actual capabilities.

use std::sync::Arc;

use async_trait::async_trait;
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
};
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::Value;

/// Zulip bridge adapter.
pub struct ZulipApp {
    /// Zulip site base URL, e.g. `https://your-org.zulipchat.com` (trailing slash stripped).
    site: String,
    bot_email: String,
    api_key: String,
}

impl ZulipApp {
    pub fn new(
        site: impl Into<String>,
        bot_email: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        Self {
            site: site.into(),
            bot_email: bot_email.into(),
            api_key: api_key.into(),
        }
    }

    /// Registers an event queue, returning `(queue_id, last_event_id)`.
    async fn register(&self, ctx: &Arc<MessageContext>) -> Result<(String, i64)> {
        let url = format!("{}/api/v1/register", self.site);
        // Subscribe only to message events.
        let resp = ctx
            .http
            .post(&url)
            .basic_auth(&self.bot_email, Some(&self.api_key))
            .form(&[("event_types", "[\"message\"]")])
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("Zulip register request failed: {e}")))?;

        let body: Value = resp
            .json()
            .await
            .map_err(|e| BridgeError::App(format!("Zulip register parse failed: {e}")))?;

        let queue_id = body
            .get("queue_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| BridgeError::App(format!("Zulip register has no queue_id: {body}")))?
            .to_owned();
        let last_event_id = body
            .get("last_event_id")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);
        Ok((queue_id, last_event_id))
    }
}

#[async_trait]
impl MessageBridge for ZulipApp {
    fn name(&self) -> &str {
        "zulip"
    }

    async fn run(self: Arc<Self>, ctx: Arc<MessageContext>) -> Result<()> {
        let events_url = format!("{}/api/v1/events", self.site);
        loop {
            let (queue_id, mut last_event_id) = match self.register(&ctx).await {
                Ok(queue) => queue,
                Err(e) => {
                    tracing::warn!(error = %e, "Zulip queue registration failed, retrying");
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                    continue;
                }
            };
            tracing::info!(queue = %queue_id, "Zulip event queue registered, starting long-polling");

            loop {
                // Long-polling: dont_block=false -> the server blocks until a new event arrives or it times out.
                let resp = ctx
                    .http
                    .get(&events_url)
                    .basic_auth(&self.bot_email, Some(&self.api_key))
                    .query(&[
                        ("queue_id", queue_id.as_str()),
                        ("last_event_id", &last_event_id.to_string()),
                    ])
                    .send()
                    .await;

                let body: Value = match resp {
                    Ok(r) => match r.json().await {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(error = %e, "Zulip events parse failed, retrying later");
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            continue;
                        }
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "Zulip events request failed, retrying later");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        continue;
                    }
                };

                if body.get("result").and_then(|v| v.as_str()) == Some("error")
                    && body.get("code").and_then(|v| v.as_str()) == Some("BAD_EVENT_QUEUE_ID")
                {
                    tracing::warn!("Zulip event queue expired, re-registering");
                    break;
                }

                let Some(events) = body.get("events").and_then(|v| v.as_array()) else {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                };

                for ev in events {
                    if let Some(id) = ev.get("id").and_then(|v| v.as_i64()) {
                        last_event_id = last_event_id.max(id);
                    }
                    if ev.get("type").and_then(|v| v.as_str()) != Some("message") {
                        continue;
                    }
                    let Some(message) = ev.get("message") else {
                        continue;
                    };

                    // Skip messages sent by ourselves (the bot) to avoid loops.
                    let sender_email = message
                        .get("sender_email")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    if sender_email.eq_ignore_ascii_case(&self.bot_email) {
                        continue;
                    }

                    // Stream channels are keyed as "<stream_id>/<topic>" so outbound can preserve the topic.
                    let app_channel = match message.get("type").and_then(|v| v.as_str()) {
                        Some("stream") => {
                            let stream_id = message
                                .get("stream_id")
                                .and_then(|v| v.as_i64())
                                .unwrap_or_default();
                            let topic = message
                                .get("subject")
                                .or_else(|| message.get("topic"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("cokret");
                            format!("{stream_id}/{topic}")
                        }
                        _ => format!(
                            "pm/{}",
                            message
                                .get("sender_id")
                                .and_then(|v| v.as_i64())
                                .unwrap_or_default()
                        ),
                    };

                    let Some(app_message_id) = message
                        .get("id")
                        .and_then(|v| v.as_i64())
                        .map(|n| n.to_string())
                    else {
                        tracing::warn!("Zulip message missing id; skipping");
                        continue;
                    };
                    let inbound = InboundAppMessage {
                        app_channel,
                        app_user: message
                            .get("sender_id")
                            .and_then(|v| v.as_i64())
                            .map(|n| n.to_string())
                            .unwrap_or_default(),
                        app_message_id,
                        body: message
                            .get("content")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_owned(),
                    };
                    if let Err(e) = ctx.submit_app_message(inbound).await {
                        tracing::warn!(error = %e, "Zulip -> cokret submit failed");
                    }
                }
            }
        }
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let url = format!("{}/api/v1/messages", self.site);
        let body = format!("**{}**: {}", msg.sender_display, msg.body);

        // An app_channel shaped like "pm/<id>" is treated as a direct message.
        // Stream channels use "<stream_id>/<topic>".
        let mut form: Vec<(&str, String)> = Vec::new();
        if let Some(rest) = msg.app_channel.strip_prefix("pm/") {
            form.push(("type", "private".to_owned()));
            form.push(("to", format!("[{rest}]")));
        } else {
            let (stream, topic) = msg
                .app_channel
                .split_once('/')
                .unwrap_or((msg.app_channel.as_str(), "cokret"));
            form.push(("type", "stream".to_owned()));
            form.push(("to", stream.to_owned()));
            form.push(("topic", topic.to_owned()));
        }
        form.push(("content", body));

        let resp = ctx
            .http
            .post(&url)
            .basic_auth(&self.bot_email, Some(&self.api_key))
            .form(&form)
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("Zulip send failed: {e}")))?;

        let payload: Value = resp
            .json()
            .await
            .map_err(|e| BridgeError::App(format!("Zulip send response parse failed: {e}")))?;

        if payload.get("result").and_then(|v| v.as_str()) != Some("success") {
            return Err(BridgeError::App(format!(
                "Zulip send returned an error: {payload}"
            )));
        }
        let id = payload
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|n| n.to_string())
            .unwrap_or_default();
        Ok(AppMessageRef { app_message_id: id })
    }
}
