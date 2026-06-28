//! Zulip adapter (event queue long-polling).
//!
//! - Inbound (Zulip -> cokret): `run` uses reqwest to call Zulip `register` to create an event
//!   queue, then loops `GET /api/v1/events` long-polling to pull new messages ->
//!   [`MessageContext::submit_app_message`].
//! - Outbound (cokret -> Zulip): [`MessageBridge::send_to_app`] uses `ctx.http` to POST
//!   `{site}/api/v1/messages` (HTTP basic auth: bot_email + api_key).
//!
//! The receive path uses Zulip's official event queue long-polling REST
//! interface.

use std::sync::Arc;

use async_trait::async_trait;
use cokret_bridge_messaging::runtime::{BridgeError, Result, redact_sensitive_url_values};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle,
};
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
            .map_err(|e| {
                BridgeError::App(format!(
                    "Zulip register request failed: {}",
                    redact_sensitive_url_values(e.to_string())
                ))
            })?;

        let body: Value = resp
            .json()
            .await
            .map_err(|e| {
                BridgeError::App(format!(
                    "Zulip register parse failed: {}",
                    redact_sensitive_url_values(e.to_string())
                ))
            })?;

        let queue_id = body
            .get("queue_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BridgeError::App(format!(
                    "Zulip register has no queue_id: {}",
                    redact_sensitive_url_values(body.to_string())
                ))
            })?
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
                // Long-polling: dont_block=false -> the server blocks until a new event arrives or
                // it times out.
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

                let mut retry_poll = false;
                for ev in events {
                    let event_id = ev.get("id").and_then(|v| v.as_i64());
                    if ev.get("type").and_then(|v| v.as_str()) != Some("message") {
                        if let Some(id) = event_id {
                            last_event_id = last_event_id.max(id);
                        }
                        continue;
                    }
                    let Some(message) = ev.get("message") else {
                        if let Some(id) = event_id {
                            last_event_id = last_event_id.max(id);
                        }
                        continue;
                    };

                    // Skip messages sent by ourselves (the bot) to avoid loops.
                    let sender_email = message
                        .get("sender_email")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    if sender_email.eq_ignore_ascii_case(&self.bot_email) {
                        if let Some(id) = event_id {
                            last_event_id = last_event_id.max(id);
                        }
                        continue;
                    }

                    let app_channel = zulip_app_channel(message);

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
                    match ctx.submit_app_message(inbound.clone()).await {
                        Ok(_) => {
                            if let Some(id) = event_id {
                                last_event_id = last_event_id.max(id);
                            }
                        }
                        Err(e) => {
                            let retriable = e.is_retriable();
                            tracing::warn!(error = %e, retriable, "Zulip -> cokret submit failed");
                            ctx.report_inbound_bridge_error(&inbound, &e, retriable)
                                .await;
                            if retriable {
                                retry_poll = true;
                                break;
                            }
                            if let Some(id) = event_id {
                                last_event_id = last_event_id.max(id);
                            }
                        }
                    }
                }
                if retry_poll {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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
        let body = msg.rendered_body(SenderRenderStyle::MarkdownBold);

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
            .map_err(|e| {
                BridgeError::App(format!(
                    "Zulip send failed: {}",
                    redact_sensitive_url_values(e.to_string())
                ))
            })?;

        let payload: Value = resp
            .json()
            .await
            .map_err(|e| {
                BridgeError::App(format!(
                    "Zulip send response parse failed: {}",
                    redact_sensitive_url_values(e.to_string())
                ))
            })?;

        if payload.get("result").and_then(|v| v.as_str()) != Some("success") {
            return Err(BridgeError::App(format!(
                "Zulip send returned an error: {}",
                redact_sensitive_url_values(payload.to_string())
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

fn zulip_app_channel(message: &Value) -> String {
    if message.get("type").and_then(|v| v.as_str()) == Some("stream") {
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
    } else {
        format!(
            "pm/{}",
            message
                .get("sender_id")
                .and_then(|v| v.as_i64())
                .unwrap_or_default()
        )
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn zulip_app_channel_preserves_stream_topic() {
        let message = json!({
            "type": "stream",
            "stream_id": 42,
            "subject": "deploys"
        });
        assert_eq!(zulip_app_channel(&message), "42/deploys");
    }

    #[test]
    fn zulip_app_channel_falls_back_to_pm_sender() {
        let message = json!({
            "type": "private",
            "sender_id": 7
        });
        assert_eq!(zulip_app_channel(&message), "pm/7");
    }
}
