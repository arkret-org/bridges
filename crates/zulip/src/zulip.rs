//! Zulip adapter (event queue long-polling).
//!
//! - Inbound (Zulip -> arkret): `run` uses reqwest to call Zulip `register` to create an event
//!   queue, then loops `GET /api/v1/events` long-polling to pull new messages ->
//!   [`MessageContext::submit_app_message`].
//! - Outbound (arkret -> Zulip): [`MessageBridge::send_to_app`] uses `ctx.http` to POST
//!   `{site}/api/v1/messages` (HTTP basic auth: bot_email + api_key).
//!
//! The receive path uses Zulip's official event queue long-polling REST
//! interface.

use std::sync::Arc;

use arkret_bridge_messaging::runtime::{
    BridgeError, Result, exponential_backoff_with_jitter, redact_sensitive_url_values,
};
use arkret_bridge_messaging::{
    AppMessageRef, ExternalMediaRequest, InboundAppMessage, InboundMediaAuthorization,
    MessageBridge, MessageContext, OutboundAppMessage, SenderRenderStyle, send_json_expect,
};
use async_trait::async_trait;
use quick_xml::Reader;
use quick_xml::events::Event as XmlEvent;
use serde_json::Value;

/// Zulip REST success flag: top-level `result == "success"`.
fn zulip_result_ok(payload: &Value) -> bool {
    payload.get("result").and_then(Value::as_str) == Some("success")
}

/// Base delay for the long-poll failure backoff.
const ZULIP_BACKOFF_BASE: std::time::Duration = std::time::Duration::from_secs(2);
/// Ceiling for the long-poll failure backoff.
const ZULIP_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(60);
/// Consecutive long-poll failures after which the event queue is re-registered
/// (a persistently malformed/erroring queue is most likely stale or gone).
const ZULIP_REREGISTER_AFTER_FAILURES: u32 = 5;

/// Record one long-poll failure, sleep an exponential+jittered backoff, and
/// report whether the caller should break the inner loop to re-register the
/// event queue (once consecutive failures reach the threshold).
async fn zulip_poll_backoff(failures: &mut u32, context: &str, detail: &str) -> bool {
    *failures = failures.saturating_add(1);
    if *failures >= ZULIP_REREGISTER_AFTER_FAILURES {
        tracing::warn!(
            failures = *failures,
            detail,
            "{context}; re-registering the event queue"
        );
        return true;
    }
    let delay =
        exponential_backoff_with_jitter(*failures - 1, ZULIP_BACKOFF_BASE, ZULIP_BACKOFF_MAX);
    tracing::warn!(
        failures = *failures,
        delay_ms = delay.as_millis() as u64,
        detail,
        "{context}; backing off"
    );
    tokio::time::sleep(delay).await;
    false
}

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

        let body: Value = resp.json().await.map_err(|e| {
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
        let mut register_attempt: u32 = 0;
        loop {
            let (queue_id, mut last_event_id) = match self.register(&ctx).await {
                Ok(queue) => queue,
                Err(e) => {
                    let delay = exponential_backoff_with_jitter(
                        register_attempt,
                        ZULIP_BACKOFF_BASE,
                        ZULIP_BACKOFF_MAX,
                    );
                    register_attempt = register_attempt.saturating_add(1);
                    tracing::warn!(error = %e, delay_ms = delay.as_millis() as u64, "Zulip queue registration failed, retrying");
                    tokio::time::sleep(delay).await;
                    continue;
                }
            };
            register_attempt = 0;
            tracing::info!(queue = %queue_id, "Zulip event queue registered, starting long-polling");

            // Consecutive long-poll failures (request/parse error or a malformed
            // response with no `events` array). Drives an exponential+jittered
            // backoff and forces a re-register after a threshold, instead of
            // spinning at a fixed 1s cadence forever.
            let mut poll_failures: u32 = 0;
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
                            if zulip_poll_backoff(
                                &mut poll_failures,
                                "Zulip events parse failed",
                                &e.to_string(),
                            )
                            .await
                            {
                                break;
                            }
                            continue;
                        }
                    },
                    Err(e) => {
                        if zulip_poll_backoff(
                            &mut poll_failures,
                            "Zulip events request failed",
                            &e.to_string(),
                        )
                        .await
                        {
                            break;
                        }
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
                    // Malformed response (no events array, not a known error code).
                    // Back off and re-register after the threshold rather than
                    // spinning at a fixed cadence against a broken queue.
                    if zulip_poll_backoff(
                        &mut poll_failures,
                        "Zulip events response malformed",
                        "missing events array",
                    )
                    .await
                    {
                        break;
                    }
                    continue;
                };
                // A well-formed poll resets the failure backoff.
                poll_failures = 0;

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
                    let app_user = message
                        .get("sender_id")
                        .and_then(|v| v.as_i64())
                        .map(|n| n.to_string())
                        .unwrap_or_default();
                    for (index, media) in zulip_uploaded_media(&self.site, message)
                        .into_iter()
                        .enumerate()
                    {
                        let media_inbound = InboundAppMessage {
                            app_channel: app_channel.clone(),
                            app_user: app_user.clone(),
                            app_message_id: format!("{app_message_id}:upload:{index}"),
                            body: String::new(),
                        };
                        if let Err(error) = ctx
                            .forward_external_media(
                                "zulip",
                                media_inbound,
                                ExternalMediaRequest {
                                    url: &media.url,
                                    authorization: Some(InboundMediaAuthorization::Basic {
                                        username: self.bot_email.clone(),
                                        password: self.api_key.clone(),
                                    }),
                                    allowed_hosts: &[media.allowed_host.as_str()],
                                    mime_hint: None,
                                    filename: media.filename,
                                },
                            )
                            .await
                        {
                            if error.is_retriable() {
                                retry_poll = true;
                                break;
                            }
                        }
                    }
                    if retry_poll {
                        break;
                    }
                    let inbound = InboundAppMessage {
                        app_channel,
                        app_user,
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
                            if ctx.report_inbound_failure("zulip", &inbound, &e).await {
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
                .unwrap_or((msg.app_channel.as_str(), "arkret"));
            form.push(("type", "stream".to_owned()));
            form.push(("to", stream.to_owned()));
            form.push(("topic", topic.to_owned()));
        }
        form.push(("content", body));

        let request = ctx
            .http
            .post(&url)
            .basic_auth(&self.bot_email, Some(&self.api_key))
            .form(&form);
        let payload = send_json_expect(request, "Zulip send", zulip_result_ok).await?;
        let id = payload
            .get("id")
            .and_then(|v| v.as_i64())
            .map(|n| n.to_string())
            .unwrap_or_default();
        Ok(AppMessageRef { app_message_id: id })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ZulipUploadedMedia {
    url: String,
    allowed_host: String,
    filename: Option<String>,
}

/// Extract same-origin Zulip upload links from the server-rendered message
/// HTML. Anchor `href` values point at the original upload; image `src` values
/// may point at thumbnails and are deliberately ignored.
fn zulip_uploaded_media(site: &str, message: &Value) -> Vec<ZulipUploadedMedia> {
    let Some(content) = message.get("content").and_then(Value::as_str) else {
        return Vec::new();
    };
    let Ok(site_url) = url::Url::parse(site) else {
        return Vec::new();
    };
    if site_url.scheme() != "https"
        || !site_url.username().is_empty()
        || site_url.password().is_some()
    {
        return Vec::new();
    }
    let Some(site_host) = site_url.host_str().map(str::to_owned) else {
        return Vec::new();
    };
    let mut reader = Reader::from_str(content);
    reader.config_mut().allow_unmatched_ends = true;
    reader.config_mut().check_end_names = false;
    let decoder = reader.decoder();
    let mut seen = std::collections::HashSet::new();
    let mut media = Vec::new();
    loop {
        let element = match reader.read_event() {
            Ok(XmlEvent::Start(element)) | Ok(XmlEvent::Empty(element))
                if element.name().as_ref().eq_ignore_ascii_case(b"a") =>
            {
                element
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => continue,
            Err(_) => break,
        };
        let Some(href) = element.attributes().flatten().find_map(|attribute| {
            attribute
                .key
                .as_ref()
                .eq_ignore_ascii_case(b"href")
                .then(|| attribute.decode_and_unescape_value(decoder).ok())
                .flatten()
                .map(|value| value.into_owned())
        }) else {
            continue;
        };
        let Ok(resolved) = site_url.join(&href) else {
            continue;
        };
        if resolved.scheme() != site_url.scheme()
            || resolved.host_str() != site_url.host_str()
            || resolved.port_or_known_default() != site_url.port_or_known_default()
            || !resolved.username().is_empty()
            || resolved.password().is_some()
            || !resolved.path().starts_with("/user_uploads/")
            || !seen.insert(resolved.as_str().to_owned())
        {
            continue;
        }
        let filename = resolved
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .filter(|filename| !filename.is_empty())
            .map(str::to_owned);
        media.push(ZulipUploadedMedia {
            url: resolved.to_string(),
            allowed_host: site_host.clone(),
            filename,
        });
    }
    media
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
            .unwrap_or("arkret");
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

    #[test]
    fn zulip_uploaded_media_extracts_unique_same_origin_upload_links() {
        let message = json!({
            "content": concat!(
                "<p><a href=\"/user_uploads/1/ab/report.pdf\">report</a>",
                "<a href=\"https://chat.example.test/user_uploads/1/cd/photo.png\">",
                "<img src=\"/user_uploads/thumbnail/1/cd/photo.png\"></a>",
                "<a href=\"/user_uploads/1/ef/archive.zip\">archive</a>",
                "<a href=\"/user_uploads/1/ab/report.pdf\">duplicate</a>",
                "<a href=\"https://attacker.invalid/user_uploads/1/evil\">external</a></p>"
            )
        });
        let media = zulip_uploaded_media("https://chat.example.test", &message);
        assert_eq!(media.len(), 3);
        assert_eq!(
            media[0],
            ZulipUploadedMedia {
                url: "https://chat.example.test/user_uploads/1/ab/report.pdf".to_owned(),
                allowed_host: "chat.example.test".to_owned(),
                filename: Some("report.pdf".to_owned()),
            }
        );
        assert_eq!(media[1].filename.as_deref(), Some("photo.png"));
        assert_eq!(media[2].filename.as_deref(), Some("archive.zip"));
    }

    #[test]
    fn zulip_uploaded_media_ignores_non_upload_links_and_invalid_sites() {
        let message = json!({
            "content": concat!(
                "<p><a href=\"/help\">help</a>",
                "<a href=\"https://example.test/file\">file</a>",
                "<a href=\"https://user:secret@chat.example.test/user_uploads/1/evil\">",
                "credential URL</a></p>"
            )
        });
        assert!(zulip_uploaded_media("https://chat.example.test", &message).is_empty());
        assert!(zulip_uploaded_media("not a url", &message).is_empty());
        assert!(zulip_uploaded_media("http://chat.example.test", &message).is_empty());
    }
}
