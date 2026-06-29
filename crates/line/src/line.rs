//! LINE adapter (LINE Messaging API, reqwest HTTP).
//!
//! - Inbound (LINE -> cokret): the Messaging API pushes signed events via `/webhooks/line`.
//! - Outbound (cokret → LINE): [`MessageBridge::send_to_app`] uses `ctx.http` (reqwest) to POST `https://api.line.me/v2/bot/message/push`.

use std::sync::Arc;

use async_trait::async_trait;
use cokret_bridge_messaging::runtime::{BridgeError, Result, redact_sensitive_url_values};
use cokret_bridge_messaging::salvo::prelude::*;
use cokret_bridge_messaging::salvo::{self, affix_state};
use cokret_bridge_messaging::{
    AppMessageRef, Attachment, DEFAULT_MEDIA_MIME, InboundAppMessage, MessageBridge, MessageContext,
    OutboundAppMessage, SenderRenderStyle, webhook,
};
use serde_json::{Value, json};

/// LINE bridge adapter.
pub struct LineApp {
    /// Push message token (Bearer).
    channel_access_token: String,
    /// Webhook signature verification secret.
    channel_secret: String,
}

impl LineApp {
    pub fn new(channel_access_token: impl Into<String>, channel_secret: impl Into<String>) -> Self {
        Self {
            channel_access_token: channel_access_token.into(),
            channel_secret: channel_secret.into(),
        }
    }
}

#[async_trait]
impl MessageBridge for LineApp {
    fn name(&self) -> &str {
        "line"
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let text = msg.rendered_body(SenderRenderStyle::Plain);

        // app_channel is treated as the push target ID (userId / groupId / roomId).
        let body = json!({
            "to": msg.app_channel,
            "messages": [
                {
                    "type": "text",
                    "text": text,
                }
            ],
        });

        let resp = ctx
            .http
            .post("https://api.line.me/v2/bot/message/push")
            .bearer_auth(&self.channel_access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                BridgeError::App(format!(
                    "LINE send failed: {}",
                    redact_sensitive_url_values(e.to_string())
                ))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(BridgeError::App(format!(
                "LINE send returned non-2xx: {status} {}",
                redact_sensitive_url_values(detail)
            )));
        }

        // The LINE push endpoint's successful response body contains no message
        // id. Return the empty string when `x-line-request-id` is absent rather
        // than falling back to the target id: a non-message-id value would
        // pollute the message mapping (messaging skips recording an empty id).
        let app_message_id = resp
            .headers()
            .get("x-line-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned())
            .unwrap_or_default();

        Ok(AppMessageRef { app_message_id })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        Some(
            salvo::Router::with_path("webhooks/line")
                .hoop(affix_state::inject(LineWebhookState { app: self, ctx }))
                .post(line_delivery),
        )
    }
}

#[derive(Clone)]
struct LineWebhookState {
    app: Arc<LineApp>,
    ctx: Arc<MessageContext>,
}

#[handler]
async fn line_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<LineWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let signature = req.header::<String>("x-line-signature").unwrap_or_default();
    // Fail closed on an empty channel_secret: HMAC over an empty key is publicly
    // computable, so a mis-configured empty secret would let anyone forge a valid
    // `x-line-signature` (parity with the other signed bridges).
    if state.app.channel_secret.is_empty() {
        webhook::unauthorized(res, "LINE channel_secret is not configured");
        return;
    }
    // Use the shared `raw_body` helper so the webhook body is bounded by
    // `MAX_WEBHOOK_BODY_BYTES` instead of reading an unbounded payload.
    let Some(payload) = webhook::raw_body(req, res).await else {
        return;
    };
    if !verify_line_signature(&state.app.channel_secret, &payload, &signature) {
        webhook::unauthorized(res, "LINE signature mismatch");
        return;
    }
    let body: Value = match serde_json::from_slice(&payload) {
        Ok(value) => value,
        Err(err) => {
            webhook::bad_request(res, format!("invalid LINE JSON body: {err}"));
            return;
        }
    };

    // When any message in the batch hits a transient failure we respond 5xx so
    // LINE redelivers the whole batch; inbound dedup makes the replay idempotent.
    let mut retry = false;
    for event in body
        .get("events")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if webhook::str_at(event, "/type") != Some("message") {
            continue;
        }
        let channel = webhook::first_string_at(
            event,
            &["/source/groupId", "/source/roomId", "/source/userId"],
        )
        .unwrap_or_default();
        let user = webhook::string_at(event, "/source/userId").unwrap_or_else(|| channel.clone());
        let Some(message_id) =
            webhook::first_non_empty_string_at(event, &["/message/id", "/webhookEventId"])
        else {
            tracing::warn!("LINE message event missing message id; skipping");
            continue;
        };
        let msg_type = webhook::str_at(event, "/message/type").unwrap_or_default();

        if msg_type == "text" {
            let Some(text) = webhook::str_at(event, "/message/text") else {
                continue;
            };
            let outcome = webhook::submit(
                state.ctx.clone(),
                "line",
                InboundAppMessage {
                    app_channel: channel,
                    app_user: user,
                    app_message_id: message_id,
                    body: text.to_owned(),
                },
            )
            .await;
            retry |= outcome == webhook::SubmitOutcome::Retry;
            continue;
        }

        if matches!(msg_type, "image" | "video" | "audio" | "file") {
            // The content id is the message id; the binary is fetched from the
            // LINE content endpoint.
            let Some(content_id) = webhook::non_empty_string_at(event, "/message/id") else {
                tracing::warn!("LINE media event missing content message id; skipping");
                continue;
            };
            let filename = webhook::string_at(event, "/message/fileName");
            if let Err(e) =
                forward_line_media(state, &channel, &user, &message_id, &content_id, filename).await
            {
                tracing::warn!(error = %e, "LINE media bridging failed");
            }
        }
    }
    if retry {
        webhook::submission_retry(res);
    } else {
        webhook::ok_json(res, json!({ "ok": true }));
    }
}

/// Download LINE message content (image/video/audio/file) from the content
/// endpoint, upload it to the cokret blob store, and submit a media message.
async fn forward_line_media(
    state: &LineWebhookState,
    channel: &str,
    user: &str,
    message_id: &str,
    content_id: &str,
    filename: Option<String>,
) -> Result<()> {
    let url = format!("https://api-data.line.me/v2/bot/message/{content_id}/content");
    let media = state
        .ctx
        .download_external_media(
            &url,
            Some(&state.app.channel_access_token),
            &["api-data.line.me"],
        )
        .await?;
    let mime = media
        .content_type
        .unwrap_or_else(|| DEFAULT_MEDIA_MIME.to_owned());
    let blob_ref = state.ctx.upload_blob(&media.bytes, &mime).await?;

    let attachment = Attachment {
        blob_ref,
        media_type: Some(mime),
        filename,
        size: Some(media.bytes.len() as u64),
        caption: String::new(),
    };
    let inbound = InboundAppMessage {
        app_channel: channel.to_owned(),
        app_user: user.to_owned(),
        app_message_id: message_id.to_owned(),
        body: String::new(),
    };
    state.ctx.submit_media_message(inbound, attachment).await?;
    Ok(())
}

fn verify_line_signature(secret: &str, payload: &[u8], signature: &str) -> bool {
    // LINE's `x-line-signature` is base64(HMAC-SHA256(channel_secret, body)).
    // Use the shared constant-time comparator to avoid a timing side channel.
    webhook::verify_hmac_sha256(
        secret.as_bytes(),
        payload,
        signature,
        webhook::SigEncoding::Base64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_signature_accepts_known_hmac_vector() {
        let payload = br#"{"events":[{"message":{"type":"text","text":"hi"}}]}"#;
        let signature = "NQkdfT4RlWYj5i1Rux1N9Evba0OP1IFi6c6/ltJM3Zo=";
        assert!(verify_line_signature("topsecret", payload, signature));
        assert!(!verify_line_signature("topsecret", payload, "invalid"));
        assert!(!verify_line_signature("wrong", payload, signature));
    }
}
