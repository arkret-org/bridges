//! WhatsApp adapter (WhatsApp Cloud API, reqwest HTTP).
//!
//! - Inbound (WhatsApp -> arkret): the Cloud API pushes messages via `/webhooks/whatsapp` (GET
//!   verification + POST delivery).
//! - Outbound (arkret → WhatsApp): [`MessageBridge::send_to_app`] uses `ctx.http` (reqwest) to POST
//!   `https://graph.facebook.com/v20.0/{phone_number_id}/messages`.

use std::sync::Arc;
use std::time::Duration;

use arkret_bridge_messaging::runtime::{BridgeError, Result};
use arkret_bridge_messaging::salvo::prelude::*;
use arkret_bridge_messaging::salvo::{self, affix_state};
use arkret_bridge_messaging::{
    AppMessageRef, ExternalMediaRequest, InboundAppMessage, MessageBridge, MessageContext,
    OutboundAppMessage, SenderRenderStyle, send_json_expect_status, webhook,
};
use async_trait::async_trait;
use serde_json::{Value, json};

/// WhatsApp bridge adapter.
pub struct WhatsAppApp {
    /// Sender phone number ID (outbound URL path segment).
    phone_number_id: String,
    /// Cloud API token (Bearer).
    access_token: String,
    /// Webhook verification echo token.
    verify_token: String,
    /// Meta app secret used to verify the `X-Hub-Signature-256` of each POST
    /// delivery (HMAC-SHA256 over the raw request body).
    app_secret: String,
    /// Meta Graph API version segment (e.g. `v20.0`), configurable so an
    /// operator can roll to a newer version without a code release.
    graph_api_version: String,
}

impl WhatsAppApp {
    pub fn new(
        phone_number_id: impl Into<String>,
        access_token: impl Into<String>,
        verify_token: impl Into<String>,
        app_secret: impl Into<String>,
        graph_api_version: impl Into<String>,
    ) -> Self {
        Self {
            phone_number_id: phone_number_id.into(),
            access_token: access_token.into(),
            verify_token: verify_token.into(),
            app_secret: app_secret.into(),
            graph_api_version: graph_api_version.into(),
        }
    }
}

#[async_trait]
impl MessageBridge for WhatsAppApp {
    fn name(&self) -> &str {
        "whatsapp"
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let url = format!(
            "https://graph.facebook.com/{}/{}/messages",
            self.graph_api_version, self.phone_number_id
        );

        let text = msg.rendered_body(SenderRenderStyle::Plain);

        // app_channel is treated as the recipient WhatsApp number (E.164, without +).
        let body = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": msg.app_channel,
            "type": "text",
            "text": {
                "preview_url": false,
                "body": text,
            },
        });

        let value = send_json_expect_status(
            ctx.http
                .post(&url)
                .bearer_auth(&self.access_token)
                .json(&body),
            "WhatsApp send",
        )
        .await?;

        // Return messages[0].id as the app-side message identifier. Return the
        // empty string when absent rather than falling back to the recipient
        // number: a non-message-id value would pollute the message mapping
        // (messaging skips recording an empty id).
        let app_message_id = value
            .get("messages")
            .and_then(|m| m.get(0))
            .and_then(|m| m.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .unwrap_or_default();

        Ok(AppMessageRef { app_message_id })
    }

    fn expects_webhook_inbound(&self) -> bool {
        true
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        if self.verify_token.trim().is_empty() || self.app_secret.trim().is_empty() {
            return None;
        }
        let replay = ctx.replay_window(WHATSAPP_REPLAY_TTL);
        Some(
            salvo::Router::with_path("webhooks/whatsapp")
                .hoop(affix_state::inject(WhatsAppWebhookState {
                    app: self,
                    ctx,
                    replay,
                }))
                .get(whatsapp_verify)
                .post(whatsapp_delivery),
        )
    }
}

/// In-handler bounded replay window for WhatsApp. The Meta signature
/// (`HMAC-SHA256(app_secret, raw_body)`) covers the body but carries no
/// timestamp/nonce, so a captured `(body, signature)` pair would otherwise
/// verify forever; the bridge contract (G-4) mandates a bounded replay/dedupe
/// guard keyed on the stable platform message id. The TTL covers Meta's
/// redelivery window with margin.
const WHATSAPP_REPLAY_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone)]
struct WhatsAppWebhookState {
    app: Arc<WhatsAppApp>,
    ctx: Arc<MessageContext>,
    /// Bounded replay guard keyed on the platform `message.id`; a captured,
    /// validly signed event is accepted at most once inside the window.
    replay: Arc<webhook::ReplayWindow>,
}

#[handler]
async fn whatsapp_verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = webhook::require_state::<WhatsAppWebhookState>(depot, res) else {
        return;
    };
    webhook::meta_hub_verify(req, res, &state.app.verify_token);
}

#[handler]
async fn whatsapp_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = webhook::require_state::<WhatsAppWebhookState>(depot, res) else {
        return;
    };
    let Some((_raw, body)) = webhook::meta_signed_json_body(req, res, &state.app.app_secret).await
    else {
        return;
    };

    // Respond 5xx if any message hit a transient failure so Meta redelivers the
    // batch; inbound dedup keeps the replay idempotent.
    let mut retry = false;
    for entry in body
        .get("entry")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for change in entry
            .get("changes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let value = change.get("value").unwrap_or(change);
            for message in value
                .get("messages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let from = webhook::string_at(message, "/from").unwrap_or_default();
                let Some(message_id) = webhook::non_empty_string_at(message, "/id") else {
                    tracing::warn!("WhatsApp message missing id; skipping");
                    continue;
                };
                // Bounded replay/dedupe (BRG-SEC-001 / contract G-4): the Meta
                // signature does not bind a timestamp, so a captured event would
                // replay forever. Text submits use the shared dedupe helper;
                // media keeps local handling because it resolves Graph media
                // before Arkret submit.
                let replay_key = format!("whatsapp:{message_id}");

                if let Some(text) = webhook::str_at(message, "/text/body") {
                    let outcome = webhook::submit_deduped(
                        state.ctx.clone(),
                        "whatsapp",
                        &state.replay,
                        replay_key,
                        InboundAppMessage {
                            app_channel: from.clone(),
                            app_user: from,
                            app_message_id: message_id.clone(),
                            body: text.to_owned(),
                        },
                    )
                    .await;
                    retry |= outcome == webhook::SubmitOutcome::Retry;
                    continue;
                }

                if let Some((media_id, mime, filename)) = whatsapp_media_ref(message) {
                    if !state.replay.check_and_record(replay_key.clone()).await {
                        tracing::debug!(message_id = %message_id, "WhatsApp event replayed; skipping");
                        continue;
                    }
                    match forward_whatsapp_media(
                        state,
                        &from,
                        &message_id,
                        &media_id,
                        mime,
                        filename,
                    )
                    .await
                    {
                        Ok(_) => {}
                        // The shared media forwarder already ran the inbound
                        // failure audit; only translate retriability here.
                        Err(e) => {
                            tracing::warn!(error = %e, "WhatsApp media bridging failed");
                            if e.is_retriable() {
                                state.replay.forget(replay_key).await;
                                retry = true;
                            }
                        }
                    }
                }
            }
        }
    }
    if retry {
        webhook::submission_retry(res);
    } else {
        webhook::ok_json(res, json!({ "ok": true }));
    }
}

/// Identify an inbound media object on a WhatsApp message: `(media_id, mime, filename)`.
fn whatsapp_media_ref(message: &Value) -> Option<(String, Option<String>, Option<String>)> {
    for kind in ["image", "document", "video", "audio", "sticker"] {
        if let Some(obj) = message.get(kind) {
            let id = obj.get("id").and_then(Value::as_str)?.to_owned();
            let mime = obj
                .get("mime_type")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let filename = obj
                .get("filename")
                .and_then(Value::as_str)
                .map(str::to_owned);
            return Some((id, mime, filename));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whatsapp_media_ref_extracts_id_mime_and_filename() {
        let message = json!({
            "document": {
                "id": "media-1",
                "mime_type": "application/pdf",
                "filename": "brief.pdf"
            }
        });
        assert_eq!(
            whatsapp_media_ref(&message),
            Some((
                "media-1".to_owned(),
                Some("application/pdf".to_owned()),
                Some("brief.pdf".to_owned())
            ))
        );
    }

    #[test]
    fn whatsapp_media_ref_requires_media_id() {
        assert!(whatsapp_media_ref(&json!({"image": {"mime_type": "image/jpeg"}})).is_none());
        assert!(whatsapp_media_ref(&json!({"text": {"body": "hello"}})).is_none());
    }
}

/// Resolve a WhatsApp media id to its download URL (platform-specific step),
/// then hand off to the shared [`MessageContext::forward_external_media`]
/// skeleton (download → blob upload → media message + failure audit).
async fn forward_whatsapp_media(
    state: &WhatsAppWebhookState,
    from: &str,
    message_id: &str,
    media_id: &str,
    mime: Option<String>,
    filename: Option<String>,
) -> Result<String> {
    let token = &state.app.access_token;
    let inbound = InboundAppMessage {
        app_channel: from.to_owned(),
        app_user: from.to_owned(),
        app_message_id: message_id.to_owned(),
        body: String::new(),
    };
    // Platform-specific: resolve the (short-lived) media URL. A lookup failure
    // gets the same inbound-failure audit the shared forwarder applies.
    let meta_url = format!(
        "https://graph.facebook.com/{}/{media_id}",
        state.app.graph_api_version
    );
    let meta = match send_json_expect_status(
        state.ctx.http.get(&meta_url).bearer_auth(token),
        "WhatsApp media lookup",
    )
    .await
    {
        Ok(meta) => meta,
        Err(e) => {
            state
                .ctx
                .report_inbound_failure("whatsapp", &inbound, &e)
                .await;
            return Err(e);
        }
    };
    let Some(url) = meta.get("url").and_then(Value::as_str) else {
        let e = BridgeError::App("WhatsApp media response has no url".to_owned());
        state
            .ctx
            .report_inbound_failure("whatsapp", &inbound, &e)
            .await;
        return Err(e);
    };
    let mime_hint = mime.or_else(|| {
        meta.get("mime_type")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });

    state
        .ctx
        .forward_external_media(
            "whatsapp",
            inbound,
            ExternalMediaRequest {
                url,
                bearer_token: Some(token),
                allowed_hosts: &[
                    "lookaside.fbsbx.com",
                    "lookaside.facebook.com",
                    "graph.facebook.com",
                    "mmg.whatsapp.net",
                ],
                mime_hint,
                filename,
            },
        )
        .await
}
