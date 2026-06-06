//! WhatsApp adapter (WhatsApp Cloud API, reqwest HTTP).
//!
//! - Inbound (WhatsApp -> cokret): the Cloud API pushes messages via
//!   `/webhooks/whatsapp` (GET verification + POST delivery).
//! - Outbound (cokret → WhatsApp): [`MessageBridge::send_to_app`] uses `ctx.http`
//!   (reqwest) to POST `https://graph.facebook.com/v20.0/{phone_number_id}/messages`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cokret_bridge_messaging::salvo::{self, affix_state, prelude::*};
use cokret_bridge_messaging::{
    AppMessageRef, Attachment, InboundAppMessage, MessageBridge, MessageContext,
    OutboundAppMessage, webhook,
};
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::{Value, json};

/// Graph API version.
const GRAPH_API_VERSION: &str = "v20.0";

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
}

impl WhatsAppApp {
    pub fn new(
        phone_number_id: impl Into<String>,
        access_token: impl Into<String>,
        verify_token: impl Into<String>,
        app_secret: impl Into<String>,
    ) -> Self {
        Self {
            phone_number_id: phone_number_id.into(),
            access_token: access_token.into(),
            verify_token: verify_token.into(),
            app_secret: app_secret.into(),
        }
    }
}

#[async_trait]
impl MessageBridge for WhatsAppApp {
    fn name(&self) -> &str {
        "whatsapp"
    }

    async fn run(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let url = format!(
            "https://graph.facebook.com/{GRAPH_API_VERSION}/{}/messages",
            self.phone_number_id
        );

        // Prefix the text with the sender, matching the discord template style.
        let text = format!("{}: {}", msg.sender_display, msg.body);

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

        let resp = ctx
            .http
            .post(&url)
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("WhatsApp send failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(BridgeError::App(format!(
                "WhatsApp send returned non-2xx: {status} {detail}"
            )));
        }

        let value: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| BridgeError::App(format!("WhatsApp send response parse failed: {e}")))?;

        // Return messages[0].id as the app-side message identifier; fall back to the recipient number if missing.
        let app_message_id = value
            .get("messages")
            .and_then(|m| m.get(0))
            .and_then(|m| m.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .unwrap_or_else(|| msg.app_channel.clone());

        Ok(AppMessageRef { app_message_id })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        Some(
            salvo::Router::with_path("webhooks/whatsapp")
                .hoop(affix_state::inject(WhatsAppWebhookState { app: self, ctx }))
                .get(whatsapp_verify)
                .post(whatsapp_delivery),
        )
    }
}

#[derive(Clone)]
struct WhatsAppWebhookState {
    app: Arc<WhatsAppApp>,
    ctx: Arc<MessageContext>,
}

#[handler]
async fn whatsapp_verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<WhatsAppWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let mode = req.query::<String>("hub.mode").unwrap_or_default();
    let token = req.query::<String>("hub.verify_token").unwrap_or_default();
    let challenge = req.query::<String>("hub.challenge").unwrap_or_default();
    if mode == "subscribe" && token == state.app.verify_token {
        webhook::ok_text(res, challenge);
    } else {
        webhook::unauthorized(res, "WhatsApp verify token mismatch");
    }
}

#[handler]
async fn whatsapp_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<WhatsAppWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    // Fail closed: every POST delivery MUST carry a valid
    // `X-Hub-Signature-256: sha256=<hmac>` over the exact raw body.
    if state.app.app_secret.is_empty() {
        webhook::unauthorized(res, "WhatsApp app_secret not configured");
        return;
    }
    let Some(raw) = webhook::raw_body(req, res).await else {
        return;
    };
    let signature = req
        .header::<String>("x-hub-signature-256")
        .unwrap_or_default();
    if !webhook::verify_meta_x_hub_signature_256(state.app.app_secret.as_bytes(), &raw, &signature)
    {
        webhook::unauthorized(res, "WhatsApp X-Hub-Signature-256 mismatch");
        return;
    }
    let body: Value = match serde_json::from_slice(&raw) {
        Ok(value) => value,
        Err(err) => {
            webhook::bad_request(res, format!("invalid WhatsApp JSON body: {err}"));
            return;
        }
    };

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
                let message_id = webhook::string_at(message, "/id")
                    .or_else(|| webhook::string_at(message, "/timestamp"))
                    .unwrap_or_default();

                if let Some(text) = webhook::str_at(message, "/text/body") {
                    webhook::submit(
                        state.ctx.clone(),
                        "whatsapp",
                        InboundAppMessage {
                            app_channel: from.clone(),
                            app_user: from,
                            app_message_id: message_id,
                            body: text.to_owned(),
                        },
                    )
                    .await;
                    continue;
                }

                if let Some((media_id, mime, filename)) = whatsapp_media_ref(message) {
                    if let Err(e) =
                        forward_whatsapp_media(state, &from, &message_id, &media_id, mime, filename)
                            .await
                    {
                        tracing::warn!(error = %e, "WhatsApp media bridging failed");
                    }
                }
            }
        }
    }
    webhook::ok_json(res, json!({ "ok": true }));
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

/// Resolve a WhatsApp media id to its download URL, fetch the bytes (Bearer
/// auth on both calls), upload to the cokret blob store, and submit a media
/// message.
async fn forward_whatsapp_media(
    state: &WhatsAppWebhookState,
    from: &str,
    message_id: &str,
    media_id: &str,
    mime: Option<String>,
    filename: Option<String>,
) -> Result<()> {
    let token = &state.app.access_token;
    // 1) Resolve the (short-lived) media URL.
    let meta_url = format!("https://graph.facebook.com/{GRAPH_API_VERSION}/{media_id}");
    let meta: Value = state
        .ctx
        .http
        .get(&meta_url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| BridgeError::App(format!("WhatsApp media lookup failed: {e}")))?
        .json()
        .await
        .map_err(|e| BridgeError::App(format!("WhatsApp media lookup parse failed: {e}")))?;
    let url = meta
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| BridgeError::App(format!("WhatsApp media has no url: {meta}")))?;
    let resolved_mime = mime
        .or_else(|| {
            meta.get("mime_type")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "application/octet-stream".to_owned());

    // 2) Download the bytes (also Bearer-authenticated).
    let bytes = state
        .ctx
        .http
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| BridgeError::App(format!("WhatsApp media download failed: {e}")))?
        .bytes()
        .await
        .map_err(|e| BridgeError::App(format!("WhatsApp media read failed: {e}")))?;
    let blob_ref = state.ctx.upload_blob(&bytes, &resolved_mime).await?;

    let attachment = Attachment {
        blob_ref,
        media_type: Some(resolved_mime),
        filename,
        size: Some(bytes.len() as u64),
        caption: String::new(),
    };
    let inbound = InboundAppMessage {
        app_channel: from.to_owned(),
        app_user: from.to_owned(),
        app_message_id: message_id.to_owned(),
        body: String::new(),
    };
    state.ctx.submit_media_message(inbound, attachment).await?;
    Ok(())
}
