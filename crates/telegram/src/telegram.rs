//! Telegram adapter (teloxide long polling).
//!
//! - Inbound (Telegram → cokret): once `teloxide::repl` long polling receives a
//!   text message, it calls [`MessageContext::submit_app_message`].
//! - Outbound (cokret → Telegram): [`MessageBridge::send_to_app`] uses the Bot HTTP
//!   `send_message` to deliver to the corresponding chat.

use std::sync::Arc;

use async_trait::async_trait;
use cokret_bridge_messaging::{
    AppMessageRef, Attachment, InboundAppMessage, MessageBridge, MessageContext,
    OutboundAppMessage, SenderRenderStyle,
};
use cokret_bridge_runtime::{BridgeError, Result};
use teloxide::prelude::*;
use teloxide::types::{ChatId, FileId, InputFile};

/// Telegram bridge adapter.
pub struct TelegramApp {
    token: String,
}

impl TelegramApp {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

#[async_trait]
impl MessageBridge for TelegramApp {
    fn name(&self) -> &str {
        "telegram"
    }

    async fn run(self: Arc<Self>, ctx: Arc<MessageContext>) -> Result<()> {
        let bot = Bot::new(&self.token);
        let token = self.token.clone();

        // teloxide long-polling receive loop; submit text and media to the core.
        teloxide::repl(bot, move |bot: Bot, msg: Message| {
            let ctx = ctx.clone();
            let token = token.clone();
            async move {
                let channel = msg.chat.id.0.to_string();
                let user = msg
                    .from
                    .as_ref()
                    .map(|u| u.id.0.to_string())
                    .unwrap_or_default();

                if let Some(text) = msg.text() {
                    let inbound = InboundAppMessage {
                        app_channel: channel.clone(),
                        app_user: user.clone(),
                        app_message_id: msg.id.0.to_string(),
                        body: text.to_owned(),
                    };
                    if let Err(e) = ctx.submit_app_message(inbound).await {
                        tracing::warn!(error = %e, "Telegram → cokret submission failed");
                    }
                }

                if let Some((file_id, filename, mime)) = telegram_media(&msg) {
                    if let Err(e) = forward_media(
                        &bot, &ctx, &token, &channel, &user, &msg, file_id, filename, mime,
                    )
                    .await
                    {
                        tracing::warn!(error = %e, "Telegram media bridging failed");
                    }
                }

                respond(())
            }
        })
        .await;

        Ok(())
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let chat_raw: i64 = msg.app_channel.parse().map_err(|_| {
            BridgeError::App(format!("invalid Telegram chat id: {}", msg.app_channel))
        })?;
        let bot = Bot::new(&self.token);
        let body = msg.rendered_body(SenderRenderStyle::Plain);

        // With an attachment: download the cokret blob and send it as a document.
        if let Some(att) = &msg.attachment {
            let bytes = ctx.download_blob(&att.blob_ref).await?;
            let filename = att.filename.clone().unwrap_or_else(|| "file".to_owned());
            let file = InputFile::memory(bytes).file_name(filename);
            let sent = bot
                .send_document(ChatId(chat_raw), file)
                .caption(body)
                .await
                .map_err(|e| BridgeError::App(format!("Telegram document send failed: {e}")))?;
            return Ok(AppMessageRef {
                app_message_id: sent.id.0.to_string(),
            });
        }

        let sent = bot
            .send_message(ChatId(chat_raw), body)
            .await
            .map_err(|e| BridgeError::App(format!("Telegram send failed: {e}")))?;
        Ok(AppMessageRef {
            app_message_id: sent.id.0.to_string(),
        })
    }
}

/// Extract a downloadable media reference from a Telegram message, if any:
/// `(file_id, filename, mime_type)`. Documents are preferred; otherwise the
/// largest photo size is used.
fn telegram_media(msg: &Message) -> Option<(FileId, Option<String>, Option<String>)> {
    if let Some(doc) = msg.document() {
        return Some((
            doc.file.id.clone(),
            doc.file_name.clone(),
            doc.mime_type.as_ref().map(|m| m.to_string()),
        ));
    }
    if let Some(photo) = msg.photo().and_then(<[_]>::last) {
        return Some((photo.file.id.clone(), None, Some("image/jpeg".to_owned())));
    }
    None
}

/// Download Telegram media via `get_file` + the file download endpoint, upload
/// it to the cokret blob store, and submit a media message.
#[allow(clippy::too_many_arguments)]
async fn forward_media(
    bot: &Bot,
    ctx: &Arc<MessageContext>,
    token: &str,
    channel: &str,
    user: &str,
    msg: &Message,
    file_id: FileId,
    filename: Option<String>,
    mime: Option<String>,
) -> Result<()> {
    let file = bot
        .get_file(file_id)
        .await
        .map_err(|e| BridgeError::App(format!("Telegram get_file failed: {e}")))?;
    let url = format!("https://api.telegram.org/file/bot{token}/{}", file.path);
    let media = ctx
        .download_external_media(&url, None, &["api.telegram.org"])
        .await?;
    let mime = mime.unwrap_or_else(|| "application/octet-stream".to_owned());
    let blob_ref = ctx.upload_blob(&media.bytes, &mime).await?;

    let caption = msg.caption().unwrap_or_default().to_owned();
    let attachment = Attachment {
        blob_ref,
        media_type: Some(mime),
        filename,
        size: Some(media.bytes.len() as u64),
        caption: caption.clone(),
    };
    let inbound = InboundAppMessage {
        app_channel: channel.to_owned(),
        app_user: user.to_owned(),
        app_message_id: msg.id.0.to_string(),
        body: caption,
    };
    ctx.submit_media_message(inbound, attachment).await?;
    Ok(())
}
