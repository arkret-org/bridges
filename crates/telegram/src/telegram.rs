//! Telegram adapter (teloxide long polling).
//!
//! - Inbound (Telegram → arkret): once `teloxide::repl` long polling receives a text message, it
//!   calls [`MessageContext::submit_app_message`].
//! - Outbound (arkret → Telegram): [`MessageBridge::send_to_app`] uses the Bot HTTP `send_message`
//!   to deliver to the corresponding chat.

use std::sync::Arc;

use async_trait::async_trait;
use cokret_bridge_messaging::runtime::{BridgeError, Result, redact_sensitive_url_values};
use cokret_bridge_messaging::{
    AppMessageRef, ExternalMediaRequest, InboundAppMessage, MessageBridge,
    MessageBridgeCapabilities, MessageContext, OutboundAppMessage, SenderRenderStyle,
};
use teloxide::prelude::*;
use teloxide::types::{ChatId, FileId, InputFile};

/// Telegram bridge adapter.
pub struct TelegramApp {
    token: String,
    /// A single `Bot` (which owns a reqwest client) cached for reuse across the
    /// receive loop and every outbound send, rather than rebuilt per message.
    bot: Bot,
}

impl TelegramApp {
    pub fn new(token: impl Into<String>) -> Self {
        let token = token.into();
        let bot = Bot::new(&token);
        Self { token, bot }
    }
}

#[async_trait]
impl MessageBridge for TelegramApp {
    fn name(&self) -> &str {
        "telegram"
    }

    fn capabilities(&self) -> MessageBridgeCapabilities {
        MessageBridgeCapabilities::native_outbound_attachments()
    }

    async fn run(self: Arc<Self>, ctx: Arc<MessageContext>) -> Result<()> {
        let bot = self.bot.clone();
        let token = self.token.clone();

        // teloxide long-polling receive loop; submit text and media to the core.
        teloxide::repl(bot, move |bot: Bot, msg: Message| {
            let ctx = ctx.clone();
            let token = token.clone();
            async move {
                // Defense-in-depth loop guard, aligning with the other gateway
                // bridges (Discord `author.bot`, Slack `bot_id`, Zulip
                // `sender_email`): skip messages authored by any bot, including
                // this bot's own echoes. Telegram's privacy mode usually hides
                // these, but a group with privacy off (or multiple bots) can
                // surface them. The authoritative loop guard remains in the
                // shared layer (`on_cokret_event`).
                if msg.from.as_ref().map(|u| u.is_bot).unwrap_or(false) {
                    return respond(());
                }
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
                    if let Err(e) = ctx.submit_app_message(inbound.clone()).await
                        && ctx.report_inbound_failure("telegram", &inbound, &e).await
                    {
                        return telegram_retry_error("Telegram text submit retriable failure");
                    }
                }

                if let Some((file_id, filename, mime)) = telegram_media(&msg)
                    && let Err(e) = forward_media(
                        &bot, &ctx, &token, &channel, &user, &msg, file_id, filename, mime,
                    )
                    .await
                {
                    // The media forwarder already ran the inbound failure
                    // audit; only translate retriability here.
                    if e.is_retriable() {
                        return telegram_retry_error("Telegram media submit retriable failure");
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
        let chat = parse_telegram_chat_id(&msg.app_channel)?;
        let bot = &self.bot;
        let body = msg.rendered_body(SenderRenderStyle::Plain);

        // With an attachment: download the arkret blob and send it as a document.
        if let Some(att) = &msg.attachment {
            let bytes = ctx.download_blob(&att.blob_ref).await?;
            let filename = att.filename.clone().unwrap_or_else(|| "file".to_owned());
            let file = InputFile::memory(bytes).file_name(filename);
            let sent = bot
                .send_document(chat, file)
                .caption(body)
                .await
                .map_err(|e| {
                    BridgeError::App(format!(
                        "Telegram document send failed: {}",
                        redact_sensitive_url_values(e.to_string())
                    ))
                })?;
            return Ok(AppMessageRef {
                app_message_id: sent.id.0.to_string(),
            });
        }

        let sent = bot.send_message(chat, body).await.map_err(|e| {
            BridgeError::App(format!(
                "Telegram send failed: {}",
                redact_sensitive_url_values(e.to_string())
            ))
        })?;
        Ok(AppMessageRef {
            app_message_id: sent.id.0.to_string(),
        })
    }
}

fn telegram_retry_error(message: &'static str) -> teloxide::requests::ResponseResult<()> {
    Err(teloxide::RequestError::Io(Arc::new(std::io::Error::other(
        message,
    ))))
}

fn parse_telegram_chat_id(channel: &str) -> Result<ChatId> {
    let chat_raw: i64 = channel
        .parse()
        .map_err(|_| BridgeError::App(format!("invalid Telegram chat id: {channel}")))?;
    Ok(ChatId(chat_raw))
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

/// Resolve the Telegram file download URL via `get_file` (platform-specific
/// step), then hand off to the shared
/// [`MessageContext::forward_external_media`] skeleton (download → blob upload
/// → media message + failure audit).
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
) -> Result<String> {
    let caption = msg.caption().unwrap_or_default().to_owned();
    let inbound = InboundAppMessage {
        app_channel: channel.to_owned(),
        app_user: user.to_owned(),
        app_message_id: msg.id.0.to_string(),
        // The caption becomes the media message body/attachment caption.
        body: caption,
    };
    let file = match bot.get_file(file_id).await {
        Ok(file) => file,
        Err(e) => {
            let e = BridgeError::App(format!(
                "Telegram get_file failed: {}",
                redact_sensitive_url_values(e.to_string())
            ));
            // Platform-specific pre-step failures get the same inbound-failure
            // audit the shared forwarder applies.
            ctx.report_inbound_failure("telegram", &inbound, &e).await;
            return Err(e);
        }
    };
    let url = telegram_file_download_url(token, &file.path);
    ctx.forward_external_media(
        "telegram",
        inbound,
        ExternalMediaRequest {
            url: &url,
            bearer_token: None,
            allowed_hosts: &["api.telegram.org"],
            mime_hint: mime,
            filename,
        },
    )
    .await
}

fn telegram_file_download_url(token: &str, file_path: &str) -> String {
    format!("https://api.telegram.org/file/bot{token}/{file_path}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegram_chat_id_parser_accepts_signed_numeric_ids() {
        assert_eq!(parse_telegram_chat_id("12345").unwrap().0, 12345);
        assert_eq!(parse_telegram_chat_id("-10012345").unwrap().0, -10012345);
    }

    #[test]
    fn telegram_chat_id_parser_rejects_non_numeric_ids() {
        assert!(parse_telegram_chat_id("@channel").is_err());
        assert!(parse_telegram_chat_id("").is_err());
    }

    #[test]
    fn telegram_file_download_url_uses_bot_file_endpoint() {
        assert_eq!(
            telegram_file_download_url("TOKEN", "documents/file.dat"),
            "https://api.telegram.org/file/botTOKEN/documents/file.dat"
        );
    }
}
