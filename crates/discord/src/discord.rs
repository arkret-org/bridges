//! Discord adapter (serenity).
//!
//! - Inbound (Discord → arkret): once the gateway `EventHandler::message` receives a message, it
//!   calls [`MessageContext::submit_app_message`].
//! - Outbound (arkret → Discord): [`MessageBridge::send_to_app`] uses the serenity HTTP client to
//!   send a message to the channel.

use std::sync::Arc;

use arkret_bridge_messaging::runtime::{BridgeError, Result};
use arkret_bridge_messaging::{
    AppMessageRef, ExternalMediaRequest, InboundAppMessage, MessageBridge,
    MessageBridgeCapabilities, MessageContext, OutboundAppMessage, SenderRenderStyle,
};
use async_trait::async_trait;
use serenity::all::{
    ChannelId, CreateAttachment, CreateMessage, GatewayIntents, Http, Message, MessageId,
};
use serenity::client::{Context as SerenityContext, EventHandler};

/// Discord bridge adapter.
pub struct DiscordApp {
    token: String,
    http: Arc<Http>,
}

impl DiscordApp {
    pub fn new(token: impl Into<String>) -> Self {
        let token = token.into();
        let http = Arc::new(Http::new(&token));
        Self { token, http }
    }
}

#[async_trait]
impl MessageBridge for DiscordApp {
    fn name(&self) -> &str {
        "discord"
    }

    fn capabilities(&self) -> MessageBridgeCapabilities {
        MessageBridgeCapabilities::native_outbound_attachments()
    }

    async fn run(self: Arc<Self>, ctx: Arc<MessageContext>) -> Result<()> {
        let intents = GatewayIntents::GUILD_MESSAGES
            | GatewayIntents::DIRECT_MESSAGES
            | GatewayIntents::MESSAGE_CONTENT;

        let mut client = serenity::Client::builder(&self.token, intents)
            .event_handler(Handler { ctx })
            .await
            .map_err(|e| BridgeError::App(format!("failed to build serenity client: {e}")))?;

        client
            .start()
            .await
            .map_err(|e| BridgeError::App(format!("serenity client failed: {e}")))
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let channel = parse_discord_channel_id(&msg.app_channel)?;
        let body = msg.rendered_body(SenderRenderStyle::MarkdownBold);

        // With an attachment: download the arkret blob and upload it to Discord.
        if let Some(att) = &msg.attachment {
            let bytes = ctx.download_blob(&att.blob_ref).await?;
            let filename = att.filename.clone().unwrap_or_else(|| "file".to_owned());
            let file = CreateAttachment::bytes(bytes, filename);
            let message = CreateMessage::new().content(body).add_file(file);
            let sent = channel
                .send_message(self.http.as_ref(), message)
                .await
                .map_err(|e| BridgeError::App(format!("Discord file send failed: {e}")))?;
            return Ok(AppMessageRef {
                app_message_id: sent.id.to_string(),
            });
        }

        let sent = channel
            .say(self.http.as_ref(), body)
            .await
            .map_err(|e| BridgeError::App(format!("Discord send failed: {e}")))?;
        Ok(AppMessageRef {
            app_message_id: sent.id.to_string(),
        })
    }

    async fn redact_in_app(
        &self,
        _ctx: Arc<MessageContext>,
        app_channel: &str,
        app_message_id: &str,
    ) -> Result<()> {
        let channel = parse_discord_channel_id(app_channel)?;
        let message = parse_discord_message_id(app_message_id)?;
        channel
            .delete_message(self.http.as_ref(), message)
            .await
            .map_err(|e| BridgeError::App(format!("Discord delete failed: {e}")))
    }
}

fn parse_discord_channel_id(channel: &str) -> Result<ChannelId> {
    let channel_raw: u64 = channel
        .parse()
        .map_err(|_| BridgeError::App(format!("invalid Discord channel id: {channel}")))?;
    Ok(ChannelId::new(channel_raw))
}

fn parse_discord_message_id(message: &str) -> Result<MessageId> {
    let message_raw: u64 = message
        .parse()
        .map_err(|_| BridgeError::App(format!("invalid Discord message id: {message}")))?;
    Ok(MessageId::new(message_raw))
}

/// Gateway event handling: forward inbound Discord messages to the core.
struct Handler {
    ctx: Arc<MessageContext>,
}

#[async_trait]
impl EventHandler for Handler {
    async fn message(&self, _c: SerenityContext, m: Message) {
        if m.author.bot {
            return;
        }
        let channel = m.channel_id.to_string();
        let user = m.author.id.to_string();

        // Forward the text body (if any) as a text message.
        if !m.content.is_empty() {
            let inbound = InboundAppMessage {
                app_channel: channel.clone(),
                app_user: user.clone(),
                app_message_id: m.id.to_string(),
                body: m.content.clone(),
            };
            if let Err(e) = self.ctx.submit_app_message(inbound.clone()).await {
                self.ctx
                    .report_inbound_failure("discord", &inbound, &e)
                    .await;
            }
        }

        // Forward each attachment through the shared media skeleton (download
        // from the Discord CDN → blob upload → media message). The forwarder
        // already runs the inbound failure audit on error.
        for att in &m.attachments {
            if let Err(e) = self.forward_attachment(&channel, &user, att).await {
                tracing::warn!(error = %e, url = %att.url, "Discord attachment bridging failed");
            }
        }
    }
}

impl Handler {
    async fn forward_attachment(
        &self,
        channel: &str,
        user: &str,
        att: &serenity::all::Attachment,
    ) -> Result<String> {
        // Use the attachment id as the app message id so it maps distinctly from
        // the text message.
        let inbound = InboundAppMessage {
            app_channel: channel.to_owned(),
            app_user: user.to_owned(),
            app_message_id: att.id.to_string(),
            body: String::new(),
        };
        self.ctx
            .forward_external_media(
                "discord",
                inbound,
                ExternalMediaRequest {
                    url: &att.url,
                    authorization: None,
                    allowed_hosts: &["cdn.discordapp.com", "media.discordapp.net"],
                    mime_hint: att.content_type.clone(),
                    filename: Some(att.filename.clone()),
                },
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discord_channel_id_parser_accepts_numeric_ids() {
        assert_eq!(parse_discord_channel_id("123456").unwrap().get(), 123456);
    }

    #[test]
    fn discord_channel_id_parser_rejects_non_numeric_ids() {
        assert!(parse_discord_channel_id("general").is_err());
        assert!(parse_discord_channel_id("").is_err());
    }

    #[test]
    fn discord_message_id_parser_accepts_numeric_ids() {
        assert_eq!(parse_discord_message_id("987654").unwrap().get(), 987654);
    }

    #[test]
    fn discord_message_id_parser_rejects_non_numeric_ids() {
        assert!(parse_discord_message_id("not-a-message").is_err());
        assert!(parse_discord_message_id("").is_err());
    }
}
