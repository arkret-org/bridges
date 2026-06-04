//! Discord adapter (serenity).
//!
//! - Inbound (Discord → cokret): once the gateway `EventHandler::message`
//!   receives a message, it calls [`MessageContext::submit_app_message`].
//! - Outbound (cokret → Discord): [`MessageBridge::send_to_app`] uses the serenity
//!   HTTP client to send a message to the channel.

use std::sync::Arc;

use async_trait::async_trait;
use cokret_bridge_messaging::InboundAppMessage;
use cokret_bridge_messaging::{AppMessageRef, MessageBridge, MessageContext, OutboundAppMessage};
use cokret_bridge_runtime::{BridgeError, Result};
use serenity::all::{ChannelId, GatewayIntents, Http, Message};
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
        _ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let channel_raw: u64 = msg.app_channel.parse().map_err(|_| {
            BridgeError::App(format!("invalid Discord channel id: {}", msg.app_channel))
        })?;
        let channel = ChannelId::new(channel_raw);
        let body = format!("**{}**: {}", msg.sender_display, msg.body);
        let sent = channel
            .say(self.http.as_ref(), body)
            .await
            .map_err(|e| BridgeError::App(format!("Discord send failed: {e}")))?;
        Ok(AppMessageRef {
            app_message_id: sent.id.to_string(),
        })
    }
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
        let inbound = InboundAppMessage {
            app_channel: m.channel_id.to_string(),
            app_user: m.author.id.to_string(),
            app_message_id: m.id.to_string(),
            body: m.content.clone(),
        };
        if let Err(e) = self.ctx.submit_app_message(inbound).await {
            tracing::warn!(error = %e, "Discord → cokret submission failed");
        }
    }
}
