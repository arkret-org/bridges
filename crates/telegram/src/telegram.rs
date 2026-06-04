//! Telegram adapter (teloxide long polling).
//!
//! - Inbound (Telegram → cokret): once `teloxide::repl` long polling receives a
//!   text message, it calls [`MessageContext::submit_app_message`].
//! - Outbound (cokret → Telegram): [`MessageBridge::send_to_app`] uses the Bot HTTP
//!   `send_message` to deliver to the corresponding chat.

use std::sync::Arc;

use async_trait::async_trait;
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
};
use cokret_bridge_runtime::{BridgeError, Result};
use teloxide::prelude::*;
use teloxide::types::ChatId;

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

        // teloxide long-polling receive loop; submit each text message to the core.
        teloxide::repl(bot, move |msg: Message| {
            let ctx = ctx.clone();
            async move {
                if let Some(text) = msg.text() {
                    // Only forward user text (ignore the bot itself and messages without text).
                    let from_id = msg
                        .from
                        .as_ref()
                        .map(|u| u.id.0.to_string())
                        .unwrap_or_default();
                    let inbound = InboundAppMessage {
                        app_channel: msg.chat.id.0.to_string(),
                        app_user: from_id,
                        app_message_id: msg.id.0.to_string(),
                        body: text.to_owned(),
                    };
                    if let Err(e) = ctx.submit_app_message(inbound).await {
                        tracing::warn!(error = %e, "Telegram → cokret submission failed");
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
        _ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let chat_raw: i64 = msg.app_channel.parse().map_err(|_| {
            BridgeError::App(format!("invalid Telegram chat id: {}", msg.app_channel))
        })?;
        let bot = Bot::new(&self.token);
        let body = format!("{}: {}", msg.sender_display, msg.body);
        let sent = bot
            .send_message(ChatId(chat_raw), body)
            .await
            .map_err(|e| BridgeError::App(format!("Telegram send failed: {e}")))?;
        Ok(AppMessageRef {
            app_message_id: sent.id.0.to_string(),
        })
    }
}
