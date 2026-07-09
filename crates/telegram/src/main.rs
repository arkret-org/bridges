//! arkret-bridge-telegram executable entry point.

mod telegram;

use arkret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::telegram::TelegramApp;

#[derive(Deserialize)]
struct AppConfig {
    /// Telegram bot token used by the teloxide long-polling client.
    bot_token: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("arkret <-> Telegram bridge", |app: AppConfig, _ctx| {
        Ok(TelegramApp::new(app.bot_token))
    })
    .await
}
