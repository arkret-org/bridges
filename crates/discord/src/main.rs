//! arkret-bridge-discord executable entry point.

mod discord;

use arkret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::discord::DiscordApp;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppConfig {
    /// Discord bot token used by the serenity gateway client.
    bot_token: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("arkret <-> Discord bridge", |app: AppConfig, _ctx| {
        Ok(DiscordApp::new(app.bot_token))
    })
    .await
}
