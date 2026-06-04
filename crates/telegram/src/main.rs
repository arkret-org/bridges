//! cokret-bridge-telegram executable entry point.

mod telegram;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::telegram::TelegramApp;

#[derive(Parser, Debug)]
#[command(
    name = "cokret-bridge-telegram",
    version,
    about = "cokret <-> Telegram bridge"
)]
struct Cli {
    /// Path to the config file (.yaml or .kdl).
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    logging::init(&config.logging);

    let token = config
        .app
        .get("bot_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.bot_token is missing"))?
        .to_owned();

    run_message_bridge(config, move |_ctx: Arc<_>| Ok(TelegramApp::new(token)))
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))
}
