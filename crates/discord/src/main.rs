//! cokret-bridge-discord executable entry point.

mod discord;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::discord::DiscordApp;

#[derive(Parser, Debug)]
#[command(
    name = "cokret-bridge-discord",
    version,
    about = "cokret <-> Discord bridge"
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

    run_message_bridge(config, move |_ctx: Arc<_>| Ok(DiscordApp::new(token)))
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))
}
