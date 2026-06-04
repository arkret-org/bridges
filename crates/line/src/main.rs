//! cokret-bridge-line executable entry point.

mod line;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::line::LineApp;

#[derive(Parser, Debug)]
#[command(name = "cokret-bridge-line", version, about = "cokret <-> LINE bridge")]
struct Cli {
    /// Config file path (.yaml or .kdl).
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    logging::init(&config.logging);

    // LINE Messaging API credentials:
    // - channel_access_token: used to push messages (Bearer).
    // - channel_secret: used for webhook signature verification (used for inbound onboarding).
    let channel_access_token = config
        .app
        .get("channel_access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.channel_access_token missing"))?
        .to_owned();
    let channel_secret = config
        .app
        .get("channel_secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.channel_secret missing"))?
        .to_owned();

    run_message_bridge(config, move |_ctx: Arc<_>| {
        Ok(LineApp::new(channel_access_token, channel_secret))
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
