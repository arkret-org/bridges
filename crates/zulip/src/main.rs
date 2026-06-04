//! cokret-bridge-zulip executable entry point.

mod zulip;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::zulip::ZulipApp;

#[derive(Parser, Debug)]
#[command(
    name = "cokret-bridge-zulip",
    version,
    about = "cokret <-> Zulip bridge"
)]
struct Cli {
    /// Configuration file path (.yaml or .kdl).
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    logging::init(&config.logging);

    let site = config
        .app
        .get("site")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.site is missing"))?
        .trim_end_matches('/')
        .to_owned();
    let bot_email = config
        .app
        .get("bot_email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.bot_email is missing"))?
        .to_owned();
    let api_key = config
        .app
        .get("api_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.api_key is missing"))?
        .to_owned();

    run_message_bridge(config, move |_ctx: Arc<_>| {
        Ok(ZulipApp::new(site, bot_email, api_key))
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
