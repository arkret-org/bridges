//! cokret-bridge-imessage executable entry point.

mod imessage;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::imessage::IMessageApp;

#[derive(Parser, Debug)]
#[command(
    name = "cokret-bridge-imessage",
    version,
    about = "cokret <-> iMessage bridge"
)]
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

    // iMessage is sent/received via HTTP gateways such as BlueBubbles / AirMessage.
    let gateway_url = config
        .app
        .get("gateway_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.gateway_url missing"))?
        .to_owned();
    let password = config
        .app
        .get("password")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    run_message_bridge(config, move |_ctx: Arc<_>| {
        Ok(IMessageApp::new(gateway_url, password))
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
