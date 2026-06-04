//! cokret-bridge-feishu executable entry point.

mod feishu;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::feishu::FeishuApp;

#[derive(Parser, Debug)]
#[command(
    name = "cokret-bridge-feishu",
    version,
    about = "cokret <-> Feishu bridge"
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

    let app_id = config
        .app
        .get("app_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.app_id is missing"))?
        .to_owned();
    let app_secret = config
        .app
        .get("app_secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.app_secret is missing"))?
        .to_owned();

    run_message_bridge(config, move |_ctx: Arc<_>| {
        Ok(FeishuApp::new(app_id, app_secret))
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
