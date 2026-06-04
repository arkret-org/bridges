//! cokret-bridge-dingtalk executable entry point.

mod dingtalk;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::dingtalk::DingTalkApp;

#[derive(Parser, Debug)]
#[command(
    name = "cokret-bridge-dingtalk",
    version,
    about = "cokret <-> DingTalk bridge"
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

    // DingTalk enterprise internal app credentials: app_key/app_secret are used to obtain an access_token;
    // robot_code identifies the robot. All three are read from config.app.
    let app_key = config
        .app
        .get("app_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.app_key is missing"))?
        .to_owned();
    let app_secret = config
        .app
        .get("app_secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.app_secret is missing"))?
        .to_owned();
    let robot_code = config
        .app
        .get("robot_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.robot_code is missing"))?
        .to_owned();

    run_message_bridge(config, move |_ctx: Arc<_>| {
        Ok(DingTalkApp::new(app_key, app_secret, robot_code))
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
