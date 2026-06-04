//! cokret-bridge-slack executable entry point.

mod slack;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::slack::SlackApp;

#[derive(Parser, Debug)]
#[command(
    name = "cokret-bridge-slack",
    version,
    about = "cokret <-> Slack bridge"
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

    // bot_token: the `xoxb-` token used to authenticate the Web API (chat.postMessage).
    let bot_token = config
        .app
        .get("bot_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.bot_token is missing"))?
        .to_owned();

    // app_token: the `xapp-` token used to establish the socket mode connection.
    let app_token = config
        .app
        .get("app_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.app_token is missing"))?
        .to_owned();

    run_message_bridge(config, move |_ctx: Arc<_>| {
        Ok(SlackApp::new(bot_token, app_token))
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
