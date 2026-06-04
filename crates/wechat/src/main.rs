//! cokret-bridge-wechat executable entry point.

mod wechat;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::wechat::WechatApp;

#[derive(Parser, Debug)]
#[command(
    name = "cokret-bridge-wechat",
    version,
    about = "cokret <-> WeChat bridge"
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

    // WeChat Work uses corp_id/corp_secret; Official Accounts use app_id/app_secret. Both are accepted,
    // preferring corp_id and falling back to app_id, passed to the adapter as a unified "credential id".
    let cred_id = config
        .app
        .get("corp_id")
        .or_else(|| config.app.get("app_id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.corp_id or app_id is missing"))?
        .to_owned();
    let cred_secret = config
        .app
        .get("corp_secret")
        .or_else(|| config.app.get("app_secret"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.corp_secret or app_secret is missing"))?
        .to_owned();
    // WeChat Work requires agent_id to send app messages (Official Account customer-service messages do not).
    let agent_id = config.app.get("agent_id").and_then(|v| v.as_i64());

    run_message_bridge(config, move |_ctx: Arc<_>| {
        Ok(WechatApp::new(cred_id, cred_secret, agent_id))
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
