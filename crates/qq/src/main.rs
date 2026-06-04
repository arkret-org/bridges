//! cokret-bridge-qq executable entry point.

mod qq;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::qq::QqApp;

#[derive(Parser, Debug)]
#[command(name = "cokret-bridge-qq", version, about = "cokret <-> QQ bridge")]
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

    // OneBot onboarding: onebot_url (HTTP API base) + access_token.
    let onebot_url = config
        .app
        .get("onebot_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.onebot_url missing"))?
        .to_owned();
    let access_token = config
        .app
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    run_message_bridge(config, move |_ctx: Arc<_>| {
        Ok(QqApp::new(onebot_url, access_token))
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
