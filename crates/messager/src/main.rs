//! cokret-bridge-messager executable entry point.

mod messager;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::messager::MessagerApp;

#[derive(Parser, Debug)]
#[command(
    name = "cokret-bridge-messager",
    version,
    about = "cokret <-> Messenger bridge"
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

    // Facebook Messenger: the Page access token is used for sending, verify_token for webhook verification.
    let page_access_token = config
        .app
        .get("page_access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.page_access_token missing"))?
        .to_owned();
    let verify_token = config
        .app
        .get("verify_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());
    // app_secret: Meta app secret used to verify X-Hub-Signature-256 on each POST.
    let app_secret = config
        .app
        .get("app_secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.app_secret missing"))?
        .to_owned();

    run_message_bridge(config, move |_ctx: Arc<_>| {
        Ok(MessagerApp::new(
            page_access_token,
            verify_token,
            app_secret,
        ))
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
