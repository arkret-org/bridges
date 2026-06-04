//! cokret-bridge-teams executable entry point.

mod teams;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::teams::TeamsApp;

#[derive(Parser, Debug)]
#[command(
    name = "cokret-bridge-teams",
    version,
    about = "cokret <-> Microsoft Teams bridge"
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

    // Bot Framework application credentials.
    let app_id = config
        .app
        .get("app_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.app_id is missing"))?
        .to_owned();
    let app_password = config
        .app
        .get("app_password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.app_password is missing"))?
        .to_owned();
    // The Bot Framework serviceUrl assembled when sending outbound messages (e.g.
    // https://smba.trafficmanager.net/...).
    let service_url = config
        .app
        .get("service_url")
        .and_then(|v| v.as_str())
        .unwrap_or("https://smba.trafficmanager.net/amer/")
        .to_owned();

    run_message_bridge(config, move |_ctx: Arc<_>| {
        Ok(TeamsApp::new(app_id, app_password, service_url))
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
