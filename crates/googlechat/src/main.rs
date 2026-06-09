//! cokret-bridge-googlechat executable entry point.

mod googlechat;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::{run_message_bridge, webhook::JwtAuthConfig};
use cokret_bridge_runtime::{Config, logging};

use crate::googlechat::GoogleChatApp;

#[derive(Parser, Debug)]
#[command(
    name = "cokret-bridge-googlechat",
    version,
    about = "cokret <-> Google Chat bridge"
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

    let access_token = config
        .app
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.token is missing"))?
        .to_owned();
    let inbound_jwt: JwtAuthConfig = serde_json::from_value(
        config
            .app
            .get("inbound_jwt")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("config.app.inbound_jwt is missing"))?,
    )?;

    run_message_bridge(config, move |ctx: Arc<_>| {
        Ok(GoogleChatApp::new(
            access_token,
            Arc::new(cokret_bridge_messaging::webhook::JwtVerifier::new(
                inbound_jwt,
                ctx.http.clone(),
            )),
        ))
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
