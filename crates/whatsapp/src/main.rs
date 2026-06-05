//! cokret-bridge-whatsapp executable entry point.

mod whatsapp;

use std::sync::Arc;

use clap::Parser;
use cokret_bridge_messaging::run_message_bridge;
use cokret_bridge_runtime::{Config, logging};

use crate::whatsapp::WhatsAppApp;

#[derive(Parser, Debug)]
#[command(
    name = "cokret-bridge-whatsapp",
    version,
    about = "cokret <-> WhatsApp bridge"
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

    // WhatsApp Cloud API credentials:
    // - phone_number_id: sender phone number ID (outbound URL path segment).
    // - access_token: Cloud API permanent/temporary token (Bearer).
    // - verify_token: webhook verification echo token (used for inbound onboarding).
    let phone_number_id = config
        .app
        .get("phone_number_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.phone_number_id missing"))?
        .to_owned();
    let access_token = config
        .app
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.access_token missing"))?
        .to_owned();
    let verify_token = config
        .app
        .get("verify_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.verify_token missing"))?
        .to_owned();
    // app_secret: Meta app secret used to verify X-Hub-Signature-256 on each POST.
    let app_secret = config
        .app
        .get("app_secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("config.app.app_secret missing"))?
        .to_owned();

    run_message_bridge(config, move |_ctx: Arc<_>| {
        Ok(WhatsAppApp::new(
            phone_number_id,
            access_token,
            verify_token,
            app_secret,
        ))
    })
    .await
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}
