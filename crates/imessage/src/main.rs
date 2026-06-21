//! cokret-bridge-imessage executable entry point.

mod imessage;

use cokret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::imessage::IMessageApp;

/// iMessage is sent/received via HTTP gateways such as BlueBubbles / AirMessage.
#[derive(Debug, Deserialize)]
struct AppConfig {
    gateway_url: String,
    password: Option<String>,
    /// Optional shared secret guarding the inbound `/webhooks/imessage` endpoint.
    webhook_secret: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("cokret <-> iMessage bridge", |app: AppConfig, _ctx| {
        Ok(IMessageApp::new(
            app.gateway_url,
            app.password,
            app.webhook_secret,
        ))
    })
    .await
}
