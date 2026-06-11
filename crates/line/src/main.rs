//! cokret-bridge-line executable entry point.

mod line;

use cokret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::line::LineApp;

/// LINE Messaging API credentials.
#[derive(Debug, Deserialize)]
struct AppConfig {
    /// Used to push messages (Bearer).
    channel_access_token: String,
    /// Used for webhook signature verification (inbound onboarding).
    channel_secret: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("cokret <-> LINE bridge", |app: AppConfig, _ctx| {
        Ok(LineApp::new(app.channel_access_token, app.channel_secret))
    })
    .await
}
