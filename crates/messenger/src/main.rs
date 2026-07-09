//! arkret-bridge-messenger executable entry point.

mod messenger;

use cokret_bridge_messaging::{DEFAULT_GRAPH_API_VERSION, bridge_main};
use serde::Deserialize;

use crate::messenger::MessengerApp;

/// Facebook Messenger credentials.
#[derive(Deserialize)]
struct AppConfig {
    /// Page access token used for sending (Bearer).
    page_access_token: String,
    /// Webhook verification token; required (parity with WhatsApp) so a missing
    /// value fails at startup rather than at the first Meta GET handshake.
    verify_token: String,
    /// Meta app secret used to verify X-Hub-Signature-256 on each POST.
    app_secret: String,
    /// Meta Graph API version segment (e.g. `v20.0`). Optional; defaults to
    /// [`DEFAULT_GRAPH_API_VERSION`] so the version can be rolled forward via
    /// config without a code release.
    graph_api_version: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("arkret <-> Messenger bridge", |app: AppConfig, _ctx| {
        Ok(MessengerApp::new(
            app.page_access_token,
            app.verify_token,
            app.app_secret,
            app.graph_api_version
                .unwrap_or_else(|| DEFAULT_GRAPH_API_VERSION.to_owned()),
        ))
    })
    .await
}
