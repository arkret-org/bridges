//! arkret-bridge-whatsapp executable entry point.

mod whatsapp;

use cokret_bridge_messaging::{DEFAULT_GRAPH_API_VERSION, bridge_main};
use serde::Deserialize;

use crate::whatsapp::WhatsAppApp;

/// WhatsApp Cloud API credentials.
#[derive(Deserialize)]
struct AppConfig {
    /// Sender phone number ID (outbound URL path segment).
    phone_number_id: String,
    /// Cloud API permanent/temporary token (Bearer).
    access_token: String,
    /// Webhook verification echo token (used for inbound onboarding).
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
    bridge_main("arkret <-> WhatsApp bridge", |app: AppConfig, _ctx| {
        Ok(WhatsAppApp::new(
            app.phone_number_id,
            app.access_token,
            app.verify_token,
            app.app_secret,
            app.graph_api_version
                .unwrap_or_else(|| DEFAULT_GRAPH_API_VERSION.to_owned()),
        ))
    })
    .await
}
