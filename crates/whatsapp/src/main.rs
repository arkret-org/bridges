//! cokret-bridge-whatsapp executable entry point.

mod whatsapp;

use cokret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::whatsapp::WhatsAppApp;

/// WhatsApp Cloud API credentials.
#[derive(Debug, Deserialize)]
struct AppConfig {
    /// Sender phone number ID (outbound URL path segment).
    phone_number_id: String,
    /// Cloud API permanent/temporary token (Bearer).
    access_token: String,
    /// Webhook verification echo token (used for inbound onboarding).
    verify_token: String,
    /// Meta app secret used to verify X-Hub-Signature-256 on each POST.
    app_secret: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("cokret <-> WhatsApp bridge", |app: AppConfig, _ctx| {
        Ok(WhatsAppApp::new(
            app.phone_number_id,
            app.access_token,
            app.verify_token,
            app.app_secret,
        ))
    })
    .await
}
