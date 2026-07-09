//! arkret-bridge-qq executable entry point.

mod qq;

use arkret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::qq::QqApp;

/// OneBot onboarding configuration.
#[derive(Deserialize)]
struct AppConfig {
    /// OneBot HTTP API base URL.
    onebot_url: String,
    access_token: Option<String>,
    /// OneBot HTTP POST signing secret used to verify X-Signature.
    signing_secret: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("arkret <-> QQ bridge", |app: AppConfig, _ctx| {
        Ok(QqApp::new(
            app.onebot_url,
            app.access_token,
            app.signing_secret,
        ))
    })
    .await
}
