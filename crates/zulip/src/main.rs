//! cokret-bridge-zulip executable entry point.

mod zulip;

use cokret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::zulip::ZulipApp;

#[derive(Debug, Deserialize)]
struct AppConfig {
    /// Zulip server base URL (trailing slashes are trimmed).
    site: String,
    bot_email: String,
    api_key: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("cokret <-> Zulip bridge", |app: AppConfig, _ctx| {
        Ok(ZulipApp::new(
            app.site.trim_end_matches('/').to_owned(),
            app.bot_email,
            app.api_key,
        ))
    })
    .await
}
