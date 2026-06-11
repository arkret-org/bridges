//! cokret-bridge-wechat executable entry point.

mod wechat;

use cokret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::wechat::WeChatApp;

/// WeChat Work uses `corp_id`/`corp_secret`; Official Accounts use
/// `app_id`/`app_secret`. Both spellings are accepted (serde aliases) and
/// passed to the adapter as a unified "credential id"/secret.
#[derive(Debug, Deserialize)]
struct AppConfig {
    #[serde(alias = "app_id")]
    corp_id: String,
    #[serde(alias = "app_secret")]
    corp_secret: String,
    /// WeChat Work requires agent_id to send app messages (Official Account
    /// customer-service messages do not).
    agent_id: Option<i64>,
    /// Callback Token used to verify the inbound `signature` (required, fail closed).
    webhook_token: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("cokret <-> WeChat bridge", |app: AppConfig, _ctx| {
        Ok(WeChatApp::new(
            app.corp_id,
            app.corp_secret,
            app.agent_id,
            app.webhook_token,
        ))
    })
    .await
}
