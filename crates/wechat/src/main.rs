//! cokret-bridge-wechat executable entry point.

mod wechat;

use cokret_bridge_messaging::bridge_main;
use cokret_bridge_runtime::BridgeError;
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
    /// Optional EncodingAESKey (43-char base64). When set, inbound callbacks run
    /// in encrypted **safe mode** (AES-256-CBC + `msg_signature`). Required for
    /// WeChat Work inbound, whose callbacks are always encrypted.
    encoding_aes_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("cokret <-> WeChat bridge", |app: AppConfig, _ctx| {
        let has_safe_mode = app
            .encoding_aes_key
            .as_ref()
            .map(|k| !k.trim().is_empty())
            .unwrap_or(false);
        // WeChat Work callbacks are always encrypted, so Work inbound requires an
        // EncodingAESKey for safe mode. Fail closed without one.
        if app.agent_id.is_some() && !has_safe_mode {
            return Err(BridgeError::Config(
                "WeChat Work inbound callbacks require encrypted safe mode; set encoding_aes_key (43-char EncodingAESKey) or use Official Account mode"
                    .to_owned(),
            ));
        }
        WeChatApp::from_config(
            app.corp_id,
            app.corp_secret,
            app.agent_id,
            app.webhook_token,
            app.encoding_aes_key,
        )
    })
    .await
}
