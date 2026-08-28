//! arkret-bridge-wechat executable entry point.

mod wechat;

use arkret_bridge_messaging::bridge_main;
use arkret_bridge_messaging::runtime::BridgeError;
use serde::Deserialize;

use crate::wechat::WechatApp;

/// WeChat Work and Official Accounts both use the bridge-owned canonical
/// `credential_id` / `credential_secret` configuration fields. The adapter
/// maps them to the external API parameter names selected by `agent_id`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppConfig {
    credential_id: String,
    credential_secret: String,
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
    bridge_main("arkret <-> WeChat bridge", |app: AppConfig, ctx| {
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
        WechatApp::new(
            app.credential_id,
            app.credential_secret,
            app.agent_id,
            app.webhook_token,
            app.encoding_aes_key,
            ctx.token_cache("wechat_access_token"),
        )
    })
    .await
}
