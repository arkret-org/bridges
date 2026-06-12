//! cokret-bridge-feishu executable entry point.

mod feishu;

use cokret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::feishu::FeishuApp;

#[derive(Debug, Deserialize)]
struct AppConfig {
    app_id: String,
    app_secret: String,
    /// Event-subscription Verification Token (required, fail closed).
    verification_token: String,
    /// Optional Encrypt Key; when set, enables encrypted callback mode
    /// (AES-256-CBC decryption under `SHA256(encrypt_key)`). Leave unset for
    /// plaintext mode.
    encrypt_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("cokret <-> Feishu bridge", |app: AppConfig, _ctx| {
        Ok(FeishuApp::new(
            app.app_id,
            app.app_secret,
            app.verification_token,
            app.encrypt_key,
        ))
    })
    .await
}
