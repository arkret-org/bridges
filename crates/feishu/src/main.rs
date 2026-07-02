//! cokret-bridge-feishu executable entry point.

mod feishu;

use cokret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::feishu::FeishuApp;

#[derive(Deserialize)]
struct AppConfig {
    app_id: String,
    app_secret: String,
    /// Event-subscription Verification Token (required, fail closed).
    verification_token: String,
    /// Encrypt Key (required for production). Enables encrypted callback mode so
    /// Feishu signs every delivery with `X-Lark-Signature`; the bridge enforces
    /// per-delivery signature + freshness + replay checks. When unset the webhook
    /// router is not mounted (plaintext callbacks have no per-delivery signature,
    /// so they are refused — fail closed).
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
