//! cokret-bridge-dingtalk executable entry point.

mod dingtalk;

use cokret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::dingtalk::DingTalkApp;

/// DingTalk enterprise internal app credentials: `app_key`/`app_secret` are
/// used to obtain an access_token; `robot_code` identifies the robot. The
/// optional inbound body HMAC secret is required to accept message deliveries.
#[derive(Deserialize)]
struct AppConfig {
    app_key: String,
    app_secret: String,
    robot_code: String,
    webhook_body_hmac_secret: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("cokret <-> DingTalk bridge", |app: AppConfig, ctx| {
        Ok(DingTalkApp::new(
            app.app_key,
            app.app_secret,
            app.robot_code,
            app.webhook_body_hmac_secret,
            ctx.token_cache("dingtalk_access_token"),
        ))
    })
    .await
}
