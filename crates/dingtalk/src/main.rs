//! cokret-bridge-dingtalk executable entry point.

mod dingtalk;

use cokret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::dingtalk::DingTalkApp;

/// DingTalk enterprise internal app credentials: `app_key`/`app_secret` are
/// used to obtain an access_token; `robot_code` identifies the robot.
#[derive(Debug, Deserialize)]
struct AppConfig {
    app_key: String,
    app_secret: String,
    robot_code: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("cokret <-> DingTalk bridge", |app: AppConfig, _ctx| {
        Ok(DingTalkApp::new(app.app_key, app.app_secret, app.robot_code))
    })
    .await
}
