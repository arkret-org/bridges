//! arkret-bridge-slack executable entry point.

mod slack;

use arkret_bridge_messaging::bridge_main;
use serde::Deserialize;

use crate::slack::SlackApp;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppConfig {
    /// The `xoxb-` token used to authenticate the Web API (chat.postMessage).
    bot_token: String,
    /// The `xapp-` token used to establish the socket mode connection.
    app_token: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("arkret <-> Slack bridge", |app: AppConfig, _ctx| {
        Ok(SlackApp::new(app.bot_token, app.app_token))
    })
    .await
}
