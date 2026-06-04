//! DingTalk adapter (reqwest HTTP).
//!
//! - Inbound (DingTalk -> cokret): DingTalk callback messages are accepted at
//!   `/webhooks/dingtalk`.
//! - Outbound (cokret -> DingTalk): [`MessageBridge::send_to_app`] uses `ctx.http` (reqwest)
//!   to POST the DingTalk enterprise robot message-sending API.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cokret_bridge_messaging::salvo::{self, affix_state, prelude::*};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage, webhook,
};
use cokret_bridge_runtime::{BridgeError, Result};
use serde_json::{Value, json};

/// DingTalk bridge adapter.
pub struct DingTalkApp {
    /// Enterprise internal app AppKey.
    app_key: String,
    /// Enterprise internal app AppSecret.
    app_secret: String,
    /// Robot code (robotCode).
    robot_code: String,
}

impl DingTalkApp {
    pub fn new(
        app_key: impl Into<String>,
        app_secret: impl Into<String>,
        robot_code: impl Into<String>,
    ) -> Self {
        Self {
            app_key: app_key.into(),
            app_secret: app_secret.into(),
            robot_code: robot_code.into(),
        }
    }

    /// Exchanges AppKey/AppSecret for an access_token.
    ///
    /// A DingTalk access_token is valid for about 7200s; production should cache it and refresh
    /// as needed; here it is fetched before each send to keep the code readable and compilable.
    async fn fetch_access_token(&self, ctx: &Arc<MessageContext>) -> Result<String> {
        // DingTalk's new API for obtaining an access_token.
        let resp = ctx
            .http
            .post("https://api.dingtalk.com/v1.0/oauth2/accessToken")
            .json(&json!({
                "appKey": self.app_key,
                "appSecret": self.app_secret,
            }))
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("DingTalk access_token request failed: {e}")))?;

        let value: serde_json::Value = resp.json().await.map_err(|e| {
            BridgeError::App(format!("DingTalk access_token response parse failed: {e}"))
        })?;

        value
            .get("accessToken")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .ok_or_else(|| BridgeError::App(format!("DingTalk access_token is missing: {value}")))
    }
}

#[async_trait]
impl MessageBridge for DingTalkApp {
    fn name(&self) -> &str {
        "dingtalk"
    }

    async fn run(self: Arc<Self>, _ctx: Arc<MessageContext>) -> Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let access_token = self.fetch_access_token(&ctx).await?;

        // Prepend the sender prefix to the text, consistent with the discord template style.
        let text = format!("{}: {}", msg.sender_display, msg.body);

        // DingTalk enterprise robot group message API; app_channel is treated as openConversationId.
        // msgParam must be a JSON string.
        let body = json!({
            "robotCode": self.robot_code,
            "openConversationId": msg.app_channel,
            "msgKey": "sampleText",
            "msgParam": json!({ "content": text }).to_string(),
        });

        let resp = ctx
            .http
            .post("https://api.dingtalk.com/v1.0/robot/groupMessages/send")
            .header("x-acs-dingtalk-access-token", access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("DingTalk send failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            return Err(BridgeError::App(format!(
                "DingTalk send returned non-2xx: {status} {detail}"
            )));
        }

        let value: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| BridgeError::App(format!("DingTalk send response parse failed: {e}")))?;

        // DingTalk returns processQueryKey as the message tracking identifier; falls back to the conversation id when missing.
        let app_message_id = value
            .get("processQueryKey")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .unwrap_or_else(|| msg.app_channel.clone());

        Ok(AppMessageRef { app_message_id })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        Some(
            salvo::Router::with_path("webhooks/dingtalk")
                .hoop(affix_state::inject(DingTalkWebhookState { ctx }))
                .post(dingtalk_delivery),
        )
    }
}

#[derive(Clone)]
struct DingTalkWebhookState {
    ctx: Arc<MessageContext>,
}

#[handler]
async fn dingtalk_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<DingTalkWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let Some(body) = webhook::json_body(req, res).await else {
        return;
    };
    if let Some(challenge) = body.get("challenge").and_then(Value::as_str) {
        webhook::ok_json(res, json!({ "challenge": challenge }));
        return;
    }

    let text = webhook::first_string_at(
        &body,
        &[
            "/text/content",
            "/text",
            "/content",
            "/message/text",
            "/message/content",
        ],
    )
    .unwrap_or_default();
    if text.is_empty() {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let channel = webhook::first_string_at(
        &body,
        &[
            "/openConversationId",
            "/conversationId",
            "/conversation_id",
            "/chatbotCorpId",
        ],
    )
    .unwrap_or_default();
    let user = webhook::first_string_at(
        &body,
        &[
            "/senderStaffId",
            "/senderId",
            "/userId",
            "/openId",
            "/senderNick",
        ],
    )
    .unwrap_or_default();
    let message_id = webhook::first_string_at(&body, &["/msgId", "/messageId", "/eventId"])
        .or_else(|| body.get("createAt").map(|v| v.to_string()))
        .unwrap_or_default();
    webhook::submit(
        state.ctx.clone(),
        "dingtalk",
        InboundAppMessage {
            app_channel: channel,
            app_user: user,
            app_message_id: message_id,
            body: text,
        },
    )
    .await;
    webhook::ok_json(res, json!({ "ok": true }));
}
