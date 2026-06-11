//! WeChat (WeChat Work / Official Account) adapter (reqwest).
//!
//! - Inbound (WeChat -> cokret): WeChat plaintext XML callbacks are accepted
//!   at `/webhooks/wechat`.
//! - Outbound (cokret -> WeChat): [`MessageBridge::send_to_app`] uses `ctx.http` to first
//!   exchange corp_id/corp_secret (or app_id/app_secret) for an `access_token`, then POST to
//!   the WeChat Work app-message / Official Account customer-service-message API.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cokret_bridge_messaging::salvo::{self, affix_state, prelude::*};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle, webhook,
};
use cokret_bridge_runtime::cache::TokenCache;
use cokret_bridge_runtime::{BridgeError, Result};
use quick_xml::Reader;
use quick_xml::events::Event as XmlEvent;
use serde_json::{Value, json};

const WECHAT_OFFICIAL_BASE: &str = "https://api.weixin.qq.com/cgi-bin";
const WECHAT_WORK_BASE: &str = "https://qyapi.weixin.qq.com/cgi-bin";
/// Fallback validity (seconds) when the API omits `expires_in`.
const WECHAT_TOKEN_FALLBACK_SECS: u64 = 7000;

/// WeChat bridge adapter.
pub struct WeChatApp {
    /// WeChat Work corp_id or Official Account app_id.
    cred_id: String,
    /// WeChat Work corp_secret or Official Account app_secret.
    cred_secret: String,
    /// WeChat Work app agent_id (required to send app messages); None for Official Account customer-service messages.
    agent_id: Option<i64>,
    /// Callback Token used to verify the `signature` of inbound calls
    /// (`sha1(sort(token, timestamp, nonce))`). Required (fail closed).
    webhook_token: String,
    token_cache: TokenCache,
}

impl WeChatApp {
    pub fn new(
        cred_id: impl Into<String>,
        cred_secret: impl Into<String>,
        agent_id: Option<i64>,
        webhook_token: impl Into<String>,
    ) -> Self {
        Self {
            cred_id: cred_id.into(),
            cred_secret: cred_secret.into(),
            agent_id,
            webhook_token: webhook_token.into(),
            token_cache: TokenCache::new(),
        }
    }

    fn mode(&self) -> WechatMode {
        if self.agent_id.is_some() {
            WechatMode::Work
        } else {
            WechatMode::OfficialAccount
        }
    }

    /// Returns an `access_token`, served from the cache until it nears the
    /// vendor-reported expiry, then re-fetched.
    async fn access_token(&self, ctx: &Arc<MessageContext>) -> Result<String> {
        self.token_cache
            .get_or_try_refresh(|| async {
                let url = match self.mode() {
                    WechatMode::Work => format!(
                        "{WECHAT_WORK_BASE}/gettoken?corpid={}&corpsecret={}",
                        self.cred_id, self.cred_secret
                    ),
                    WechatMode::OfficialAccount => format!(
                        "{WECHAT_OFFICIAL_BASE}/token?grant_type=client_credential&appid={}&secret={}",
                        self.cred_id, self.cred_secret
                    ),
                };
                let resp = ctx
                    .http
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| BridgeError::App(format!("WeChat token request failed: {e}")))?;

                let body: Value = resp
                    .json()
                    .await
                    .map_err(|e| BridgeError::App(format!("WeChat token parse failed: {e}")))?;

                if body.get("errcode").and_then(|v| v.as_i64()).unwrap_or(0) != 0 {
                    return Err(BridgeError::App(format!(
                        "WeChat token returned an error: {body}"
                    )));
                }
                let token = body
                    .get("access_token")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_owned())
                    .ok_or_else(|| BridgeError::App(format!("WeChat token is missing: {body}")))?;
                let ttl = body
                    .get("expires_in")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(WECHAT_TOKEN_FALLBACK_SECS);
                Ok((token, Duration::from_secs(ttl)))
            })
            .await
    }
}

#[async_trait]
impl MessageBridge for WeChatApp {
    fn name(&self) -> &str {
        "wechat"
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let token = self.access_token(&ctx).await?;

        let text = msg.rendered_body(SenderRenderStyle::Plain);

        let (url, payload) = match self.mode() {
            WechatMode::Work => (
                format!("{WECHAT_WORK_BASE}/message/send?access_token={token}"),
                json!({
                    "touser": msg.app_channel,
                    "msgtype": "text",
                    "agentid": self.agent_id,
                    "text": { "content": text },
                }),
            ),
            WechatMode::OfficialAccount => (
                format!("{WECHAT_OFFICIAL_BASE}/message/custom/send?access_token={token}"),
                json!({
                    "touser": msg.app_channel,
                    "msgtype": "text",
                    "text": { "content": text },
                }),
            ),
        };

        let resp = ctx
            .http
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| BridgeError::App(format!("WeChat send failed: {e}")))?;

        let body: Value = resp
            .json()
            .await
            .map_err(|e| BridgeError::App(format!("WeChat send response parse failed: {e}")))?;

        if body.get("errcode").and_then(|v| v.as_i64()).unwrap_or(0) != 0 {
            return Err(BridgeError::App(format!(
                "WeChat send returned an error: {body}"
            )));
        }
        // WeChat APIs often return no standalone message id; msgid is used when present.
        let message_id = body
            .get("msgid")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        Ok(AppMessageRef {
            app_message_id: message_id,
        })
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        let webhook_token = self.webhook_token.clone();
        Some(
            salvo::Router::with_path("webhooks/wechat")
                .hoop(affix_state::inject(WechatWebhookState {
                    ctx,
                    webhook_token,
                }))
                .get(wechat_verify)
                .post(wechat_delivery),
        )
    }
}

#[derive(Clone, Copy)]
enum WechatMode {
    Work,
    OfficialAccount,
}

#[derive(Clone)]
struct WechatWebhookState {
    ctx: Arc<MessageContext>,
    /// Callback Token for `signature` verification.
    webhook_token: String,
}

/// Verify the WeChat接入 `signature` query parameter, which is
/// `sha1(sort(token, timestamp, nonce))`, in constant time.
fn wechat_signature_ok(token: &str, req: &Request) -> bool {
    if token.is_empty() {
        return false;
    }
    let signature = req.query::<String>("signature").unwrap_or_default();
    let timestamp = req.query::<String>("timestamp").unwrap_or_default();
    let nonce = req.query::<String>("nonce").unwrap_or_default();
    let expected = webhook::sha1_hex_sorted(&[token, &timestamp, &nonce]);
    webhook::constant_time_eq(expected.as_bytes(), signature.as_bytes())
}

#[handler]
async fn wechat_verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<WechatWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    // Fail closed: only echo `echostr` after the接入 signature checks out.
    if !wechat_signature_ok(&state.webhook_token, req) {
        webhook::unauthorized(res, "WeChat signature mismatch");
        return;
    }
    let echostr = req.query::<String>("echostr").unwrap_or_default();
    if echostr.is_empty() {
        webhook::bad_request(res, "missing echostr");
    } else {
        webhook::ok_text(res, echostr);
    }
}

#[handler]
async fn wechat_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<WechatWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    // Fail closed: verify the plaintext-mode `signature` before processing.
    if !wechat_signature_ok(&state.webhook_token, req) {
        webhook::unauthorized(res, "WeChat signature mismatch");
        return;
    }
    // Use the shared `raw_body` helper so the webhook body is bounded by
    // `MAX_WEBHOOK_BODY_BYTES` instead of reading an unbounded payload.
    let Some(payload) = webhook::raw_body(req, res).await else {
        return;
    };
    let xml = match std::str::from_utf8(&payload) {
        Ok(text) => text,
        Err(err) => {
            webhook::bad_request(res, format!("WeChat payload is not UTF-8: {err}"));
            return;
        }
    };
    let fields = parse_wechat_xml(xml);
    if fields.encrypt.is_some() && fields.content.is_none() {
        webhook::bad_request(
            res,
            "encrypted WeChat callbacks require AES decryption configuration",
        );
        return;
    }
    if fields.msg_type.as_deref() != Some("text") {
        webhook::ok_text(res, "success");
        return;
    }
    let Some(content) = fields.content else {
        webhook::ok_text(res, "success");
        return;
    };
    let user = fields.from_user.unwrap_or_default();
    let channel = user.clone();
    let Some(message_id) = fields.msg_id.filter(|id| !id.trim().is_empty()) else {
        webhook::bad_request(res, "WeChat MsgId missing");
        return;
    };
    webhook::submit(
        state.ctx.clone(),
        "wechat",
        InboundAppMessage {
            app_channel: channel,
            app_user: user,
            app_message_id: message_id,
            body: content,
        },
    )
    .await;
    webhook::ok_text(res, "success");
}

#[derive(Default)]
struct WechatXmlFields {
    from_user: Option<String>,
    msg_type: Option<String>,
    content: Option<String>,
    msg_id: Option<String>,
    encrypt: Option<String>,
}

fn parse_wechat_xml(xml: &str) -> WechatXmlFields {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut current = String::new();
    let mut fields = WechatXmlFields::default();

    loop {
        match reader.read_event() {
            Ok(XmlEvent::Start(e)) => {
                current = String::from_utf8_lossy(e.name().as_ref()).to_string();
            }
            Ok(XmlEvent::Text(e)) => {
                let value = e.decode().map(|v| v.into_owned()).unwrap_or_default();
                match current.as_str() {
                    "FromUserName" => fields.from_user = Some(value),
                    "MsgType" => fields.msg_type = Some(value),
                    "Content" => fields.content = Some(value),
                    "MsgId" => fields.msg_id = Some(value),
                    "Encrypt" => fields.encrypt = Some(value),
                    _ => {}
                }
            }
            Ok(XmlEvent::CData(e)) => {
                let value = e.decode().map(|v| v.into_owned()).unwrap_or_default();
                match current.as_str() {
                    "FromUserName" => fields.from_user = Some(value),
                    "MsgType" => fields.msg_type = Some(value),
                    "Content" => fields.content = Some(value),
                    "MsgId" => fields.msg_id = Some(value),
                    "Encrypt" => fields.encrypt = Some(value),
                    _ => {}
                }
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    fields
}
