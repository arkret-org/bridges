//! WeChat (WeChat Work / Official Account) adapter (reqwest).
//!
//! - Inbound (WeChat -> cokret): WeChat callbacks are accepted at `/webhooks/wechat`. Inbound
//!   **delivery (POST) requires safe mode** (EncodingAESKey configured): only `msg_signature`
//!   covers the request body, so plaintext POST deliveries are rejected fail-closed. The GET
//!   subscription handshake still echoes in either mode.
//! - Outbound (cokret -> WeChat): [`MessageBridge::send_to_app`] uses `ctx.http` to first exchange
//!   corp_id/corp_secret (or app_id/app_secret) for an `access_token`, then POST to the WeChat Work
//!   app-message / Official Account customer-service-message API.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cokret_bridge_messaging::runtime::cache::TokenCache;
use cokret_bridge_messaging::runtime::{BridgeError, Result, redact_sensitive_url_values};
use cokret_bridge_messaging::salvo::prelude::*;
use cokret_bridge_messaging::salvo::{self, affix_state};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle, send_json_expect, webhook,
};
use serde_json::{Value, json};

/// WeChat API success flag: top-level `errcode == 0` (absent treated as 0).
fn wechat_errcode_ok(body: &Value) -> bool {
    body.get("errcode").and_then(Value::as_i64).unwrap_or(0) == 0
}

const WECHAT_OFFICIAL_BASE: &str = "https://api.weixin.qq.com/cgi-bin";
const WECHAT_WORK_BASE: &str = "https://qyapi.weixin.qq.com/cgi-bin";
/// Fallback validity (seconds) when the API omits `expires_in`.
const WECHAT_TOKEN_FALLBACK_SECS: u64 = 7000;
const WECHAT_TIMESTAMP_WINDOW_SECS: i64 = 5 * 60;

/// WeChat bridge adapter.
pub struct WechatApp {
    /// WeChat Work corp_id or Official Account app_id.
    cred_id: String,
    /// WeChat Work corp_secret or Official Account app_secret.
    cred_secret: String,
    /// WeChat Work app agent_id (required to send app messages); None for Official Account
    /// customer-service messages.
    agent_id: Option<i64>,
    /// Callback Token used to verify the `signature` of inbound calls
    /// (`sha1(sort(token, timestamp, nonce))`). Required (fail closed).
    webhook_token: String,
    /// Optional EncodingAESKey (43-char base64). When set, inbound callbacks run
    /// in **safe mode**: the body is AES-256-CBC encrypted and authenticated by
    /// `msg_signature = sha1(sort(token, timestamp, nonce, encrypt))`.
    aes_key: Option<WechatAesKey>,
    token_cache: TokenCache,
}

/// 32-byte AES key decoded from a 43-char EncodingAESKey. WeChat safe mode uses
/// AES-256-CBC with the IV taken as the first 16 bytes of this key.
#[derive(Clone)]
struct WechatAesKey([u8; 32]);

impl WechatAesKey {
    /// Decode `EncodingAESKey` (43-char standard base64 without padding) into the
    /// 32-byte AES key. WeChat documents appending a single `=` before decoding.
    fn from_encoding_key(encoding_aes_key: &str) -> Option<Self> {
        let key = encoding_aes_key.trim();
        if key.len() != 43 {
            return None;
        }
        let decoded = webhook::base64_decode(&format!("{key}="))?;
        let bytes: [u8; 32] = decoded.try_into().ok()?;
        Some(Self(bytes))
    }
}

impl WechatApp {
    /// Build the adapter, decoding the optional EncodingAESKey. Returns an error
    /// when an EncodingAESKey is configured but malformed (fail closed rather
    /// than silently dropping safe mode). This is the single, fallible
    /// constructor (`new(...) -> Result<Self>`), keeping the bridge constructor
    /// convention uniform with the other adapters' `new`.
    pub fn new(
        cred_id: impl Into<String>,
        cred_secret: impl Into<String>,
        agent_id: Option<i64>,
        webhook_token: impl Into<String>,
        encoding_aes_key: Option<String>,
        token_cache: TokenCache,
    ) -> Result<Self> {
        let aes_key = match encoding_aes_key
            .map(|k| k.trim().to_owned())
            .filter(|k| !k.is_empty())
        {
            Some(key) => Some(WechatAesKey::from_encoding_key(&key).ok_or_else(|| {
                BridgeError::Config(
                    "WeChat encoding_aes_key must be a 43-character base64 EncodingAESKey"
                        .to_owned(),
                )
            })?),
            None => None,
        };
        Ok(Self {
            cred_id: cred_id.into(),
            cred_secret: cred_secret.into(),
            agent_id,
            webhook_token: webhook_token.into(),
            aes_key,
            token_cache,
        })
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
                    .map_err(|e| {
                        BridgeError::App(format!(
                            "WeChat token request failed: {}",
                            redact_sensitive_url_values(e.to_string())
                        ))
                    })?;

                let body: Value = resp
                    .json()
                    .await
                    .map_err(|e| {
                        BridgeError::App(format!(
                            "WeChat token parse failed: {}",
                            redact_sensitive_url_values(e.to_string())
                        ))
                    })?;

                if body.get("errcode").and_then(|v| v.as_i64()).unwrap_or(0) != 0 {
                    return Err(BridgeError::App(format!(
                        "WeChat token returned an error: {}",
                        redact_sensitive_url_values(body.to_string())
                    )));
                }
                let token = body
                    .get("access_token")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_owned())
                    .ok_or_else(|| BridgeError::App("WeChat access_token is missing".to_owned()))?;
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
impl MessageBridge for WechatApp {
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

        let body = send_json_expect(
            ctx.http.post(&url).json(&payload),
            "WeChat send",
            wechat_errcode_ok,
        )
        .await?;
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

    fn expects_webhook_inbound(&self) -> bool {
        true
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        let webhook_token = self.webhook_token.clone();
        if webhook_token.trim().is_empty() {
            return None;
        }
        // BRG-SEC-002: `unix_timestamp_is_fresh` accepts |now-ts| <= window, so
        // the acceptance window spans 2*window (past+future). The replay TTL
        // must cover the whole window or a captured delivery could be replayed in
        // the off-window gap.
        let replay_window =
            ctx.replay_window(Duration::from_secs(2 * WECHAT_TIMESTAMP_WINDOW_SECS as u64));
        Some(
            salvo::Router::with_path("webhooks/wechat")
                .hoop(affix_state::inject(WechatWebhookState {
                    ctx,
                    webhook_token,
                    aes_key: self.aes_key.clone(),
                    cred_id: self.cred_id.clone(),
                    replay_window,
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
    /// EncodingAESKey-derived key for safe mode. `None` means plaintext mode, in
    /// which inbound POST deliveries are rejected (no body-bound signature); only
    /// the GET handshake echo is served in plaintext mode.
    aes_key: Option<WechatAesKey>,
    /// Configured corp_id / app_id, checked against the receiveid trailer of a
    /// safe-mode decrypted body.
    cred_id: String,
    replay_window: Arc<webhook::ReplayWindow>,
}

/// Verify the WeChat server-verification `signature` query parameter, which is
/// `sha1(sort(token, timestamp, nonce))`, in constant time. Plaintext mode
/// cannot authenticate the body, so delivery handlers also bind each accepted
/// query triple to a short replay window.
#[derive(Default)]
struct WechatSignatureInput {
    signature: String,
    timestamp: String,
    nonce: String,
}

fn wechat_signature_input(req: &Request) -> WechatSignatureInput {
    WechatSignatureInput {
        signature: req.query::<String>("signature").unwrap_or_default(),
        timestamp: req.query::<String>("timestamp").unwrap_or_default(),
        nonce: req.query::<String>("nonce").unwrap_or_default(),
    }
}

fn wechat_signature_ok(token: &str, input: &WechatSignatureInput) -> bool {
    if token.is_empty()
        || input.signature.is_empty()
        || input.timestamp.is_empty()
        || input.nonce.is_empty()
    {
        return false;
    }
    if !webhook::unix_timestamp_is_fresh(
        &input.timestamp,
        std::time::Duration::from_secs(WECHAT_TIMESTAMP_WINDOW_SECS as u64),
    ) {
        return false;
    }
    let expected = webhook::sha1_hex_sorted(&[token, &input.timestamp, &input.nonce]);
    webhook::constant_time_eq(expected.as_bytes(), input.signature.as_bytes())
}

fn wechat_replay_key(input: &WechatSignatureInput) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}",
        input.timestamp, input.nonce, input.signature
    )
}

/// Verify the WeChat **safe mode** `msg_signature`, which authenticates the
/// encrypted body: `msg_signature = sha1(sort(token, timestamp, nonce, encrypt))`.
/// Constant-time compared. The `signature` field of `input` carries the
/// `msg_signature` query parameter in safe mode.
fn wechat_msg_signature_ok(
    token: &str,
    input: &WechatSignatureInput,
    encrypt: &str,
    timestamp_window_secs: i64,
) -> bool {
    if token.is_empty()
        || input.signature.is_empty()
        || input.timestamp.is_empty()
        || input.nonce.is_empty()
        || encrypt.is_empty()
    {
        return false;
    }
    if !webhook::unix_timestamp_is_fresh(
        &input.timestamp,
        std::time::Duration::from_secs(timestamp_window_secs as u64),
    ) {
        return false;
    }
    let expected = webhook::sha1_hex_sorted(&[token, &input.timestamp, &input.nonce, encrypt]);
    webhook::constant_time_eq(expected.as_bytes(), input.signature.as_bytes())
}

/// Decrypt a WeChat safe-mode `Encrypt` payload. The base64-decoded ciphertext is
/// AES-256-CBC under the EncodingAESKey-derived key, with the IV being the first
/// 16 bytes of that key. The recovered plaintext is:
///   16-byte random prefix || 4-byte network-order msg length || msg || receiveid
/// where `receiveid` MUST equal the configured corp_id / app_id. Returns the
/// inner `msg` (the original XML) only when every check passes; `None` otherwise
/// (fail closed, no padding-oracle branching surfaced to the caller).
fn wechat_decrypt_safe_mode(
    key: &WechatAesKey,
    expected_receiveid: &str,
    encrypt: &str,
) -> Option<String> {
    let ciphertext = webhook::base64_decode(encrypt)?;
    let iv = &key.0[..16];
    let plain = webhook::aes_cbc_decrypt(&key.0, iv, &ciphertext)?;
    // 16-byte random prefix + 4-byte length header is the minimum.
    if plain.len() < 20 {
        return None;
    }
    let msg_len = u32::from_be_bytes([plain[16], plain[17], plain[18], plain[19]]) as usize;
    let msg_start: usize = 20;
    let msg_end = msg_start.checked_add(msg_len)?;
    if msg_end > plain.len() {
        return None;
    }
    let receiveid = &plain[msg_end..];
    // Constant-time bind the trailing receiveid to the configured credential id.
    if !webhook::constant_time_eq(receiveid, expected_receiveid.as_bytes()) {
        return None;
    }
    String::from_utf8(plain[msg_start..msg_end].to_vec()).ok()
}

/// Security invariant for inbound POST deliveries: a delivery may only be
/// accepted when WeChat **safe mode** is configured (an EncodingAESKey is
/// present), because only `msg_signature` covers the request body. In plaintext
/// mode (`aes_key == None`) the `signature` query parameter authenticates the
/// `(token, timestamp, nonce)` triple but NOT the body, so a forged or replayed
/// body cannot be detected. Returns `true` when the delivery MUST be rejected
/// (fail closed). The GET subscription handshake is intentionally not gated by
/// this — it only echoes a challenge and submits nothing into the ingress.
fn plaintext_delivery_must_be_rejected(aes_key: Option<&WechatAesKey>) -> bool {
    aes_key.is_none()
}

/// Build the safe-mode signature input from a request: in safe mode the
/// authenticating query parameter is `msg_signature` (not `signature`).
fn wechat_msg_signature_input(req: &Request) -> WechatSignatureInput {
    WechatSignatureInput {
        signature: req.query::<String>("msg_signature").unwrap_or_default(),
        timestamp: req.query::<String>("timestamp").unwrap_or_default(),
        nonce: req.query::<String>("nonce").unwrap_or_default(),
    }
}

#[handler]
async fn wechat_verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<WechatWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let echostr = req.query::<String>("echostr").unwrap_or_default();
    if echostr.is_empty() {
        webhook::bad_request(res, "missing echostr");
        return;
    }
    // Safe mode: `echostr` is the encrypted payload, authenticated by
    // `msg_signature = sha1(sort(token, timestamp, nonce, echostr))`. Echo the
    // decrypted plaintext after verifying.
    if let Some(aes_key) = state.aes_key.as_ref() {
        let sig_input = wechat_msg_signature_input(req);
        if !wechat_msg_signature_ok(
            &state.webhook_token,
            &sig_input,
            &echostr,
            WECHAT_TIMESTAMP_WINDOW_SECS,
        ) {
            webhook::unauthorized(res, "WeChat msg_signature mismatch");
            return;
        }
        match wechat_decrypt_safe_mode(aes_key, &state.cred_id, &echostr) {
            Some(plain) => webhook::ok_text(res, plain),
            None => webhook::unauthorized(res, "WeChat echostr decryption failed"),
        }
        return;
    }
    // Plaintext mode: only echo `echostr` after the server-verification signature checks out.
    let signature_input = wechat_signature_input(req);
    if !wechat_signature_ok(&state.webhook_token, &signature_input) {
        webhook::unauthorized(res, "WeChat signature mismatch");
        return;
    }
    webhook::ok_text(res, echostr);
}

#[handler]
async fn wechat_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<WechatWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };

    // Read raw body first (bounded by `MAX_WEBHOOK_BODY_BYTES`).
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

    // Per-delivery source verification REQUIRES a platform signature that covers
    // the POST body. Only WeChat safe mode provides that: the body carries an
    // `<Encrypt>` element authenticated by
    // `msg_signature = sha1(sort(token, timestamp, nonce, encrypt))`.
    //
    // Plaintext mode (`aes_key == None`) only has `signature`, which covers the
    // query triple but NOT the body — an attacker with a valid `(timestamp, nonce,
    // signature)` triple (or a replay inside the window) could swap the XML body
    // and inject forged messages into the applet ingress. There is no body-bound
    // platform signature to fall back on, so we fail closed and refuse plaintext
    // POST deliveries entirely. EncodingAESKey / safe mode is mandatory for
    // inbound delivery; the GET handshake echo is unaffected.
    // Fail closed: plaintext mode has no body-bound platform signature, so a
    // POST delivery cannot be source-verified per delivery. Reject it. See
    // `plaintext_delivery_must_be_rejected` for the security invariant under test.
    let Some(aes_key) = state.aes_key.as_ref() else {
        debug_assert!(plaintext_delivery_must_be_rejected(state.aes_key.as_ref()));
        tracing::warn!(
            target: "wechat",
            "rejecting WeChat webhook delivery: plaintext mode has no body-bound \
             signature; configure EncodingAESKey (safe mode) to accept inbound messages"
        );
        webhook::unauthorized(
            res,
            "WeChat plaintext webhook delivery is rejected: EncodingAESKey (safe mode) \
             is required for body-bound source verification",
        );
        return;
    };

    let sig_input = wechat_msg_signature_input(req);
    let envelope = parse_wechat_xml(xml);
    let Some(encrypt) = envelope.encrypt else {
        webhook::bad_request(res, "WeChat safe mode requires an Encrypt body");
        return;
    };
    if !wechat_msg_signature_ok(
        &state.webhook_token,
        &sig_input,
        &encrypt,
        WECHAT_TIMESTAMP_WINDOW_SECS,
    ) {
        webhook::unauthorized(res, "WeChat msg_signature mismatch");
        return;
    }
    // Replay-bind the authenticated (timestamp, nonce, msg_signature) triple.
    if !state
        .replay_window
        .check_and_record(wechat_replay_key(&sig_input))
    {
        webhook::unauthorized(res, "WeChat callback replay");
        return;
    }
    let inner_xml = match wechat_decrypt_safe_mode(aes_key, &state.cred_id, &encrypt) {
        Some(plain) => plain,
        None => {
            webhook::unauthorized(res, "WeChat safe-mode decryption failed");
            return;
        }
    };

    let fields = parse_wechat_xml(&inner_xml);
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
    let outcome = webhook::submit(
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
    match outcome {
        // WeChat treats the literal body "success" as acknowledgement.
        webhook::SubmitOutcome::Accepted => webhook::ok_text(res, "success"),
        webhook::SubmitOutcome::Retry => webhook::submission_retry(res),
    }
}

/// The subset of a WeChat callback `<xml>` envelope this bridge reads. Both the
/// outer safe-mode envelope (only `<Encrypt>` populated) and the inner decrypted
/// message map to this one shape. `quick_xml::de` transparently handles text and
/// `<![CDATA[..]]>` element bodies, so there is no Text/CData branching, and
/// `#[serde(default)]` makes every field optional (absent elements stay `None`).
#[derive(Default, serde::Deserialize)]
#[serde(rename = "xml", default)]
struct WechatXmlFields {
    #[serde(rename = "FromUserName")]
    from_user: Option<String>,
    #[serde(rename = "MsgType")]
    msg_type: Option<String>,
    #[serde(rename = "Content")]
    content: Option<String>,
    #[serde(rename = "MsgId")]
    msg_id: Option<String>,
    #[serde(rename = "Encrypt")]
    encrypt: Option<String>,
}

/// Deserialize a WeChat callback XML envelope into [`WechatXmlFields`]. Malformed
/// XML yields an all-`None` envelope (fields the callers already treat as absent),
/// matching the previous fail-soft parsing.
fn parse_wechat_xml(xml: &str) -> WechatXmlFields {
    quick_xml::de::from_str(xml).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_unix_timestamp() -> String {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    #[test]
    fn wechat_signature_accepts_fresh_matching_query() {
        let token = "callback-token";
        let timestamp = current_unix_timestamp();
        let nonce = "nonce-1".to_owned();
        let signature = webhook::sha1_hex_sorted(&[token, &timestamp, &nonce]);
        let input = WechatSignatureInput {
            signature,
            timestamp,
            nonce,
        };

        assert!(wechat_signature_ok(token, &input));
    }

    #[test]
    fn wechat_signature_rejects_stale_query() {
        let token = "callback-token";
        let timestamp = "1700000000".to_owned();
        let nonce = "nonce-1".to_owned();
        let signature = webhook::sha1_hex_sorted(&[token, &timestamp, &nonce]);
        let input = WechatSignatureInput {
            signature,
            timestamp,
            nonce,
        };

        assert!(!wechat_signature_ok(token, &input));
    }

    /// Encrypt `msg` into a WeChat safe-mode `Encrypt` base64 string using the
    /// documented envelope: 16B random || 4B BE length || msg || receiveid.
    fn encrypt_safe_mode(key: &WechatAesKey, receiveid: &str, msg: &str) -> String {
        use base64::Engine as _;
        use cbc::Encryptor;
        use cbc::cipher::block_padding::Pkcs7;
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};

        let mut plain = Vec::new();
        plain.extend_from_slice(&[0u8; 16]); // random prefix (fixed for the test)
        plain.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        plain.extend_from_slice(msg.as_bytes());
        plain.extend_from_slice(receiveid.as_bytes());

        let iv = &key.0[..16];
        let mut buf = vec![0u8; plain.len() + 16];
        let ct = Encryptor::<aes::Aes256>::new_from_slices(&key.0, iv)
            .unwrap()
            .encrypt_padded_b2b_mut::<Pkcs7>(&plain, &mut buf)
            .unwrap();
        base64::engine::general_purpose::STANDARD.encode(ct)
    }

    fn sample_aes_key() -> WechatAesKey {
        // 43-char base64 -> 32 bytes. Use a deterministic key for the test.
        let encoding = "A".repeat(43);
        WechatAesKey::from_encoding_key(&encoding).expect("valid encoding key")
    }

    #[test]
    fn encoding_aes_key_requires_43_chars() {
        assert!(WechatAesKey::from_encoding_key(&"A".repeat(43)).is_some());
        assert!(WechatAesKey::from_encoding_key(&"A".repeat(42)).is_none());
        assert!(WechatAesKey::from_encoding_key("not-base64-#####").is_none());
    }

    #[test]
    fn safe_mode_decrypts_and_binds_receiveid() {
        let key = sample_aes_key();
        let receiveid = "wx-corp-id";
        let msg = "<xml><FromUserName><![CDATA[u1]]></FromUserName>\
                   <MsgType><![CDATA[text]]></MsgType>\
                   <Content><![CDATA[hello safe]]></Content><MsgId>99</MsgId></xml>";
        let encrypt = encrypt_safe_mode(&key, receiveid, msg);

        // Correct receiveid recovers the inner XML.
        let recovered = wechat_decrypt_safe_mode(&key, receiveid, &encrypt).expect("decrypt");
        assert_eq!(recovered, msg);
        let fields = parse_wechat_xml(&recovered);
        assert_eq!(fields.content.as_deref(), Some("hello safe"));

        // Wrong receiveid fails closed.
        assert!(wechat_decrypt_safe_mode(&key, "other-corp", &encrypt).is_none());
        // Tampered ciphertext fails closed.
        let mut bad = encrypt.clone();
        bad.push('A');
        assert!(wechat_decrypt_safe_mode(&key, receiveid, &bad).is_none());
    }

    #[test]
    fn msg_signature_matches_sorted_sha1() {
        let token = "callback-token";
        let timestamp = current_unix_timestamp();
        let nonce = "n-1".to_owned();
        let encrypt = "ENCRYPTED-PAYLOAD";
        let signature = webhook::sha1_hex_sorted(&[token, &timestamp, &nonce, encrypt]);
        let input = WechatSignatureInput {
            signature,
            timestamp,
            nonce,
        };
        assert!(wechat_msg_signature_ok(
            token,
            &input,
            encrypt,
            WECHAT_TIMESTAMP_WINDOW_SECS
        ));
        // Different encrypt body invalidates the signature (body is authenticated).
        assert!(!wechat_msg_signature_ok(
            token,
            &input,
            "OTHER",
            WECHAT_TIMESTAMP_WINDOW_SECS
        ));
    }

    #[test]
    fn plaintext_delivery_is_rejected_safe_mode_is_accepted() {
        // BRIDGES-01: plaintext mode (no EncodingAESKey) has no body-bound
        // signature, so inbound POST deliveries MUST be rejected fail-closed.
        assert!(plaintext_delivery_must_be_rejected(None));
        // Safe mode (EncodingAESKey configured) authenticates the body via
        // `msg_signature` and is accepted.
        let key = sample_aes_key();
        assert!(!plaintext_delivery_must_be_rejected(Some(&key)));
    }

    #[test]
    fn parse_wechat_xml_reads_text_message_fields() {
        let fields = parse_wechat_xml(
            r#"<xml>
                <FromUserName><![CDATA[user-openid]]></FromUserName>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[hello]]></Content>
                <MsgId>12345</MsgId>
            </xml>"#,
        );

        assert_eq!(fields.from_user.as_deref(), Some("user-openid"));
        assert_eq!(fields.msg_type.as_deref(), Some("text"));
        assert_eq!(fields.content.as_deref(), Some("hello"));
        assert_eq!(fields.msg_id.as_deref(), Some("12345"));
    }
}
