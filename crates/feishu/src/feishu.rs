//! Feishu / Lark adapter (reqwest).
//!
//! - Inbound (Feishu -> arkret): Feishu events are pushed via `/webhooks/feishu`.
//! - Outbound (arkret -> Feishu): [`MessageBridge::send_to_app`] uses `ctx.http` `POST https://open.feishu.cn/open-apis/im/v1/messages`,
//!   which first exchanges app_id/app_secret for a `tenant_access_token`.

use std::sync::Arc;
use std::time::Duration;

use arkret_bridge_messaging::runtime::Result;
use arkret_bridge_messaging::runtime::cache::TokenCache;
use arkret_bridge_messaging::salvo::prelude::*;
use arkret_bridge_messaging::salvo::{self, affix_state};
use arkret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle, VendorTokenCheck, fetch_vendor_token, send_json_expect, webhook,
};
use async_trait::async_trait;
use serde_json::{Value, json};

/// Feishu / Lark API success flag: top-level `code == 0`.
fn feishu_code_ok(body: &Value) -> bool {
    body.get("code").and_then(Value::as_i64) == Some(0)
}

const FEISHU_BASE: &str = "https://open.feishu.cn/open-apis";
/// Fallback validity (seconds) when the API omits `expire`.
const FEISHU_TOKEN_FALLBACK: Duration = Duration::from_secs(7000);
/// Freshness window for the `X-Lark-Request-Timestamp` carried by each delivery.
/// Deliveries whose timestamp is outside this skew (past or future) are rejected,
/// bounding the replay window the source signature alone cannot close.
const FEISHU_DELIVERY_MAX_SKEW: Duration = Duration::from_secs(300);
/// Feishu bridge adapter.
pub struct FeishuApp {
    app_id: String,
    app_secret: String,
    /// Event-subscription Verification Token. Inbound callbacks (challenge and
    /// events) MUST carry this token; compared in constant time (fail closed).
    verification_token: String,
    /// Event-subscription Encrypt Key (REQUIRED). Feishu encrypts the callback
    /// body (`{"encrypt": "..."}`) with AES-256-CBC under `SHA256(encrypt_key)`
    /// and signs every delivery with `X-Lark-Signature`. The bridge mandates this
    /// mode because plaintext callbacks carry no per-delivery body signature, and
    /// the bridge contract requires every inbound delivery to be source-verified
    /// (a one-time challenge / verification token is NOT a substitute). When the
    /// Encrypt Key is missing the webhook router is not mounted (fail closed).
    encrypt_key: Option<String>,
    token_cache: TokenCache,
}

impl FeishuApp {
    pub fn new(
        app_id: impl Into<String>,
        app_secret: impl Into<String>,
        verification_token: impl Into<String>,
        encrypt_key: Option<String>,
        token_cache: TokenCache,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            app_secret: app_secret.into(),
            verification_token: verification_token.into(),
            encrypt_key: encrypt_key.filter(|k| !k.is_empty()),
            token_cache,
        }
    }

    /// Returns a `tenant_access_token`, served from the cache until it nears the
    /// vendor-reported expiry, then re-fetched via app_id/app_secret.
    async fn access_token(&self, ctx: &Arc<MessageContext>) -> Result<String> {
        self.token_cache
            .get_or_try_refresh(|| {
                let url = format!("{FEISHU_BASE}/auth/v3/tenant_access_token/internal");
                let request = ctx.http.post(&url).json(&json!({
                    "app_id": self.app_id,
                    "app_secret": self.app_secret,
                }));
                fetch_vendor_token(
                    request,
                    "Feishu token",
                    VendorTokenCheck::JsonBody(feishu_code_ok),
                    "/tenant_access_token",
                    "/expire",
                    FEISHU_TOKEN_FALLBACK,
                )
            })
            .await
    }
}

#[async_trait]
impl MessageBridge for FeishuApp {
    fn name(&self) -> &str {
        "feishu"
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        let token = self.access_token(&ctx).await?;

        // app_channel can be plain chat_id or prefixed as `open_id/<id>`,
        // `user_id/<id>`, `union_id/<id>`, or `chat_id/<id>`.
        let (receive_id_type, receive_id) = receive_id_parts(&msg.app_channel);
        let url = format!("{FEISHU_BASE}/im/v1/messages?receive_id_type={receive_id_type}");
        let text = msg.rendered_body(SenderRenderStyle::Plain);
        // For Feishu text messages, content is a "JSON string".
        let content = json!({ "text": text }).to_string();

        let request = ctx.http.post(&url).bearer_auth(&token).json(&json!({
            "receive_id": receive_id,
            "msg_type": "text",
            "content": content,
        }));
        let body = send_json_expect(request, "Feishu send", feishu_code_ok).await?;
        let message_id = body
            .get("data")
            .and_then(|d| d.get("message_id"))
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
        // Fail closed: without an Encrypt Key, Feishu sends neither an encrypted
        // body nor the `X-Lark-Signature` over each delivery, so there is no
        // per-delivery source signature to verify. Refuse to mount the webhook at
        // all rather than accept plaintext callbacks authenticated only by a
        // static verification token (which the bridge contract forbids as a
        // substitute for per-delivery verification).
        let Some(encrypt_key) = self.encrypt_key.clone() else {
            tracing::error!(
                "Feishu inbound webhook disabled: encrypt_key is required so every \
                 delivery carries an X-Lark-Signature; plaintext callback mode is not \
                 permitted (per-delivery source verification is mandatory)"
            );
            return None;
        };
        if self.verification_token.is_empty() {
            tracing::error!(
                "Feishu inbound webhook disabled: verification_token is required (fail closed)"
            );
            return None;
        }
        let verification_token = self.verification_token.clone();
        // Derive the AES-256 key once: key = SHA256(encrypt_key).
        let encrypt_aes_key = webhook::sha256_bytes(encrypt_key.as_bytes());
        let replay = ctx.replay_window(2 * FEISHU_DELIVERY_MAX_SKEW);
        Some(
            salvo::Router::with_path("webhooks/feishu")
                .hoop(affix_state::inject(FeishuWebhookState {
                    ctx,
                    verification_token,
                    encrypt_key,
                    encrypt_aes_key,
                    // BRG-SEC-002: `unix_timestamp_is_fresh` accepts |now-ts| <=
                    // skew, so the freshness window spans 2*skew (past+future).
                    // The replay TTL must cover that full window or a captured
                    // delivery could be replayed in the off-window gap. Keep the
                    // guard alive for the entire acceptance window.
                    replay,
                }))
                .post(feishu_delivery),
        )
    }
}

fn receive_id_parts(channel: &str) -> (&str, &str) {
    for kind in ["open_id", "user_id", "union_id", "chat_id"] {
        if let Some(rest) = channel.strip_prefix(&format!("{kind}/")) {
            return (kind, rest);
        }
    }
    ("chat_id", channel)
}

#[derive(Clone)]
struct FeishuWebhookState {
    ctx: Arc<MessageContext>,
    /// Event-subscription Verification Token (constant-time compared).
    verification_token: String,
    /// Raw Encrypt Key, used for the mandatory `X-Lark-Signature`
    /// `sha256(timestamp+nonce+encrypt_key+body)` header check on every delivery.
    encrypt_key: String,
    /// AES-256 key (`SHA256(encrypt_key)`) for decrypting the callback body.
    encrypt_aes_key: [u8; 32],
    /// Bounded replay guard keyed on `timestamp:nonce:signature`; a captured
    /// (and validly signed) delivery cannot be accepted twice inside the window.
    replay: Arc<webhook::ReplayWindow>,
}

/// Read the verification token carried by a Feishu callback. v2 events nest it
/// under `header.token`; the v1 challenge and v1 events carry a top-level
/// `token`.
fn feishu_callback_token(body: &Value) -> &str {
    webhook::str_at(body, "/header/token")
        .or_else(|| body.get("token").and_then(Value::as_str))
        .unwrap_or_default()
}

/// Decrypt a Feishu Encrypt Key payload. The `encrypt` field is base64; the
/// decoded bytes are `IV(16) || AES-256-CBC ciphertext` under
/// `key = SHA256(encrypt_key)`. Returns the decrypted plaintext JSON string, or
/// `None` on any decode / decrypt / padding failure (fail closed).
fn feishu_decrypt(aes_key: &[u8; 32], encrypt_b64: &str) -> Option<Value> {
    let raw = webhook::base64_decode(encrypt_b64)?;
    if raw.len() <= 16 {
        return None;
    }
    let (iv, ciphertext) = raw.split_at(16);
    let plain = webhook::aes_cbc_decrypt(aes_key, iv, ciphertext)?;
    serde_json::from_slice::<Value>(&plain).ok()
}

#[handler]
async fn feishu_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(state) = webhook::require_state::<FeishuWebhookState>(depot, res) else {
        return;
    };
    // Fail closed: a Verification Token MUST be configured.
    if state.verification_token.is_empty() {
        webhook::unauthorized(res, "Feishu verification_token not configured");
        return;
    }
    // Read the raw body first: the `X-Lark-Signature` covers the exact wire
    // bytes, and the envelope must be decoded before the JSON parse.
    let Some(raw) = webhook::raw_body(req, res).await else {
        return;
    };

    // Fail closed on EVERY delivery: a valid `X-Lark-Signature` over
    // `timestamp || nonce || encrypt_key || raw_body` is mandatory. Missing,
    // malformed, or mismatched signatures are rejected before any parsing so a
    // forged or tampered request never reaches the message pipeline.
    let Some(signature) = req
        .header::<String>("x-lark-signature")
        .filter(|s| !s.trim().is_empty())
    else {
        webhook::unauthorized(res, "Feishu X-Lark-Signature header is required");
        return;
    };
    let Some(timestamp) = req
        .header::<String>("x-lark-request-timestamp")
        .filter(|s| !s.trim().is_empty())
    else {
        webhook::unauthorized(res, "Feishu X-Lark-Request-Timestamp header is required");
        return;
    };
    let Some(nonce) = req
        .header::<String>("x-lark-request-nonce")
        .filter(|s| !s.trim().is_empty())
    else {
        webhook::unauthorized(res, "Feishu X-Lark-Request-Nonce header is required");
        return;
    };
    // Reject deliveries whose timestamp falls outside the freshness window. This
    // bounds replay to the window and lets the replay guard stay small.
    if !webhook::unix_timestamp_is_fresh(&timestamp, FEISHU_DELIVERY_MAX_SKEW) {
        webhook::unauthorized(res, "Feishu delivery timestamp is stale or invalid");
        return;
    }
    if !webhook::verify_lark_signature(
        state.encrypt_key.as_bytes(),
        &timestamp,
        &nonce,
        &raw,
        &signature,
    ) {
        webhook::unauthorized(res, "Feishu X-Lark-Signature mismatch");
        return;
    }
    // Replay guard: a validly signed delivery is accepted at most once inside the
    // freshness window. Keyed on the signature (which covers timestamp+nonce+body)
    // so two distinct deliveries are never conflated.
    match state
        .replay
        .check_and_record(format!("{timestamp}:{nonce}:{signature}"))
        .await
    {
        Ok(webhook::ReplayGuardVerdict::Fresh) => {}
        Ok(webhook::ReplayGuardVerdict::Replay) => {
            webhook::unauthorized(res, "Feishu delivery replayed");
            return;
        }
        Err(error) => {
            webhook::replay_guard_unavailable(res, &error);
            return;
        }
    }

    let Ok(envelope) = serde_json::from_slice::<Value>(&raw) else {
        webhook::bad_request(res, "invalid Feishu webhook JSON body");
        return;
    };
    // Encrypted mode is mandatory: the body MUST be an `{"encrypt": "..."}`
    // envelope decryptable under `SHA256(encrypt_key)` (fail closed otherwise).
    let Some(encrypt_b64) = envelope.get("encrypt").and_then(Value::as_str) else {
        webhook::unauthorized(res, "Feishu encrypted mode requires an encrypted body");
        return;
    };
    let Some(body) = feishu_decrypt(&state.encrypt_aes_key, encrypt_b64) else {
        webhook::unauthorized(res, "Feishu callback decryption failed");
        return;
    };

    // Authenticate the (now plaintext) callback by its Verification Token.
    let provided = feishu_callback_token(&body);
    if !webhook::constant_time_eq(provided.as_bytes(), state.verification_token.as_bytes()) {
        webhook::unauthorized(res, "Feishu verification token mismatch");
        return;
    }
    if let Some(challenge) = body.get("challenge").and_then(Value::as_str) {
        webhook::ok_json(res, json!({ "challenge": challenge }));
        return;
    }

    let event = body.get("event").unwrap_or(&body);
    if event.get("message").is_none() {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let channel = webhook::string_at(event, "/message/chat_id").unwrap_or_default();
    let user = webhook::first_string_at(
        event,
        &[
            "/sender/sender_id/open_id",
            "/sender/sender_id/user_id",
            "/sender/sender_id/union_id",
        ],
    )
    .unwrap_or_default();
    let Some(message_id) = webhook::non_empty_string_at(event, "/message/message_id") else {
        webhook::bad_request(res, "Feishu message_id missing");
        return;
    };
    let message_type = webhook::str_at(event, "/message/message_type").unwrap_or_default();
    if message_type != "text" {
        state
            .ctx
            .report_unsupported_inbound_media("feishu", channel, user, message_id, message_type)
            .await;
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let content_raw = webhook::str_at(event, "/message/content").unwrap_or_default();
    let text = webhook::body_text_from_json_string(content_raw, "text");
    let outcome = webhook::submit(
        state.ctx.clone(),
        "feishu",
        InboundAppMessage {
            app_channel: channel,
            app_user: user,
            app_message_id: message_id,
            body: text,
        },
    )
    .await;
    webhook::respond_submit(res, outcome);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encrypt a plaintext JSON string the way Feishu does: AES-256-CBC under
    /// `SHA256(encrypt_key)`, with a 16-byte IV prepended to the ciphertext, the
    /// whole thing base64-encoded.
    fn encrypt(encrypt_key: &str, plaintext: &str) -> String {
        use base64::Engine as _;
        use cbc::Encryptor;
        use cbc::cipher::block_padding::Pkcs7;
        use cbc::cipher::{BlockModeEncrypt, KeyIvInit};

        let key = webhook::sha256_bytes(encrypt_key.as_bytes());
        let iv = [0x11u8; 16];
        let mut buf = vec![0u8; plaintext.len() + 16];
        let ct = Encryptor::<aes::Aes256>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_b2b::<Pkcs7>(plaintext.as_bytes(), &mut buf)
            .unwrap();
        let mut framed = iv.to_vec();
        framed.extend_from_slice(ct);
        base64::engine::general_purpose::STANDARD.encode(framed)
    }

    #[test]
    fn feishu_decrypt_recovers_plaintext_json() {
        let encrypt_key = "test-encrypt-key";
        let aes_key = webhook::sha256_bytes(encrypt_key.as_bytes());
        let plaintext = r#"{"challenge":"abc","token":"verif","type":"url_verification"}"#;
        let envelope = encrypt(encrypt_key, plaintext);

        let decrypted = feishu_decrypt(&aes_key, &envelope).expect("decrypt");
        assert_eq!(
            decrypted.get("challenge").and_then(Value::as_str),
            Some("abc")
        );
        assert_eq!(
            decrypted.get("token").and_then(Value::as_str),
            Some("verif")
        );

        // Wrong key fails closed.
        let wrong = webhook::sha256_bytes(b"other-key");
        assert!(feishu_decrypt(&wrong, &envelope).is_none());
        // Too-short payload (no room for IV) fails closed.
        assert!(feishu_decrypt(&aes_key, "AAAA").is_none());
    }

    #[test]
    fn lark_signature_matches_reference() {
        let encrypt_key = "test-encrypt-key";
        let timestamp = "1700000000";
        let nonce = "nonce-xyz";
        let body = br#"{"encrypt":"..."}"#;
        // Reference digest computed via the same primitive.
        let sig = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(timestamp.as_bytes());
            h.update(nonce.as_bytes());
            h.update(encrypt_key.as_bytes());
            h.update(body);
            hex_encode(&h.finalize())
        };
        assert!(webhook::verify_lark_signature(
            encrypt_key.as_bytes(),
            timestamp,
            nonce,
            body,
            &sig
        ));
        assert!(!webhook::verify_lark_signature(
            encrypt_key.as_bytes(),
            timestamp,
            nonce,
            body,
            "deadbeef"
        ));
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn timestamp_freshness_rejects_stale_future_and_garbage() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let skew = Duration::from_secs(300);
        // Within the window (now, and just inside either edge) is accepted.
        assert!(webhook::unix_timestamp_is_fresh(&now.to_string(), skew));
        assert!(webhook::unix_timestamp_is_fresh(
            &(now - 299).to_string(),
            skew
        ));
        assert!(webhook::unix_timestamp_is_fresh(
            &(now + 299).to_string(),
            skew
        ));
        // Outside the window (past or future) is rejected.
        assert!(!webhook::unix_timestamp_is_fresh(
            &(now - 3600).to_string(),
            skew
        ));
        assert!(!webhook::unix_timestamp_is_fresh(
            &(now + 3600).to_string(),
            skew
        ));
        // Non-numeric / empty timestamps fail closed.
        assert!(!webhook::unix_timestamp_is_fresh("not-a-number", skew));
        assert!(!webhook::unix_timestamp_is_fresh("", skew));
    }

    #[tokio::test]
    async fn replay_guard_rejects_second_identical_delivery() {
        use arkret_bridge_messaging::runtime::db::{
            DatabaseManager, DbReplayGuardStore, MIGRATIONS,
        };

        // The handler keys the replay guard on `timestamp:nonce:signature`. A
        // captured (validly signed) delivery must be accepted at most once.
        #[cfg(feature = "sqlite")]
        let database_url = "sqlite://:memory:".to_owned();
        #[cfg(all(feature = "postgres", not(feature = "sqlite")))]
        let database_url =
            std::env::var("BRIDGES_TEST_DATABASE_URL").expect("isolated test database required");
        let db = Arc::new(
            DatabaseManager::connect(&arkret_bridge_messaging::runtime::DatabaseConfig {
                url: database_url,
                pool_size: 1,
            })
            .unwrap(),
        );
        db.run_migrations(MIGRATIONS).unwrap();
        let window = webhook::ReplayWindow::new(
            Arc::new(DbReplayGuardStore::new(db)),
            Duration::from_secs(300),
        );
        let key = format!(
            "1700000000:nonce-xyz-{}-{}:deadbeef",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        assert_eq!(
            window.check_and_record(key.as_str()).await.unwrap(),
            webhook::ReplayGuardVerdict::Fresh
        );
        assert_eq!(
            window.check_and_record(key.as_str()).await.unwrap(),
            webhook::ReplayGuardVerdict::Replay
        );
    }
}
