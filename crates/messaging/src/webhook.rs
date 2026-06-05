//! Small helpers for adapter-owned Salvo webhook handlers.

use std::sync::Arc;

use base64::Engine as _;
use hmac::{Hmac, Mac};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{InboundAppMessage, MessageContext};

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

/// Constant-time byte-slice equality. Use for all signature/secret comparisons
/// to avoid leaking match position through early-exit timing.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // A length mismatch short-circuits (the length itself is not secret); when
    // lengths match, `subtle` performs a fixed-time comparison.
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Encoding of an HMAC digest as carried in a signature header.
#[derive(Clone, Copy, Debug)]
pub enum SigEncoding {
    /// Lowercase hex (e.g. Meta `sha256=...`).
    Hex,
    /// Standard base64 (e.g. LINE, DingTalk `sign`).
    Base64,
}

fn encode_digest(bytes: &[u8], enc: SigEncoding) -> String {
    match enc {
        SigEncoding::Hex => hex::encode(bytes),
        SigEncoding::Base64 => base64::engine::general_purpose::STANDARD.encode(bytes),
    }
}

/// Verify `provided` equals `HMAC-SHA256(secret, body)` rendered in `enc`,
/// using a constant-time comparison. Returns false on any keying error.
pub fn verify_hmac_sha256(secret: &[u8], body: &[u8], provided: &str, enc: SigEncoding) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    let expected = encode_digest(&mac.finalize().into_bytes(), enc);
    constant_time_eq(expected.as_bytes(), provided.as_bytes())
}

/// Verify `provided` equals `HMAC-SHA1(secret, body)` rendered in `enc`,
/// using a constant-time comparison.
pub fn verify_hmac_sha1(secret: &[u8], body: &[u8], provided: &str, enc: SigEncoding) -> bool {
    let Ok(mut mac) = HmacSha1::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    let expected = encode_digest(&mac.finalize().into_bytes(), enc);
    constant_time_eq(expected.as_bytes(), provided.as_bytes())
}

/// Verify a Meta (WhatsApp / Messenger) `X-Hub-Signature-256` header of the
/// form `sha256=<hex>` against `HMAC-SHA256(app_secret, raw_body)`.
pub fn verify_meta_x_hub_signature_256(app_secret: &[u8], body: &[u8], header: &str) -> bool {
    let Some(hex_sig) = header.strip_prefix("sha256=") else {
        return false;
    };
    verify_hmac_sha256(app_secret, body, hex_sig, SigEncoding::Hex)
}

/// Compute lowercase-hex `SHA1(parts sorted lexicographically, concatenated)`.
/// Used by WeChat's接入校验 (`signature = sha1(sort(token, timestamp, nonce))`).
pub fn sha1_hex_sorted(parts: &[&str]) -> String {
    use sha1::Digest;
    let mut sorted: Vec<&str> = parts.to_vec();
    sorted.sort_unstable();
    let mut hasher = Sha1::new();
    hasher.update(sorted.concat().as_bytes());
    hex::encode(hasher.finalize())
}

/// Read the raw request body bytes, rendering a 400 and returning `None` on
/// failure. Needed by signature schemes that sign the exact wire bytes.
pub async fn raw_body(req: &mut Request, res: &mut Response) -> Option<Vec<u8>> {
    match req.payload().await {
        Ok(bytes) => Some(bytes.to_vec()),
        Err(err) => {
            bad_request(res, format!("failed to read request body: {err}"));
            None
        }
    }
}

pub async fn json_body(req: &mut Request, res: &mut Response) -> Option<Value> {
    match req.parse_json::<Value>().await {
        Ok(value) => Some(value),
        Err(err) => {
            bad_request(res, format!("invalid JSON body: {err}"));
            None
        }
    }
}

pub fn ok_json(res: &mut Response, value: Value) {
    res.render(Json(value));
}

pub fn ok_text(res: &mut Response, value: impl Into<String>) {
    res.render(Text::Plain(value.into()));
}

pub fn bad_request(res: &mut Response, message: impl Into<String>) {
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(json!({ "ok": false, "error": message.into() })));
}

pub fn unauthorized(res: &mut Response, message: impl Into<String>) {
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(json!({ "ok": false, "error": message.into() })));
}

pub async fn submit(ctx: Arc<MessageContext>, label: &str, inbound: InboundAppMessage) {
    if let Err(error) = ctx.submit_app_message(inbound).await {
        tracing::warn!(%error, bridge = label, "webhook submission failed");
    }
}

pub fn str_at<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

pub fn string_at(value: &Value, pointer: &str) -> Option<String> {
    str_at(value, pointer).map(str::to_owned)
}

pub fn first_string_at(value: &Value, pointers: &[&str]) -> Option<String> {
    pointers
        .iter()
        .find_map(|pointer| string_at(value, pointer))
}

pub fn body_text_from_json_string(raw: &str, key: &str) -> String {
    serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|value| value.get(key).and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| raw.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_only_identical() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 test case 1: key = 20 * 0x0b, data = "Hi There".
        let key = [0x0bu8; 20];
        let expected_hex = "b0344c61d8db38535ca8afceaf0bf12b\
                            881dc200c9833da726e9376c2e32cff7";
        assert!(verify_hmac_sha256(
            &key,
            b"Hi There",
            expected_hex,
            SigEncoding::Hex
        ));
        assert!(!verify_hmac_sha256(
            &key,
            b"Hi There",
            "deadbeef",
            SigEncoding::Hex
        ));
    }

    #[test]
    fn meta_x_hub_signature_requires_prefix_and_match() {
        let secret = b"app-secret";
        let body = br#"{"object":"page"}"#;
        // Compute the reference signature via the same primitive.
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        assert!(verify_meta_x_hub_signature_256(
            secret,
            body,
            &format!("sha256={sig}")
        ));
        // Missing prefix is rejected.
        assert!(!verify_meta_x_hub_signature_256(secret, body, &sig));
        // Wrong digest is rejected.
        assert!(!verify_meta_x_hub_signature_256(
            secret,
            body,
            "sha256=00"
        ));
    }

    #[test]
    fn wechat_signature_sorts_lexicographically() {
        // Reference values from WeChat docs-style ordering: sort then sha1.
        let token = "tok";
        let timestamp = "1700000000";
        let nonce = "abc";
        let a = sha1_hex_sorted(&[token, timestamp, nonce]);
        let b = sha1_hex_sorted(&[nonce, token, timestamp]);
        assert_eq!(a, b, "order of inputs must not change the digest");
        assert_eq!(a.len(), 40, "sha1 hex is 40 chars");
    }
}
