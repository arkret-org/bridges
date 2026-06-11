//! Small helpers for adapter-owned Salvo webhook handlers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

use crate::{InboundAppMessage, MessageContext};

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

pub const MAX_WEBHOOK_BODY_BYTES: usize = 1024 * 1024;
const JWT_JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

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

/// Handle the Meta (WhatsApp / Messenger) GET webhook verification handshake:
/// echo `hub.challenge` when `hub.mode == "subscribe"` and `hub.verify_token`
/// matches `verify_token` (constant time); reject with 401 otherwise. An empty
/// configured token always rejects (fail closed).
pub fn meta_hub_verify(req: &mut Request, res: &mut Response, verify_token: &str) {
    let mode = req.query::<String>("hub.mode").unwrap_or_default();
    let token = req.query::<String>("hub.verify_token").unwrap_or_default();
    let challenge = req.query::<String>("hub.challenge").unwrap_or_default();
    let token_ok =
        !verify_token.is_empty() && constant_time_eq(token.as_bytes(), verify_token.as_bytes());
    if mode == "subscribe" && token_ok {
        ok_text(res, challenge);
    } else {
        unauthorized(res, "Meta hub.verify_token mismatch");
    }
}

/// The fail-closed preamble shared by Meta (WhatsApp / Messenger) POST
/// delivery handlers: require a configured `app_secret`, read the raw body,
/// verify `X-Hub-Signature-256` over the exact wire bytes, then parse JSON.
/// On any failure the response is already rendered and `None` is returned.
pub async fn meta_signed_json_body(
    req: &mut Request,
    res: &mut Response,
    app_secret: &str,
) -> Option<(Vec<u8>, Value)> {
    // Fail closed: every POST delivery MUST carry a valid
    // `X-Hub-Signature-256: sha256=<hmac>` over the exact raw body.
    if app_secret.is_empty() {
        unauthorized(res, "Meta app_secret not configured");
        return None;
    }
    let raw = raw_body(req, res).await?;
    let signature = req
        .header::<String>("x-hub-signature-256")
        .unwrap_or_default();
    if !verify_meta_x_hub_signature_256(app_secret.as_bytes(), &raw, &signature) {
        unauthorized(res, "Meta X-Hub-Signature-256 mismatch");
        return None;
    }
    match serde_json::from_slice::<Value>(&raw) {
        Ok(body) => Some((raw, body)),
        Err(err) => {
            bad_request(res, format!("invalid Meta webhook JSON body: {err}"));
            None
        }
    }
}

/// Compute lowercase-hex `SHA1(parts sorted lexicographically, concatenated)`.
/// Used by WeChat server verification (`signature = sha1(sort(token, timestamp, nonce))`).
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
        Ok(bytes) if bytes.len() <= MAX_WEBHOOK_BODY_BYTES => Some(bytes.to_vec()),
        Ok(bytes) => {
            payload_too_large(
                res,
                format!(
                    "webhook body is {} bytes; limit is {} bytes",
                    bytes.len(),
                    MAX_WEBHOOK_BODY_BYTES
                ),
            );
            None
        }
        Err(err) => {
            bad_request(res, format!("failed to read request body: {err}"));
            None
        }
    }
}

pub async fn json_body(req: &mut Request, res: &mut Response) -> Option<Value> {
    let bytes = raw_body(req, res).await?;
    match serde_json::from_slice::<Value>(&bytes) {
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

pub fn payload_too_large(res: &mut Response, message: impl Into<String>) {
    res.status_code(StatusCode::PAYLOAD_TOO_LARGE);
    res.render(Json(json!({ "ok": false, "error": message.into() })));
}

/// Configuration for webhook sources that authenticate with a Bearer JWT whose
/// signing keys are published as JWKS.
#[derive(Clone, Debug, Deserialize)]
pub struct JwtAuthConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
}

#[derive(Clone)]
struct CachedJwks {
    set: Arc<JwkSet>,
    expires_at: Instant,
}

/// Minimum interval between JWKS refreshes triggered by an unknown `kid`. Bounds
/// the outbound-amplification / upstream-rate-limit DoS where an attacker sends
/// JWTs with random kids to force one JWKS fetch each.
const JWKS_MISSING_KEY_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// JWKS-backed Bearer JWT verifier shared by Google Chat and Teams webhook
/// handlers.
pub struct JwtVerifier {
    config: JwtAuthConfig,
    http: reqwest::Client,
    jwks: RwLock<Option<CachedJwks>>,
    /// Last time a MissingKey-triggered refresh was actually performed; used to
    /// throttle refreshes for unknown kids.
    last_missing_key_refresh: RwLock<Option<Instant>>,
}

enum JwtDecodeFailure {
    MissingKey,
    Invalid(String),
}

impl JwtVerifier {
    pub fn new(config: JwtAuthConfig, http: reqwest::Client) -> Self {
        Self {
            config,
            http,
            jwks: RwLock::new(None),
            last_missing_key_refresh: RwLock::new(None),
        }
    }

    pub async fn verify_authorization(
        &self,
        authorization: Option<&str>,
    ) -> std::result::Result<Value, String> {
        let token = bearer_token(authorization)?;
        let header = decode_header(token).map_err(|err| format!("JWT header is invalid: {err}"))?;
        if !matches!(header.alg, Algorithm::RS256) {
            return Err("JWT alg must be RS256".to_owned());
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|kid| !kid.trim().is_empty())
            .ok_or_else(|| "JWT kid header is required".to_owned())?;

        let jwks = self.cached_jwks().await?;
        match self.decode_with_jwks(token, kid, &jwks) {
            Ok(claims) => Ok(claims),
            Err(JwtDecodeFailure::MissingKey) => {
                // Throttle refreshes for unknown kids so a flood of random-kid
                // JWTs cannot amplify into an equal flood of JWKS fetches (and the
                // resulting upstream rate-limiting). Within the cool-down window
                // we reject without re-fetching.
                {
                    let last = *self.last_missing_key_refresh.read().await;
                    if let Some(last) = last
                        && last.elapsed() < JWKS_MISSING_KEY_REFRESH_MIN_INTERVAL
                    {
                        return Err("JWT kid is not present in JWKS".to_owned());
                    }
                }
                *self.last_missing_key_refresh.write().await = Some(Instant::now());
                let refreshed = self.refresh_jwks().await?;
                self.decode_with_jwks(token, kid, &refreshed)
                    .map_err(jwt_decode_failure_message)
            }
            Err(err) => Err(jwt_decode_failure_message(err)),
        }
    }

    async fn cached_jwks(&self) -> std::result::Result<Arc<JwkSet>, String> {
        let now = Instant::now();
        if let Some(cached) = self.jwks.read().await.as_ref()
            && cached.expires_at > now
        {
            return Ok(cached.set.clone());
        }
        self.refresh_jwks().await
    }

    async fn refresh_jwks(&self) -> std::result::Result<Arc<JwkSet>, String> {
        let set = self
            .http
            .get(&self.config.jwks_url)
            .send()
            .await
            .map_err(|err| format!("JWKS fetch failed: {err}"))?
            .error_for_status()
            .map_err(|err| format!("JWKS fetch failed: {err}"))?
            .json::<JwkSet>()
            .await
            .map_err(|err| format!("JWKS parse failed: {err}"))?;
        let set = Arc::new(set);
        *self.jwks.write().await = Some(CachedJwks {
            set: set.clone(),
            expires_at: Instant::now() + JWT_JWKS_CACHE_TTL,
        });
        Ok(set)
    }

    fn decode_with_jwks(
        &self,
        token: &str,
        kid: &str,
        jwks: &JwkSet,
    ) -> std::result::Result<Value, JwtDecodeFailure> {
        let jwk = jwks
            .keys
            .iter()
            .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))
            .ok_or(JwtDecodeFailure::MissingKey)?;
        let key = DecodingKey::from_jwk(jwk)
            .map_err(|err| JwtDecodeFailure::Invalid(format!("JWT JWK is invalid: {err}")))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.set_audience(&[self.config.audience.as_str()]);
        let data = decode::<Value>(token, &key, &validation)
            .map_err(|err| JwtDecodeFailure::Invalid(format!("JWT verification failed: {err}")))?;
        Ok(data.claims)
    }
}

fn jwt_decode_failure_message(err: JwtDecodeFailure) -> String {
    match err {
        JwtDecodeFailure::MissingKey => "JWT kid is not present in JWKS".to_owned(),
        JwtDecodeFailure::Invalid(message) => message,
    }
}

fn bearer_token(authorization: Option<&str>) -> std::result::Result<&str, String> {
    let value = authorization
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "Authorization Bearer JWT is required".to_owned())?;
    let mut parts = value.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or_default();
    let token = parts
        .next()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| "Authorization Bearer JWT is malformed".to_owned())?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err("Authorization scheme must be Bearer".to_owned());
    }
    Ok(token)
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

pub fn non_empty_string_at(value: &Value, pointer: &str) -> Option<String> {
    string_at(value, pointer).and_then(|s| if s.trim().is_empty() { None } else { Some(s) })
}

pub fn first_non_empty_string_at(value: &Value, pointers: &[&str]) -> Option<String> {
    pointers
        .iter()
        .find_map(|pointer| non_empty_string_at(value, pointer))
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
        assert!(!verify_meta_x_hub_signature_256(secret, body, "sha256=00"));
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

    #[test]
    fn bearer_token_requires_bearer_scheme() {
        assert_eq!(bearer_token(Some("Bearer abc.def")).unwrap(), "abc.def");
        assert_eq!(bearer_token(Some("bearer   abc")).unwrap(), "abc");
        assert!(bearer_token(None).is_err());
        assert!(bearer_token(Some("Basic abc")).is_err());
        assert!(bearer_token(Some("Bearer")).is_err());
    }
}
