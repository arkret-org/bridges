use std::time::Duration;

use arkret_bridge_runtime::{BridgeError, Result};
use serde_json::Value;

use crate::{send_json_expect, send_json_expect_status};

/// How a vendor token response reports request success.
#[derive(Clone, Copy)]
pub enum VendorTokenCheck {
    /// The token endpoint is successful when the HTTP status is 2xx.
    HttpStatus,
    /// The token endpoint is successful when the parsed JSON body matches.
    JsonBody(fn(&Value) -> bool),
}

/// Fetch a vendor access token with the shared HTTP/JSON/token/TTL skeleton.
///
/// `token_pointer` and `ttl_pointer` are JSON Pointers into the response body.
/// Missing or non-numeric TTL values fall back to `fallback_ttl`; a missing or
/// empty token is an error.
pub async fn fetch_vendor_token(
    request: reqwest::RequestBuilder,
    label: &str,
    check: VendorTokenCheck,
    token_pointer: &str,
    ttl_pointer: &str,
    fallback_ttl: Duration,
) -> Result<(String, Duration)> {
    let body = match check {
        VendorTokenCheck::HttpStatus => send_json_expect_status(request, label).await?,
        VendorTokenCheck::JsonBody(is_success) => {
            send_json_expect(request, label, is_success).await?
        }
    };
    vendor_token_from_body(&body, label, token_pointer, ttl_pointer, fallback_ttl)
}

fn vendor_token_from_body(
    body: &Value,
    label: &str,
    token_pointer: &str,
    ttl_pointer: &str,
    fallback_ttl: Duration,
) -> Result<(String, Duration)> {
    let token = body
        .pointer(token_pointer)
        .and_then(Value::as_str)
        .filter(|token| !token.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            BridgeError::App(format!("{label} response missing token at {token_pointer}"))
        })?;
    let ttl = body
        .pointer(ttl_pointer)
        .and_then(Value::as_u64)
        .map(Duration::from_secs)
        .unwrap_or(fallback_ttl);
    Ok((token, ttl))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn vendor_token_from_body_reads_token_and_ttl() {
        let (token, ttl) = vendor_token_from_body(
            &json!({
                "data": {
                    "access_token": "tok",
                    "expires_in": 123
                }
            }),
            "Example token",
            "/data/access_token",
            "/data/expires_in",
            Duration::from_secs(60),
        )
        .unwrap();

        assert_eq!(token, "tok");
        assert_eq!(ttl, Duration::from_secs(123));
    }

    #[test]
    fn vendor_token_from_body_uses_fallback_ttl() {
        let (_, ttl) = vendor_token_from_body(
            &json!({ "access_token": "tok" }),
            "Example token",
            "/access_token",
            "/expires_in",
            Duration::from_secs(60),
        )
        .unwrap();

        assert_eq!(ttl, Duration::from_secs(60));
    }

    #[test]
    fn vendor_token_from_body_rejects_missing_token() {
        let err = vendor_token_from_body(
            &json!({ "access_token": "" }),
            "Example token",
            "/access_token",
            "/expires_in",
            Duration::from_secs(60),
        )
        .unwrap_err();

        assert!(err.to_string().contains("missing token"));
    }
}
