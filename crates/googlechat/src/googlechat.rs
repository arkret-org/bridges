//! Google Chat adapter (Google Chat REST API, pure reqwest).
//!
//! - Inbound (Google Chat -> cokret): Google Chat pushes message events via `/webhooks/googlechat`.
//! - Outbound (cokret → Google Chat): [`MessageBridge::send_to_app`] uses `ctx.http` to POST `https://chat.googleapis.com/v1/{space}/messages`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use cokret_bridge_messaging::runtime::cache::TokenCache;
use cokret_bridge_messaging::runtime::{BridgeError, Result, redact_sensitive_url_values};
use cokret_bridge_messaging::salvo::prelude::*;
use cokret_bridge_messaging::salvo::{self, affix_state};
use cokret_bridge_messaging::{
    AppMessageRef, InboundAppMessage, MessageBridge, MessageContext, OutboundAppMessage,
    SenderRenderStyle, webhook,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Google Chat API base.
const CHAT_API_BASE: &str = "https://chat.googleapis.com/v1";
/// Google OAuth2 token endpoint for the JWT-bearer grant.
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// OAuth2 scope required to post Chat messages as a bot.
const CHAT_BOT_SCOPE: &str = "https://www.googleapis.com/auth/chat.bot";
/// Lifetime (seconds) of the self-signed JWT assertion (Google caps this at 1h).
const ASSERTION_TTL_SECS: u64 = 3600;

/// A Google service-account JSON key (the relevant subset) used to mint
/// JWT-bearer assertions for the OAuth2 token endpoint.
#[derive(Clone, Deserialize)]
pub struct ServiceAccountKey {
    pub client_email: String,
    pub private_key: String,
    #[serde(default = "default_token_uri")]
    pub token_uri: String,
}

fn default_token_uri() -> String {
    GOOGLE_TOKEN_URL.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_token_uri_is_google_oauth_token_endpoint() {
        assert_eq!(default_token_uri(), "https://oauth2.googleapis.com/token");
    }
}

/// How the bridge authenticates outbound Chat API calls.
pub enum GoogleChatAuth {
    /// A ready OAuth2 access token. Expires (~1h) and is not auto-refreshed; kept
    /// for back-compat / short-lived testing only.
    StaticToken(String),
    /// A service account that mints a fresh access token on demand and caches it
    /// until shortly before expiry — the recommended, operable configuration.
    ServiceAccount(Box<ServiceAccountKey>),
}

/// Google Chat bridge adapter.
pub struct GoogleChatApp {
    auth: GoogleChatAuth,
    token_cache: TokenCache,
    inbound_jwt: Arc<webhook::JwtVerifier>,
}

#[derive(Serialize)]
struct JwtBearerClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

impl GoogleChatApp {
    pub fn new(auth: GoogleChatAuth, inbound_jwt: Arc<webhook::JwtVerifier>) -> Self {
        Self {
            auth,
            token_cache: TokenCache::new(),
            inbound_jwt,
        }
    }

    /// Obtain an OAuth2 access token for the Chat API. Static tokens are returned
    /// verbatim; a service account mints + caches a JWT-bearer grant so a
    /// long-running bridge keeps working past the ~1h token lifetime.
    async fn bearer_token(&self, ctx: &Arc<MessageContext>) -> Result<String> {
        match &self.auth {
            GoogleChatAuth::StaticToken(token) => Ok(token.clone()),
            GoogleChatAuth::ServiceAccount(key) => {
                self.token_cache
                    .get_or_try_refresh(|| async {
                        let (token, ttl) = fetch_service_account_token(ctx, key).await?;
                        Ok::<_, BridgeError>((token, ttl))
                    })
                    .await
            }
        }
    }
}

/// Mint a JWT-bearer assertion from the service account key and exchange it at
/// the Google token endpoint for an access token + its TTL.
async fn fetch_service_account_token(
    ctx: &Arc<MessageContext>,
    key: &ServiceAccountKey,
) -> Result<(String, Duration)> {
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let claims = JwtBearerClaims {
        iss: &key.client_email,
        scope: CHAT_BOT_SCOPE,
        aud: &key.token_uri,
        iat: now,
        exp: now + ASSERTION_TTL_SECS,
    };
    let encoding_key = EncodingKey::from_rsa_pem(key.private_key.as_bytes()).map_err(|e| {
        BridgeError::App(format!("Google service account private_key invalid: {e}"))
    })?;
    let assertion = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)
        .map_err(|e| BridgeError::App(format!("Google JWT assertion signing failed: {e}")))?;

    let resp = ctx
        .http
        .post(&key.token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &assertion),
        ])
        .send()
        .await
        .map_err(|e| {
            BridgeError::App(format!(
                "Google token request failed: {}",
                redact_sensitive_url_values(e.to_string())
            ))
        })?;
    let status = resp.status();
    let body: Value = resp.json().await.map_err(|e| {
        BridgeError::App(format!(
            "Google token parse failed (status={status}): {}",
            redact_sensitive_url_values(e.to_string())
        ))
    })?;
    if !status.is_success() {
        return Err(BridgeError::App(format!(
            "Google token exchange failed status={status}: {}",
            redact_sensitive_url_values(body.to_string())
        )));
    }
    let token = body
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| BridgeError::App("Google token response missing access_token".to_owned()))?
        .to_owned();
    let ttl = body
        .get("expires_in")
        .and_then(Value::as_u64)
        .unwrap_or(ASSERTION_TTL_SECS);
    Ok((token, Duration::from_secs(ttl)))
}

#[async_trait]
impl MessageBridge for GoogleChatApp {
    fn name(&self) -> &str {
        "googlechat"
    }

    async fn send_to_app(
        &self,
        ctx: Arc<MessageContext>,
        msg: OutboundAppMessage,
    ) -> Result<AppMessageRef> {
        // app_channel is the space resource name, like `spaces/AAAAAAAAAAA`.
        let space = msg.app_channel.trim_matches('/');
        let url = format!("{CHAT_API_BASE}/{space}/messages");
        let body = msg.rendered_body(SenderRenderStyle::Plain);
        let payload = json!({ "text": body });

        let token = self.bearer_token(&ctx).await?;
        let resp = ctx
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                BridgeError::App(format!(
                    "Google Chat send request failed: {}",
                    redact_sensitive_url_values(e.to_string())
                ))
            })?;

        let status = resp.status();
        let value: serde_json::Value = resp.json().await.map_err(|e| {
            BridgeError::App(format!(
                "Google Chat response parse failed (status={status}): {}",
                redact_sensitive_url_values(e.to_string())
            ))
        })?;
        if !status.is_success() {
            return Err(BridgeError::App(format!(
                "Google Chat send failed status={status}: {}",
                redact_sensitive_url_values(value.to_string())
            )));
        }

        // The message resource name returned on success looks like spaces/AAA/messages/BBB.CCC.
        let message_id = value
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default()
            .to_string();
        Ok(AppMessageRef {
            app_message_id: message_id,
        })
    }

    fn expects_webhook_inbound(&self) -> bool {
        true
    }

    fn webhook_router(self: Arc<Self>, ctx: Arc<MessageContext>) -> Option<salvo::Router> {
        Some(
            salvo::Router::with_path("webhooks/googlechat")
                .hoop(affix_state::inject(GoogleChatWebhookState {
                    ctx,
                    inbound_jwt: self.inbound_jwt.clone(),
                }))
                .post(googlechat_delivery),
        )
    }
}

#[derive(Clone)]
struct GoogleChatWebhookState {
    ctx: Arc<MessageContext>,
    inbound_jwt: Arc<webhook::JwtVerifier>,
}

#[handler]
async fn googlechat_delivery(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<GoogleChatWebhookState>() else {
        webhook::bad_request(res, "webhook state missing");
        return;
    };
    let authorization = req.header::<String>("authorization");
    if let Err(error) = state
        .inbound_jwt
        .verify_authorization(authorization.as_deref())
        .await
    {
        webhook::unauthorized(res, format!("Google Chat JWT rejected: {error}"));
        return;
    }
    let Some(body) = webhook::json_body(req, res).await else {
        return;
    };
    if body.get("type").and_then(Value::as_str) != Some("MESSAGE") {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    }
    let message = body.get("message").unwrap_or(&body);
    let Some(text) = webhook::str_at(message, "/text") else {
        webhook::ok_json(res, json!({ "ok": true }));
        return;
    };
    let channel = webhook::first_string_at(message, &["/space/name", "/thread/name"])
        .or_else(|| webhook::string_at(&body, "/space/name"))
        .unwrap_or_default();
    let user = webhook::first_string_at(&body, &["/user/name", "/sender/name"]).unwrap_or_default();
    let Some(message_id) = webhook::non_empty_string_at(message, "/name") else {
        webhook::bad_request(res, "Google Chat message name missing");
        return;
    };
    let outcome = webhook::submit(
        state.ctx.clone(),
        "googlechat",
        InboundAppMessage {
            app_channel: channel,
            app_user: user,
            app_message_id: message_id,
            body: text.to_owned(),
        },
    )
    .await;
    webhook::respond_submit(res, outcome);
}
