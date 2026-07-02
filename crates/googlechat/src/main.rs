//! cokret-bridge-googlechat executable entry point.

mod googlechat;

use std::sync::Arc;

use cokret_bridge_messaging::bridge_main;
use cokret_bridge_messaging::runtime::BridgeError;
use cokret_bridge_messaging::webhook::{JwtAuthConfig, JwtVerifier};
use serde::Deserialize;

use crate::googlechat::{GoogleChatApp, GoogleChatAuth, ServiceAccountKey};

#[derive(Deserialize)]
struct AppConfig {
    /// Service account key (auto-refreshing); preferred over `token`.
    service_account_json: Option<ServiceAccountKey>,
    /// Back-compat static access token, short-lived only (expires in ~1h).
    token: Option<String>,
    /// Inbound webhook Bearer JWT verification (issuer/audience/JWKS).
    inbound_jwt: JwtAuthConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("cokret <-> Google Chat bridge", |app: AppConfig, ctx| {
        // Prefer a service account (auto-refreshing) over a static access token.
        let auth = match (app.service_account_json, app.token) {
            (Some(key), _) => GoogleChatAuth::ServiceAccount(Box::new(key)),
            (None, Some(token)) => GoogleChatAuth::StaticToken(token),
            (None, None) => {
                return Err(BridgeError::Config(
                    "config.app requires either service_account_json or token".into(),
                ));
            }
        };
        Ok(GoogleChatApp::new(
            auth,
            Arc::new(JwtVerifier::new(app.inbound_jwt, ctx.http.clone())),
        ))
    })
    .await
}
