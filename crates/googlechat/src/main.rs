//! arkret-bridge-googlechat executable entry point.

mod googlechat;

use std::sync::Arc;

use arkret_bridge_messaging::bridge_main;
use arkret_bridge_messaging::webhook::{JwtAuthConfig, JwtVerifier};
use serde::Deserialize;

use crate::googlechat::{GoogleChatApp, ServiceAccountKey};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppConfig {
    /// Service account key used for auto-refreshing OAuth2 access tokens.
    service_account_json: ServiceAccountKey,
    /// Inbound webhook Bearer JWT verification (issuer/audience/JWKS).
    inbound_jwt: JwtAuthConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("arkret <-> Google Chat bridge", |app: AppConfig, ctx| {
        Ok(GoogleChatApp::new(
            Box::new(app.service_account_json),
            Arc::new(JwtVerifier::new(app.inbound_jwt, ctx.http.clone())),
            ctx.token_cache("googlechat_chat_api_token"),
        ))
    })
    .await
}
