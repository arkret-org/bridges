//! cokret-bridge-teams executable entry point.

mod teams;

use std::sync::Arc;

use cokret_bridge_messaging::bridge_main;
use cokret_bridge_messaging::webhook::{JwtAuthConfig, JwtVerifier};
use serde::Deserialize;

use crate::teams::TeamsApp;

/// Bot Framework application credentials.
#[derive(Debug, Deserialize)]
struct AppConfig {
    app_id: String,
    app_password: String,
    /// The Bot Framework serviceUrl assembled when sending outbound messages
    /// (e.g. https://smba.trafficmanager.net/...).
    service_url: String,
    /// Inbound webhook Bearer JWT verification (issuer/audience/JWKS).
    inbound_jwt: JwtAuthConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge_main("cokret <-> Microsoft Teams bridge", |app: AppConfig, ctx| {
        Ok(TeamsApp::new(
            app.app_id,
            app.app_password,
            app.service_url,
            Arc::new(JwtVerifier::new(app.inbound_jwt, ctx.http.clone())),
        ))
    })
    .await
}
