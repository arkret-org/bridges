//! # cokret-bridge-runtime
//!
//! A reusable **Applet bridge runtime** layered on top of the `cokret` SDK. The SDK
//! already provides the full protocol surface — the `AppletHandler` inbound
//! path and `events_submit` / event signing on the outbound path — so this
//! crate adds *no new protocol capability*. What it factors out (so that N
//! bridges don't each re-implement it) is:
//!
//! - **Inbound async pump**: turns the SDK's synchronous `AppletHandler`
//!   transaction pushes into an async [`cokret::Event`] stream + a background
//!   consumer ([`app::consume_inbound`]).
//! - **Outbound mint bookkeeping**: monotonic `actor_seq`, HLC generation,
//!   `applet_id` stamping and signing, wrapped in
//!   [`cokret_edge::CokretEdge::mint_event`] / `submit_event`.
//! - **App-runtime scaffolding**: config loading, a diesel pool + migration
//!   runner, a salvo server (applet routes + health/metrics + app webhooks),
//!   and the [`run_bridge`] orchestration loop.
//!
//! The base contract [`app::BridgeApp`] is **generic** (it deals in raw cokret
//! events) so it can back non-social integrations (IoT, ticketing, CI, ...).
//! Chat/social bridge helpers live in `cokret-bridge-messaging`; this runtime
//! intentionally does not expose message-shaped APIs.

pub mod app;
pub mod cache;
pub mod cokret_edge;
pub mod config;
pub mod db;
pub mod error;
pub mod logging;
pub mod media;
pub mod queue;
pub mod web;

pub use app::{BridgeApp, BridgeContext};
pub use cokret_edge::CokretEdge;
pub use config::Config;
pub use error::{BridgeError, Result};
pub use salvo;

use std::sync::Arc;

use tokio::sync::mpsc;

/// Wire up and run a generic bridge: load config -> build the cokret edge ->
/// build the database -> start the adapter and the web service.
///
/// `app_factory` receives a ready [`BridgeContext`] and returns the
/// [`BridgeApp`] adapter. Social bridges typically call
/// [`messaging::run_message_bridge`] instead, which adds the chat helpers.
pub async fn run_bridge<A, F>(config: Config, app_factory: F) -> Result<()>
where
    A: BridgeApp,
    F: FnOnce(Arc<BridgeContext>) -> Result<A>,
{
    let config = Arc::new(config);

    // Events pushed by the cokret server are queued first, then forwarded to
    // the adapter by the background consumer loop.
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();

    let edge = Arc::new(cokret_edge::CokretEdge::new(config.clone(), inbound_tx)?);
    let db = Arc::new(db::DatabaseManager::connect(&config.database)?);
    let ctx = Arc::new(BridgeContext::new(config.clone(), edge.clone(), db));

    let app = Arc::new(app_factory(ctx.clone())?);

    // 1) Background: consume cokret -> adapter events
    let consumer = {
        let ctx = ctx.clone();
        let app = app.clone();
        tokio::spawn(async move { app::consume_inbound(ctx, app, inbound_rx).await })
    };

    // 2) web: health/metrics + applet routes + app webhook routes
    let web = {
        let ctx = ctx.clone();
        let extra = app.clone().webhook_router(ctx.clone());
        tokio::spawn(async move { web::serve(ctx, extra).await })
    };

    // 3) The adapter's own receive loop (gateway/websocket/webhook/poll)
    let runner = {
        let ctx = ctx.clone();
        let app = app.clone();
        tokio::spawn(async move { app.run(ctx).await })
    };

    tracing::info!(bridge = %config.bridge.bridge_id, "cokret bridge started");

    tokio::select! {
        r = consumer => r.map_err(|e| BridgeError::Runtime(e.to_string()))?,
        r = web => r.map_err(|e| BridgeError::Runtime(e.to_string()))?,
        r = runner => r.map_err(|e| BridgeError::Runtime(e.to_string()))?,
    }
}
