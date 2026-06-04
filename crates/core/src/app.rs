//! The generic bridge contract — carries **no** chat/messaging assumptions.
//!
//! The cokret SDK already provides the protocol primitives (the `AppletHandler`
//! inbound surface and `events_submit` outbound). This module adds only the
//! reusable *bridge runtime* on top of the SDK:
//!
//! - Inbound (cokret -> external): the cokret server pushes transactions; the
//!   core turns them into an async stream and calls
//!   [`BridgeApp::on_cokret_event`] with the raw [`cokret::Event`].
//! - Outbound (external -> cokret): the adapter mints + submits events via
//!   [`crate::cokret_edge::CokretEdge`] (any event kind, arbitrary payload).
//!
//! A bridge to a non-social system (IoT, ticketing, CI, …) implements
//! [`BridgeApp`] directly. Social/chat bridges use the ergonomic helpers in
//! [`crate::messaging`], which are built on top of this same runtime.

use std::sync::Arc;

use async_trait::async_trait;
use cokret::Event;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::cokret_edge::CokretEdge;
use crate::config::Config;
use crate::db::DatabaseManager;
use crate::error::Result;
use crate::queue::ChannelQueue;

/// Runtime context shared with every adapter. Generic: it exposes the cokret
/// edge, the (schema-agnostic) database manager, a per-key serial queue, and a
/// shared HTTP client. No messaging-specific surface here.
pub struct BridgeContext {
    pub config: Arc<Config>,
    pub edge: Arc<CokretEdge>,
    pub db: Arc<DatabaseManager>,
    pub queue: ChannelQueue,
    pub http: reqwest::Client,
}

impl BridgeContext {
    pub fn new(config: Arc<Config>, edge: Arc<CokretEdge>, db: Arc<DatabaseManager>) -> Self {
        Self {
            config,
            edge,
            db,
            queue: ChannelQueue::new(),
            http: reqwest::Client::new(),
        }
    }
}

/// The generic contract implemented by any bridge adapter.
#[async_trait]
pub trait BridgeApp: Send + Sync + 'static {
    /// The bridge name (e.g. `discord`, `iot-telemetry`).
    fn name(&self) -> &str;

    /// Start and run the external-side receive loop (gateway / websocket /
    /// webhook / poll). Submit outbound events via `ctx.edge`. Blocks until an
    /// error occurs.
    async fn run(self: Arc<Self>, ctx: Arc<BridgeContext>) -> Result<()>;

    /// Handle one raw cokret event pushed by the server. The adapter decides
    /// what (if anything) to do with each event kind.
    async fn on_cokret_event(&self, ctx: Arc<BridgeContext>, event: Event) -> Result<()>;

    /// Optional: webhook routes mounted on the core salvo service to receive
    /// app-initiated callbacks. Defaults to `None`.
    fn webhook_router(self: Arc<Self>, _ctx: Arc<BridgeContext>) -> Option<salvo::Router> {
        None
    }
}

/// Inbound consumer loop: events pushed by the cokret server -> adapter.
pub async fn consume_inbound<A: BridgeApp>(
    ctx: Arc<BridgeContext>,
    app: Arc<A>,
    mut rx: UnboundedReceiver<Event>,
) -> Result<()> {
    while let Some(event) = rx.recv().await {
        if let Err(e) = app.on_cokret_event(ctx.clone(), event).await {
            tracing::warn!(error = %e, "failed to forward cokret event to adapter");
        }
    }
    Ok(())
}
