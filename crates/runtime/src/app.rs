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
//! [`BridgeApp`] directly. Social/chat bridges use the ergonomic helpers in the
//! `cokret-bridge-messaging` crate, which are built on top of this same runtime.

use serde_json::Value;

#[cfg(feature = "runtime")]
use std::sync::Arc;
#[cfg(feature = "runtime")]
use std::time::Duration;

#[cfg(feature = "runtime")]
use async_trait::async_trait;
#[cfg(feature = "runtime")]
use cokret::Event;
#[cfg(feature = "runtime")]
use parking_lot::Mutex;
#[cfg(feature = "runtime")]
use tokio::sync::mpsc::UnboundedReceiver;

// `Value` is also used below for the ephemeral payload type.

#[cfg(feature = "runtime")]
use crate::cokret_edge::CokretEdge;
#[cfg(feature = "runtime")]
use crate::config::Config;
#[cfg(feature = "runtime")]
use crate::db::DatabaseManager;
#[cfg(feature = "runtime")]
use crate::error::{BridgeError, Result};
#[cfg(feature = "runtime")]
use crate::queue::ChannelQueue;

/// A resolved actor returned to the cokret server's `resolve_actor` probe.
#[derive(Clone, Debug)]
pub struct ResolvedActor {
    /// The canonical cokret actor DID (as a string; parsed by the handler).
    pub actor_id: String,
    pub display_name: Option<String>,
    /// Provenance back to the upstream app (e.g. `{ "app_user": "U123" }`).
    pub external_ref: Value,
}

/// A resolved realm returned to the cokret server's `resolve_realm` probe.
#[derive(Clone, Debug)]
pub struct ResolvedRealm {
    /// The canonical cokret realm id (as a string; parsed by the handler).
    pub realm_id: String,
    pub title: Option<String>,
    /// Provenance back to the upstream app (e.g. `{ "app_channel": "C123" }`).
    pub external_ref: Value,
}

/// Optional ghost/portal resolution backing the applet `resolve_actor` /
/// `resolve_realm` endpoints. The generic runtime owns no mapping schema, so a
/// higher layer (e.g. `cokret-bridge-messaging`) installs an implementation via
/// [`BridgeContext::set_resolver`]. When absent, both probes report
/// `exists: false`, preserving the previous behaviour.
pub trait AppletResolver: Send + Sync + 'static {
    fn resolve_actor(&self, actor_id: &str) -> Option<ResolvedActor>;
    fn resolve_realm(&self, realm_id_or_alias: &str) -> Option<ResolvedRealm>;
}

/// Runtime context shared with every adapter. Generic: it exposes the cokret
/// edge, the (schema-agnostic) database manager, a per-key serial queue, and a
/// shared HTTP client. No messaging-specific surface here.
#[cfg(feature = "runtime")]
pub struct BridgeContext {
    pub config: Arc<Config>,
    pub edge: Arc<CokretEdge>,
    pub db: Arc<DatabaseManager>,
    pub queue: ChannelQueue,
    pub http: reqwest::Client,
    /// Installed by a higher layer before the web service starts; read by the
    /// applet handler to answer actor/realm resolution probes.
    resolver: Mutex<Option<Arc<dyn AppletResolver>>>,
}

#[cfg(feature = "runtime")]
impl BridgeContext {
    pub fn new(
        config: Arc<Config>,
        edge: Arc<CokretEdge>,
        db: Arc<DatabaseManager>,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| BridgeError::Runtime(format!("build HTTP client: {err}")))?;
        Ok(Self {
            config,
            edge,
            db,
            queue: ChannelQueue::new(),
            http,
            resolver: Mutex::new(None),
        })
    }

    /// Install the actor/realm resolver. Must be called during the adapter
    /// factory (before the web service is spawned) to take effect.
    pub fn set_resolver(&self, resolver: Arc<dyn AppletResolver>) {
        *self.resolver.lock() = Some(resolver);
    }

    /// Current resolver, if any.
    pub fn resolver(&self) -> Option<Arc<dyn AppletResolver>> {
        self.resolver.lock().clone()
    }
}

/// The generic contract implemented by any bridge adapter.
#[cfg(feature = "runtime")]
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

    /// Handle an ephemeral payload (typing/presence/receipts) pushed by the
    /// server alongside events. The payload is raw JSON until a typed schema is
    /// defined; defaults to a no-op so it is observed rather than dropped.
    async fn on_ephemeral(&self, _ctx: Arc<BridgeContext>, _ephemeral: Value) -> Result<()> {
        Ok(())
    }

    /// Optional: webhook routes mounted on the core salvo service to receive
    /// app-initiated callbacks. Defaults to `None`.
    fn webhook_router(self: Arc<Self>, _ctx: Arc<BridgeContext>) -> Option<salvo::Router> {
        None
    }
}

/// Inbound consumer loop: events pushed by the cokret server -> adapter.
#[cfg(feature = "runtime")]
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

/// Ephemeral consumer loop: typing/presence/receipts pushed by the cokret
/// server -> adapter.
#[cfg(feature = "runtime")]
pub async fn consume_ephemeral<A: BridgeApp>(
    ctx: Arc<BridgeContext>,
    app: Arc<A>,
    mut rx: UnboundedReceiver<Value>,
) -> Result<()> {
    while let Some(ephemeral) = rx.recv().await {
        if let Err(e) = app.on_ephemeral(ctx.clone(), ephemeral).await {
            tracing::warn!(error = %e, "failed to forward ephemeral to adapter");
        }
    }
    Ok(())
}
