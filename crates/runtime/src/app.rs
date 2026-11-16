//! The generic bridge contract — carries **no** chat/messaging assumptions.
//!
//! The arkret SDK already provides the protocol primitives (the `AppletHandler`
//! inbound surface and `events_submit` outbound). This module adds only the
//! reusable *bridge runtime* on top of the SDK:
//!
//! - Inbound (arkret -> external): accepted native managed Devices deliver authenticated content
//!   through [`BridgeApp::on_native_content`].
//! - Outbound (external -> arkret): the adapter mints + submits events via
//!   [`crate::arkret_edge::ArkretEdge`] (any event kind, arbitrary payload).
//!
//! A bridge to a non-social system (IoT, ticketing, CI, …) implements
//! [`BridgeApp`] directly. Social/chat bridges use the ergonomic helpers in the
//! `arkret-bridge-messaging` crate, which are built on top of this same runtime.

#[cfg(feature = "runtime")]
use std::sync::Arc;
#[cfg(feature = "runtime")]
use std::time::Duration;

use arkret::{ActorId, ExternalRef};
#[cfg(feature = "runtime")]
use async_trait::async_trait;
#[cfg(feature = "runtime")]
use parking_lot::Mutex;

#[cfg(feature = "runtime")]
use crate::arkret_edge::ArkretEdge;
#[cfg(feature = "runtime")]
use crate::config::Config;
#[cfg(feature = "runtime")]
use crate::db::DatabaseManager;
#[cfg(feature = "runtime")]
use crate::error::{BridgeError, Result};
#[cfg(feature = "runtime")]
use crate::queue::ChannelQueue;

/// A resolved actor returned to the arkret server's `resolve_actor` probe.
#[derive(Clone, Debug)]
pub struct ResolvedActor {
    /// The stable Arkret actor identity.
    pub actor_id: ActorId,
    pub display_name: Option<String>,
    /// Provenance back to the upstream app.
    pub external_ref: Option<ExternalRef>,
}

/// A resolved realm returned to the arkret server's `resolve_realm` probe.
#[derive(Clone, Debug)]
pub struct ResolvedRealm {
    /// The canonical arkret realm id (as a string; parsed by the handler).
    pub realm_id: String,
    pub title: Option<String>,
    /// Provenance back to the upstream app.
    pub external_ref: Option<ExternalRef>,
}

/// Optional ghost/portal resolution backing the applet `resolve_actor` /
/// `resolve_realm` endpoints. The generic runtime owns no mapping schema, so a
/// higher layer (e.g. `arkret-bridge-messaging`) installs an implementation via
/// [`BridgeContext::set_resolver`]. When absent, both probes report
/// `exists: false`, preserving the previous behaviour.
pub trait AppletResolver: Send + Sync + 'static {
    fn resolve_actor(&self, actor_id: &str) -> Option<ResolvedActor>;
    fn resolve_realm(&self, realm_id_or_alias: &str) -> Option<ResolvedRealm>;
}

/// Runtime context shared with every adapter. Generic: it exposes the arkret
/// edge, the (schema-agnostic) database manager, a per-key serial queue, and a
/// shared HTTP client. No messaging-specific surface here.
#[cfg(feature = "runtime")]
pub struct BridgeContext {
    pub config: Arc<Config>,
    pub edge: Arc<ArkretEdge>,
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
        edge: Arc<ArkretEdge>,
        db: Arc<DatabaseManager>,
    ) -> Result<Self> {
        crate::install_default_crypto_provider();
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
    /// Whether this host consumes decrypted attachment bytes.
    fn native_attachments(&self) -> bool {
        false
    }
    /// The bridge name (e.g. `discord`, `iot-telemetry`).
    fn name(&self) -> &str;

    /// Start and run the external-side receive loop (gateway / websocket /
    /// webhook / poll). Submit outbound events via `ctx.edge`. Blocks until an
    /// error occurs.
    async fn run(self: Arc<Self>, ctx: Arc<BridgeContext>) -> Result<()>;

    /// Device-authenticated native content, with the immutable signed original
    /// and its decrypted local view kept distinct.
    #[cfg(feature = "managed-authoring")]
    async fn on_native_content(
        &self,
        _ctx: Arc<BridgeContext>,
        _content: &crate::managed_device::NativeContent,
    ) -> Result<()> {
        Err(BridgeError::App(
            "adapter has no native content consumer".into(),
        ))
    }

    /// Whether this bridge's inbound surface is the salvo `webhook_router`. When
    /// true, [`crate::run_bridge`] fails fast at startup if `webhook_router`
    /// returns `None` (e.g. a required body-signature key is missing), instead
    /// of silently running a process with no inbound plane (BRG-REL-001).
    /// Gateway / long-poll bridges leave this `false`.
    fn expects_webhook_inbound(&self) -> bool {
        false
    }

    /// Optional: webhook routes mounted on the core salvo service to receive
    /// app-initiated callbacks. Defaults to `None`.
    fn webhook_router(self: Arc<Self>, _ctx: Arc<BridgeContext>) -> Option<salvo::Router> {
        None
    }

    /// Optional trusted Applet protocol routes mounted on the loopback-by-
    /// default admin/edge plane. Product webhook routes must stay in
    /// [`Self::webhook_router`]; Applet protocol operations belong here.
    fn internal_router(self: Arc<Self>, _ctx: Arc<BridgeContext>) -> Option<salvo::Router> {
        None
    }
}

#[cfg(all(feature = "runtime", feature = "managed-authoring"))]
pub(crate) struct AppContentSink<A: BridgeApp> {
    pub ctx: Arc<BridgeContext>,
    pub app: Arc<A>,
}

#[cfg(all(feature = "runtime", feature = "managed-authoring"))]
#[async_trait]
impl<A: BridgeApp> crate::managed_device::NativeContentSink for AppContentSink<A> {
    fn requires_attachments(&self) -> bool {
        self.app.native_attachments()
    }
    async fn deliver(
        &self,
        _recipient: &crate::managed_device::NativeContentRecipient,
        content: &crate::managed_device::NativeContent,
    ) -> Result<()> {
        let key = content.original().event.realm_id.to_string();
        self.ctx
            .queue
            .run(&key, || {
                self.app.on_native_content(self.ctx.clone(), content)
            })
            .await
    }
}
