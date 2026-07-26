//! # arkret-bridge-runtime
//!
//! A reusable **Applet bridge runtime** layered on top of the `arkret` SDK. The SDK
//! already provides the full protocol surface — the `AppletHandler` inbound
//! path and `events_submit` / event signing on the outbound path — so this
//! crate adds *no new protocol capability*. What it factors out (so that N
//! bridges don't each re-implement it) is:
//!
//! - **Inbound async pump**: turns the SDK's synchronous `AppletHandler` transaction pushes into an
//!   async [`arkret::Event`] stream + a background consumer ([`app::consume_inbound`]).
//! - **Outbound mint bookkeeping**: monotonic `actor_seq`, HLC generation, `applet_id` stamping and
//!   one-pass signing, exposed through the asynchronous unsigned-mint methods on
//!   [`arkret_edge::ArkretEdge`].
//! - **App-runtime scaffolding**: config loading, a diesel pool + migration runner, a salvo server
//!   (applet routes + health/metrics + app webhooks), and the [`run_bridge`] orchestration loop.
//!
//! The base contract [`app::BridgeApp`] is **generic** (it deals in raw arkret
//! events) so it can back non-social integrations (IoT, ticketing, CI, ...).
//! Chat/social bridge helpers live in `arkret-bridge-messaging`; this runtime
//! intentionally does not expose message-shaped APIs.
//!
//! ## Cargo features
//!
//! - `edge` (always available): the protocol edge ([`ArkretEdge`], the [`SeqStore`] trait +
//!   [`SeqAllocator`], config, errors, cache/queue, and blob helpers) without diesel or salvo. A
//!   host injects its own [`SeqStore`].
//! - `db`: the diesel-backed database pool ([`db`]) and [`DbSeqStore`].
//! - `web`: the salvo HTTP service ([`web`]).
//! - `runtime` (= `db` + `web`): [`BridgeContext`] / [`BridgeApp`] / [`run_bridge`].
//! - `full` (= `db` + `web` + `runtime`) and `default` (= `full` + `sqlite`) keep all historical
//!   behavior.

pub mod app;
mod arkret_edge;
pub mod backoff;
pub mod blocking;
pub mod cache;
mod config;
pub mod dead_letter;
mod error;
mod file_seq_store;
pub mod idempotency;
pub mod logging;
pub mod queue;
pub mod telemetry;

#[cfg(feature = "db")]
pub mod db;
#[cfg(feature = "web")]
pub mod web;

#[cfg(feature = "runtime")]
use std::sync::Arc;

pub use app::{AppletResolver, ResolvedActor, ResolvedRealm};
#[cfg(feature = "runtime")]
pub use app::{BridgeApp, BridgeContext};
pub use arkret::{IdempotencyIdentity, TransactionClaim, TransactionIdempotencyStore};
#[cfg(feature = "db")]
pub use arkret_edge::DbSeqStore;
pub use arkret_edge::{ArkretEdge, SeqAllocator, SeqStore};
pub use backoff::{exponential_backoff_with_jitter, jittered_delay};
pub use blocking::run_blocking;
pub use cache::{PersistedToken, TokenCache, TokenStore};
pub use config::{Config, DatabaseConfig, WebhookRateLimitConfig};
#[cfg(feature = "db")]
pub use db::{
    DbEventDedupStore, DbOutboundDeadLetterStore, DbReplayGuardStore, DbTokenStore,
    DbTransactionIdempotencyStore,
};
pub use dead_letter::{
    OUTBOUND_DEAD_LETTER_REPLAY_INTERVAL_SECS, OutboundDeadLetter, OutboundDeadLetterRecord,
    OutboundDeadLetterStore,
};
pub use error::{BridgeError, Result, redact_sensitive_url_values};
pub use file_seq_store::FileSeqStore;
pub use idempotency::{
    DedupVerdict, EventDedupStore, MemoryEventDedupStore, MemoryTransactionIdempotencyStore,
    ReplayGuardStore, ReplayGuardVerdict,
};
#[cfg(feature = "web")]
pub use salvo;
pub use telemetry::increment_counter;
#[cfg(feature = "runtime")]
use tokio::sync::mpsc;

/// Install the workspace-default rustls provider before constructing HTTP
/// clients. If a host already installed a provider, preserve that choice.
pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Wire up and run a generic bridge: load config -> build the arkret edge ->
/// build the database -> start the adapter and the web service.
///
/// `app_factory` receives a ready [`BridgeContext`] and returns the
/// [`BridgeApp`] adapter. Social bridges typically call
/// [`messaging::run_message_bridge`] instead, which adds the chat helpers.
#[cfg(feature = "runtime")]
pub async fn run_bridge<A, F>(config: Config, app_factory: F) -> Result<()>
where
    A: BridgeApp,
    F: FnOnce(Arc<BridgeContext>) -> Result<A>,
{
    install_default_crypto_provider();
    let config = Arc::new(config);

    // Events pushed by the arkret server are queued first, then forwarded to
    // the adapter by the background consumer loop. Bounded so a slow consumer
    // applies backpressure (the applet handler returns `retry_after_ms` when
    // full) instead of buffering without limit (BRG-02-001).
    let (inbound_tx, inbound_rx) = mpsc::channel(arkret_edge::INBOUND_QUEUE_CAPACITY);
    // Ephemeral (typing/presence/receipts) is best-effort and may be dropped.
    // Keep it bounded so a slow adapter cannot turn provider bursts into
    // unbounded process memory growth.
    let (ephemeral_tx, ephemeral_rx) = mpsc::channel(arkret_edge::EPHEMERAL_QUEUE_CAPACITY);

    let db = Arc::new(db::DatabaseManager::connect(&config.database)?);
    // The diesel-backed restart-safe sequence store, injected into the edge.
    let seq: Arc<dyn SeqStore> = Arc::new(DbSeqStore::new(db.clone())?);

    let mut edge = ArkretEdge::new(config.clone(), seq, inbound_tx)?;
    edge.set_ephemeral_sender(ephemeral_tx);
    let edge = Arc::new(edge);

    let ctx = Arc::new(BridgeContext::new(config.clone(), edge.clone(), db)?);

    let app = Arc::new(app_factory(ctx.clone())?);

    // 1) Background: consume arkret -> adapter events
    let consumer = {
        let ctx = ctx.clone();
        let app = app.clone();
        tokio::spawn(async move { app::consume_inbound(ctx, app, inbound_rx).await })
    };

    // 1b) Background: consume ephemeral -> adapter
    let ephemeral_consumer = {
        let ctx = ctx.clone();
        let app = app.clone();
        tokio::spawn(async move { app::consume_ephemeral(ctx, app, ephemeral_rx).await })
    };

    // 1c) Background: retry persisted arkret -> adapter dead letters.
    let dead_letter_replayer = {
        let ctx = ctx.clone();
        let app = app.clone();
        tokio::spawn(async move { app::replay_outbound_dead_letters(ctx, app).await })
    };

    // 2) web: health/metrics + applet routes + app webhook routes
    let web = {
        let ctx = ctx.clone();
        let extra = app.clone().webhook_router(ctx.clone());
        // Fail fast (BRG-REL-001): a bridge whose inbound surface is the webhook
        // router MUST mount it. If the router is `None` (e.g. a required
        // body-signature key such as Feishu `encrypt_key` is missing) we refuse
        // to start rather than run a "healthy" process with no inbound plane,
        // which would silently drop every inbound message.
        if app.expects_webhook_inbound() && extra.is_none() {
            return Err(BridgeError::Config(format!(
                "bridge `{}` declares a webhook inbound surface but webhook_router \
                 returned None; a required inbound credential (e.g. body-signature \
                 key) is likely missing — refusing to start with no inbound plane",
                config.bridge.bridge_id
            )));
        }
        tokio::spawn(async move { web::serve(ctx, extra).await })
    };

    // 3) The adapter's own receive loop (gateway/websocket/webhook/poll)
    let runner = {
        let ctx = ctx.clone();
        let app = app.clone();
        tokio::spawn(async move { app.run(ctx).await })
    };

    tracing::info!(bridge = %config.bridge.bridge_id, "arkret bridge started");

    tokio::select! {
        r = consumer => r.map_err(|e| BridgeError::Runtime(e.to_string()))?,
        r = ephemeral_consumer => r.map_err(|e| BridgeError::Runtime(e.to_string()))?,
        r = dead_letter_replayer => r.map_err(|e| BridgeError::Runtime(e.to_string()))?,
        r = web => r.map_err(|e| BridgeError::Runtime(e.to_string()))?,
        r = runner => r.map_err(|e| BridgeError::Runtime(e.to_string()))?,
    }
}
