//! The generic bridge contract — carries **no** chat/messaging assumptions.
//!
//! The arkret SDK already provides the protocol primitives (the `AppletHandler`
//! inbound surface and `events_submit` outbound). This module adds only the
//! reusable *bridge runtime* on top of the SDK:
//!
//! - Inbound (arkret -> external): the arkret server pushes transactions; the core turns them into
//!   an async stream and calls [`BridgeApp::on_arkret_event`] with the raw [`arkret::Event`].
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

#[cfg(feature = "runtime")]
use arkret::Event;
use arkret::ExternalRef;
#[cfg(feature = "runtime")]
use arkret_wire::SignalEnvelope;
#[cfg(feature = "runtime")]
use async_trait::async_trait;
#[cfg(feature = "runtime")]
use parking_lot::Mutex;
#[cfg(feature = "runtime")]
use tokio::sync::mpsc::Receiver;

#[cfg(feature = "runtime")]
use crate::arkret_edge::ArkretEdge;
#[cfg(feature = "runtime")]
use crate::config::Config;
#[cfg(feature = "runtime")]
use crate::db::{DatabaseManager, DbOutboundDeadLetterStore};
#[cfg(feature = "runtime")]
use crate::dead_letter::{OutboundDeadLetterRecord, OutboundDeadLetterStore};
#[cfg(feature = "runtime")]
use crate::error::{BridgeError, Result, redact_sensitive_url_values};
#[cfg(feature = "runtime")]
use crate::queue::ChannelQueue;

/// A resolved actor returned to the arkret server's `resolve_actor` probe.
#[derive(Clone, Debug)]
pub struct ResolvedActor {
    /// The canonical arkret actor DID (as a string; parsed by the handler).
    pub actor_id: String,
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
    pub dead_letters: Arc<dyn OutboundDeadLetterStore>,
    pub queue: ChannelQueue,
    pub http: reqwest::Client,
    /// Installed by a higher layer before the web service starts; read by the
    /// applet handler to answer actor/realm resolution probes.
    resolver: Mutex<Option<Arc<dyn AppletResolver>>>,
    /// The set of arkret event kinds this bridge actually consumes on the inbound
    /// (arkret → app) path, declared by a higher layer (e.g. messaging declares
    /// `ak.message.create` + `ak.message.redact`). The applet handler rejects any
    /// pushed event whose kind is not in this set as `capability_denied`
    /// (applet-integration §7/§13 capability enforcement). `None` (the generic
    /// default) is permissive: a bridge that has not declared a kind set accepts
    /// every kind, preserving prior behaviour for non-messaging bridges.
    handled_event_kinds: Mutex<Option<Vec<String>>>,
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
            dead_letters: Arc::new(DbOutboundDeadLetterStore::new(db.clone())),
            db,
            queue: ChannelQueue::new(),
            http,
            resolver: Mutex::new(None),
            handled_event_kinds: Mutex::new(None),
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

    /// Declare the inbound event kinds this bridge consumes (capability
    /// enforcement). Must be called during the adapter factory (before the web
    /// service is spawned) to take effect. Empty input is ignored (a bridge that
    /// handles nothing would otherwise reject everything).
    pub fn set_handled_event_kinds<I, S>(&self, kinds: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let kinds: Vec<String> = kinds.into_iter().map(Into::into).collect();
        if kinds.is_empty() {
            return;
        }
        *self.handled_event_kinds.lock() = Some(kinds);
    }

    /// The declared inbound event-kind set, if any.
    pub fn handled_event_kinds(&self) -> Option<Vec<String>> {
        self.handled_event_kinds.lock().clone()
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

    /// Handle one raw arkret event pushed by the server. The adapter decides
    /// what (if anything) to do with each event kind.
    async fn on_arkret_event(&self, ctx: Arc<BridgeContext>, event: Event) -> Result<()>;

    /// Handle an encrypted Signal pushed alongside events as the SDK
    /// [`SignalEnvelope`] wire type. Product kind and payload stay encrypted;
    /// adapters must not infer them from the server-visible outer header.
    async fn on_signal(&self, _ctx: Arc<BridgeContext>, _signal: SignalEnvelope) -> Result<()> {
        Ok(())
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

/// Maximum delivery attempts for one inbound (arkret → app) event before it is
/// dead-lettered. Only transient ([`BridgeError::is_retriable`]) failures are
/// retried; deterministic failures fail fast on the first attempt.
#[cfg(feature = "runtime")]
const INBOUND_MAX_DELIVERY_ATTEMPTS: u32 = 4;

/// Base backoff between inbound delivery retries; doubled each attempt.
#[cfg(feature = "runtime")]
const INBOUND_RETRY_BASE_BACKOFF: Duration = Duration::from_millis(200);

/// Maximum dead-letter rows replayed in one scan tick.
#[cfg(feature = "runtime")]
const OUTBOUND_DEAD_LETTER_SCAN_LIMIT: u32 = 100;

/// Per-realm worker mailbox depth. Each realm gets its own ordered worker; this
/// bounds how far ahead the dispatcher may run before a slow realm applies
/// back-pressure to the shared dispatch loop (which in turn back-pressures the
/// applet handler's bounded inbound queue).
#[cfg(feature = "runtime")]
const INBOUND_REALM_MAILBOX_DEPTH: usize = 256;

/// How long a per-realm worker may sit idle (no events received) before it
/// exits and its `workers` map entry is reclaimed. Without this, deployments
/// with high realm cardinality (e.g. per-user PSID/chat realms on
/// WhatsApp/Messenger/Telegram) would grow the worker map and the count of
/// resident tokio tasks without bound for the life of the process (BRG-02-005).
/// A reclaimed realm's worker is transparently recreated when its next event
/// arrives; per-realm ordering still holds because at most one worker runs for
/// a given realm at any instant.
#[cfg(feature = "runtime")]
const INBOUND_REALM_IDLE_TTL: Duration = Duration::from_secs(300);

/// Inbound consumer loop: events pushed by the arkret server -> adapter.
///
/// Events are routed to a per-realm worker so distinct realms drain in parallel
/// (one slow channel no longer head-of-line-blocks the rest) while events within
/// a realm stay strictly ordered (each worker drains its mailbox sequentially in
/// receive order). Delivery to the adapter is retried with exponential backoff on
/// transient failures and dead-lettered after [`INBOUND_MAX_DELIVERY_ATTEMPTS`]
/// (BRG-02-002).
#[cfg(feature = "runtime")]
pub async fn consume_inbound<A: BridgeApp>(
    ctx: Arc<BridgeContext>,
    app: Arc<A>,
    mut rx: Receiver<Event>,
) -> Result<()> {
    use std::collections::HashMap;

    use tokio::sync::mpsc;

    // One ordered worker per realm. Workers self-exit after
    // `INBOUND_REALM_IDLE_TTL` of inactivity (or at shutdown when their sender is
    // dropped) so the map and the count of resident tasks stay bounded even with
    // high realm cardinality (BRG-02-005). A reclaimed realm is recreated on its
    // next event; ordering holds because at most one worker exists per realm at
    // any instant.
    let mut workers: HashMap<String, mpsc::Sender<Event>> = HashMap::new();

    // Spawn a fresh ordered worker for `realm`, returning its mailbox sender. The
    // worker drains events strictly in order and exits once idle past the TTL.
    let spawn_worker = |realm: String| -> mpsc::Sender<Event> {
        let (tx, mut worker_rx) = mpsc::channel::<Event>(INBOUND_REALM_MAILBOX_DEPTH);
        let ctx = ctx.clone();
        let app = app.clone();
        tokio::spawn(async move {
            loop {
                match tokio::time::timeout(INBOUND_REALM_IDLE_TTL, worker_rx.recv()).await {
                    // Sender dropped (shutdown / realm reclaimed): exit.
                    Ok(None) => break,
                    Ok(Some(event)) => {
                        deliver_inbound_event(ctx.clone(), app.clone(), event).await;
                    }
                    // Idle past the TTL with an empty mailbox: exit so the entry
                    // can be reclaimed. The dispatcher recreates the worker if the
                    // realm sees traffic again.
                    Err(_) => {
                        tracing::debug!(realm = %realm, "inbound realm worker idle; reclaiming");
                        break;
                    }
                }
            }
        });
        tx
    };

    while let Some(event) = rx.recv().await {
        let realm = event.realm_id.to_string();

        // Reclaim map entries whose worker has self-exited (idle TTL) or
        // panicked: a closed sender means its receiver was dropped. Pruning here
        // keeps the map bounded by the count of *currently active* realms rather
        // than the total ever seen (BRG-02-005). Cheap: `is_closed` is a flag
        // read, and the entry for the realm we are about to serve is recreated
        // just below if it was pruned.
        workers.retain(|_, tx| !tx.is_closed());

        let mut tx = workers
            .entry(realm.clone())
            .or_insert_with(|| spawn_worker(realm.clone()))
            .clone();
        // Await the per-realm mailbox: a full mailbox back-pressures the shared
        // dispatcher (and thus the applet handler's bounded queue) rather than
        // buffering without limit. A closed worker means it exited (idle-reclaimed
        // or panicked) after we cloned its sender; recreate it once and re-send so
        // the event is never dropped on a benign idle-reclaim race.
        if let Err(mpsc::error::SendError(event)) = tx.send(event).await {
            tx = spawn_worker(realm.clone());
            let recreated = tx.clone();
            if recreated.send(event).await.is_err() {
                tracing::error!(realm = %realm, "inbound realm worker is gone; dropping event");
            }
            workers.insert(realm, tx);
        }
    }
    Ok(())
}

/// Deliver one inbound event to the adapter with bounded retry + backoff, then
/// dead-letter on persistent failure.
#[cfg(feature = "runtime")]
async fn deliver_inbound_event<A: BridgeApp>(
    ctx: Arc<BridgeContext>,
    app: Arc<A>,
    event: Event,
) -> bool {
    let event_id = event.event_id.to_string();
    let mut backoff = INBOUND_RETRY_BASE_BACKOFF;
    for attempt in 1..=INBOUND_MAX_DELIVERY_ATTEMPTS {
        match app.on_arkret_event(ctx.clone(), event.clone()).await {
            Ok(()) => return true,
            Err(e) => {
                let retriable = e.is_retriable();
                if !retriable || attempt == INBOUND_MAX_DELIVERY_ATTEMPTS {
                    // Dead-letter: a deterministic failure (no point retrying) or
                    // retries exhausted. Surface loudly so the failure is
                    // observable rather than silently dropped.
                    tracing::error!(
                        %event_id,
                        error = %e,
                        attempt,
                        retriable,
                        "dead-lettering inbound event: delivery to adapter failed"
                    );
                    record_outbound_dead_letter(ctx.clone(), &event, attempt, retriable, &e).await;
                    return false;
                }
                tracing::warn!(
                    %event_id,
                    error = %e,
                    attempt,
                    "inbound delivery failed; retrying after backoff"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
        }
    }
    false
}

#[cfg(feature = "runtime")]
async fn record_outbound_dead_letter(
    ctx: Arc<BridgeContext>,
    event: &Event,
    attempts: u32,
    retriable: bool,
    error: &BridgeError,
) {
    let event_id = event.event_id.to_string();
    let event_json = match serde_json::to_string(event) {
        Ok(event_json) => event_json,
        Err(err) => {
            tracing::error!(%event_id, error = %err, "failed to serialize outbound dead-letter event");
            return;
        }
    };
    let record = OutboundDeadLetterRecord {
        event_id: event_id.clone(),
        realm_id: event.realm_id.to_string(),
        kind: event.kind.to_string(),
        attempts,
        retriable,
        last_error: redact_sensitive_url_values(error.to_string()),
        event_json,
    };
    let store = ctx.dead_letters.clone();
    if let Err(err) = crate::run_blocking(move || store.record(record)).await {
        tracing::error!(%event_id, error = %err, "failed to persist outbound dead-letter event");
    }
}

/// Low-frequency dead-letter replayer. It reuses the exact adapter delivery
/// path; a successful replay clears the row, a failed replay refreshes the row's
/// `updated_at` through `deliver_inbound_event` so it is not retried in a tight
/// loop.
#[cfg(feature = "runtime")]
pub async fn replay_outbound_dead_letters<A: BridgeApp>(
    ctx: Arc<BridgeContext>,
    app: Arc<A>,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(
        crate::dead_letter::OUTBOUND_DEAD_LETTER_REPLAY_INTERVAL_SECS as u64,
    ));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let store = ctx.dead_letters.clone();
        let due = crate::run_blocking(move || {
            store.list_due(
                chrono::Utc::now().timestamp(),
                OUTBOUND_DEAD_LETTER_SCAN_LIMIT,
            )
        })
        .await?;
        for dead in due {
            let event_id = dead.event_id.clone();
            let event: Event = match serde_json::from_str(&dead.event_json) {
                Ok(event) => event,
                Err(err) => {
                    tracing::error!(%event_id, error = %err, "outbound dead-letter row contains unreadable event json");
                    continue;
                }
            };
            if deliver_inbound_event(ctx.clone(), app.clone(), event).await {
                let store = ctx.dead_letters.clone();
                let clear_event_id = event_id.clone();
                if let Err(err) = crate::run_blocking(move || store.clear(&clear_event_id)).await {
                    tracing::error!(%event_id, error = %err, "failed to clear replayed outbound dead-letter event");
                }
            }
        }
    }
}

/// Encrypted Signal consumer loop: arkret server -> adapter.
#[cfg(feature = "runtime")]
pub async fn consume_signals<A: BridgeApp>(
    ctx: Arc<BridgeContext>,
    app: Arc<A>,
    mut rx: Receiver<SignalEnvelope>,
) -> Result<()> {
    while let Some(signal) = rx.recv().await {
        if let Err(e) = app.on_signal(ctx.clone(), signal).await {
            tracing::warn!(error = %e, "failed to forward Signal to adapter");
        }
    }
    Ok(())
}
