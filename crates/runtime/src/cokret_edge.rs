//! The cokret protocol-side edge (replaces the Matrix bridge's
//! `MatrixAppservice`).
//!
//! - **Outbound (app -> cokret)**: [`CokretEdge::mint_event`] /
//!   [`CokretEdge::submit`] build and sign an `Event` and submit it via
//!   [`cokret::http_client::Client::events_submit`].
//! - **Inbound (cokret → app)**: transactions pushed by the cokret server via
//!   the applet HTTP endpoints are placed into the `inbound_tx` queue by
//!   [`BridgeAppletHandler`]; after the core consumes them they are forwarded
//!   to the app adapter.
//! - **Media**: [`CokretEdge::upload_blob`] / [`CokretEdge::download_blob`].
//!
//! The restart-safe monotonic actor-sequence allocator is abstracted behind the
//! [`SeqStore`] trait so a host can inject a non-diesel persistence backend. The
//! diesel-backed implementation [`DbSeqStore`] is only compiled under the `db`
//! feature.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use cokret::Ed25519MoveSigner;
use cokret::http_client::{Auth, Client};
#[cfg(any(feature = "web", test))]
use cokret::model::{
    AppletActorView, AppletDescription, AppletPingOutcome, AppletProtocolMetadata, AppletRealmView,
    AppletTransactionOutcome, AppletTransactionRequestBody,
};
#[cfg(any(feature = "web", test))]
use cokret::signatures::EventProofBuilder;
use cokret::signatures::{SignEventOptions, sign_event};
use cokret::{Did, Event, Hlc, RealmId};
use parking_lot::Mutex;
use serde_json::Value;
#[cfg(any(feature = "web", test))]
use serde_json::json;
use tokio::sync::mpsc::UnboundedSender;

#[cfg(any(feature = "web", test))]
use crate::app::AppletResolver;
use crate::config::Config;
use crate::error::{BridgeError, Result};

/// How many actor sequence numbers to reserve in the store per refill. A larger
/// block means fewer store writes at the cost of skipping more numbers on each
/// restart (gaps are harmless; only monotonicity matters).
const SEQ_RESERVE_BLOCK: i64 = 256;
/// The default `bridge_state` row key under which the reserved actor-seq
/// high-water mark is persisted.
pub const SEQ_STATE_KEY: &str = "actor_seq_reserved";

/// Pluggable, restart-safe high-water-mark storage backing [`SeqAllocator`].
///
/// A host injects an implementation so the runtime can allocate strictly
/// monotonic actor sequence numbers without depending on diesel. The contract:
/// `reserve_block` atomically advances the persisted value for `key` by `block`
/// and returns the **new** value (the highest sequence number now reserved).
pub trait SeqStore: Send + Sync + 'static {
    fn reserve_block(&self, key: &str, block: i64) -> crate::error::Result<i64>;
}

/// Restart-safe monotonic allocator for the service actor's event sequence.
///
/// Numbers are reserved from the backing [`SeqStore`] in blocks: on each refill
/// the persisted high-water mark is advanced by [`SEQ_RESERVE_BLOCK`] and the
/// reserved range handed out from memory. A restart resumes strictly above the
/// last reserved block, so sequence numbers never regress (unused numbers in a
/// partially consumed block are skipped — gaps are acceptable).
pub struct SeqAllocator {
    store: Arc<dyn SeqStore>,
    key: String,
    state: Mutex<SeqWindow>,
}

#[derive(Default)]
struct SeqWindow {
    /// Next sequence number to hand out.
    next: i64,
    /// Exclusive upper bound of the currently reserved window.
    limit: i64,
}

impl SeqAllocator {
    /// Build an allocator over `store`, persisting its high-water mark under
    /// `key`. Infallible: no migration is performed here (the store owns its own
    /// initialization).
    pub fn new(store: Arc<dyn SeqStore>, key: impl Into<String>) -> Self {
        Self {
            store,
            key: key.into(),
            state: Mutex::new(SeqWindow::default()),
        }
    }

    /// Allocate the next sequence number, reserving a fresh block when the
    /// in-memory window is exhausted.
    pub fn alloc(&self) -> Result<u64> {
        let mut win = self.state.lock();
        if win.next >= win.limit {
            let reserved = self.store.reserve_block(&self.key, SEQ_RESERVE_BLOCK)?;
            win.next = reserved - SEQ_RESERVE_BLOCK + 1;
            win.limit = reserved + 1;
        }
        let seq = win.next;
        win.next += 1;
        Ok(seq as u64)
    }
}

/// The cokret edge client.
pub struct CokretEdge {
    config: Arc<Config>,
    client: Client,
    signer: Ed25519MoveSigner,
    service_did: Did,
    node_id: String,
    /// Store-backed, restart-safe actor sequence allocator.
    seq: SeqAllocator,
    /// Packed HLC state: `(last_ms << 16) | logical`. Updated with a CAS loop so
    /// the logical counter resets to 0 whenever the millisecond advances and only
    /// increments within the same millisecond (classic HLC), never wrapping.
    hlc_state: AtomicU64,
    /// Inbound event queue: cokret server push → core consumer loop. `None` for
    /// outbound-only edges.
    inbound_tx: Option<UnboundedSender<Event>>,
    /// Inbound ephemeral queue (typing/presence/receipts; raw JSON until a typed
    /// schema is defined): cokret server push → core consumer loop. `None` for
    /// outbound-only edges.
    ephemeral_tx: Option<UnboundedSender<Value>>,
}

impl CokretEdge {
    /// Build an inbound-capable edge: signs with the seed from
    /// [`Config::signing_seed`] and queues inbound events into `inbound_tx`.
    pub fn new(
        config: Arc<Config>,
        seq: Arc<dyn SeqStore>,
        inbound_tx: UnboundedSender<Event>,
    ) -> Result<Self> {
        let service_did = Did::new(config.cokret.service_did.clone())?;
        let seed = config.signing_seed()?;
        let signer = Ed25519MoveSigner::from_did_key_seed(
            seed,
            service_did.clone(),
            config.cokret.verification_method_id.clone(),
        );
        Self::build(config, seq, signer, service_did, Some(inbound_tx))
    }

    /// Build an outbound-only edge (no inbound queue), signing with the seed
    /// from [`Config::signing_seed`].
    pub fn for_outbound(config: Arc<Config>, seq: Arc<dyn SeqStore>) -> Result<Self> {
        let service_did = Did::new(config.cokret.service_did.clone())?;
        let seed = config.signing_seed()?;
        let signer = Ed25519MoveSigner::from_did_key_seed(
            seed,
            service_did.clone(),
            config.cokret.verification_method_id.clone(),
        );
        Self::build(config, seq, signer, service_did, None)
    }

    /// Build an outbound-only edge using a caller-supplied signer (rather than
    /// deriving one from the configured seed). `service_did` / `node_id` are
    /// still derived from `config`.
    pub fn with_signer(
        config: Arc<Config>,
        seq: Arc<dyn SeqStore>,
        signer: cokret::Ed25519MoveSigner,
    ) -> Result<Self> {
        let service_did = Did::new(config.cokret.service_did.clone())?;
        Self::build(config, seq, signer, service_did, None)
    }

    fn build(
        config: Arc<Config>,
        seq: Arc<dyn SeqStore>,
        signer: Ed25519MoveSigner,
        service_did: Did,
        inbound_tx: Option<UnboundedSender<Event>>,
    ) -> Result<Self> {
        let base = url::Url::parse(&config.cokret.server_url)
            .map_err(|e| BridgeError::Config(format!("server_url: {e}")))?;
        let client = Client::builder(base)
            .auth(Auth::Bearer(config.cokret.access_token.clone()))
            .build()?;

        // Derive a stable 8-digit hexadecimal HLC node id from bridge_id.
        let node_id = stable_node_id(&config.bridge.bridge_id);

        let seq = SeqAllocator::new(seq, SEQ_STATE_KEY);

        Ok(Self {
            config,
            client,
            signer,
            service_did,
            node_id,
            seq,
            hlc_state: AtomicU64::new(0),
            inbound_tx,
            ephemeral_tx: None,
        })
    }

    /// Install the ephemeral (typing/presence/receipts) sender. Used by the
    /// `run_bridge` path which wires a parallel queue.
    pub fn set_ephemeral_sender(&mut self, tx: UnboundedSender<Value>) {
        self.ephemeral_tx = Some(tx);
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn service_did(&self) -> &Did {
        &self.service_did
    }

    /// The inbound event sender, if this edge was built with one.
    pub fn inbound_sender(&self) -> Option<UnboundedSender<Event>> {
        self.inbound_tx.clone()
    }

    /// The ephemeral sender, if installed.
    pub fn ephemeral_sender(&self) -> Option<UnboundedSender<Value>> {
        self.ephemeral_tx.clone()
    }

    /// Allocate the next monotonic actor sequence number.
    pub fn alloc_seq(&self) -> Result<u64> {
        self.seq.alloc()
    }

    /// Generate the next HLC (`{ms:012x}-{logical:04x}-{node:08x}`).
    ///
    /// The logical counter resets to 0 when the physical millisecond advances and
    /// increments within the same millisecond, guaranteeing strict monotonicity
    /// without wraparound. If the wall clock goes backwards (NTP step), the last
    /// observed millisecond is reused and the logical counter advances instead.
    pub fn next_hlc(&self) -> Result<Hlc> {
        const LOGICAL_BITS: u32 = 16;
        const LOGICAL_MASK: u64 = (1 << LOGICAL_BITS) - 1;
        const MAX_LOGICAL: u64 = LOGICAL_MASK;

        let now_ms = (chrono::Utc::now().timestamp_millis().max(0) as u64) & 0xFFFF_FFFF_FFFF;

        let mut prev = self.hlc_state.load(Ordering::Relaxed);
        let (ms, logical) = loop {
            let last_ms = prev >> LOGICAL_BITS;
            let last_logical = prev & LOGICAL_MASK;
            let (ms, logical) = if now_ms > last_ms {
                (now_ms, 0)
            } else {
                // Same millisecond, or clock moved backwards: keep last_ms and
                // bump the logical counter (saturating at the field width).
                if last_logical >= MAX_LOGICAL {
                    return Err(BridgeError::App(format!(
                        "HLC logical counter exhausted within ms {last_ms}"
                    )));
                }
                (last_ms, last_logical + 1)
            };
            let next = (ms << LOGICAL_BITS) | logical;
            match self.hlc_state.compare_exchange_weak(
                prev,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break (ms, logical),
                Err(observed) => prev = observed,
            }
        };

        let raw = format!("{ms:012x}-{logical:04x}-{}", self.node_id);
        Hlc::new(raw).map_err(Into::into)
    }

    /// Build and sign an event emitted by this bridge's service actor.
    pub fn mint_event(&self, kind: &str, realm_id: &RealmId, content: Value) -> Result<Event> {
        self.mint_event_as_inner(self.service_did.clone(), kind, realm_id, content)
    }

    /// Build and sign an event attributed to `actor` and executed by this
    /// bridge service under a durable delegated authorization.
    ///
    /// The proof verification method stays on the service DID. The envelope
    /// carries `executed_by = service_did` and `authorization_ref`, allowing the
    /// reducer to verify who actually signed while preserving the virtual
    /// actor as `actor_id`.
    pub fn mint_event_as(
        &self,
        actor: &cokret::Did,
        kind: &str,
        realm_id: &RealmId,
        content: Value,
        authorization_ref: &str,
    ) -> Result<Event> {
        let authorization_ref = validate_authorization_ref(authorization_ref)?;
        let seq = self.seq.alloc()?;
        let hlc = self.next_hlc()?;
        let mut event = Event::new(kind, realm_id.clone(), actor.clone(), seq, hlc, content)?;
        event.executed_by = Some(self.service_did.clone());
        event.authorization_ref = Some(authorization_ref);
        stamp_applet_metadata(&mut event, &self.config.cokret.applet_id);
        let verification_method = self.verification_method_for_actor(&self.service_did)?;
        sign_event(
            &mut event,
            &self.signer,
            &verification_method,
            SignEventOptions::new(),
        )?;
        Ok(event)
    }

    fn mint_event_as_inner(
        &self,
        actor: Did,
        kind: &str,
        realm_id: &RealmId,
        content: Value,
    ) -> Result<Event> {
        let seq = self.seq.alloc()?;
        let hlc = self.next_hlc()?;
        let mut event = Event::new(kind, realm_id.clone(), actor, seq, hlc, content)?;
        stamp_applet_metadata(&mut event, &self.config.cokret.applet_id);
        let verification_method = self.verification_method_for_actor(&event.actor_id)?;
        sign_event(
            &mut event,
            &self.signer,
            &verification_method,
            SignEventOptions::new(),
        )?;
        Ok(event)
    }

    fn verification_method_for_actor(&self, actor: &Did) -> Result<String> {
        let (_, fragment) = self
            .config
            .cokret
            .verification_method_id
            .rsplit_once('#')
            .ok_or_else(|| {
                BridgeError::Config(
                    "verification_method_id must contain a #key fragment".to_owned(),
                )
            })?;
        if fragment.trim().is_empty() {
            return Err(BridgeError::Config(
                "verification_method_id key fragment must not be empty".to_owned(),
            ));
        }
        Ok(format!("{}#{fragment}", actor.as_str()))
    }

    /// Outbound: submit an already-minted event and return its event_id.
    /// Generic over event kind — carries no messaging assumptions.
    pub async fn submit_event(&self, event: &Event) -> Result<String> {
        let event_id = event.event_id.to_string();
        self.client.events_submit(event).await?;
        Ok(event_id)
    }

    /// Outbound convenience: mint + sign + submit an event of `kind` into
    /// `realm_id` with `content`. Returns the event_id.
    pub async fn submit(&self, realm_id: &str, kind: &str, content: Value) -> Result<String> {
        let realm = RealmId::new(realm_id.to_owned())?;
        let event = self.mint_event(kind, &realm, content)?;
        self.submit_event(&event).await
    }

    /// Outbound convenience with bridge provenance. Current SDK Event envelopes
    /// no longer expose signed top-level `external_ref`, so the value is carried
    /// as `unsigned` transport metadata.
    pub async fn submit_with_external_ref(
        &self,
        realm_id: &str,
        kind: &str,
        content: Value,
        external_ref: Value,
    ) -> Result<String> {
        let realm = RealmId::new(realm_id.to_owned())?;
        let mut event = self.mint_event(kind, &realm, content)?;
        stamp_external_ref(&mut event, external_ref);
        event.proofs.clear();
        let verification_method = self.verification_method_for_actor(&event.actor_id)?;
        sign_event(
            &mut event,
            &self.signer,
            &verification_method,
            SignEventOptions::new(),
        )?;
        self.submit_event(&event).await
    }

    /// Outbound convenience with bridge provenance and an explicit delegated
    /// actor. Used by messaging bridges to submit per-user Ghost Actor events
    /// after provisioning returned a durable authorization ref.
    pub async fn submit_with_external_ref_as(
        &self,
        actor: &Did,
        realm_id: &str,
        kind: &str,
        content: Value,
        external_ref: Value,
        authorization_ref: &str,
    ) -> Result<String> {
        let realm = RealmId::new(realm_id.to_owned())?;
        let mut event = self.mint_event_as(actor, kind, &realm, content, authorization_ref)?;
        stamp_external_ref(&mut event, external_ref);
        event.proofs.clear();
        let verification_method = self.verification_method_for_actor(&self.service_did)?;
        sign_event(
            &mut event,
            &self.signer,
            &verification_method,
            SignEventOptions::new(),
        )?;
        self.submit_event(&event).await
    }

    /// Outbound: redact a previously submitted event by id.
    pub async fn submit_redaction(&self, realm_id: &str, target_event_id: &str) -> Result<String> {
        let realm = RealmId::new(realm_id.to_owned())?;
        let content = serde_json::json!({ "target_event_id": target_event_id });
        let mut event = self.mint_event("ck.message.redact", &realm, content)?;
        event.redacts = Some(cokret::EventId::new(target_event_id.to_owned())?);
        // redacts is set after minting, so re-sign to override.
        event.proofs.clear();
        let verification_method = self.verification_method_for_actor(&event.actor_id)?;
        sign_event(
            &mut event,
            &self.signer,
            &verification_method,
            SignEventOptions::new(),
        )?;
        self.submit_event(&event).await
    }

    /// Media upload: returns the blob reference string.
    pub async fn upload_blob(&self, bytes: &[u8], mime: &str) -> Result<String> {
        let meta = cokret::model::BlobUploadMetadata {
            realm_id: None,
            content_digest: None,
            size_bytes: bytes.len() as u64,
            media_type: Some(mime.to_owned()),
            filename: None,
            purpose: None,
        };
        let res = self.client.blob_upload_bytes(&meta, bytes.to_vec()).await?;
        Ok(res.blob_ref.to_string())
    }

    /// Media download.
    pub async fn download_blob(&self, blob_ref: &str) -> Result<Vec<u8>> {
        let r = cokret::BlobRef::new(blob_ref.to_owned())?;
        Ok(self.client.blob_download(&r, None).await?)
    }
}

fn validate_authorization_ref(authorization_ref: &str) -> Result<String> {
    let authorization_ref = authorization_ref.trim();
    if authorization_ref.is_empty() {
        return Err(BridgeError::Cokret(
            "delegated actor events require authorization_ref".to_owned(),
        ));
    }
    Ok(authorization_ref.to_owned())
}

fn stamp_applet_metadata(event: &mut Event, applet_id: &str) {
    event
        .unsigned
        .insert("applet_id".to_owned(), Value::String(applet_id.to_owned()));
}

fn stamp_external_ref(event: &mut Event, external_ref: Value) {
    event
        .unsigned
        .insert("external_ref".to_owned(), external_ref);
}

/// Diesel-backed [`SeqStore`]. Persists each key's high-water mark in a
/// runtime-owned `bridge_state` table. Only compiled under the `db` feature.
#[cfg(feature = "db")]
pub struct DbSeqStore {
    db: Arc<crate::db::DatabaseManager>,
}

/// Runtime-owned key/value state table (generic; not messaging-specific).
#[cfg(feature = "db")]
mod state_schema {
    diesel::table! {
        bridge_state (state_key) {
            state_key -> Text,
            state_value -> BigInt,
        }
    }
}

#[cfg(feature = "db")]
impl DbSeqStore {
    /// Build the store, running the `bridge_state` migration (idempotent).
    pub fn new(db: Arc<crate::db::DatabaseManager>) -> Result<Self> {
        db.run_migrations(&["CREATE TABLE IF NOT EXISTS bridge_state (\
                state_key TEXT PRIMARY KEY,\
                state_value BIGINT NOT NULL)"])?;
        Ok(Self { db })
    }
}

#[cfg(feature = "db")]
impl SeqStore for DbSeqStore {
    /// Advance the persisted high-water mark for `key` by `block` and return the
    /// new value (the highest sequence number now reserved).
    fn reserve_block(&self, key: &str, block: i64) -> Result<i64> {
        use diesel::prelude::*;
        use state_schema::bridge_state::dsl;

        let mut conn = self.db.conn()?;
        let current: i64 = dsl::bridge_state
            .filter(dsl::state_key.eq(key))
            .select(dsl::state_value)
            .first::<i64>(&mut conn)
            .optional()?
            .unwrap_or(0);
        let reserved = current + block;

        let updated = diesel::update(dsl::bridge_state.filter(dsl::state_key.eq(key)))
            .set(dsl::state_value.eq(reserved))
            .execute(&mut conn)?;
        if updated == 0 {
            diesel::insert_into(dsl::bridge_state)
                .values((dsl::state_key.eq(key), dsl::state_value.eq(reserved)))
                .execute(&mut conn)?;
        }
        Ok(reserved)
    }
}

/// [`stable_node_id`] maps any bridge_id to an 8-digit lower-hex value.
fn stable_node_id(bridge_id: &str) -> String {
    // A simple FNV-1a 32-bit hash, to avoid pulling in extra dependencies.
    let mut hash: u32 = 0x811c_9dc5;
    for b in bridge_id.bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    format!("{hash:08x}")
}

#[cfg(any(feature = "web", test))]
/// Bounded in-memory window of recently seen `event_id`s used to enforce the
/// single-event-level dedup rule of `applet-integration.md` §7.3: a repeated
/// `event_id` with identical signed content is accepted, while conflicting
/// content is rejected.
///
/// The SDK [`cokret::idempotency::IdempotencyWindow`] only covers the
/// transaction-level `Idempotency-Key`; it does not look at individual events.
/// This window therefore tracks `event_id -> canonical content fingerprint` so a
/// re-pushed event with identical content is dropped (treated as accepted) while
/// a re-pushed event with a *different* body under the same id is rejected.
///
/// It is intentionally process-local and best-effort: it hardens against
/// duplicate fan-out within a running process. Cross-restart / cross-process
/// dedup against durable history is tracked as a separate SDK gap in
/// `_bridges_todos.md §3` (transaction push inbound verification).
struct EventDedupWindow {
    /// `event_id -> fingerprint` of the first body seen for that id. A
    /// fingerprint collision is astronomically unlikely for the FNV-1a 64-bit
    /// hash used here, and a mismatch only ever leads to a (safe) rejection.
    seen: Mutex<std::collections::HashMap<String, u64>>,
    /// Soft cap on retained ids; on overflow the window is cleared. Duplicates
    /// older than the window simply re-enter as fresh events (at-least-once),
    /// which is the correct conservative behaviour.
    capacity: usize,
}

#[cfg(any(feature = "web", test))]
/// Outcome of consulting the [`EventDedupWindow`] for one event.
enum DedupVerdict {
    /// First time this `event_id` (with this body) is seen — process it.
    Fresh,
    /// Same `event_id` and identical body already seen — MUST be accepted
    /// without re-processing (no duplicate fan-out).
    DuplicateSameContent,
    /// Same `event_id` but a *different* body — MUST be rejected.
    DuplicateConflict,
}

#[cfg(any(feature = "web", test))]
impl EventDedupWindow {
    fn new(capacity: usize) -> Self {
        Self {
            seen: Mutex::new(std::collections::HashMap::new()),
            capacity,
        }
    }

    /// Record `event_id` with the fingerprint of its canonical body and return
    /// the dedup verdict.
    fn check(&self, event_id: &str, fingerprint: u64) -> DedupVerdict {
        let mut seen = self.seen.lock();
        match seen.get(event_id) {
            Some(&prev) if prev == fingerprint => DedupVerdict::DuplicateSameContent,
            Some(_) => DedupVerdict::DuplicateConflict,
            None => {
                if seen.len() >= self.capacity {
                    seen.clear();
                }
                seen.insert(event_id.to_owned(), fingerprint);
                DedupVerdict::Fresh
            }
        }
    }
}

#[cfg(any(feature = "web", test))]
/// Stable 64-bit FNV-1a fingerprint over an event's signed canonical envelope.
/// Used only for same-id content-equality comparison in [`EventDedupWindow`];
/// not a security primitive.
fn event_content_fingerprint(event: &Event) -> u64 {
    let canonical = EventProofBuilder::new()
        .envelope_bytes(event)
        .unwrap_or_default();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in canonical {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(any(feature = "web", test))]
/// The receiver for transactions pushed by the cokret server (implements
/// [`cokret::AppletHandler`]). It delivers the events in a transaction to the
/// inbound queue; the business forwarding is done in the core consumer loop.
pub struct BridgeAppletHandler {
    applet_id: String,
    service_did: Did,
    protocols: Vec<String>,
    namespaces: Value,
    limits: Value,
    auth: Value,
    inbound_tx: UnboundedSender<Event>,
    ephemeral_tx: Option<UnboundedSender<Value>>,
    resolver: Option<Arc<dyn AppletResolver>>,
    /// Single-event-level dedup window (see [`EventDedupWindow`]).
    dedup: EventDedupWindow,
}

#[cfg(any(feature = "web", test))]
/// Soft cap on the number of `event_id`s the per-handler dedup window retains.
const EVENT_DEDUP_CAPACITY: usize = 8192;

#[cfg(any(feature = "web", test))]
fn default_applet_namespaces(bridge_id: &str, service_did: &Did) -> Value {
    let service_did = service_did.as_str();
    json!({
        "actors": [{
            "exclusive": true,
            "pattern": format!("{service_did}:ghost:*"),
        }],
        "realms": [{
            "exclusive": true,
            "pattern": format!("{bridge_id}:*"),
        }],
        "handles": [{
            "exclusive": true,
            "pattern": format!("{bridge_id}/*"),
        }],
    })
}

#[cfg(any(feature = "web", test))]
fn default_applet_limits() -> Value {
    json!({
        "max_events_per_transaction": EVENT_DEDUP_CAPACITY,
        "receive_events": true,
        "receive_ephemeral": true,
        "rate_limited": true,
    })
}

#[cfg(any(feature = "web", test))]
fn default_applet_auth(service_did: &Did, verification_method_id: &str) -> Value {
    let key_ref = if verification_method_id.starts_with("did:") {
        verification_method_id.to_owned()
    } else {
        format!("{}{}", service_did.as_str(), verification_method_id)
    };
    json!({
        "type": "http_message_signature",
        "key_ref": key_ref,
    })
}

#[cfg(any(feature = "web", test))]
impl BridgeAppletHandler {
    /// Build the handler from an inbound-capable edge. The edge must have been
    /// constructed with an inbound sender (the run_bridge/web path always is).
    pub fn new(edge: &CokretEdge, resolver: Option<Arc<dyn AppletResolver>>) -> Self {
        let bridge_id = edge.config.bridge.bridge_id.clone();
        let service_did = edge.service_did.clone();
        let verification_method_id = edge.config.cokret.verification_method_id.clone();
        Self {
            applet_id: edge.config.cokret.applet_id.clone(),
            service_did: service_did.clone(),
            protocols: vec![bridge_id.clone()],
            namespaces: edge
                .config
                .cokret
                .applet_namespaces
                .clone()
                .unwrap_or_else(|| default_applet_namespaces(&bridge_id, &service_did)),
            limits: edge
                .config
                .cokret
                .applet_limits
                .clone()
                .unwrap_or_else(default_applet_limits),
            auth: edge
                .config
                .cokret
                .applet_auth
                .clone()
                .unwrap_or_else(|| default_applet_auth(&service_did, &verification_method_id)),
            inbound_tx: edge.inbound_sender().expect("inbound enabled"),
            ephemeral_tx: edge.ephemeral_sender(),
            resolver,
            dedup: EventDedupWindow::new(EVENT_DEDUP_CAPACITY),
        }
    }

    /// Whether `realm_id` falls inside one of the realm namespace patterns this
    /// applet declared in `describe` (applet-integration §7/§13 namespace
    /// matching). Patterns use the spec's `*` suffix-glob form (e.g.
    /// `{bridge_id}:*`). When no realm patterns are declared the check is
    /// permissive (cannot constrain what was never declared).
    fn realm_in_namespace(&self, realm_id: &str) -> bool {
        let patterns = self
            .namespaces
            .get("realms")
            .and_then(Value::as_array)
            .map(|realms| {
                realms
                    .iter()
                    .filter_map(|entry| entry.get("pattern").and_then(Value::as_str))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if patterns.is_empty() {
            return true;
        }
        patterns
            .iter()
            .any(|pattern| glob_suffix_match(pattern, realm_id))
    }
}

/// Match a spec namespace pattern against a candidate id. Supports a trailing
/// `*` wildcard (prefix match) and exact equality otherwise; an interior `*` is
/// treated literally (the spec only uses trailing globs for namespaces).
fn glob_suffix_match(pattern: &str, candidate: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => candidate.starts_with(prefix),
        None => pattern == candidate,
    }
}

#[cfg(any(feature = "web", test))]
impl cokret::AppletHandler for BridgeAppletHandler {
    fn ping(&self) -> cokret::Result<AppletPingOutcome> {
        Ok(AppletPingOutcome {
            ok: true,
            applet_id: self.applet_id.clone(),
            service_did: self.service_did.clone(),
            protocol_version: "1.0".to_owned(),
        })
    }

    fn describe(&self) -> cokret::Result<AppletDescription> {
        Ok(AppletDescription {
            applet_id: self.applet_id.clone(),
            service_did: self.service_did.clone(),
            protocols: self.protocols.clone(),
            namespaces: self.namespaces.clone(),
            limits: self.limits.clone(),
            auth: self.auth.clone(),
        })
    }

    fn handle_transaction(
        &self,
        _idempotency_key: Option<&str>,
        req: AppletTransactionRequestBody,
    ) -> cokret::Result<AppletTransactionOutcome> {
        let mut rejected: Vec<Value> = Vec::new();
        let mut enqueue_failed = false;

        for event in req.events {
            let event_id = event.event_id.to_string();

            // Namespace enforcement (applet-integration §7 / §13): the pushed
            // event's realm MUST fall inside the realm namespace this applet
            // declared in `describe`. A trusted-channel event for a realm outside
            // our namespace is rejected before it can be forwarded to the app.
            if !self.realm_in_namespace(&event.realm_id.to_string()) {
                tracing::warn!(
                    %event_id,
                    realm = %event.realm_id,
                    "rejecting event: realm is outside this applet's declared namespace"
                );
                rejected.push(serde_json::json!({
                    "event_id": event_id,
                    "reason": "namespace_mismatch",
                }));
                continue;
            }

            // Single-event-level dedup (§7.3): identical re-push is accepted
            // without re-forwarding; a conflicting body under the same id is
            // rejected.
            match self
                .dedup
                .check(&event_id, event_content_fingerprint(&event))
            {
                DedupVerdict::Fresh => {}
                DedupVerdict::DuplicateSameContent => {
                    // Already processed with identical content — accept silently,
                    // do not fan out again.
                    continue;
                }
                DedupVerdict::DuplicateConflict => {
                    tracing::warn!(
                        %event_id,
                        "rejecting event: same event_id pushed with conflicting content"
                    );
                    rejected.push(serde_json::json!({
                        "event_id": event_id,
                        "reason": "duplicate_conflict",
                    }));
                    continue;
                }
            }

            // Enqueue for the core consumer loop. A closed/dropped receiver means
            // the consumer is gone; surface it instead of silently dropping the
            // event so the server can retry rather than treat it as delivered.
            if let Err(err) = self.inbound_tx.send(event) {
                enqueue_failed = true;
                tracing::error!(%event_id, error = %err, "failed to enqueue inbound event");
                rejected.push(serde_json::json!({
                    "event_id": event_id,
                    "reason": "internal_error",
                }));
            }
        }

        // Forward ephemeral (typing/presence/receipts) when present instead of
        // silently dropping it; consumers receive the raw JSON. Ephemeral loss is
        // non-fatal (best-effort) and does not affect the durable ack.
        if !req.ephemeral.is_null() {
            if let Some(tx) = self.ephemeral_tx.as_ref() {
                if let Err(err) = tx.send(req.ephemeral) {
                    tracing::warn!(error = %err, "failed to enqueue ephemeral payload");
                }
            }
        }

        // `ok` reflects whether every durable event was accepted (either freshly
        // enqueued or de-duplicated). When enqueueing failed, signal a retry so
        // the server re-pushes rather than dropping the batch.
        Ok(AppletTransactionOutcome {
            ok: rejected.is_empty(),
            rejected,
            retry_after_ms: enqueue_failed.then_some(1000),
        })
    }

    fn resolve_actor(&self, actor_id: &str) -> cokret::Result<AppletActorView> {
        if let Some(resolved) = self
            .resolver
            .as_ref()
            .and_then(|r| r.resolve_actor(actor_id))
        {
            if let Ok(did) = Did::new(resolved.actor_id) {
                return Ok(AppletActorView {
                    exists: true,
                    actor_id: Some(did),
                    display_name: resolved.display_name,
                    external_ref: resolved.external_ref,
                });
            }
        }
        Ok(AppletActorView {
            exists: false,
            actor_id: None,
            display_name: None,
            external_ref: Value::Null,
        })
    }

    fn resolve_realm(&self, realm_id_or_alias: &str) -> cokret::Result<AppletRealmView> {
        if let Some(resolved) = self
            .resolver
            .as_ref()
            .and_then(|r| r.resolve_realm(realm_id_or_alias))
        {
            if let Ok(realm) = RealmId::new(resolved.realm_id) {
                return Ok(AppletRealmView {
                    exists: true,
                    realm_id: Some(realm),
                    title: resolved.title,
                    external_ref: resolved.external_ref,
                });
            }
        }
        Ok(AppletRealmView {
            exists: false,
            realm_id: None,
            title: None,
            external_ref: Value::Null,
        })
    }

    fn resolve_protocol(&self, protocol: &str) -> cokret::Result<AppletProtocolMetadata> {
        Ok(AppletProtocolMetadata {
            protocol: protocol.to_owned(),
            display_name: protocol.to_owned(),
            icon_blob_ref: None,
            field_types: Value::Null,
            instances: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// An in-memory [`SeqStore`] for tests: maps key -> reserved high-water mark.
    #[derive(Default)]
    struct MemSeqStore {
        inner: Mutex<HashMap<String, i64>>,
    }

    impl SeqStore for MemSeqStore {
        fn reserve_block(&self, key: &str, block: i64) -> Result<i64> {
            let mut guard = self.inner.lock();
            let current = guard.get(key).copied().unwrap_or(0);
            let reserved = current + block;
            guard.insert(key.to_owned(), reserved);
            Ok(reserved)
        }
    }

    #[test]
    fn alloc_is_monotonic() {
        let store: Arc<dyn SeqStore> = Arc::new(MemSeqStore::default());
        let alloc = SeqAllocator::new(store, "k");
        let mut prev = None;
        for _ in 0..1000 {
            let n = alloc.alloc().unwrap();
            if let Some(p) = prev {
                assert!(n > p, "expected {n} > {p}");
            }
            prev = Some(n);
        }
    }

    #[test]
    fn alloc_crosses_block_boundaries() {
        let store: Arc<dyn SeqStore> = Arc::new(MemSeqStore::default());
        let alloc = SeqAllocator::new(store, "k");
        // SEQ_RESERVE_BLOCK numbers come from the first reserved block; the next
        // alloc must trigger a fresh block and still be strictly greater.
        let first_block: Vec<u64> = (0..SEQ_RESERVE_BLOCK)
            .map(|_| alloc.alloc().unwrap())
            .collect();
        let next = alloc.alloc().unwrap();
        assert_eq!(*first_block.first().unwrap(), 1);
        assert_eq!(*first_block.last().unwrap(), SEQ_RESERVE_BLOCK as u64);
        assert_eq!(next, SEQ_RESERVE_BLOCK as u64 + 1);
        // Confirm contiguity within the first block.
        for (i, n) in first_block.iter().enumerate() {
            assert_eq!(*n, (i as u64) + 1);
        }
    }

    #[test]
    fn dedup_window_distinguishes_same_and_conflicting_content() {
        let win = EventDedupWindow::new(16);
        // First sight of an id+fingerprint is Fresh.
        assert!(matches!(win.check("ev1", 100), DedupVerdict::Fresh));
        // Same id + same fingerprint is an accepted duplicate (no re-fanout).
        assert!(matches!(
            win.check("ev1", 100),
            DedupVerdict::DuplicateSameContent
        ));
        // Same id + different fingerprint is a conflict (must reject).
        assert!(matches!(
            win.check("ev1", 200),
            DedupVerdict::DuplicateConflict
        ));
        // A different id is independent.
        assert!(matches!(win.check("ev2", 100), DedupVerdict::Fresh));
    }

    #[test]
    fn dedup_window_clears_on_capacity_overflow() {
        let win = EventDedupWindow::new(2);
        assert!(matches!(win.check("a", 1), DedupVerdict::Fresh));
        assert!(matches!(win.check("b", 1), DedupVerdict::Fresh));
        // Inserting a third id overflows the soft cap, clearing the window; the
        // new id is recorded fresh and prior ids re-enter as fresh (at-least-once).
        assert!(matches!(win.check("c", 1), DedupVerdict::Fresh));
        assert!(matches!(win.check("a", 1), DedupVerdict::Fresh));
    }

    #[test]
    fn event_fingerprint_ignores_unsigned_and_proofs() {
        let realm = RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d").unwrap();
        let actor = Did::new("did:web:alice.example").unwrap();
        let hlc = Hlc::new("01970e589d21-0001-a13f9c2e").unwrap();
        let mut first = Event::new(
            "ck.message.create",
            realm,
            actor,
            1,
            hlc,
            json!({ "body": "hello" }),
        )
        .unwrap();
        let mut second = first.clone();

        first
            .unsigned
            .insert("delivery".to_owned(), json!({ "attempt": 1 }));
        second
            .unsigned
            .insert("delivery".to_owned(), json!({ "attempt": 2 }));
        first.proofs.push(test_proof("header.payload.signature-a"));
        second.proofs.push(test_proof("header.payload.signature-b"));

        assert_eq!(
            event_content_fingerprint(&first),
            event_content_fingerprint(&second)
        );

        second.content = json!({ "body": "changed" });
        assert_ne!(
            event_content_fingerprint(&first),
            event_content_fingerprint(&second)
        );
    }

    fn test_proof(jws: &str) -> cokret::Proof {
        cokret::Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:alice.example#key-1".to_owned(),
            event_digest: cokret::Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            jws: jws.to_owned(),
        }
    }

    #[test]
    fn fresh_allocator_resumes_above_high_water_mark() {
        let store: Arc<dyn SeqStore> = Arc::new(MemSeqStore::default());

        // First allocator hands out a few numbers (consuming part of one block).
        let last_handed_out;
        {
            let a1 = SeqAllocator::new(store.clone(), "k");
            let mut last = 0;
            for _ in 0..5 {
                last = a1.alloc().unwrap();
            }
            last_handed_out = last;
        }

        // A fresh allocator over the SAME store must resume strictly above the
        // prior reserved high-water mark (no regression). Since the first
        // allocator reserved a full block of SEQ_RESERVE_BLOCK, the resumed
        // value starts at SEQ_RESERVE_BLOCK + 1.
        let a2 = SeqAllocator::new(store, "k");
        let resumed = a2.alloc().unwrap();
        assert!(
            resumed > last_handed_out,
            "expected resumed {resumed} > last {last_handed_out}"
        );
        assert_eq!(resumed, SEQ_RESERVE_BLOCK as u64 + 1);
    }
}
