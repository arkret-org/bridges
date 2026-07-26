//! Transaction-level idempotency and single-event dedup storage contracts
//! (applet-integration §7.3 / §13).
//!
//! The spec wording is MUST: persist transaction ids for idempotency and
//! deduplicate external events. The production path therefore persists both
//! records in the bridge database ([`crate::db::DbTransactionIdempotencyStore`] /
//! [`crate::db::DbEventDedupStore`]).

use crate::error::Result;

/// Retention for persisted transaction-idempotency records and event-dedup
/// entries, in seconds.
///
/// applet-integration §7.3/§14 let the server keep retrying a transaction with
/// the same `Idempotency-Key` on 5xx/timeout without bounding the retry window;
/// the record must therefore outlive any plausible server-side retry schedule
/// (hours), not just an in-flight request. 24 hours keeps the table bounded
/// while staying on the same order as a server retry/backoff horizon.
pub const IDEMPOTENCY_TTL_SECS: i64 = 24 * 60 * 60;

/// How long a `pending` claim blocks duplicate processing before a retry may
/// take it over. A bridge crash between claim and record would otherwise leave
/// the key stuck in `pending` until TTL expiry, turning server retries into a
/// permanent `retry_after_ms` loop.
pub const PENDING_TAKEOVER_GRACE_SECS: i64 = 300;

/// Outcome of consulting the event dedup store for one `event_id`.
pub enum DedupVerdict {
    /// First time this `event_id` (with this body) is seen — process it.
    Fresh,
    /// Same `event_id` and identical body already seen — MUST be accepted
    /// without re-processing (no duplicate fan-out).
    DuplicateSameContent,
    /// Same `event_id` but a *different* body — MUST be rejected.
    DuplicateConflict,
}

/// Persistence contract for the single-event-level dedup rule of
/// applet-integration §7.3: a repeated `event_id` with identical signed content
/// is accepted, conflicting content is rejected.
///
/// `fingerprint` is a stable hash over the event's signed canonical envelope
/// (see `event_content_fingerprint`); it is an equality token, not a security
/// primitive.
pub trait EventDedupStore: Send + Sync + 'static {
    fn check_and_record(&self, event_id: &str, fingerprint: i64) -> Result<DedupVerdict>;
}

/// Outcome of atomically claiming a public-webhook replay key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayGuardVerdict {
    /// This key was absent and has now been claimed for its retention window.
    Fresh,
    /// This key was already present and unexpired.
    Replay,
}

/// Persistence contract for the public-webhook replay guard (bridge contract
/// G-4: any inbound verification scheme without a per-body nonce MUST hold a
/// bounded replay/dedupe window).
///
/// Keys are only claimed for deliveries that already passed source verification,
/// so the table growth is bounded by legitimate traffic plus the TTL cleanup.
/// The store is durable and shared, so the guard holds across restarts and
/// across horizontally scaled replicas (unlike the former process-local
/// window).
pub trait ReplayGuardStore: Send + Sync + 'static {
    /// Whether `key` is present and unexpired. Does not record the key.
    fn contains(&self, key: &str) -> Result<bool>;
    /// Atomically claim `key` with `ttl_secs` retention. Storage failures are
    /// returned separately from a confirmed replay so callers can request
    /// vendor redelivery instead of acknowledging a fresh webhook.
    fn check_and_record(&self, key: &str, ttl_secs: i64) -> Result<ReplayGuardVerdict>;
    /// Release a previously claimed key after a retriable downstream failure so
    /// the vendor's redelivery can attempt the bridge submit again.
    fn forget(&self, key: &str) -> Result<()>;
}
