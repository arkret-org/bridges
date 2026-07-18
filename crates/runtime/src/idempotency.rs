//! Transaction-level idempotency and single-event dedup storage contracts
//! (applet-integration §7.3 / §13).
//!
//! The spec wording is MUST: persist transaction ids for idempotency and
//! deduplicate external events. The production path therefore persists both
//! records in the bridge database ([`crate::db::DbTransactionIdempotencyStore`] /
//! [`crate::db::DbEventDedupStore`]); the in-memory implementations here remain
//! for tests and for hosts that inject their own persistence.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use arkret::models::AppletTransactionOutcome;
use arkret::{IdempotencyIdentity, TransactionClaim, TransactionIdempotencyStore};
use parking_lot::Mutex;

use crate::error::{BridgeError, Result};

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

/// In-memory [`TransactionIdempotencyStore`] (tests / hosts without a DB).
pub struct MemoryTransactionIdempotencyStore {
    ttl: Duration,
    inner: Mutex<HashMap<String, CachedTransaction>>,
}

enum CachedTransaction {
    Pending {
        hash: String,
        source_signature_anchor: String,
        expires_at: Instant,
    },
    Completed {
        hash: String,
        source_signature_anchor: String,
        response: AppletTransactionOutcome,
        expires_at: Instant,
    },
}

impl CachedTransaction {
    fn expires_at(&self) -> Instant {
        match self {
            Self::Pending { expires_at, .. } | Self::Completed { expires_at, .. } => *expires_at,
        }
    }
}

fn transaction_cache_key(replay: &IdempotencyIdentity) -> String {
    [
        replay.operation_id.as_str(),
        replay.direction.as_str(),
        replay.source_service_id.as_str(),
        replay.destination_service_id.as_str(),
        replay.idempotency_key.as_str(),
    ]
    .join("\u{1f}")
}

impl MemoryTransactionIdempotencyStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl TransactionIdempotencyStore<AppletTransactionOutcome> for MemoryTransactionIdempotencyStore {
    type Error = BridgeError;

    fn claim(
        &self,
        replay: &IdempotencyIdentity,
        hash: &str,
        source_signature_anchor: &str,
    ) -> Result<TransactionClaim<AppletTransactionOutcome>> {
        let cache_key = transaction_cache_key(replay);
        let now = Instant::now();
        let mut inner = self.inner.lock();
        inner.retain(|_, cached| cached.expires_at() > now);
        Ok(match inner.get(&cache_key) {
            Some(CachedTransaction::Completed {
                hash: cached_hash,
                source_signature_anchor: cached_anchor,
                response,
                ..
            }) if cached_hash == hash && cached_anchor == source_signature_anchor => {
                TransactionClaim::Duplicate(response.clone())
            }
            Some(CachedTransaction::Pending {
                hash: cached_hash,
                source_signature_anchor: cached_anchor,
                ..
            }) if cached_hash == hash && cached_anchor == source_signature_anchor => {
                TransactionClaim::Pending
            }
            Some(_) => TransactionClaim::Conflict,
            None => {
                inner.insert(
                    cache_key,
                    CachedTransaction::Pending {
                        hash: hash.to_owned(),
                        source_signature_anchor: source_signature_anchor.to_owned(),
                        expires_at: now + self.ttl,
                    },
                );
                TransactionClaim::Claimed
            }
        })
    }

    fn record(
        &self,
        replay: &IdempotencyIdentity,
        hash: &str,
        source_signature_anchor: &str,
        response: &AppletTransactionOutcome,
    ) -> Result<()> {
        self.inner.lock().insert(
            transaction_cache_key(replay),
            CachedTransaction::Completed {
                hash: hash.to_owned(),
                source_signature_anchor: source_signature_anchor.to_owned(),
                response: response.clone(),
                expires_at: Instant::now() + self.ttl,
            },
        );
        Ok(())
    }

    fn release(
        &self,
        replay: &IdempotencyIdentity,
        hash: &str,
        source_signature_anchor: &str,
    ) -> Result<()> {
        let cache_key = transaction_cache_key(replay);
        let mut inner = self.inner.lock();
        let should_remove = matches!(
            inner.get(&cache_key),
            Some(CachedTransaction::Pending {
                hash: cached_hash,
                source_signature_anchor: cached_anchor,
                ..
            }) if cached_hash == hash && cached_anchor == source_signature_anchor
        );
        if should_remove {
            inner.remove(&cache_key);
        }
        Ok(())
    }
}

/// In-memory [`EventDedupStore`] (tests / hosts without a DB). Bounded: on
/// overflow the window is cleared, so old duplicates re-enter as fresh events
/// (at-least-once — the conservative direction).
pub struct MemoryEventDedupStore {
    seen: Mutex<HashMap<String, i64>>,
    capacity: usize,
}

impl MemoryEventDedupStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            capacity,
        }
    }
}

impl EventDedupStore for MemoryEventDedupStore {
    fn check_and_record(&self, event_id: &str, fingerprint: i64) -> Result<DedupVerdict> {
        let mut seen = self.seen.lock();
        Ok(match seen.get(event_id) {
            Some(&prev) if prev == fingerprint => DedupVerdict::DuplicateSameContent,
            Some(_) => DedupVerdict::DuplicateConflict,
            None => {
                if seen.len() >= self.capacity {
                    seen.clear();
                }
                seen.insert(event_id.to_owned(), fingerprint);
                DedupVerdict::Fresh
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use arkret::IdempotencyDirection;

    use super::*;

    fn replay_key(idempotency_key: &str) -> IdempotencyIdentity {
        replay_key_to("did:webvh:bridge.example", idempotency_key)
    }

    fn replay_key_to(destination_service_id: &str, idempotency_key: &str) -> IdempotencyIdentity {
        IdempotencyIdentity::applet_transaction(
            IdempotencyDirection::NodeToApplet,
            "did:webvh:server.example",
            destination_service_id,
            idempotency_key,
        )
    }

    #[test]
    fn dedup_store_distinguishes_same_and_conflicting_content() {
        let win = MemoryEventDedupStore::new(16);
        assert!(matches!(
            win.check_and_record("ev1", 100).unwrap(),
            DedupVerdict::Fresh
        ));
        assert!(matches!(
            win.check_and_record("ev1", 100).unwrap(),
            DedupVerdict::DuplicateSameContent
        ));
        assert!(matches!(
            win.check_and_record("ev1", 200).unwrap(),
            DedupVerdict::DuplicateConflict
        ));
        assert!(matches!(
            win.check_and_record("ev2", 100).unwrap(),
            DedupVerdict::Fresh
        ));
    }

    #[test]
    fn dedup_store_clears_on_capacity_overflow() {
        let win = MemoryEventDedupStore::new(2);
        assert!(matches!(
            win.check_and_record("a", 1).unwrap(),
            DedupVerdict::Fresh
        ));
        assert!(matches!(
            win.check_and_record("b", 1).unwrap(),
            DedupVerdict::Fresh
        ));
        assert!(matches!(
            win.check_and_record("c", 1).unwrap(),
            DedupVerdict::Fresh
        ));
        assert!(matches!(
            win.check_and_record("a", 1).unwrap(),
            DedupVerdict::Fresh
        ));
    }

    #[test]
    fn idempotency_claim_blocks_duplicate_until_recorded() {
        let cache = MemoryTransactionIdempotencyStore::new(Duration::from_secs(300));
        assert!(matches!(
            cache.claim(&replay_key("idem-1"), "hash-a", "anchor-a"),
            Ok(TransactionClaim::Claimed)
        ));
        assert!(matches!(
            cache.claim(&replay_key("idem-1"), "hash-a", "anchor-a"),
            Ok(TransactionClaim::Pending)
        ));

        let response = AppletTransactionOutcome {
            ok: true,
            rejected: Vec::new(),
            retry_after_ms: None,
        };
        cache
            .record(&replay_key("idem-1"), "hash-a", "anchor-a", &response)
            .unwrap();

        match cache.claim(&replay_key("idem-1"), "hash-a", "anchor-a") {
            Ok(TransactionClaim::Duplicate(cached)) => assert_eq!(cached.ok, response.ok),
            _ => panic!("expected duplicate response"),
        }
    }

    #[test]
    fn idempotency_release_allows_retry_after_failure() {
        let cache = MemoryTransactionIdempotencyStore::new(Duration::from_secs(300));
        assert!(matches!(
            cache.claim(&replay_key("idem-2"), "hash-a", "anchor-a"),
            Ok(TransactionClaim::Claimed)
        ));
        assert!(matches!(
            cache.claim(&replay_key("idem-2"), "hash-b", "anchor-a"),
            Ok(TransactionClaim::Conflict)
        ));

        cache
            .release(&replay_key("idem-2"), "hash-a", "anchor-a")
            .unwrap();

        assert!(matches!(
            cache.claim(&replay_key("idem-2"), "hash-a", "anchor-a"),
            Ok(TransactionClaim::Claimed)
        ));
    }

    #[test]
    fn idempotency_binds_replay_to_anchor_and_destination() {
        let cache = MemoryTransactionIdempotencyStore::new(Duration::from_secs(300));
        assert!(matches!(
            cache.claim(&replay_key("idem-3"), "hash-a", "anchor-a"),
            Ok(TransactionClaim::Claimed)
        ));
        assert!(matches!(
            cache.claim(&replay_key("idem-3"), "hash-a", "anchor-b"),
            Ok(TransactionClaim::Conflict)
        ));
        assert!(matches!(
            cache.claim(
                &replay_key_to("did:webvh:other-bridge.example", "idem-3"),
                "hash-a",
                "anchor-b"
            ),
            Ok(TransactionClaim::Claimed)
        ));
    }
}
