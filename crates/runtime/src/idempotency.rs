//! Transaction-level idempotency and single-event dedup storage contracts
//! (applet-integration §7.3 / §13).
//!
//! The spec wording is MUST: "持久化 transaction id,保证幂等" and "对外部事件做
//! 去重". The production path therefore persists both records in the bridge
//! database ([`crate::db::DbTransactionIdempotencyStore`] /
//! [`crate::db::DbEventDedupStore`]); the in-memory implementations here remain
//! for tests and for hosts that inject their own persistence.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use cokret::model::AppletTransactionOutcome;
use parking_lot::Mutex;

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

/// Outcome of consulting the transaction idempotency store for one
/// `(source_service_did, Idempotency-Key, body_hash)` triple.
pub enum TransactionClaim {
    /// First sight (or takeover of a stale pending claim) — process it.
    Claimed,
    /// Same key + same body is currently being processed — ask for a retry.
    Pending,
    /// Same key + same body already completed — replay the recorded response.
    Duplicate(AppletTransactionOutcome),
    /// Same key but a different body — `duplicate_conflict` (§7.3).
    Conflict,
}

/// Persistence contract for transaction-level idempotency (§7.3: "Applet SHOULD
/// 先持久化幂等记录,再执行外部副作用" — `claim` runs before any side effect).
pub trait TransactionIdempotencyStore: Send + Sync + 'static {
    fn claim(&self, source: &str, key: &str, hash: &str) -> Result<TransactionClaim>;
    fn record(
        &self,
        source: &str,
        key: &str,
        hash: &str,
        response: &AppletTransactionOutcome,
    ) -> Result<()>;
    /// Drop a pending claim after a processing failure so the server's retry
    /// can be accepted instead of replaying a failure.
    fn release(&self, source: &str, key: &str, hash: &str) -> Result<()>;
}

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

/// In-memory [`TransactionIdempotencyStore`] (tests / hosts without a DB).
pub struct MemoryTransactionIdempotencyStore {
    ttl: Duration,
    inner: Mutex<HashMap<String, CachedTransaction>>,
}

enum CachedTransaction {
    Pending {
        hash: String,
        expires_at: Instant,
    },
    Completed {
        hash: String,
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

fn transaction_cache_key(source: &str, key: &str) -> String {
    format!("{source}\u{1f}{key}")
}

impl MemoryTransactionIdempotencyStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl TransactionIdempotencyStore for MemoryTransactionIdempotencyStore {
    fn claim(&self, source: &str, key: &str, hash: &str) -> Result<TransactionClaim> {
        let cache_key = transaction_cache_key(source, key);
        let now = Instant::now();
        let mut inner = self.inner.lock();
        inner.retain(|_, cached| cached.expires_at() > now);
        Ok(match inner.get(&cache_key) {
            Some(CachedTransaction::Completed {
                hash: cached_hash,
                response,
                ..
            }) if cached_hash == hash => TransactionClaim::Duplicate(response.clone()),
            Some(CachedTransaction::Pending {
                hash: cached_hash, ..
            }) if cached_hash == hash => TransactionClaim::Pending,
            Some(_) => TransactionClaim::Conflict,
            None => {
                inner.insert(
                    cache_key,
                    CachedTransaction::Pending {
                        hash: hash.to_owned(),
                        expires_at: now + self.ttl,
                    },
                );
                TransactionClaim::Claimed
            }
        })
    }

    fn record(
        &self,
        source: &str,
        key: &str,
        hash: &str,
        response: &AppletTransactionOutcome,
    ) -> Result<()> {
        self.inner.lock().insert(
            transaction_cache_key(source, key),
            CachedTransaction::Completed {
                hash: hash.to_owned(),
                response: response.clone(),
                expires_at: Instant::now() + self.ttl,
            },
        );
        Ok(())
    }

    fn release(&self, source: &str, key: &str, hash: &str) -> Result<()> {
        let cache_key = transaction_cache_key(source, key);
        let mut inner = self.inner.lock();
        let should_remove = matches!(
            inner.get(&cache_key),
            Some(CachedTransaction::Pending { hash: cached_hash, .. }) if cached_hash == hash
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
    use super::*;

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
            cache.claim("did:web:server.example", "idem-1", "hash-a"),
            Ok(TransactionClaim::Claimed)
        ));
        assert!(matches!(
            cache.claim("did:web:server.example", "idem-1", "hash-a"),
            Ok(TransactionClaim::Pending)
        ));

        let response = AppletTransactionOutcome {
            ok: true,
            rejected: Vec::new(),
            retry_after_ms: None,
        };
        cache
            .record("did:web:server.example", "idem-1", "hash-a", &response)
            .unwrap();

        match cache.claim("did:web:server.example", "idem-1", "hash-a") {
            Ok(TransactionClaim::Duplicate(cached)) => assert_eq!(cached.ok, response.ok),
            _ => panic!("expected duplicate response"),
        }
    }

    #[test]
    fn idempotency_release_allows_retry_after_failure() {
        let cache = MemoryTransactionIdempotencyStore::new(Duration::from_secs(300));
        assert!(matches!(
            cache.claim("did:web:server.example", "idem-2", "hash-a"),
            Ok(TransactionClaim::Claimed)
        ));
        assert!(matches!(
            cache.claim("did:web:server.example", "idem-2", "hash-b"),
            Ok(TransactionClaim::Conflict)
        ));

        cache
            .release("did:web:server.example", "idem-2", "hash-a")
            .unwrap();

        assert!(matches!(
            cache.claim("did:web:server.example", "idem-2", "hash-a"),
            Ok(TransactionClaim::Claimed)
        ));
    }
}
