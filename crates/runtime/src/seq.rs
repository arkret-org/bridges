//! Restart-safe monotonic actor-sequence allocation.
//!
//! The allocator is abstracted behind the [`SeqStore`] trait so a host can
//! inject a non-diesel persistence backend. The diesel-backed implementation
//! [`DbSeqStore`] is only compiled under the `db` feature.

use std::sync::Arc;

use parking_lot::Mutex;

use crate::error::Result;

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
#[derive(Clone)]
pub struct SeqAllocator {
    store: Arc<dyn SeqStore>,
    key: String,
    state: Arc<Mutex<SeqWindow>>,
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
            state: Arc::new(Mutex::new(SeqWindow::default())),
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

    /// Async-path allocation that moves the synchronous backing-store refill
    /// onto Tokio's blocking pool. The hot path stays lock-only when the current
    /// reserved window still has numbers.
    pub async fn alloc_blocking(&self) -> Result<u64> {
        if let Some(seq) = self.try_alloc_from_window() {
            return Ok(seq);
        }

        let store = self.store.clone();
        let key = self.key.clone();
        let state = self.state.clone();
        crate::run_blocking(move || {
            let mut win = state.lock();
            if win.next >= win.limit {
                let reserved = store.reserve_block(&key, SEQ_RESERVE_BLOCK)?;
                win.next = reserved - SEQ_RESERVE_BLOCK + 1;
                win.limit = reserved + 1;
            }
            let seq = win.next;
            win.next += 1;
            Ok(seq as u64)
        })
        .await
    }

    fn try_alloc_from_window(&self) -> Option<u64> {
        let mut win = self.state.try_lock()?;
        if win.next >= win.limit {
            return None;
        }
        let seq = win.next;
        win.next += 1;
        Some(seq as u64)
    }
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
    /// Build the store, running the embedded runtime migrations (which include
    /// the `bridge_state` table; already-applied migrations are skipped).
    pub fn new(db: Arc<crate::db::DatabaseManager>) -> Result<Self> {
        db.run_migrations(crate::db::MIGRATIONS)?;
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

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
    fn cloned_allocator_shares_the_current_window() {
        let store: Arc<dyn SeqStore> = Arc::new(MemSeqStore::default());
        let first = SeqAllocator::new(store, "k");
        let second = first.clone();
        assert_eq!(first.alloc().unwrap(), 1);
        assert_eq!(second.alloc().unwrap(), 2);
        assert_eq!(first.alloc().unwrap(), 3);
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
