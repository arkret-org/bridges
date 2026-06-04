//! A simple async cache with TTL, equivalent to the Matrix bridge's
//! `AsyncTimedCache`. Used for debouncing/deduplication (e.g. recently
//! forwarded message ids, ghost user resolution results).

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

struct Entry<V> {
    value: V,
    expires_at: Instant,
}

/// A thread-safe key-value cache with expiration.
pub struct AsyncTimedCache<K, V> {
    ttl: Duration,
    inner: Mutex<HashMap<K, Entry<V>>>,
}

impl<K: Eq + Hash + Clone, V: Clone> AsyncTimedCache<K, V> {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn insert(&self, key: K, value: V) {
        let mut guard = self.inner.lock();
        guard.insert(
            key,
            Entry {
                value,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let mut guard = self.inner.lock();
        match guard.get(key) {
            Some(entry) if entry.expires_at > Instant::now() => Some(entry.value.clone()),
            Some(_) => {
                guard.remove(key);
                None
            }
            None => None,
        }
    }

    pub fn contains(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Remove all expired entries and return the remaining count.
    pub fn evict_expired(&self) -> usize {
        let now = Instant::now();
        let mut guard = self.inner.lock();
        guard.retain(|_, e| e.expires_at > now);
        guard.len()
    }
}
