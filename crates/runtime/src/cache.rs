//! A simple async cache with TTL, equivalent to the Matrix bridge's
//! `AsyncTimedCache`. Used for debouncing/deduplication (e.g. recently
//! forwarded message ids, ghost user resolution results).

use std::collections::HashMap;
use std::future::Future;
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

struct CachedToken {
    value: String,
    expires_at: Instant,
}

/// A single-slot access-token cache with a server-provided, per-fetch TTL.
///
/// App bridges (Feishu/WeChat/DingTalk/Teams) obtain an OAuth-style access token
/// that is valid for a vendor-defined window (typically ~7200s). This holds the
/// most recent token and only re-fetches once it is within [`refresh_skew`] of
/// expiry, so the common path avoids a network round trip per send.
///
/// Concurrent misses may each trigger a refresh (last write wins); this is
/// acceptable for a low-frequency token fetch and avoids holding a lock across
/// `.await`.
pub struct TokenCache {
    inner: Mutex<Option<CachedToken>>,
    /// How early before the reported expiry to consider the token stale.
    refresh_skew: Duration,
}

impl TokenCache {
    /// Create a cache with the default 60s refresh skew.
    pub fn new() -> Self {
        Self::with_skew(Duration::from_secs(60))
    }

    pub fn with_skew(refresh_skew: Duration) -> Self {
        Self {
            inner: Mutex::new(None),
            refresh_skew,
        }
    }

    /// Return the cached token if still fresh; otherwise call `refresh` to fetch
    /// a new `(token, ttl)` pair, cache it (minus the refresh skew), and return
    /// the token. `refresh` errors are propagated unchanged and not cached.
    pub async fn get_or_try_refresh<F, Fut, E>(&self, refresh: F) -> std::result::Result<String, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = std::result::Result<(String, Duration), E>>,
    {
        if let Some(token) = self.peek() {
            return Ok(token);
        }
        let (value, ttl) = refresh().await?;
        let expires_at = Instant::now() + ttl.saturating_sub(self.refresh_skew);
        *self.inner.lock() = Some(CachedToken {
            value: value.clone(),
            expires_at,
        });
        Ok(value)
    }

    fn peek(&self) -> Option<String> {
        let guard = self.inner.lock();
        match &*guard {
            Some(token) if token.expires_at > Instant::now() => Some(token.value.clone()),
            _ => None,
        }
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}
