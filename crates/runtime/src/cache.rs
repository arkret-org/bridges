//! A single-slot OAuth access-token cache with a vendor-provided, per-fetch TTL.

use std::future::Future;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

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
