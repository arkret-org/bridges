//! A shared, persistent OAuth access-token cache with a vendor-provided,
//! per-fetch TTL.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::Result;
use crate::run_blocking;

/// A persisted vendor access token: the value plus its absolute Unix-seconds
/// expiry.
pub struct PersistedToken {
    pub value: String,
    pub expires_at: i64,
}

/// Persistence contract backing [`TokenCache`].
///
/// The store is durable and shared across replicas of the same bridge. That is
/// a hard requirement for vendors where fetching a new token invalidates the
/// previously issued one (WeChat): with process-local caches two replicas keep
/// invalidating each other's token. The production path injects
/// [`crate::db::DbTokenStore`].
pub trait TokenStore: Send + Sync + 'static {
    /// Load the persisted token under `key`, if any.
    fn load(&self, key: &str) -> Result<Option<PersistedToken>>;
    /// Persist `token` under `key` with its absolute expiry (last write wins).
    fn store(&self, key: &str, token: &str, expires_at: i64) -> Result<()>;
}

/// A store-backed access-token cache with a server-provided, per-fetch TTL.
///
/// App bridges (Feishu/WeChat/DingTalk/Teams/Google Chat) obtain an OAuth-style
/// access token that is valid for a vendor-defined window (typically ~7200s).
/// The freshest token is read from the shared [`TokenStore`] on each use and
/// only re-fetched once it is within [`refresh_skew`](Self::with_skew) of
/// expiry, so every replica observes the token most recently fetched by any
/// replica.
///
/// Concurrent misses may each trigger a refresh (last write wins); this is
/// acceptable for a low-frequency token fetch and matches the vendor semantics
/// where the newest issued token is the live one.
pub struct TokenCache {
    store: Arc<dyn TokenStore>,
    /// The store key this cache reads/writes (unique per bridge + purpose,
    /// e.g. `wechat_access_token`).
    cache_key: String,
    /// How early before the reported expiry to consider the token stale.
    refresh_skew: Duration,
}

impl TokenCache {
    /// Create a cache over `store` under `cache_key` with the default 60s
    /// refresh skew.
    pub fn new(store: Arc<dyn TokenStore>, cache_key: impl Into<String>) -> Self {
        Self::with_skew(store, cache_key, Duration::from_secs(60))
    }

    pub fn with_skew(
        store: Arc<dyn TokenStore>,
        cache_key: impl Into<String>,
        refresh_skew: Duration,
    ) -> Self {
        Self {
            store,
            cache_key: cache_key.into(),
            refresh_skew,
        }
    }

    /// Return the stored token if still fresh; otherwise call `refresh` to
    /// fetch a new `(token, ttl)` pair, persist it, and return the token.
    /// `refresh` errors are propagated unchanged and not cached. Store failures
    /// degrade to a refetch (read) or an unshared token (write) with a warning
    /// rather than failing the send path.
    pub async fn get_or_try_refresh<F, Fut>(&self, refresh: F) -> Result<String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(String, Duration)>>,
    {
        let now = unix_now();
        let skew = self.refresh_skew.as_secs().min(i64::MAX as u64) as i64;
        let store = self.store.clone();
        let cache_key = self.cache_key.clone();
        match run_blocking(move || store.load(&cache_key)).await {
            Ok(Some(token)) if token.expires_at > now.saturating_add(skew) => {
                return Ok(token.value);
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, key = %self.cache_key, "token cache read failed; refetching");
            }
        }
        let (value, ttl) = refresh().await?;
        let ttl_secs = ttl.as_secs().min(i64::MAX as u64) as i64;
        let store = self.store.clone();
        let cache_key = self.cache_key.clone();
        let stored_value = value.clone();
        if let Err(err) = run_blocking(move || {
            store.store(&cache_key, &stored_value, now.saturating_add(ttl_secs))
        })
        .await
        {
            tracing::warn!(error = %err, key = %self.cache_key, "token cache write failed; token not shared");
        }
        Ok(value)
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}
