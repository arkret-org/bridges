//! A task queue serialized per conversation (channel/realm), equivalent to the
//! Matrix bridge's `ChannelQueue`. It guarantees in-order delivery of messages
//! within the same channel while different channels run in parallel.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::Mutex as AsyncMutex;

/// One async lock per key, serializing tasks on that key.
#[derive(Default)]
pub struct ChannelQueue {
    locks: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
}

impl ChannelQueue {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_for(&self, key: &str) -> Arc<AsyncMutex<()>> {
        let mut guard = self.locks.lock();
        guard
            .entry(key.to_owned())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    /// Run `task` within the serial domain of `key`. Concurrent calls on the
    /// same key are queued.
    pub async fn run<F, Fut, T>(&self, key: &str, task: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let lock = self.lock_for(key);
        let result = {
            let _guard = lock.lock().await;
            task().await
        };
        // Lazily reclaim the per-key entry once no other task is using it. High
        // cardinality keys (e.g. per-user channels on WhatsApp/Messenger) would
        // otherwise grow the map unboundedly. We hold one `Arc` (`lock`); the map
        // holds another. After dropping the guard, a strong_count of 2 means only
        // we and the map reference it, so it is safe to remove.
        {
            let mut guard = self.locks.lock();
            if let Some(entry) = guard.get(key)
                && Arc::strong_count(entry) <= 2
            {
                guard.remove(key);
            }
        }
        result
    }
}
