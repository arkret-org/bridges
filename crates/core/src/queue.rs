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
        let _guard = lock.lock().await;
        task().await
    }
}
