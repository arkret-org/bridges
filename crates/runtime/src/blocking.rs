//! Utilities for isolating synchronous persistence work from async executors.

use crate::error::{BridgeError, Result};

pub async fn run_blocking<T, F>(operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|err| BridgeError::Runtime(format!("blocking task join failed: {err}")))?
}
