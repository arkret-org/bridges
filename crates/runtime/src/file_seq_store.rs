//! File-backed persistence for [`crate::SeqAllocator`].

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::{BridgeError, Result, SeqStore};

type SeqMap = HashMap<String, i64>;

/// A file-backed, restart-safe [`SeqStore`].
///
/// High-water marks are stored as a flat JSON object. Updates are serialized
/// through one mutex and persisted with a sibling temporary file plus rename,
/// so a value is durable before it is returned to an allocator.
#[derive(Debug)]
pub struct FileSeqStore {
    path: PathBuf,
    state: Mutex<SeqMap>,
}

impl FileSeqStore {
    /// Open a store, treating a missing file as an empty map.
    pub fn new(path: PathBuf) -> Result<Self> {
        let state = load_map(&path)?;
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    /// Return a trait object ready for [`crate::SeqAllocator::new`].
    pub fn shared(path: PathBuf) -> Result<Arc<dyn SeqStore>> {
        Ok(Arc::new(Self::new(path)?))
    }

    fn persist(&self, map: &SeqMap) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(map)
            .map_err(|e| BridgeError::App(format!("seq_store: serialize: {e}")))?;
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                BridgeError::App(format!("seq_store: create dir {}: {e}", parent.display()))
            })?;
        }
        let tmp = self.tmp_path();
        std::fs::write(&tmp, &bytes)
            .map_err(|e| BridgeError::App(format!("seq_store: write {}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            BridgeError::App(format!(
                "seq_store: rename {} -> {}: {e}",
                tmp.display(),
                self.path.display()
            ))
        })?;
        Ok(())
    }

    fn tmp_path(&self) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(|name| name.to_os_string())
            .unwrap_or_else(|| "seq_store.json".into());
        name.push(".tmp");
        self.path.with_file_name(name)
    }
}

impl SeqStore for FileSeqStore {
    fn reserve_block(&self, key: &str, block: i64) -> Result<i64> {
        if block <= 0 {
            return Err(BridgeError::App(
                "seq_store: reservation block must be positive".to_owned(),
            ));
        }
        let mut map = self.state.lock();
        let current = map.get(key).copied().unwrap_or(0);
        let reserved = current.checked_add(block).ok_or_else(|| {
            BridgeError::App(format!("seq_store: high-water mark overflow for key {key}"))
        })?;
        map.insert(key.to_owned(), reserved);
        self.persist(&map)?;
        Ok(reserved)
    }
}

fn load_map(path: &PathBuf) -> Result<SeqMap> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.is_empty() => Ok(SeqMap::new()),
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| BridgeError::App(format!("seq_store: parse {}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SeqMap::new()),
        Err(e) => Err(BridgeError::App(format!(
            "seq_store: read {}: {e}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    fn temp_file(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "arkret-bridge-seq-{label}-{}-{}.json",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ))
    }

    #[test]
    fn restart_preserves_existing_file_format_and_monotonicity() {
        let path = temp_file("restart");
        std::fs::write(&path, br#"{"applet:test:actor_seq":512}"#).unwrap();
        let store = FileSeqStore::new(path.clone()).unwrap();
        assert_eq!(
            store.reserve_block("applet:test:actor_seq", 256).unwrap(),
            768
        );
        drop(store);
        let reopened = FileSeqStore::new(path.clone()).unwrap();
        assert_eq!(
            reopened
                .reserve_block("applet:test:actor_seq", 256)
                .unwrap(),
            1024
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn distinct_keys_are_independent() {
        let path = temp_file("keys");
        let store = FileSeqStore::new(path.clone()).unwrap();
        assert_eq!(store.reserve_block("a", 10).unwrap(), 10);
        assert_eq!(store.reserve_block("b", 5).unwrap(), 5);
        assert_eq!(store.reserve_block("a", 10).unwrap(), 20);
        let _ = std::fs::remove_file(path);
    }
}
