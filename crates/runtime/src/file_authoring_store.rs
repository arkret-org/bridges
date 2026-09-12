//! Append-only durable journal with OS file locking across independent hosts/processes.
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;

use crate::{AuthoringStore, BridgeError, Result};

#[derive(Debug)]
pub struct FileAuthoringStore {
    path: PathBuf,
}

impl FileAuthoringStore {
    pub fn new(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io_error)?;
        }
        let store = Self { path };
        store.locked_file()?;
        Ok(store)
    }
    pub fn shared(path: PathBuf) -> Result<Arc<dyn AuthoringStore>> {
        Ok(Arc::new(Self::new(path)?))
    }

    fn locked_file(&self) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)
            .map_err(io_error)?;
        file.lock().map_err(io_error)?;
        Ok(file)
    }
}

fn io_error(error: std::io::Error) -> BridgeError {
    BridgeError::Database(format!("ordinary authoring journal: {error}"))
}

/// A torn final append was never committed; truncate it before the next append.
/// Complete entries are never rewritten, so failure cannot erase an accepted frontier.
fn read_entries(file: &mut File) -> Result<BTreeMap<String, String>> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(io_error)?;
    let committed = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |end| end + 1);
    let mut entries = BTreeMap::new();
    for line in bytes[..committed]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let (scope, journal): (String, String) = serde_json::from_slice(line)?;
        entries.insert(scope, journal);
    }
    if committed != bytes.len() {
        file.set_len(committed as u64).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
    }
    Ok(entries)
}

impl AuthoringStore for FileAuthoringStore {
    fn load(&self, scope: &str) -> Result<Option<String>> {
        Ok(read_entries(&mut self.locked_file()?)?.remove(scope))
    }
    fn compare_exchange(
        &self,
        scope: &str,
        expected: Option<&str>,
        replacement: &str,
    ) -> Result<bool> {
        let mut file = self.locked_file()?;
        let entries = read_entries(&mut file)?;
        if entries.get(scope).map(String::as_str) != expected {
            return Ok(false);
        }
        let mut bytes = serde_json::to_vec(&(scope, replacement))?;
        bytes.push(b'\n');
        file.seek(SeekFrom::End(0)).map_err(io_error)?;
        file.write_all(&bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        Ok(true)
    }
    fn entries(&self) -> Result<Vec<(String, String)>> {
        Ok(read_entries(&mut self.locked_file()?)?
            .into_iter()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    fn path() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "bridge-authoring-{}-{}.jsonl",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
    #[test]
    fn independent_instances_cas_and_restart_preserve_exact_bytes() {
        let path = path();
        let one = FileAuthoringStore::new(path.clone()).unwrap();
        let two = FileAuthoringStore::new(path.clone()).unwrap();
        assert!(
            one.compare_exchange("realm-a/full-actor-a", None, "signed bytes")
                .unwrap()
        );
        assert!(
            !two.compare_exchange("realm-a/full-actor-a", None, "replacement")
                .unwrap()
        );
        assert!(
            two.compare_exchange("realm-b/full-actor-a", None, "other realm")
                .unwrap()
        );
        assert!(
            two.compare_exchange("realm-a/full-actor-b", None, "other account")
                .unwrap()
        );
        drop(one);
        drop(two);
        let reopened = FileAuthoringStore::new(path.clone()).unwrap();
        assert_eq!(
            reopened.load("realm-a/full-actor-a").unwrap().as_deref(),
            Some("signed bytes")
        );
        assert!(
            !reopened
                .compare_exchange("realm-a/full-actor-a", Some("stale"), "lost")
                .unwrap()
        );
        assert!(
            reopened
                .compare_exchange(
                    "realm-a/full-actor-a",
                    Some("signed bytes"),
                    "accepted frontier"
                )
                .unwrap()
        );
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn crash_partial_append_cannot_destroy_committed_entry() {
        let path = path();
        let store = FileAuthoringStore::new(path.clone()).unwrap();
        assert!(store.compare_exchange("scope", None, "frozen").unwrap());
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(b"[partial").unwrap();
            file.sync_all().unwrap();
        }
        assert_eq!(store.load("scope").unwrap().as_deref(), Some("frozen"));
        assert!(
            store
                .compare_exchange("scope", Some("frozen"), "accepted")
                .unwrap()
        );
        assert_eq!(store.load("scope").unwrap().as_deref(), Some("accepted"));
        std::fs::remove_file(path).unwrap();
    }
}
