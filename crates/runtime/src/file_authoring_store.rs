//! Single-process, crash-safe indexed storage for edge-only deployments.
//! The database owns its OS lock for its lifetime. Other processes fail closed;
//! deployments requiring multiple writers use the SQL authoring backend.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use redb::{Database, Durability, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{AuthoringStore, BridgeError, Result};

const ENTRIES: TableDefinition<&str, &str> = TableDefinition::new("authoring_journal");
const BARRIER: TableDefinition<&str, u64> = TableDefinition::new("durability_barrier");
const CACHE_BYTES: usize = 16 * 1024 * 1024;

struct Engine {
    // None is poisoned: even reads are forbidden until every owner closes and
    // a new instance recovers the database with a successful durability barrier.
    database: Mutex<Option<Database>>,
}

pub struct FileAuthoringStore {
    engine: Arc<Engine>,
}

fn storage_error(error: impl std::fmt::Display) -> BridgeError {
    BridgeError::Database(format!("authoring journal storage: {error}"))
}

fn engines() -> &'static Mutex<BTreeMap<PathBuf, Weak<Engine>>> {
    static ENGINES: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Engine>>>> = OnceLock::new();
    ENGINES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn canonical_path(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path).map_err(storage_error)?;
    if absolute.exists() {
        return absolute.canonicalize().map_err(storage_error);
    }
    let parent = absolute
        .parent()
        .ok_or_else(|| storage_error("database has no parent"))?;
    std::fs::create_dir_all(parent).map_err(storage_error)?;
    let name = absolute
        .file_name()
        .ok_or_else(|| storage_error("database has no filename"))?;
    Ok(parent.canonicalize().map_err(storage_error)?.join(name))
}

impl FileAuthoringStore {
    pub fn new(path: PathBuf) -> Result<Self> {
        let path = canonical_path(&path)?;
        let mut registry = engines().lock().map_err(storage_error)?;
        if let Some(engine) = registry.get(&path).and_then(Weak::upgrade) {
            if engine.database.lock().map_err(storage_error)?.is_none() {
                return Err(storage_error(
                    "database is poisoned; close all owners before recovery",
                ));
            }
            return Ok(Self { engine });
        }
        let mut builder = Database::builder();
        builder.set_cache_size(CACHE_BYTES);
        let database = builder.create(&path).map_err(storage_error)?;
        let store = Self::from_database(database)?;
        registry.insert(path, Arc::downgrade(&store.engine));
        Ok(store)
    }
    pub fn shared(path: PathBuf) -> Result<Arc<dyn AuthoringStore>> {
        Ok(Arc::new(Self::new(path)?))
    }

    fn from_database(database: Database) -> Result<Self> {
        // Opening a database alone is not permission to send a recovered Event:
        // a previous failing commit may have left visible but unsynced pages.
        // A fresh immediate two-phase commit must succeed before exposing reads.
        let mut transaction = database.begin_write().map_err(storage_error)?;
        transaction
            .set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        transaction.set_two_phase_commit(true);
        {
            transaction.open_table(ENTRIES).map_err(storage_error)?;
            let mut table = transaction.open_table(BARRIER).map_err(storage_error)?;
            let previous = table
                .get("reopen")
                .map_err(storage_error)?
                .map_or(0, |value| value.value());
            table
                .insert("reopen", previous.wrapping_add(1))
                .map_err(storage_error)?;
        }
        transaction.commit().map_err(storage_error)?;
        Ok(Self {
            engine: Arc::new(Engine {
                database: Mutex::new(Some(database)),
            }),
        })
    }

    fn with_database<T>(&self, operation: impl FnOnce(&Database) -> Result<T>) -> Result<T> {
        let mut owner = self.engine.database.lock().map_err(storage_error)?;
        let database = owner.as_ref().ok_or_else(|| {
            storage_error("database is poisoned; close all owners before recovery")
        })?;
        let result = operation(database);
        if result.is_err() {
            // Commit errors have an unknown outcome, not an assumed rollback.
            // Drop the database and poison this shared owner before returning.
            *owner = None;
        }
        result
    }
}

impl AuthoringStore for FileAuthoringStore {
    fn load(&self, key: &str) -> Result<Option<String>> {
        self.with_database(|database| {
            let read = database.begin_read().map_err(storage_error)?;
            let table = read.open_table(ENTRIES).map_err(storage_error)?;
            Ok(table
                .get(key)
                .map_err(storage_error)?
                .map(|value| value.value().to_owned()))
        })
    }
    fn compare_exchange_batch(
        &self,
        expected: &[(String, Option<String>)],
        writes: &[(String, Option<String>)],
    ) -> Result<bool> {
        self.with_database(|database| {
            let mut transaction = database.begin_write().map_err(storage_error)?;
            transaction
                .set_durability(Durability::Immediate)
                .map_err(storage_error)?;
            transaction.set_two_phase_commit(true);
            {
                let mut table = transaction.open_table(ENTRIES).map_err(storage_error)?;
                for (key, expected) in expected {
                    if table
                        .get(key.as_str())
                        .map_err(storage_error)?
                        .as_ref()
                        .map(|entry| entry.value())
                        != expected.as_deref()
                    {
                        return Ok(false);
                    }
                }
                for (key, value) in writes {
                    match value {
                        Some(value) => {
                            table
                                .insert(key.as_str(), value.as_str())
                                .map_err(storage_error)?;
                        }
                        None => {
                            table.remove(key.as_str()).map_err(storage_error)?;
                        }
                    }
                }
            }
            transaction.commit().map_err(storage_error)?;
            Ok(true)
        })
    }
    fn entries_with_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>> {
        self.with_database(|database| {
            let read = database.begin_read().map_err(storage_error)?;
            let table = read.open_table(ENTRIES).map_err(storage_error)?;
            let upper = format!("{prefix}\u{10ffff}");
            let mut entries = Vec::new();
            for row in table.range(prefix..upper.as_str()).map_err(storage_error)? {
                let (key, value) = row.map_err(storage_error)?;
                entries.push((key.value().to_owned(), value.value().to_owned()));
            }
            Ok(entries)
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    fn path() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "bridge-authoring-{}-{}.redb",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
    #[test]
    fn shared_instances_atomic_cas_and_restart_preserve_exact_bytes() {
        let path = path();
        let one = FileAuthoringStore::new(path.clone()).unwrap();
        let two = FileAuthoringStore::new(path.clone()).unwrap();
        assert!(Arc::ptr_eq(&one.engine, &two.engine));
        let original = "exact signed Event bytes including proof";
        assert!(
            one.compare_exchange_batch(
                &[("head/a".into(), None), ("operation/a/1".into(), None)],
                &[
                    ("head/a".into(), Some("pending".into())),
                    ("operation/a/1".into(), Some(original.into()))
                ]
            )
            .unwrap()
        );
        assert!(
            !two.compare_exchange_batch(
                &[("head/a".into(), None)],
                &[("operation/a/2".into(), Some("must rollback".into()))]
            )
            .unwrap()
        );
        assert_eq!(two.load("operation/a/2").unwrap(), None);
        assert!(matches!(
            Database::open(&path),
            Err(redb::DatabaseError::DatabaseAlreadyOpen)
        ));
        drop(one);
        drop(two);
        let reopened = FileAuthoringStore::new(path.clone()).unwrap();
        assert_eq!(
            reopened.load("operation/a/1").unwrap().as_deref(),
            Some(original)
        );
        assert_eq!(reopened.entries_with_prefix("head/").unwrap().len(), 1);
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }

    #[derive(Clone, Debug, Default)]
    pub(crate) struct FaultBackend(Arc<Mutex<Pages>>);
    #[derive(Debug, Default)]
    struct Pages {
        visible: Vec<u8>,
        durable: Vec<u8>,
        fail_write: bool,
        fail_sync: bool,
    }
    impl FaultBackend {
        pub(crate) fn fail_sync(&self) {
            self.0.lock().unwrap().fail_sync = true;
        }
        pub(crate) fn power_loss(&self) {
            let mut state = self.0.lock().unwrap();
            state.visible = state.durable.clone();
            state.fail_sync = false;
            state.fail_write = false;
        }
    }
    impl redb::StorageBackend for FaultBackend {
        fn len(&self) -> std::io::Result<u64> {
            Ok(self.0.lock().unwrap().visible.len() as u64)
        }
        fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
            let state = self.0.lock().unwrap();
            let begin = offset as usize;
            let end = begin
                .checked_add(out.len())
                .ok_or_else(|| std::io::Error::other("overflow"))?;
            let bytes = state
                .visible
                .get(begin..end)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
            out.copy_from_slice(bytes);
            Ok(())
        }
        fn set_len(&self, len: u64) -> std::io::Result<()> {
            self.0.lock().unwrap().visible.resize(len as usize, 0);
            Ok(())
        }
        fn sync_data(&self) -> std::io::Result<()> {
            let mut state = self.0.lock().unwrap();
            if state.fail_sync {
                return Err(std::io::Error::other("injected sync failure"));
            }
            state.durable = state.visible.clone();
            Ok(())
        }
        fn write(&self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
            let mut state = self.0.lock().unwrap();
            if state.fail_write {
                return Err(std::io::Error::other("injected write failure"));
            }
            let start = offset as usize;
            let end = start + bytes.len();
            if state.visible.len() < end {
                state.visible.resize(end, 0);
            }
            state.visible[start..end].copy_from_slice(bytes);
            Ok(())
        }
    }
    pub(crate) fn fault_store(backend: FaultBackend) -> FileAuthoringStore {
        let mut builder = Database::builder();
        builder.set_cache_size(1024 * 1024);
        FileAuthoringStore::from_database(builder.create_with_backend(backend).unwrap()).unwrap()
    }
    #[test]
    fn storage_failure_poison_blocks_send_reads_until_durable_reopen() {
        for write_failure in [false, true] {
            let backend = FaultBackend::default();
            let store = fault_store(backend.clone());
            assert!(
                store
                    .compare_exchange_batch(
                        &[("operation/old".into(), None)],
                        &[("operation/old".into(), Some("original signature".into()))]
                    )
                    .unwrap()
            );
            {
                let mut pages = backend.0.lock().unwrap();
                pages.fail_write = write_failure;
                pages.fail_sync = !write_failure;
            }
            assert!(
                store
                    .compare_exchange_batch(
                        &[("operation/new".into(), None)],
                        &[(
                            "operation/new".into(),
                            Some("unacknowledged signature".into())
                        )]
                    )
                    .is_err()
            );
            // A retry must read the frozen original before transport. No read
            // escapes this poisoned owner, even if the failed row is visible.
            let sent = std::sync::atomic::AtomicU64::new(0);
            if store.load("operation/new").is_ok() {
                sent.fetch_add(1, Ordering::SeqCst);
            }
            assert_eq!(sent.load(Ordering::SeqCst), 0);
            assert!(store.load("operation/old").is_err());
            drop(store);
            // Simulated power loss discards the backend's unsynced pages.
            {
                let mut pages = backend.0.lock().unwrap();
                pages.visible = pages.durable.clone();
                pages.fail_write = false;
                pages.fail_sync = false;
            }
            let recovered = fault_store(backend);
            assert_eq!(
                recovered.load("operation/old").unwrap().as_deref(),
                Some("original signature")
            );
            if let Some(value) = recovered.load("operation/new").unwrap() {
                assert_eq!(value, "unacknowledged signature");
            }
        }
    }

    #[test]
    #[ignore = "explicit growth benchmark: 1k/10k/100k immediate durable commits"]
    fn indexed_journal_growth_1000_10000_100000() {
        let path = path();
        let store = FileAuthoringStore::new(path.clone()).unwrap();
        let started = std::time::Instant::now();
        let payload = "x".repeat(1024);
        let mut previous = None;
        for n in 1..=100_000_u64 {
            let next = n.to_string();
            let operation = format!("operation/{n:08}");
            assert!(
                store
                    .compare_exchange_batch(
                        &[
                            ("head/a".into(), previous.clone()),
                            (operation.clone(), None)
                        ],
                        &[
                            ("head/a".into(), Some(next.clone())),
                            (operation.clone(), Some(payload.clone()))
                        ]
                    )
                    .unwrap()
            );
            assert_eq!(
                store.load(&operation).unwrap().as_deref(),
                Some(payload.as_str())
            );
            previous = Some(next);
            if [1000, 10000, 100000].contains(&n) {
                let size = std::fs::metadata(&path).unwrap().len();
                eprintln!(
                    "records={n} bytes={size} elapsed_ms={}",
                    started.elapsed().as_millis()
                );
                // Loose physical bound accommodates page allocation; catches
                // reintroducing whole-history values without timing flakiness.
                assert!(size < n * 64 * 1024 + 16 * 1024 * 1024);
            }
        }
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}
