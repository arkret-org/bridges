//! Generic database access (diesel + r2d2). Defaults to sqlite; features can
//! switch to postgres/mysql.
//!
//! The core only owns the connection pool and a generic migration runner.
//! Domain-specific tables (e.g. the room/message/user mappings used by the
//! messaging layer) are defined and migrated by the layer that needs them,
//! via [`DatabaseManager::run_migrations`]. This keeps the core free of any
//! chat/messaging assumptions so it can back non-social bridges too.

use std::sync::Arc;

use cokret::models::AppletTransactionOutcome;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

use crate::config::DatabaseConfig;
use crate::error::{BridgeError, Result};
use crate::idempotency::{
    DedupVerdict, EventDedupStore, IDEMPOTENCY_TTL_SECS, PENDING_TAKEOVER_GRACE_SECS,
    TransactionClaim, TransactionIdempotencyStore,
};

/// Embedded migrations for the runtime-owned tables (`transaction_idempotency`,
/// `event_dedup`, `bridge_state`). The backend dialect is selected at compile
/// time via the active connection feature, matching [`DbConnection`].
#[cfg(feature = "sqlite")]
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/sqlite");
#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/postgres");
#[cfg(all(feature = "mysql", not(feature = "sqlite"), not(feature = "postgres")))]
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/mysql");

/// The backend connection type (selected by feature, exactly one).
#[cfg(feature = "sqlite")]
pub type DbConnection = diesel::SqliteConnection;
#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
pub type DbConnection = diesel::PgConnection;
#[cfg(all(feature = "mysql", not(feature = "sqlite"), not(feature = "postgres")))]
pub type DbConnection = diesel::MysqlConnection;

pub type DbPool = Pool<ConnectionManager<DbConnection>>;
pub type DbConn = PooledConnection<ConnectionManager<DbConnection>>;

/// Generic connection pool wrapper.
pub struct DatabaseManager {
    pool: DbPool,
}

impl DatabaseManager {
    /// Build the connection pool from the configuration. No schema is created
    /// here — call [`DatabaseManager::run_migrations`] from each layer for its
    /// own tables.
    pub fn connect(cfg: &DatabaseConfig) -> Result<Self> {
        let url = normalize_url(&cfg.url);
        let manager = ConnectionManager::<DbConnection>::new(url);
        let pool = Pool::builder()
            .max_size(cfg.pool_size)
            .build(manager)
            .map_err(|e| BridgeError::Database(e.to_string()))?;
        Ok(Self { pool })
    }

    pub fn conn(&self) -> Result<DbConn> {
        self.pool.get().map_err(Into::into)
    }

    /// Run the embedded, versioned migrations for one layer's tables. Each
    /// layer passes its own [`EmbeddedMigrations`] (built with
    /// [`embed_migrations!`] against its per-backend migration directory).
    /// Already-applied migrations are skipped via `__diesel_schema_migrations`,
    /// so this is safe to call once per store at startup.
    pub fn run_migrations(&self, migrations: EmbeddedMigrations) -> Result<()> {
        let mut conn = self.conn()?;
        conn.run_pending_migrations(migrations)
            .map_err(|e| BridgeError::Database(e.to_string()))?;
        Ok(())
    }
}

/// Normalize `sqlite://path` into the plain path diesel sqlite accepts; other
/// URLs are returned unchanged.
fn normalize_url(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("sqlite://") {
        rest.to_owned()
    } else {
        url.to_owned()
    }
}

// ---------------------------------------------------------------------------
// Durable idempotency / dedup stores (applet-integration §7.3 / §13 MUST:
// "持久化 transaction id,保证幂等" / "对外部事件做去重"). These replace the
// former process-local caches so restarts and TTL expiry no longer turn server
// retries into duplicate deliveries.
// ---------------------------------------------------------------------------

mod idempotency_schema {
    diesel::table! {
        /// Transaction-level idempotency records, keyed by
        /// `(source_service_did, Idempotency-Key)`.
        transaction_idempotency (source_service_did, idempotency_key) {
            source_service_did -> Text,
            idempotency_key -> Text,
            body_hash -> Text,
            status -> Text,
            outcome -> Nullable<Text>,
            created_at -> BigInt,
            expires_at -> BigInt,
        }
    }

    diesel::table! {
        /// Single-event dedup window: `event_id -> canonical fingerprint`.
        event_dedup (event_id) {
            event_id -> Text,
            fingerprint -> BigInt,
            expires_at -> BigInt,
        }
    }
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

const STATUS_PENDING: &str = "pending";
const STATUS_COMPLETED: &str = "completed";

/// Diesel-backed [`TransactionIdempotencyStore`]: persists
/// `(source_service_did, Idempotency-Key, body_hash, outcome)` so transaction
/// idempotency survives restarts (applet-integration §13 MUST).
pub struct DbTransactionIdempotencyStore {
    db: Arc<DatabaseManager>,
}

impl DbTransactionIdempotencyStore {
    /// Build the store, running its migration (idempotent; shared with
    /// [`DbEventDedupStore`]).
    pub fn new(db: Arc<DatabaseManager>) -> Result<Self> {
        db.run_migrations(MIGRATIONS)?;
        Ok(Self { db })
    }
}

#[derive(Queryable)]
struct TransactionIdempotencyRow {
    body_hash: String,
    status: String,
    outcome: Option<String>,
    created_at: i64,
}

impl TransactionIdempotencyStore for DbTransactionIdempotencyStore {
    fn claim(&self, source: &str, key: &str, hash: &str) -> Result<TransactionClaim> {
        use idempotency_schema::transaction_idempotency::dsl;

        let mut conn = self.db.conn()?;
        let now = now_ts();
        diesel::delete(dsl::transaction_idempotency.filter(dsl::expires_at.le(now)))
            .execute(&mut conn)?;

        // Two attempts: a lost insert race re-reads the winner's row once.
        for _ in 0..2 {
            let row = dsl::transaction_idempotency
                .filter(dsl::source_service_did.eq(source))
                .filter(dsl::idempotency_key.eq(key))
                .select((dsl::body_hash, dsl::status, dsl::outcome, dsl::created_at))
                .first::<TransactionIdempotencyRow>(&mut conn)
                .optional()?;
            match row {
                Some(row) if row.body_hash != hash => return Ok(TransactionClaim::Conflict),
                Some(row) if row.status == STATUS_COMPLETED => {
                    let outcome = row.outcome.ok_or_else(|| {
                        BridgeError::Database("completed idempotency record has no outcome".into())
                    })?;
                    let response: AppletTransactionOutcome = serde_json::from_str(&outcome)
                        .map_err(|err| {
                            BridgeError::Database(format!(
                                "recorded transaction outcome is unreadable: {err}"
                            ))
                        })?;
                    return Ok(TransactionClaim::Duplicate(response));
                }
                Some(row) => {
                    // Pending with the same hash. A claim older than the grace
                    // window is presumed crashed mid-flight and taken over;
                    // otherwise ask the server to retry shortly.
                    if row.created_at + PENDING_TAKEOVER_GRACE_SECS <= now {
                        diesel::update(
                            dsl::transaction_idempotency
                                .filter(dsl::source_service_did.eq(source))
                                .filter(dsl::idempotency_key.eq(key)),
                        )
                        .set((
                            dsl::created_at.eq(now),
                            dsl::expires_at.eq(now + IDEMPOTENCY_TTL_SECS),
                        ))
                        .execute(&mut conn)?;
                        return Ok(TransactionClaim::Claimed);
                    }
                    return Ok(TransactionClaim::Pending);
                }
                None => {
                    let inserted = diesel::insert_into(dsl::transaction_idempotency)
                        .values((
                            dsl::source_service_did.eq(source),
                            dsl::idempotency_key.eq(key),
                            dsl::body_hash.eq(hash),
                            dsl::status.eq(STATUS_PENDING),
                            dsl::outcome.eq(None::<String>),
                            dsl::created_at.eq(now),
                            dsl::expires_at.eq(now + IDEMPOTENCY_TTL_SECS),
                        ))
                        .execute(&mut conn);
                    match inserted {
                        Ok(_) => return Ok(TransactionClaim::Claimed),
                        Err(diesel::result::Error::DatabaseError(
                            diesel::result::DatabaseErrorKind::UniqueViolation,
                            _,
                        )) => continue,
                        Err(err) => return Err(err.into()),
                    }
                }
            }
        }
        // Lost the insert race twice in a row; let the server retry.
        Ok(TransactionClaim::Pending)
    }

    fn record(
        &self,
        source: &str,
        key: &str,
        hash: &str,
        response: &AppletTransactionOutcome,
    ) -> Result<()> {
        use idempotency_schema::transaction_idempotency::dsl;

        let outcome = serde_json::to_string(response)
            .map_err(|err| BridgeError::Database(format!("serialize outcome: {err}")))?;
        let mut conn = self.db.conn()?;
        diesel::update(
            dsl::transaction_idempotency
                .filter(dsl::source_service_did.eq(source))
                .filter(dsl::idempotency_key.eq(key))
                .filter(dsl::body_hash.eq(hash)),
        )
        .set((
            dsl::status.eq(STATUS_COMPLETED),
            dsl::outcome.eq(Some(outcome)),
            dsl::expires_at.eq(now_ts() + IDEMPOTENCY_TTL_SECS),
        ))
        .execute(&mut conn)?;
        Ok(())
    }

    fn release(&self, source: &str, key: &str, hash: &str) -> Result<()> {
        use idempotency_schema::transaction_idempotency::dsl;

        let mut conn = self.db.conn()?;
        diesel::delete(
            dsl::transaction_idempotency
                .filter(dsl::source_service_did.eq(source))
                .filter(dsl::idempotency_key.eq(key))
                .filter(dsl::body_hash.eq(hash))
                .filter(dsl::status.eq(STATUS_PENDING)),
        )
        .execute(&mut conn)?;
        Ok(())
    }
}

/// Diesel-backed [`EventDedupStore`]: persists `event_id -> fingerprint` so
/// single-event dedup (applet-integration §7.3) survives restarts and is not
/// bounded by an in-memory window.
pub struct DbEventDedupStore {
    db: Arc<DatabaseManager>,
}

impl DbEventDedupStore {
    /// Build the store, running its migration (idempotent; shared with
    /// [`DbTransactionIdempotencyStore`]).
    pub fn new(db: Arc<DatabaseManager>) -> Result<Self> {
        db.run_migrations(MIGRATIONS)?;
        Ok(Self { db })
    }
}

impl EventDedupStore for DbEventDedupStore {
    fn check_and_record(&self, event_id: &str, fingerprint: i64) -> Result<DedupVerdict> {
        use idempotency_schema::event_dedup::dsl;

        let mut conn = self.db.conn()?;
        let now = now_ts();
        diesel::delete(dsl::event_dedup.filter(dsl::expires_at.le(now))).execute(&mut conn)?;

        for _ in 0..2 {
            let seen = dsl::event_dedup
                .filter(dsl::event_id.eq(event_id))
                .select(dsl::fingerprint)
                .first::<i64>(&mut conn)
                .optional()?;
            match seen {
                Some(prev) if prev == fingerprint => {
                    return Ok(DedupVerdict::DuplicateSameContent);
                }
                Some(_) => return Ok(DedupVerdict::DuplicateConflict),
                None => {
                    let inserted = diesel::insert_into(dsl::event_dedup)
                        .values((
                            dsl::event_id.eq(event_id),
                            dsl::fingerprint.eq(fingerprint),
                            dsl::expires_at.eq(now + IDEMPOTENCY_TTL_SECS),
                        ))
                        .execute(&mut conn);
                    match inserted {
                        Ok(_) => return Ok(DedupVerdict::Fresh),
                        Err(diesel::result::Error::DatabaseError(
                            diesel::result::DatabaseErrorKind::UniqueViolation,
                            _,
                        )) => continue,
                        Err(err) => return Err(err.into()),
                    }
                }
            }
        }
        // Lost the insert race twice: another writer recorded the id; treat the
        // mismatch case conservatively as a same-content duplicate is wrong, so
        // re-read once more and fall back to conflict on persistent absence.
        let seen = {
            use idempotency_schema::event_dedup::dsl;
            dsl::event_dedup
                .filter(dsl::event_id.eq(event_id))
                .select(dsl::fingerprint)
                .first::<i64>(&mut conn)
                .optional()?
        };
        Ok(match seen {
            Some(prev) if prev == fingerprint => DedupVerdict::DuplicateSameContent,
            _ => DedupVerdict::DuplicateConflict,
        })
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;

    fn memory_db() -> Arc<DatabaseManager> {
        Arc::new(
            DatabaseManager::connect(&DatabaseConfig {
                url: "sqlite://:memory:".to_owned(),
                pool_size: 1,
            })
            .unwrap(),
        )
    }

    #[test]
    fn db_idempotency_claim_record_replay() {
        let store = DbTransactionIdempotencyStore::new(memory_db()).unwrap();
        assert!(matches!(
            store.claim("did:web:server.example", "idem-1", "hash-a"),
            Ok(TransactionClaim::Claimed)
        ));
        assert!(matches!(
            store.claim("did:web:server.example", "idem-1", "hash-a"),
            Ok(TransactionClaim::Pending)
        ));
        assert!(matches!(
            store.claim("did:web:server.example", "idem-1", "hash-b"),
            Ok(TransactionClaim::Conflict)
        ));

        let response = AppletTransactionOutcome {
            ok: true,
            rejected: Vec::new(),
            retry_after_ms: None,
        };
        store
            .record("did:web:server.example", "idem-1", "hash-a", &response)
            .unwrap();
        match store.claim("did:web:server.example", "idem-1", "hash-a") {
            Ok(TransactionClaim::Duplicate(cached)) => assert!(cached.ok),
            _ => panic!("expected duplicate replay"),
        }
    }

    #[test]
    fn db_idempotency_release_allows_retry() {
        let store = DbTransactionIdempotencyStore::new(memory_db()).unwrap();
        assert!(matches!(
            store.claim("did:web:server.example", "idem-2", "hash-a"),
            Ok(TransactionClaim::Claimed)
        ));
        store
            .release("did:web:server.example", "idem-2", "hash-a")
            .unwrap();
        assert!(matches!(
            store.claim("did:web:server.example", "idem-2", "hash-a"),
            Ok(TransactionClaim::Claimed)
        ));
    }

    #[test]
    fn db_event_dedup_verdicts() {
        let store = DbEventDedupStore::new(memory_db()).unwrap();
        assert!(matches!(
            store.check_and_record("ev1", 100),
            Ok(DedupVerdict::Fresh)
        ));
        assert!(matches!(
            store.check_and_record("ev1", 100),
            Ok(DedupVerdict::DuplicateSameContent)
        ));
        assert!(matches!(
            store.check_and_record("ev1", 200),
            Ok(DedupVerdict::DuplicateConflict)
        ));
        assert!(matches!(
            store.check_and_record("ev2", 100),
            Ok(DedupVerdict::Fresh)
        ));
    }
}
