//! Generic database access (diesel + r2d2). Defaults to sqlite; features can
//! switch to postgres/mysql.
//!
//! The core only owns the connection pool and a generic migration runner.
//! Domain-specific tables (e.g. the channel/realm/message/user mappings used
//! by the messaging layer) are defined and migrated by the layer that needs
//! them, via [`DatabaseManager::run_migrations`]. This keeps the core free of
//! any chat/messaging assumptions so it can back non-social bridges too.

use std::sync::Arc;

use cokret::models::AppletTransactionOutcome;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

use crate::cache::{PersistedToken, TokenStore};
use crate::config::DatabaseConfig;
use crate::error::{BridgeError, Result};
use crate::idempotency::{
    DedupVerdict, EventDedupStore, IDEMPOTENCY_TTL_SECS, PENDING_TAKEOVER_GRACE_SECS,
    ReplayGuardStore, TransactionClaim, TransactionIdempotencyStore, TransactionReplayKey,
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
// persist transaction ids for idempotency and deduplicate external events).
// These replace the former process-local caches so restarts and TTL expiry no
// longer turn server retries into duplicate deliveries.
// ---------------------------------------------------------------------------

mod idempotency_schema {
    diesel::table! {
        /// Transaction-level idempotency records, keyed by
        /// `(operation_id, direction, source_service_did, destination_service_did, Idempotency-Key)`.
        transaction_idempotency (
            operation_id,
            direction,
            source_service_did,
            destination_service_did,
            idempotency_key
        ) {
            operation_id -> Text,
            direction -> Text,
            source_service_did -> Text,
            destination_service_did -> Text,
            idempotency_key -> Text,
            body_hash -> Text,
            source_signature_anchor -> Text,
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

    diesel::table! {
        /// Public-webhook replay guard window (bridge contract G-4): one row per
        /// accepted replay key, TTL-cleaned via `expires_at`.
        webhook_replay_guard (replay_key) {
            replay_key -> Text,
            expires_at -> BigInt,
        }
    }

    diesel::table! {
        /// Vendor OAuth access-token cache, shared across replicas so
        /// "fetching a new token invalidates the old one" platforms (WeChat)
        /// stay consistent under horizontal scaling.
        token_cache (cache_key) {
            cache_key -> Text,
            token_value -> Text,
            expires_at -> BigInt,
        }
    }
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

const STATUS_PENDING: &str = "pending";
const STATUS_COMPLETED: &str = "completed";

/// Diesel-backed [`TransactionIdempotencyStore`]: persists the channel-specific
/// replay identity plus `(body_hash, source_signature_anchor, outcome)` so
/// transaction
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
    source_signature_anchor: String,
    status: String,
    outcome: Option<String>,
    created_at: i64,
}

impl TransactionIdempotencyStore for DbTransactionIdempotencyStore {
    fn claim(
        &self,
        replay: &TransactionReplayKey<'_>,
        hash: &str,
        source_signature_anchor: &str,
    ) -> Result<TransactionClaim> {
        use idempotency_schema::transaction_idempotency::dsl;

        let mut conn = self.db.conn()?;
        let now = now_ts();
        diesel::delete(dsl::transaction_idempotency.filter(dsl::expires_at.le(now)))
            .execute(&mut conn)?;

        // Two attempts: a lost insert race re-reads the winner's row once.
        for _ in 0..2 {
            let row = dsl::transaction_idempotency
                .filter(dsl::operation_id.eq(replay.operation_id))
                .filter(dsl::direction.eq(replay.direction))
                .filter(dsl::source_service_did.eq(replay.source_service_did))
                .filter(dsl::destination_service_did.eq(replay.destination_service_did))
                .filter(dsl::idempotency_key.eq(replay.idempotency_key))
                .select((
                    dsl::body_hash,
                    dsl::source_signature_anchor,
                    dsl::status,
                    dsl::outcome,
                    dsl::created_at,
                ))
                .first::<TransactionIdempotencyRow>(&mut conn)
                .optional()?;
            match row {
                Some(row)
                    if row.body_hash != hash
                        || row.source_signature_anchor != source_signature_anchor =>
                {
                    return Ok(TransactionClaim::Conflict);
                }
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
                                .filter(dsl::operation_id.eq(replay.operation_id))
                                .filter(dsl::direction.eq(replay.direction))
                                .filter(dsl::source_service_did.eq(replay.source_service_did))
                                .filter(
                                    dsl::destination_service_did.eq(replay.destination_service_did),
                                )
                                .filter(dsl::idempotency_key.eq(replay.idempotency_key)),
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
                            dsl::operation_id.eq(replay.operation_id),
                            dsl::direction.eq(replay.direction),
                            dsl::source_service_did.eq(replay.source_service_did),
                            dsl::destination_service_did.eq(replay.destination_service_did),
                            dsl::idempotency_key.eq(replay.idempotency_key),
                            dsl::body_hash.eq(hash),
                            dsl::source_signature_anchor.eq(source_signature_anchor),
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
        replay: &TransactionReplayKey<'_>,
        hash: &str,
        source_signature_anchor: &str,
        response: &AppletTransactionOutcome,
    ) -> Result<()> {
        use idempotency_schema::transaction_idempotency::dsl;

        let outcome = serde_json::to_string(response)
            .map_err(|err| BridgeError::Database(format!("serialize outcome: {err}")))?;
        let mut conn = self.db.conn()?;
        diesel::update(
            dsl::transaction_idempotency
                .filter(dsl::operation_id.eq(replay.operation_id))
                .filter(dsl::direction.eq(replay.direction))
                .filter(dsl::source_service_did.eq(replay.source_service_did))
                .filter(dsl::destination_service_did.eq(replay.destination_service_did))
                .filter(dsl::idempotency_key.eq(replay.idempotency_key))
                .filter(dsl::body_hash.eq(hash))
                .filter(dsl::source_signature_anchor.eq(source_signature_anchor)),
        )
        .set((
            dsl::status.eq(STATUS_COMPLETED),
            dsl::outcome.eq(Some(outcome)),
            dsl::expires_at.eq(now_ts() + IDEMPOTENCY_TTL_SECS),
        ))
        .execute(&mut conn)?;
        Ok(())
    }

    fn release(
        &self,
        replay: &TransactionReplayKey<'_>,
        hash: &str,
        source_signature_anchor: &str,
    ) -> Result<()> {
        use idempotency_schema::transaction_idempotency::dsl;

        let mut conn = self.db.conn()?;
        diesel::delete(
            dsl::transaction_idempotency
                .filter(dsl::operation_id.eq(replay.operation_id))
                .filter(dsl::direction.eq(replay.direction))
                .filter(dsl::source_service_did.eq(replay.source_service_did))
                .filter(dsl::destination_service_did.eq(replay.destination_service_did))
                .filter(dsl::idempotency_key.eq(replay.idempotency_key))
                .filter(dsl::body_hash.eq(hash))
                .filter(dsl::source_signature_anchor.eq(source_signature_anchor))
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

/// Diesel-backed [`ReplayGuardStore`]: persists webhook replay keys so the
/// bounded replay/dedupe guard (bridge contract G-4) survives restarts and is
/// shared across horizontally scaled replicas.
pub struct DbReplayGuardStore {
    db: Arc<DatabaseManager>,
}

impl DbReplayGuardStore {
    /// Build the store. The `webhook_replay_guard` table is created by the
    /// runtime migrations, which [`crate::run_bridge`] applies at startup (via
    /// [`crate::DbSeqStore::new`]); standalone hosts and tests must run
    /// [`MIGRATIONS`] themselves.
    pub fn new(db: Arc<DatabaseManager>) -> Self {
        Self { db }
    }
}

impl ReplayGuardStore for DbReplayGuardStore {
    fn contains(&self, key: &str) -> Result<bool> {
        use idempotency_schema::webhook_replay_guard::dsl;

        let mut conn = self.db.conn()?;
        let now = now_ts();
        diesel::delete(dsl::webhook_replay_guard.filter(dsl::expires_at.le(now)))
            .execute(&mut conn)?;
        let seen = dsl::webhook_replay_guard
            .filter(dsl::replay_key.eq(key))
            .select(dsl::replay_key)
            .first::<String>(&mut conn)
            .optional()?;
        Ok(seen.is_some())
    }

    fn check_and_record(&self, key: &str, ttl_secs: i64) -> Result<bool> {
        use idempotency_schema::webhook_replay_guard::dsl;

        let mut conn = self.db.conn()?;
        let now = now_ts();
        diesel::delete(dsl::webhook_replay_guard.filter(dsl::expires_at.le(now)))
            .execute(&mut conn)?;
        let inserted = diesel::insert_into(dsl::webhook_replay_guard)
            .values((dsl::replay_key.eq(key), dsl::expires_at.eq(now + ttl_secs)))
            .execute(&mut conn);
        match inserted {
            Ok(_) => Ok(true),
            // A concurrent writer (another replica) won the insert race, or the
            // key is already present: either way this delivery is a replay.
            Err(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => Ok(false),
            Err(err) => Err(err.into()),
        }
    }

    fn forget(&self, key: &str) -> Result<()> {
        use idempotency_schema::webhook_replay_guard::dsl;

        let mut conn = self.db.conn()?;
        diesel::delete(dsl::webhook_replay_guard.filter(dsl::replay_key.eq(key)))
            .execute(&mut conn)?;
        Ok(())
    }
}

/// Diesel-backed [`TokenStore`]: persists vendor access tokens so replicas of
/// the same bridge share one token (required by "new token invalidates the old
/// one" vendors such as WeChat) and a restart does not force a refetch.
pub struct DbTokenStore {
    db: Arc<DatabaseManager>,
}

impl DbTokenStore {
    /// Build the store. The `token_cache` table is created by the runtime
    /// migrations, which [`crate::run_bridge`] applies at startup (via
    /// [`crate::DbSeqStore::new`]); standalone hosts and tests must run
    /// [`MIGRATIONS`] themselves.
    pub fn new(db: Arc<DatabaseManager>) -> Self {
        Self { db }
    }
}

impl TokenStore for DbTokenStore {
    fn load(&self, key: &str) -> Result<Option<PersistedToken>> {
        use idempotency_schema::token_cache::dsl;

        let mut conn = self.db.conn()?;
        let row = dsl::token_cache
            .filter(dsl::cache_key.eq(key))
            .select((dsl::token_value, dsl::expires_at))
            .first::<(String, i64)>(&mut conn)
            .optional()?;
        Ok(row.map(|(value, expires_at)| PersistedToken { value, expires_at }))
    }

    fn store(&self, key: &str, token: &str, expires_at: i64) -> Result<()> {
        use idempotency_schema::token_cache::dsl;

        let mut conn = self.db.conn()?;
        // Backend-agnostic upsert: delete + insert, last write wins (matching
        // the vendor semantics where the newest fetched token is the live one).
        // A lost insert race means a concurrent refresh already stored a newer
        // token, which is exactly the value the next read should observe.
        diesel::delete(dsl::token_cache.filter(dsl::cache_key.eq(key))).execute(&mut conn)?;
        let inserted = diesel::insert_into(dsl::token_cache)
            .values((
                dsl::cache_key.eq(key),
                dsl::token_value.eq(token),
                dsl::expires_at.eq(expires_at),
            ))
            .execute(&mut conn);
        match inserted {
            Ok(_) => Ok(()),
            Err(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => Ok(()),
            Err(err) => Err(err.into()),
        }
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

    fn replay_key(idempotency_key: &str) -> TransactionReplayKey<'_> {
        replay_key_to("did:webvh:bridge.example", idempotency_key)
    }

    fn replay_key_to<'a>(
        destination_service_did: &'a str,
        idempotency_key: &'a str,
    ) -> TransactionReplayKey<'a> {
        TransactionReplayKey {
            operation_id: "ck.edge.applet.command.transaction",
            direction: "node_to_applet",
            source_service_did: "did:webvh:server.example",
            destination_service_did,
            idempotency_key,
        }
    }

    #[test]
    fn db_idempotency_claim_record_replay() {
        let store = DbTransactionIdempotencyStore::new(memory_db()).unwrap();
        assert!(matches!(
            store.claim(&replay_key("idem-1"), "hash-a", "anchor-a"),
            Ok(TransactionClaim::Claimed)
        ));
        assert!(matches!(
            store.claim(&replay_key("idem-1"), "hash-a", "anchor-a"),
            Ok(TransactionClaim::Pending)
        ));
        assert!(matches!(
            store.claim(&replay_key("idem-1"), "hash-b", "anchor-a"),
            Ok(TransactionClaim::Conflict)
        ));

        let response = AppletTransactionOutcome {
            ok: true,
            rejected: Vec::new(),
            retry_after_ms: None,
        };
        store
            .record(&replay_key("idem-1"), "hash-a", "anchor-a", &response)
            .unwrap();
        match store.claim(&replay_key("idem-1"), "hash-a", "anchor-a") {
            Ok(TransactionClaim::Duplicate(cached)) => assert!(cached.ok),
            _ => panic!("expected duplicate replay"),
        }
    }

    #[test]
    fn db_idempotency_release_allows_retry() {
        let store = DbTransactionIdempotencyStore::new(memory_db()).unwrap();
        assert!(matches!(
            store.claim(&replay_key("idem-2"), "hash-a", "anchor-a"),
            Ok(TransactionClaim::Claimed)
        ));
        store
            .release(&replay_key("idem-2"), "hash-a", "anchor-a")
            .unwrap();
        assert!(matches!(
            store.claim(&replay_key("idem-2"), "hash-a", "anchor-a"),
            Ok(TransactionClaim::Claimed)
        ));
    }

    #[test]
    fn db_idempotency_binds_replay_to_anchor_and_destination() {
        let store = DbTransactionIdempotencyStore::new(memory_db()).unwrap();
        assert!(matches!(
            store.claim(&replay_key("idem-3"), "hash-a", "anchor-a"),
            Ok(TransactionClaim::Claimed)
        ));
        assert!(matches!(
            store.claim(&replay_key("idem-3"), "hash-a", "anchor-b"),
            Ok(TransactionClaim::Conflict)
        ));
        assert!(matches!(
            store.claim(
                &replay_key_to("did:webvh:other-bridge.example", "idem-3"),
                "hash-a",
                "anchor-b"
            ),
            Ok(TransactionClaim::Claimed)
        ));
    }

    #[test]
    fn db_replay_guard_rejects_duplicate_and_expires() {
        let db = memory_db();
        db.run_migrations(MIGRATIONS).unwrap();
        let store = DbReplayGuardStore::new(db);
        assert!(!store.contains("k1").unwrap());
        assert!(store.check_and_record("k1", 600).unwrap());
        assert!(store.contains("k1").unwrap());
        assert!(!store.check_and_record("k1", 600).unwrap());
        // An already-expired row is purged on the next probe.
        assert!(store.check_and_record("k2", -1).unwrap());
        assert!(!store.contains("k2").unwrap());
        assert!(store.check_and_record("k2", 600).unwrap());
        assert!(store.check_and_record("k3", 600).unwrap());
        assert!(store.contains("k3").unwrap());
        store.forget("k3").unwrap();
        assert!(!store.contains("k3").unwrap());
        assert!(store.check_and_record("k3", 600).unwrap());
    }

    #[test]
    fn db_token_store_last_write_wins() {
        let db = memory_db();
        db.run_migrations(MIGRATIONS).unwrap();
        let store = DbTokenStore::new(db);
        assert!(store.load("wechat_access_token").unwrap().is_none());
        store.store("wechat_access_token", "tok-1", 100).unwrap();
        store.store("wechat_access_token", "tok-2", 200).unwrap();
        let token = store.load("wechat_access_token").unwrap().unwrap();
        assert_eq!(token.value, "tok-2");
        assert_eq!(token.expires_at, 200);
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
