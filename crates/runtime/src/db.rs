//! Generic database access through Horme query leases. Defaults to sqlite; features can
//! switch to postgres.
//!
//! The core only owns the connection pool and a generic migration runner.
//! Domain-specific tables (e.g. the channel/realm/message/user mappings used
//! by the messaging layer) are defined and migrated by the layer that needs
//! them, via [`DatabaseManager::run_migrations`]. This keeps the core free of
//! any chat/messaging assumptions so it can back non-social bridges too.

use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use arkret::{IdempotencyIdentity, TransactionClaim, TransactionIdempotencyStore};
use arkret_models_integration::AppletTransactionResponseBody;
use diesel::prelude::*;
use diesel_async::SimpleAsyncConnection;
#[cfg(feature = "sqlite")]
use diesel_async::sync_connection_wrapper::SyncConnectionWrapper;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};
#[cfg(any(feature = "sqlite", test))]
use horme::GetConnection;
use horme::pool::AsyncDieselConnectionManager;
use horme::pool::deadpool::Pool;
use horme::{OptionalExtension, RunQueryDsl};

use crate::cache::{PersistedToken, TokenStore};
use crate::config::DatabaseConfig;
use crate::dead_letter::{OutboundDeadLetter, OutboundDeadLetterRecord, OutboundDeadLetterStore};
use crate::error::{BridgeError, Result};
use crate::idempotency::{
    DedupVerdict, EventDedupStore, IDEMPOTENCY_TTL_SECS, PENDING_TAKEOVER_GRACE_SECS,
    ReplayGuardStore, ReplayGuardVerdict,
};

/// Embedded migrations for the runtime-owned tables (`transaction_idempotency`,
/// `event_dedup`, `authoring_journal`). The SQL uses the common subset supported by
/// SQLite and PostgreSQL, so every backend embeds the same migration.
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

/// Synchronous backend used for migrations and wrapped async execution.
#[cfg(feature = "sqlite")]
pub type DbConnection = diesel::SqliteConnection;
#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
pub type DbConnection = diesel::PgConnection;

#[cfg(feature = "sqlite")]
type AsyncDbConnection = SyncConnectionWrapper<DbConnection>;
#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
type AsyncDbConnection = diesel_async::AsyncPgConnection;
pub type DbPool = Pool<AsyncDbConnection>;
pub type DbConn = horme::Db<DbPool>;

/// Pool and executor for the SDK's synchronous persistence contracts.
pub struct DatabaseManager {
    pool: DbPool,
    runtime: &'static tokio::runtime::Runtime,
    #[cfg(all(feature = "postgres", not(feature = "sqlite")))]
    database_url: String,
}

static DATABASE_RUNTIME: OnceLock<std::io::Result<tokio::runtime::Runtime>> = OnceLock::new();

impl DatabaseManager {
    /// Build an async pool without leasing a connection.
    pub fn connect(cfg: &DatabaseConfig) -> Result<Self> {
        let runtime = DATABASE_RUNTIME
            .get_or_init(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_name("bridge-database")
                    .enable_all()
                    .build()
            })
            .as_ref()
            .map_err(|error| BridgeError::Database(error.to_string()))?;
        let url = normalize_url(&cfg.url);
        let manager = AsyncDieselConnectionManager::<AsyncDbConnection>::new(url.clone());
        let budget = Duration::from_secs(5);
        let pool = Pool::builder(manager)
            .max_size(cfg.pool_size as usize)
            .wait_timeout(Some(budget))
            .create_timeout(Some(budget))
            .recycle_timeout(Some(budget))
            .runtime(deadpool::Runtime::Tokio1)
            .post_create(horme::pool::deadpool::Hook::async_fn(|conn: &mut AsyncDbConnection, _| Box::pin(async move {
                #[cfg(feature = "sqlite")]
                let sql = "PRAGMA busy_timeout = 5000;";
                #[cfg(all(feature = "postgres", not(feature = "sqlite")))]
                let sql = "SET statement_timeout = '30s'; SET lock_timeout = '5s'; SET idle_in_transaction_session_timeout = '60s';";
                conn.batch_execute(sql).await.map_err(|error| {
                    horme::pool::deadpool::HookError::Backend(diesel_async::pooled_connection::PoolError::QueryError(error))
                })?;
                Ok(())
            })))
            .build()
            .map_err(|error| BridgeError::Database(error.to_string()))?;
        Ok(Self {
            pool,
            runtime,
            #[cfg(all(feature = "postgres", not(feature = "sqlite")))]
            database_url: url,
        })
    }

    /// Each buffered query leases independently from this handle.
    pub fn queries(&self) -> DbConn {
        horme::Db::new(self.pool.clone())
    }

    /// Drive a synchronous persistence operation without nesting Tokio runtimes.
    /// Async bridge callers already dispatch these contracts via `run_blocking`.
    pub fn block_on<F: Future + Send>(&self, future: F) -> F::Output
    where
        F::Output: Send,
    {
        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::scope(|scope| {
                scope
                    .spawn(|| self.runtime.block_on(future))
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
        } else {
            self.runtime.block_on(future)
        }
    }

    /// Apply the caller's migrations on a deliberately scoped physical lease.
    pub fn run_migrations(&self, migrations: EmbeddedMigrations) -> Result<()> {
        #[cfg(feature = "sqlite")]
        {
            self.block_on(async {
                let mut db = self.queries();
                let mut lease = db.get_mut_conn().await?;
                lease
                    .spawn_blocking(move |connection| {
                        connection
                            .run_pending_migrations(migrations)
                            .map(|_| ())
                            .map_err(diesel::result::Error::QueryBuilderError)
                    })
                    .await?;
                Ok(())
            })
        }
        #[cfg(all(feature = "postgres", not(feature = "sqlite")))]
        {
            let url = bounded_postgres_url(&self.database_url)?;
            self.block_on(async {
                tokio::task::spawn_blocking(move || {
                    use diesel::Connection;
                    let mut connection = diesel::PgConnection::establish(&url)
                        .map_err(|error| BridgeError::Database(error.to_string()))?;
                    connection
                        .run_pending_migrations(migrations)
                        .map(|_| ())
                        .map_err(|error| BridgeError::Database(error.to_string()))
                })
                .await
                .map_err(|error| BridgeError::Database(error.to_string()))?
            })
        }
    }

    pub fn cleanup_expired_runtime_rows(&self) -> Result<usize> {
        self.block_on(async {
            let mut db = self.queries();
            let now = now_ts();
            db.transaction(async |conn| {
                let mut deleted = 0;
                deleted += diesel::delete(
                    idempotency_schema::transaction_idempotency::table
                        .filter(idempotency_schema::transaction_idempotency::expires_at.le(now)),
                )
                .execute(conn)
                .await?;
                deleted += diesel::delete(
                    idempotency_schema::event_dedup::table
                        .filter(idempotency_schema::event_dedup::expires_at.le(now)),
                )
                .execute(conn)
                .await?;
                deleted += diesel::delete(
                    idempotency_schema::webhook_replay_guard::table
                        .filter(idempotency_schema::webhook_replay_guard::expires_at.le(now)),
                )
                .execute(conn)
                .await?;
                deleted += diesel::delete(
                    idempotency_schema::token_cache::table
                        .filter(idempotency_schema::token_cache::expires_at.le(now)),
                )
                .execute(conn)
                .await?;
                Ok::<_, horme::Error>(deleted)
            })
            .await
            .map_err(Into::into)
        })
    }
}

#[cfg(all(test, feature = "postgres", not(feature = "sqlite")))]
mod wait_bound_tests {
    use super::*;

    #[test]
    fn postgres_sessions_bound_lock_wait_and_preserve_pool_capacity() {
        let database_url =
            std::env::var("BRIDGES_TEST_DATABASE_URL").expect("isolated test database required");
        let db = DatabaseManager::connect(&DatabaseConfig {
            url: database_url,
            pool_size: 2,
        })
        .unwrap();
        db.block_on(async {
        let mut first_db = db.queries();
        let mut second_db = db.queries();
        let mut first = first_db.get_mut_conn().await.unwrap();
        let mut second = second_db.get_mut_conn().await.unwrap();
        let bounded: bool = diesel::select(diesel::dsl::sql::<diesel::sql_types::Bool>(
            "current_setting('statement_timeout')::interval = interval '30 seconds' AND current_setting('lock_timeout')::interval = interval '5 seconds'",
        ))
        .get_result(&mut *second).await
        .unwrap();
        assert!(bounded);
        first
            .batch_execute("BEGIN; SELECT pg_advisory_xact_lock(876543210);")
            .await
            .unwrap();
        let start = std::time::Instant::now();
        let result = second.batch_execute("SELECT pg_advisory_xact_lock(876543210)").await;
        first.batch_execute("ROLLBACK").await.unwrap();
        assert!(result.is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(7));
        drop(second);
        assert!(second_db.get_mut_conn().await.is_ok());
        });
    }
}

/// Normalize `sqlite://path` into the plain path diesel sqlite accepts; other
/// URLs are returned unchanged.
#[cfg(all(feature = "postgres", not(feature = "sqlite")))]
fn bounded_postgres_url(raw: &str) -> Result<String> {
    let mut url = url::Url::parse(raw)
        .map_err(|_| BridgeError::Config("PostgreSQL database URL is invalid".into()))?;
    let pairs: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| {
            !matches!(
                key.as_ref(),
                "connect_timeout"
                    | "keepalives"
                    | "keepalives_idle"
                    | "keepalives_interval"
                    | "keepalives_count"
                    | "tcp_user_timeout"
            )
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    url.set_query(None);
    url.query_pairs_mut().extend_pairs(pairs).extend_pairs([
        ("connect_timeout", "5"),
        ("keepalives", "1"),
        ("keepalives_idle", "5"),
        ("keepalives_interval", "1"),
        ("keepalives_count", "3"),
        ("tcp_user_timeout", "5000"),
    ]);
    Ok(url.into())
}

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
        /// `(operation_id, direction, source_id, destination_id, Idempotency-Key)`.
        transaction_idempotency (
            operation_id,
            direction,
            source_id,
            destination_id,
            idempotency_key
        ) {
            operation_id -> Text,
            direction -> Text,
            source_id -> Text,
            destination_id -> Text,
            idempotency_key -> Text,
            body_hash -> Text,
            delivery_authentication_record_digest -> Text,
            status -> Text,
            outcome -> Nullable<Text>,
            expires_at -> BigInt,
            created_at -> BigInt,
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

    diesel::table! {
        /// Durable dead letters for arkret-to-app delivery failures.
        outbound_dead_letters (event_id) {
            event_id -> Text,
            realm_id -> Text,
            kind -> Text,
            attempts -> Integer,
            retriable -> Bool,
            last_error -> Text,
            event_json -> Text,
            first_seen_at -> BigInt,
            updated_at -> BigInt,
        }
    }
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

const STATUS_PENDING: &str = "pending";
const STATUS_COMPLETED: &str = "completed";

/// Diesel-backed [`TransactionIdempotencyStore`]: persists the channel-specific
/// replay identity plus `(body_hash, delivery_authentication_record_digest, outcome)` so
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
    delivery_authentication_record_digest: String,
    status: String,
    outcome: Option<String>,
    created_at: i64,
}

impl TransactionIdempotencyStore<AppletTransactionResponseBody> for DbTransactionIdempotencyStore {
    type Error = BridgeError;

    fn claim(
        &self,
        replay: &IdempotencyIdentity,
        hash: &str,
        delivery_authentication_record_digest: &str,
    ) -> Result<TransactionClaim<AppletTransactionResponseBody>> {
        self.db.block_on(async {
            use idempotency_schema::transaction_idempotency::dsl;

            let mut conn = self.db.queries();
            let now = now_ts();
            // Two attempts: a lost insert race re-reads the winner's row once.
            for _ in 0..2 {
                let row = dsl::transaction_idempotency
                    .filter(dsl::operation_id.eq(&replay.operation_id))
                    .filter(dsl::direction.eq(replay.direction.as_str()))
                    .filter(dsl::source_id.eq(replay.source_id.as_str()))
                    .filter(dsl::destination_id.eq(replay.destination_id.as_str()))
                    .filter(dsl::idempotency_key.eq(&replay.idempotency_key))
                    .select((
                        dsl::body_hash,
                        dsl::delivery_authentication_record_digest,
                        dsl::status,
                        dsl::outcome,
                        dsl::created_at,
                    ))
                    .first::<TransactionIdempotencyRow>(&mut conn)
                    .await
                    .optional()?;
                match row {
                    Some(row)
                        if row.body_hash != hash
                            || row.delivery_authentication_record_digest
                                != delivery_authentication_record_digest =>
                    {
                        return Ok(TransactionClaim::Conflict);
                    }
                    Some(row) if row.status == STATUS_COMPLETED => {
                        let outcome = row.outcome.ok_or_else(|| {
                            BridgeError::Database(
                                "completed idempotency record has no outcome".into(),
                            )
                        })?;
                        let response: AppletTransactionResponseBody =
                            serde_json::from_str(&outcome).map_err(|err| {
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
                            let claimed = diesel::update(
                                dsl::transaction_idempotency
                                    .filter(dsl::operation_id.eq(&replay.operation_id))
                                    .filter(dsl::direction.eq(replay.direction.as_str()))
                                    .filter(dsl::source_id.eq(replay.source_id.as_str()))
                                    .filter(dsl::destination_id.eq(replay.destination_id.as_str()))
                                    .filter(dsl::idempotency_key.eq(&replay.idempotency_key))
                                    .filter(dsl::status.eq(STATUS_PENDING))
                                    .filter(dsl::created_at.eq(row.created_at)),
                            )
                            .set((
                                dsl::created_at.eq(now),
                                dsl::expires_at.eq(now + IDEMPOTENCY_TTL_SECS),
                            ))
                            .execute(&mut conn)
                            .await?;
                            if claimed == 1 {
                                return Ok(TransactionClaim::Claimed);
                            }
                            continue;
                        }
                        return Ok(TransactionClaim::Pending);
                    }
                    None => {
                        let inserted = diesel::insert_into(dsl::transaction_idempotency)
                            .values((
                                dsl::operation_id.eq(&replay.operation_id),
                                dsl::direction.eq(replay.direction.as_str()),
                                dsl::source_id.eq(replay.source_id.as_str()),
                                dsl::destination_id.eq(replay.destination_id.as_str()),
                                dsl::idempotency_key.eq(&replay.idempotency_key),
                                dsl::body_hash.eq(hash),
                                dsl::delivery_authentication_record_digest
                                    .eq(delivery_authentication_record_digest),
                                dsl::status.eq(STATUS_PENDING),
                                dsl::outcome.eq(None::<String>),
                                dsl::created_at.eq(now),
                                dsl::expires_at.eq(now + IDEMPOTENCY_TTL_SECS),
                            ))
                            .execute(&mut conn)
                            .await;
                        match inserted {
                            Ok(_) => return Ok(TransactionClaim::Claimed),
                            Err(horme::Error::Query(diesel::result::Error::DatabaseError(
                                diesel::result::DatabaseErrorKind::UniqueViolation,
                                _,
                            ))) => continue,
                            Err(err) => return Err(err.into()),
                        }
                    }
                }
            }
            // Lost the insert race twice in a row; let the server retry.
            Ok(TransactionClaim::Pending)
        })
    }

    fn record(
        &self,
        replay: &IdempotencyIdentity,
        hash: &str,
        delivery_authentication_record_digest: &str,
        response: &AppletTransactionResponseBody,
    ) -> Result<()> {
        self.db.block_on(async {
            use idempotency_schema::transaction_idempotency::dsl;

            let outcome = serde_json::to_string(response)
                .map_err(|err| BridgeError::Database(format!("serialize outcome: {err}")))?;
            let mut conn = self.db.queries();
            let updated = diesel::update(
                dsl::transaction_idempotency
                    .filter(dsl::operation_id.eq(&replay.operation_id))
                    .filter(dsl::direction.eq(replay.direction.as_str()))
                    .filter(dsl::source_id.eq(replay.source_id.as_str()))
                    .filter(dsl::destination_id.eq(replay.destination_id.as_str()))
                    .filter(dsl::idempotency_key.eq(&replay.idempotency_key))
                    .filter(dsl::body_hash.eq(hash))
                    .filter(
                        dsl::delivery_authentication_record_digest
                            .eq(delivery_authentication_record_digest),
                    ),
            )
            .set((
                dsl::status.eq(STATUS_COMPLETED),
                dsl::outcome.eq(Some(outcome)),
                dsl::expires_at.eq(now_ts() + IDEMPOTENCY_TTL_SECS),
            ))
            .execute(&mut conn)
            .await?;
            if updated != 1 {
                return Err(BridgeError::Database(
                    "idempotency outcome did not update the exact pending claim".to_owned(),
                ));
            }
            Ok(())
        })
    }

    fn release(
        &self,
        replay: &IdempotencyIdentity,
        hash: &str,
        delivery_authentication_record_digest: &str,
    ) -> Result<()> {
        self.db.block_on(async {
            use idempotency_schema::transaction_idempotency::dsl;

            let mut conn = self.db.queries();
            diesel::delete(
                dsl::transaction_idempotency
                    .filter(dsl::operation_id.eq(&replay.operation_id))
                    .filter(dsl::direction.eq(replay.direction.as_str()))
                    .filter(dsl::source_id.eq(replay.source_id.as_str()))
                    .filter(dsl::destination_id.eq(replay.destination_id.as_str()))
                    .filter(dsl::idempotency_key.eq(&replay.idempotency_key))
                    .filter(dsl::body_hash.eq(hash))
                    .filter(
                        dsl::delivery_authentication_record_digest
                            .eq(delivery_authentication_record_digest),
                    )
                    .filter(dsl::status.eq(STATUS_PENDING)),
            )
            .execute(&mut conn)
            .await?;
            Ok(())
        })
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
        self.db.block_on(async {
            use idempotency_schema::event_dedup::dsl;

            let mut conn = self.db.queries();
            let now = now_ts();
            for _ in 0..2 {
                let seen = dsl::event_dedup
                    .filter(dsl::event_id.eq(event_id))
                    .select(dsl::fingerprint)
                    .first::<i64>(&mut conn)
                    .await
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
                            .execute(&mut conn)
                            .await;
                        match inserted {
                            Ok(_) => return Ok(DedupVerdict::Fresh),
                            Err(horme::Error::Query(diesel::result::Error::DatabaseError(
                                diesel::result::DatabaseErrorKind::UniqueViolation,
                                _,
                            ))) => continue,
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
                    .await
                    .optional()?
            };
            Ok(match seen {
                Some(prev) if prev == fingerprint => DedupVerdict::DuplicateSameContent,
                _ => DedupVerdict::DuplicateConflict,
            })
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
    /// [`crate::DbAuthoringStore::new`]); standalone hosts and tests must run
    /// [`MIGRATIONS`] themselves.
    pub fn new(db: Arc<DatabaseManager>) -> Self {
        Self { db }
    }
}

impl ReplayGuardStore for DbReplayGuardStore {
    fn contains(&self, key: &str) -> Result<bool> {
        self.db.block_on(async {
            use idempotency_schema::webhook_replay_guard::dsl;

            let mut conn = self.db.queries();
            let seen = dsl::webhook_replay_guard
                .filter(dsl::replay_key.eq(key))
                .filter(dsl::expires_at.gt(now_ts()))
                .select(dsl::replay_key)
                .first::<String>(&mut conn)
                .await
                .optional()?;
            Ok(seen.is_some())
        })
    }

    fn check_and_record(&self, key: &str, ttl_secs: i64) -> Result<ReplayGuardVerdict> {
        self.db.block_on(async {
            use idempotency_schema::webhook_replay_guard::dsl;

            let mut conn = self.db.queries();
            let now = now_ts();
            diesel::delete(
                dsl::webhook_replay_guard
                    .filter(dsl::replay_key.eq(key))
                    .filter(dsl::expires_at.le(now)),
            )
            .execute(&mut conn)
            .await?;
            let inserted = diesel::insert_into(dsl::webhook_replay_guard)
                .values((dsl::replay_key.eq(key), dsl::expires_at.eq(now + ttl_secs)))
                .execute(&mut conn)
                .await;
            match inserted {
                Ok(_) => Ok(ReplayGuardVerdict::Fresh),
                // A concurrent writer (another replica) won the insert race, or the
                // key is already present: either way this delivery is a replay.
                Err(horme::Error::Query(diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                ))) => Ok(ReplayGuardVerdict::Replay),
                Err(err) => Err(err.into()),
            }
        })
    }

    fn forget(&self, key: &str) -> Result<()> {
        self.db.block_on(async {
            use idempotency_schema::webhook_replay_guard::dsl;

            let mut conn = self.db.queries();
            diesel::delete(dsl::webhook_replay_guard.filter(dsl::replay_key.eq(key)))
                .execute(&mut conn)
                .await?;
            Ok(())
        })
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
    /// [`crate::DbAuthoringStore::new`]); standalone hosts and tests must run
    /// [`MIGRATIONS`] themselves.
    pub fn new(db: Arc<DatabaseManager>) -> Self {
        Self { db }
    }
}

impl TokenStore for DbTokenStore {
    fn load(&self, key: &str) -> Result<Option<PersistedToken>> {
        self.db.block_on(async {
            use idempotency_schema::token_cache::dsl;

            let mut conn = self.db.queries();
            let row = dsl::token_cache
                .filter(dsl::cache_key.eq(key))
                .select((dsl::token_value, dsl::expires_at))
                .first::<(String, i64)>(&mut conn)
                .await
                .optional()?;
            Ok(row.map(|(value, expires_at)| PersistedToken { value, expires_at }))
        })
    }

    fn store(&self, key: &str, token: &str, expires_at: i64) -> Result<()> {
        self.db.block_on(async {
            use idempotency_schema::token_cache::dsl;

            let mut conn = self.db.queries();
            conn.transaction(async |conn| {
                diesel::delete(dsl::token_cache.filter(dsl::cache_key.eq(key)))
                    .execute(conn)
                    .await?;
                diesel::insert_into(dsl::token_cache)
                    .values((
                        dsl::cache_key.eq(key),
                        dsl::token_value.eq(token),
                        dsl::expires_at.eq(expires_at),
                    ))
                    .execute(conn)
                    .await?;
                Ok::<_, horme::Error>(())
            })
            .await
            .map_err(Into::into)
        })
    }
}

/// Diesel-backed [`OutboundDeadLetterStore`]: persists arkret-to-app events that
/// exhausted adapter delivery retries so they can be replayed after recovery.
pub struct DbOutboundDeadLetterStore {
    db: Arc<DatabaseManager>,
}

impl DbOutboundDeadLetterStore {
    /// Build the store. The `outbound_dead_letters` table is created by the
    /// runtime migrations, which [`crate::run_bridge`] applies at startup (via
    /// [`crate::DbAuthoringStore::new`]); standalone hosts and tests must run
    /// [`MIGRATIONS`] themselves.
    pub fn new(db: Arc<DatabaseManager>) -> Self {
        Self { db }
    }
}

#[derive(Queryable)]
struct OutboundDeadLetterRow {
    event_id: String,
    realm_id: String,
    kind: String,
    attempts: i32,
    retriable: bool,
    last_error: String,
    event_json: String,
    first_seen_at: i64,
    updated_at: i64,
}

impl From<OutboundDeadLetterRow> for OutboundDeadLetter {
    fn from(row: OutboundDeadLetterRow) -> Self {
        Self {
            event_id: row.event_id,
            realm_id: row.realm_id,
            kind: row.kind,
            attempts: row.attempts.max(0) as u32,
            retriable: row.retriable,
            last_error: row.last_error,
            event_json: row.event_json,
            first_seen_at: row.first_seen_at,
            updated_at: row.updated_at,
        }
    }
}

impl OutboundDeadLetterStore for DbOutboundDeadLetterStore {
    fn record(&self, record: OutboundDeadLetterRecord) -> Result<()> {
        self.db.block_on(async {
            use idempotency_schema::outbound_dead_letters::dsl;

            let mut conn = self.db.queries();
            let now = now_ts();
            let new_attempts = i32::try_from(record.attempts).unwrap_or(i32::MAX);
            let previous_attempts = dsl::outbound_dead_letters
                .filter(dsl::event_id.eq(record.event_id.as_str()))
                .select(dsl::attempts)
                .first::<i32>(&mut conn)
                .await
                .optional()?
                .unwrap_or(0);
            let attempts = previous_attempts.saturating_add(new_attempts);
            let updated = diesel::update(
                dsl::outbound_dead_letters.filter(dsl::event_id.eq(record.event_id.as_str())),
            )
            .set((
                dsl::realm_id.eq(record.realm_id.as_str()),
                dsl::kind.eq(record.kind.as_str()),
                dsl::attempts.eq(attempts),
                dsl::retriable.eq(record.retriable),
                dsl::last_error.eq(record.last_error.as_str()),
                dsl::event_json.eq(record.event_json.as_str()),
                dsl::updated_at.eq(now),
            ))
            .execute(&mut conn)
            .await?;
            if updated == 0 {
                diesel::insert_into(dsl::outbound_dead_letters)
                    .values((
                        dsl::event_id.eq(record.event_id.as_str()),
                        dsl::realm_id.eq(record.realm_id.as_str()),
                        dsl::kind.eq(record.kind.as_str()),
                        dsl::attempts.eq(attempts),
                        dsl::retriable.eq(record.retriable),
                        dsl::last_error.eq(record.last_error.as_str()),
                        dsl::event_json.eq(record.event_json.as_str()),
                        dsl::first_seen_at.eq(now),
                        dsl::updated_at.eq(now),
                    ))
                    .execute(&mut conn)
                    .await?;
            }
            Ok(())
        })
    }

    fn clear(&self, event_id: &str) -> Result<()> {
        self.db.block_on(async {
            use idempotency_schema::outbound_dead_letters::dsl;

            let mut conn = self.db.queries();
            diesel::delete(dsl::outbound_dead_letters.filter(dsl::event_id.eq(event_id)))
                .execute(&mut conn)
                .await?;
            Ok(())
        })
    }

    fn load(&self, event_id: &str) -> Result<Option<OutboundDeadLetter>> {
        self.db.block_on(async {
            use idempotency_schema::outbound_dead_letters::dsl;

            let mut conn = self.db.queries();
            dsl::outbound_dead_letters
                .filter(dsl::event_id.eq(event_id))
                .select((
                    dsl::event_id,
                    dsl::realm_id,
                    dsl::kind,
                    dsl::attempts,
                    dsl::retriable,
                    dsl::last_error,
                    dsl::event_json,
                    dsl::first_seen_at,
                    dsl::updated_at,
                ))
                .first::<OutboundDeadLetterRow>(&mut conn)
                .await
                .optional()
                .map(|row| row.map(Into::into))
                .map_err(Into::into)
        })
    }

    fn list_due(&self, now_ts: i64, limit: u32) -> Result<Vec<OutboundDeadLetter>> {
        self.db.block_on(async {
            use idempotency_schema::outbound_dead_letters::dsl;

            let mut conn = self.db.queries();
            dsl::outbound_dead_letters
                .filter(
                    dsl::updated_at
                        .le(now_ts - crate::dead_letter::OUTBOUND_DEAD_LETTER_REPLAY_INTERVAL_SECS),
                )
                .order(dsl::updated_at.asc())
                .limit(i64::from(limit))
                .select((
                    dsl::event_id,
                    dsl::realm_id,
                    dsl::kind,
                    dsl::attempts,
                    dsl::retriable,
                    dsl::last_error,
                    dsl::event_json,
                    dsl::first_seen_at,
                    dsl::updated_at,
                ))
                .load::<OutboundDeadLetterRow>(&mut conn)
                .await
                .map(|rows| rows.into_iter().map(Into::into).collect())
                .map_err(Into::into)
        })
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use arkret::IdempotencyDirection;

    use super::*;

    #[test]
    fn query_handles_release_a_single_connection_and_transaction_rolls_back() {
        let db = memory_db();
        db.block_on(async {
            let mut first = db.queries();
            let mut second = db.queries();
            diesel::sql_query("CREATE TABLE lease_probe (id INTEGER PRIMARY KEY)")
                .execute(&mut first)
                .await
                .unwrap();
            diesel::sql_query("INSERT INTO lease_probe VALUES (1)")
                .execute(&mut second)
                .await
                .unwrap();
            let result = first
                .transaction(async |conn| {
                    diesel::sql_query("INSERT INTO lease_probe VALUES (2)")
                        .execute(conn)
                        .await?;
                    Err::<(), _>(horme::Error::Query(
                        diesel::result::Error::RollbackTransaction,
                    ))
                })
                .await;
            assert!(result.is_err());
            let count: i64 = diesel::select(diesel::dsl::sql::<diesel::sql_types::BigInt>(
                "(SELECT COUNT(*) FROM lease_probe)",
            ))
            .get_result(&mut second)
            .await
            .unwrap();
            assert_eq!(count, 1);
        });
    }

    fn memory_db() -> Arc<DatabaseManager> {
        Arc::new(
            DatabaseManager::connect(&DatabaseConfig {
                url: "sqlite://:memory:".to_owned(),
                pool_size: 1,
            })
            .unwrap(),
        )
    }

    fn replay_key(idempotency_key: &str) -> IdempotencyIdentity {
        replay_key_to("ak:did_core:webvh:bridge", idempotency_key)
    }

    fn replay_key_to(destination_id: &str, idempotency_key: &str) -> IdempotencyIdentity {
        IdempotencyIdentity::applet_transaction(
            IdempotencyDirection::NodeToApplet,
            arkret::DidCoreId::new("ak:did_core:webvh:server").unwrap(),
            arkret::DidCoreId::new(destination_id).unwrap(),
            idempotency_key,
        )
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

        let response = AppletTransactionResponseBody::Accepted {
            committed_event_refs: Vec::new(),
            rejections: Vec::new(),
            retry_after_ms: None,
        };
        store
            .record(&replay_key("idem-1"), "hash-a", "anchor-a", &response)
            .unwrap();
        match store.claim(&replay_key("idem-1"), "hash-a", "anchor-a") {
            Ok(TransactionClaim::Duplicate(cached)) => assert_eq!(
                cached.status(),
                arkret_models_integration::AppletTransactionStatus::Accepted
            ),
            _ => panic!("expected duplicate replay"),
        }
    }

    #[test]
    fn db_idempotency_record_requires_the_exact_pending_claim() {
        let store = DbTransactionIdempotencyStore::new(memory_db()).unwrap();
        let response = AppletTransactionResponseBody::Accepted {
            committed_event_refs: Vec::new(),
            rejections: Vec::new(),
            retry_after_ms: None,
        };
        assert!(
            store
                .record(&replay_key("missing"), "hash-a", "anchor-a", &response)
                .is_err()
        );
    }

    #[test]
    fn db_idempotency_stale_pending_can_resume_without_losing_body_binding() {
        use idempotency_schema::transaction_idempotency::dsl;

        let db = memory_db();
        let store = DbTransactionIdempotencyStore::new(db.clone()).unwrap();
        let replay = replay_key("crash-after-cas");
        assert!(matches!(
            store.claim(&replay, "hash-a", "anchor-a"),
            Ok(TransactionClaim::Claimed)
        ));
        db.block_on(async {
            let mut conn = db.queries();
            diesel::update(
                dsl::transaction_idempotency
                    .filter(dsl::operation_id.eq(&replay.operation_id))
                    .filter(dsl::idempotency_key.eq(&replay.idempotency_key)),
            )
            .set(dsl::created_at.eq(now_ts() - PENDING_TAKEOVER_GRACE_SECS - 1))
            .execute(&mut conn)
            .await
            .unwrap();
            drop(conn);
        });

        assert!(matches!(
            store.claim(&replay, "hash-a", "anchor-a"),
            Ok(TransactionClaim::Claimed)
        ));
        assert!(matches!(
            store.claim(&replay, "hash-b", "anchor-a"),
            Ok(TransactionClaim::Conflict)
        ));
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
                &replay_key_to("ak:did_core:webvh:otherbridge", "idem-3"),
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
        assert_eq!(
            store.check_and_record("k1", 600).unwrap(),
            ReplayGuardVerdict::Fresh
        );
        assert!(store.contains("k1").unwrap());
        assert_eq!(
            store.check_and_record("k1", 600).unwrap(),
            ReplayGuardVerdict::Replay
        );
        // An already-expired row is purged on the next probe.
        assert_eq!(
            store.check_and_record("k2", -1).unwrap(),
            ReplayGuardVerdict::Fresh
        );
        assert!(!store.contains("k2").unwrap());
        assert_eq!(
            store.check_and_record("k2", 600).unwrap(),
            ReplayGuardVerdict::Fresh
        );
        assert_eq!(
            store.check_and_record("k3", 600).unwrap(),
            ReplayGuardVerdict::Fresh
        );
        assert!(store.contains("k3").unwrap());
        store.forget("k3").unwrap();
        assert!(!store.contains("k3").unwrap());
        assert_eq!(
            store.check_and_record("k3", 600).unwrap(),
            ReplayGuardVerdict::Fresh
        );
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

    #[test]
    fn db_outbound_dead_letter_records_updates_lists_and_clears() {
        let db = memory_db();
        db.run_migrations(MIGRATIONS).unwrap();
        let store = DbOutboundDeadLetterStore::new(db);
        store
            .record(OutboundDeadLetterRecord {
                event_id: "ak:event:AZYV_itSkJCtJoO-pBKwQZKbDZWvoTeETPflKYEPv5Lj".to_owned(),
                realm_id: "ak:realm:AWQecQmcKsfSGVm4lyJ7Zfbdg_SWLo-soLmh0S34ECwx".to_owned(),
                kind: "ak.message.create".to_owned(),
                attempts: 4,
                retriable: true,
                last_error: "first failure".to_owned(),
                event_json:
                    r#"{"event_id":"ak:event:AZYV_itSkJCtJoO-pBKwQZKbDZWvoTeETPflKYEPv5Lj"}"#
                        .to_owned(),
            })
            .unwrap();
        let first = store
            .load("ak:event:AZYV_itSkJCtJoO-pBKwQZKbDZWvoTeETPflKYEPv5Lj")
            .unwrap()
            .unwrap();
        assert_eq!(first.attempts, 4);
        assert_eq!(first.last_error, "first failure");

        store
            .record(OutboundDeadLetterRecord {
                event_id: first.event_id.clone(),
                realm_id: first.realm_id.clone(),
                kind: first.kind.clone(),
                attempts: 2,
                retriable: false,
                last_error: "deterministic failure".to_owned(),
                event_json:
                    r#"{"event_id":"ak:event:AZYV_itSkJCtJoO-pBKwQZKbDZWvoTeETPflKYEPv5Lj","retry":2}"#
                        .to_owned(),
            })
            .unwrap();
        let updated = store.load(&first.event_id).unwrap().unwrap();
        assert_eq!(updated.attempts, 6);
        assert!(!updated.retriable);
        assert_eq!(updated.first_seen_at, first.first_seen_at);
        assert_eq!(updated.last_error, "deterministic failure");

        let due = store
            .list_due(
                updated.updated_at + crate::dead_letter::OUTBOUND_DEAD_LETTER_REPLAY_INTERVAL_SECS,
                10,
            )
            .unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].event_id, updated.event_id);

        store.clear(&updated.event_id).unwrap();
        assert!(store.load(&updated.event_id).unwrap().is_none());
    }
}
