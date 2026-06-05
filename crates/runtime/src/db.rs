//! Generic database access (diesel + r2d2). Defaults to sqlite; features can
//! switch to postgres/mysql.
//!
//! The core only owns the connection pool and a generic migration runner.
//! Domain-specific tables (e.g. the room/message/user mappings used by the
//! messaging layer) are defined and migrated by the layer that needs them,
//! via [`DatabaseManager::run_migrations`]. This keeps the core free of any
//! chat/messaging assumptions so it can back non-social bridges too.

use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};

use crate::config::DatabaseConfig;
use crate::error::{BridgeError, Result};

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

    /// Run a batch of idempotent DDL statements (e.g.
    /// `CREATE TABLE IF NOT EXISTS ...`). In production you can switch to
    /// diesel_migrations.
    pub fn run_migrations(&self, statements: &[&str]) -> Result<()> {
        let mut conn = self.conn()?;
        for stmt in statements {
            diesel::sql_query(*stmt)
                .execute(&mut conn)
                .map_err(|e| BridgeError::Database(e.to_string()))?;
        }
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
