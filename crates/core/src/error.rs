//! Unified error type.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, BridgeError>;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("cokret protocol error: {0}")]
    Cokret(String),

    #[error("app adapter error: {0}")]
    App(String),

    #[error("runtime error: {0}")]
    Runtime(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<cokret::Error> for BridgeError {
    fn from(e: cokret::Error) -> Self {
        BridgeError::Cokret(e.to_string())
    }
}

impl From<cokret::identifiers::IdentifierError> for BridgeError {
    fn from(e: cokret::identifiers::IdentifierError) -> Self {
        BridgeError::Cokret(e.to_string())
    }
}

impl From<diesel::result::Error> for BridgeError {
    fn from(e: diesel::result::Error) -> Self {
        BridgeError::Database(e.to_string())
    }
}

impl From<diesel::r2d2::PoolError> for BridgeError {
    fn from(e: diesel::r2d2::PoolError) -> Self {
        BridgeError::Database(e.to_string())
    }
}
