//! Store layer error type.

use thiserror::Error;

/// Errors raised by the persistence layer.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error("migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error(transparent)]
    Core(#[from] ioc_vault_core::CoreError),

    #[error("failed to (de)serialize JSON column: {0}")]
    Json(#[from] serde_json::Error),

    #[error("data integrity error: {0}")]
    Integrity(String),
}

/// Convenience result alias for the store layer.
pub type Result<T> = std::result::Result<T, StoreError>;
