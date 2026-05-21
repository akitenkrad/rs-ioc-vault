//! Core domain error type.

use thiserror::Error;

/// Errors raised by the core domain layer (normalization, parsing, validation).
#[derive(Debug, Error)]
pub enum CoreError {
    /// The raw value could not be normalized for the given [`crate::IocType`].
    #[error("failed to normalize {ioc_type} value {value:?}: {reason}")]
    Normalize {
        ioc_type: crate::IocType,
        value: String,
        reason: String,
    },

    /// An enum value (TLP, IoC type, ...) was not recognized.
    #[error("unknown {kind} variant: {value:?}")]
    UnknownVariant { kind: &'static str, value: String },
}

/// Convenience result alias for the core layer.
pub type Result<T> = std::result::Result<T, CoreError>;
