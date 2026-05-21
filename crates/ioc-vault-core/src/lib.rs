//! Core domain types for `rs-ioc-vault`.
//!
//! This crate is I/O-free: it defines the IoC data model, value normalization,
//! the dedup hash, and the search query model. Higher layers (store, collect,
//! enrich, export) build on these types.

pub mod decay;
pub mod defang;
pub mod error;
pub mod normalize;
pub mod query;
pub mod types;

pub use decay::DecayModel;
pub use defang::{defang, defang_auto, defang_json, is_defanged};
pub use error::{CoreError, Result};
pub use normalize::{normalize, value_hash};
pub use query::{OrderBy, SearchQuery, SearchQueryBuilder, ValueMatcher};
pub use types::{
    IocRecord, IocType, RawIoc, Relationship, Sighting, SourceSighting, Tlp, UpsertStats,
};
