//! `seadog-core` — shared data + logic layer for the seadog ephemeral
//! test-environment provisioner.
//!
//! Phase 1a is the **data layer only**: models, config parsing, the
//! SQLite store, and atomic vmid/IP allocation. Business logic
//! (identity triangulation, the kento bridge, validation, the reaper,
//! notifications) is Phase 1b and lives in modules added later.
//!
//! ## Conventions
//! - **JSON-ready**: every user-facing entity derives
//!   `serde::Serialize`/`Deserialize`.
//! - **Timestamps** are `i64` unix epoch seconds throughout.
//! - **Injected clock**: any logic whose behavior depends on "now" takes
//!   `now_unix: i64` explicitly rather than reading the system clock, so
//!   tests can control time. [`now_unix`] is the thin real-clock helper
//!   for callers.

pub mod alloc;
pub mod config;
pub mod identity;
pub mod kento;
pub mod models;
pub mod notify;
pub mod reap;
pub mod store;
pub mod validate;

pub use config::Config;
pub use models::{Env, EnvStatus, Mode, NotifyState};

use thiserror::Error as ThisError;

/// The crate-wide error type.
#[derive(Debug, ThisError)]
pub enum Error {
    /// Reading or parsing the YAML config failed.
    #[error("config error: {0}")]
    Config(String),

    /// The parsed config violated a semantic invariant.
    #[error("config validation error: {0}")]
    ConfigValidation(String),

    /// A SQLite/storage-layer operation failed.
    #[error("store error: {0}")]
    Store(String),

    /// A required row was absent.
    #[error("not found: {0}")]
    NotFound(String),

    /// The vmid range or IP pool had no free slot.
    #[error("resource exhausted: {0}")]
    Exhausted(String),

    /// Caller-supplied input failed validation (bad vmid, name, image).
    #[error("validation error: {0}")]
    Validation(String),

    /// A `kento`/runtime-bridge operation failed (spawn, exec, timeout).
    #[error("kento error: {0}")]
    Kento(String),

    /// The pmxcfs quorum was lost / the cluster filesystem is read-only.
    /// Surfaced (not retried) so sweeps stop cleanly instead of spinning.
    #[error("quorum lost: {0}")]
    QuorumLost(String),

    /// A raw rusqlite error (connection, SQL, type conversion).
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Real "now" as unix epoch seconds. Thin helper for callers; logic that
/// tests must control should take `now_unix: i64` instead of calling
/// this.
pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
