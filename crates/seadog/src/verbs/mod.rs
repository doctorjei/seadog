//! Verb implementations. One module per verb; this file re-exports them
//! and defines the shared [`Ctx`] every verb receives.
//!
//! **DB-only vs. elevated.** `ls`/`show`/`health`/`history`/`stats`/
//! `extend`/`ack` run entirely against `core::store` with no root. `create`
//! and `destroy` need PVE ops, so they route through the [`elevate`]
//! seam (`crate::elevate`) and, in Phase 2a, return the typed
//! "bridge not wired" error.
//!
//! Every verb returns a `serde_json::Value` (or an `anyhow::Error`) which
//! `main` renders as pretty JSON. Logic that needs "now" takes `now_unix`
//! from [`Ctx`] (set once at the top-level call site via
//! `core::now_unix()`), never reading the clock itself.

use rusqlite::Connection;
use seadog_core::Config;

pub mod ack;
pub mod create;
pub mod destroy;
pub mod extend;
pub mod health;
pub mod history;
pub mod ls;
pub mod show;
pub mod stats;

/// Per-invocation context handed to every verb: the trusted owner, the
/// open store connection, the parsed config, and the injected clock.
pub struct Ctx<'a> {
    /// The trusted, sshd-resolved owner this invocation acts as.
    pub owner: String,
    /// Open SQLite connection (already migrated).
    pub conn: &'a Connection,
    /// Parsed config (caps, lifecycle defaults, image allowlist).
    /// Loaded now and validated at startup; consulted by the elevated
    /// `create` path in Phase 2b (cap/image checks), so the front-end
    /// fails fast on a bad config even for DB-only verbs.
    #[allow(dead_code)]
    pub config: &'a Config,
    /// Injected "now" (unix epoch seconds), set once at the call site.
    pub now_unix: i64,
    /// The resolved DB path (same file `conn` is open on). The elevated
    /// `create` path needs a *writable* connection for the atomic
    /// allocate-+-insert (`core::alloc::allocate` takes `&mut Connection`),
    /// which it opens fresh from this path — `conn` is shared (`&`) so it
    /// can't be re-borrowed mutably. WAL makes the second handle safe.
    pub db_path: String,
}
