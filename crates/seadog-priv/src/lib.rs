//! Library face of `seadog-priv`, exposing the reaper entry points so they
//! can be exercised end-to-end from integration tests with a primed
//! [`FakeKento`](seadog_core::kento::FakeKento) against a temp DB — without
//! a real PVE host.
//!
//! The binary (`main.rs`) keeps the privilege-sensitive verb dispatch
//! (provision/teardown/…) to itself; only the DB-touching reaper modules
//! (`sweep`/`watch`) and the small DB test fixtures live here, since those
//! are what the integration suite drives.

pub mod sweep;
pub mod watch;

/// Reusable DB fixtures for tests (unit + integration). Always compiled so
/// the integration crate can seed a DB exactly the way the unit tests do.
pub mod fixtures;
