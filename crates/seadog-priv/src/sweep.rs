//! `seadog-priv sweep` — the **one-shot** reaper pass.
//!
//! This is the 60-minute systemd-timer backstop target: systemd runs it
//! directly as root, so there is no bridge and no flock (the timer
//! serializes it). It opens the DB, calls the shared
//! [`core::reap::sweep`](seadog_core::reap::sweep) **once** (which writes
//! the heartbeat + routes every reap/flag/heads-up), prunes terminal rows
//! past the retention window, and prints the [`SweepOutcome`] as JSON.
//!
//! All reaping logic lives in `core::reap` — this module is a thin
//! DB-open-and-wiring shell, so there is zero version-skew with the watch
//! loop, which calls the exact same `core::reap::sweep`.

use anyhow::{anyhow, Result};
use rusqlite::Connection;
use serde_json::{json, Value};

use seadog_core::config::Config;
use seadog_core::kento::Kento;
use seadog_core::reap::{sweep as core_sweep, SweepOutcome};
use seadog_core::store;

/// Default DB path; overridable by `$SEADOG_DB` (tests).
pub const DEFAULT_DB: &str = "/var/lib/seadog/seadog.db";

/// Resolve the DB path (`$SEADOG_DB` override, else the default) and open
/// (or create) it. This is seadog-priv's first DB access — the deadlines
/// and heartbeat live here.
pub fn open_db() -> Result<Connection> {
    let path = std::env::var("SEADOG_DB").unwrap_or_else(|_| DEFAULT_DB.to_string());
    store::open(&path).map_err(|e| anyhow!("opening seadog DB {path}: {e}"))
}

/// Run one sweep + prune over an already-open DB, returning the JSON the
/// `sweep` verb prints. Split from [`run`] so tests drive it with an
/// in-memory DB and an injected clock.
///
/// On `quorum_lost`, the outcome is surfaced in the JSON and we still
/// return `Ok` (the verb exits cleanly with no retry — the systemd timer
/// will try again next cycle).
pub fn run_with_db(
    conn: &Connection,
    kento: &dyn Kento,
    config: &Config,
    now_unix: i64,
) -> Result<Value> {
    let outcome = core_sweep(kento, conn, config, now_unix).map_err(anyhow::Error::from)?;

    // Age out only OLD terminal rows; a live overdue row is never pruned.
    let retention = config.retention.terminal.as_secs() as i64;
    let pruned = store::prune_terminal(conn, now_unix, retention).map_err(anyhow::Error::from)?;

    Ok(outcome_json(&outcome, pruned))
}

/// The `sweep` entry point used by `main`: open the DB, sweep once, prune,
/// print JSON. `now_unix` is injected (prod passes wall-clock `now`).
pub fn run(kento: &dyn Kento, config: &Config, now_unix: i64) -> Result<Value> {
    let conn = open_db()?;
    run_with_db(&conn, kento, config, now_unix)
}

/// Render a [`SweepOutcome`] (+ prune count) as the verb's JSON payload.
fn outcome_json(outcome: &SweepOutcome, pruned: usize) -> Value {
    json!({
        "ok": true,
        "reaped": outcome.reaped,
        "flagged": outcome.flagged,
        "heads_up": outcome.heads_up,
        "deferred": outcome.deferred,
        "vanished": outcome.vanished,
        "pruned": pruned,
        "quorum_lost": outcome.quorum_lost,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use seadog_core::kento::FakeKento;
    use seadog_core::store;

    use crate::fixtures::{config, insert_active, signals_for};

    #[test]
    fn one_shot_reaps_expired_and_writes_heartbeat() {
        let cfg = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "g1", 10010, now - 3600, now - 100);
        let k = FakeKento::new();
        k.set_guests(vec![signals_for(&conn, "g1", 10010)]);

        let v = run_with_db(&conn, &k, &cfg, now).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["reaped"], 1);
        assert_eq!(k.teardowns().len(), 1);
        assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(now));
    }

    #[test]
    fn quorum_loss_surfaced_and_returns_clean() {
        let cfg = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        let k = FakeKento::new();
        k.set_quorum_lost("pmxcfs read-only: no quorum");

        let v = run_with_db(&conn, &k, &cfg, now).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["reaped"], 0);
        assert!(v["quorum_lost"].is_string());
        // Heartbeat still stamped so health sees the reaper ran.
        assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(now));
    }
}
