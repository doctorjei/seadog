//! `seadog-priv sweep` — the **one-shot** reaper pass.
//!
//! This is the 60-minute systemd-timer backstop target: systemd runs it
//! directly as root. The timer serializes sweep-vs-sweep, but NOT
//! sweep-vs-watcher — so the one-shot now takes the **same watcher flock**
//! ([`crate::watch::lock_path`]) before sweeping, so it never races a
//! concurrent watcher reap (the cross-process race that produced spurious
//! `VmidReuse` anomalies during a watcher's mid-teardown window). If the
//! watcher holds the lock but its heartbeat is stale (older than 3× the
//! fast cadence ⇒ the watcher is dead/wedged), the sweep overrides and runs
//! anyway WITHOUT the lock — preserving the failure-domain-diverse backstop
//! (a wedged watcher must never be able to stop reaping). It opens the DB,
//! calls the shared [`core::reap::sweep`](seadog_core::reap::sweep) **once**
//! (which writes the heartbeat + routes every reap/flag/heads-up), prunes
//! terminal rows past the retention window, and prints the [`SweepOutcome`]
//! as JSON.
//!
//! All reaping logic lives in `core::reap` — this module is a thin
//! DB-open-and-wiring shell, so there is zero version-skew with the watch
//! loop, which calls the exact same `core::reap::sweep`.

use std::path::Path;

use anyhow::{anyhow, Result};
use rusqlite::Connection;
use serde_json::{json, Value};

use seadog_core::config::Config;
use seadog_core::kento::Kento;
use seadog_core::reap::{sweep as core_sweep, SweepOutcome};
use seadog_core::store;

use crate::watch;
use crate::watch::LockOutcome;

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

/// The `sweep` entry point used by `main`: open the DB, then run the
/// flock-gated sweep. `now_unix` is injected (prod passes wall-clock `now`).
pub fn run(kento: &dyn Kento, config: &Config, now_unix: i64) -> Result<Value> {
    let conn = open_db()?;
    run_gated(&conn, kento, config, now_unix, &watch::lock_path())
}

/// Run the one-shot sweep under the watcher flock so it never races a
/// concurrent watcher reap.
///
/// - **Lock free** → acquire it, run the sweep while holding it (so a
///   watcher starting mid-sweep can't race), then release.
/// - **Lock held by a watcher** → decide via heartbeat staleness:
///   - **Fresh** (`Some(t)` and `now - t <= 3× fast cadence`) → a healthy
///     watcher is actively reaping; SKIP (return a zero result tagged
///     `skipped`), do NOT sweep.
///   - **Stale or never-run** (`None`, or `now - t >` threshold) → the
///     watcher is dead/wedged; the failure-domain-diverse backstop must run,
///     so sweep anyway WITHOUT the lock (it's held by the wedged watcher) and
///     tag the result `overrode_stale_watcher`.
pub fn run_gated(
    conn: &Connection,
    kento: &dyn Kento,
    config: &Config,
    now_unix: i64,
    lock_path: &Path,
) -> Result<Value> {
    match watch::acquire_lock(lock_path)? {
        LockOutcome::Acquired(lock) => {
            // Hold the lock for the whole sweep so a watcher starting
            // mid-sweep can't race us.
            let v = run_with_db(conn, kento, config, now_unix)?;
            drop(lock);
            Ok(v)
        }
        LockOutcome::AlreadyHeld => {
            // A watcher process holds the lock. Decide via heartbeat
            // staleness whether to skip (healthy watcher) or override
            // (dead/wedged watcher).
            let threshold = 3 * config.cadence.fast.as_secs() as i64;
            let hb = store::read_heartbeat(conn)?;
            let fresh = matches!(hb, Some(t) if now_unix - t <= threshold);
            if fresh {
                // Healthy watcher actively reaping — don't double-reap.
                Ok(skipped_json("watcher active"))
            } else {
                // Stale or never-run heartbeat ⇒ wedged watcher. The
                // backstop runs anyway, without holding the lock (it's held
                // by the wedged watcher).
                let mut v = run_with_db(conn, kento, config, now_unix)?;
                v["overrode_stale_watcher"] = json!(true);
                Ok(v)
            }
        }
    }
}

/// A zero-valued SWEEP result tagged with why we skipped. A superset of the
/// normal [`outcome_json`] schema so existing JSON consumers don't break.
fn skipped_json(reason: &str) -> Value {
    json!({
        "ok": true,
        "reaped": 0,
        "flagged": 0,
        "heads_up": 0,
        "deferred": 0,
        "vanished": 0,
        "pruned": 0,
        "quorum_lost": null,
        "skipped": reason,
    })
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

    /// A unique temp dir under the system tempdir (no external deps),
    /// mirroring `watch.rs`'s test helper.
    fn tempdir() -> std::path::PathBuf {
        let base = std::env::temp_dir();
        let unique = format!(
            "seadog-sweep-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = base.join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn gated_reaps_when_lock_is_free() {
        let cfg = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "g1", 10010, now - 3600, now - 100);
        let k = FakeKento::new();
        k.set_guests(vec![signals_for(&conn, "g1", 10010)]);

        let path = tempdir().join("watcher.lock");
        let v = run_gated(&conn, &k, &cfg, now, &path).unwrap();
        assert_eq!(v["reaped"], 1);
        assert_eq!(k.teardowns().len(), 1);
    }

    #[test]
    fn gated_skips_when_watcher_holds_lock_and_heartbeat_fresh() {
        let cfg = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;

        let path = tempdir().join("watcher.lock");
        // A "watcher" holds the lock for the duration of this test.
        let _held = match watch::acquire_lock(&path).unwrap() {
            LockOutcome::Acquired(l) => l,
            LockOutcome::AlreadyHeld => panic!("lock should be free"),
        };
        // Fresh heartbeat ⇒ healthy watcher.
        store::write_heartbeat(&conn, now).unwrap();

        insert_active(&conn, "g1", 10010, now - 3600, now - 100);
        let k = FakeKento::new();
        k.set_guests(vec![signals_for(&conn, "g1", 10010)]);

        let v = run_gated(&conn, &k, &cfg, now, &path).unwrap();
        // Skipped: no reap, no teardown — the live watcher owns reaping.
        assert!(v.get("skipped").is_some());
        assert_eq!(v["reaped"], 0);
        assert!(k.teardowns().is_empty());
    }

    #[test]
    fn gated_overrides_when_lock_held_but_heartbeat_stale() {
        let cfg = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;

        let path = tempdir().join("watcher.lock");
        // A wedged "watcher" still holds the lock...
        let _held = match watch::acquire_lock(&path).unwrap() {
            LockOutcome::Acquired(l) => l,
            LockOutcome::AlreadyHeld => panic!("lock should be free"),
        };
        // ...but its heartbeat is stale (way past 3× the fast cadence).
        store::write_heartbeat(&conn, now - 10_000).unwrap();

        insert_active(&conn, "g1", 10010, now - 3600, now - 100);
        let k = FakeKento::new();
        k.set_guests(vec![signals_for(&conn, "g1", 10010)]);

        let v = run_gated(&conn, &k, &cfg, now, &path).unwrap();
        // Backstop overrode the wedged watcher and reaped.
        assert_eq!(v["reaped"], 1);
        assert_eq!(k.teardowns().len(), 1);
        assert_eq!(v["overrode_stale_watcher"], true);
    }
}
