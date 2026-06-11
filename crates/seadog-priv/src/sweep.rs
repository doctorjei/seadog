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
//! (which writes the heartbeat + routes every reap/flag/re-adoption), prunes
//! terminal rows past the retention window, and prints the [`SweepOutcome`]
//! as JSON.
//!
//! All reaping logic lives in `core::reap` — this module is a thin
//! DB-open-and-wiring shell, so there is zero version-skew with the watch
//! loop, which calls the exact same `core::reap::sweep`.

use std::os::unix::fs::PermissionsExt;
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

/// The front-end's run-as user — the DB's intended owner. Matches
/// `deploy/rpm/post.sh`'s `USER_NAME` (the install contract).
const DB_OWNER_USER: &str = "testenv";
/// The shared group on `/var/lib/seadog`. Matches `deploy/rpm/post.sh`'s
/// `GROUP_NAME` (the setgid group the front-end belongs to).
const DB_OWNER_GROUP: &str = "seadog";

/// Resolve the DB path (`$SEADOG_DB` override, else the default) and open
/// (or create) it. This is seadog-priv's first DB access — the deadlines
/// and heartbeat live here.
///
/// After the open/migration (which may run as root — e.g. a manual `sweep`
/// or the `watch` loop), [`normalize_db_perms`] restores `testenv:seadog`
/// `0664` on the DB so the unprivileged front-end can always write it.
pub fn open_db() -> Result<Connection> {
    let path = std::env::var("SEADOG_DB").unwrap_or_else(|_| DEFAULT_DB.to_string());
    let conn = store::open(&path).map_err(|e| anyhow!("opening seadog DB {path}: {e}"))?;
    normalize_db_perms(&path);
    Ok(conn)
}

/// Restore `testenv:seadog` ownership and mode `0664` on the DB file and its
/// `-wal`/`-shm` sidecars after a root-invoked open/migration, so the
/// unprivileged front-end (the `testenv` user, group `seadog`) can always
/// write it.
///
/// This closes a footgun: a **manual root** DB-touching invocation (e.g. a
/// 0.5→0.7 schema migration run by hand) leaves the DB `root:seadog 0644`,
/// after which the front-end hits "readonly database" because group `seadog`
/// only has read. The automated systemd sweeper avoids it (umask 0002 +
/// setgid dir), but any root-run open re-trips it — so we re-assert the
/// intended perms here regardless of caller. Root keeps access either way.
///
/// Purely best-effort and non-fatal: if `testenv`/`seadog` don't resolve
/// (dev boxes, tests) we skip; a non-root caller EPERMs on the `chown` and
/// that's fine. Every failure is debug-logged and ignored — never propagated.
fn normalize_db_perms(path: &str) {
    use std::ffi::CString;

    // Resolve the target uid/gid by name; either missing ⇒ no-op (this is
    // what makes it inert on dev boxes / in tests with no such accounts).
    let user_c = match CString::new(DB_OWNER_USER) {
        Ok(c) => c,
        Err(_) => return,
    };
    let group_c = match CString::new(DB_OWNER_GROUP) {
        Ok(c) => c,
        Err(_) => return,
    };
    let pw = unsafe { libc::getpwnam(user_c.as_ptr()) };
    if pw.is_null() {
        tracing::debug!("normalize_db_perms: user '{DB_OWNER_USER}' not found, skipping");
        return;
    }
    let gr = unsafe { libc::getgrnam(group_c.as_ptr()) };
    if gr.is_null() {
        tracing::debug!("normalize_db_perms: group '{DB_OWNER_GROUP}' not found, skipping");
        return;
    }
    let uid = unsafe { (*pw).pw_uid };
    let gid = unsafe { (*gr).gr_gid };

    // The DB plus the WAL/SHM sidecars SQLite leaves alongside it.
    for p in [
        path.to_string(),
        format!("{path}-wal"),
        format!("{path}-shm"),
    ] {
        if !Path::new(&p).exists() {
            continue;
        }
        let c_path = match CString::new(p.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // Best-effort chown; a non-root caller EPERMs here (expected/fine).
        let rc = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
        if rc != 0 {
            tracing::debug!(
                "normalize_db_perms: chown {DB_OWNER_USER}:{DB_OWNER_GROUP} on {p} skipped: {}",
                std::io::Error::last_os_error()
            );
        }
        if let Err(e) = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o664)) {
            tracing::debug!("normalize_db_perms: set mode 0664 on {p} skipped: {e}");
        }
    }
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
        "readopted": 0,
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
        "readopted": outcome.readopted,
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
        k.set_instances(vec![signals_for(&conn, "g1", 10010)]);

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

    /// `normalize_db_perms` is best-effort: against a real temp file run as a
    /// non-root caller it must never panic/error — it silently no-ops because
    /// either the `testenv`/`seadog` lookup fails or the `chown` EPERMs. We
    /// assert only that it returns and the file survives (no ownership check —
    /// the test box has no `testenv` user).
    #[test]
    fn normalize_db_perms_is_best_effort_noop() {
        let dir = tempdir();
        let db = dir.join("seadog.db");
        std::fs::write(&db, b"not-really-a-db").unwrap();
        let path = db.to_str().unwrap();

        // Must return without panicking and leave the file intact.
        normalize_db_perms(path);
        assert!(db.exists());
    }

    #[test]
    fn gated_reaps_when_lock_is_free() {
        let cfg = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "g1", 10010, now - 3600, now - 100);
        let k = FakeKento::new();
        k.set_instances(vec![signals_for(&conn, "g1", 10010)]);

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
        k.set_instances(vec![signals_for(&conn, "g1", 10010)]);

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
        k.set_instances(vec![signals_for(&conn, "g1", 10010)]);

        let v = run_gated(&conn, &k, &cfg, now, &path).unwrap();
        // Backstop overrode the wedged watcher and reaped.
        assert_eq!(v["reaped"], 1);
        assert_eq!(k.teardowns().len(), 1);
        assert_eq!(v["overrode_stale_watcher"], true);
    }
}
