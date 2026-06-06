//! `seadog-priv watch` — the **fast self-extinguishing reaper loop.**
//!
//! Launched once by the unprivileged front-end as
//! `setsid sudo seadog-priv watch` (see `seadog::elevate::spawn_watcher`).
//! It is the failure-domain-diverse partner to the systemd `sweep` timer:
//! while ≥1 env is active it sweeps on the fast cadence; when the system
//! goes idle it self-extinguishes.
//!
//! Two invariants:
//!
//! 1. **At-most-one** — a [`flock`](WatcherLock)`(LOCK_EX | LOCK_NB)` on
//!    `$SEADOG_WATCHER_LOCK` (default `/run/seadog/watcher.lock`) is taken
//!    FIRST. If another watcher already holds it, this process exits 0
//!    immediately. This is the authoritative guard the front-end relies on.
//! 2. **Zero new reaping logic** — every tick calls the shared
//!    [`core::reap::sweep`](seadog_core::reap::sweep), exactly like the
//!    `sweep` one-shot, so there is zero version-skew.
//!
//! The loop body is factored into [`tick`] and [`run_loop`] takes an
//! injectable clock + iteration bound + sleep hook so the zero-env exit and
//! the quorum-loss non-spin are unit-testable without sleeping 60s.

use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};
use rusqlite::Connection;
use serde_json::{json, Value};

use seadog_core::config::Config;
use seadog_core::kento::Kento;
use seadog_core::models::EnvStatus;
use seadog_core::reap::sweep as core_sweep;
use seadog_core::store;

use crate::sweep::open_db;

/// Default watcher flock path; overridable by `$SEADOG_WATCHER_LOCK`. MUST
/// match `seadog::elevate`'s default (the front-end pre-checks the same
/// path) — keep these in sync.
pub const DEFAULT_WATCHER_LOCK: &str = "/run/seadog/watcher.lock";

/// An advisory `flock(LOCK_EX)` held for the watcher's lifetime. Dropping it
/// (process exit, or explicit drop) releases the lock — a fresh watcher can
/// then acquire it. The owned fd keeps the lock alive.
pub struct WatcherLock {
    _fd: OwnedFd,
}

/// The result of trying to acquire the singleton lock.
pub enum LockOutcome {
    /// We hold the lock; proceed to run the loop.
    Acquired(WatcherLock),
    /// Another watcher already holds it; this process must exit 0.
    AlreadyHeld,
}

/// Resolve the flock path (`$SEADOG_WATCHER_LOCK` override, else default).
pub fn lock_path() -> PathBuf {
    std::env::var_os("SEADOG_WATCHER_LOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WATCHER_LOCK))
}

/// Open `path` and take a non-blocking exclusive `flock`.
///
/// - The parent dir is created best-effort (prod: `/run/seadog`).
/// - `LOCK_EX | LOCK_NB`: if another process holds it we get `EWOULDBLOCK`
///   and return [`LockOutcome::AlreadyHeld`] (the caller exits 0) rather
///   than blocking.
/// - On success the [`WatcherLock`] owns the fd; the lock lives until it is
///   dropped.
pub fn acquire_lock(path: &Path) -> Result<LockOutcome> {
    if let Some(parent) = path.parent() {
        // Best-effort: a missing /run/seadog shouldn't be fatal if the path
        // itself is openable, but normally we create it.
        let _ = std::fs::create_dir_all(parent);
    }

    // Open (create) the lock file. We keep the fd in an OwnedFd so the
    // advisory lock is tied to the fd's lifetime.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| anyhow!("opening watcher lock {}: {e}", path.display()))?;
    let fd: OwnedFd = file.into();

    // SAFETY: fd is a valid open file descriptor owned by `fd`.
    let rc = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(LockOutcome::Acquired(WatcherLock { _fd: fd }));
    }

    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
            Ok(LockOutcome::AlreadyHeld)
        }
        _ => Err(anyhow!("flock on watcher lock {}: {err}", path.display())),
    }
}

/// Count the envs that still hold a live lease (`Active`). The loop
/// self-extinguishes when this is zero.
fn active_env_count(conn: &Connection) -> Result<usize> {
    let envs = store::list_by_status(conn, EnvStatus::Active).map_err(anyhow::Error::from)?;
    Ok(envs.len())
}

/// One loop iteration: run the shared sweep (writes heartbeat + reaps),
/// then report the post-sweep active-env count and the outcome's
/// quorum-loss flag. Factored out so tests can drive a single tick without
/// the loop driver.
///
/// Returns `(active_after, quorum_lost)`.
pub fn tick(
    conn: &Connection,
    kento: &dyn Kento,
    config: &Config,
    now_unix: i64,
) -> Result<TickResult> {
    let outcome = core_sweep(kento, conn, config, now_unix).map_err(anyhow::Error::from)?;
    let active_after = active_env_count(conn)?;
    Ok(TickResult {
        active_after,
        quorum_lost: outcome.quorum_lost,
        reaped: outcome.reaped,
    })
}

/// What one [`tick`] observed, for the loop driver + tests.
#[derive(Debug, Clone)]
pub struct TickResult {
    /// Envs still `Active` after the sweep — zero ⇒ self-extinguish.
    pub active_after: usize,
    /// Set when the sweep aborted on a quorum loss.
    pub quorum_lost: Option<String>,
    /// Envs reaped this tick (for the summary).
    pub reaped: u32,
}

/// Why the watch loop stopped, for the JSON summary + tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// No `Active` envs remain — the loop self-extinguished.
    Idle,
    /// The injected iteration bound was hit (tests; never in prod where the
    /// bound is `None`).
    MaxIterations,
}

/// The watch loop's result, printed as JSON and asserted in tests.
#[derive(Debug, Clone)]
pub struct LoopSummary {
    /// Total sweeps run.
    pub ticks: u32,
    /// Total envs reaped across all ticks.
    pub reaped: u32,
    /// Why the loop stopped.
    pub stop: StopReason,
    /// The last quorum-loss message seen, if any (the loop continued on the
    /// normal cadence rather than tight-spinning).
    pub quorum_lost: Option<String>,
}

/// Drive the watch loop over an already-open DB.
///
/// - `now_fn` is the injectable clock (prod: wall-clock seconds); called
///   once per tick so a test can advance time deterministically.
/// - `max_iterations`: `Some(n)` bounds the loop to `n` ticks (tests);
///   `None` runs until idle (prod).
/// - `sleep_fn` is the inter-tick delay hook; prod sleeps `cadence.fast`,
///   tests pass a no-op. It is **skipped** entirely when `cadence.fast` is
///   zero, so a test can also disable sleeping via config.
///
/// Self-extinguish: after each tick, if the active-env count is zero we
/// release (return) immediately. On quorum loss we do **not** tight-spin —
/// we record it and continue on the normal cadence (the bound still applies
/// in tests). The flock is released when the caller drops the
/// [`WatcherLock`].
pub fn run_loop<C, S>(
    conn: &Connection,
    kento: &dyn Kento,
    config: &Config,
    mut now_fn: C,
    max_iterations: Option<u32>,
    mut sleep_fn: S,
) -> Result<LoopSummary>
where
    C: FnMut() -> i64,
    S: FnMut(Duration),
{
    let mut ticks = 0u32;
    let mut reaped = 0u32;
    let mut quorum_lost = None;

    loop {
        if let Some(max) = max_iterations {
            if ticks >= max {
                return Ok(LoopSummary {
                    ticks,
                    reaped,
                    stop: StopReason::MaxIterations,
                    quorum_lost,
                });
            }
        }

        let now = now_fn();
        let result = tick(conn, kento, config, now)?;
        ticks += 1;
        reaped += result.reaped;
        if result.quorum_lost.is_some() {
            quorum_lost = result.quorum_lost.clone();
        }

        // Self-extinguish when idle: no live leases left to watch.
        if result.active_after == 0 {
            return Ok(LoopSummary {
                ticks,
                reaped,
                stop: StopReason::Idle,
                quorum_lost,
            });
        }

        // Otherwise sleep the fast cadence and loop. A zero cadence (tests)
        // skips the sleep entirely; quorum loss does NOT shorten it (no
        // tight-spin) — we just continue on the normal interval.
        let fast = config.cadence.fast;
        if !fast.is_zero() {
            sleep_fn(fast);
        }
    }
}

/// The `watch` entry point used by `main`.
///
/// Acquires the flock singleton FIRST (exit 0 if already held), opens the
/// DB, then runs the loop until idle. `now_fn` is injected so it stays
/// consistent with the rest of the wiring; prod passes wall-clock seconds,
/// `None` bound (run until idle), and a real `std::thread::sleep`.
pub fn run(kento: &dyn Kento, config: &Config) -> Result<Value> {
    let path = lock_path();
    let _lock = match acquire_lock(&path)? {
        LockOutcome::Acquired(l) => l,
        LockOutcome::AlreadyHeld => {
            // A watcher is already running — exit 0 cleanly, no sweep.
            return Ok(json!({
                "ok": true,
                "watcher": "already-running",
                "lock": path.display().to_string(),
            }));
        }
    };

    let conn = open_db()?;
    let summary = run_loop(&conn, kento, config, wall_clock_now, None, |d| {
        std::thread::sleep(d)
    })?;

    Ok(summary_json(&summary))
}

/// Wall-clock seconds since the unix epoch (prod clock).
fn wall_clock_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Render a [`LoopSummary`] as the verb's JSON payload.
fn summary_json(summary: &LoopSummary) -> Value {
    let stop = match summary.stop {
        StopReason::Idle => "idle",
        StopReason::MaxIterations => "max-iterations",
    };
    json!({
        "ok": true,
        "watcher": "ran",
        "ticks": summary.ticks,
        "reaped": summary.reaped,
        "stop": stop,
        "quorum_lost": summary.quorum_lost,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    use seadog_core::kento::FakeKento;
    use seadog_core::store;

    use crate::fixtures::{config, insert_active, signals_for};

    /// A config with a ZERO fast cadence so the loop never sleeps in tests.
    fn nosleep_config() -> Config {
        let mut c = config();
        c.cadence.fast = Duration::ZERO;
        c
    }

    fn never_sleep(_d: Duration) {
        panic!("loop must not sleep in these tests (cadence.fast = 0)");
    }

    #[test]
    fn acquire_then_second_attempt_is_already_held() {
        let dir = tempdir();
        let path = dir.join("watcher.lock");

        let first = acquire_lock(&path).unwrap();
        assert!(matches!(first, LockOutcome::Acquired(_)));

        // A second attempt on the same path, while the first is held, must
        // report AlreadyHeld (no double-start).
        match acquire_lock(&path).unwrap() {
            LockOutcome::AlreadyHeld => {}
            LockOutcome::Acquired(_) => panic!("second acquire should have been blocked"),
        }

        // Releasing the first lets a new one acquire.
        drop(first);
        match acquire_lock(&path).unwrap() {
            LockOutcome::Acquired(_) => {}
            LockOutcome::AlreadyHeld => panic!("lock should be free after release"),
        }
    }

    #[test]
    fn zero_env_exits_after_one_tick() {
        let cfg = nosleep_config();
        let conn = store::open_in_memory().unwrap();
        let k = FakeKento::new();
        let now = 1_000_000i64;

        let summary = run_loop(&conn, &k, &cfg, || now, Some(10), never_sleep).unwrap();
        // No active envs ⇒ self-extinguish on the very first tick.
        assert_eq!(summary.ticks, 1);
        assert_eq!(summary.stop, StopReason::Idle);
        assert_eq!(summary.reaped, 0);
        // Heartbeat written by the shared sweep even with nothing to reap.
        assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(now));
    }

    #[test]
    fn one_reap_then_idle_exits() {
        let cfg = nosleep_config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        // One expired+unanimous env.
        insert_active(&conn, "g1", 10010, now - 3600, now - 100);
        let k = FakeKento::new();
        k.set_instances(vec![signals_for(&conn, "g1", 10010)]);

        let summary = run_loop(&conn, &k, &cfg, || now, Some(10), never_sleep).unwrap();
        // First tick reaps it; the post-sweep active count is then zero ⇒
        // exit. So exactly one tick, one reap.
        assert_eq!(summary.ticks, 1);
        assert_eq!(summary.reaped, 1);
        assert_eq!(summary.stop, StopReason::Idle);
        assert_eq!(
            k.teardowns(),
            vec![(
                "seadog-alice-p-g1".to_string(),
                seadog_core::models::Mode::Vm
            )]
        );
        assert_eq!(
            store::get_env(&conn, "g1").unwrap().unwrap().status,
            EnvStatus::Reaped
        );
    }

    #[test]
    fn quorum_loss_does_not_tight_spin() {
        let cfg = nosleep_config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        // An active env keeps the loop from self-extinguishing, so the
        // bound is what stops it — proving it neither exits on idle nor
        // tight-spins past the bound.
        insert_active(&conn, "g1", 10010, now - 3600, now + 10_000);
        let k = FakeKento::new();
        k.set_quorum_lost("pmxcfs read-only: no quorum");

        // Count how many times the sleep hook is invoked: under quorum loss
        // the loop must still go through the normal (here zero) cadence and
        // honor the bound, not busy-loop unbounded.
        let summary = run_loop(&conn, &k, &cfg, || now, Some(3), never_sleep).unwrap();
        assert_eq!(summary.stop, StopReason::MaxIterations);
        assert_eq!(summary.ticks, 3, "bounded, not unbounded spin");
        assert!(summary.quorum_lost.is_some());
        // Nothing reaped (sweep aborted on quorum loss each tick).
        assert_eq!(summary.reaped, 0);
        // Heartbeat still stamped.
        assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(now));
    }

    #[test]
    fn sleep_hook_runs_on_nonzero_cadence_between_ticks() {
        // With a non-zero cadence and an env that never goes idle, the loop
        // sleeps once per tick between ticks (bounded by max_iterations).
        let cfg = config(); // default fast = 60s
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "g1", 10010, now - 3600, now + 10_000);
        let k = FakeKento::new();
        k.set_instances(vec![signals_for(&conn, "g1", 10010)]);

        let sleeps = Cell::new(0u32);
        let summary = run_loop(
            &conn,
            &k,
            &cfg,
            || now,
            Some(2),
            |_d| sleeps.set(sleeps.get() + 1),
        )
        .unwrap();
        assert_eq!(summary.ticks, 2);
        assert_eq!(summary.stop, StopReason::MaxIterations);
        // One sleep after each of the two non-terminal ticks.
        assert_eq!(sleeps.get(), 2);
    }

    /// A unique temp dir under the system tempdir (no external deps).
    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir();
        let unique = format!(
            "seadog-watch-test-{}-{}",
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
}
