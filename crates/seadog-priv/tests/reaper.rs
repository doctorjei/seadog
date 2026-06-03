//! End-to-end integration of the `seadog-priv` reaper modes.
//!
//! These drive the **real** `sweep`/`watch` entry points (`sweep::run_with_db`
//! and `watch::{tick, run_loop, acquire_lock}`) against a temp on-disk DB
//! (`core::store::open`) and a primed `FakeKento` — not `core::reap` in
//! isolation. They prove the seadog-priv wiring: DB open, the shared sweep,
//! `prune_terminal`, the heartbeat, the flock singleton, and the
//! self-extinguishing loop.

use std::path::PathBuf;
use std::time::Duration;

use rusqlite::Connection;

use seadog_core::kento::FakeKento;
use seadog_core::models::{EnvStatus, Mode};
use seadog_core::store;

use seadog_priv::fixtures::{
    clobbered_signals_for, config, foreign_signals, insert_active, insert_with_status, signals_for,
};
use seadog_priv::{sweep, watch};

/// A unique temp dir under the system tempdir (no external deps).
fn tempdir(tag: &str) -> PathBuf {
    let unique = format!(
        "seadog-reaper-it-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let dir = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Open a fresh on-disk DB (exercises the real `store::open` + WAL path,
/// unlike the in-memory unit tests).
fn open_temp_db(tag: &str) -> (Connection, PathBuf) {
    let dir = tempdir(tag);
    let db = dir.join("seadog.db");
    let conn = store::open(&db).unwrap();
    (conn, db)
}

#[test]
fn sweep_one_shot_mixes_fixtures_and_routes_each() {
    let (conn, _db) = open_temp_db("oneshot");
    let cfg = config();
    let now = 2_000_000i64;

    // expired + unanimous → reaped
    insert_active(&conn, "expired", 10010, now - 3600, now - 100);
    // anomaly: row present, but live desc-GUID clobbered → flagged, NOT reaped
    insert_active(&conn, "anomaly", 10011, now - 3600, now - 100);
    // a foreign in-range guest with no DB row → heads-up, never touched
    // a live but NOT-yet-expired env (deadline in the future) → survives
    insert_active(&conn, "live", 10013, now - 3600, now + 10_000);
    // an OLD terminal row (reaped long ago) → pruned by prune_terminal
    let retention = cfg.retention.terminal.as_secs() as i64;
    insert_with_status(
        &conn,
        "ancient",
        10014,
        now - retention - 10_000,
        now - retention - 5_000,
        EnvStatus::Reaped,
    );

    let k = FakeKento::new();
    k.set_guests(vec![
        signals_for(&conn, "expired", 10010),
        clobbered_signals_for(&conn, "anomaly", 10011),
        foreign_signals(10012),
        signals_for(&conn, "live", 10013),
    ]);

    let v = sweep::run_with_db(&conn, &k, &cfg, now).unwrap();
    assert_eq!(v["ok"], true);

    // expired+unanimous → reaped (teardown called + row marked).
    assert_eq!(v["reaped"], 1);
    assert_eq!(k.teardowns(), vec![(10010, Mode::Vm)]);
    assert_eq!(
        store::get_env(&conn, "expired").unwrap().unwrap().status,
        EnvStatus::Reaped
    );

    // anomaly → flagged, NOT reaped; its row stays Active.
    assert_eq!(v["flagged"], 1);
    assert_eq!(
        store::get_env(&conn, "anomaly").unwrap().unwrap().status,
        EnvStatus::Active
    );

    // foreign-in-range → heads-up, never touched.
    assert_eq!(v["heads_up"], 1);

    // live (future deadline) survives untouched.
    assert_eq!(
        store::get_env(&conn, "live").unwrap().unwrap().status,
        EnvStatus::Active
    );

    // heartbeat written.
    assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(now));

    // prune dropped only the OLD terminal row; the live (overdue) rows
    // remain. The "expired" row was reaped THIS sweep but its created_at is
    // recent, so it survives the retention cutoff.
    assert_eq!(v["pruned"], 1);
    assert!(store::get_env(&conn, "ancient").unwrap().is_none());
    assert!(store::get_env(&conn, "expired").unwrap().is_some());
    assert!(store::get_env(&conn, "live").unwrap().is_some());
}

#[test]
fn sweep_one_shot_surfaces_quorum_loss_cleanly() {
    let (conn, _db) = open_temp_db("qloss");
    let cfg = config();
    let now = 2_000_000i64;
    let k = FakeKento::new();
    k.set_quorum_lost("pmxcfs read-only: no quorum");

    let v = sweep::run_with_db(&conn, &k, &cfg, now).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["reaped"], 0);
    assert!(v["quorum_lost"].is_string());
    // Heartbeat still stamped so health sees the reaper ran.
    assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(now));
}

#[test]
fn watch_loop_reaps_one_then_self_extinguishes() {
    let (conn, _db) = open_temp_db("reap-idle");
    let mut cfg = config();
    cfg.cadence.fast = Duration::ZERO; // never sleep in the test
    let now = 2_000_000i64;

    insert_active(&conn, "g1", 10010, now - 3600, now - 100);
    let k = FakeKento::new();
    k.set_guests(vec![signals_for(&conn, "g1", 10010)]);

    let summary = watch::run_loop(
        &conn,
        &k,
        &cfg,
        || now,
        Some(10),
        |_d| panic!("must not sleep when cadence is zero"),
    )
    .unwrap();

    // One tick reaps it; the post-sweep active count is zero → self-extinguish.
    assert_eq!(summary.ticks, 1);
    assert_eq!(summary.reaped, 1);
    assert_eq!(summary.stop, watch::StopReason::Idle);
    assert_eq!(k.teardowns(), vec![(10010, Mode::Vm)]);
    assert_eq!(
        store::get_env(&conn, "g1").unwrap().unwrap().status,
        EnvStatus::Reaped
    );
    assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(now));
}

#[test]
fn watch_loop_zero_env_exits_immediately() {
    let (conn, _db) = open_temp_db("zero");
    let mut cfg = config();
    cfg.cadence.fast = Duration::ZERO;
    let now = 2_000_000i64;
    let k = FakeKento::new();

    let summary = watch::run_loop(&conn, &k, &cfg, || now, Some(5), |_d| ()).unwrap();
    assert_eq!(summary.ticks, 1);
    assert_eq!(summary.stop, watch::StopReason::Idle);
}

#[test]
fn watch_tick_is_callable_directly() {
    // The loop body factors into `tick` so a single iteration is testable
    // without the loop driver.
    let (conn, _db) = open_temp_db("tick");
    let cfg = config();
    let now = 2_000_000i64;
    insert_active(&conn, "g1", 10010, now - 3600, now - 100);
    let k = FakeKento::new();
    k.set_guests(vec![signals_for(&conn, "g1", 10010)]);

    let r = watch::tick(&conn, &k, &cfg, now).unwrap();
    assert_eq!(r.reaped, 1);
    assert_eq!(r.active_after, 0);
    assert!(r.quorum_lost.is_none());
}

#[test]
fn flock_singleton_blocks_second_and_frees_on_release() {
    let dir = tempdir("flock");
    let path = dir.join("watcher.lock");

    let first = watch::acquire_lock(&path).unwrap();
    assert!(matches!(first, watch::LockOutcome::Acquired(_)));

    // Second attempt while held → AlreadyHeld (no double-start).
    assert!(matches!(
        watch::acquire_lock(&path).unwrap(),
        watch::LockOutcome::AlreadyHeld
    ));

    // Release → a fresh acquire succeeds.
    drop(first);
    assert!(matches!(
        watch::acquire_lock(&path).unwrap(),
        watch::LockOutcome::Acquired(_)
    ));
}

#[test]
fn watch_loop_does_not_tight_spin_on_quorum_loss() {
    let (conn, _db) = open_temp_db("qspin");
    let mut cfg = config();
    cfg.cadence.fast = Duration::ZERO;
    let now = 2_000_000i64;
    // A future-deadline active env keeps the loop from going idle, so the
    // injected bound is what stops it — proving bounded, not unbounded.
    insert_active(&conn, "g1", 10010, now - 3600, now + 10_000);
    let k = FakeKento::new();
    k.set_quorum_lost("no quorum");

    let summary = watch::run_loop(&conn, &k, &cfg, || now, Some(4), |_d| ()).unwrap();
    assert_eq!(summary.stop, watch::StopReason::MaxIterations);
    assert_eq!(summary.ticks, 4);
    assert!(summary.quorum_lost.is_some());
    assert_eq!(summary.reaped, 0);
}
