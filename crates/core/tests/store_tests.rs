//! Store-layer tests: cold-start open + WAL + schema, env CRUD,
//! lookups, status transitions, notify-state, heartbeat, and the
//! DB-authoritative-deadline property.

use seadog_core::models::{Env, EnvStatus, Mode, NotifyState};
use seadog_core::store;

fn sample_env(guid: &str, vmid: Option<u32>, owner: &str) -> Env {
    Env {
        guid: guid.to_string(),
        vmid,
        mode: Mode::Lxc,
        owner: owner.to_string(),
        image: "loom".to_string(),
        name: format!("seadog-{owner}-proj-tok"),
        ip: "192.168.99.192".to_string(),
        mac: "AA:BB:CC:DD:EE:FF".to_string(),
        ssh_host_key_fps: vec!["SHA256:hk1".to_string(), "SHA256:hk2".to_string()],
        created_at: 1_000,
        ttl_deadline: 4_600,
        soft_deadline: 2_800,
        status: EnvStatus::Active,
    }
}

#[test]
fn cold_start_creates_db_wal_and_schema() {
    let dir = tempdir();
    let path = dir.join("seadog.db");
    assert!(!path.exists());

    let conn = store::open(&path).expect("open cold");
    assert!(path.exists(), "db file created");

    // WAL mode active.
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode.to_lowercase(), "wal");

    // Schema tables exist.
    for t in ["envs", "notify_state", "heartbeat"] {
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [t],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1, "table {t} missing");
    }

    // Idempotent re-open on an existing file.
    drop(conn);
    let _conn2 = store::open(&path).expect("re-open warm");
}

#[test]
fn env_insert_get_roundtrip() {
    let conn = store::open_in_memory().unwrap();
    let env = sample_env("g1", Some(10000), "alice");
    store::insert_env(&conn, &env).unwrap();

    let got = store::get_env(&conn, "g1").unwrap().expect("present");
    assert_eq!(got, env);

    // removed: get_env_by_vmid lookup (vmid is no longer a query key after
    // the kento decouple — the join key is GUID). Cover a None-vmid row
    // round-trip instead, the new backend-neutral shape.
    let mut nov = sample_env("g-nov", None, "alice");
    nov.name = "seadog-alice-proj-nov".to_string();
    store::insert_env(&conn, &nov).unwrap();
    let got_nov = store::get_env(&conn, "g-nov").unwrap().expect("present");
    assert_eq!(got_nov.vmid, None);
    assert_eq!(got_nov, nov);

    assert!(store::get_env(&conn, "missing").unwrap().is_none());
}

#[test]
fn lookup_by_owner_and_status() {
    let conn = store::open_in_memory().unwrap();
    let mut a = sample_env("ga", Some(10000), "alice");
    a.created_at = 100;
    let mut b = sample_env("gb", Some(10001), "alice");
    b.created_at = 200;
    let bob = sample_env("gc", Some(10002), "bob");
    store::insert_env(&conn, &a).unwrap();
    store::insert_env(&conn, &b).unwrap();
    store::insert_env(&conn, &bob).unwrap();

    let alice = store::list_by_owner(&conn, "alice").unwrap();
    assert_eq!(alice.len(), 2);
    // Newest first.
    assert_eq!(alice[0].guid, "gb");
    assert_eq!(alice[1].guid, "ga");

    let active = store::list_by_status(&conn, EnvStatus::Active).unwrap();
    assert_eq!(active.len(), 3);
    assert!(store::list_by_status(&conn, EnvStatus::Reaped)
        .unwrap()
        .is_empty());
}

#[test]
fn mark_reaped_and_vanished_transition_status() {
    let conn = store::open_in_memory().unwrap();
    store::insert_env(&conn, &sample_env("g1", Some(10000), "alice")).unwrap();
    store::insert_env(&conn, &sample_env("g2", Some(10001), "alice")).unwrap();

    store::mark_reaped(&conn, "g1").unwrap();
    store::mark_vanished(&conn, "g2").unwrap();

    assert_eq!(
        store::get_env(&conn, "g1").unwrap().unwrap().status,
        EnvStatus::Reaped
    );
    assert_eq!(
        store::get_env(&conn, "g2").unwrap().unwrap().status,
        EnvStatus::Vanished
    );

    // Transitioning a missing env errors.
    assert!(store::mark_reaped(&conn, "nope").is_err());
}

#[test]
fn set_ttl_deadline_updates_and_errors_on_missing() {
    let conn = store::open_in_memory().unwrap();
    let env = sample_env("g1", Some(10000), "alice");
    store::insert_env(&conn, &env).unwrap();
    assert_eq!(env.ttl_deadline, 4_600);
    assert_eq!(env.created_at, 1_000);

    // Bump the deadline (the `extend` verb's DB op). A generous ceiling
    // (created_at + 1e9) leaves 9_000 unclamped; the stored value is returned.
    let stored = store::set_ttl_deadline(&conn, "g1", 9_000, 1_000_000_000).unwrap();
    assert_eq!(stored, 9_000);
    assert_eq!(
        store::get_env(&conn, "g1").unwrap().unwrap().ttl_deadline,
        9_000
    );

    // Other env columns untouched.
    let got = store::get_env(&conn, "g1").unwrap().unwrap();
    assert_eq!(got.owner, "alice");
    assert_eq!(got.status, EnvStatus::Active);

    // Missing guid is a typed NotFound error.
    assert!(store::set_ttl_deadline(&conn, "nope", 1, 1_000_000_000).is_err());
}

#[test]
fn set_ttl_deadline_clamps_to_max_ttl_window() {
    let conn = store::open_in_memory().unwrap();
    let env = sample_env("g1", Some(10000), "alice"); // created_at = 1_000
    store::insert_env(&conn, &env).unwrap();

    // max_ttl of 3_600s ⇒ ceiling = created_at + 3_600 = 4_600. A request far
    // past the ceiling is clamped DOWN to it; the clamped value is returned.
    let stored = store::set_ttl_deadline(&conn, "g1", 999_999_999, 3_600).unwrap();
    assert_eq!(stored, 4_600, "deadline clamped down to created_at + max_ttl");
    assert_eq!(
        store::get_env(&conn, "g1").unwrap().unwrap().ttl_deadline,
        4_600
    );

    // A request BELOW created_at is clamped UP to created_at (never earlier).
    let stored = store::set_ttl_deadline(&conn, "g1", 0, 3_600).unwrap();
    assert_eq!(stored, 1_000, "deadline clamped up to created_at");

    // A request inside the window passes through unchanged.
    let stored = store::set_ttl_deadline(&conn, "g1", 2_000, 3_600).unwrap();
    assert_eq!(stored, 2_000);
}

#[test]
fn set_mac_updates_and_errors_on_missing() {
    let conn = store::open_in_memory().unwrap();
    let env = sample_env("g1", Some(10000), "alice");
    store::insert_env(&conn, &env).unwrap();

    // Record the effective (kento-assigned) MAC read back after provision.
    store::set_mac(&conn, "g1", "bc:00:00:27:10:00").unwrap();
    assert_eq!(
        store::get_env(&conn, "g1").unwrap().unwrap().mac,
        "bc:00:00:27:10:00"
    );

    // Other columns untouched.
    let got = store::get_env(&conn, "g1").unwrap().unwrap();
    assert_eq!(got.owner, "alice");
    assert_eq!(got.status, EnvStatus::Active);

    // Missing guid is a typed NotFound error.
    assert!(store::set_mac(&conn, "nope", "bc:00:00:00:00:00").is_err());
}

#[test]
fn notify_state_write_read() {
    let conn = store::open_in_memory().unwrap();
    store::insert_env(&conn, &sample_env("g1", Some(10000), "alice")).unwrap();
    assert!(store::get_notify_state(&conn, "g1").unwrap().is_none());

    let s = NotifyState {
        guid: "g1".to_string(),
        last_severity: "warning".to_string(),
        last_emitted_at: 1234,
        acked: false,
        acked_by: None,
        acked_at: None,
    };
    store::put_notify_state(&conn, &s).unwrap();
    assert_eq!(store::get_notify_state(&conn, "g1").unwrap().unwrap(), s);

    // Upsert path: also exercises the ack-audit columns round-tripping.
    let s2 = NotifyState {
        guid: "g1".to_string(),
        last_severity: "critical".to_string(),
        last_emitted_at: 5678,
        acked: true,
        acked_by: Some("alice".to_string()),
        acked_at: Some(5678),
    };
    store::put_notify_state(&conn, &s2).unwrap();
    assert_eq!(store::get_notify_state(&conn, "g1").unwrap().unwrap(), s2);
}

#[test]
fn heartbeat_write_read() {
    let conn = store::open_in_memory().unwrap();
    assert!(store::read_heartbeat(&conn).unwrap().is_none());

    store::write_heartbeat(&conn, 1111).unwrap();
    assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(1111));

    // Single-row: overwrites, not appends.
    store::write_heartbeat(&conn, 2222).unwrap();
    assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(2222));
    let n: i64 = conn
        .query_row("SELECT count(*) FROM heartbeat", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
}

#[test]
fn deadline_is_db_authoritative() {
    // Persist an env, then simulate a "PVE description clobber" — i.e.
    // the guest's notes get rewritten out-of-band but the DB row is
    // never touched. The deadline read back from the DB must be
    // unchanged: the DB owns *when* an env dies.
    let dir = tempdir();
    let path = dir.join("seadog.db");
    let conn = store::open(&path).unwrap();

    let mut env = sample_env("g1", Some(10000), "alice");
    env.ttl_deadline = 9_999;
    store::insert_env(&conn, &env).unwrap();

    // "Clobber" happens elsewhere (PVE-side): we deliberately do NOT
    // write the DB here. Re-read and assert the deadline survived.
    let got = store::get_env(&conn, "g1").unwrap().unwrap();
    assert_eq!(got.ttl_deadline, 9_999);

    // And it survives a close/reopen too.
    drop(conn);
    let conn2 = store::open(&path).unwrap();
    let got2 = store::get_env(&conn2, "g1").unwrap().unwrap();
    assert_eq!(got2.ttl_deadline, 9_999);
}

/// Create a unique temp directory that is cleaned up at process exit
/// (good enough for tests; avoids pulling in the `tempfile` crate).
fn tempdir() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static CTR: AtomicU32 = AtomicU32::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("seadog-store-{pid}-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
