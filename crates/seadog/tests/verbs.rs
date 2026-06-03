//! Integration tests for the DB-only verbs + the elevated stubs.
//!
//! Each test seeds a temp SQLite DB directly via `seadog-core::store`,
//! writes a minimal config, then runs the compiled `seadog` binary with
//! `$SEADOG_DB` / `$SEADOG_CONFIG` / `$SEADOG_AUTHORIZED_KEYS` pointed at
//! the fixtures, asserting on the JSON it emits. Owner is injected with a
//! trusted top-level `--owner` (the forced-command convention).

use std::process::Command;

use seadog_core::models::{Env, EnvStatus, Mode, NotifyState};
use seadog_core::store;
use serde_json::Value;

/// A minimal valid config (image allowlist non-empty so `validate` passes).
const CONFIG_YAML: &str = r#"
images:
  loom:     { ref: "ghcr.io/x/droste:loom",     modes: [lxc] }
  kanibako: { ref: "ghcr.io/x/kanibako:latest",  modes: [lxc, vm] }
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: String,
    config_path: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("seadog.db").to_str().unwrap().to_string();
        let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
        std::fs::write(&config_path, CONFIG_YAML).unwrap();
        // Touch the DB (open creates + migrates).
        let _ = store::open(&db_path).unwrap();
        Fixture {
            _dir: dir,
            db_path,
            config_path,
        }
    }

    fn conn(&self) -> rusqlite::Connection {
        store::open(&self.db_path).unwrap()
    }

    /// Run `seadog --owner <owner> <args...>` (direct argv path) and return
    /// (exit_success, stdout_json_or_null, stderr_string).
    fn run(&self, owner: &str, args: &[&str]) -> (bool, Value, String) {
        let exe = env!("CARGO_BIN_EXE_seadog");
        let mut cmd = Command::new(exe);
        cmd.env("SEADOG_DB", &self.db_path)
            .env("SEADOG_CONFIG", &self.config_path)
            .env_remove("SSH_ORIGINAL_COMMAND")
            .env_remove("SSH_AUTH_INFO_0")
            .arg("--owner")
            .arg(owner);
        for a in args {
            cmd.arg(a);
        }
        let out = cmd.output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let json = serde_json::from_str(&stdout).unwrap_or(Value::Null);
        (out.status.success(), json, stderr)
    }
}

fn mk_env(guid: &str, vmid: u32, owner: &str, status: EnvStatus, created_at: i64, ttl: i64) -> Env {
    Env {
        guid: guid.into(),
        vmid,
        mode: Mode::Lxc,
        owner: owner.into(),
        image: "loom".into(),
        name: format!("seadog-{owner}-p-{guid}"),
        ip: "192.168.0.200".into(),
        mac: format!("aa:bb:cc:00:00:{:02x}", vmid % 256),
        created_at,
        ttl_deadline: ttl,
        soft_deadline: ttl - 600,
        status,
    }
}

#[test]
fn ls_shows_only_owner_active_and_all_shows_everything() {
    let fx = Fixture::new();
    let conn = fx.conn();
    store::insert_env(
        &conn,
        &mk_env("g-alice-1", 10010, "alice", EnvStatus::Active, 1000, 5000),
    )
    .unwrap();
    store::insert_env(
        &conn,
        &mk_env("g-alice-2", 10011, "alice", EnvStatus::Reaped, 900, 4000),
    )
    .unwrap();
    store::insert_env(
        &conn,
        &mk_env("g-bob-1", 10012, "bob", EnvStatus::Active, 1100, 6000),
    )
    .unwrap();

    // alice's `ls`: only her ACTIVE env.
    let (ok, json, err) = fx.run("alice", &["ls"]);
    assert!(ok, "stderr: {err}");
    let envs = json["envs"].as_array().unwrap();
    assert_eq!(envs.len(), 1, "alice has one active env");
    assert_eq!(envs[0]["guid"], "g-alice-1");
    assert_eq!(json["count"], 1);
    assert_eq!(json["all"], false);

    // `ls --all`: every env regardless of owner/status.
    let (ok, json, _) = fx.run("alice", &["ls", "--all"]);
    assert!(ok);
    assert_eq!(json["envs"].as_array().unwrap().len(), 3);
    assert_eq!(json["all"], true);
}

#[test]
fn show_returns_env_or_not_found() {
    let fx = Fixture::new();
    let conn = fx.conn();
    store::insert_env(
        &conn,
        &mk_env("g-1", 10010, "alice", EnvStatus::Active, 1000, 5000),
    )
    .unwrap();

    let (ok, json, _) = fx.run("alice", &["show", "g-1"]);
    assert!(ok);
    assert_eq!(json["env"]["guid"], "g-1");
    assert_eq!(json["env"]["vmid"], 10010);

    let (ok, json, err) = fx.run("alice", &["show", "nope"]);
    assert!(!ok, "missing env must be an error");
    assert!(json.is_null());
    let errobj: Value = serde_json::from_str(&err).unwrap();
    assert!(errobj["error"].as_str().unwrap().contains("nope"));
}

#[test]
fn extend_bumps_deadline_and_refuses_foreign_env() {
    let fx = Fixture::new();
    let conn = fx.conn();
    store::insert_env(
        &conn,
        &mk_env("g-mine", 10010, "alice", EnvStatus::Active, 1000, 5000),
    )
    .unwrap();
    store::insert_env(
        &conn,
        &mk_env("g-theirs", 10011, "bob", EnvStatus::Active, 1000, 5000),
    )
    .unwrap();

    // alice extends her own env by 30m (1800s).
    let (ok, json, err) = fx.run("alice", &["extend", "g-mine", "30m"]);
    assert!(ok, "stderr: {err}");
    assert_eq!(json["previous_ttl_deadline"], 5000);
    assert_eq!(json["ttl_deadline"], 5000 + 1800);
    assert_eq!(json["extended_by_secs"], 1800);
    // Persisted.
    let env = store::get_env(&fx.conn(), "g-mine").unwrap().unwrap();
    assert_eq!(env.ttl_deadline, 5000 + 1800);

    // alice cannot extend bob's env.
    let (ok, _json, err) = fx.run("alice", &["extend", "g-theirs", "30m"]);
    assert!(!ok, "foreign extend must be refused");
    let errobj: Value = serde_json::from_str(&err).unwrap();
    assert!(errobj["error"].as_str().unwrap().contains("not owned"));
    // bob's deadline unchanged.
    assert_eq!(
        store::get_env(&fx.conn(), "g-theirs")
            .unwrap()
            .unwrap()
            .ttl_deadline,
        5000
    );
}

#[test]
fn ack_flips_notify_state() {
    let fx = Fixture::new();
    let conn = fx.conn();
    store::insert_env(
        &conn,
        &mk_env("g-1", 10010, "alice", EnvStatus::Active, 1000, 5000),
    )
    .unwrap();
    // Seed an un-acked notify state.
    store::put_notify_state(
        &conn,
        &NotifyState {
            guid: "g-1".into(),
            last_severity: "warn".into(),
            last_emitted_at: 1234,
            acked: false,
        },
    )
    .unwrap();

    let (ok, json, err) = fx.run("alice", &["ack", "10010"]);
    assert!(ok, "stderr: {err}");
    assert_eq!(json["guid"], "g-1");
    assert_eq!(json["acked"], true);
    // Persisted flip.
    let s = store::get_notify_state(&fx.conn(), "g-1").unwrap().unwrap();
    assert!(s.acked);
    assert_eq!(s.last_severity, "warn", "ack must not clobber severity");
}

#[test]
fn health_reports_counts_and_heartbeat() {
    let fx = Fixture::new();
    let conn = fx.conn();
    store::insert_env(
        &conn,
        &mk_env("g-a", 10010, "alice", EnvStatus::Active, 1000, 5000),
    )
    .unwrap();
    store::insert_env(
        &conn,
        &mk_env("g-r", 10011, "alice", EnvStatus::Reaped, 900, 4000),
    )
    .unwrap();
    store::write_heartbeat(&conn, 1_000_000).unwrap();

    let (ok, json, err) = fx.run("alice", &["health"]);
    assert!(ok, "stderr: {err}");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(json["counts"]["active"], 1);
    assert_eq!(json["counts"]["reaped"], 1);
    assert_eq!(json["counts"]["total"], 2);
    assert_eq!(json["heartbeat"]["last_sweep_at"], 1_000_000);
    assert!(json["heartbeat"]["age_secs"].is_i64());
}

#[test]
fn health_null_heartbeat_before_first_sweep() {
    let fx = Fixture::new();
    let (ok, json, _) = fx.run("alice", &["health"]);
    assert!(ok);
    assert!(json["heartbeat"].is_null());
}

#[test]
fn history_and_stats_read() {
    let fx = Fixture::new();
    let conn = fx.conn();
    store::insert_env(
        &conn,
        &mk_env("g-a", 10010, "alice", EnvStatus::Active, 5000, 9000),
    )
    .unwrap();
    store::insert_env(
        &conn,
        &mk_env("g-r", 10011, "alice", EnvStatus::Reaped, 4000, 8000),
    )
    .unwrap();
    store::insert_env(
        &conn,
        &mk_env("g-v", 10012, "bob", EnvStatus::Vanished, 3000, 7000),
    )
    .unwrap();

    // history with no window: both terminal envs.
    let (ok, json, _) = fx.run("alice", &["history"]);
    assert!(ok);
    assert_eq!(json["count"], 2);

    // stats: totals + breakdowns.
    let (ok, json, _) = fx.run("alice", &["stats"]);
    assert!(ok);
    assert_eq!(json["total"], 3);
    assert_eq!(json["by_status"]["active"], 1);
    assert_eq!(json["by_status"]["reaped"], 1);
    assert_eq!(json["by_status"]["vanished"], 1);
    assert_eq!(json["active_by_owner"]["alice"], 1);
}

#[test]
fn create_returns_bridge_not_wired() {
    let fx = Fixture::new();
    let (ok, _json, err) = fx.run("alice", &["create", "--image", "loom"]);
    assert!(!ok, "create must fail in Phase 2a");
    let errobj: Value = serde_json::from_str(&err).unwrap();
    let msg = errobj["error"].as_str().unwrap();
    assert!(msg.contains("Phase 2b"), "got: {msg}");
}

#[test]
fn destroy_returns_bridge_not_wired() {
    let fx = Fixture::new();
    let conn = fx.conn();
    store::insert_env(
        &conn,
        &mk_env("g-1", 10010, "alice", EnvStatus::Active, 1000, 5000),
    )
    .unwrap();

    let (ok, _json, err) = fx.run("alice", &["destroy", "g-1"]);
    assert!(!ok, "destroy must fail in Phase 2a");
    let errobj: Value = serde_json::from_str(&err).unwrap();
    assert!(errobj["error"].as_str().unwrap().contains("Phase 2b"));
}

#[test]
fn owner_cannot_be_set_from_verb_args() {
    // A user-supplied trailing `--owner attacker` after the verb must NOT
    // override the trusted owner: clap sees it as an unknown arg to `ls`
    // and rejects the invocation (it never runs as `attacker`).
    let fx = Fixture::new();
    let (ok, _json, err) = fx.run("alice", &["ls", "--owner", "attacker"]);
    assert!(!ok, "trailing --owner must be rejected, not honored");
    assert!(!err.is_empty());
}
