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
  ci:       { ref: "ghcr.io/x/ci:latest",        modes: [lxc, vm] }
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: String,
    config_path: String,
}

impl Fixture {
    fn new() -> Self {
        Self::with_config(CONFIG_YAML)
    }

    /// Build a fixture with a custom config YAML (e.g. to set a low cap).
    fn with_config(config_yaml: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("seadog.db").to_str().unwrap().to_string();
        let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
        std::fs::write(&config_path, config_yaml).unwrap();
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
        self.run_envs(owner, args, &[])
    }

    /// Like [`Fixture::run`] but with extra `(key, value)` env vars layered
    /// on (used to point the privileged path at the fake helper).
    fn run_envs(&self, owner: &str, args: &[&str], envs: &[(&str, &str)]) -> (bool, Value, String) {
        let exe = env!("CARGO_BIN_EXE_seadog");
        let mut cmd = Command::new(exe);
        cmd.env("SEADOG_DB", &self.db_path)
            .env("SEADOG_CONFIG", &self.config_path)
            .env_remove("SSH_ORIGINAL_COMMAND")
            .env_remove("SSH_AUTH_INFO_0")
            // Default the privileged path to the fake helper with no sudo and
            // no setsid, so verbs that opportunistically spawn the watcher
            // don't shell a real `setsid sudo /usr/lib/...` during tests.
            .env("SEADOG_SUDO", "")
            .env("SEADOG_SETSID", "")
            .env("SEADOG_PRIV_BIN", fake_priv_path())
            .arg("--owner")
            .arg(owner);
        for (k, v) in envs {
            cmd.env(k, v);
        }
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

/// Absolute path to the fake `seadog-priv` script, `chmod +x`'d once. The
/// front-end shells this with `$SEADOG_SUDO=""` so no real sudo runs.
fn fake_priv_path() -> String {
    use std::sync::Once;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fake-seadog-priv.sh");
    static CHMOD: Once = Once::new();
    CHMOD.call_once(|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
        }
    });
    path.to_str().unwrap().to_string()
}

fn mk_env(guid: &str, vmid: u32, owner: &str, status: EnvStatus, created_at: i64, ttl: i64) -> Env {
    Env {
        guid: guid.into(),
        vmid: Some(vmid),
        mode: Mode::Lxc,
        owner: owner.into(),
        image: "loom".into(),
        name: format!("seadog-{owner}-p-{guid}"),
        ip: "192.168.99.200".into(),
        mac: format!("aa:bb:cc:00:00:{:02x}", vmid % 256),
        ssh_host_key_fps: Vec::new(),
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
            acked_by: None,
            acked_at: None,
        },
    )
    .unwrap();

    let (ok, json, err) = fx.run("alice", &["ack", "g-1"]);
    assert!(ok, "stderr: {err}");
    assert_eq!(json["guid"], "g-1");
    assert_eq!(json["acked"], true);
    // Persisted flip.
    let s = store::get_notify_state(&fx.conn(), "g-1").unwrap().unwrap();
    assert!(s.acked);
    assert_eq!(s.last_severity, "warn", "ack must not clobber severity");
    // Audit recorded: who acked (the trusted owner) and when (some time).
    assert_eq!(s.acked_by.as_deref(), Some("alice"));
    assert!(s.acked_at.is_some(), "ack must record acked_at");
}

#[test]
fn ack_refuses_foreign_healthy_env_but_allows_flagged() {
    let fx = Fixture::new();
    let conn = fx.conn();
    // bob's healthy (Active) env — alice must NOT be able to mute it.
    store::insert_env(
        &conn,
        &mk_env("g-bob-active", 10010, "bob", EnvStatus::Active, 1000, 5000),
    )
    .unwrap();
    // bob's Flagged env — anyone may silence the anomaly heads-up.
    store::insert_env(
        &conn,
        &mk_env("g-bob-flagged", 10011, "bob", EnvStatus::Flagged, 1000, 5000),
    )
    .unwrap();

    // alice acking bob's healthy env is refused (scope check).
    let (ok, _json, err) = fx.run("alice", &["ack", "g-bob-active"]);
    assert!(!ok, "acking a foreign healthy env must be refused");
    let errobj: Value = serde_json::from_str(&err).unwrap();
    assert!(
        errobj["error"].as_str().unwrap().contains("not yours"),
        "error should explain the scope: {err}"
    );
    // No notify_state row was created for the refused env.
    assert!(store::get_notify_state(&fx.conn(), "g-bob-active")
        .unwrap()
        .is_none());

    // alice acking bob's Flagged env is allowed (the legitimate case), and
    // the audit records alice as the acker even though she isn't the owner.
    let (ok, json, err) = fx.run("alice", &["ack", "g-bob-flagged"]);
    assert!(ok, "acking a flagged env must be allowed; stderr: {err}");
    assert_eq!(json["acked"], true);
    let s = store::get_notify_state(&fx.conn(), "g-bob-flagged")
        .unwrap()
        .unwrap();
    assert!(s.acked);
    assert_eq!(s.acked_by.as_deref(), Some("alice"));
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
fn create_shells_provision_and_writes_active_row() {
    let fx = Fixture::new();
    let log = fx._dir.path().join("fake.log");
    let log_s = log.to_str().unwrap().to_string();

    let (ok, json, err) = fx.run_envs(
        "alice",
        &["create", "--image", "loom"],
        &[("SEADOG_FAKE_LOG", &log_s)],
    );
    assert!(ok, "create should succeed; stderr: {err}");

    // The verb's JSON result.
    let id = json["id"].as_str().expect("id present");
    assert!(!id.is_empty());
    assert_eq!(json["ip"].as_str().unwrap(), "192.168.99.192");
    let name = json["name"].as_str().unwrap();
    assert!(name.starts_with("seadog-alice-loom-"), "got: {name}");
    // vmid now comes from the helper's read-back (ProvisionOutcome), not from
    // front-end allocation. The fake reports 10000.
    let vmid = json["vmid"].as_u64().unwrap();
    assert_eq!(vmid, 10000);
    assert_eq!(json["mode"], "lxc");
    assert!(json["ttl_deadline"].is_i64());

    // The DB row exists and is Active.
    let env = store::get_env(&fx.conn(), id).unwrap().unwrap();
    assert_eq!(env.status, EnvStatus::Active);
    assert_eq!(env.owner, "alice");
    // The read-back vmid + host-key fps were written onto the row via
    // `set_provision_signals`.
    assert_eq!(env.vmid, Some(10000));
    assert_eq!(env.ssh_host_key_fps, vec!["SHA256:fakefp".to_string()]);
    // LXC: the helper reports no effective MAC (this fake omits the field),
    // so the front-end records "" ("no MAC recorded") rather than the
    // fictional minted MAC. Identity treats MAC as confirming-when-present.
    assert_eq!(env.mac, "", "LXC row must record an empty MAC");

    // The fake was shelled with `provision` and the right argv.
    let logged = std::fs::read_to_string(&log).unwrap();
    let prov = logged
        .lines()
        .find(|l| l.starts_with("provision "))
        .expect("provision was invoked");
    assert!(prov.contains("--owner alice"), "argv: {prov}");
    // No `--vmid`: kento auto-assigns; the front-end allocates name + IP only.
    assert!(
        !prov.contains("--vmid"),
        "argv must not carry --vmid: {prov}"
    );
    assert!(prov.contains("--ip 192.168.99.192"), "argv: {prov}");
    assert!(prov.contains(&format!("--name {name}")), "argv: {prov}");
    assert!(prov.contains(&format!("--guid {id}")), "argv: {prov}");
    // Resolved image *ref* (from the allowlist), not the bare name.
    assert!(
        prov.contains("--image-ref ghcr.io/x/droste:loom"),
        "argv: {prov}"
    );
    // A locally-administered MAC was minted and passed.
    assert!(prov.contains("--mac "), "argv: {prov}");
    // allow_nesting resolved from loom's catalog entry (no field ⇒ false).
    assert!(prov.contains("--allow-nesting false"), "argv: {prov}");
}

#[test]
fn create_rolls_back_when_provision_fails() {
    let fx = Fixture::new();
    let log = fx._dir.path().join("fake.log");
    let log_s = log.to_str().unwrap().to_string();

    let (ok, _json, err) = fx.run_envs(
        "alice",
        &["create", "--image", "loom"],
        &[("SEADOG_FAKE_LOG", &log_s), ("SEADOG_FAKE_FAIL", "1")],
    );
    assert!(!ok, "create must fail when provision fails");
    let errobj: Value = serde_json::from_str(&err).unwrap();
    assert!(
        errobj["error"].as_str().unwrap().contains("provision"),
        "error should mention the helper: {err}"
    );

    // The fake WAS invoked (allocation happened, then provision failed).
    let logged = std::fs::read_to_string(&log).unwrap();
    assert!(logged.lines().any(|l| l.starts_with("provision ")));

    // The lease must be freed: no Active row remains for alice.
    let actives: Vec<_> = store::list_by_owner(&fx.conn(), "alice")
        .unwrap()
        .into_iter()
        .filter(|e| e.status == EnvStatus::Active)
        .collect();
    assert!(actives.is_empty(), "rollback must free the lease");
    // And the row was retained as Vanished (history), not Active.
    let vanished: Vec<_> = store::list_by_status(&fx.conn(), EnvStatus::Vanished).unwrap();
    assert_eq!(vanished.len(), 1, "failed attempt kept as Vanished");
}

#[test]
fn create_rejected_at_cap_before_allocating() {
    // A config with an lxc cap of 1 for everyone.
    let capped = r#"
allocation:
  caps: { max_lxc_per_owner: 1, max_vm_per_owner: 1 }
images:
  loom: { ref: "ghcr.io/x/droste:loom", modes: [lxc] }
"#;
    let fx = Fixture::with_config(capped);
    let conn = fx.conn();
    // Seed alice at the lxc cap (1 active lxc).
    store::insert_env(
        &conn,
        &mk_env("g-existing", 10005, "alice", EnvStatus::Active, 1000, 5000),
    )
    .unwrap();

    let log = fx._dir.path().join("fake.log");
    let log_s = log.to_str().unwrap().to_string();

    let (ok, _json, err) = fx.run_envs(
        "alice",
        &["create", "--image", "loom"],
        &[("SEADOG_FAKE_LOG", &log_s)],
    );
    assert!(!ok, "create must be rejected at cap");
    let errobj: Value = serde_json::from_str(&err).unwrap();
    assert!(
        errobj["error"].as_str().unwrap().contains("cap"),
        "error should mention the cap: {err}"
    );

    // No new row was inserted (still exactly one active for alice).
    let actives: Vec<_> = store::list_by_owner(&fx.conn(), "alice")
        .unwrap()
        .into_iter()
        .filter(|e| e.status == EnvStatus::Active)
        .collect();
    assert_eq!(actives.len(), 1, "no allocation past the cap");
    // And the fake `provision` was never called (rejected before elevate).
    let logged = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !logged.lines().any(|l| l.starts_with("provision ")),
        "helper must not be shelled when capped"
    );
}

#[test]
fn destroy_shells_teardown_and_refuses_foreign_or_unknown() {
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

    let log = fx._dir.path().join("fake.log");
    let log_s = log.to_str().unwrap().to_string();

    // alice destroys her own env.
    let (ok, json, err) = fx.run_envs(
        "alice",
        &["destroy", "g-mine"],
        &[("SEADOG_FAKE_LOG", &log_s)],
    );
    assert!(ok, "destroy own env should succeed; stderr: {err}");
    assert_eq!(json["id"], "g-mine");
    assert_eq!(json["status"], "reaped");
    // Row flipped to Reaped (lease freed).
    let env = store::get_env(&fx.conn(), "g-mine").unwrap().unwrap();
    assert_eq!(env.status, EnvStatus::Reaped);
    // Teardown shelled with structured args.
    let logged = std::fs::read_to_string(&log).unwrap();
    let td = logged
        .lines()
        .find(|l| l.starts_with("teardown "))
        .expect("teardown invoked");
    assert!(td.contains("--owner alice"), "argv: {td}");
    assert!(td.contains("--guid g-mine"), "argv: {td}");
    // GUID-driven teardown: no `--vmid` (kento owns backend ids now).
    assert!(!td.contains("--vmid"), "argv must not carry --vmid: {td}");
    assert!(td.contains("--mode lxc"), "argv: {td}");

    // alice cannot destroy bob's env (refused).
    let (ok, _json, err) = fx.run("alice", &["destroy", "g-theirs"]);
    assert!(!ok, "foreign destroy must be refused");
    let errobj: Value = serde_json::from_str(&err).unwrap();
    assert!(errobj["error"].as_str().unwrap().contains("not owned"));
    // bob's env untouched.
    assert_eq!(
        store::get_env(&fx.conn(), "g-theirs")
            .unwrap()
            .unwrap()
            .status,
        EnvStatus::Active
    );

    // Unknown id errors.
    let (ok, _json, err) = fx.run("alice", &["destroy", "nope"]);
    assert!(!ok, "unknown id must error");
    let errobj: Value = serde_json::from_str(&err).unwrap();
    assert!(errobj["error"].as_str().unwrap().contains("not found"));
}

#[test]
fn watcher_spawns_at_most_once() {
    // Two opportunistic spawns racing for the same flock: exactly one wins
    // and writes a marker line. The fake `watch` holds the lock across a
    // short sleep so the second invocation overlaps and is rejected.
    let fx = Fixture::new();
    let lock = fx._dir.path().join("watcher.lock");
    let marker = fx._dir.path().join("watcher.marker");
    let lock_s = lock.to_str().unwrap().to_string();
    let marker_s = marker.to_str().unwrap().to_string();

    // Each `ls` opportunistically spawns the detached watcher. Fire two
    // quickly so their `watch` invocations overlap on the flock.
    let envs = [
        ("SEADOG_WATCHER_LOCK", lock_s.as_str()),
        ("SEADOG_WATCHER_MARKER", marker_s.as_str()),
    ];
    let (ok1, _, e1) = fx.run_envs("alice", &["ls"], &envs);
    let (ok2, _, e2) = fx.run_envs("alice", &["ls"], &envs);
    assert!(ok1, "ls 1: {e1}");
    assert!(ok2, "ls 2: {e2}");

    // The detached watchers race; give them time to resolve the flock.
    std::thread::sleep(std::time::Duration::from_millis(1200));

    let marker_lines = std::fs::read_to_string(&marker).unwrap_or_default();
    let n = marker_lines.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(
        n, 1,
        "exactly one watcher may hold the lock; marker:\n{marker_lines}"
    );
}

#[test]
fn watcher_spawn_failure_does_not_break_verb() {
    // Point the helper at a nonexistent path: the opportunistic watcher
    // spawn fails, but `ls` must still succeed (best-effort hook).
    let fx = Fixture::new();
    let conn = fx.conn();
    store::insert_env(
        &conn,
        &mk_env("g-1", 10010, "alice", EnvStatus::Active, 1000, 5000),
    )
    .unwrap();

    let (ok, json, err) = fx.run_envs(
        "alice",
        &["ls"],
        &[("SEADOG_PRIV_BIN", "/nonexistent/seadog-priv-xyz")],
    );
    assert!(ok, "ls must survive a watcher spawn failure; stderr: {err}");
    assert_eq!(json["count"], 1);
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
