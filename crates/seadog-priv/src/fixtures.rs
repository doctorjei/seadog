//! DB seeding fixtures shared by the reaper unit tests and the end-to-end
//! integration suite. Always compiled (not `#[cfg(test)]`) so the
//! integration crate (a separate compilation unit) can seed an identical
//! DB. Pure test scaffolding — no prod code path calls these.

use rusqlite::Connection;

use seadog_core::config::Config;
use seadog_core::kento::InstanceSignals;
use seadog_core::models::{Env, EnvStatus, Mode};
use seadog_core::store;

/// A config whose allowlist has a dual-mode `loom` and a vm-only `vmonly`,
/// with a small herd cap.
pub fn config() -> Config {
    let yaml = r#"
lifecycle:
  herd_cap: 8
images:
  loom:
    ref: "registry.example.com/loom:1.0"
    modes: [lxc, vm]
  vmonly:
    ref: "registry.example.com/vmonly:2.0"
    modes: [vm]
"#;
    let c = Config::from_yaml_str(yaml).unwrap();
    c.validate().unwrap();
    c
}

/// Insert an `Active` env row (a live lease) for the reaper to find.
pub fn insert_active(conn: &Connection, guid: &str, vmid: u32, created_at: i64, ttl: i64) {
    insert_with_status(conn, guid, vmid, created_at, ttl, EnvStatus::Active);
}

/// Insert an env row with an explicit status (e.g. a terminal `Reaped` row
/// to exercise `prune_terminal`).
pub fn insert_with_status(
    conn: &Connection,
    guid: &str,
    vmid: u32,
    created_at: i64,
    ttl: i64,
    status: EnvStatus,
) {
    let env = Env {
        guid: guid.into(),
        vmid: Some(vmid),
        mode: Mode::Vm,
        owner: "alice".into(),
        image: "loom".into(),
        name: format!("seadog-alice-p-{guid}"),
        ip: "192.168.99.200".into(),
        mac: format!("aa:bb:cc:00:00:{:02x}", vmid % 256),
        ssh_host_key_fps: vec![format!("SHA256:fp-{guid}")],
        created_at,
        ttl_deadline: ttl,
        soft_deadline: ttl - 600,
        status,
    };
    store::insert_env(conn, &env).unwrap();
}

/// Live kento signals for an inserted env that **agree** with the DB row
/// (GUID + name + MAC + host-key-fps all match → reap-eligible once past
/// deadline). The `vmid` arg is informational only (kento exposes it on PVE
/// backends); the identity anchor is the injected `SEADOG_GUID`.
pub fn signals_for(conn: &Connection, guid: &str, vmid: u32) -> InstanceSignals {
    let env = store::get_env(conn, guid).unwrap().unwrap();
    InstanceSignals {
        name: env.name.clone(),
        guid: Some(guid.to_string()),
        owner: Some(env.owner.clone()),
        mac: Some(env.mac.clone()),
        ssh_host_key_fps: env.ssh_host_key_fps.clone(),
        image: env.image.clone(),
        status: "running".to_string(),
        mode: env.mode,
        vmid: Some(vmid),
    }
}

/// Live signals for an inserted env whose strong confirmer is **clobbered**
/// (the live instance carries the right GUID but a mismatched name) → the
/// classifier flags it as an anomaly, never reaped.
pub fn clobbered_signals_for(conn: &Connection, guid: &str, vmid: u32) -> InstanceSignals {
    let mut s = signals_for(conn, guid, vmid);
    s.name = "seadog-alice-clobbered".into();
    s
}

/// A **foreign** kento instance carrying no `SEADOG_GUID` anchor → ignored
/// (no flag, no row, never touched). No DB row backs it.
pub fn foreign_signals(vmid: u32) -> InstanceSignals {
    InstanceSignals {
        name: "someones-prod-db".into(),
        guid: None,
        owner: None,
        mac: Some("11:22:33:44:55:66".into()),
        ssh_host_key_fps: Vec::new(),
        image: "registry.example.com/foreign:1".into(),
        status: "running".to_string(),
        mode: Mode::Vm,
        vmid: Some(vmid),
    }
}
