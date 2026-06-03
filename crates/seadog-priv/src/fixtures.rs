//! DB seeding fixtures shared by the reaper unit tests and the end-to-end
//! integration suite. Always compiled (not `#[cfg(test)]`) so the
//! integration crate (a separate compilation unit) can seed an identical
//! DB. Pure test scaffolding — no prod code path calls these.

use rusqlite::Connection;

use seadog_core::config::Config;
use seadog_core::identity::{Fingerprint, GuestSignals, GUID_MARKER_PREFIX, OWNER_MARKER_PREFIX};
use seadog_core::models::{Env, EnvStatus, Mode};
use seadog_core::store;

/// A config whose allowlist has a dual-mode `loom` and a vm-only `vmonly`,
/// with the default `[10000, 10999]` vmid range and a small herd cap.
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
        vmid,
        mode: Mode::Vm,
        owner: "alice".into(),
        image: "loom".into(),
        name: format!("seadog-alice-p-{guid}"),
        ip: "192.168.99.200".into(),
        mac: format!("aa:bb:cc:00:00:{:02x}", vmid % 256),
        created_at,
        ttl_deadline: ttl,
        soft_deadline: ttl - 600,
        status,
    };
    store::insert_env(conn, &env).unwrap();
}

/// Live-PVE signals for an inserted env that triangulate as **unanimous**
/// (name + desc GUID + owner all agree with the row → `Reap`-classified).
pub fn signals_for(conn: &Connection, guid: &str, vmid: u32) -> GuestSignals {
    let env = store::get_env(conn, guid).unwrap().unwrap();
    GuestSignals {
        vmid,
        name: Some(env.name.clone()),
        description: Some(format!(
            "{GUID_MARKER_PREFIX}{guid}\n{OWNER_MARKER_PREFIX}{}",
            env.owner
        )),
        mac: Some(env.mac.clone()),
        fingerprint: Fingerprint::default(),
    }
}

/// Live signals for an inserted env with the description marker **clobbered**
/// (an anomaly): seadog name still present, but no desc-GUID → `Anomaly`,
/// flagged, never reaped.
pub fn clobbered_signals_for(conn: &Connection, guid: &str, vmid: u32) -> GuestSignals {
    let mut s = signals_for(conn, guid, vmid);
    s.description = Some("user wiped this description".into());
    s
}

/// A **foreign** in-range guest with no seadog markers at all → `HeadsUp`,
/// one-time heads-up, never touched. No DB row should back it.
pub fn foreign_signals(vmid: u32) -> GuestSignals {
    GuestSignals {
        vmid,
        name: Some("someones-prod-db".into()),
        description: Some("not a seadog guest".into()),
        mac: Some("11:22:33:44:55:66".into()),
        fingerprint: Fingerprint::default(),
    }
}
