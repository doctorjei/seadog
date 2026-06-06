//! `seadog-priv teardown` — **the critical security gate.**
//!
//! Root never blindly trusts the front-end for a destroy. Teardown is
//! **GUID-driven**: the front-end passes the instance `--guid`, `--owner`
//! and `--mode`; the helper re-validates against its OWN sources before
//! destroying anything:
//!
//! 1. **DB row exists** — `store::get_env(guid)` returns a row (refuse if
//!    not: we never destroy something with no lease record).
//! 2. **Owner matches** — the row's recorded `owner` equals `--owner` (the
//!    owner the front-end resolved from the caller's key). Refuse on
//!    mismatch — one owner cannot tear down another's env.
//! 3. **Live instance carries the guid** — `kento.list_instances()` is
//!    scanned for the instance whose injected `SEADOG_GUID` equals `--guid`.
//!    Its **own name** (read from the live list, never caller-supplied) must
//!    equal the DB row's name; refuse on mismatch.
//! 4. **Destroy by that live name** — `kento.teardown(name, mode)`.
//!
//! If NO live instance carries the guid, the env is already gone →
//! **idempotent success** (no destroy needed). Any of: no DB row, owner
//! mismatch, or live-name ≠ row-name → a typed refusal, NO destroy.

use anyhow::{bail, Result};
use clap::Args;
use serde_json::{json, Value};

use seadog_core::config::Config;
use seadog_core::kento::Kento;
use seadog_core::store;

use crate::parse_mode;
use seadog_priv::sweep::open_db;

/// `teardown --owner <name> --guid <uuid> --mode <lxc|vm>`.
#[derive(Debug, Args)]
pub struct TeardownArgs {
    /// Requesting owner — must match the env row's recorded owner.
    #[arg(long)]
    pub owner: String,
    /// Instance GUID — must match a DB row AND a live instance's anchor.
    #[arg(long)]
    pub guid: String,
    /// `lxc` or `vm`.
    #[arg(long)]
    pub mode: String,
}

/// Run `teardown`. Re-validates owner against the DB row, then confirms a
/// live kento instance carries the guid and matches the row's name before
/// destroying. Idempotent when the instance is already gone.
pub fn run(args: &TeardownArgs, kento: &dyn Kento, _config: &Config) -> Result<Value> {
    let mode = parse_mode(&args.mode)?;

    // (1) DB row must exist. The helper opens its OWN store (same env-driven
    //     path the reaper uses); it never trusts a relayed row.
    let conn = open_db()?;
    let row = store::get_env(&conn, &args.guid)
        .map_err(anyhow::Error::from)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "refusing teardown: no env row for guid {} (unknown lease)",
                args.guid
            )
        })?;

    // (2) Owner must match the row. The front-end resolves owner from the
    //     caller's key, but root re-checks it against the DB row of record.
    if row.owner != args.owner {
        bail!(
            "refusing teardown: env {} is not owned by '{}' (owner mismatch)",
            args.guid,
            args.owner
        );
    }

    // (3) Find the LIVE instance carrying this guid. kento only knows kento
    //     instances; the live set IS the scan.
    let live = kento.list_instances().map_err(anyhow::Error::from)?;
    let instance = live
        .into_iter()
        .find(|i| i.guid.as_deref() == Some(args.guid.as_str()));

    let Some(instance) = instance else {
        // No live instance carries the guid → it's already gone. Idempotent
        // success: nothing to destroy.
        return Ok(json!({
            "ok": true,
            "mode": mode.as_str(),
            "guid": args.guid,
            "owner": args.owner,
            "status": "already-gone",
        }));
    };

    // The live instance's OWN name must match the DB row's name. Destroy by
    // that live name (never a caller-supplied one).
    if instance.name != row.name {
        bail!(
            "refusing teardown: live instance for guid {} has name '{}' but the row records '{}' (name mismatch)",
            args.guid,
            instance.name,
            row.name
        );
    }

    // (4) ALL checks passed → destroy by the live instance name.
    kento
        .teardown(&instance.name, mode)
        .map_err(anyhow::Error::from)?;

    Ok(json!({
        "ok": true,
        "mode": mode.as_str(),
        "guid": args.guid,
        "owner": args.owner,
        "status": "reaped",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::DB_ENV_LOCK;
    use seadog_core::kento::{FakeKento, InstanceSignals};
    use seadog_core::models::Mode;
    use seadog_priv::fixtures::{config, insert_active, signals_for};

    const GUID: &str = "11111111-1111-4111-8111-111111111111";

    fn args(guid: &str, owner: &str) -> TeardownArgs {
        TeardownArgs {
            owner: owner.into(),
            guid: guid.into(),
            mode: "vm".into(),
        }
    }

    /// Open an isolated temp DB the teardown path will see via `$SEADOG_DB`,
    /// returning the connection plus a guard that restores the env on drop.
    fn isolated_db() -> (rusqlite::Connection, DbEnvGuard) {
        let unique = format!(
            "seadog-teardown-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("seadog.db");
        let prev = std::env::var_os("SEADOG_DB");
        std::env::set_var("SEADOG_DB", &db);
        let conn = store::open(&db).unwrap();
        (conn, DbEnvGuard { dir, prev })
    }

    /// RAII: restore `$SEADOG_DB` and remove the temp dir on drop. Tests that
    /// touch `$SEADOG_DB` serialize on this lock so they can't race.
    struct DbEnvGuard {
        dir: std::path::PathBuf,
        prev: Option<std::ffi::OsString>,
    }
    impl Drop for DbEnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("SEADOG_DB", v),
                None => std::env::remove_var("SEADOG_DB"),
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn matching_owner_and_live_instance_is_destroyed() {
        let _lock = DB_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let cfg = config();
        let (conn, _g) = isolated_db();
        let now = 1_000_000i64;
        insert_active(&conn, GUID, 10010, now - 3600, now + 10_000);
        let k = FakeKento::new();
        k.set_instances(vec![signals_for(&conn, GUID, 10010)]);

        let out = run(&args(GUID, "alice"), &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["status"], "reaped");
        assert_eq!(
            k.teardowns(),
            vec![(format!("seadog-alice-p-{GUID}"), Mode::Vm)]
        );
    }

    #[test]
    fn no_db_row_is_refused() {
        let _lock = DB_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let cfg = config();
        let (conn, _g) = isolated_db();
        // Live instance exists, but no DB row backs the guid.
        let k = FakeKento::new();
        k.set_instances(vec![InstanceSignals {
            name: format!("seadog-alice-p-{GUID}"),
            guid: Some(GUID.into()),
            owner: Some("alice".into()),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            ssh_host_key_fps: Vec::new(),
            image: "loom".into(),
            status: "running".into(),
            mode: Mode::Vm,
            vmid: Some(10010),
        }]);
        let _ = &conn;
        assert!(run(&args(GUID, "alice"), &k, &cfg).is_err());
        assert!(k.teardowns().is_empty());
    }

    #[test]
    fn another_owners_env_is_refused() {
        let _lock = DB_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let cfg = config();
        let (conn, _g) = isolated_db();
        let now = 1_000_000i64;
        // Row owned by alice; bob asks to tear it down.
        insert_active(&conn, GUID, 10010, now - 3600, now + 10_000);
        let k = FakeKento::new();
        k.set_instances(vec![signals_for(&conn, GUID, 10010)]);

        assert!(run(&args(GUID, "bob"), &k, &cfg).is_err());
        assert!(k.teardowns().is_empty());
    }

    #[test]
    fn live_name_mismatch_is_refused() {
        let _lock = DB_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let cfg = config();
        let (conn, _g) = isolated_db();
        let now = 1_000_000i64;
        insert_active(&conn, GUID, 10010, now - 3600, now + 10_000);
        // Live instance carries the right guid/owner but a DIFFERENT name.
        let mut sig = signals_for(&conn, GUID, 10010);
        sig.name = "seadog-alice-impostor".into();
        let k = FakeKento::new();
        k.set_instances(vec![sig]);

        assert!(run(&args(GUID, "alice"), &k, &cfg).is_err());
        assert!(k.teardowns().is_empty());
    }

    #[test]
    fn no_live_instance_is_idempotent_success() {
        let _lock = DB_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let cfg = config();
        let (conn, _g) = isolated_db();
        let now = 1_000_000i64;
        // Row exists, owner matches, but nothing live carries the guid.
        insert_active(&conn, GUID, 10010, now - 3600, now + 10_000);
        let k = FakeKento::new();

        let out = run(&args(GUID, "alice"), &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["status"], "already-gone");
        assert!(k.teardowns().is_empty());
    }
}
