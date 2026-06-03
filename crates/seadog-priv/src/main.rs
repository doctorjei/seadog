//! `seadog-priv` — the **root** half of seadog. This is the ONLY code that
//! runs as root; the unprivileged front-end (`seadog`) reaches it through
//! the elevation seam (`sudo seadog-priv <verb> …`).
//!
//! ## Trust model (the whole point of this binary)
//! The helper **trusts nothing** from the front-end. Every argument is
//! re-validated independently against the helper's *own* `Config` load
//! (`/etc/seadog/config.yaml`, `$SEADOG_CONFIG` override for tests):
//!
//! - It does NOT depend on the `seadog` crate — the untrusted SSH-command
//!   parser is never linked in here.
//! - It does NOT allocate — `provision` receives the front-end-allocated
//!   vmid/ip/mac/guid/name and re-checks them, then creates the guest.
//! - It does NOT touch the DB in this phase — `teardown` re-triangulates
//!   against **live PVE** (`Kento::list_guests`), never the DB, because
//!   "root never blindly trusts the DB for a destroy."
//!
//! Every verb emits **JSON on stdout** (the front-end parses it); an error
//! emits JSON on stderr and exits non-zero.

mod owners;
mod provision;
mod set_meta;
mod start_sshd;
mod teardown;
mod verify;

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};

// The reaper entry points live in the library face (so the integration
// suite can drive them); the binary calls into them like any other module.
use seadog_priv::{sweep, watch};

use seadog_core::config::Config;
use seadog_core::kento::Kento;
use seadog_core::models::Mode;

/// Default config path; overridable by `$SEADOG_CONFIG` (tests).
const DEFAULT_CONFIG: &str = "/etc/seadog/config.yaml";

/// The privileged helper CLI.
#[derive(Debug, Parser)]
#[command(name = "seadog-priv", version, about = "seadog privileged helper")]
struct Cli {
    #[command(subcommand)]
    verb: Verb,
}

/// Every privileged verb the front-end can elevate. The argv shape here is
/// the **contract** the front-end emits (see `seadog::elevate`).
#[derive(Debug, Subcommand)]
enum Verb {
    /// Create a guest with the front-end-allocated identifiers.
    Provision(provision::ProvisionArgs),
    /// Destroy a guest after re-triangulating it against live PVE.
    Teardown(teardown::TeardownArgs),
    /// Narrow metadata update (deadline/description) on a seadog guest.
    SetMeta(set_meta::SetMetaArgs),
    /// Start the in-CT sshd on a verified seadog LXC.
    StartSshd(start_sshd::StartSshdArgs),
    /// Reaper watcher loop: fast self-extinguishing sweep loop (flock
    /// singleton; exits when idle).
    Watch,
    /// One-shot sweep: the 60-min systemd-timer backstop.
    Sweep,
    /// Authorize a key for an owner in the root-owned authorized_keys.
    AddOwner(owners::AddOwnerArgs),
    /// List the owner→key mappings in the root-owned authorized_keys.
    ListOwners(owners::ListOwnersArgs),
    /// Remove an owner's mapping(s) from the root-owned authorized_keys.
    RemoveOwner(owners::RemoveOwnerArgs),
}

impl Verb {
    /// Short stable name for the per-op journald log line.
    fn name(&self) -> &'static str {
        match self {
            Verb::Provision(_) => "provision",
            Verb::Teardown(_) => "teardown",
            Verb::SetMeta(_) => "set-meta",
            Verb::StartSshd(_) => "start-sshd",
            Verb::Watch => "watch",
            Verb::Sweep => "sweep",
            Verb::AddOwner(_) => "add-owner",
            Verb::ListOwners(_) => "list-owners",
            Verb::RemoveOwner(_) => "remove-owner",
        }
    }
}

/// Parse the `--mode <lxc|vm>` value the same way everywhere, rejecting
/// anything else (the helper trusts no mode token from the front-end).
fn parse_mode(s: &str) -> Result<Mode> {
    Mode::from_str_opt(s).ok_or_else(|| anyhow!("invalid mode '{s}' (expected lxc|vm)"))
}

/// Refuse to run unless `euid == 0`.
///
/// Takes `euid` as a parameter (rather than reading it) so the guard is
/// unit-testable without actually being root: `main` calls it with
/// `unsafe { libc::geteuid() }`.
fn ensure_root(euid: u32) -> Result<()> {
    if euid != 0 {
        bail!("seadog-priv must run as root (euid 0), but euid is {euid}");
    }
    Ok(())
}

/// Resolve the config path (`$SEADOG_CONFIG` override, else the default)
/// and load + validate it. The helper re-loads its own config — it never
/// trusts config values relayed by the front-end.
fn load_config() -> Result<Config> {
    let path = std::env::var("SEADOG_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());
    let config = Config::from_path(&path).map_err(|e| anyhow!("loading config {path}: {e}"))?;
    config
        .validate()
        .map_err(|e| anyhow!("config {path} is invalid: {e}"))?;
    Ok(config)
}

/// Dispatch one verb against a [`Kento`] backend and the loaded config.
///
/// Split out from `main` (which selects the real backend + does the euid
/// guard) so tests drive it directly with a `FakeKento` and a fixture
/// config. Returns the JSON the verb prints on success.
/// `dispatch` covers the verbs whose behavior is fully determined by their
/// args + the `Kento`/`Config` seam. `watch`/`sweep` additionally need DB
/// access (deadlines + heartbeat live in `$SEADOG_DB`); they open the DB
/// inside their own modules (`sweep::run` / `watch::run`) so provision/
/// teardown/etc. keep their exact signatures and never touch the DB. `main`
/// routes those two there directly.
fn dispatch(verb: &Verb, kento: &dyn Kento, config: &Config) -> Result<Value> {
    match verb {
        Verb::Provision(args) => provision::run(args, kento, config),
        Verb::Teardown(args) => teardown::run(args, kento, config),
        Verb::SetMeta(args) => set_meta::run(args, kento, config),
        Verb::StartSshd(args) => start_sshd::run(args, kento, config),
        // watch/sweep open the DB themselves (they are the only DB-touching
        // verbs); `now` is wall-clock in prod.
        Verb::Sweep => sweep::run(kento, config, wall_clock_now()),
        Verb::Watch => watch::run(kento, config),
        // Owner-management verbs touch only the root-owned authorized_keys
        // file — no Kento backend, no DB — so they bypass that part of the
        // seam (like watch/sweep bypass others). `kento` is unused here.
        Verb::AddOwner(a) => owners::add_owner(a),
        Verb::ListOwners(a) => owners::list_owners(a),
        Verb::RemoveOwner(a) => owners::remove_owner(a),
    }
}

/// Wall-clock seconds since the unix epoch (the `sweep` one-shot's clock;
/// the watch loop reads its own per-tick clock internally).
fn wall_clock_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Log every privileged op to journald (best-effort, non-fatal): the
/// resolved owner, the verb, and the target. Logging must never stop the
/// op, so failures are swallowed by the tracing layer itself.
fn log_op(verb: &Verb) {
    let (owner, target): (&str, String) = match verb {
        Verb::Provision(a) => (a.owner.as_str(), format!("vmid {}", a.vmid)),
        Verb::Teardown(a) => (a.owner.as_str(), format!("vmid {}", a.vmid)),
        Verb::SetMeta(a) => ("-", format!("vmid {}", a.vmid)),
        Verb::StartSshd(a) => ("-", format!("vmid {}", a.vmid)),
        Verb::Watch | Verb::Sweep => ("-", "-".to_string()),
        Verb::AddOwner(a) => (a.owner.as_str(), a.owner.clone()),
        Verb::RemoveOwner(a) => (a.owner.as_str(), a.owner.clone()),
        Verb::ListOwners(_) => ("-", "-".to_string()),
    };
    tracing::info!(
        owner = owner,
        verb = verb.name(),
        target = %target,
        "seadog-priv privileged op"
    );
}

fn main() {
    // Shared-DB footgun: the SQLite WAL/SHM sidecars must stay
    // group-writable (group `seadog`) so the testenv front-end and the root
    // reaper can both write the DB. The setgid `/var/lib/seadog` dir fixes
    // group *ownership*; this fixes the file *mode* regardless of how sudo
    // (watcher) or systemd (sweeper) leaves our umask. Must run before any
    // file is created.
    unsafe { libc::umask(0o002) };

    seadog_core::notify::init_logging();

    let cli = Cli::parse();

    // EUID guard FIRST — refuse before doing anything privileged.
    let euid = unsafe { libc::geteuid() };
    if let Err(e) = ensure_root(euid) {
        emit_err(&e);
        std::process::exit(1);
    }

    let config = match load_config() {
        Ok(c) => c,
        Err(e) => {
            emit_err(&e);
            std::process::exit(1);
        }
    };

    // Per-op journald audit line (non-fatal).
    log_op(&cli.verb);

    // Real backend selection. RealKento is feature-gated; without the
    // feature the helper still builds (compiles to the FakeKento path is
    // NOT acceptable for prod, so we hard-error to avoid silently faking a
    // privileged op).
    let result = run_with_real_backend(&cli.verb, &config);

    match result {
        Ok(v) => {
            println!("{v}");
        }
        Err(e) => {
            emit_err(&e);
            std::process::exit(1);
        }
    }
}

/// Print an error as JSON on stderr (the front-end's `elevate` captures it).
fn emit_err(e: &anyhow::Error) {
    let v = json!({ "ok": false, "error": e.to_string() });
    eprintln!("{v}");
}

#[cfg(feature = "real-kento")]
fn run_with_real_backend(verb: &Verb, config: &Config) -> Result<Value> {
    let kento = seadog_core::kento::RealKento::new();
    dispatch(verb, &kento, config)
}

#[cfg(not(feature = "real-kento"))]
fn run_with_real_backend(verb: &Verb, config: &Config) -> Result<Value> {
    // Built without the privileged backend: every Kento op refuses rather
    // than silently operating against a fake. We still route through
    // `dispatch` (so the same arg re-validation runs and nothing is dead
    // code), but the backend hard-errors at the first privileged call.
    // Production builds with the default `real-kento` feature.
    struct NoBackend;
    impl Kento for NoBackend {
        fn list_guests(
            &self,
            _vmid_range: (u32, u32),
        ) -> std::result::Result<Vec<seadog_core::identity::GuestSignals>, seadog_core::Error>
        {
            Err(no_backend_err())
        }
        fn teardown(&self, _vmid: u32, _mode: Mode) -> std::result::Result<(), seadog_core::Error> {
            Err(no_backend_err())
        }
        fn provision(
            &self,
            _spec: &seadog_core::kento::ProvisionSpec,
        ) -> std::result::Result<(), seadog_core::Error> {
            Err(no_backend_err())
        }
        fn set_meta(
            &self,
            _vmid: u32,
            _mode: Mode,
            _meta: &seadog_core::kento::MetaUpdate,
        ) -> std::result::Result<(), seadog_core::Error> {
            Err(no_backend_err())
        }
        fn start_sshd(&self, _vmid: u32) -> std::result::Result<(), seadog_core::Error> {
            Err(no_backend_err())
        }
    }
    fn no_backend_err() -> seadog_core::Error {
        seadog_core::Error::Kento(
            "seadog-priv was built without the real-kento backend; rebuild with --features real-kento".to_string(),
        )
    }
    dispatch(verb, &NoBackend, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_root_accepts_zero() {
        assert!(ensure_root(0).is_ok());
    }

    #[test]
    fn ensure_root_rejects_nonzero() {
        assert!(ensure_root(1000).is_err());
        assert!(ensure_root(1).is_err());
    }

    #[test]
    fn parse_mode_roundtrips_and_rejects() {
        assert_eq!(parse_mode("lxc").unwrap(), Mode::Lxc);
        assert_eq!(parse_mode("vm").unwrap(), Mode::Vm);
        assert!(parse_mode("container").is_err());
        assert!(parse_mode("").is_err());
    }

    #[test]
    fn watch_and_sweep_run_against_an_isolated_db() {
        // With no active envs, both verbs run cleanly: sweep over an empty
        // DB returns ok; watch acquires the lock, self-extinguishes on the
        // first idle tick, and returns ok. We point both at temp paths so
        // the test never touches the prod DB / lock.
        let cfg = crate::test_support::config();
        let k = seadog_core::kento::FakeKento::new();
        let _g = crate::test_support::TempEnv::isolated();

        let v = dispatch(&Verb::Sweep, &k, &cfg).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["reaped"], 0);

        let v = dispatch(&Verb::Watch, &k, &cfg).unwrap();
        assert_eq!(v["ok"], true);
        // Either it ran one idle tick, or (if a stray lock existed) reported
        // already-running; both are ok=true.
        assert!(v["watcher"].is_string());
    }
}

/// Shared test fixtures for the verb modules' unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use seadog_core::config::Config;

    /// A config whose allowlist has a dual-mode `loom` and a vm-only
    /// `vmonly`, with the default `[10000, 10999]` vmid range.
    pub fn config() -> Config {
        let yaml = r#"
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

    /// Point `$SEADOG_DB` + `$SEADOG_WATCHER_LOCK` at fresh temp paths for a
    /// test that exercises the prod `dispatch` path (which opens the DB /
    /// flock by env). Restores the prior values on drop.
    pub struct TempEnv {
        _dir: std::path::PathBuf,
        prev_db: Option<std::ffi::OsString>,
        prev_lock: Option<std::ffi::OsString>,
    }

    impl TempEnv {
        pub fn isolated() -> Self {
            let unique = format!(
                "seadog-priv-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let dir = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&dir).unwrap();
            let prev_db = std::env::var_os("SEADOG_DB");
            let prev_lock = std::env::var_os("SEADOG_WATCHER_LOCK");
            std::env::set_var("SEADOG_DB", dir.join("seadog.db"));
            std::env::set_var("SEADOG_WATCHER_LOCK", dir.join("watcher.lock"));
            TempEnv {
                _dir: dir,
                prev_db,
                prev_lock,
            }
        }
    }

    impl Drop for TempEnv {
        fn drop(&mut self) {
            match &self.prev_db {
                Some(v) => std::env::set_var("SEADOG_DB", v),
                None => std::env::remove_var("SEADOG_DB"),
            }
            match &self.prev_lock {
                Some(v) => std::env::set_var("SEADOG_WATCHER_LOCK", v),
                None => std::env::remove_var("SEADOG_WATCHER_LOCK"),
            }
        }
    }
}
