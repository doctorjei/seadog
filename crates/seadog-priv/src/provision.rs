//! `seadog-priv provision` — realize a guest from the front-end-allocated
//! identifiers, after **independently re-validating every argument**.
//!
//! Allocation is the front-end's job; this verb does NOT allocate. It
//! receives the allocated ip/mac/guid/name + the server-resolved image ref
//! and creates the guest with exactly those values, injecting the seadog
//! identity anchor (`SEADOG_GUID`/`SEADOG_OWNER` env) so a later teardown
//! can re-confirm it. No vmid: kento auto-assigns where the backend has one.
//!
//! The security-critical re-checks the helper performs (trusting nothing
//! from the front-end):
//! - `--name` is a valid `seadog-…` DNS label,
//! - `--mode` ∈ {lxc, vm},
//! - `--mac` matches `^([0-9a-f]{2}:){5}[0-9a-f]{2}$`,
//! - `--ip` parses as an IPv4 address,
//! - `--image-ref` is an **allowlisted** ref for the requested mode — a
//!   compromised front-end cannot smuggle an arbitrary OCI ref past this,
//! - `--allow-nesting` matches the allowlist entry for the resolved ref —
//!   the front-end resolves nesting from the served *alias* but only the
//!   *ref* crosses the boundary, so the helper re-confirms SOME entry has
//!   this ref AND this nesting setting (the privilege-boundary re-check).

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use regex::Regex;
use serde_json::{json, Value};

use seadog_core::config::Config;
use seadog_core::kento::{Kento, ProvisionSpec};
use seadog_core::models::Mode;
use seadog_core::validate::{validate_guest_name, validate_owner_name};

use crate::owners::owner_key_bodies;
use crate::parse_mode;

/// An RAII-cleaned temp file holding the owner's authorized pubkey line(s),
/// created mode `0600` and removed on drop (success OR error path). Never
/// logs its path or contents.
struct OwnerKeyFile {
    path: PathBuf,
}

impl OwnerKeyFile {
    /// Materialize `bodies` (one `ssh-…` line each) into a fresh `0600` file
    /// in `dir` (a root-only directory — the authorized_keys parent). The
    /// file is created with `O_CREAT|O_EXCL` so it cannot clobber/leak into
    /// an attacker-planted path, and `0600` so only root can read the key.
    fn create(dir: &Path, bodies: &[String]) -> Result<Self> {
        let name = format!(
            ".seadog-ownerkey.{}.{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let path = dir.join(name);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            // Deliberately omit the path from the error to avoid leaking it.
            .context("creating owner-key temp file")?;
        for body in bodies {
            f.write_all(body.as_bytes()).context("writing owner key")?;
            f.write_all(b"\n").context("writing owner key")?;
        }
        f.flush().ok();
        Ok(OwnerKeyFile { path })
    }
}

impl Drop for OwnerKeyFile {
    fn drop(&mut self) {
        // Best-effort removal on every path (success + error). Never log the
        // path or contents.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `provision --owner <name> --guid <uuid> --ip <ipv4> --mac <mac>
/// --name <label> --mode <lxc|vm> --image-ref <ref>
/// --allow-nesting <true|false>`.
#[derive(Debug, Args)]
pub struct ProvisionArgs {
    /// Resolved owner (trusted from the front-end; recorded in the guest).
    #[arg(long)]
    pub owner: String,
    /// Instance GUID (uuid-v4) minted by the front-end.
    #[arg(long)]
    pub guid: String,
    /// Leased IPv4.
    #[arg(long)]
    pub ip: String,
    /// Assigned MAC.
    #[arg(long)]
    pub mac: String,
    /// `seadog-…` guest name.
    #[arg(long)]
    pub name: String,
    /// `lxc` or `vm`.
    #[arg(long)]
    pub mode: String,
    /// Server-resolved OCI ref (must be allowlisted for the mode).
    #[arg(long = "image-ref")]
    pub image_ref: String,
    /// Whether nesting is permitted, resolved by the front-end from the
    /// served image alias. Re-validated here against the allowlist.
    #[arg(long = "allow-nesting", action = clap::ArgAction::Set)]
    pub allow_nesting: bool,
    /// Optional memory ceiling-clamped request (MB). Forwarded to kento
    /// `--memory`; omitted ⇒ kento default.
    #[arg(long)]
    pub memory: Option<u32>,
    /// Optional cores ceiling-clamped request. Forwarded to kento `--cores`;
    /// omitted ⇒ kento default.
    #[arg(long)]
    pub cores: Option<u32>,
}

/// Compiled MAC regex: six lowercase hex octets, colon-separated.
fn mac_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$").expect("static mac regex"))
}

/// Re-validate the MAC shape independently of whatever the front-end sent.
fn validate_mac(mac: &str) -> Result<()> {
    if !mac_re().is_match(mac) {
        bail!("mac '{mac}' is not a lowercase xx:xx:xx:xx:xx:xx address");
    }
    Ok(())
}

/// Re-validate that `image_ref` is an allowlisted ref for `mode`.
///
/// This is the server-side enforcement of "never an arbitrary caller ref":
/// even a fully-compromised front-end can only ask for an OCI ref that
/// appears verbatim in `config.images` AND whose entry permits the
/// requested mode. Any other ref is refused.
fn validate_image_ref(image_ref: &str, mode: Mode, config: &Config) -> Result<()> {
    let allowed = config
        .images
        .values()
        .any(|img| img.image_ref == image_ref && img.modes.contains(&mode));
    if !allowed {
        bail!(
            "image-ref '{image_ref}' is not allowlisted for mode '{}' (rejecting arbitrary ref)",
            mode.as_str()
        );
    }
    Ok(())
}

/// Boundary re-clamp for an explicit sizing request (`--memory`/`--cores`):
/// trust nothing from the front-end. Reject `Some(0)` (kento requires ≥ 1) and
/// clamp `Some(v)` to `ceiling` when `ceiling != 0` (0 ⇒ unlimited/no clamp).
/// `None` stays `None` so kento applies its own default.
fn clamp_resource(req: Option<u32>, ceiling: u32, label: &str) -> Result<Option<u32>> {
    match req {
        None => Ok(None),
        Some(0) => bail!("--{label} must be >= 1"),
        Some(v) if ceiling == 0 => Ok(Some(v)),
        Some(v) => Ok(Some(v.min(ceiling))),
    }
}

/// Run `provision`: re-validate all args, then create the guest (kento
/// injects the seadog identity anchor + owner key). Prints `{ok, name, …,
/// vmid, mac, ssh_host_key_fps}` from the [`ProvisionOutcome`].
pub fn run(args: &ProvisionArgs, kento: &dyn Kento, config: &Config) -> Result<Value> {
    // Re-validate EVERY field against the helper's own config.
    let mode = parse_mode(&args.mode)?;
    validate_guest_name(&args.name).map_err(|e| anyhow!(e))?;
    validate_mac(&args.mac)?;
    let _ip: Ipv4Addr = args
        .ip
        .parse()
        .map_err(|e| anyhow!("ip '{}' is not a valid IPv4 address: {e}", args.ip))?;
    if args.guid.trim().is_empty() {
        bail!("guid must not be empty");
    }
    validate_owner_name(&args.owner).map_err(|e| anyhow!(e))?;
    validate_image_ref(&args.image_ref, mode, config)?;

    // Privilege-boundary re-validation of the nesting request: the front-end
    // resolved it from the served alias, but only the OCI ref crossed the
    // boundary. Confirm SOME allowlist entry has this ref AND this nesting
    // setting — else refuse (a compromised front-end can't smuggle nesting on
    // an image whose entry forbids it).
    if !config.nesting_ok_for_ref(&args.image_ref, args.allow_nesting) {
        bail!("nesting setting not permitted for image");
    }

    // Resolve the login user the owner's key will authorize: the image
    // entry's pinned `user` (matched by the resolved ref) else the
    // top-level `default_user` (itself `"root"`). Never errors (fail-open).
    let ssh_key_user = config.login_user_for_ref(&args.image_ref);

    // Re-derive the OWNER's authorized pubkey(s) from the helper's OWN
    // authorized_keys by owner name (never key material from the front-end).
    // If the owner has no key (shouldn't happen — validated upstream), we
    // proceed WITHOUT `--ssh-key` (fail-open) rather than fail the create.
    // The temp file (mode 0600, root-owned, RAII-removed on every path) is
    // bound to `_owner_key` so it lives until after `kento.provision` returns.
    let key_bodies = owner_key_bodies(&args.owner).unwrap_or_default();
    // `.ok()` → fail-open: a temp-file creation failure never blocks a create,
    // and the error (which omits the path) is dropped rather than logged.
    let _owner_key = if key_bodies.is_empty() {
        None
    } else {
        OwnerKeyFile::create(&crate::owners::authkeys_dir(), &key_bodies).ok()
    };
    let ssh_key_file = _owner_key.as_ref().map(|f| f.path.clone());

    // BOUNDARY re-validation/clamp of the sizing requests (same posture as the
    // mac/ip/name/nesting re-checks above — trust nothing from the front-end).
    // Reject 0 (kento requires ≥ 1) and re-clamp to the operator ceilings; a
    // ceiling of 0 means unlimited/no clamp.
    let mem_ceiling = config.allocation.caps.max_memory_mb;
    let cores_ceiling = config.allocation.caps.max_cores;
    let memory = clamp_resource(args.memory, mem_ceiling, "memory")?;
    let cores = clamp_resource(args.cores, cores_ceiling, "cores")?;

    // Create the guest with exactly the allocated params + markers. The
    // bridge + IP prefix/gateway come from the helper's own config (kento
    // owns networking; we pass `--network bridge=<bridge> --ip <ip>/<prefix>
    // --gateway <gw>`).
    let spec = ProvisionSpec {
        mode,
        image_ref: args.image_ref.clone(),
        name: args.name.clone(),
        mac: args.mac.clone(),
        ip: args.ip.clone(),
        prefix: config.allocation.ip_pool.prefix,
        gateway: config.allocation.ip_pool.gateway.to_string(),
        bridge: config.allocation.bridge.clone(),
        guid: args.guid.clone(),
        owner: args.owner.clone(),
        ssh_key_file,
        ssh_key_user,
        allow_nesting: args.allow_nesting,
        memory,
        cores,
    };
    // kento reports the realized signals (MAC + host-key fps + backend vmid
    // where one exists) via `inspect --json`. The helper just returns them;
    // the front-end records them on the DB row.
    let outcome = kento.provision(&spec).map_err(|e| anyhow!(e))?;

    Ok(json!({
        "ok": true,
        "name": args.name,
        "mode": mode.as_str(),
        "guid": args.guid,
        "owner": args.owner,
        // Realized signals straight from the ProvisionOutcome (kento
        // `inspect`): the backend vmid (JSON `null` for backend-neutral
        // runtimes), the effective MAC, and the SSH host-key fingerprints.
        "vmid": outcome.vmid,
        "mac": outcome.mac,
        "ssh_host_key_fps": outcome.ssh_host_key_fps,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{config, AuthkeysEnv};
    use seadog_core::kento::FakeKento;

    fn args() -> ProvisionArgs {
        ProvisionArgs {
            owner: "alice".into(),
            guid: "11111111-1111-4111-8111-111111111111".into(),
            ip: "192.168.99.200".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            name: "seadog-alice-proj-ab12".into(),
            mode: "lxc".into(),
            image_ref: "registry.example.com/loom:1.0".into(),
            allow_nesting: false,
            memory: None,
            cores: None,
        }
    }

    #[test]
    fn valid_lxc_provisions_with_exact_params() {
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        let out = run(&args(), &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        // kento reports the realized signals back: an LXC has NO MAC (kento
        // reports a MAC for VM modes only), so `mac` is JSON null; host-key
        // fingerprints are still reported.
        assert!(out["mac"].is_null(), "LXC has no MAC");
        assert!(out["ssh_host_key_fps"].is_array());
        // FakeKento has no PVE backend → vmid is JSON null.
        assert!(out["vmid"].is_null());

        // FakeKento.provision was called with the exact params (no vmid).
        let provs = k.provisions();
        assert_eq!(provs.len(), 1);
        let p = &provs[0];
        assert_eq!(p.mode, Mode::Lxc);
        assert_eq!(p.name, "seadog-alice-proj-ab12");
        assert_eq!(p.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(p.ip, "192.168.99.200");
        assert_eq!(p.owner, "alice");

        // The realized instance now carries the seadog identity anchor.
        let live = k.list_instances().unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(
            live[0].guid.as_deref(),
            Some("11111111-1111-4111-8111-111111111111")
        );
        assert_eq!(live[0].owner.as_deref(), Some("alice"));
    }

    #[test]
    fn vm_path_provisions_and_reports_mac() {
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        a.mode = "vm".into();
        a.image_ref = "registry.example.com/vmonly:2.0".into();
        let out = run(&a, &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(k.provisions().len(), 1);
        // VM: --mac is honored, so the effective MAC is the one we passed.
        assert_eq!(out["mac"], "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn memory_cores_none_omitted() {
        // Default args carry no sizing ⇒ the recorded spec leaves both None so
        // kento applies its own default (no --memory/--cores in argv).
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        let out = run(&args(), &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        let p = &k.provisions()[0];
        assert_eq!(p.memory, None);
        assert_eq!(p.cores, None);
    }

    #[test]
    fn memory_cores_reach_spec_within_ceiling() {
        // Explicit requests below the (default 8192/8) ceilings reach the spec
        // verbatim.
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        a.memory = Some(2048);
        a.cores = Some(4);
        let out = run(&a, &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        let p = &k.provisions()[0];
        assert_eq!(p.memory, Some(2048));
        assert_eq!(p.cores, Some(4));
    }

    #[test]
    fn memory_cores_clamped_to_ceiling() {
        // A config with small operator ceilings (1024 MB / 2 cores). An
        // over-ceiling request is silently clamped at the helper boundary.
        let _env = AuthkeysEnv::new();
        let yaml = r#"
allocation:
  caps:
    max_memory_mb: 1024
    max_cores: 2
images:
  loom:
    ref: "registry.example.com/loom:1.0"
    modes: [lxc, vm]
"#;
        let cfg = seadog_core::config::Config::from_yaml_str(yaml).unwrap();
        cfg.validate().unwrap();
        let k = FakeKento::new();
        let mut a = args();
        a.memory = Some(4096);
        a.cores = Some(8);
        let out = run(&a, &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        let p = &k.provisions()[0];
        assert_eq!(p.memory, Some(1024));
        assert_eq!(p.cores, Some(2));
    }

    #[test]
    fn memory_zero_rejected() {
        // kento requires memory ≥ 1; a 0 request is refused at the boundary and
        // no provision is recorded.
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        a.memory = Some(0);
        assert!(run(&a, &k, &cfg).is_err());
        assert!(k.provisions().is_empty());
    }

    #[test]
    fn allow_nesting_true_passes_revalidation_and_reaches_spec() {
        // A served entry whose ref permits nesting; the front-end passed
        // --allow-nesting true. Re-validation passes and the flag reaches the
        // spec (FakeKento records it).
        let _env = AuthkeysEnv::new();
        let yaml = r#"
images:
  nested:
    ref: "registry.example.com/nested:1.0"
    modes: [lxc, vm]
    allow_nesting: true
"#;
        let cfg = seadog_core::config::Config::from_yaml_str(yaml).unwrap();
        cfg.validate().unwrap();
        let k = FakeKento::new();
        let mut a = args();
        a.image_ref = "registry.example.com/nested:1.0".into();
        a.allow_nesting = true;
        let out = run(&a, &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(k.provision_allow_nesting(), vec![true]);
        assert!(k.provisions()[0].allow_nesting);
    }

    #[test]
    fn allow_nesting_not_permitted_is_rejected_at_revalidation() {
        // loom's entry has no allow_nesting (⇒ false). A front-end asking for
        // --allow-nesting true must be refused server-side, no provision.
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        a.allow_nesting = true; // not permitted for loom's ref
        assert!(run(&a, &k, &cfg).is_err());
        assert!(k.provisions().is_empty());
    }

    const TEST_BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBVL8h1uvNvR2v2c0Yk6Yz0mYy8w0cZk6Q1yK0a8mDcL";

    fn managed_line(owner: &str) -> String {
        format!(
            "command=\"/usr/lib/seadog/seadog --owner {owner}\",restrict ssh-ed25519 {TEST_BLOB} {owner}@host"
        )
    }

    #[test]
    fn injects_owner_key_and_user_for_lxc_and_cleans_up() {
        let _env = AuthkeysEnv::seeded(&format!("{}\n", managed_line("alice")));
        let cfg = config();
        let k = FakeKento::new();
        // lxc path (loom ref is dual-mode in the fixture config).
        let out = run(&args(), &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);

        let provs = k.provisions();
        assert_eq!(provs.len(), 1);
        let p = &provs[0];
        // The owner's key was materialized and passed (argv `--ssh-key`).
        let key_path = p.ssh_key_file.clone().expect("ssh_key_file passed");
        // Default login user (no per-image `user` in the fixture) is "root".
        assert_eq!(p.ssh_key_user, "root");
        // Cleanup: the temp keyfile is removed after provision returns.
        assert!(
            !key_path.exists(),
            "owner-key temp file must be cleaned up after provision"
        );
    }

    #[test]
    fn injects_owner_key_for_vm_too() {
        let _env = AuthkeysEnv::seeded(&format!("{}\n", managed_line("alice")));
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        a.mode = "vm".into();
        a.image_ref = "registry.example.com/vmonly:2.0".into();
        run(&a, &k, &cfg).unwrap();

        let provs = k.provisions();
        let p = &provs[0];
        assert!(p.ssh_key_file.is_some(), "vm path must also inject the key");
        assert!(!p.ssh_key_file.clone().unwrap().exists(), "cleaned up");
        assert_eq!(p.ssh_key_user, "root");
    }

    #[test]
    fn no_owner_key_provisions_fail_open_without_key() {
        // An authorized_keys with NO line for this owner → fail-open: the
        // create still proceeds, just without `--ssh-key`.
        let _env = AuthkeysEnv::seeded(&format!("{}\n", managed_line("someone-else")));
        let cfg = config();
        let k = FakeKento::new();
        let out = run(&args(), &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        let provs = k.provisions();
        assert_eq!(provs.len(), 1);
        assert!(
            provs[0].ssh_key_file.is_none(),
            "no owner key → no --ssh-key (fail-open)"
        );
    }

    #[test]
    fn rejects_bad_name() {
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        a.name = "not-a-seadog-name".into();
        assert!(run(&a, &k, &cfg).is_err());
        assert!(k.provisions().is_empty());
    }

    #[test]
    fn rejects_bad_mac() {
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        a.mac = "AA:BB:CC:DD:EE:FF".into(); // uppercase rejected
        assert!(run(&a, &k, &cfg).is_err());
        let mut a2 = args();
        a2.mac = "zz:zz:zz:zz:zz:zz".into();
        assert!(run(&a2, &k, &cfg).is_err());
        assert!(k.provisions().is_empty());
    }

    #[test]
    fn rejects_mode_image_does_not_allow() {
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        // vmonly only allows vm; ask for lxc with its ref.
        let mut a = args();
        a.mode = "lxc".into();
        a.image_ref = "registry.example.com/vmonly:2.0".into();
        assert!(run(&a, &k, &cfg).is_err());
        assert!(k.provisions().is_empty());
    }

    #[test]
    fn rejects_non_allowlisted_image_ref() {
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        // A ref that is NOT in the allowlist — even from a compromised
        // front-end, this must be refused server-side.
        a.image_ref = "evil.example.com/backdoor:latest".into();
        assert!(run(&a, &k, &cfg).is_err());
        assert!(k.provisions().is_empty());
    }

    #[test]
    fn allow_nesting_value_form_argv_parses() {
        use clap::Parser;
        #[derive(Parser)]
        struct Harness {
            #[command(flatten)]
            a: ProvisionArgs,
        }
        // Mirror exactly what crates/seadog/src/verbs/create.rs builds.
        let base = [
            "provision",
            "--owner",
            "kanibako",
            "--guid",
            "11111111-1111-1111-1111-111111111111",
            "--ip",
            "10.0.4.192",
            "--mac",
            "00:11:22:33:44:55",
            "--name",
            "seadog-kanibako-p-abcd",
            "--mode",
            "lxc",
            "--image-ref",
            "localhost/gemet-bifrost-kento:1.7.2",
        ];
        for (val, expect) in [("false", false), ("true", true)] {
            let mut argv: Vec<&str> = base.to_vec();
            argv.push("--allow-nesting");
            argv.push(val);
            let h = Harness::try_parse_from(argv).expect("value-form --allow-nesting must parse");
            assert_eq!(h.a.allow_nesting, expect);
        }
    }

    #[test]
    fn rejects_bad_ip() {
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        a.ip = "999.0.0.1".into();
        assert!(run(&a, &k, &cfg).is_err());
        assert!(k.provisions().is_empty());
    }

    #[test]
    fn provision_failure_from_kento_propagates_as_err() {
        // The image-not-found / "kento does NOT auto-pull" class: all args are
        // valid (re-validation passes, so the provision IS attempted), but
        // kento itself fails the create. `run` must propagate the error — no
        // panic — rather than report `ok: true`. This exercises the
        // provision-failure path through real `run` code, not just FakeKento.
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        k.fail_provision("image not found in root podman store (kento does not auto-pull)");
        let err = run(&args(), &k, &cfg).unwrap_err();
        // The kento failure message surfaces in the error chain.
        assert!(
            err.to_string().contains("image not found"),
            "kento provision error should propagate, got: {err}"
        );
        // A failed provision realizes no instance: FakeKento records only
        // SUCCESSFUL provisions (the provision_fail hook returns before the
        // record, symmetric to its teardown_fail contract). That run() reached
        // kento at all is already proven above — the "image not found" text can
        // only originate from that hook inside FakeKento::provision, which run()
        // reaches only after re-validation passes.
        assert!(
            k.provisions().is_empty(),
            "a failed provision must leave no recorded instance"
        );
    }

    #[test]
    fn provision_quorum_loss_propagates() {
        // A quorum-loss on provision must propagate as an error (not be
        // swallowed or mis-mapped) so the caller stops cleanly. Args are valid,
        // so the provision is attempted and the global condition surfaces.
        let _env = AuthkeysEnv::new();
        let cfg = config();
        let k = FakeKento::new();
        k.set_quorum_lost("no quorum (pmxcfs read-only)");
        let err = run(&args(), &k, &cfg).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("quorum"),
            "quorum-loss should propagate, got: {err}"
        );
    }
}
