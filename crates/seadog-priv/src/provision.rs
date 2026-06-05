//! `seadog-priv provision` — realize a guest from the front-end-allocated
//! identifiers, after **independently re-validating every argument**.
//!
//! Allocation is the front-end's job; this verb does NOT allocate. It
//! receives the allocated vmid/ip/mac/guid/name + the server-resolved
//! image ref and creates the guest with exactly those values, writing the
//! seadog guest-side markers (name prefix, GUID+owner description block,
//! assigned MAC) so a later teardown can triangulate it.
//!
//! The security-critical re-checks the helper performs (trusting nothing
//! from the front-end):
//! - `--vmid` lies in `config.allocation.vmid_range`,
//! - `--name` is a valid `seadog-…` DNS label,
//! - `--mode` ∈ {lxc, vm},
//! - `--mac` matches `^([0-9a-f]{2}:){5}[0-9a-f]{2}$`,
//! - `--ip` parses as an IPv4 address,
//! - `--image-ref` is an **allowlisted** ref for the requested mode — a
//!   compromised front-end cannot smuggle an arbitrary OCI ref past this.

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
use seadog_core::validate::{validate_guest_name, validate_vmid};

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

/// `provision --owner <name> --guid <uuid> --vmid <u32> --ip <ipv4>
/// --mac <mac> --name <label> --mode <lxc|vm> --image-ref <ref>`.
#[derive(Debug, Args)]
pub struct ProvisionArgs {
    /// Resolved owner (trusted from the front-end; recorded in the guest).
    #[arg(long)]
    pub owner: String,
    /// Instance GUID (uuid-v4) minted by the front-end.
    #[arg(long)]
    pub guid: String,
    /// Allocated Proxmox guest id.
    #[arg(long)]
    pub vmid: u32,
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

/// Run `provision`: re-validate all args, create the guest, write markers,
/// and (lxc only) start the in-CT sshd. Prints `{ok, vmid, name, …}`.
pub fn run(args: &ProvisionArgs, kento: &dyn Kento, config: &Config) -> Result<Value> {
    // Re-validate EVERY field against the helper's own config.
    let mode = parse_mode(&args.mode)?;
    validate_vmid(args.vmid, config).map_err(|e| anyhow!(e))?;
    validate_guest_name(&args.name).map_err(|e| anyhow!(e))?;
    validate_mac(&args.mac)?;
    let _ip: Ipv4Addr = args
        .ip
        .parse()
        .map_err(|e| anyhow!("ip '{}' is not a valid IPv4 address: {e}", args.ip))?;
    if args.guid.trim().is_empty() {
        bail!("guid must not be empty");
    }
    if args.owner.trim().is_empty() {
        bail!("owner must not be empty");
    }
    validate_image_ref(&args.image_ref, mode, config)?;

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

    // Create the guest with exactly the allocated params + markers. The
    // bridge + IP prefix/gateway come from the helper's own config (kento
    // owns networking; we pass `--network bridge=<bridge> --ip <ip>/<prefix>
    // --gateway <gw>`).
    let spec = ProvisionSpec {
        vmid: args.vmid,
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
    };
    // `--mac` is VM-only. For a VM the effective MAC is the minted one; for
    // an LXC the MAC is unobservable via `pct config`, so the outcome MAC is
    // `None`. The effective MAC flows back to the front-end (serialized as a
    // string for a VM, JSON `null` for an LXC) so it records the REAL mac (or
    // `""` for the unobservable LXC) on the DB row.
    let outcome = kento.provision(&spec).map_err(|e| anyhow!(e))?;

    // loom ships sshd disabled; on the LXC path bring it up after create.
    let sshd_started = if mode == Mode::Lxc {
        kento.start_sshd(args.vmid).map_err(|e| anyhow!(e))?;
        true
    } else {
        false
    };

    Ok(json!({
        "ok": true,
        "vmid": args.vmid,
        "name": args.name,
        "mode": mode.as_str(),
        "guid": args.guid,
        "owner": args.owner,
        // The EFFECTIVE mac the guest actually carries: a string for a VM
        // (the minted MAC), JSON `null` for an LXC (unobservable). The
        // front-end records the string, or `""` when null.
        "mac": outcome.mac,
        "sshd_started": sshd_started,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::config;
    use seadog_core::identity::{extract_desc_guid, extract_desc_owner};
    use seadog_core::kento::FakeKento;

    fn args() -> ProvisionArgs {
        ProvisionArgs {
            owner: "alice".into(),
            guid: "11111111-1111-4111-8111-111111111111".into(),
            vmid: 10010,
            ip: "192.168.99.200".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            name: "seadog-alice-proj-ab12".into(),
            mode: "lxc".into(),
            image_ref: "registry.example.com/loom:1.0".into(),
        }
    }

    #[test]
    fn valid_lxc_provisions_with_exact_params_and_starts_sshd() {
        let cfg = config();
        let k = FakeKento::new();
        let out = run(&args(), &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["sshd_started"], true);
        // LXC: the MAC is unobservable via pct config, so the effective MAC
        // in the output is JSON null (the front-end records "" for it).
        assert!(out["mac"].is_null());

        // FakeKento.provision was called with the exact params.
        let provs = k.provisions();
        assert_eq!(provs.len(), 1);
        let p = &provs[0];
        assert_eq!(p.vmid, 10010);
        assert_eq!(p.mode, Mode::Lxc);
        assert_eq!(p.name, "seadog-alice-proj-ab12");
        assert_eq!(p.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(p.ip, "192.168.99.200");
        assert_eq!(p.owner, "alice");

        // lxc path started sshd on the right vmid.
        assert_eq!(k.sshd_starts(), vec![10010]);

        // The realized guest now triangulates (markers written).
        let g = k.list_guests((10000, 10999)).unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(
            extract_desc_guid(g[0].description.as_deref()).as_deref(),
            Some("11111111-1111-4111-8111-111111111111")
        );
        assert_eq!(
            extract_desc_owner(g[0].description.as_deref()).as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn vm_path_does_not_start_sshd() {
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        a.mode = "vm".into();
        a.image_ref = "registry.example.com/vmonly:2.0".into();
        let out = run(&a, &k, &cfg).unwrap();
        assert_eq!(out["sshd_started"], false);
        assert!(k.sshd_starts().is_empty());
        assert_eq!(k.provisions().len(), 1);
        // VM: --mac is honored, so the effective MAC is the one we passed.
        assert_eq!(out["mac"], "aa:bb:cc:dd:ee:ff");
    }

    /// Point `$SEADOG_AUTHKEYS` at a fresh temp file seeded with a managed
    /// owner line, restoring the prior value on drop. Serialized via a
    /// process-global lock since the env var is shared.
    struct OwnerKeysEnv {
        dir: PathBuf,
        prev: Option<std::ffi::OsString>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    static OWNERKEYS_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    impl OwnerKeysEnv {
        fn new(contents: &str) -> Self {
            let guard = OWNERKEYS_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let unique = format!(
                "seadog-provision-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let dir = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("authorized_keys");
            std::fs::write(&path, contents).unwrap();
            let prev = std::env::var_os("SEADOG_AUTHKEYS");
            std::env::set_var("SEADOG_AUTHKEYS", &path);
            OwnerKeysEnv {
                dir,
                prev,
                _guard: guard,
            }
        }
    }

    impl Drop for OwnerKeysEnv {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("SEADOG_AUTHKEYS", v),
                None => std::env::remove_var("SEADOG_AUTHKEYS"),
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    const TEST_BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBVL8h1uvNvR2v2c0Yk6Yz0mYy8w0cZk6Q1yK0a8mDcL";

    fn managed_line(owner: &str) -> String {
        format!(
            "command=\"/usr/lib/seadog/seadog --owner {owner}\",restrict ssh-ed25519 {TEST_BLOB} {owner}@host"
        )
    }

    #[test]
    fn injects_owner_key_and_user_for_lxc_and_cleans_up() {
        let _env = OwnerKeysEnv::new(&format!("{}\n", managed_line("alice")));
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
        let _env = OwnerKeysEnv::new(&format!("{}\n", managed_line("alice")));
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
        let _env = OwnerKeysEnv::new(&format!("{}\n", managed_line("someone-else")));
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
    fn rejects_out_of_range_vmid() {
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        a.vmid = 105; // a production VM id, far out of range
        assert!(run(&a, &k, &cfg).is_err());
        assert!(k.provisions().is_empty());
    }

    #[test]
    fn rejects_bad_name() {
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        a.name = "not-a-seadog-name".into();
        assert!(run(&a, &k, &cfg).is_err());
        assert!(k.provisions().is_empty());
    }

    #[test]
    fn rejects_bad_mac() {
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
    fn rejects_bad_ip() {
        let cfg = config();
        let k = FakeKento::new();
        let mut a = args();
        a.ip = "999.0.0.1".into();
        assert!(run(&a, &k, &cfg).is_err());
        assert!(k.provisions().is_empty());
    }
}
