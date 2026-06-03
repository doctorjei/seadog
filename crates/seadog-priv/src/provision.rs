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

use std::net::Ipv4Addr;
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Result};
use clap::Args;
use regex::Regex;
use serde_json::{json, Value};

use seadog_core::config::Config;
use seadog_core::kento::{Kento, ProvisionSpec};
use seadog_core::models::Mode;
use seadog_core::validate::{validate_guest_name, validate_vmid};

use crate::parse_mode;

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

    // Create the guest with exactly the allocated params + markers.
    let spec = ProvisionSpec {
        vmid: args.vmid,
        mode,
        image_ref: args.image_ref.clone(),
        name: args.name.clone(),
        mac: args.mac.clone(),
        ip: args.ip.clone(),
        guid: args.guid.clone(),
        owner: args.owner.clone(),
    };
    kento.provision(&spec).map_err(|e| anyhow!(e))?;

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
            owner: "jei".into(),
            guid: "11111111-1111-4111-8111-111111111111".into(),
            vmid: 10010,
            ip: "192.168.0.200".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            name: "seadog-jei-proj-ab12".into(),
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

        // FakeKento.provision was called with the exact params.
        let provs = k.provisions();
        assert_eq!(provs.len(), 1);
        let p = &provs[0];
        assert_eq!(p.vmid, 10010);
        assert_eq!(p.mode, Mode::Lxc);
        assert_eq!(p.name, "seadog-jei-proj-ab12");
        assert_eq!(p.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(p.ip, "192.168.0.200");
        assert_eq!(p.owner, "jei");

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
            Some("jei")
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
