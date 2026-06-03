//! `seadog-priv teardown` — **the critical security gate.**
//!
//! Root never blindly trusts the DB for a destroy. Before tearing anything
//! down, the helper re-triangulates the live guest at `--vmid` against
//! **live PVE** (`Kento::list_guests`) and destroys ONLY when every check
//! passes:
//!
//! 1. **In range** — the vmid is inside `config.allocation.vmid_range`.
//! 2. **Seadog-marked** — the live guest has the `seadog-` name prefix
//!    AND a GUID marker in its description.
//! 3. **Instance keys match** — the live desc-GUID equals `--guid`, and
//!    the live MAC… (the GUID is the strong key; the MAC is corroborating
//!    — both must agree with what the front-end passed for the destroy).
//! 4. **Owned by `--owner`** — the live guest's `seadog-owner:` marker
//!    equals the requesting owner.
//!
//! Any failure → a typed refusal, NO destroy — *even when explicitly
//! asked*. `teardown --vmid 105` (a production VM) is impossible: 105 is
//! out of range, so step 1 refuses it.

use anyhow::{bail, Result};
use clap::Args;
use serde_json::{json, Value};

use seadog_core::config::Config;
use seadog_core::identity::{extract_desc_guid, extract_desc_owner, GuestSignals, NAME_PREFIX};
use seadog_core::kento::Kento;

use crate::parse_mode;

/// `teardown --owner <name> --guid <uuid> --vmid <u32> --mode <lxc|vm>`.
#[derive(Debug, Args)]
pub struct TeardownArgs {
    /// Requesting owner — must match the guest's recorded owner.
    #[arg(long)]
    pub owner: String,
    /// Instance GUID — must match the guest's desc-GUID marker.
    #[arg(long)]
    pub guid: String,
    /// Target vmid — must be in range and resolve to a live seadog guest.
    #[arg(long)]
    pub vmid: u32,
    /// `lxc` or `vm`.
    #[arg(long)]
    pub mode: String,
}

/// Run `teardown` against live PVE. Refuses (typed error, no destroy) on
/// any triangulation failure; destroys only on unanimous agreement.
pub fn run(args: &TeardownArgs, kento: &dyn Kento, config: &Config) -> Result<Value> {
    let mode = parse_mode(&args.mode)?;
    let [lo, hi] = config.allocation.vmid_range;

    // (1) In range. A production vmid (e.g. 105) fails here — full stop,
    //     we never even look it up.
    if args.vmid < lo || args.vmid > hi {
        bail!(
            "refusing teardown: vmid {} is outside the seadog range [{lo}, {hi}]",
            args.vmid
        );
    }

    // Re-enumerate LIVE PVE (never the DB) and find the guest at this vmid.
    let live = kento.list_guests((lo, hi)).map_err(anyhow::Error::from)?;
    let guest: &GuestSignals = live.iter().find(|g| g.vmid == args.vmid).ok_or_else(|| {
        anyhow::anyhow!(
            "refusing teardown: no live guest at vmid {} in PVE",
            args.vmid
        )
    })?;

    // (2) Seadog-marked: BOTH the seadog- name prefix AND a desc-GUID.
    let has_name = guest
        .name
        .as_deref()
        .is_some_and(|n| n.starts_with(NAME_PREFIX));
    let desc_guid = extract_desc_guid(guest.description.as_deref());
    if !has_name || desc_guid.is_none() {
        bail!(
            "refusing teardown: vmid {} is not a seadog-marked guest (name_prefix={has_name}, desc_guid={})",
            args.vmid,
            desc_guid.is_some()
        );
    }
    let desc_guid = desc_guid.unwrap();

    // (3) Instance keys match the passed --guid. The GUID is the strong
    //     key; we require it to match exactly.
    if desc_guid != args.guid {
        bail!(
            "refusing teardown: vmid {} desc-GUID does not match the requested guid (guid/MAC mismatch)",
            args.vmid
        );
    }

    // (4) Owned by --owner, per the guest's own owner marker.
    let owner = extract_desc_owner(guest.description.as_deref());
    match owner.as_deref() {
        Some(o) if o == args.owner => {}
        _ => bail!(
            "refusing teardown: vmid {} is not owned by '{}' (owner mismatch)",
            args.vmid,
            args.owner
        ),
    }

    // ALL checks passed → destroy.
    kento
        .teardown(args.vmid, mode)
        .map_err(anyhow::Error::from)?;

    Ok(json!({
        "ok": true,
        "vmid": args.vmid,
        "mode": mode.as_str(),
        "guid": args.guid,
        "owner": args.owner,
        "status": "reaped",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::config;
    use seadog_core::identity::{GUID_MARKER_PREFIX, OWNER_MARKER_PREFIX};
    use seadog_core::kento::FakeKento;
    use seadog_core::models::Mode;

    const GUID: &str = "11111111-1111-4111-8111-111111111111";

    /// A well-formed live seadog guest (as provision would have left it).
    fn seadog_guest(vmid: u32, guid: &str, owner: &str) -> GuestSignals {
        GuestSignals {
            vmid,
            name: Some("seadog-alice-proj-ab12".into()),
            description: Some(format!(
                "{GUID_MARKER_PREFIX}{guid}\n{OWNER_MARKER_PREFIX}{owner}"
            )),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            fingerprint: Default::default(),
        }
    }

    fn args(vmid: u32, guid: &str, owner: &str) -> TeardownArgs {
        TeardownArgs {
            owner: owner.into(),
            guid: guid.into(),
            vmid,
            mode: "lxc".into(),
        }
    }

    #[test]
    fn matching_seadog_guest_is_destroyed() {
        let cfg = config();
        let k = FakeKento::new();
        k.set_guests(vec![seadog_guest(10010, GUID, "alice")]);
        let out = run(&args(10010, GUID, "alice"), &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(k.teardowns(), vec![(10010, Mode::Lxc)]);
    }

    #[test]
    fn out_of_range_vmid_is_refused_without_lookup() {
        let cfg = config();
        let k = FakeKento::new();
        // A production VM at 105: must be impossible to destroy.
        assert!(run(&args(105, GUID, "alice"), &k, &cfg).is_err());
        assert!(k.teardowns().is_empty());
    }

    #[test]
    fn unmarked_foreign_in_range_guest_is_refused() {
        let cfg = config();
        let k = FakeKento::new();
        // A foreign guest squatting in-range: no seadog- name, no marker.
        k.set_guests(vec![GuestSignals {
            vmid: 10010,
            name: Some("someones-prod-db".into()),
            description: Some("not ours".into()),
            mac: Some("11:22:33:44:55:66".into()),
            fingerprint: Default::default(),
        }]);
        assert!(run(&args(10010, GUID, "alice"), &k, &cfg).is_err());
        assert!(k.teardowns().is_empty());
    }

    #[test]
    fn guid_mismatch_is_refused() {
        let cfg = config();
        let k = FakeKento::new();
        // Live guest carries a DIFFERENT guid than the destroy request.
        k.set_guests(vec![seadog_guest(
            10010,
            "99999999-9999-4999-8999-999999999999",
            "alice",
        )]);
        assert!(run(&args(10010, GUID, "alice"), &k, &cfg).is_err());
        assert!(k.teardowns().is_empty());
    }

    #[test]
    fn another_owners_guest_is_refused() {
        let cfg = config();
        let k = FakeKento::new();
        // Same guid, but the guest is owned by someone else.
        k.set_guests(vec![seadog_guest(10010, GUID, "bob")]);
        assert!(run(&args(10010, GUID, "alice"), &k, &cfg).is_err());
        assert!(k.teardowns().is_empty());
    }

    #[test]
    fn no_live_guest_at_vmid_is_refused() {
        let cfg = config();
        let k = FakeKento::new();
        // In-range vmid, but nothing live there.
        assert!(run(&args(10010, GUID, "alice"), &k, &cfg).is_err());
        assert!(k.teardowns().is_empty());
    }
}
