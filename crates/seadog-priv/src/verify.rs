//! Shared server-side verification: confirm a target vmid resolves to an
//! in-range, seadog-marked **live** guest before any narrow privileged
//! mutation (`set-meta`, `start-sshd`). Like teardown, this trusts only
//! live PVE — never the DB — and refuses anything not provably ours.

use anyhow::{anyhow, bail, Result};

use seadog_core::config::Config;
use seadog_core::identity::{extract_desc_guid, GuestSignals, NAME_PREFIX};
use seadog_core::kento::Kento;

/// Find the live guest at `vmid`, requiring it to be in-range and
/// seadog-marked (the `seadog-` name prefix AND a desc-GUID). Returns the
/// matched [`GuestSignals`] on success; a typed refusal otherwise.
pub fn verified_seadog_guest(
    vmid: u32,
    kento: &dyn Kento,
    config: &Config,
) -> Result<GuestSignals> {
    let [lo, hi] = config.allocation.vmid_range;
    if vmid < lo || vmid > hi {
        bail!("refusing: vmid {vmid} is outside the seadog range [{lo}, {hi}]");
    }
    let live = kento.list_guests((lo, hi)).map_err(anyhow::Error::from)?;
    let guest = live
        .into_iter()
        .find(|g| g.vmid == vmid)
        .ok_or_else(|| anyhow!("refusing: no live guest at vmid {vmid} in PVE"))?;

    let has_name = guest
        .name
        .as_deref()
        .is_some_and(|n| n.starts_with(NAME_PREFIX));
    let has_guid = extract_desc_guid(guest.description.as_deref()).is_some();
    if !has_name || !has_guid {
        bail!(
            "refusing: vmid {vmid} is not a seadog-marked guest (name_prefix={has_name}, desc_guid={has_guid})"
        );
    }
    Ok(guest)
}
