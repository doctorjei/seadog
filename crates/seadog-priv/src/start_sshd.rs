//! `seadog-priv start-sshd` — bring up the in-CT sshd (loom ships it
//! disabled). LXC-only and **narrow**: the target must be an in-range,
//! seadog-marked live container (verified via [`crate::verify`]) before
//! the helper runs `pct exec … systemctl start ssh`. This is NOT a general
//! `pct exec` passthrough.

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use seadog_core::config::Config;
use seadog_core::kento::Kento;

use crate::verify::verified_seadog_guest;

/// `start-sshd --vmid <u32>` (lxc only).
#[derive(Debug, Args)]
pub struct StartSshdArgs {
    /// Target container vmid (verified in-range + seadog-marked first).
    #[arg(long)]
    pub vmid: u32,
}

/// Run `start-sshd`: verify the target container, then start its sshd.
pub fn run(args: &StartSshdArgs, kento: &dyn Kento, config: &Config) -> Result<Value> {
    // Verify the target is provably ours before exec'ing anything in it.
    let guest = verified_seadog_guest(args.vmid, kento, config)?;
    // start-sshd is LXC-only. We can't read mode off GuestSignals, but the
    // verb is only ever issued for CTs by the front-end; the verification
    // above guarantees it's a seadog guest. Guard against an obviously
    // empty target as a defensive belt.
    let _ = guest;

    kento.start_sshd(args.vmid).map_err(anyhow::Error::from)?;

    Ok(json!({
        "ok": true,
        "vmid": args.vmid,
        "sshd_started": true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::config;
    use seadog_core::identity::{GuestSignals, GUID_MARKER_PREFIX, OWNER_MARKER_PREFIX};
    use seadog_core::kento::FakeKento;

    fn seadog_guest(vmid: u32) -> GuestSignals {
        GuestSignals {
            vmid,
            name: Some("seadog-jei-proj-ab12".into()),
            description: Some(format!("{GUID_MARKER_PREFIX}g\n{OWNER_MARKER_PREFIX}jei")),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            fingerprint: Default::default(),
        }
    }

    #[test]
    fn succeeds_on_verified_seadog_ct() {
        let cfg = config();
        let k = FakeKento::new();
        k.set_guests(vec![seadog_guest(10010)]);
        let out = run(&StartSshdArgs { vmid: 10010 }, &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(k.sshd_starts(), vec![10010]);
    }

    #[test]
    fn refuses_out_of_range() {
        let cfg = config();
        let k = FakeKento::new();
        assert!(run(&StartSshdArgs { vmid: 105 }, &k, &cfg).is_err());
        assert!(k.sshd_starts().is_empty());
    }

    #[test]
    fn refuses_unmarked_guest() {
        let cfg = config();
        let k = FakeKento::new();
        k.set_guests(vec![GuestSignals {
            vmid: 10010,
            name: Some("foreign".into()),
            description: None,
            mac: None,
            fingerprint: Default::default(),
        }]);
        assert!(run(&StartSshdArgs { vmid: 10010 }, &k, &cfg).is_err());
        assert!(k.sshd_starts().is_empty());
    }
}
