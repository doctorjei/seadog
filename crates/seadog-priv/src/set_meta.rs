//! `seadog-priv set-meta` — narrow metadata update (`qm set`/`pct set`).
//!
//! Sets a TTL-deadline tag and/or description **only** on an in-range,
//! seadog-marked live guest (verified first via [`crate::verify`]). This
//! is not a general `qm set`/`pct set` passthrough — the target is proven
//! ours before any mutation.

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use seadog_core::config::Config;
use seadog_core::kento::{Kento, MetaUpdate};

use crate::parse_mode;
use crate::verify::verified_seadog_guest;

/// `set-meta --vmid <u32> --mode <lxc|vm> [--ttl-deadline <epoch>]
/// [--description <str>]`.
#[derive(Debug, Args)]
pub struct SetMetaArgs {
    /// Target vmid (verified in-range + seadog-marked first).
    #[arg(long)]
    pub vmid: u32,
    /// `lxc` or `vm`.
    #[arg(long)]
    pub mode: String,
    /// New TTL-deadline as a unix epoch second.
    #[arg(long = "ttl-deadline")]
    pub ttl_deadline: Option<i64>,
    /// New description body.
    #[arg(long)]
    pub description: Option<String>,
}

/// Run `set-meta`: verify the target, then apply the narrow update.
pub fn run(args: &SetMetaArgs, kento: &dyn Kento, config: &Config) -> Result<Value> {
    let mode = parse_mode(&args.mode)?;
    // Verify the target is provably ours before touching it.
    verified_seadog_guest(args.vmid, kento, config)?;

    let meta = MetaUpdate {
        description: args.description.clone(),
        ttl_deadline: args.ttl_deadline,
    };
    kento
        .set_meta(args.vmid, mode, &meta)
        .map_err(anyhow::Error::from)?;

    Ok(json!({
        "ok": true,
        "vmid": args.vmid,
        "mode": mode.as_str(),
        "ttl_deadline": args.ttl_deadline,
        "description_set": args.description.is_some(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::config;
    use seadog_core::identity::{GuestSignals, GUID_MARKER_PREFIX, OWNER_MARKER_PREFIX};
    use seadog_core::kento::FakeKento;
    use seadog_core::models::Mode;

    fn seadog_guest(vmid: u32) -> GuestSignals {
        GuestSignals {
            vmid,
            name: Some("seadog-jei-proj-ab12".into()),
            description: Some(format!("{GUID_MARKER_PREFIX}g\n{OWNER_MARKER_PREFIX}jei")),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            fingerprint: Default::default(),
        }
    }

    fn args(vmid: u32) -> SetMetaArgs {
        SetMetaArgs {
            vmid,
            mode: "vm".into(),
            ttl_deadline: Some(5000),
            description: Some("updated".into()),
        }
    }

    #[test]
    fn succeeds_on_verified_seadog_guest() {
        let cfg = config();
        let k = FakeKento::new();
        k.set_guests(vec![seadog_guest(10010)]);
        let out = run(&args(10010), &k, &cfg).unwrap();
        assert_eq!(out["ok"], true);
        let calls = k.set_metas();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 10010);
        assert_eq!(calls[0].1, Mode::Vm);
        assert_eq!(calls[0].2.ttl_deadline, Some(5000));
    }

    #[test]
    fn refuses_out_of_range() {
        let cfg = config();
        let k = FakeKento::new();
        assert!(run(&args(105), &k, &cfg).is_err());
        assert!(k.set_metas().is_empty());
    }

    #[test]
    fn refuses_unmarked_guest() {
        let cfg = config();
        let k = FakeKento::new();
        k.set_guests(vec![GuestSignals {
            vmid: 10010,
            name: Some("foreign".into()),
            description: Some("nope".into()),
            mac: None,
            fingerprint: Default::default(),
        }]);
        assert!(run(&args(10010), &k, &cfg).is_err());
        assert!(k.set_metas().is_empty());
    }
}
