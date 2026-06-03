//! `ack <vmid>` — acknowledge a notification, suppressing further
//! escalation for that env.
//!
//! DB-only: flips the `acked` flag in the env's `notify_state` row. The
//! notify-state table is keyed by `guid`, so we resolve the `vmid` to its
//! current env first. `ack` exists to silence a foreign/anomaly heads-up,
//! so it is intentionally *not* owner-scoped (an anomaly env may not be
//! owned by the acker).

use anyhow::{anyhow, Result};
use seadog_core::models::NotifyState;
use seadog_core::store;
use serde_json::{json, Value};

use super::Ctx;

/// `ack <vmid>`. Resolves the vmid to its env, then sets that env's
/// notify-state `acked = true` (creating the row if none exists yet, so an
/// ack lands even before the reaper has emitted). Returns the affected
/// guid.
pub fn run(ctx: &Ctx, vmid: u32) -> Result<Value> {
    let env = store::get_env_by_vmid(ctx.conn, vmid)?
        .ok_or_else(|| anyhow!("no env with vmid {vmid}"))?;

    let prior = store::get_notify_state(ctx.conn, &env.guid)?;
    let new_state = match prior {
        Some(mut s) => {
            s.acked = true;
            s
        }
        None => NotifyState {
            guid: env.guid.clone(),
            last_severity: String::new(),
            last_emitted_at: ctx.now_unix,
            acked: true,
        },
    };
    store::put_notify_state(ctx.conn, &new_state)?;

    Ok(json!({
        "guid": env.guid,
        "vmid": vmid,
        "acked": true,
    }))
}
