//! `ack <env-id>` — acknowledge a notification, suppressing further
//! escalation for that env.
//!
//! DB-only: flips the `acked` flag in the env's `notify_state` row. Keyed by
//! the env-id (`guid`) — the same id `destroy`/`show` take — which is also
//! the `notify_state` primary key. `ack` exists to silence a foreign/anomaly
//! heads-up, so it is intentionally *not* owner-scoped (an anomaly env may
//! not be owned by the acker).

use anyhow::{anyhow, Result};
use seadog_core::models::NotifyState;
use seadog_core::store;
use serde_json::{json, Value};

use super::Ctx;

/// `ack <env-id>`. Resolves the env-id (guid) to its env, then sets that
/// env's notify-state `acked = true` (creating the row if none exists yet,
/// so an ack lands even before the reaper has emitted). Returns the affected
/// guid.
pub fn run(ctx: &Ctx, env_id: &str) -> Result<Value> {
    let env =
        store::get_env(ctx.conn, env_id)?.ok_or_else(|| anyhow!("env '{env_id}' not found"))?;

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
        "acked": true,
    }))
}
