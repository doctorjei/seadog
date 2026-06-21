//! `ack <env-id>` — acknowledge a notification, suppressing further
//! escalation for that env.
//!
//! DB-only: flips the `acked` flag in the env's `notify_state` rows. The
//! escalating events (`Anomaly`/`OverdueUnreaped`) load their prior state via
//! per-kind namespaced keys (`{guid}:anomaly` / `{guid}:overdue`), so ack
//! writes an acked row for BOTH of those keys (no escalation reads a bare-guid
//! env row any more). The env-id (`guid`) is the same id `destroy`/`show`
//! take.
//!
//! Scoped: an owner may ack their **own** env, or any env that is `Flagged`
//! (the legitimate "silence a foreign/anomaly heads-up" case — a flagged env
//! may not be owned by the acker). Acking another owner's *healthy* env is
//! refused, so a stranger who knows a guid can't mute someone's live env. The
//! ack also records who acked and when (`acked_by` / `acked_at`) for audit.

use anyhow::{anyhow, Result};
use seadog_core::models::{EnvStatus, NotifyState};
use seadog_core::store;
use serde_json::{json, Value};

use super::Ctx;

/// `ack <env-id>`. Resolves the env-id (guid) to its env, enforces the ack
/// scope (own env OR `Flagged`), then sets `acked = true` plus the
/// `acked_by` / `acked_at` audit on the notify-state rows for BOTH escalating
/// keys (`{guid}:anomaly` and `{guid}:overdue`), creating either if none
/// exists yet (so an ack lands even before the reaper has emitted). Returns
/// the affected guid.
pub fn run(ctx: &Ctx, env_id: &str) -> Result<Value> {
    let env =
        store::get_env(ctx.conn, env_id)?.ok_or_else(|| anyhow!("env '{env_id}' not found"))?;

    // Scope: only the owner may mute their own env; anyone may silence a
    // Flagged anomaly heads-up. Refuse acking a foreign healthy env.
    if env.owner != ctx.owner && env.status != EnvStatus::Flagged {
        return Err(anyhow!(
            "env '{env_id}' is not yours and not flagged; cannot ack"
        ));
    }

    // The escalating events load prior state via per-kind namespaced keys, so
    // ack must write an acked row for each — a single bare-guid row would no
    // longer be read by either.
    for key in [
        format!("{}:anomaly", env.guid),
        format!("{}:overdue", env.guid),
    ] {
        let new_state = match store::get_notify_state(ctx.conn, &key)? {
            Some(mut s) => {
                s.acked = true;
                s.acked_by = Some(ctx.owner.clone());
                s.acked_at = Some(ctx.now_unix);
                s
            }
            None => NotifyState {
                guid: key,
                last_severity: String::new(),
                last_emitted_at: ctx.now_unix,
                acked: true,
                acked_by: Some(ctx.owner.clone()),
                acked_at: Some(ctx.now_unix),
            },
        };
        store::put_notify_state(ctx.conn, &new_state)?;
    }

    Ok(json!({
        "guid": env.guid,
        "acked": true,
    }))
}
