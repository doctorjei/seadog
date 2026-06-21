//! `extend <env-id> <duration>` — push out an env's hard-kill deadline.
//!
//! DB-only: the deadline is DB-authoritative, so no PVE/root op is needed.
//! Owner-scoped — a caller may only extend their **own** env; another
//! owner's env is rejected (not found-leaked beyond ownership).

use anyhow::{anyhow, Result};
use seadog_core::store;
use serde_json::{json, Value};

use super::Ctx;

/// `extend <env-id> <duration>`. Parses `duration` as a humantime string
/// (`30m`, `1h`, `2h30m`), adds it to the env's current `ttl_deadline`,
/// and persists. Rejects a missing env and an env owned by someone else.
pub fn run(ctx: &Ctx, env_id: &str, duration: std::time::Duration) -> Result<Value> {
    let owner = ctx.require_owner()?;

    let env =
        store::get_env(ctx.conn, env_id)?.ok_or_else(|| anyhow!("no env with id '{env_id}'"))?;

    if env.owner != owner {
        // Don't extend a foreign env; refuse with a clear (non-leaky)
        // ownership error.
        return Err(anyhow!(
            "env '{env_id}' is not owned by '{owner}'; cannot extend"
        ));
    }

    let add =
        i64::try_from(duration.as_secs()).map_err(|_| anyhow!("duration is too large to add"))?;
    let requested_deadline = env
        .ttl_deadline
        .checked_add(add)
        .ok_or_else(|| anyhow!("resulting deadline overflows"))?;

    // The store clamps the requested deadline to [created_at, created_at +
    // max_ttl] and returns the value it actually stored. Report that clamped
    // deadline (and recompute the realized delta from it) so the JSON never
    // overstates an extension the ceiling refused.
    let max_ttl_secs = i64::try_from(ctx.config.lifecycle.max_ttl.as_secs())
        .map_err(|_| anyhow!("configured max_ttl is too large"))?;
    let stored_deadline =
        store::set_ttl_deadline(ctx.conn, env_id, requested_deadline, max_ttl_secs)?;

    Ok(json!({
        "guid": env.guid,
        "previous_ttl_deadline": env.ttl_deadline,
        "ttl_deadline": stored_deadline,
        "extended_by_secs": stored_deadline - env.ttl_deadline,
    }))
}
