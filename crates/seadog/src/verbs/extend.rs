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
    let env =
        store::get_env(ctx.conn, env_id)?.ok_or_else(|| anyhow!("no env with id '{env_id}'"))?;

    if env.owner != ctx.owner {
        // Don't extend a foreign env; refuse with a clear (non-leaky)
        // ownership error.
        return Err(anyhow!(
            "env '{env_id}' is not owned by '{}'; cannot extend",
            ctx.owner
        ));
    }

    let add = duration.as_secs() as i64;
    let new_deadline = env.ttl_deadline + add;
    store::set_ttl_deadline(ctx.conn, env_id, new_deadline)?;

    Ok(json!({
        "guid": env.guid,
        "previous_ttl_deadline": env.ttl_deadline,
        "ttl_deadline": new_deadline,
        "extended_by_secs": add,
    }))
}
