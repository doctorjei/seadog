//! `destroy <env-id>` — tear down an env now. **Elevated** (PVE op), so it
//! routes through the [`elevate`](crate::elevate) seam.
//!
//! The front-end resolves the env-id (a `guid`) to the caller's own env,
//! refusing another owner's env or an unknown id, then elevates `teardown`
//! with **structured args** (`--guid`/`--vmid`/`--mode`). The helper
//! (Phase 3a) re-validates ownership and re-triangulates against live PVE
//! before destroying — the front-end passes data, never a raw command.
//!
//! On helper success the row is marked `Reaped` (the lease frees). On
//! helper failure the row is left `Active` and the error is surfaced; the
//! reaper will reconcile later.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use seadog_core::store;
use seadog_core::EnvStatus;

use super::Ctx;
use crate::elevate::{elevate, spawn_watcher, ElevateArgs};

/// `destroy <env-id>`. env-id is the `guid`.
pub fn run(ctx: &Ctx, env_id: &str) -> Result<Value> {
    // Opportunistic reap hook (best-effort; never blocks/fails the verb).
    let _ = spawn_watcher();

    // Resolve the env-id to the caller's own env. Unknown id → error;
    // another owner's id → refused (never leaks existence beyond "not
    // yours" semantics — we 404 it the same as unknown for non-owners).
    let env =
        store::get_env(ctx.conn, env_id)?.ok_or_else(|| anyhow!("env '{env_id}' not found"))?;
    if env.owner != ctx.owner {
        return Err(anyhow!("env '{env_id}' is not owned by '{}'", ctx.owner));
    }

    // Structured teardown args. The helper re-validates + triangulates.
    let argv = vec![
        "--guid".to_string(),
        env.guid.clone(),
        "--vmid".to_string(),
        env.vmid.to_string(),
        "--mode".to_string(),
        env.mode.as_str().to_string(),
    ];
    let req = ElevateArgs::new("teardown", ctx.owner.clone(), argv);

    let outcome = elevate(&req).map_err(|e| anyhow!(e))?;

    // Helper succeeded → mark the row reaped (frees the lease). If the
    // status flip fails, surface it (the guest is gone but the row is
    // stale; the reaper reconciles).
    if env.status == EnvStatus::Active {
        store::mark_reaped(ctx.conn, &env.guid)?;
    }

    Ok(json!({
        "id": env.guid,
        "vmid": env.vmid,
        "mode": env.mode.as_str(),
        "status": EnvStatus::Reaped.as_str(),
        "helper": outcome.result,
    }))
}
