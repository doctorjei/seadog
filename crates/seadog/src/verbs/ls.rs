//! `ls` — list the caller's active envs (or every env with `--all`).

use anyhow::Result;
use seadog_core::store;
use seadog_core::EnvStatus;
use serde_json::{json, Value};

use super::Ctx;
use crate::elevate::spawn_watcher;

/// `ls [--all]`. Without `--all`: the caller's own **active** envs. With
/// `--all`: every env in the DB regardless of owner/status (operator view).
pub fn run(ctx: &Ctx, all: bool) -> Result<Value> {
    // Opportunistic reap hook: `ls` is a common, cheap touch, so it's a
    // good place to ensure the root watcher is alive. Best-effort — a
    // spawn failure never affects the listing.
    let _ = spawn_watcher();

    // The host operator (root, no resolved owner) gets the operator view too,
    // same as an explicit `--all`.
    let operator_view = all || ctx.owner.is_none();
    let envs = if operator_view {
        // Every env, newest first — union across statuses via a full scan
        // by listing each status; simpler: list by owner is wrong here, so
        // we read all four statuses and merge by created_at.
        let mut v = Vec::new();
        for st in [
            EnvStatus::Active,
            EnvStatus::Reaped,
            EnvStatus::Vanished,
            EnvStatus::Flagged,
        ] {
            v.extend(store::list_by_status(ctx.conn, st)?);
        }
        v.sort_by_key(|e| std::cmp::Reverse(e.created_at));
        v
    } else {
        let owner = ctx
            .owner
            .as_deref()
            .expect("owner present when not operator_view");
        store::list_by_owner(ctx.conn, owner)?
            .into_iter()
            .filter(|e| e.status == EnvStatus::Active)
            .collect()
    };

    Ok(json!({
        "envs": envs,
        "count": envs.len(),
        "all": operator_view,
    }))
}
