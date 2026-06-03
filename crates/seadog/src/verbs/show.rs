//! `show <env-id>` — one env's full metadata. env-id is the `guid` PK.

use anyhow::{anyhow, Result};
use seadog_core::store;
use serde_json::{json, Value};

use super::Ctx;

/// `show <env-id>`. Returns the env row as JSON, or a not-found error.
/// Read-only and not owner-scoped (any caller may inspect a guid they
/// know); the operator `--all` view in `ls` surfaces guids.
pub fn run(ctx: &Ctx, env_id: &str) -> Result<Value> {
    match store::get_env(ctx.conn, env_id)? {
        Some(env) => Ok(json!({ "env": env })),
        None => Err(anyhow!("no env with id '{env_id}'")),
    }
}
