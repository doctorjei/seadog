//! `destroy <env-id>` — tear down an env now. **Elevated** (PVE op), so it
//! routes through the [`elevate`](crate::elevate) seam.
//!
//! Phase 2a: argv mapping wired; `elevate` stubbed (bridge-not-wired).

use anyhow::Result;
use serde_json::Value;

use super::Ctx;
use crate::elevate::{elevate, ElevateArgs};

/// `destroy <env-id>`. env-id is the `guid`. Routes a privileged
/// `teardown <guid>` through [`elevate`]; Phase 2a returns the typed
/// bridge-not-wired error. (Phase 2b's helper re-validates ownership +
/// live-PVE triangulation before tearing down.)
pub fn run(ctx: &Ctx, env_id: &str) -> Result<Value> {
    let req = ElevateArgs::new("teardown", ctx.owner.clone(), vec![env_id.to_string()]);
    let outcome = elevate(&req)?;
    Ok(serde_json::to_value(outcome)?)
}
