//! `create` — provision a new env. **Elevated** (PVE op), so it routes
//! through the [`elevate`](crate::elevate) seam.
//!
//! Phase 2a: the argv mapping into [`ElevateArgs`] is wired (so Phase 2b
//! only implements the sudo exec), but `elevate` is stubbed and returns
//! the typed "bridge not wired" error.

use anyhow::Result;
use serde_json::Value;

use super::Ctx;
use crate::elevate::{elevate, ElevateArgs};

/// Parsed `create` arguments (clap-populated in `main`).
#[derive(Debug, Clone)]
pub struct CreateArgs {
    /// Allowlist image *name* (e.g. `loom`) — never an OCI ref.
    pub image: String,
    /// Optional explicit mode (`lxc`/`vm`); defaults to the image's first
    /// allowed mode in the helper.
    pub mode: Option<String>,
    /// Optional hard-kill TTL override (humantime string, passed through).
    pub ttl: Option<String>,
    /// Optional soft "expected done" duration override (humantime string).
    pub duration: Option<String>,
}

/// `create --image <name> [--mode lxc|vm] [--ttl <dur>] [--duration <dur>]`.
///
/// Builds the privileged `provision` argv and routes it through
/// [`elevate`]. In Phase 2a this returns the typed bridge-not-wired error.
pub fn run(ctx: &Ctx, args: &CreateArgs) -> Result<Value> {
    // Map clap values → the helper's argv. This is the contract Phase 2b's
    // `seadog-priv provision` will re-parse + re-validate.
    let mut argv = vec!["--image".to_string(), args.image.clone()];
    if let Some(mode) = &args.mode {
        argv.push("--mode".to_string());
        argv.push(mode.clone());
    }
    if let Some(ttl) = &args.ttl {
        argv.push("--ttl".to_string());
        argv.push(ttl.clone());
    }
    if let Some(duration) = &args.duration {
        argv.push("--duration".to_string());
        argv.push(duration.clone());
    }

    let req = ElevateArgs::new("provision", ctx.owner.clone(), argv);
    let outcome = elevate(&req)?; // Phase 2a: always Err(NotWired).
    Ok(serde_json::to_value(outcome)?)
}
