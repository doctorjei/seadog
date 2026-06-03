//! `history [duration]` — terminal envs (reaped/vanished) within a window.

use anyhow::Result;
use seadog_core::store;
use seadog_core::EnvStatus;
use serde_json::{json, Value};

use super::Ctx;

/// `history [duration]`. Lists terminal envs (`reaped`/`vanished`) whose
/// `created_at` falls within the last `window_secs`. A `None` window means
/// "all history". Newest first.
pub fn run(ctx: &Ctx, window_secs: Option<i64>) -> Result<Value> {
    let cutoff = window_secs.map(|w| ctx.now_unix - w);

    let mut envs = Vec::new();
    for st in [EnvStatus::Reaped, EnvStatus::Vanished] {
        for e in store::list_by_status(ctx.conn, st)? {
            if cutoff.map(|c| e.created_at >= c).unwrap_or(true) {
                envs.push(e);
            }
        }
    }
    envs.sort_by_key(|e| std::cmp::Reverse(e.created_at));

    Ok(json!({
        "envs": envs,
        "count": envs.len(),
        "window_secs": window_secs,
    }))
}
