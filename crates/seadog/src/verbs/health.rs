//! `health` — binary version, reaper heartbeat freshness, env counts.

use anyhow::Result;
use seadog_core::store;
use seadog_core::EnvStatus;
use serde_json::{json, Value};

use super::Ctx;

/// `health`. Reports:
/// - `version`: this binary's crate version.
/// - `heartbeat`: last sweep timestamp + its age in seconds (`null` if the
///   reaper has never run), so a stale/dead reaper is visible.
/// - `counts`: env counts by status.
pub fn run(ctx: &Ctx) -> Result<Value> {
    let active = store::list_by_status(ctx.conn, EnvStatus::Active)?.len();
    let reaped = store::list_by_status(ctx.conn, EnvStatus::Reaped)?.len();
    let vanished = store::list_by_status(ctx.conn, EnvStatus::Vanished)?.len();
    let flagged = store::list_by_status(ctx.conn, EnvStatus::Flagged)?.len();

    let heartbeat = match store::read_heartbeat(ctx.conn)? {
        Some(ts) => json!({
            "last_sweep_at": ts,
            "age_secs": ctx.now_unix - ts,
        }),
        None => Value::Null,
    };

    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "now_unix": ctx.now_unix,
        "heartbeat": heartbeat,
        "counts": {
            "active": active,
            "reaped": reaped,
            "vanished": vanished,
            "flagged": flagged,
            "total": active + reaped + vanished + flagged,
        },
    }))
}
