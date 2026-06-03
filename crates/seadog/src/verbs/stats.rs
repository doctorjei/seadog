//! `stats` — aggregate env counts (by status and by owner).

use anyhow::Result;
use seadog_core::store;
use seadog_core::EnvStatus;
use serde_json::{json, Value};
use std::collections::BTreeMap;

use super::Ctx;

/// `stats`. Aggregate counts across all envs: totals by status, by owner,
/// and the active-by-owner breakdown (the cap-relevant view).
pub fn run(ctx: &Ctx) -> Result<Value> {
    let mut by_status: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_owner: BTreeMap<String, usize> = BTreeMap::new();
    let mut active_by_owner: BTreeMap<String, usize> = BTreeMap::new();
    let mut total = 0usize;

    for st in [
        EnvStatus::Active,
        EnvStatus::Reaped,
        EnvStatus::Vanished,
        EnvStatus::Flagged,
    ] {
        let rows = store::list_by_status(ctx.conn, st)?;
        by_status.insert(st.as_str(), rows.len());
        for e in rows {
            total += 1;
            *by_owner.entry(e.owner.clone()).or_default() += 1;
            if st == EnvStatus::Active {
                *active_by_owner.entry(e.owner.clone()).or_default() += 1;
            }
        }
    }

    Ok(json!({
        "total": total,
        "by_status": by_status,
        "by_owner": by_owner,
        "active_by_owner": active_by_owner,
    }))
}
