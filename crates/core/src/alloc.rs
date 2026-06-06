//! Atomic name + IP allocation.
//!
//! [`allocate`] picks the lowest-available IPv4 in `[pool.0, pool.1]`,
//! skipping addresses currently held by an `Active` env, and inserts the
//! leased env row. Concurrency-safe: the read + the write happen inside a
//! single `BEGIN IMMEDIATE` transaction, which takes a RESERVED lock up
//! front so two concurrent allocators cannot observe the same gap and both
//! claim it. The "lease" is just the inserted `Active` env row — releasing
//! is transitioning that row out of `Active` (see
//! [`crate::store::mark_reaped`] / [`crate::store::mark_vanished`]), which
//! frees the IP for reuse. vmid is no longer allocated: kento auto-assigns
//! a backend vmid where one exists (PVE), and seadog allocates by unique
//! name + IP only.

use std::net::Ipv4Addr;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::models::{Env, EnvStatus, Mode};
use crate::Error;

/// A claimed allocation: the lowest-available IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allocation {
    pub ip: Ipv4Addr,
}

/// Inputs needed to materialize the leased env row once a slot is found.
///
/// Allocation and row-insert are one atomic step, so the caller supplies
/// the rest of the [`Env`] fields up front. `ip` is filled in by the
/// allocator; `vmid` is no longer allocated (kento auto-assigns it).
pub struct NewEnv<'a> {
    pub guid: &'a str,
    pub mode: Mode,
    pub owner: &'a str,
    pub image: &'a str,
    pub name: &'a str,
    pub mac: &'a str,
    pub created_at: i64,
    pub ttl_deadline: i64,
    pub soft_deadline: i64,
}

/// Allocate the lowest-available IP and insert the `Active` env row,
/// atomically.
///
/// `ip_pool` is an inclusive `[low, high]`. Returns the claimed
/// [`Allocation`]; the env is persisted with `status = Active` inside the
/// same transaction (vmid `NULL`, host-key fps empty — both are recorded
/// post-provision from the kento read-back). Returns [`Error::Exhausted`]
/// if the IP pool has no free slot.
pub fn allocate(
    conn: &mut Connection,
    ip_pool: (Ipv4Addr, Ipv4Addr),
    new: &NewEnv<'_>,
) -> Result<Allocation, Error> {
    // IMMEDIATE: take the RESERVED write lock now, before reading the
    // occupied set — serializes concurrent allocators so two cannot
    // pick the same gap.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let ip =
        lowest_free_ip(&tx, ip_pool)?.ok_or_else(|| Error::Exhausted("ip pool".to_string()))?;

    let env = Env {
        guid: new.guid.to_string(),
        vmid: None,
        mode: new.mode,
        owner: new.owner.to_string(),
        image: new.image.to_string(),
        name: new.name.to_string(),
        ip: ip.to_string(),
        mac: new.mac.to_string(),
        ssh_host_key_fps: Vec::new(),
        created_at: new.created_at,
        ttl_deadline: new.ttl_deadline,
        soft_deadline: new.soft_deadline,
        status: EnvStatus::Active,
    };

    tx.execute(
        r#"INSERT INTO envs
            (guid, vmid, mode, owner, image, name, ip, mac, ssh_host_key_fps,
             created_at, ttl_deadline, soft_deadline, status)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"#,
        params![
            env.guid,
            env.vmid,
            env.mode.as_str(),
            env.owner,
            env.image,
            env.name,
            env.ip,
            env.mac,
            env.ssh_host_key_fps.join(","),
            env.created_at,
            env.ttl_deadline,
            env.soft_deadline,
            env.status.as_str(),
        ],
    )?;

    tx.commit()?;
    Ok(Allocation { ip })
}

/// Whether an `Active` env already holds the instance `name`.
///
/// Name is now an allocation key (unique among live envs), so the
/// front-end checks this before minting a guest name. Terminal rows
/// (reaped/vanished) free the name for reuse, so only `Active` rows count.
pub fn name_in_use(conn: &Connection, name: &str) -> Result<bool, Error> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM envs WHERE status = 'active' AND name = ?1 LIMIT 1",
            params![name],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

/// Lowest IPv4 in `[lo, hi]` not held by an `Active` env, or `None` if
/// the pool is full.
fn lowest_free_ip(
    conn: &Connection,
    (lo, hi): (Ipv4Addr, Ipv4Addr),
) -> Result<Option<Ipv4Addr>, Error> {
    // Collect the occupied addresses into a sorted u32 set. The pool is
    // tiny (<= a /24 tail), so this is cheap and avoids string-vs-int
    // ordering pitfalls.
    let mut stmt = conn.prepare("SELECT ip FROM envs WHERE status = 'active'")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;

    let lo_u = u32::from(lo);
    let hi_u = u32::from(hi);
    let mut occupied: Vec<u32> = Vec::new();
    for r in rows {
        let s = r?;
        if let Ok(addr) = s.parse::<Ipv4Addr>() {
            let v = u32::from(addr);
            if (lo_u..=hi_u).contains(&v) {
                occupied.push(v);
            }
        }
    }
    occupied.sort_unstable();

    let mut candidate = lo_u;
    for used in occupied {
        if used > candidate {
            break;
        }
        if used == candidate {
            if candidate == hi_u {
                return Ok(None);
            }
            candidate += 1;
        }
    }
    if candidate <= hi_u {
        Ok(Some(Ipv4Addr::from(candidate)))
    } else {
        Ok(None)
    }
}
