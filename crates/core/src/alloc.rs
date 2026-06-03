//! Atomic vmid + IP allocation.
//!
//! [`allocate`] picks the lowest-available vmid in `[range.0, range.1]`
//! and the lowest-available IPv4 in `[pool.0, pool.1]`, skipping values
//! currently held by an `Active` env. Concurrency-safe: the read + the
//! write happen inside a single `BEGIN IMMEDIATE` transaction, which
//! takes a RESERVED lock up front so two concurrent allocators cannot
//! observe the same gap and both claim it. The "lease" is just the
//! inserted `Active` env row — releasing is transitioning that row out
//! of `Active` (see [`crate::store::mark_reaped`] /
//! [`crate::store::mark_vanished`]), which frees the vmid/ip for reuse.

use std::net::Ipv4Addr;

use rusqlite::{params, Connection, TransactionBehavior};

use crate::models::{Env, EnvStatus, Mode};
use crate::Error;

/// A claimed allocation: the lowest-available vmid + IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allocation {
    pub vmid: u32,
    pub ip: Ipv4Addr,
}

/// Inputs needed to materialize the leased env row once a slot is found.
///
/// Allocation and row-insert are one atomic step, so the caller supplies
/// the rest of the [`Env`] fields up front. `vmid`/`ip` are filled in by
/// the allocator.
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

/// Allocate the lowest-available vmid + IP and insert the `Active` env
/// row, atomically.
///
/// `vmid_range` and `ip_pool` are inclusive `[low, high]`. Returns the
/// claimed [`Allocation`]; the env is persisted with `status = Active`
/// inside the same transaction. Returns [`Error::Exhausted`] if either
/// the vmid range or the IP pool has no free slot.
pub fn allocate(
    conn: &mut Connection,
    vmid_range: (u32, u32),
    ip_pool: (Ipv4Addr, Ipv4Addr),
    new: &NewEnv<'_>,
) -> Result<Allocation, Error> {
    // IMMEDIATE: take the RESERVED write lock now, before reading the
    // occupied sets — serializes concurrent allocators so two cannot
    // pick the same gap.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let vmid = lowest_free_vmid(&tx, vmid_range)?
        .ok_or_else(|| Error::Exhausted("vmid range".to_string()))?;
    let ip =
        lowest_free_ip(&tx, ip_pool)?.ok_or_else(|| Error::Exhausted("ip pool".to_string()))?;

    let env = Env {
        guid: new.guid.to_string(),
        vmid,
        mode: new.mode,
        owner: new.owner.to_string(),
        image: new.image.to_string(),
        name: new.name.to_string(),
        ip: ip.to_string(),
        mac: new.mac.to_string(),
        created_at: new.created_at,
        ttl_deadline: new.ttl_deadline,
        soft_deadline: new.soft_deadline,
        status: EnvStatus::Active,
    };

    tx.execute(
        r#"INSERT INTO envs
            (guid, vmid, mode, owner, image, name, ip, mac,
             created_at, ttl_deadline, soft_deadline, status)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"#,
        params![
            env.guid,
            env.vmid,
            env.mode.as_str(),
            env.owner,
            env.image,
            env.name,
            env.ip,
            env.mac,
            env.created_at,
            env.ttl_deadline,
            env.soft_deadline,
            env.status.as_str(),
        ],
    )?;

    tx.commit()?;
    Ok(Allocation { vmid, ip })
}

/// Lowest vmid in `[lo, hi]` not held by an `Active` env, or `None` if
/// the range is full.
fn lowest_free_vmid(conn: &Connection, (lo, hi): (u32, u32)) -> Result<Option<u32>, Error> {
    let mut stmt = conn.prepare(
        "SELECT vmid FROM envs WHERE status = 'active' \
         AND vmid BETWEEN ?1 AND ?2 ORDER BY vmid",
    )?;
    let mut rows = stmt.query(params![lo, hi])?;

    // Walk the occupied set in ascending order; the first integer it
    // skips is the lowest free slot.
    let mut candidate = lo;
    while let Some(row) = rows.next()? {
        let used: u32 = row.get(0)?;
        if used > candidate {
            return Ok(Some(candidate));
        }
        if used == candidate {
            if candidate == hi {
                return Ok(None);
            }
            candidate += 1;
        }
    }
    if candidate <= hi {
        Ok(Some(candidate))
    } else {
        Ok(None)
    }
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
