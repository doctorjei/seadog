//! Allocation tests: lowest-available IP, consecutive runs, release/reuse,
//! exhaustion, name uniqueness, and concurrency (no two threads claim the
//! same IP).
//!
//! vmid allocation was removed in the kento decouple — seadog allocates by
//! unique name + lowest-available IP lease only (kento auto-assigns a
//! backend vmid where one exists). The old VMID_RANGE arg and `Allocation.vmid`
//! are gone; these tests assert the IP lease + name-uniqueness behavior.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Barrier};
use std::thread;

use rusqlite::Connection;

use seadog_core::alloc::{allocate, name_in_use, NewEnv};
use seadog_core::store;
use seadog_core::Error;

const IP_LO: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 192);
const IP_HI: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 254);

fn new_env<'a>(guid: &'a str, name: &'a str) -> NewEnv<'a> {
    NewEnv {
        guid,
        mode: seadog_core::models::Mode::Lxc,
        owner: "alice",
        image: "loom",
        name,
        mac: "AA:BB:CC:DD:EE:FF",
        created_at: 1000,
        ttl_deadline: 4600,
        soft_deadline: 2800,
    }
}

#[test]
fn lowest_available_starts_at_floor() {
    let mut conn = store::open_in_memory().unwrap();
    let a = allocate(&mut conn, (IP_LO, IP_HI), &new_env("g1", "seadog-a-1")).unwrap();
    assert_eq!(a.ip, IP_LO);
}

#[test]
fn consecutive_allocations_are_consecutive() {
    let mut conn = store::open_in_memory().unwrap();
    for i in 0..5u32 {
        let a = allocate(
            &mut conn,
            (IP_LO, IP_HI),
            &new_env(&format!("g{i}"), &format!("seadog-a-{i}")),
        )
        .unwrap();
        assert_eq!(a.ip, Ipv4Addr::from(u32::from(IP_LO) + i));
    }
}

#[test]
fn release_frees_value_for_reuse() {
    let mut conn = store::open_in_memory().unwrap();
    let a0 = allocate(&mut conn, (IP_LO, IP_HI), &new_env("g0", "seadog-a-0")).unwrap();
    let a1 = allocate(&mut conn, (IP_LO, IP_HI), &new_env("g1", "seadog-a-1")).unwrap();
    assert_eq!(a0.ip, IP_LO);
    assert_eq!(a1.ip, Ipv4Addr::from(u32::from(IP_LO) + 1));

    // Release g0 (leaves Active) -> .192 free again.
    store::mark_reaped(&conn, "g0").unwrap();

    let a2 = allocate(&mut conn, (IP_LO, IP_HI), &new_env("g2", "seadog-a-2")).unwrap();
    assert_eq!(a2.ip, IP_LO, "freed ip reused");
}

#[test]
fn exhaustion_returns_typed_error() {
    // A single-IP pool exhausts after the first lease.
    let mut conn = store::open_in_memory().unwrap();
    let one_ip = (IP_LO, IP_LO);
    allocate(&mut conn, one_ip, &new_env("h0", "seadog-a-0")).unwrap();
    let err = allocate(&mut conn, one_ip, &new_env("h1", "seadog-a-1"))
        .expect_err("second must exhaust the ip pool");
    assert!(matches!(err, Error::Exhausted(_)), "{err:?}");
}

#[test]
fn name_in_use_tracks_active_rows() {
    // removed: vmid-range exhaustion (vmid no longer allocated). Replaced
    // with name-uniqueness coverage — the new "name + IP" allocation key.
    let mut conn = store::open_in_memory().unwrap();
    assert!(!name_in_use(&conn, "seadog-a-1").unwrap());

    allocate(&mut conn, (IP_LO, IP_HI), &new_env("g1", "seadog-a-1")).unwrap();
    assert!(
        name_in_use(&conn, "seadog-a-1").unwrap(),
        "active name in use"
    );
    assert!(!name_in_use(&conn, "seadog-a-2").unwrap());

    // A terminal row frees the name for reuse.
    store::mark_reaped(&conn, "g1").unwrap();
    assert!(
        !name_in_use(&conn, "seadog-a-1").unwrap(),
        "reaped row frees its name"
    );
}

#[test]
fn concurrent_allocations_never_collide() {
    // Shared DB file (WAL) + many threads each allocating once. With
    // BEGIN IMMEDIATE no two may claim the same ip.
    let dir = {
        let p = std::env::temp_dir().join(format!("seadog-alloc-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    };
    let path = dir.join("seadog.db");
    // Cold-start the schema once.
    store::open(&path).unwrap();

    const N: usize = 16;
    let barrier = Arc::new(Barrier::new(N));
    let path = Arc::new(path);

    let handles: Vec<_> = (0..N)
        .map(|i| {
            let barrier = Arc::clone(&barrier);
            let path = Arc::clone(&path);
            thread::spawn(move || {
                let mut conn = Connection::open(&*path).unwrap();
                // Wait so SQLite has to serialize the writers, not just
                // run them sequentially.
                conn.busy_timeout(std::time::Duration::from_secs(10))
                    .unwrap();
                barrier.wait();
                let guid = format!("g{i}");
                let name = format!("seadog-a-{i}");
                let env = new_env(&guid, &name);
                loop {
                    match allocate(&mut conn, (IP_LO, IP_HI), &env) {
                        Ok(a) => return a.ip,
                        // Under contention SQLite may surface a busy
                        // error despite the timeout; retry.
                        Err(Error::Sqlite(_)) => continue,
                        Err(e) => panic!("unexpected alloc error: {e:?}"),
                    }
                }
            })
        })
        .collect();

    let mut ips = HashSet::new();
    for h in handles {
        let ip = h.join().unwrap();
        assert!(ips.insert(ip), "duplicate ip {ip}");
    }
    assert_eq!(ips.len(), N);

    // The claimed ips are exactly the lowest N (no gaps/dupes).
    let mut sorted: Vec<u32> = ips.into_iter().map(u32::from).collect();
    sorted.sort_unstable();
    let base = u32::from(IP_LO);
    let expected: Vec<u32> = (base..base + N as u32).collect();
    assert_eq!(sorted, expected);
}
