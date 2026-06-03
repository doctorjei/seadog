//! Allocation tests: lowest-available vmid + IP, consecutive runs,
//! release/reuse, exhaustion, and concurrency (no two threads claim the
//! same slot).

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Barrier};
use std::thread;

use rusqlite::Connection;

use seadog_core::alloc::{allocate, NewEnv};
use seadog_core::store;
use seadog_core::Error;

const VMID_RANGE: (u32, u32) = (10000, 10999);
const IP_LO: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 192);
const IP_HI: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 254);

fn new_env(guid: &str) -> NewEnv<'_> {
    NewEnv {
        guid,
        mode: seadog_core::models::Mode::Lxc,
        owner: "alice",
        image: "loom",
        name: "seadog-alice-proj-tok",
        mac: "AA:BB:CC:DD:EE:FF",
        created_at: 1000,
        ttl_deadline: 4600,
        soft_deadline: 2800,
    }
}

#[test]
fn lowest_available_starts_at_floor() {
    let mut conn = store::open_in_memory().unwrap();
    let a = allocate(&mut conn, VMID_RANGE, (IP_LO, IP_HI), &new_env("g1")).unwrap();
    assert_eq!(a.vmid, 10000);
    assert_eq!(a.ip, IP_LO);
}

#[test]
fn consecutive_allocations_are_consecutive() {
    let mut conn = store::open_in_memory().unwrap();
    for i in 0..5u32 {
        let a = allocate(
            &mut conn,
            VMID_RANGE,
            (IP_LO, IP_HI),
            &new_env(&format!("g{i}")),
        )
        .unwrap();
        assert_eq!(a.vmid, 10000 + i);
        assert_eq!(a.ip, Ipv4Addr::from(u32::from(IP_LO) + i));
    }
}

#[test]
fn release_frees_value_for_reuse() {
    let mut conn = store::open_in_memory().unwrap();
    let a0 = allocate(&mut conn, VMID_RANGE, (IP_LO, IP_HI), &new_env("g0")).unwrap();
    let a1 = allocate(&mut conn, VMID_RANGE, (IP_LO, IP_HI), &new_env("g1")).unwrap();
    assert_eq!(a0.vmid, 10000);
    assert_eq!(a1.vmid, 10001);

    // Release g0 (leaves Active) -> 10000 / .192 free again.
    store::mark_reaped(&conn, "g0").unwrap();

    let a2 = allocate(&mut conn, VMID_RANGE, (IP_LO, IP_HI), &new_env("g2")).unwrap();
    assert_eq!(a2.vmid, 10000, "freed vmid reused");
    assert_eq!(a2.ip, IP_LO, "freed ip reused");
}

#[test]
fn exhaustion_returns_typed_error() {
    let mut conn = store::open_in_memory().unwrap();
    // Tiny range: two vmids, plenty of IPs -> vmid exhausts first.
    let small = (10000u32, 10001u32);
    allocate(&mut conn, small, (IP_LO, IP_HI), &new_env("g0")).unwrap();
    allocate(&mut conn, small, (IP_LO, IP_HI), &new_env("g1")).unwrap();
    let err =
        allocate(&mut conn, small, (IP_LO, IP_HI), &new_env("g2")).expect_err("third must exhaust");
    assert!(matches!(err, Error::Exhausted(_)), "{err:?}");

    // Tiny IP pool exhausts independently.
    let mut conn2 = store::open_in_memory().unwrap();
    let one_ip = (IP_LO, IP_LO);
    allocate(&mut conn2, VMID_RANGE, one_ip, &new_env("h0")).unwrap();
    let err2 =
        allocate(&mut conn2, VMID_RANGE, one_ip, &new_env("h1")).expect_err("ip pool exhausts");
    assert!(matches!(err2, Error::Exhausted(_)), "{err2:?}");
}

#[test]
fn concurrent_allocations_never_collide() {
    // Shared DB file (WAL) + many threads each allocating once. With
    // BEGIN IMMEDIATE no two may claim the same vmid or ip.
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
                let env = new_env(&guid);
                loop {
                    match allocate(&mut conn, VMID_RANGE, (IP_LO, IP_HI), &env) {
                        Ok(a) => return (a.vmid, a.ip),
                        // Under contention SQLite may surface a busy
                        // error despite the timeout; retry.
                        Err(Error::Sqlite(_)) => continue,
                        Err(e) => panic!("unexpected alloc error: {e:?}"),
                    }
                }
            })
        })
        .collect();

    let mut vmids = HashSet::new();
    let mut ips = HashSet::new();
    for h in handles {
        let (vmid, ip) = h.join().unwrap();
        assert!(vmids.insert(vmid), "duplicate vmid {vmid}");
        assert!(ips.insert(ip), "duplicate ip {ip}");
    }
    assert_eq!(vmids.len(), N);
    assert_eq!(ips.len(), N);

    // The claimed vmids are exactly the lowest N (no gaps/dupes).
    let mut sorted: Vec<u32> = vmids.into_iter().collect();
    sorted.sort_unstable();
    let expected: Vec<u32> = (10000..10000 + N as u32).collect();
    assert_eq!(sorted, expected);
}
