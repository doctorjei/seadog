//! The shared sweep: one codepath for all three reap triggers
//! (opportunistic, watch-loop, systemd-backstop).
//!
//! [`sweep`] scans the vmid range via [`Kento::list_guests`], loads the
//! matching DB rows, [`classify`](crate::identity::classify)es each live
//! guest, and acts:
//! - **age floor**: never reap an env younger than `lifecycle.age_floor`
//!   (covers the non-atomic create window).
//! - **deadline**: only [`Reap`](crate::identity::Classification::Reap)-
//!   classified envs **past their DB `ttl_deadline`** are torn down.
//! - **grace warning**: warn when within `lifecycle.grace` of the
//!   deadline, before the kill.
//! - **herd cap**: at most `lifecycle.herd_cap` teardowns per sweep; the
//!   remainder is carried to the next tick and **logged**, never silently
//!   dropped.
//! - **anomaly / heads-up**: routed to [`notify`](crate::notify), never
//!   destroyed.
//! - **quorum loss**: surfaced and the sweep stops cleanly — no spin.
//!
//! The heartbeat (`last_sweep_at = now`) is written at the end so
//! `health` can detect a dead reaper.

use rusqlite::Connection;

use crate::config::Config;
use crate::identity::{classify, Classification, GuestSignals};
use crate::kento::Kento;
use crate::models::{Env, EnvStatus};
use crate::notify::{decide, emit, Event};
use crate::{store, Error};

/// Per-sweep result, for tests and for `health`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Envs actually torn down this tick.
    pub reaped: u32,
    /// Anomalies routed to notify (flagged, never destroyed).
    pub flagged: u32,
    /// Foreign heads-ups routed to notify.
    pub heads_up: u32,
    /// Envs eligible to reap but deferred by the herd cap (carried over).
    pub deferred: u32,
    /// Envs detected as vanished (row present, guest gone).
    pub vanished: u32,
    /// Set when a quorum-loss aborted the sweep early.
    pub quorum_lost: Option<String>,
}

/// Run one sweep over the configured vmid range.
///
/// `now_unix` is injected so tests control time. On a quorum-loss signal
/// from `list_guests`/`teardown`, the sweep records it in
/// [`SweepOutcome::quorum_lost`], routes a `SweeperDegraded` notify, and
/// returns **cleanly** — it does not retry in a loop. The heartbeat is
/// written at the end (even on quorum loss, so health sees liveness).
pub fn sweep(
    kento: &dyn Kento,
    conn: &Connection,
    config: &Config,
    now_unix: i64,
) -> Result<SweepOutcome, Error> {
    let mut outcome = SweepOutcome::default();
    let [lo, hi] = config.allocation.vmid_range;

    let guests = match kento.list_guests((lo, hi)) {
        Ok(g) => g,
        Err(Error::QuorumLost(msg)) => {
            surface_quorum_loss(config, &msg, now_unix, conn);
            outcome.quorum_lost = Some(msg);
            // Still stamp the heartbeat so health sees the reaper ran.
            store::write_heartbeat(conn, now_unix)?;
            return Ok(outcome);
        }
        Err(e) => return Err(e),
    };

    let age_floor = config.lifecycle.age_floor.as_secs() as i64;
    let grace = config.lifecycle.grace.as_secs() as i64;
    let herd_cap = config.lifecycle.herd_cap;

    for g in &guests {
        // The authoritative row for this vmid is the *active* one, if any.
        let db_row = active_env_for_vmid(conn, g.vmid)?;
        let cls = classify(g, db_row.as_ref(), None, config);

        match cls {
            Classification::Reap { guid, .. } => {
                let env = match db_row {
                    Some(e) => e,
                    None => continue, // unreachable: Reap implies a row
                };
                handle_reap_candidate(
                    kento,
                    conn,
                    config,
                    now_unix,
                    age_floor,
                    grace,
                    herd_cap,
                    g,
                    &env,
                    &guid,
                    &mut outcome,
                )?;
                if outcome.quorum_lost.is_some() {
                    break;
                }
            }
            Classification::Anomaly { detail, .. } => {
                outcome.flagged += 1;
                let guid = db_row
                    .map(|e| e.guid)
                    .unwrap_or_else(|| format!("vmid-{}", g.vmid));
                route(conn, config, now_unix, Event::Anomaly { guid, detail });
            }
            Classification::HeadsUp { detail, .. } => {
                outcome.heads_up += 1;
                route(
                    conn,
                    config,
                    now_unix,
                    Event::ForeignHeadsUp {
                        guid_or_vmid: format!("vmid-{}", g.vmid),
                        detail,
                    },
                );
            }
            Classification::Vanished { guid } => {
                outcome.vanished += 1;
                let _ = store::mark_vanished(conn, &guid);
                route(
                    conn,
                    config,
                    now_unix,
                    Event::Lifecycle {
                        guid,
                        detail: format!("guest at vmid {} vanished from PVE", g.vmid),
                    },
                );
            }
        }
    }

    store::write_heartbeat(conn, now_unix)?;
    Ok(outcome)
}

/// Decide + act on one `Reap`-classified guest: enforce age-floor +
/// deadline, honor the herd cap, warn within grace, then teardown +
/// mark-reaped. Mutates `outcome`.
#[allow(clippy::too_many_arguments)]
fn handle_reap_candidate(
    kento: &dyn Kento,
    conn: &Connection,
    config: &Config,
    now_unix: i64,
    age_floor: i64,
    grace: i64,
    herd_cap: u32,
    g: &GuestSignals,
    env: &Env,
    guid: &str,
    outcome: &mut SweepOutcome,
) -> Result<(), Error> {
    // Age floor: never reap a just-born env (non-atomic create window).
    if now_unix - env.created_at < age_floor {
        return Ok(());
    }

    // Deadline: only past-deadline envs are eligible.
    if now_unix < env.ttl_deadline {
        // Grace warning: within `grace` of the deadline, warn (no kill).
        if now_unix >= env.ttl_deadline - grace {
            route(
                conn,
                config,
                now_unix,
                Event::Lifecycle {
                    guid: guid.to_string(),
                    detail: format!(
                        "env {} (vmid {}) within grace of ttl deadline",
                        guid, g.vmid
                    ),
                },
            );
        }
        return Ok(());
    }

    // Past deadline → eligible. Herd cap: cap reaps per sweep, carry the
    // remainder to the next tick (logged below via OverdueUnreaped).
    if outcome.reaped >= herd_cap {
        outcome.deferred += 1;
        route(
            conn,
            config,
            now_unix,
            Event::OverdueUnreaped {
                guid: guid.to_string(),
                detail: format!(
                    "env {} (vmid {}) overdue but deferred by herd cap ({herd_cap}/sweep)",
                    guid, g.vmid
                ),
            },
        );
        return Ok(());
    }

    // Tear it down by the LIVE guest name (kento destroys by name, cleaning
    // its overlay state too). A `Reap` classification is unanimous, which
    // requires the seadog- name prefix, so `g.name` is present here; guard
    // defensively against a missing name rather than ever passing an empty
    // one to a destroy.
    let live_name = match g.name.as_deref() {
        Some(n) if !n.is_empty() => n,
        _ => {
            outcome.deferred += 1;
            route(
                conn,
                config,
                now_unix,
                Event::OverdueUnreaped {
                    guid: guid.to_string(),
                    detail: format!(
                        "teardown of env {} (vmid {}) skipped: live guest has no name",
                        guid, g.vmid
                    ),
                },
            );
            return Ok(());
        }
    };
    match kento.teardown(live_name, env.mode) {
        Ok(()) => {
            store::mark_reaped(conn, guid)?;
            outcome.reaped += 1;
            route(
                conn,
                config,
                now_unix,
                Event::Lifecycle {
                    guid: guid.to_string(),
                    detail: format!("reaped env {} (vmid {}) past ttl", guid, g.vmid),
                },
            );
        }
        Err(Error::QuorumLost(msg)) => {
            surface_quorum_loss(config, &msg, now_unix, conn);
            outcome.quorum_lost = Some(msg);
        }
        Err(e) => {
            // Teardown failed for a non-quorum reason: surface as our
            // overdue-unreaped problem (escalates on backoff), don't spin.
            outcome.deferred += 1;
            route(
                conn,
                config,
                now_unix,
                Event::OverdueUnreaped {
                    guid: guid.to_string(),
                    detail: format!("teardown of env {} (vmid {}) failed: {e}", guid, g.vmid),
                },
            );
        }
    }
    Ok(())
}

/// Fetch the **active** env row for a vmid, if any. Terminal rows for the
/// same (reused) vmid are ignored — only a live lease is authoritative
/// for a live guest.
fn active_env_for_vmid(conn: &Connection, vmid: u32) -> Result<Option<Env>, Error> {
    match store::get_env_by_vmid(conn, vmid)? {
        Some(env) if env.status == EnvStatus::Active => Ok(Some(env)),
        _ => Ok(None),
    }
}

/// Route an event through the notify policy: load prior state, [`decide`],
/// [`emit`], and persist the new state when it emitted. Best-effort —
/// notify failures never abort a sweep.
fn route(conn: &Connection, config: &Config, now_unix: i64, event: Event) {
    let key = event_key(&event);
    let prior = store::get_notify_state(conn, &key).ok().flatten();
    let decision = decide(&event, prior.as_ref(), config, now_unix);
    emit(&event, &decision, config);
    if decision.emit {
        let _ = store::put_notify_state(conn, &decision.new_state);
    }
}

/// The notify-state key for an event (mirrors `Event::key`, exposed here
/// only to load prior state before `decide`).
fn event_key(event: &Event) -> String {
    match event {
        Event::ForeignHeadsUp { guid_or_vmid, .. } => guid_or_vmid.clone(),
        Event::Anomaly { guid, .. }
        | Event::OverdueUnreaped { guid, .. }
        | Event::Lifecycle { guid, .. } => guid.clone(),
        Event::SweeperDegraded { .. } => "sweeper".to_string(),
    }
}

/// Emit a `SweeperDegraded` (crit) notify for a quorum-loss. Does not
/// persist sweeper state beyond what `route` records.
fn surface_quorum_loss(config: &Config, msg: &str, now_unix: i64, conn: &Connection) {
    route(
        conn,
        config,
        now_unix,
        Event::SweeperDegraded {
            detail: format!("sweep aborted: {msg}"),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Fingerprint, GUID_MARKER_PREFIX};
    use crate::kento::FakeKento;
    use crate::models::{Env, EnvStatus, Mode};
    use crate::store;

    fn config() -> Config {
        // age_floor 5m, grace 10m, herd_cap small for tests.
        let yaml = r#"
lifecycle:
  herd_cap: 2
images:
  loom:
    ref: "r/loom:1"
    modes: [vm]
"#;
        Config::from_yaml_str(yaml).unwrap()
    }

    fn insert_active(conn: &Connection, guid: &str, vmid: u32, created_at: i64, ttl: i64) {
        let env = Env {
            guid: guid.into(),
            vmid,
            mode: Mode::Vm,
            owner: "alice".into(),
            image: "loom".into(),
            name: format!("seadog-alice-p-{guid}"),
            ip: "192.168.99.200".into(),
            mac: format!("aa:bb:cc:00:00:{:02x}", vmid % 256),
            created_at,
            ttl_deadline: ttl,
            soft_deadline: ttl - 600,
            status: EnvStatus::Active,
        };
        store::insert_env(conn, &env).unwrap();
    }

    fn signals_for(conn: &Connection, guid: &str, vmid: u32) -> GuestSignals {
        let env = store::get_env(conn, guid).unwrap().unwrap();
        GuestSignals {
            vmid,
            name: Some(env.name.clone()),
            description: Some(format!("{GUID_MARKER_PREFIX}{guid}")),
            mac: Some(env.mac.clone()),
            fingerprint: Fingerprint::default(),
        }
    }

    #[test]
    fn age_floor_skips_just_born_expired_env() {
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        // Created 1 minute ago (< 5m age floor), already "expired".
        insert_active(&conn, "g1", 10010, now - 60, now - 10);
        let k = FakeKento::new();
        k.set_guests(vec![signals_for(&conn, "g1", 10010)]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.reaped, 0, "age floor must protect just-born env");
        assert!(k.teardowns().is_empty());
        // Row still active.
        assert_eq!(
            store::get_env(&conn, "g1").unwrap().unwrap().status,
            EnvStatus::Active
        );
    }

    #[test]
    fn past_deadline_unanimous_reaps_and_marks_row() {
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        // Old enough (created 1h ago), past deadline.
        insert_active(&conn, "g1", 10010, now - 3600, now - 100);
        let k = FakeKento::new();
        k.set_guests(vec![signals_for(&conn, "g1", 10010)]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.reaped, 1);
        assert_eq!(
            k.teardowns(),
            vec![("seadog-alice-p-g1".to_string(), Mode::Vm)]
        );
        assert_eq!(
            store::get_env(&conn, "g1").unwrap().unwrap().status,
            EnvStatus::Reaped
        );
        // Heartbeat written.
        assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(now));
    }

    #[test]
    fn lxc_no_mac_past_deadline_reaps() {
        // An LXC env: the DB row records no MAC ("") and the live guest
        // exposes none (mac=None), but GUID/name/desc all agree. Past its
        // deadline + age floor, it must reap — the regression this fixes
        // (previously the fictional row MAC vs None blocked the LXC path).
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        // Insert an LXC row with an empty MAC (the "unknown" sentinel).
        let env = Env {
            guid: "lxc1".into(),
            vmid: 10020,
            mode: Mode::Lxc,
            owner: "alice".into(),
            image: "loom".into(),
            name: "seadog-alice-p-lxc1".into(),
            ip: "192.168.99.201".into(),
            mac: String::new(),
            created_at: now - 3600,
            ttl_deadline: now - 100,
            soft_deadline: now - 700,
            status: EnvStatus::Active,
        };
        store::insert_env(&conn, &env).unwrap();
        // Live signals as a kento LXC would present: markers + seadog- name,
        // but NO MAC.
        let s = GuestSignals {
            vmid: 10020,
            name: Some("seadog-alice-p-lxc1".into()),
            description: Some(format!("{GUID_MARKER_PREFIX}lxc1")),
            mac: None,
            fingerprint: Fingerprint::default(),
        };
        let k = FakeKento::new();
        k.set_guests(vec![s]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.reaped, 1, "LXC with no live MAC must reap");
        assert_eq!(
            k.teardowns(),
            vec![("seadog-alice-p-lxc1".to_string(), Mode::Lxc)]
        );
        assert_eq!(
            store::get_env(&conn, "lxc1").unwrap().unwrap().status,
            EnvStatus::Reaped
        );
    }

    #[test]
    fn ambiguous_is_flagged_not_reaped() {
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "g1", 10010, now - 3600, now - 100);
        // Clobber the description marker → desc-clobber anomaly.
        let mut s = signals_for(&conn, "g1", 10010);
        s.description = Some("user wiped this".into());
        let k = FakeKento::new();
        k.set_guests(vec![s]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.reaped, 0);
        assert_eq!(out.flagged, 1);
        assert!(k.teardowns().is_empty(), "anomaly must not be torn down");
        assert_eq!(
            store::get_env(&conn, "g1").unwrap().unwrap().status,
            EnvStatus::Active
        );
    }

    #[test]
    fn herd_cap_caps_reaps_and_reports_deferred() {
        let c = config(); // herd_cap = 2
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        let mut guests = Vec::new();
        for i in 0..5u32 {
            let guid = format!("g{i}");
            let vmid = 10010 + i;
            insert_active(&conn, &guid, vmid, now - 3600, now - 100);
            guests.push(signals_for(&conn, &guid, vmid));
        }
        let k = FakeKento::new();
        k.set_guests(guests);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.reaped, 2, "herd cap limits reaps per sweep");
        assert_eq!(out.deferred, 3, "remainder carried + reported");
        assert_eq!(k.teardowns().len(), 2);
    }

    #[test]
    fn quorum_loss_surfaces_stops_and_does_not_spin() {
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        let k = FakeKento::new();
        k.set_quorum_lost("pmxcfs read-only: no quorum");

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert!(out.quorum_lost.is_some());
        assert_eq!(out.reaped, 0);
        // Heartbeat still written so health sees the reaper ran.
        assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(now));
    }

    #[test]
    fn nonquorum_teardown_failure_defers_not_reaps() {
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "g1", 10010, now - 3600, now - 100);
        let k = FakeKento::new();
        k.set_guests(vec![signals_for(&conn, "g1", 10010)]);
        // Teardown fails for a non-quorum reason → deferred, not reaped,
        // and the row stays Active (no spin).
        k.fail_teardown("seadog-alice-p-g1", "lock busy");

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.reaped, 0);
        assert_eq!(out.deferred, 1);
        assert!(out.quorum_lost.is_none());
        assert_eq!(
            store::get_env(&conn, "g1").unwrap().unwrap().status,
            EnvStatus::Active
        );
    }

    #[test]
    fn heartbeat_written_on_clean_sweep() {
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 42i64;
        let k = FakeKento::new();
        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out, SweepOutcome::default());
        assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(now));
    }
}
