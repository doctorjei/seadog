//! The shared sweep: one codepath for all three reap triggers
//! (opportunistic, watch-loop, systemd-backstop).
//!
//! [`sweep`] enumerates every live kento instance via
//! [`Kento::list_instances`], joins each to its DB row **by GUID**,
//! [`classify`](crate::identity::classify)es it, and acts:
//! - **foreign**: an instance with no `SEADOG_GUID` is ignored (kento only
//!   lists kento instances anyway).
//! - **orphan**: a GUID with no DB row is **re-adopted** onto a fresh
//!   `Active` row (deadline = `now + lifecycle.default_ttl`) and flagged.
//! - **anomaly**: a name/MAC confirmer mismatch is routed to
//!   [`notify`](crate::notify) (create-window-suppressed inside the age
//!   floor when a DB row exists), never destroyed.
//! - **reap-eligible**: gated by age floor, DB `ttl_deadline` (+ grace
//!   warning) and the per-sweep herd cap before teardown.
//! - **vanished**: after the live pass, every `Active` DB row whose GUID is
//!   absent from the live set is marked `Vanished`.
//! - **quorum loss**: surfaced and the sweep stops cleanly — no spin.
//!
//! The heartbeat (`last_sweep_at = now`) is written at the end so `health`
//! can detect a dead reaper.

use std::collections::HashSet;

use rusqlite::Connection;

use crate::config::Config;
use crate::identity::{classify, Classification};
use crate::kento::{InstanceSignals, Kento};
use crate::models::{Env, EnvStatus};
use crate::notify::{decide, emit, Event};
use crate::{store, Error};

/// Per-sweep result, for tests and for `health`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Envs actually torn down this tick.
    pub reaped: u32,
    /// Anomalies routed to notify (flagged, never destroyed). Re-adopted
    /// orphans also bump this (they route an anomaly event).
    pub flagged: u32,
    /// Orphans re-adopted onto a fresh DB row this tick.
    pub readopted: u32,
    /// Envs eligible to reap but deferred by the herd cap (carried over).
    pub deferred: u32,
    /// Envs detected as vanished (Active row, GUID absent from live set).
    pub vanished: u32,
    /// Set when a quorum-loss aborted the sweep early.
    pub quorum_lost: Option<String>,
}

/// Run one sweep over every live kento instance.
///
/// `now_unix` is injected so tests control time. On a quorum-loss signal
/// from `list_instances`/`teardown`, the sweep records it in
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

    let instances = match kento.list_instances() {
        Ok(i) => i,
        Err(Error::QuorumLost(msg)) => {
            surface_quorum_loss(config, &msg, now_unix, conn);
            outcome.quorum_lost = Some(msg);
            // Still stamp the heartbeat so health sees the reaper ran.
            store::write_heartbeat(conn, now_unix)?;
            return Ok(outcome);
        }
        Err(e) => return Err(e),
    };

    // The live GUID set, for the vanished pass. Only instances carrying a
    // SEADOG_GUID participate (foreign instances have none).
    let live_guids: HashSet<String> = instances.iter().filter_map(|i| i.guid.clone()).collect();

    let age_floor = config.lifecycle.age_floor.as_secs() as i64;
    let grace = config.lifecycle.grace.as_secs() as i64;
    let herd_cap = config.lifecycle.herd_cap;

    for sig in &instances {
        // Join the live instance to its DB row by GUID (None when foreign).
        let db_row = match &sig.guid {
            Some(g) => store::get_env(conn, g)?,
            None => None,
        };
        let cls = classify(sig, db_row.as_ref());

        match cls {
            // Foreign: not ours, ignore entirely (no notify).
            Classification::Foreign => {}

            // Orphan: a GUID with no DB row → re-adopt onto a fresh Active
            // row and flag the event for the operator.
            Classification::Orphan { guid, owner } => {
                readopt_orphan(conn, config, now_unix, sig, &guid, owner, &mut outcome);
            }

            // Anomaly: a hard-confirmer mismatch. Suppress inside the create
            // window when a DB row exists (it carries created_at); otherwise
            // flag + route.
            Classification::Anomaly { detail, .. } => {
                if let Some(env) = db_row.as_ref() {
                    if now_unix - env.created_at < age_floor {
                        continue;
                    }
                }
                outcome.flagged += 1;
                let guid = db_row
                    .map(|e| e.guid)
                    .or_else(|| sig.guid.clone())
                    .unwrap_or_else(|| format!("name-{}", sig.name));
                route(conn, config, now_unix, Event::Anomaly { guid, detail });
            }

            // Reap-eligible: GUID + confirmers agree. A ReapEligible always
            // implies a DB row (classify returns it only when one matched).
            // `host_key_mismatch` is a soft, non-blocking signal: when set we
            // route an info-level breadcrumb (below) but the reap proceeds
            // exactly as if it were clear.
            Classification::ReapEligible {
                guid,
                host_key_mismatch,
            } => {
                let env = match db_row {
                    Some(e) => e,
                    None => continue, // unreachable: ReapEligible implies a row
                };
                // Non-blocking breadcrumb: a reused GUID whose guest
                // regenerated its host keys. Purely additive observability —
                // it does NOT gate, abort, or alter the reap below.
                if host_key_mismatch {
                    route(
                        conn,
                        config,
                        now_unix,
                        Event::HostKeyRegen {
                            guid: guid.clone(),
                            detail: format!(
                                "env {} ({}) ssh host-key fingerprints regenerated \
                                 (soft signal); reaping unaffected",
                                guid, sig.name
                            ),
                        },
                    );
                }
                handle_reap_candidate(
                    kento,
                    conn,
                    config,
                    now_unix,
                    age_floor,
                    grace,
                    herd_cap,
                    sig,
                    &env,
                    &guid,
                    &mut outcome,
                )?;
                if outcome.quorum_lost.is_some() {
                    break;
                }
            }
        }
    }

    // Vanished pass: every Active DB row whose GUID is absent from the live
    // set has lost its backing instance. Mark it Vanished + route lifecycle.
    if outcome.quorum_lost.is_none() {
        for env in store::list_by_status(conn, EnvStatus::Active)? {
            if !live_guids.contains(&env.guid) {
                // Don't vanish within the create window: a just-written Active
                // row can precede its instance appearing in `kento list`
                // (create is not atomic). Defer to a later sweep — the same
                // age floor the anomaly and reap-candidate paths already apply.
                if now_unix - env.created_at < age_floor {
                    continue;
                }
                // Gate the success-side effects on the UPDATE succeeding: a
                // transient lock must leave the row Active and route nothing,
                // so the next sweep retries (self-healing). Don't `?` here —
                // one stuck row must not abort the rest of the pass.
                match store::mark_vanished(conn, &env.guid) {
                    Ok(()) => {
                        outcome.vanished += 1;
                        route(
                            conn,
                            config,
                            now_unix,
                            Event::Vanished {
                                guid: env.guid.clone(),
                                detail: format!(
                                    "env {} ({}) vanished: no live kento instance carries its guid",
                                    env.guid, env.name
                                ),
                            },
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "mark_vanished failed for {}: {e}; leaving Active for next sweep",
                            env.guid
                        );
                    }
                }
            }
        }
    }

    store::write_heartbeat(conn, now_unix)?;
    Ok(outcome)
}

/// Re-adopt an orphan (GUID present, no DB row) onto a fresh `Active` row
/// and route an anomaly event so the operator knows. Deadlines reuse
/// `lifecycle.default_ttl` / `default_duration` (no new knob). Mutates
/// `outcome` (`readopted` + `flagged`).
fn readopt_orphan(
    conn: &Connection,
    config: &Config,
    now_unix: i64,
    sig: &InstanceSignals,
    guid: &str,
    owner: Option<String>,
    outcome: &mut SweepOutcome,
) {
    let default_ttl = config.lifecycle.default_ttl.as_secs() as i64;
    let default_duration = config.lifecycle.default_duration.as_secs() as i64;

    let env = Env {
        guid: guid.to_string(),
        vmid: sig.vmid,
        // kento reports the backend mode via inspect.mode, surfaced on the
        // signals — use it directly (no status-text heuristic).
        mode: sig.mode,
        owner: owner.unwrap_or_else(|| "unknown".to_string()),
        image: sig.image.clone(),
        name: sig.name.clone(),
        // Lease unknown at adopt time — record empty.
        ip: String::new(),
        mac: sig.mac.clone().unwrap_or_default(),
        ssh_host_key_fps: sig.ssh_host_key_fps.clone(),
        created_at: now_unix,
        ttl_deadline: now_unix + default_ttl,
        soft_deadline: now_unix + default_duration,
        status: EnvStatus::Active,
    };

    if let Err(e) = store::insert_env(conn, &env) {
        // A racing insert (or guid collision) shouldn't abort the sweep;
        // surface it as an anomaly and move on.
        outcome.flagged += 1;
        route(
            conn,
            config,
            now_unix,
            Event::Anomaly {
                guid: guid.to_string(),
                detail: format!("failed to re-adopt orphan {} ({}): {e}", guid, sig.name),
            },
        );
        return;
    }

    outcome.readopted += 1;
    outcome.flagged += 1;
    route(
        conn,
        config,
        now_unix,
        Event::Anomaly {
            guid: guid.to_string(),
            detail: format!(
                "re-adopted orphan {} ({}) with no DB row; fresh ttl deadline set",
                guid, sig.name
            ),
        },
    );
}

/// Decide + act on one `ReapEligible` instance: enforce age-floor +
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
    sig: &InstanceSignals,
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
                Event::GraceWarning {
                    guid: guid.to_string(),
                    detail: format!("env {} ({}) within grace of ttl deadline", guid, sig.name),
                },
            );
        }
        return Ok(());
    }

    // Past deadline → eligible. Herd cap: cap reaps per sweep, carry the
    // remainder to the next tick (logged below via OverdueUnreaped). A
    // `herd_cap` of 0 means UNLIMITED (no throttle) — never strand reaps.
    if herd_cap != 0 && outcome.reaped >= herd_cap {
        outcome.deferred += 1;
        route(
            conn,
            config,
            now_unix,
            Event::OverdueUnreaped {
                guid: guid.to_string(),
                detail: format!(
                    "env {} ({}) overdue but deferred by herd cap ({herd_cap}/sweep)",
                    guid, sig.name
                ),
            },
        );
        return Ok(());
    }

    // Tear it down by the LIVE instance name (kento destroys by name,
    // cleaning its overlay state too) and the DB row's mode.
    match kento.teardown(&sig.name, env.mode) {
        Ok(()) => {
            store::mark_reaped(conn, guid)?;
            outcome.reaped += 1;
            route(
                conn,
                config,
                now_unix,
                Event::Reaped {
                    guid: guid.to_string(),
                    detail: format!("reaped env {} ({}) past ttl", guid, sig.name),
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
                    detail: format!("teardown of env {} ({}) failed: {e}", guid, sig.name),
                },
            );
        }
    }
    Ok(())
}

/// Route an event through the notify policy: load prior state, [`decide`],
/// [`emit`], and persist the new state when it emitted. Best-effort —
/// notify failures never abort a sweep.
fn route(conn: &Connection, config: &Config, now_unix: i64, event: Event) {
    // Load prior state by the event's OWN notify key (now namespaced per-kind
    // for the one-shot lifecycle events). Use `Event::key` directly — no local
    // mirror to drift out of sync.
    let key = event.key();
    let prior = store::get_notify_state(conn, &key).ok().flatten();
    let decision = decide(&event, prior.as_ref(), config, now_unix);
    emit(&event, &decision, config);
    if decision.emit {
        let _ = store::put_notify_state(conn, &decision.new_state);
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
    use crate::kento::{FakeKento, InstanceSignals};
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

    fn insert_active(conn: &Connection, guid: &str, created_at: i64, ttl: i64) {
        let env = Env {
            guid: guid.into(),
            vmid: Some(10010),
            mode: Mode::Vm,
            owner: "alice".into(),
            image: "loom".into(),
            name: format!("seadog-alice-p-{guid}"),
            ip: "192.168.99.200".into(),
            mac: "aa:bb:cc:00:00:11".into(),
            ssh_host_key_fps: vec!["SHA256:hk".into()],
            created_at,
            ttl_deadline: ttl,
            soft_deadline: ttl - 600,
            status: EnvStatus::Active,
        };
        store::insert_env(conn, &env).unwrap();
    }

    /// Live signals matching a DB row exactly (GUID + name + MAC + fps).
    fn signals_for(conn: &Connection, guid: &str) -> InstanceSignals {
        let env = store::get_env(conn, guid).unwrap().unwrap();
        InstanceSignals {
            name: env.name.clone(),
            guid: Some(guid.to_string()),
            owner: Some(env.owner.clone()),
            mac: Some(env.mac.clone()),
            ssh_host_key_fps: env.ssh_host_key_fps.clone(),
            image: env.image.clone(),
            status: "running vm".to_string(),
            mode: env.mode,
            vmid: env.vmid,
        }
    }

    #[test]
    fn age_floor_skips_just_born_expired_env() {
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        // Created 1 minute ago (< 5m age floor), already "expired".
        insert_active(&conn, "g1", now - 60, now - 10);
        let k = FakeKento::new();
        k.set_instances(vec![signals_for(&conn, "g1")]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.reaped, 0, "age floor must protect just-born env");
        assert!(k.teardowns().is_empty());
        assert_eq!(
            store::get_env(&conn, "g1").unwrap().unwrap().status,
            EnvStatus::Active
        );
    }

    #[test]
    fn past_deadline_agreeing_reaps_and_marks_row() {
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "g1", now - 3600, now - 100);
        let k = FakeKento::new();
        k.set_instances(vec![signals_for(&conn, "g1")]);

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
        assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(now));
    }

    #[test]
    fn grace_warning_does_not_swallow_a_later_reap() {
        // Regression for the dedup-collision bug: an env that logs a grace
        // warning and is THEN reaped must produce BOTH notify_state rows. With
        // the per-kind keys, the prior `{guid}:grace` row no longer suppresses
        // the `{guid}:reaped` emission on the next sweep.
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let grace = c.lifecycle.grace.as_secs() as i64;
        let deadline = 2_000_000i64;
        // Created well before the age floor so the env is reap-eligible by age.
        insert_active(&conn, "g1", deadline - 100_000, deadline);

        // First sweep: inside the grace window (before the deadline) → warn,
        // no reap, and a `{guid}:grace` notify_state row lands.
        let now1 = deadline - grace / 2;
        let k = FakeKento::new();
        k.set_instances(vec![signals_for(&conn, "g1")]);
        let out1 = sweep(&k, &conn, &c, now1).unwrap();
        assert_eq!(out1.reaped, 0, "within grace: not reaped");
        assert!(
            store::get_notify_state(&conn, "g1:grace")
                .unwrap()
                .is_some(),
            "grace warning must persist a `{{guid}}:grace` notify_state row"
        );

        // Second sweep: past the deadline → reap. The reap event keys on
        // `g1:reaped`, distinct from the existing `g1:grace`, so it is NOT
        // swallowed and its row lands.
        let now2 = deadline + 100;
        let k2 = FakeKento::new();
        k2.set_instances(vec![signals_for(&conn, "g1")]);
        let out2 = sweep(&k2, &conn, &c, now2).unwrap();
        assert_eq!(out2.reaped, 1, "past deadline: reaped");
        assert_eq!(
            store::get_env(&conn, "g1").unwrap().unwrap().status,
            EnvStatus::Reaped
        );
        assert!(
            store::get_notify_state(&conn, "g1:reaped")
                .unwrap()
                .is_some(),
            "reap event must NOT be swallowed by the prior grace row"
        );
    }

    #[test]
    fn host_key_mismatch_is_non_blocking_still_reaps() {
        // A reused-GUID guest whose host keys regenerated: live fps are
        // disjoint from the DB row's. The soft signal must NOT change the reap
        // decision — the env is reaped exactly as a clean agreeing env would
        // be (the breadcrumb routed alongside is best-effort observability).
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "g1", now - 3600, now - 100);
        let mut s = signals_for(&conn, "g1");
        // Disjoint from the row's vec!["SHA256:hk"] → host_key_mismatch=true.
        s.ssh_host_key_fps = vec!["SHA256:regenerated".into()];
        let k = FakeKento::new();
        k.set_instances(vec![s]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.reaped, 1, "host-key mismatch must not block the reap");
        assert_eq!(
            k.teardowns(),
            vec![("seadog-alice-p-g1".to_string(), Mode::Vm)]
        );
        assert_eq!(
            store::get_env(&conn, "g1").unwrap().unwrap().status,
            EnvStatus::Reaped
        );
    }

    #[test]
    fn lxc_no_mac_past_deadline_reaps() {
        // LXC env: the DB row records no MAC ("") and the live instance
        // exposes none (mac=None), but GUID + name agree. Past deadline +
        // age floor, it must reap (the MAC-blocks-LXC regression).
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        let env = Env {
            guid: "lxc1".into(),
            vmid: None,
            mode: Mode::Lxc,
            owner: "alice".into(),
            image: "loom".into(),
            name: "seadog-alice-p-lxc1".into(),
            ip: "192.168.99.201".into(),
            mac: String::new(),
            ssh_host_key_fps: Vec::new(),
            created_at: now - 3600,
            ttl_deadline: now - 100,
            soft_deadline: now - 700,
            status: EnvStatus::Active,
        };
        store::insert_env(&conn, &env).unwrap();
        let s = InstanceSignals {
            name: "seadog-alice-p-lxc1".into(),
            guid: Some("lxc1".into()),
            owner: Some("alice".into()),
            mac: None,
            ssh_host_key_fps: Vec::new(),
            image: "loom".into(),
            status: "running lxc".into(),
            mode: Mode::Lxc,
            vmid: None,
        };
        let k = FakeKento::new();
        k.set_instances(vec![s]);

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
    fn anomaly_is_flagged_not_reaped() {
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "g1", now - 3600, now - 100);
        // Rename the live instance → NameMismatch anomaly.
        let mut s = signals_for(&conn, "g1");
        s.name = "user-renamed-this".into();
        let k = FakeKento::new();
        k.set_instances(vec![s]);

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
    fn young_create_window_anomaly_is_suppressed_not_flagged() {
        // A just-born instance (age < age_floor) whose name disagrees with
        // its row (set-meta still landing) → Anomaly. Inside the create
        // window this must be suppressed: no flag, no persisted notify_state.
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "g1", now - 60, now + 3600);
        let mut s = signals_for(&conn, "g1");
        s.name = "not-yet-renamed".into();
        let k = FakeKento::new();
        k.set_instances(vec![s]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(
            out.flagged, 0,
            "create-window anomaly inside age floor must not be flagged"
        );
        assert!(k.teardowns().is_empty());
        assert!(
            store::get_notify_state(&conn, "g1:anomaly")
                .unwrap()
                .is_none(),
            "no warning notify_state row must be persisted in the create window"
        );
        assert_eq!(
            store::get_env(&conn, "g1").unwrap().unwrap().status,
            EnvStatus::Active
        );
    }

    #[test]
    fn old_anomaly_is_flagged_and_persisted() {
        // Same mismatch shape, but the instance is OLD (age >= age_floor) →
        // a genuine anomaly: flagged AND a warning notify_state row persisted.
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "g1", now - 3600, now + 3600);
        let mut s = signals_for(&conn, "g1");
        s.name = "renamed".into();
        let k = FakeKento::new();
        k.set_instances(vec![s]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.flagged, 1, "an aged anomaly must still be flagged");
        assert!(k.teardowns().is_empty(), "anomaly is never reaped");
        let st = store::get_notify_state(&conn, "g1:anomaly")
            .unwrap()
            .expect("aged anomaly must persist a notify_state row");
        assert_eq!(st.last_severity, "warning");
        assert!(!st.acked);
    }

    #[test]
    fn orphan_is_readopted_and_flagged() {
        // A live instance carries a GUID but no DB row backs it → re-adopt
        // onto a fresh Active row + flag.
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        let s = InstanceSignals {
            name: "seadog-bob-p-orph".into(),
            guid: Some("550e8400-e29b-41d4-a716-446655440000".into()),
            owner: Some("bob".into()),
            mac: Some("02:aa:bb:cc:dd:ee".into()),
            ssh_host_key_fps: vec!["SHA256:hk".into()],
            image: "loom".into(),
            status: "running lxc".into(),
            mode: Mode::Lxc,
            vmid: None,
        };
        let k = FakeKento::new();
        k.set_instances(vec![s]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.readopted, 1, "orphan must be re-adopted");
        assert_eq!(out.flagged, 1, "re-adopt routes a flagged anomaly");
        assert_eq!(out.reaped, 0);
        assert!(k.teardowns().is_empty());

        // A fresh Active row now exists with the reused-ttl deadline.
        let env = store::get_env(&conn, "550e8400-e29b-41d4-a716-446655440000")
            .unwrap()
            .expect("row created");
        assert_eq!(env.status, EnvStatus::Active);
        assert_eq!(env.owner, "bob");
        assert_eq!(env.name, "seadog-bob-p-orph");
        assert_eq!(env.created_at, now);
        assert_eq!(
            env.ttl_deadline,
            now + c.lifecycle.default_ttl.as_secs() as i64
        );
        assert_eq!(env.mode, Mode::Lxc, "re-adopt uses sig.mode (Lxc)");
        assert_eq!(env.mac, "02:aa:bb:cc:dd:ee");
        assert_eq!(env.ip, "");
    }

    #[test]
    fn orphan_without_owner_defaults_unknown() {
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        let s = InstanceSignals {
            name: "seadog-x".into(),
            guid: Some("6ba7b810-9dad-11d1-80b4-00c04fd430c8".into()),
            owner: None,
            mac: None,
            ssh_host_key_fps: Vec::new(),
            image: "loom".into(),
            status: "running vm".into(),
            mode: Mode::Vm,
            vmid: Some(123),
        };
        let k = FakeKento::new();
        k.set_instances(vec![s]);

        sweep(&k, &conn, &c, now).unwrap();
        let env = store::get_env(&conn, "6ba7b810-9dad-11d1-80b4-00c04fd430c8")
            .unwrap()
            .unwrap();
        assert_eq!(env.owner, "unknown");
        assert_eq!(env.mode, Mode::Vm, "re-adopt uses sig.mode (Vm)");
        assert_eq!(env.vmid, Some(123));
        assert_eq!(env.mac, "");
    }

    #[test]
    fn foreign_instance_is_ignored() {
        // An instance with no GUID is foreign: no flag, no row, no teardown.
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        let s = InstanceSignals {
            name: "someone-elses".into(),
            guid: None,
            owner: None,
            mac: Some("11:22:33:44:55:66".into()),
            ssh_host_key_fps: Vec::new(),
            image: "other".into(),
            status: "running".into(),
            mode: Mode::Lxc,
            vmid: None,
        };
        let k = FakeKento::new();
        k.set_instances(vec![s]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(
            out,
            SweepOutcome {
                quorum_lost: None,
                ..Default::default()
            }
        );
        assert!(k.teardowns().is_empty());
    }

    #[test]
    fn vanished_active_row_with_no_live_instance_is_marked() {
        // An Active DB row whose GUID is absent from the live set → vanished.
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "gone", now - 3600, now + 3600);
        // No live instance carries "gone".
        let k = FakeKento::new();
        k.set_instances(vec![]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.vanished, 1);
        assert_eq!(out.reaped, 0);
        assert_eq!(
            store::get_env(&conn, "gone").unwrap().unwrap().status,
            EnvStatus::Vanished
        );
    }

    #[test]
    fn young_active_row_absent_from_live_is_not_vanished() {
        // A just-written Active row (age < age_floor) whose GUID is absent from
        // the live set must NOT be vanished: create is not atomic, so the row
        // can land before its instance appears in `kento list`. The create
        // window defers it to a later sweep — the row stays Active.
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        // Created just now (well within the 5m age floor).
        insert_active(&conn, "fresh", now, now + 3600);
        // No live instance carries "fresh" yet (kento create still landing).
        let k = FakeKento::new();
        k.set_instances(vec![]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.vanished, 0, "create-window row must not be vanished");
        assert_eq!(
            store::get_env(&conn, "fresh").unwrap().unwrap().status,
            EnvStatus::Active,
            "deferred create-window row stays Active, not Vanished"
        );
    }

    #[test]
    fn present_live_guid_is_not_vanished() {
        // The reaped row is removed from Active; a still-live agreeing row is
        // neither reaped (deadline in the future) nor vanished.
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "live", now - 3600, now + 3600);
        let k = FakeKento::new();
        k.set_instances(vec![signals_for(&conn, "live")]);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.vanished, 0);
        assert_eq!(out.reaped, 0);
        assert_eq!(
            store::get_env(&conn, "live").unwrap().unwrap().status,
            EnvStatus::Active
        );
    }

    #[test]
    fn herd_cap_caps_reaps_and_reports_deferred() {
        let c = config(); // herd_cap = 2
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        let mut instances = Vec::new();
        for i in 0..5u32 {
            let guid = format!("g{i}");
            // Distinct names so teardown-by-name is unambiguous.
            let env = Env {
                guid: guid.clone(),
                vmid: None,
                mode: Mode::Vm,
                owner: "alice".into(),
                image: "loom".into(),
                name: format!("seadog-alice-p-{guid}"),
                ip: format!("192.168.99.{}", 200 + i),
                mac: String::new(),
                ssh_host_key_fps: Vec::new(),
                created_at: now - 3600,
                ttl_deadline: now - 100,
                soft_deadline: now - 700,
                status: EnvStatus::Active,
            };
            store::insert_env(&conn, &env).unwrap();
            instances.push(signals_for(&conn, &guid));
        }
        let k = FakeKento::new();
        k.set_instances(instances);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.reaped, 2, "herd cap limits reaps per sweep");
        assert_eq!(out.deferred, 3, "remainder carried + reported");
        assert_eq!(k.teardowns().len(), 2);
        // The 3 deferred rows stay Active for the next tick.
        assert_eq!(
            store::list_by_status(&conn, EnvStatus::Active)
                .unwrap()
                .len(),
            3
        );
        // Deferred-but-still-live rows must NOT be counted vanished.
        assert_eq!(out.vanished, 0);
    }

    #[test]
    fn herd_cap_zero_means_unlimited_reaps_all() {
        // herd_cap = 0 is UNLIMITED (no throttle): with multiple eligible
        // envs, ALL are reaped — none stranded/deferred forever.
        let yaml = r#"
lifecycle:
  herd_cap: 0
images:
  loom:
    ref: "r/loom:1"
    modes: [vm]
"#;
        let c = Config::from_yaml_str(yaml).unwrap();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        let mut instances = Vec::new();
        for i in 0..5u32 {
            let guid = format!("g{i}");
            let env = Env {
                guid: guid.clone(),
                vmid: None,
                mode: Mode::Vm,
                owner: "alice".into(),
                image: "loom".into(),
                name: format!("seadog-alice-p-{guid}"),
                ip: format!("192.168.99.{}", 200 + i),
                mac: String::new(),
                ssh_host_key_fps: Vec::new(),
                created_at: now - 3600,
                ttl_deadline: now - 100,
                soft_deadline: now - 700,
                status: EnvStatus::Active,
            };
            store::insert_env(&conn, &env).unwrap();
            instances.push(signals_for(&conn, &guid));
        }
        let k = FakeKento::new();
        k.set_instances(instances);

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.reaped, 5, "herd_cap 0 = unlimited: all eligible reaped");
        assert_eq!(out.deferred, 0, "nothing stranded under unlimited cap");
        assert_eq!(k.teardowns().len(), 5);
        // No Active rows remain — none stranded.
        assert_eq!(
            store::list_by_status(&conn, EnvStatus::Active)
                .unwrap()
                .len(),
            0
        );
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
        assert_eq!(out.vanished, 0, "no vanished pass on quorum loss");
        assert_eq!(store::read_heartbeat(&conn).unwrap(), Some(now));
    }

    #[test]
    fn nonquorum_teardown_failure_defers_not_reaps() {
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 1_000_000i64;
        insert_active(&conn, "g1", now - 3600, now - 100);
        let k = FakeKento::new();
        k.set_instances(vec![signals_for(&conn, "g1")]);
        k.fail_teardown("seadog-alice-p-g1", "lock busy");

        let out = sweep(&k, &conn, &c, now).unwrap();
        assert_eq!(out.reaped, 0);
        assert_eq!(out.deferred, 1);
        assert!(out.quorum_lost.is_none());
        // A failed teardown leaves the row Active — and the live instance is
        // still listed, so it must NOT be counted vanished.
        assert_eq!(out.vanished, 0);
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
