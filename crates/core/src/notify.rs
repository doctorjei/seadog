//! Notifications: journald default + pluggable push, class-specific
//! escalation.
//!
//! The **policy is split from the plumbing**: [`decide`] is a pure
//! function — given an [`Event`], the prior [`NotifyState`], the config,
//! and `now` — that returns a [`NotifyDecision`] (severity, whether to
//! emit, whether to fire the push sink, and the next state). It is fully
//! unit-testable without a journal. The emit layer ([`emit`]) does the
//! journald write (falling back to stderr if the socket is unavailable —
//! a logging failure must never stop reaping) and runs the optional push
//! sink under a hard timeout ([`PUSH_TIMEOUT`]) so a flaky *or hanging*
//! webhook can't wedge the reaper: emit runs inside the sweep, so the push
//! command is bounded, killed + reaped on expiry, and its failure swallowed.
//!
//! ## Class policy
//! - **Foreign-in-range heads-up**: emit ONCE per appearance, with an
//!   ack/suppress path; don't nag.
//! - **Our overdue-but-unreaped + anomalies**: re-alert on a backoff
//!   (`notify.reescalate`, default 30m — not every tick) with climbing
//!   severity (notice → warning → crit) until resolved, firing the push
//!   sink on EVERY escalation.
//! - **Sweeper-degraded** (quorum loss): `crit`.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use wait_timeout::ChildExt as _;

use crate::config::Config;
use crate::models::NotifyState;
use crate::Error;

/// Severity ladder, low→high. Serializes to the journald `PRIORITY`
/// word the operator greps for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Foreign heads-up — informational.
    Info,
    /// Lifecycle (reap/ttl/overrun/vanished).
    Notice,
    /// Anomaly needing a human decision.
    Warning,
    /// Sweeper degraded (quorum loss) — and the top of the OUR-problem
    /// escalation ladder.
    Crit,
}

impl Severity {
    /// Stable lowercase tag (journald PRIORITY word / state column).
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Notice => "notice",
            Severity::Warning => "warning",
            Severity::Crit => "crit",
        }
    }

    fn from_str_opt(s: &str) -> Option<Severity> {
        match s {
            "info" => Some(Severity::Info),
            "notice" => Some(Severity::Notice),
            "warning" => Some(Severity::Warning),
            "crit" => Some(Severity::Crit),
            _ => None,
        }
    }

    /// Next rung up the OUR-problem ladder (notice → warning → crit, then
    /// saturates at crit).
    fn climb(self) -> Severity {
        match self {
            Severity::Info => Severity::Notice,
            Severity::Notice => Severity::Warning,
            Severity::Warning => Severity::Crit,
            Severity::Crit => Severity::Crit,
        }
    }
}

/// The classes of thing seadog reports, each with its own escalation
/// policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum Event {
    /// A foreign guest squatting in our vmid range. One-time, ack-able.
    ForeignHeadsUp {
        guid_or_vmid: String,
        detail: String,
    },
    /// An identity anomaly that needs an operator decision. Re-alerts on
    /// backoff with climbing severity.
    Anomaly { guid: String, detail: String },
    /// Our env is overdue but still unreaped (e.g. herd-capped or
    /// teardown-failing). Re-alerts on backoff with climbing severity.
    OverdueUnreaped { guid: String, detail: String },
    /// A normal lifecycle event (reaped / ttl / vanished). One emit.
    Lifecycle { guid: String, detail: String },
    /// The sweeper itself is degraded (quorum loss). Always crit.
    SweeperDegraded { detail: String },
}

impl Event {
    /// The state key (env guid, or a vmid token for foreign guests).
    fn key(&self) -> &str {
        match self {
            Event::ForeignHeadsUp { guid_or_vmid, .. } => guid_or_vmid,
            Event::Anomaly { guid, .. }
            | Event::OverdueUnreaped { guid, .. }
            | Event::Lifecycle { guid, .. } => guid,
            Event::SweeperDegraded { .. } => "sweeper",
        }
    }

    /// Human/JSON detail string.
    fn detail(&self) -> &str {
        match self {
            Event::ForeignHeadsUp { detail, .. }
            | Event::Anomaly { detail, .. }
            | Event::OverdueUnreaped { detail, .. }
            | Event::Lifecycle { detail, .. }
            | Event::SweeperDegraded { detail } => detail,
        }
    }

    /// Does this class re-alert on the `reescalate` backoff with climbing
    /// severity (our unresolved problems), versus emit once?
    fn escalates(&self) -> bool {
        matches!(self, Event::Anomaly { .. } | Event::OverdueUnreaped { .. })
    }

    /// Base severity for the class (the floor / first-emit level).
    fn base_severity(&self) -> Severity {
        match self {
            Event::ForeignHeadsUp { .. } => Severity::Info,
            Event::Anomaly { .. } => Severity::Warning,
            Event::OverdueUnreaped { .. } | Event::Lifecycle { .. } => Severity::Notice,
            Event::SweeperDegraded { .. } => Severity::Crit,
        }
    }
}

/// The pure policy verdict for one event. The emit layer consumes this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyDecision {
    /// Severity to tag the emission with.
    pub severity: Severity,
    /// Whether to emit at all this tick (false = suppressed by ack or
    /// still inside the backoff window).
    pub emit: bool,
    /// Whether to fire the push sink (command/dir). Fires on every
    /// escalation, not just the first emit.
    pub fire_push: bool,
    /// The state to persist for the next tick (only when `emit`).
    pub new_state: NotifyState,
}

/// Decide whether/how to notify for `event`, given the `prior` state.
///
/// Pure: no I/O, no clock read — `now_unix` is injected so tests drive
/// time. The emit layer persists `new_state` only when `emit` is true.
pub fn decide(
    event: &Event,
    prior: Option<&NotifyState>,
    config: &Config,
    now_unix: i64,
) -> NotifyDecision {
    let key = event.key().to_string();
    let reescalate = config.notify.reescalate.as_secs() as i64;

    // Acked → fully suppressed until the operator clears it.
    if let Some(p) = prior {
        if p.acked {
            return NotifyDecision {
                severity: prior_sev(prior, event),
                emit: false,
                fire_push: false,
                new_state: p.clone(),
            };
        }
    }

    if event.escalates() {
        // OUR unresolved problem: re-alert only after reescalate elapses,
        // with climbing severity; push fires on every escalation.
        match prior {
            None => {
                // First sighting → emit at base severity.
                let sev = event.base_severity();
                NotifyDecision {
                    severity: sev,
                    emit: true,
                    fire_push: true,
                    new_state: NotifyState {
                        guid: key,
                        last_severity: sev.as_str().to_string(),
                        last_emitted_at: now_unix,
                        acked: false,
                    },
                }
            }
            Some(p) => {
                let elapsed = now_unix - p.last_emitted_at;
                if elapsed < reescalate {
                    // Still inside the backoff window → stay quiet.
                    NotifyDecision {
                        severity: prior_sev(prior, event),
                        emit: false,
                        fire_push: false,
                        new_state: p.clone(),
                    }
                } else {
                    // Backoff elapsed → escalate one rung, fire push.
                    let next = prior_sev(prior, event).climb();
                    NotifyDecision {
                        severity: next,
                        emit: true,
                        fire_push: true,
                        new_state: NotifyState {
                            guid: key,
                            last_severity: next.as_str().to_string(),
                            last_emitted_at: now_unix,
                            acked: false,
                        },
                    }
                }
            }
        }
    } else {
        // One-shot classes (foreign heads-up, lifecycle, sweeper-degraded):
        // emit once per appearance. A prior un-acked state means we
        // already spoke → suppress (don't nag).
        let already_emitted = prior.is_some();
        let sev = event.base_severity();
        if already_emitted {
            NotifyDecision {
                severity: sev,
                emit: false,
                fire_push: false,
                new_state: prior.cloned().unwrap(),
            }
        } else {
            NotifyDecision {
                severity: sev,
                emit: true,
                fire_push: true,
                new_state: NotifyState {
                    guid: key,
                    last_severity: sev.as_str().to_string(),
                    last_emitted_at: now_unix,
                    acked: false,
                },
            }
        }
    }
}

/// The prior severity if recorded, else the event's base severity.
fn prior_sev(prior: Option<&NotifyState>, event: &Event) -> Severity {
    prior
        .and_then(|p| Severity::from_str_opt(&p.last_severity))
        .unwrap_or_else(|| event.base_severity())
}

/// Initialize the journald tracing sink, resilient to an absent socket.
///
/// If the journal socket is unavailable we fall back to a stderr
/// subscriber so logging keeps working — a logging failure must never
/// stop reaping. Idempotent: only the first call installs a subscriber.
pub fn init_logging() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::prelude::*;
        let registry = tracing_subscriber::registry();
        match tracing_journald::layer() {
            Ok(journald) => {
                // Tag every line with SYSLOG_IDENTIFIER=seadog.
                let journald = journald.with_syslog_identifier("seadog".to_string());
                let _ = registry.with(journald).try_init();
            }
            Err(_) => {
                // Journal socket unavailable → stderr, never fatal.
                let stderr = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
                let _ = registry.with(stderr).try_init();
            }
        }
    });
}

/// Emit a decided event: structured log line + optional push sink.
///
/// Never returns an error from the journald path — logging is best-effort
/// (init already falls back to stderr). Push-sink failures are logged but
/// also swallowed, and the push command runs under [`PUSH_TIMEOUT`]
/// (killed + reaped on expiry), so a flaky *or hanging* webhook can't
/// wedge the reaper.
pub fn emit(event: &Event, decision: &NotifyDecision, config: &Config) {
    if !decision.emit {
        return;
    }
    let sev = decision.severity;
    let detail = event.detail();
    let key = event.key();
    // tracing levels don't map 1:1 to syslog priority words, so we carry
    // the severity as a field and rely on init's SYSLOG_IDENTIFIER.
    match sev {
        Severity::Crit | Severity::Warning => {
            tracing::warn!(severity = sev.as_str(), key, "{detail}");
        }
        Severity::Notice | Severity::Info => {
            tracing::info!(severity = sev.as_str(), key, "{detail}");
        }
    }

    if decision.fire_push {
        fire_push(event, decision, config);
    }
}

/// Run the push sink(s): `notify.command` (event as JSON on stdin + a
/// single argv arg) and/or `notify.dir` (drop a JSON file). Side-effecting
/// and best-effort — failures are logged, never propagated.
fn fire_push(event: &Event, decision: &NotifyDecision, config: &Config) {
    let payload = match push_payload(event, decision) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("notify: failed to build push payload: {e}");
            return;
        }
    };

    if let Some(cmd) = &config.notify.command {
        if let Err(e) = run_command(cmd, &payload) {
            tracing::warn!("notify: push command failed: {e}");
        }
    }
    if let Some(dir) = &config.notify.dir {
        if let Err(e) = drop_file(dir, event, &payload) {
            tracing::warn!("notify: push dir write failed: {e}");
        }
    }
}

/// The JSON payload handed to push sinks.
fn push_payload(event: &Event, decision: &NotifyDecision) -> Result<String, Error> {
    let v = serde_json::json!({
        "severity": decision.severity.as_str(),
        "key": event.key(),
        "event": event,
    });
    serde_json::to_string(&v).map_err(|e| Error::Kento(format!("json: {e}")))
}

/// Hard wall-clock bound on the operator's push command. emit() runs
/// inside the sweep, so an unbounded `wait()` on a hanging hook (e.g. curl
/// to a black-holed host) would stall ALL reaping. We kill + reap on expiry
/// instead of blocking forever; the timeout is reported as a non-fatal
/// [`Error::Kento`] that the caller logs and swallows.
const PUSH_TIMEOUT: Duration = Duration::from_secs(5);

fn run_command(cmd: &str, payload: &str) -> Result<(), Error> {
    // Pass the JSON both as a single argv argument and on stdin so simple
    // sinks can use either. Built as an argv vector (no shell).
    let mut child = Command::new(cmd)
        .arg(payload)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| Error::Kento(format!("spawn push command '{cmd}': {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(payload.as_bytes());
    }
    // Bounded wait: a hanging hook must not wedge the sweep. On expiry, kill
    // and reap the child (the reaper is long-running — no zombies) and map to
    // a non-fatal error the caller logs + swallows.
    let status = match child
        .wait_timeout(PUSH_TIMEOUT)
        .map_err(|e| Error::Kento(format!("wait push command: {e}")))?
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::Kento(format!(
                "push command '{cmd}' timed out after {}s",
                PUSH_TIMEOUT.as_secs()
            )));
        }
    };
    if !status.success() {
        return Err(Error::Kento(format!(
            "push command exited {:?}",
            status.code()
        )));
    }
    Ok(())
}

fn drop_file(dir: &str, event: &Event, payload: &str) -> Result<(), Error> {
    let path = std::path::Path::new(dir).join(format!(
        "seadog-{}-{}.json",
        event.key(),
        crate::now_unix()
    ));
    std::fs::write(&path, payload)
        .map_err(|e| Error::Kento(format!("write {}: {e}", path.display())))
}

/// Prune terminal env rows older than `retention.terminal`. Thin wrapper
/// over [`crate::store::prune_terminal`] that reads the duration from the
/// config; live envs are never pruned no matter how overdue. Returns the
/// number of rows removed.
pub fn prune_terminal(
    conn: &rusqlite::Connection,
    config: &Config,
    now_unix: i64,
) -> Result<usize, Error> {
    let retention = config.retention.terminal.as_secs() as i64;
    crate::store::prune_terminal(conn, now_unix, retention)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::models::{Env, EnvStatus, Mode};
    use crate::store;

    fn config() -> Config {
        // reescalate defaults to 30m; retention.terminal to 7d.
        let yaml = r#"
images:
  loom:
    ref: "r/loom:1"
    modes: [vm]
"#;
        Config::from_yaml_str(yaml).unwrap()
    }

    #[test]
    fn journald_unavailable_falls_back_without_error() {
        // No journal socket in this sandbox → must not panic / error.
        init_logging();
        let c = config();
        let ev = Event::Lifecycle {
            guid: "g1".into(),
            detail: "reaped".into(),
        };
        let d = decide(&ev, None, &c, 1000);
        emit(&ev, &d, &c); // must not panic
        assert!(d.emit);
    }

    #[test]
    fn foreign_headsup_emits_once_then_suppresses() {
        let c = config();
        let ev = Event::ForeignHeadsUp {
            guid_or_vmid: "vmid-10010".into(),
            detail: "foreign".into(),
        };
        let first = decide(&ev, None, &c, 1000);
        assert!(first.emit);
        assert_eq!(first.severity, Severity::Info);

        // Second appearance with the prior state → suppressed.
        let second = decide(&ev, Some(&first.new_state), &c, 2000);
        assert!(!second.emit);
    }

    #[test]
    fn ack_suppresses_headsup() {
        let c = config();
        let ev = Event::ForeignHeadsUp {
            guid_or_vmid: "vmid-10010".into(),
            detail: "foreign".into(),
        };
        let first = decide(&ev, None, &c, 1000);
        let mut acked = first.new_state.clone();
        acked.acked = true;
        let d = decide(&ev, Some(&acked), &c, 5_000_000);
        assert!(!d.emit);
    }

    #[test]
    fn overdue_reescalates_only_after_backoff_with_climbing_severity_and_push() {
        let c = config();
        let reescalate = c.notify.reescalate.as_secs() as i64; // 1800s
        let ev = Event::OverdueUnreaped {
            guid: "g1".into(),
            detail: "overdue".into(),
        };

        // First emit: notice, push fires.
        let d0 = decide(&ev, None, &c, 0);
        assert!(d0.emit && d0.fire_push);
        assert_eq!(d0.severity, Severity::Notice);

        // Within backoff → suppressed.
        let d_mid = decide(&ev, Some(&d0.new_state), &c, reescalate - 1);
        assert!(!d_mid.emit && !d_mid.fire_push);

        // After backoff → escalate to warning, push fires again.
        let d1 = decide(&ev, Some(&d0.new_state), &c, reescalate);
        assert!(d1.emit && d1.fire_push);
        assert_eq!(d1.severity, Severity::Warning);

        // Next escalation → crit.
        let d2 = decide(&ev, Some(&d1.new_state), &c, reescalate * 2);
        assert!(d2.emit && d2.fire_push);
        assert_eq!(d2.severity, Severity::Crit);

        // Saturates at crit.
        let d3 = decide(&ev, Some(&d2.new_state), &c, reescalate * 3);
        assert_eq!(d3.severity, Severity::Crit);
    }

    #[test]
    fn anomaly_starts_at_warning() {
        let c = config();
        let ev = Event::Anomaly {
            guid: "g1".into(),
            detail: "renamed".into(),
        };
        let d = decide(&ev, None, &c, 0);
        assert_eq!(d.severity, Severity::Warning);
        assert!(d.emit && d.fire_push);
    }

    #[test]
    fn sweeper_degraded_is_crit() {
        let c = config();
        let ev = Event::SweeperDegraded {
            detail: "quorum lost".into(),
        };
        let d = decide(&ev, None, &c, 0);
        assert_eq!(d.severity, Severity::Crit);
    }

    fn env(guid: &str, status: EnvStatus, created_at: i64) -> Env {
        Env {
            guid: guid.into(),
            vmid: Some(10010),
            mode: Mode::Vm,
            owner: "alice".into(),
            image: "loom".into(),
            name: "seadog-alice-p-a".into(),
            ip: "192.168.99.200".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ssh_host_key_fps: Vec::new(),
            created_at,
            ttl_deadline: created_at + 100,
            soft_deadline: created_at + 50,
            status,
        }
    }

    #[test]
    fn run_command_bounds_a_hanging_hook() {
        // A hanging push command (here `sleep` for far longer than the bound)
        // must NOT block emit forever: run_command kills + reaps it and returns
        // a non-fatal error well inside a generous wall-clock budget. This is
        // the regression guard for the "can't wedge the reaper" claim.
        use std::time::Instant;

        // Sleep ~60s — wildly past PUSH_TIMEOUT (5s) — so a successful return
        // can only come from the timeout path, never the child finishing.
        let started = Instant::now();
        let result = run_command("/bin/sleep", "60");
        let elapsed = started.elapsed();

        // Timed out → non-fatal error (logged + swallowed by fire_push).
        assert!(result.is_err(), "a hanging hook must surface as an error");
        // Returned promptly: bounded by PUSH_TIMEOUT, not the 60s sleep. The
        // slack absorbs kill/reap + scheduler jitter without flaking.
        assert!(
            elapsed < PUSH_TIMEOUT + Duration::from_secs(10),
            "run_command must return within the bound, took {elapsed:?}"
        );
    }

    #[test]
    fn prune_keeps_live_overdue_drops_old_terminal() {
        let c = config();
        let conn = store::open_in_memory().unwrap();
        let now = 100_000_000i64;
        let retention = c.retention.terminal.as_secs() as i64; // 7d

        // Live env, wildly overdue (created long ago) — must SURVIVE.
        store::insert_env(&conn, &env("live", EnvStatus::Active, 0)).unwrap();
        // Terminal env older than retention — must be DROPPED.
        store::insert_env(
            &conn,
            &env("old-reaped", EnvStatus::Reaped, now - retention - 10),
        )
        .unwrap();
        // Terminal env within retention — must SURVIVE.
        store::insert_env(
            &conn,
            &env("recent-vanished", EnvStatus::Vanished, now - 10),
        )
        .unwrap();

        let removed = prune_terminal(&conn, &c, now).unwrap();
        assert_eq!(removed, 1);

        assert!(store::get_env(&conn, "live").unwrap().is_some());
        assert!(store::get_env(&conn, "old-reaped").unwrap().is_none());
        assert!(store::get_env(&conn, "recent-vanished").unwrap().is_some());
    }
}
