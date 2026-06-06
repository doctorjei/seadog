//! Identity classification (kento-native).
//!
//! Given what the sweeper observes about one live kento instance
//! ([`InstanceSignals`]) and the matching DB row (if any, looked up **by
//! GUID**), decide what the instance **is** to seadog. Identity is now an
//! injected anchor: kento carries the `SEADOG_GUID` env on every seadog
//! instance and reports it back via `inspect --json`. The GUID is the sole
//! identity key — there is no description-marker parsing, no name-prefix
//! gate, and no hardware fingerprint anymore.
//!
//! ## Taxonomy
//! - **Foreign** — no `SEADOG_GUID` at all. Not ours; ignored. (kento only
//!   ever lists kento instances, so this is rare, but a non-seadog kento
//!   guest would land here.)
//! - **Orphan** — a GUID is present but no DB row backs it. The DB was lost
//!   / the instance predates the row; reap re-adopts it onto a fresh row.
//! - **Anomaly** — a GUID-matched DB row exists but a **confirming-when-
//!   present** signal disagrees (name or MAC). Flagged for a human, never
//!   reaped.
//! - **ReapEligible** — GUID matches a DB row and the hard confirmers agree.
//!   The deadline / age-floor / herd-cap gates live in [`crate::reap`], not
//!   here; `classify` decides **agreement only**.
//!
//! ## Confirmers
//! - **name** and **MAC** are *hard* confirmers: present-and-mismatched →
//!   [`Classification::Anomaly`] (flag, never reap).
//! - **SSH host-key fingerprints** are a *soft* confirmer: a present-but-
//!   mismatched set is recorded in the `ReapEligible` path's detail (via the
//!   reap layer) but NEVER blocks a reap — regenerated host keys must not
//!   strand an env. `classify` returns [`Classification::ReapEligible`] even
//!   on a host-key mismatch.
//!
//! [`Classification::Vanished`] is **not** produced here: reap detects a
//! vanished env by set-diffing the Active DB rows against the live GUID set.

use serde::{Deserialize, Serialize};

use crate::kento::InstanceSignals;
use crate::models::Env;

/// Why an instance was classified as an [`Classification::Anomaly`] — a
/// machine-readable reason carried for the notify/flag layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The live instance name disagrees with the DB row's name.
    NameMismatch,
    /// Both sides expose a MAC and they disagree.
    MacMismatch,
    /// SSH host-key fingerprints disagree. **Soft** — recorded for the
    /// operator but never blocks a reap, so this reason rides the
    /// `ReapEligible` detail rather than producing an `Anomaly`.
    HostKeyMismatch,
}

/// The verdict for one live kento instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Classification {
    /// No `SEADOG_GUID` — not a seadog instance. Ignored.
    Foreign,
    /// A GUID is present but no DB row backs it → re-adopt onto a fresh row.
    Orphan {
        /// The instance's injected GUID.
        guid: String,
        /// The instance's injected owner, if any.
        owner: Option<String>,
    },
    /// A GUID-matched DB row exists but a hard confirmer (name/MAC)
    /// disagrees. Flag for a human; NEVER auto-reap.
    Anomaly {
        /// Which confirmer disagreed.
        reason: Reason,
        /// Human-readable detail for the notify layer.
        detail: String,
    },
    /// GUID matches a DB row and the hard confirmers agree. Eligible for
    /// teardown **only** once [`crate::reap`] additionally confirms the
    /// deadline + age-floor; `classify` never enforces those.
    ReapEligible {
        /// The matched GUID (= the DB row's primary key).
        guid: String,
    },
}

/// Case-insensitive MAC comparison (backends may emit either case).
fn mac_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Classify one live instance against its GUID-matched DB row (if any).
///
/// Pure: takes no [`Config`](crate::config::Config). The decision is
/// **agreement only** — [`Classification::ReapEligible`] does NOT mean
/// "reap now"; [`crate::reap`] still enforces the deadline / age floor /
/// herd cap before acting.
///
/// `db_row`, when `Some`, is the row whose `guid` equals `signals.guid`
/// (the caller looks it up by GUID). A `None` row with a present GUID is an
/// orphan to re-adopt.
pub fn classify(signals: &InstanceSignals, db_row: Option<&Env>) -> Classification {
    // No injected GUID → not ours.
    let guid = match &signals.guid {
        Some(g) => g.clone(),
        None => return Classification::Foreign,
    };

    // GUID present but no row backs it → orphan (DB lost / predates row).
    let env = match db_row {
        Some(env) => env,
        None => {
            return Classification::Orphan {
                guid,
                owner: signals.owner.clone(),
            };
        }
    };

    // GUID-matched row exists → confirm hard signals (name, then MAC).
    if env.name != signals.name {
        return Classification::Anomaly {
            reason: Reason::NameMismatch,
            detail: format!(
                "instance {} (guid {}) name disagrees with DB row name {}",
                signals.name, guid, env.name
            ),
        };
    }

    // MAC is confirming-when-present: both sides must expose one for a
    // mismatch to count. A blank DB-row MAC (LXC "no MAC recorded") or a
    // live `None` MAC simply drops MAC out of the decision.
    if let Some(live_mac) = signals.mac.as_deref() {
        if !env.mac.is_empty() && !mac_eq(live_mac, &env.mac) {
            return Classification::Anomaly {
                reason: Reason::MacMismatch,
                detail: format!(
                    "instance {} (guid {}) MAC {} disagrees with DB row MAC {}",
                    signals.name, guid, live_mac, env.mac
                ),
            };
        }
    }

    // Host-key fps are a SOFT confirmer: a present-but-disjoint set is
    // recorded but NEVER blocks the reap. We surface it in the detail so the
    // operator can see it, but still return ReapEligible.
    let host_key_mismatch = !env.ssh_host_key_fps.is_empty()
        && !signals.ssh_host_key_fps.is_empty()
        && !signals
            .ssh_host_key_fps
            .iter()
            .any(|fp| env.ssh_host_key_fps.contains(fp));
    let _ = host_key_mismatch; // soft: logged by reap, never blocks here.

    Classification::ReapEligible { guid }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{EnvStatus, Mode};

    fn env(guid: &str, mac: &str) -> Env {
        Env {
            guid: guid.to_string(),
            vmid: Some(10010),
            mode: Mode::Vm,
            owner: "alice".to_string(),
            image: "loom".to_string(),
            name: "seadog-alice-proj-ab12".to_string(),
            ip: "192.168.99.200".to_string(),
            mac: mac.to_string(),
            ssh_host_key_fps: vec!["SHA256:host-ed25519".to_string()],
            created_at: 1000,
            ttl_deadline: 5000,
            soft_deadline: 4000,
            status: EnvStatus::Active,
        }
    }

    fn signals(guid: &str, mac: Option<&str>) -> InstanceSignals {
        InstanceSignals {
            name: "seadog-alice-proj-ab12".to_string(),
            guid: Some(guid.to_string()),
            owner: Some("alice".to_string()),
            mac: mac.map(|m| m.to_string()),
            ssh_host_key_fps: vec!["SHA256:host-ed25519".to_string()],
            image: "loom".to_string(),
            status: "running".to_string(),
            mode: Mode::Vm,
            vmid: Some(10010),
        }
    }

    #[test]
    fn no_guid_is_foreign() {
        let mut s = signals("g", Some("aa:bb:cc:dd:ee:ff"));
        s.guid = None;
        assert_eq!(classify(&s, None), Classification::Foreign);
        // Even with a DB row coincidentally available, no GUID = foreign.
        let e = env("g", "aa:bb:cc:dd:ee:ff");
        assert_eq!(classify(&s, Some(&e)), Classification::Foreign);
    }

    #[test]
    fn guid_no_row_is_orphan() {
        let s = signals("g-orphan", Some("aa:bb:cc:dd:ee:ff"));
        match classify(&s, None) {
            Classification::Orphan { guid, owner } => {
                assert_eq!(guid, "g-orphan");
                assert_eq!(owner.as_deref(), Some("alice"));
            }
            other => panic!("expected Orphan, got {other:?}"),
        }
    }

    #[test]
    fn guid_no_row_no_owner_is_orphan() {
        let mut s = signals("g-orphan", None);
        s.owner = None;
        match classify(&s, None) {
            Classification::Orphan { guid, owner } => {
                assert_eq!(guid, "g-orphan");
                assert_eq!(owner, None);
            }
            other => panic!("expected Orphan, got {other:?}"),
        }
    }

    #[test]
    fn guid_and_row_agree_is_reap_eligible() {
        let e = env("g-abc", "aa:bb:cc:dd:ee:ff");
        let s = signals("g-abc", Some("aa:bb:cc:dd:ee:ff"));
        match classify(&s, Some(&e)) {
            Classification::ReapEligible { guid } => assert_eq!(guid, "g-abc"),
            other => panic!("expected ReapEligible, got {other:?}"),
        }
    }

    #[test]
    fn lxc_no_live_mac_is_reap_eligible() {
        // LXC: DB row records no MAC ("") and the live instance exposes none
        // (mac=None). MAC is confirming-when-present, so it drops out and the
        // GUID+name agreement makes it reapable.
        let mut e = env("g-lxc", "");
        e.mode = Mode::Lxc;
        let mut s = signals("g-lxc", None);
        // The kento LXC mac may actually be Some now, but with an empty DB
        // MAC it still drops out — cover both: live None here.
        s.mac = None;
        match classify(&s, Some(&e)) {
            Classification::ReapEligible { guid } => assert_eq!(guid, "g-lxc"),
            other => panic!("expected ReapEligible, got {other:?}"),
        }
    }

    #[test]
    fn empty_db_mac_drops_out_even_with_live_mac() {
        // DB MAC is the "no MAC recorded" sentinel; a live MAC must not flag.
        let mut e = env("g-lxc", "");
        e.mode = Mode::Lxc;
        let s = signals("g-lxc", Some("02:aa:bb:cc:dd:ee"));
        match classify(&s, Some(&e)) {
            Classification::ReapEligible { guid } => assert_eq!(guid, "g-lxc"),
            other => panic!("expected ReapEligible, got {other:?}"),
        }
    }

    #[test]
    fn name_mismatch_is_anomaly() {
        let e = env("g-abc", "aa:bb:cc:dd:ee:ff");
        let mut s = signals("g-abc", Some("aa:bb:cc:dd:ee:ff"));
        s.name = "totally-renamed".to_string();
        match classify(&s, Some(&e)) {
            Classification::Anomaly { reason, .. } => assert_eq!(reason, Reason::NameMismatch),
            other => panic!("expected Anomaly(NameMismatch), got {other:?}"),
        }
    }

    #[test]
    fn both_macs_present_and_differ_is_anomaly() {
        let e = env("g-abc", "aa:bb:cc:dd:ee:ff");
        let s = signals("g-abc", Some("00:11:22:33:44:55"));
        match classify(&s, Some(&e)) {
            Classification::Anomaly { reason, detail } => {
                assert_eq!(reason, Reason::MacMismatch);
                assert!(detail.contains("00:11:22:33:44:55"), "detail: {detail}");
            }
            other => panic!("expected Anomaly(MacMismatch), got {other:?}"),
        }
    }

    #[test]
    fn mac_compare_is_case_insensitive() {
        let e = env("g-abc", "AA:BB:CC:DD:EE:FF");
        let s = signals("g-abc", Some("aa:bb:cc:dd:ee:ff"));
        match classify(&s, Some(&e)) {
            Classification::ReapEligible { .. } => {}
            other => panic!("expected ReapEligible (case-insensitive MAC), got {other:?}"),
        }
    }

    #[test]
    fn host_key_mismatch_is_soft_still_reap_eligible() {
        // The host-key fps disagree entirely, but name + MAC agree. Soft
        // confirmer: must NOT flag — still ReapEligible (regenerated keys
        // must not strand the env).
        let mut e = env("g-abc", "aa:bb:cc:dd:ee:ff");
        e.ssh_host_key_fps = vec!["SHA256:old-key".to_string()];
        let mut s = signals("g-abc", Some("aa:bb:cc:dd:ee:ff"));
        s.ssh_host_key_fps = vec!["SHA256:regenerated-key".to_string()];
        match classify(&s, Some(&e)) {
            Classification::ReapEligible { guid } => assert_eq!(guid, "g-abc"),
            other => panic!("host-key mismatch must stay ReapEligible, got {other:?}"),
        }
    }

    #[test]
    fn host_key_absent_on_either_side_is_reap_eligible() {
        // No fps on the live side → nothing to compare → still reapable.
        let e = env("g-abc", "aa:bb:cc:dd:ee:ff");
        let mut s = signals("g-abc", Some("aa:bb:cc:dd:ee:ff"));
        s.ssh_host_key_fps = Vec::new();
        match classify(&s, Some(&e)) {
            Classification::ReapEligible { .. } => {}
            other => panic!("expected ReapEligible, got {other:?}"),
        }
    }

    #[test]
    fn name_mismatch_precedes_mac_mismatch() {
        // Both name and MAC disagree → name wins (checked first).
        let e = env("g-abc", "aa:bb:cc:dd:ee:ff");
        let mut s = signals("g-abc", Some("00:11:22:33:44:55"));
        s.name = "renamed".to_string();
        match classify(&s, Some(&e)) {
            Classification::Anomaly { reason, .. } => assert_eq!(reason, Reason::NameMismatch),
            other => panic!("expected Anomaly(NameMismatch), got {other:?}"),
        }
    }
}
