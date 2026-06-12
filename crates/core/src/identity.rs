//! Identity classification (kento-native).
//!
//! Given what the sweeper observes about one live kento instance
//! ([`InstanceSignals`]) and the matching DB row (if any, looked up **by
//! GUID**), decide what the instance **is** to seadog. Identity is now an
//! injected anchor: kento carries the `SEADOG_GUID` env on every seadog
//! instance and reports it back via `inspect --json`. The GUID is the primary
//! identity key — there is no description-marker parsing or hardware
//! fingerprint anymore. A matched DB row is itself corroboration (seadog wrote
//! the row at provision), so a GUID that joins a row is trusted directly. The
//! UNMATCHED (no-row) case feeds the destructive re-adopt path, so it demands
//! two independent seadog signals: the GUID must parse as a seadog-minted UUID
//! (`Uuid::new_v4()`) AND the name must pass [`crate::validate::validate_guest_name`]
//! (the minted `seadog-<owner>-<proj>-<token>` label). Both come from the same
//! create path, so a genuine orphan always satisfies both.
//!
//! ## Taxonomy
//! - **Foreign** — no `SEADOG_GUID` at all, OR a GUID present with no DB row
//!   that fails either re-adopt gate (not a valid UUID, or a non-seadog name).
//!   Either way it is not (verifiably) ours; ignored — never re-adopted, never
//!   reaped. (kento only ever lists kento instances, so a missing GUID is rare,
//!   but a non-seadog kento guest would land here.) The gates are enforced here
//!   precisely because re-adoption is destructive (see Orphan) and must not act
//!   on an unverifiable identity.
//! - **Orphan** — a GUID is present, no DB row backs it, AND it clears both
//!   re-adopt gates (canonical seadog-minted UUID + valid `seadog-…` name). The
//!   DB was lost / the instance predates the row; reap re-adopts it onto a
//!   fresh row.
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
//!   mismatched set is carried out on [`Classification::ReapEligible`]'s
//!   `host_key_mismatch` flag, which the reap layer routes as a non-blocking
//!   operator note — it NEVER blocks a reap (regenerated host keys must not
//!   strand an env). `classify` returns [`Classification::ReapEligible`] even
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
    /// SSH host-key fingerprints disagree. **Soft** — surfaced to the
    /// operator but never blocks a reap, so this rides the `ReapEligible`
    /// `host_key_mismatch` flag (routed as a non-blocking note by the reap
    /// layer) rather than producing an `Anomaly`.
    HostKeyMismatch,
}

/// The verdict for one live kento instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Classification {
    /// Not (verifiably) a seadog instance — ignored (never re-adopted, never
    /// reaped). Either no `SEADOG_GUID` at all, or a GUID present with no DB
    /// row that fails a re-adopt gate (not a canonical seadog-minted UUID, or
    /// a name that is not a valid `seadog-…` label). An unverifiable identity
    /// must not enter the destructive re-adopt path; see [`Self::Orphan`].
    Foreign,
    /// A present GUID with no DB row that clears BOTH re-adopt gates — a
    /// canonical seadog-minted UUID and a valid `seadog-…` name → re-adopt
    /// onto a fresh row.
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
        /// SSH host-key fingerprints disagree (both sides present, disjoint).
        /// A **soft** signal: surfaced by [`crate::reap`] as a non-blocking
        /// operator breadcrumb, but it NEVER changes the reap decision —
        /// regenerated host keys must not strand an env.
        host_key_mismatch: bool,
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
/// orphan to re-adopt **only** when it clears both gates — the GUID parses as
/// a seadog-minted UUID AND the name is a valid `seadog-…` label; otherwise it
/// is [`Classification::Foreign`] (re-adoption is destructive and must not act
/// on an unverifiable identity).
pub fn classify(signals: &InstanceSignals, db_row: Option<&Env>) -> Classification {
    // No injected GUID → not ours.
    let guid = match &signals.guid {
        Some(g) => g.clone(),
        None => return Classification::Foreign,
    };

    // GUID present but no row backs it → re-adopt ONLY when the instance is
    // unmistakably seadog's on TWO independent signals. The re-adopt path is
    // destructive (fresh row → reap at deadline → `kento destroy -f`) and has
    // NO DB corroboration here, so a single signal is not enough:
    //   1. the GUID must parse as a canonical UUID — seadog mints GUIDs as
    //      `Uuid::new_v4()` (create.rs), so a real seadog GUID always does; and
    //   2. the name must pass `validate_guest_name` — the minted
    //      `seadog-<owner>-<proj>-<token>` label (create.rs uses the same
    //      validator), so a genuine orphan always does.
    // Either signal failing → Foreign (never adopted, never reaped): we must
    // not act on an unverifiable identity. A matched row (Anomaly/ReapEligible
    // below) is already corroborated — seadog wrote that row at provision — so
    // neither gate applies there.
    let env = match db_row {
        Some(env) => env,
        None => {
            if uuid::Uuid::parse_str(&guid).is_ok()
                && crate::validate::validate_guest_name(&signals.name).is_ok()
            {
                return Classification::Orphan {
                    guid,
                    owner: signals.owner.clone(),
                };
            }
            return Classification::Foreign;
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
    // surfaced but NEVER blocks the reap. We carry the mismatch out on the
    // ReapEligible verdict so reap can route a non-blocking note; the reap
    // decision is unchanged either way.
    let host_key_mismatch = !env.ssh_host_key_fps.is_empty()
        && !signals.ssh_host_key_fps.is_empty()
        && !signals
            .ssh_host_key_fps
            .iter()
            .any(|fp| env.ssh_host_key_fps.contains(fp));

    Classification::ReapEligible {
        guid,
        host_key_mismatch,
    }
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
        // A seadog-minted GUID is a canonical UUID, so this exercises the
        // genuine orphan (re-adopt) path.
        let s = signals(
            "550e8400-e29b-41d4-a716-446655440000",
            Some("aa:bb:cc:dd:ee:ff"),
        );
        match classify(&s, None) {
            Classification::Orphan { guid, owner } => {
                assert_eq!(guid, "550e8400-e29b-41d4-a716-446655440000");
                assert_eq!(owner.as_deref(), Some("alice"));
            }
            other => panic!("expected Orphan, got {other:?}"),
        }
    }

    #[test]
    fn guid_no_row_no_owner_is_orphan() {
        let mut s = signals("550e8400-e29b-41d4-a716-446655440000", None);
        s.owner = None;
        match classify(&s, None) {
            Classification::Orphan { guid, owner } => {
                assert_eq!(guid, "550e8400-e29b-41d4-a716-446655440000");
                assert_eq!(owner, None);
            }
            other => panic!("expected Orphan, got {other:?}"),
        }
    }

    #[test]
    fn non_uuid_guid_no_row_is_foreign() {
        // A present GUID with no DB row that does NOT parse as a seadog-minted
        // UUID must be ignored: the re-adopt path is destructive, so an
        // unverifiable GUID must never enter it.
        let s = signals("not-a-uuid", Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(classify(&s, None), Classification::Foreign);
    }

    #[test]
    fn valid_uuid_but_non_seadog_name_no_row_is_foreign() {
        // Second re-adopt gate: even a valid UUID must NOT be re-adopted when
        // the name is not a `seadog-…` label. Both signals must agree before
        // the destructive re-adopt path runs.
        let mut s = signals("550e8400-e29b-41d4-a716-446655440000", None);
        s.name = "totally-foreign".to_string();
        assert_eq!(classify(&s, None), Classification::Foreign);
    }

    #[test]
    fn valid_uuid_guid_no_row_is_orphan() {
        // A canonical seadog-minted UUID with no DB row is a genuine orphan.
        let s = signals(
            "550e8400-e29b-41d4-a716-446655440000",
            Some("aa:bb:cc:dd:ee:ff"),
        );
        match classify(&s, None) {
            Classification::Orphan { guid, .. } => {
                assert_eq!(guid, "550e8400-e29b-41d4-a716-446655440000");
            }
            other => panic!("expected Orphan, got {other:?}"),
        }
    }

    #[test]
    fn guid_and_row_agree_is_reap_eligible() {
        let e = env("g-abc", "aa:bb:cc:dd:ee:ff");
        let s = signals("g-abc", Some("aa:bb:cc:dd:ee:ff"));
        match classify(&s, Some(&e)) {
            Classification::ReapEligible {
                guid,
                host_key_mismatch,
            } => {
                assert_eq!(guid, "g-abc");
                assert!(!host_key_mismatch, "agreeing fps must not flag a mismatch");
            }
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
        // kento reports a MAC for VM modes only, so an LXC live instance has
        // no MAC (None) — it drops out of the decision entirely.
        s.mac = None;
        match classify(&s, Some(&e)) {
            Classification::ReapEligible { guid, .. } => assert_eq!(guid, "g-lxc"),
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
            Classification::ReapEligible { guid, .. } => assert_eq!(guid, "g-lxc"),
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
        // confirmer: must NOT flag an Anomaly — still ReapEligible (regenerated
        // keys must not strand the env). The mismatch IS surfaced on the
        // verdict's `host_key_mismatch` flag for reap to route a non-blocking
        // note.
        let mut e = env("g-abc", "aa:bb:cc:dd:ee:ff");
        e.ssh_host_key_fps = vec!["SHA256:old-key".to_string()];
        let mut s = signals("g-abc", Some("aa:bb:cc:dd:ee:ff"));
        s.ssh_host_key_fps = vec!["SHA256:regenerated-key".to_string()];
        match classify(&s, Some(&e)) {
            Classification::ReapEligible {
                guid,
                host_key_mismatch,
            } => {
                assert_eq!(guid, "g-abc");
                assert!(
                    host_key_mismatch,
                    "disjoint host-key fps must surface the soft mismatch signal"
                );
            }
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
            Classification::ReapEligible {
                host_key_mismatch, ..
            } => assert!(
                !host_key_mismatch,
                "an absent fp set on either side is not a mismatch"
            ),
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
