//! Identity triangulation + classification.
//!
//! Given what the sweeper observes about one live guest ([`GuestSignals`])
//! and the matching DB row (if any), decide what the guest **is** to
//! seadog. The governing invariant: **auto-reap requires unanimous
//! agreement** across every strong signal. Any partial match is an
//! [`Classification::Anomaly`] — flagged for a human, never reaped. A
//! guest with no strong marker at all but a vmid in our range is a
//! [`Classification::HeadsUp`] (a foreign squatter we never touch).
//!
//! ## Signal hierarchy
//! 1. **Strong instance keys** uniquely pin *which* env: the **GUID**
//!    (carried in both the guest `description` marker block and the DB
//!    row) and the **MAC** (assigned at create, recorded in the DB).
//! 2. **Strong corroborating markers** assert "this is ours" without
//!    pinning which one: the `seadog-` **name prefix** and the
//!    **GUID-in-description** marker block.
//! 3. **Weighted hardware fingerprint** is investigate/tie-break ONLY.
//!    It's a *template* signature — every same-spec env matches — so it
//!    says "shaped like ours," never "which one." It is gated on at
//!    least one high-info (weight > 0) field matching, so a bare
//!    "2GB + 2 cores" never triggers it.

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::models::Env;

/// The GUID marker block written into a guest's `description`.
///
/// Format is a single line `seadog-guid:<GUID>` so it survives
/// round-tripping through the PVE description field and is trivially
/// greppable. [`extract_desc_guid`] parses it back out.
pub const GUID_MARKER_PREFIX: &str = "seadog-guid:";

/// The `seadog-` name prefix that marks one of our guests.
pub const NAME_PREFIX: &str = "seadog-";

/// The owner marker block written into a guest's `description`.
///
/// Format is a single line `seadog-owner:<OWNER>`, written by `provision`
/// alongside the GUID marker so the privileged teardown can verify the
/// guest is owned by the requesting owner against **live PVE** (never the
/// DB). [`extract_desc_owner`] parses it back out.
pub const OWNER_MARKER_PREFIX: &str = "seadog-owner:";

/// Hardware fingerprint of one live guest. Every field is optional
/// because the sweeper may not observe all of them (e.g. a half-built
/// guest), and absence must never be read as a match.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    /// Network bridge (e.g. `vmbr0`).
    pub net_bridge: Option<String>,
    /// VLAN tag.
    pub net_vlan: Option<u32>,
    /// NIC model (e.g. `virtio`).
    pub net_model: Option<String>,
    /// Disk geometry / controller string.
    pub disk_geometry: Option<String>,
    /// Disk size in bytes.
    pub disk_size: Option<u64>,
    /// QEMU machine type (e.g. `q35`).
    pub machine_type: Option<String>,
    /// BIOS (`seabios` / `ovmf`).
    pub bios: Option<String>,
    /// SCSI controller model.
    pub scsihw: Option<String>,
    /// Memory in MiB.
    pub memory: Option<u64>,
    /// vCPU cores.
    pub cores: Option<u32>,
}

/// What the sweeper observes about one live guest.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestSignals {
    /// Proxmox guest id.
    pub vmid: u32,
    /// Guest name, if set (we look for the `seadog-` prefix).
    pub name: Option<String>,
    /// Guest description, which may carry the GUID marker block.
    pub description: Option<String>,
    /// Primary NIC MAC, if observed.
    pub mac: Option<String>,
    /// Hardware fingerprint fields.
    pub fingerprint: Fingerprint,
}

impl GuestSignals {
    /// Is this signal set effectively empty (guest gone / nothing
    /// observed)? Used by the `Vanished` detection path.
    fn is_absent(&self) -> bool {
        self.name.is_none()
            && self.description.is_none()
            && self.mac.is_none()
            && self.fingerprint == Fingerprint::default()
    }
}

/// Why a guest was classified the way it was — a machine-readable reason
/// carried alongside [`Classification`] for the notify/flag layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// All strong signals agree with the DB row.
    Unanimous,
    /// Guest renamed (no `seadog-` name) but GUID/MAC still match.
    Renamed,
    /// Description clobbered (no GUID marker) but MAC/DB still match.
    DescriptionClobbered,
    /// A DB row exists for this vmid but the live guest's GUID/MAC do not
    /// match it — stale DB row / vmid reused by something else.
    VmidReuse,
    /// A strong marker is present but the signals otherwise disagree.
    PartialMatch,
    /// No strong marker; vmid is in our range (foreign squatter).
    ForeignInRange,
    /// No strong marker, but the hardware fingerprint strongly matches —
    /// possible fully-disconnected orphan.
    PossibleOrphan,
    /// DB row exists but the guest is gone from PVE.
    Vanished,
}

/// The verdict for one guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Classification {
    /// Strong keys + markers ALL agree with a DB row. Eligible for
    /// teardown **only** once `reap.rs` additionally confirms the
    /// deadline + age-floor. `classify` never enforces those.
    Reap { guid: String, reason: Reason },
    /// A strong marker is present but signals do not all agree. Flag for
    /// a human; NEVER auto-reap.
    Anomaly { reason: Reason, detail: String },
    /// No strong marker, vmid in range (foreign squatter). One-time
    /// informational; never touched.
    HeadsUp { reason: Reason, detail: String },
    /// A DB row exists but the guest is gone from PVE.
    Vanished { guid: String },
}

/// Outcome of the weighted hardware-fingerprint comparison.
#[derive(Debug, Clone, Copy, PartialEq)]
struct FingerprintMatch {
    /// Normalized score in `[0, 1]` (matched weight / total weight).
    score: f64,
    /// At least one high-info (weight > 0) field matched. The score is
    /// only meaningful — and the match only "counts" — when this is true.
    high_info_hit: bool,
}

impl FingerprintMatch {
    /// Does the fingerprint strongly match? Requires the high-info gate
    /// AND the score to meet `config.identity.threshold`.
    fn strong(&self, threshold: f64) -> bool {
        self.high_info_hit && self.score >= threshold
    }
}

/// Parse the GUID out of a guest description marker block, if present.
///
/// Scans lines for `seadog-guid:<GUID>` (leading/trailing whitespace
/// tolerated) and returns the first GUID found. Returns `None` if the
/// description is absent or carries no marker.
pub fn extract_desc_guid(description: Option<&str>) -> Option<String> {
    let desc = description?;
    for line in desc.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(GUID_MARKER_PREFIX) {
            let guid = rest.trim();
            if !guid.is_empty() {
                return Some(guid.to_string());
            }
        }
    }
    None
}

/// Parse the owner out of a guest description marker block, if present.
///
/// Scans lines for `seadog-owner:<OWNER>` (leading/trailing whitespace
/// tolerated) and returns the first owner found. Returns `None` if the
/// description is absent or carries no owner marker. Mirrors
/// [`extract_desc_guid`].
pub fn extract_desc_owner(description: Option<&str>) -> Option<String> {
    let desc = description?;
    for line in desc.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(OWNER_MARKER_PREFIX) {
            let owner = rest.trim();
            if !owner.is_empty() {
                return Some(owner.to_string());
            }
        }
    }
    None
}

/// Does the guest name carry the `seadog-` prefix?
fn has_seadog_name(signals: &GuestSignals) -> bool {
    signals
        .name
        .as_deref()
        .is_some_and(|n| n.starts_with(NAME_PREFIX))
}

/// Case-insensitive MAC comparison (PVE may emit either case).
fn mac_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Compare the observed fingerprint to the env's expected template using
/// `config.identity.weights`. Returns the normalized score plus whether
/// the high-info gate was satisfied.
///
/// We compare each observed field against the env's *spec template*. In
/// this phase the template is derived from the same `Fingerprint`-shaped
/// expectation the caller supplies via `expected`; absence on either side
/// never counts as a match.
fn fingerprint_match(
    observed: &Fingerprint,
    expected: &Fingerprint,
    config: &Config,
) -> FingerprintMatch {
    let w = &config.identity.weights;
    let mut total = 0u32;
    let mut matched = 0u32;
    let mut high_info_hit = false;

    // (weight, observed-matches-expected) per field group.
    let net_match = opt_eq(&observed.net_bridge, &expected.net_bridge)
        && opt_eq(&observed.net_vlan, &expected.net_vlan)
        && opt_eq(&observed.net_model, &expected.net_model)
        && observed.net_bridge.is_some();
    let disk_match = opt_eq(&observed.disk_geometry, &expected.disk_geometry)
        && opt_eq(&observed.disk_size, &expected.disk_size)
        && (observed.disk_geometry.is_some() || observed.disk_size.is_some());
    let machine_match = opt_eq(&observed.machine_type, &expected.machine_type)
        && opt_eq(&observed.bios, &expected.bios)
        && opt_eq(&observed.scsihw, &expected.scsihw)
        && (observed.machine_type.is_some() || observed.bios.is_some());
    let memory_match = opt_eq(&observed.memory, &expected.memory) && observed.memory.is_some();
    let cores_match = opt_eq(&observed.cores, &expected.cores) && observed.cores.is_some();

    for (weight, hit) in [
        (w.network, net_match),
        (w.disk, disk_match),
        (w.machine, machine_match),
        (w.memory, memory_match),
        (w.cores, cores_match),
    ] {
        total += weight;
        if hit {
            matched += weight;
            if weight > 0 {
                high_info_hit = true;
            }
        }
    }

    let score = if total == 0 {
        0.0
    } else {
        matched as f64 / total as f64
    };
    FingerprintMatch {
        score,
        high_info_hit,
    }
}

fn opt_eq<T: PartialEq>(a: &Option<T>, b: &Option<T>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// Classify one guest against its DB row (if any).
///
/// `expected_fp` is the fingerprint template seadog would have built for
/// `db_row` at create time; pass `None` when no template is available
/// (the fingerprint then simply never triggers). `classify` decides
/// **agreement only** — it returns [`Classification::Reap`] on full
/// unanimous agreement but does NOT check the deadline or age floor;
/// `reap.rs` enforces those before acting.
pub fn classify(
    signals: &GuestSignals,
    db_row: Option<&Env>,
    expected_fp: Option<&Fingerprint>,
    config: &Config,
) -> Classification {
    // Vanished: a row exists but nothing is observed.
    if signals.is_absent() {
        return match db_row {
            Some(env) => Classification::Vanished {
                guid: env.guid.clone(),
            },
            // Nothing observed and no row — nothing to say.
            None => Classification::HeadsUp {
                reason: Reason::ForeignInRange,
                detail: format!(
                    "vmid {} produced no signals and has no DB row",
                    signals.vmid
                ),
            },
        };
    }

    let desc_guid = extract_desc_guid(signals.description.as_deref());
    let has_name = has_seadog_name(signals);
    let has_strong_marker = has_name || desc_guid.is_some();

    let fp = expected_fp.map(|exp| fingerprint_match(&signals.fingerprint, exp, config));
    let fp_strong = fp.is_some_and(|m| m.strong(config.identity.threshold));

    // No strong marker at all → heads-up (foreign squatter), regardless
    // of any DB row coincidentally sharing the vmid (that case is caught
    // below when a row IS present). The name is one vote, not a gate.
    if !has_strong_marker {
        // If a DB row exists for this vmid but the live guest carries no
        // marker and its instance keys don't match, that's a vmid-reuse
        // anomaly, not a foreign heads-up.
        if let Some(env) = db_row {
            let guid_matches = desc_guid.as_deref() == Some(env.guid.as_str());
            let mac_matches = signals.mac.as_deref().is_some_and(|m| mac_eq(m, &env.mac));
            if !guid_matches && !mac_matches {
                return Classification::Anomaly {
                    reason: Reason::VmidReuse,
                    detail: format!(
                        "vmid {} has DB row guid {} but live guest carries no matching marker (stale DB row / vmid reused?)",
                        signals.vmid, env.guid
                    ),
                };
            }
        }
        // Pure foreign squatter. Escalate if the hardware strongly
        // matches (possible fully-disconnected orphan).
        if fp_strong {
            return Classification::HeadsUp {
                reason: Reason::PossibleOrphan,
                detail: format!(
                    "vmid {} is foreign but hardware-shaped like ours (possible fully-disconnected orphan)",
                    signals.vmid
                ),
            };
        }
        return Classification::HeadsUp {
            reason: Reason::ForeignInRange,
            detail: format!("vmid {} is a foreign guest in our range", signals.vmid),
        };
    }

    // A strong marker IS present → this asserts "ours". Now demand
    // unanimous agreement with a DB row to be eligible for reaping.
    let env = match db_row {
        Some(env) => env,
        None => {
            // Marked ours but no DB row backs it — an anomaly to flag,
            // never something to reap (we have no authoritative deadline).
            return Classification::Anomaly {
                reason: Reason::PartialMatch,
                detail: format!(
                    "vmid {} carries a seadog marker but has no DB row",
                    signals.vmid
                ),
            };
        }
    };

    let guid_in_desc = desc_guid.as_deref() == Some(env.guid.as_str());
    let mac_matches = signals.mac.as_deref().is_some_and(|m| mac_eq(m, &env.mac));

    // VMID reuse: a marker is present but neither strong instance key
    // matches this row → the row is stale / the vmid was reused.
    if !guid_in_desc && !mac_matches {
        return Classification::Anomaly {
            reason: Reason::VmidReuse,
            detail: format!(
                "vmid {} carries a marker but neither GUID nor MAC match DB row {} (stale DB row / vmid reused?)",
                signals.vmid, env.guid
            ),
        };
    }

    // Unanimous: every strong signal agrees. GUID in desc AND DB,
    // MAC matches DB, seadog- name present, desc-GUID present.
    let unanimous = guid_in_desc && mac_matches && has_name && desc_guid.is_some();
    if unanimous {
        return Classification::Reap {
            guid: env.guid.clone(),
            reason: Reason::Unanimous,
        };
    }

    // A strong marker is present but agreement is partial → anomaly.
    // Classify the specific shape for a clearer operator message.
    let reason = if !has_name && guid_in_desc && mac_matches {
        Reason::Renamed
    } else if desc_guid.is_none() && mac_matches && has_name {
        Reason::DescriptionClobbered
    } else {
        Reason::PartialMatch
    };
    Classification::Anomaly {
        reason,
        detail: format!(
            "vmid {} (DB row {}) partially matches: guid_in_desc={guid_in_desc} mac={mac_matches} seadog_name={has_name} desc_guid_present={}",
            signals.vmid,
            env.guid,
            desc_guid.is_some()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::models::{EnvStatus, Mode};

    fn config() -> Config {
        let yaml = r#"
images:
  loom:
    ref: "r/loom:1"
    modes: [vm]
"#;
        Config::from_yaml_str(yaml).unwrap()
    }

    fn env(guid: &str, mac: &str) -> Env {
        Env {
            guid: guid.to_string(),
            vmid: 10010,
            mode: Mode::Vm,
            owner: "jei".to_string(),
            image: "loom".to_string(),
            name: "seadog-jei-proj-ab12".to_string(),
            ip: "192.168.0.200".to_string(),
            mac: mac.to_string(),
            created_at: 1000,
            ttl_deadline: 5000,
            soft_deadline: 4000,
            status: EnvStatus::Active,
        }
    }

    fn full_signals(guid: &str, mac: &str) -> GuestSignals {
        GuestSignals {
            vmid: 10010,
            name: Some("seadog-jei-proj-ab12".to_string()),
            description: Some(format!("a test env\n{GUID_MARKER_PREFIX}{guid}\n")),
            mac: Some(mac.to_string()),
            fingerprint: Fingerprint::default(),
        }
    }

    fn our_fp() -> Fingerprint {
        Fingerprint {
            net_bridge: Some("vmbr0".to_string()),
            net_vlan: Some(10),
            net_model: Some("virtio".to_string()),
            disk_geometry: Some("scsi0".to_string()),
            disk_size: Some(20 * 1024 * 1024 * 1024),
            machine_type: Some("q35".to_string()),
            bios: Some("seabios".to_string()),
            scsihw: Some("virtio-scsi-pci".to_string()),
            memory: Some(2048),
            cores: Some(2),
        }
    }

    #[test]
    fn full_agreement_yields_reap() {
        let c = config();
        let e = env("guid-abc", "aa:bb:cc:dd:ee:ff");
        let s = full_signals("guid-abc", "aa:bb:cc:dd:ee:ff");
        match classify(&s, Some(&e), None, &c) {
            Classification::Reap { guid, reason } => {
                assert_eq!(guid, "guid-abc");
                assert_eq!(reason, Reason::Unanimous);
            }
            other => panic!("expected Reap, got {other:?}"),
        }
    }

    #[test]
    fn rename_yields_anomaly() {
        let c = config();
        let e = env("guid-abc", "aa:bb:cc:dd:ee:ff");
        let mut s = full_signals("guid-abc", "aa:bb:cc:dd:ee:ff");
        s.name = Some("totally-renamed".to_string()); // no seadog- prefix
        match classify(&s, Some(&e), None, &c) {
            Classification::Anomaly { reason, .. } => assert_eq!(reason, Reason::Renamed),
            other => panic!("expected Anomaly, got {other:?}"),
        }
    }

    #[test]
    fn desc_clobber_yields_anomaly() {
        let c = config();
        let e = env("guid-abc", "aa:bb:cc:dd:ee:ff");
        let mut s = full_signals("guid-abc", "aa:bb:cc:dd:ee:ff");
        s.description = Some("user clobbered this".to_string()); // no GUID marker
        match classify(&s, Some(&e), None, &c) {
            Classification::Anomaly { reason, .. } => {
                assert_eq!(reason, Reason::DescriptionClobbered)
            }
            other => panic!("expected Anomaly, got {other:?}"),
        }
    }

    #[test]
    fn foreign_in_range_yields_headsup() {
        let c = config();
        let s = GuestSignals {
            vmid: 10010,
            name: Some("someones-vm".to_string()),
            description: Some("not ours".to_string()),
            mac: Some("11:22:33:44:55:66".to_string()),
            fingerprint: Fingerprint::default(),
        };
        match classify(&s, None, None, &c) {
            Classification::HeadsUp { reason, .. } => assert_eq!(reason, Reason::ForeignInRange),
            other => panic!("expected HeadsUp, got {other:?}"),
        }
    }

    #[test]
    fn vmid_reuse_yields_anomaly() {
        let c = config();
        // DB row exists for this vmid, but the live guest carries a
        // marker whose GUID/MAC do not match the row.
        let e = env("guid-OLD", "aa:bb:cc:dd:ee:ff");
        let s = full_signals("guid-NEW", "99:99:99:99:99:99");
        match classify(&s, Some(&e), None, &c) {
            Classification::Anomaly { reason, .. } => assert_eq!(reason, Reason::VmidReuse),
            other => panic!("expected Anomaly(VmidReuse), got {other:?}"),
        }
    }

    #[test]
    fn vmid_reuse_no_marker_yields_anomaly() {
        let c = config();
        // DB row exists, live guest has NO marker and mismatched keys.
        let e = env("guid-OLD", "aa:bb:cc:dd:ee:ff");
        let s = GuestSignals {
            vmid: 10010,
            name: Some("foreign".to_string()),
            description: Some("nope".to_string()),
            mac: Some("99:99:99:99:99:99".to_string()),
            fingerprint: Fingerprint::default(),
        };
        match classify(&s, Some(&e), None, &c) {
            Classification::Anomaly { reason, .. } => assert_eq!(reason, Reason::VmidReuse),
            other => panic!("expected Anomaly(VmidReuse), got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_gates_on_high_info_field() {
        let c = config();
        // Observed matches ONLY the low-info fields (memory + cores),
        // which carry weight 0. The high-info gate must NOT fire, so a
        // foreign guest stays a plain ForeignInRange heads-up.
        let expected = our_fp();
        let s = GuestSignals {
            vmid: 10010,
            name: None,
            description: None,
            mac: Some("99:99:99:99:99:99".to_string()),
            fingerprint: Fingerprint {
                memory: Some(2048),
                cores: Some(2),
                ..Default::default()
            },
        };
        match classify(&s, None, Some(&expected), &c) {
            Classification::HeadsUp { reason, .. } => {
                assert_eq!(
                    reason,
                    Reason::ForeignInRange,
                    "low-info-only must not trigger fp"
                )
            }
            other => panic!("expected plain ForeignInRange heads-up, got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_strong_match_escalates_orphan() {
        let c = config();
        // No marker, but the full hardware template matches → orphan.
        let expected = our_fp();
        let s = GuestSignals {
            vmid: 10010,
            name: None,
            description: None,
            mac: Some("99:99:99:99:99:99".to_string()),
            fingerprint: our_fp(),
        };
        match classify(&s, None, Some(&expected), &c) {
            Classification::HeadsUp { reason, .. } => assert_eq!(reason, Reason::PossibleOrphan),
            other => panic!("expected HeadsUp(PossibleOrphan), got {other:?}"),
        }
    }

    #[test]
    fn partial_match_never_yields_reap() {
        let c = config();
        let e = env("guid-abc", "aa:bb:cc:dd:ee:ff");
        // Many partial permutations; none may produce Reap.
        let mut variants = Vec::new();

        // GUID matches desc+db, MAC mismatched.
        let mut s = full_signals("guid-abc", "aa:bb:cc:dd:ee:ff");
        s.mac = Some("00:00:00:00:00:00".to_string());
        variants.push(s);

        // name missing.
        let mut s = full_signals("guid-abc", "aa:bb:cc:dd:ee:ff");
        s.name = None;
        variants.push(s);

        // desc-guid missing.
        let mut s = full_signals("guid-abc", "aa:bb:cc:dd:ee:ff");
        s.description = Some("no marker".to_string());
        variants.push(s);

        for s in variants {
            let cls = classify(&s, Some(&e), None, &c);
            assert!(
                !matches!(cls, Classification::Reap { .. }),
                "partial match must not Reap: {cls:?}"
            );
        }
    }

    #[test]
    fn vanished_when_row_present_no_signals() {
        let c = config();
        let e = env("guid-abc", "aa:bb:cc:dd:ee:ff");
        let s = GuestSignals {
            vmid: 10010,
            ..Default::default()
        };
        match classify(&s, Some(&e), None, &c) {
            Classification::Vanished { guid } => assert_eq!(guid, "guid-abc"),
            other => panic!("expected Vanished, got {other:?}"),
        }
    }

    #[test]
    fn marked_ours_but_no_db_row_is_anomaly() {
        let c = config();
        let s = full_signals("guid-abc", "aa:bb:cc:dd:ee:ff");
        match classify(&s, None, None, &c) {
            Classification::Anomaly { reason, .. } => assert_eq!(reason, Reason::PartialMatch),
            other => panic!("expected Anomaly, got {other:?}"),
        }
    }

    #[test]
    fn extract_desc_guid_parses_marker() {
        let d = format!("line1\n  {GUID_MARKER_PREFIX}xyz-123  \nline3");
        assert_eq!(extract_desc_guid(Some(&d)), Some("xyz-123".to_string()));
        assert_eq!(extract_desc_guid(Some("nothing here")), None);
        assert_eq!(extract_desc_guid(None), None);
    }

    #[test]
    fn extract_desc_owner_parses_marker() {
        let d = format!("line1\n  {OWNER_MARKER_PREFIX}jei  \n{GUID_MARKER_PREFIX}xyz");
        assert_eq!(extract_desc_owner(Some(&d)), Some("jei".to_string()));
        assert_eq!(extract_desc_owner(Some("nothing here")), None);
        assert_eq!(extract_desc_owner(None), None);
    }
}
