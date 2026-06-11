//! Core data types for seadog.
//!
//! Every user-facing entity derives `Serialize`/`Deserialize` so the
//! front-end can emit JSON. Timestamps are stored as i64 unix epoch
//! seconds throughout (see [`crate`] module docs). This module is the
//! *data layer* only — no business logic (classification, reaping,
//! identity triangulation) lives here; that arrives in Phase 1b.

use serde::{Deserialize, Serialize};

/// Provisioning mode for an env — an LXC container or a full VM.
///
/// Serializes lowercase (`"lxc"` / `"vm"`) so the YAML `modes:` lists in
/// the image allowlist and the SQLite `mode` column share one
/// representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// LXC container (realized by the backend kento targets).
    #[default]
    Lxc,
    /// Full virtual machine (realized by the backend kento targets).
    Vm,
}

impl Mode {
    /// Stable string form used for the SQLite `mode` column.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Lxc => "lxc",
            Mode::Vm => "vm",
        }
    }

    /// Parse the SQLite/text form back into a `Mode`.
    pub fn from_str_opt(s: &str) -> Option<Mode> {
        match s {
            "lxc" => Some(Mode::Lxc),
            "vm" => Some(Mode::Vm),
            _ => None,
        }
    }
}

/// Lifecycle status of an env.
///
/// Phase 1a keeps this a plain enum value — the *classification* logic
/// (when an env becomes `Flagged`, etc.) is Phase 1b. `Vanished` means
/// the guest disappeared from the backend out from under us; `Reaped`
/// means seadog killed it on deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvStatus {
    /// Live env, holding its vmid/ip lease.
    Active,
    /// seadog destroyed it (deadline reached).
    Reaped,
    /// Guest disappeared from the backend without seadog acting.
    Vanished,
    /// Identity signals disagree — held for operator attention, never
    /// auto-reaped. Classification logic that sets this is Phase 1b.
    Flagged,
}

impl EnvStatus {
    /// Stable string form used for the SQLite `status` column.
    pub fn as_str(self) -> &'static str {
        match self {
            EnvStatus::Active => "active",
            EnvStatus::Reaped => "reaped",
            EnvStatus::Vanished => "vanished",
            EnvStatus::Flagged => "flagged",
        }
    }

    /// Parse the SQLite/text form back into an `EnvStatus`.
    pub fn from_str_opt(s: &str) -> Option<EnvStatus> {
        match s {
            "active" => Some(EnvStatus::Active),
            "reaped" => Some(EnvStatus::Reaped),
            "vanished" => Some(EnvStatus::Vanished),
            "flagged" => Some(EnvStatus::Flagged),
            _ => None,
        }
    }

    /// Whether this status still holds a vmid/ip lease. Only `Active`
    /// envs occupy allocation slots; everything else frees them for
    /// reuse.
    pub fn is_active(self) -> bool {
        matches!(self, EnvStatus::Active)
    }
}

/// A provisioned (or formerly provisioned) test environment.
///
/// The DB row is authoritative for `ttl_deadline` — a user clobbering
/// the guest must never orphan the kill time. `guid` is the primary key
/// (minted at create, globally unique, injected as the `SEADOG_GUID`
/// anchor); `ip` is a leased allocation slot freed when `status` leaves
/// `Active`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Env {
    /// Globally-unique id minted at create — the primary key.
    pub guid: String,
    /// Backend vmid when one exists (PVE backends only); `None` for
    /// backend-neutral runtimes. Informational — never an identity key.
    pub vmid: Option<u32>,
    /// LXC or VM.
    pub mode: Mode,
    /// Resolved owner name (from the SSH key fingerprint).
    pub owner: String,
    /// Allowlist image *name* (e.g. `loom`), never an OCI ref.
    pub image: String,
    /// Guest name `seadog-<owner>-<shortproj>-<token>` (DNS-label).
    pub name: String,
    /// Leased IPv4, as a string (e.g. `192.168.99.192`).
    pub ip: String,
    /// Recorded MAC address. An empty string `""` means **no MAC recorded**;
    /// the reaper treats MAC as confirming-when-present, so `""` simply drops
    /// MAC out of that env's reap decision.
    pub mac: String,
    /// Recorded SSH host-key fingerprints (kento `inspect`). A soft
    /// confirmer — present-but-mismatched is logged, never blocks a reap.
    pub ssh_host_key_fps: Vec<String>,
    /// Create time, unix epoch seconds.
    pub created_at: i64,
    /// Hard-kill deadline, unix epoch seconds. **DB-authoritative.**
    pub ttl_deadline: i64,
    /// Soft "expected done" alert time, unix epoch seconds.
    pub soft_deadline: i64,
    /// Lifecycle status.
    pub status: EnvStatus,
}

/// Per-env notification escalation state, stored in its own table.
///
/// Phase 1a defines the shape + persistence only; the escalation
/// *logic* (severity climbing, `reescalate` backoff) is Phase 1b. Keyed
/// by `guid` (1:1 with an [`Env`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyState {
    /// Env this state belongs to.
    pub guid: String,
    /// Most-recent severity emitted (free-form string; the severity
    /// ladder is defined in Phase 1b `notify`).
    pub last_severity: String,
    /// When the last notification fired, unix epoch seconds.
    pub last_emitted_at: i64,
    /// Operator acknowledged — suppresses further escalation.
    pub acked: bool,
}
