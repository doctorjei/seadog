//! Typed schema + parser for `/etc/seadog/config.yaml`.
//!
//! Mirrors the annotated `deploy/config.yaml.example` (which doubles as
//! the parse test fixture). Durations are humantime strings (`60s`,
//! `1h`, `7d`) decoded via `humantime_serde`; IP-pool bounds parse to
//! [`std::net::Ipv4Addr`]. Omitted fields fall back to [`Default`] impls
//! so a sparse config still yields a complete, valid struct. Call
//! [`Config::validate`] after parsing to catch semantic errors the type
//! system can't (empty allowlist, inverted ranges).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::models::Mode;
use crate::Error;

/// Top-level config document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Master reaper switch; off = escaped envs may live forever.
    #[serde(default = "default_true")]
    pub reaper_enabled: bool,
    #[serde(default)]
    pub cadence: Cadence,
    #[serde(default)]
    pub allocation: Allocation,
    /// Allowlist: image name -> {ref, modes}. Never empty (validated).
    #[serde(default)]
    pub images: BTreeMap<String, Image>,
    /// The login user injected ssh keys authorize for, when an image entry
    /// does not pin its own `user`. Defaults to `"root"` (fail-open).
    #[serde(default = "default_user")]
    pub default_user: String,
    /// Absolute path to the `kento` binary. `None` → spawn the bare `"kento"`
    /// name (resolved via the helper's pinned PATH). Set when kento is not on
    /// the default PATH (e.g. a pipx install under `/root/.local/bin`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kento_path: Option<String>,
    /// Per-owner cap overrides (optional).
    #[serde(default)]
    pub owners: BTreeMap<String, OwnerOverride>,
    #[serde(default)]
    pub lifecycle: Lifecycle,
    #[serde(default)]
    pub retention: Retention,
    #[serde(default)]
    pub notify: Notify,
}

/// Reaper loop / backstop cadence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cadence {
    /// Shell-spawned watcher loop interval (while >=1 env active).
    #[serde(with = "humantime_serde", default = "secs_60")]
    pub fast: Duration,
    /// systemd backstop timer floor (always-on).
    #[serde(with = "humantime_serde", default = "mins_60")]
    pub idle: Duration,
}

impl Default for Cadence {
    fn default() -> Self {
        Cadence {
            fast: secs_60(),
            idle: mins_60(),
        }
    }
}

/// name / ip / cap allocation policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    /// The bridge kento attaches guests to (e.g. `vmbr0`). Passed to
    /// `kento create` as `--network bridge=<this>`.
    #[serde(default = "default_bridge")]
    pub bridge: String,
    #[serde(default)]
    pub ip_pool: IpPool,
    #[serde(default)]
    pub caps: Caps,
}

impl Default for Allocation {
    fn default() -> Self {
        Allocation {
            bridge: default_bridge(),
            ip_pool: IpPool::default(),
            caps: Caps::default(),
        }
    }
}

/// Static IP pool: lowest-available lease at create.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpPool {
    /// Inclusive `[low, high]` IPv4 bounds.
    #[serde(default = "default_ip_range")]
    pub range: [Ipv4Addr; 2],
    #[serde(default = "default_gateway")]
    pub gateway: Ipv4Addr,
    #[serde(default = "default_prefix")]
    pub prefix: u8,
}

impl Default for IpPool {
    fn default() -> Self {
        IpPool {
            range: default_ip_range(),
            gateway: default_gateway(),
            prefix: default_prefix(),
        }
    }
}

/// Global per-owner concurrency ceilings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caps {
    #[serde(default = "max_lxc_default")]
    pub max_lxc_per_owner: u32,
    #[serde(default = "max_vm_default")]
    pub max_vm_per_owner: u32,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            max_lxc_per_owner: max_lxc_default(),
            max_vm_per_owner: max_vm_default(),
        }
    }
}

/// One allowlisted image: a name -> {ref, modes} entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Image {
    /// OCI ref (`ref` is a Rust keyword, so renamed at the serde layer).
    #[serde(rename = "ref")]
    pub image_ref: String,
    /// Allowed modes; the first is the default for `create` without
    /// `--mode`.
    pub modes: Vec<Mode>,
    /// Optional login user the owner's ssh key is authorized for in guests
    /// of this image. When unset, the top-level `default_user` applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Whether nesting is permitted for guests served from this catalog
    /// entry — mode-agnostic (VM→VM nesting / nested virt, container→
    /// container nesting). `None`/absent ⇒ false (kento's default applies).
    /// Selected per-alias by the front-end and re-validated against the
    /// allowlist via [`Config::nesting_ok_for_ref`] (the same OCI ref may be
    /// listed under two aliases with different `allow_nesting`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_nesting: Option<bool>,
}

/// Per-owner cap override block (all fields optional).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lxc: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_vm: Option<u32>,
}

/// Deadline / grace / herd-cap lifecycle policy. All duration fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    /// Never reap envs younger than this (covers the non-atomic create
    /// window).
    #[serde(with = "humantime_serde", default = "mins_5")]
    pub age_floor: Duration,
    /// Soft "expected done" alert (informational).
    #[serde(with = "humantime_serde", default = "mins_30")]
    pub default_duration: Duration,
    /// Hard kill; per-env override at create.
    #[serde(with = "humantime_serde", default = "mins_60")]
    pub default_ttl: Duration,
    /// Warning window before the hard kill (warn at ttl - grace).
    #[serde(with = "humantime_serde", default = "mins_10")]
    pub grace: Duration,
    /// Max reaps per sweep; remainder carried to the next tick.
    #[serde(default = "herd_cap_default")]
    pub herd_cap: u32,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Lifecycle {
            age_floor: mins_5(),
            default_duration: mins_30(),
            default_ttl: mins_60(),
            grace: mins_10(),
            herd_cap: herd_cap_default(),
        }
    }
}

/// DB-row retention for terminal envs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    /// Keep rows for GONE envs (reaped/vanished) this long — history
    /// only. Live envs are never pruned.
    #[serde(with = "humantime_serde", default = "days_7")]
    pub terminal: Duration,
}

impl Default for Retention {
    fn default() -> Self {
        Retention { terminal: days_7() }
    }
}

/// Notification sinks + escalation backoff.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notify {
    /// journald sink, always-on default, priority-tagged.
    #[serde(default = "default_true")]
    pub journald: bool,
    /// Optional push sink: run a command per event.
    #[serde(default)]
    pub command: Option<String>,
    /// Optional push sink: drop a file per event into this dir.
    #[serde(default)]
    pub dir: Option<String>,
    /// Unresolved OUR-problem re-alert backoff.
    #[serde(with = "humantime_serde", default = "mins_30")]
    pub reescalate: Duration,
}

impl Default for Notify {
    fn default() -> Self {
        Notify {
            journald: true,
            command: None,
            dir: None,
            reescalate: mins_30(),
        }
    }
}

impl Config {
    /// Parse a config from a YAML string. Applies defaults for omitted
    /// fields; does **not** run [`Config::validate`] (call it
    /// separately).
    pub fn from_yaml_str(s: &str) -> Result<Config, Error> {
        serde_yaml_ng::from_str(s).map_err(|e| Error::Config(e.to_string()))
    }

    /// Read + parse a config from a path. Applies defaults; does not
    /// validate.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Config, Error> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("reading {}: {}", path.display(), e)))?;
        Config::from_yaml_str(&text)
    }

    /// Validate semantic invariants the type system can't enforce.
    ///
    /// Errors on: an empty `images` allowlist; an inverted/degenerate
    /// IP-pool range.
    pub fn validate(&self) -> Result<(), Error> {
        if self.images.is_empty() {
            return Err(Error::ConfigValidation(
                "images allowlist must not be empty".to_string(),
            ));
        }
        for (name, img) in &self.images {
            if img.modes.is_empty() {
                return Err(Error::ConfigValidation(format!(
                    "image '{name}' must allow at least one mode"
                )));
            }
        }

        let [iplo, iphi] = self.allocation.ip_pool.range;
        if u32::from(iplo) >= u32::from(iphi) {
            return Err(Error::ConfigValidation(format!(
                "ip_pool.range low ({iplo}) must be < high ({iphi})"
            )));
        }

        // `kento_path`, when set, must be a non-empty path. The user fields
        // are free-form (no constraint) and intentionally fail-open.
        if let Some(p) = &self.kento_path {
            if p.trim().is_empty() {
                return Err(Error::ConfigValidation(
                    "kento_path, when set, must not be empty".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Resolve the login user the owner's ssh key should authorize for when
    /// creating a guest from image *name*: the image entry's `user` if it
    /// pins one, else the top-level `default_user` (itself `"root"` by
    /// default). Never errors — an unknown image name falls back to
    /// `default_user`, so this is fail-open by construction.
    pub fn login_user_for_image(&self, name: &str) -> String {
        self.images
            .get(name)
            .and_then(|img| img.user.clone())
            .unwrap_or_else(|| self.default_user.clone())
    }

    /// Like [`Config::login_user_for_image`] but keyed on the resolved OCI
    /// *ref* (what `seadog-priv provision` carries, since it never trusts a
    /// bare image name from the front-end). Matches the first image entry
    /// whose `ref` equals `image_ref` and returns its pinned `user`, else the
    /// top-level `default_user`. Fail-open: an unmatched ref → `default_user`.
    pub fn login_user_for_ref(&self, image_ref: &str) -> String {
        self.images
            .values()
            .find(|img| img.image_ref == image_ref)
            .and_then(|img| img.user.clone())
            .unwrap_or_else(|| self.default_user.clone())
    }

    /// Re-validate a requested `allow_nesting` value across the privilege
    /// boundary: the front-end resolves nesting from the served *alias* but
    /// passes only the OCI *ref* to `seadog-priv`, and the same ref may be
    /// listed under two aliases with different `allow_nesting`. So the helper
    /// cannot trust the requested value alone — it confirms SOME image entry
    /// exists whose `ref` equals `image_ref` AND whose effective
    /// `allow_nesting` (absent ⇒ false) equals `requested`. Returns true iff
    /// such an entry exists. This is the gate `provision` checks before
    /// setting `ProvisionSpec.allow_nesting`.
    pub fn nesting_ok_for_ref(&self, image_ref: &str, requested: bool) -> bool {
        self.images.values().any(|img| {
            img.image_ref == image_ref && img.allow_nesting.unwrap_or(false) == requested
        })
    }
}

// --- default-value helpers (functions because serde `default = "..."`
//     needs a path to a fn, and Duration/Ipv4Addr aren't const-friendly
//     literals here) ---

fn default_true() -> bool {
    true
}
fn default_user() -> String {
    "root".to_string()
}
fn secs_60() -> Duration {
    Duration::from_secs(60)
}
fn mins_5() -> Duration {
    Duration::from_secs(5 * 60)
}
fn mins_10() -> Duration {
    Duration::from_secs(10 * 60)
}
fn mins_30() -> Duration {
    Duration::from_secs(30 * 60)
}
fn mins_60() -> Duration {
    Duration::from_secs(60 * 60)
}
fn days_7() -> Duration {
    Duration::from_secs(7 * 24 * 60 * 60)
}
fn default_bridge() -> String {
    "vmbr0".to_string()
}
fn default_ip_range() -> [Ipv4Addr; 2] {
    // Example fallback only; operators set ip_pool to a free range on their network.
    [
        Ipv4Addr::new(192, 168, 99, 192),
        Ipv4Addr::new(192, 168, 99, 254),
    ]
}
fn default_gateway() -> Ipv4Addr {
    Ipv4Addr::new(192, 168, 99, 1)
}
fn default_prefix() -> u8 {
    24
}
fn max_lxc_default() -> u32 {
    8
}
fn max_vm_default() -> u32 {
    3
}
fn herd_cap_default() -> u32 {
    10
}
