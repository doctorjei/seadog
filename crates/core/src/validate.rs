//! Pure input validation for caller-supplied values.
//!
//! These checks run before anything touches PVE or the DB: a requested
//! `vmid` must lie inside the configured allocation window, a guest
//! `name` must be a strict DNS label of the `seadog-…` family, and an
//! image must resolve through the **allowlist by bare name** only — a
//! caller-supplied OCI ref must never resolve to a runnable image. All
//! functions are side-effect-free and return [`Error::Validation`] on
//! rejection so the front-end can surface a clear message.

use std::sync::OnceLock;

use regex::Regex;

use crate::config::Config;
use crate::models::Mode;
use crate::Error;

/// Validate that `vmid` is within the configured (inclusive)
/// `allocation.vmid_range`.
pub fn validate_vmid(vmid: u32, config: &Config) -> Result<(), Error> {
    let [lo, hi] = config.allocation.vmid_range;
    if vmid < lo || vmid > hi {
        return Err(Error::Validation(format!(
            "vmid {vmid} outside allocation range [{lo}, {hi}]"
        )));
    }
    Ok(())
}

/// Compiled `seadog-…` guest-name regex (lazily built once).
///
/// Lowercase letters/digits/hyphens only, mandatory `seadog-` prefix, at
/// least one char after it. Leading/trailing hyphen and the overall
/// length cap are enforced separately in [`validate_guest_name`] (the
/// regex deliberately stays simple; the extra rules are clearer as code).
fn name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^seadog-[a-z0-9-]{1,}$").expect("static guest-name regex"))
}

/// Validate a PVE guest name as a strict DNS label of the `seadog-`
/// family.
///
/// Rules: matches `^seadog-[a-z0-9-]{1,}$`, total length ≤ 63, no
/// underscores, no leading/trailing hyphen, lowercase only. (Guest names
/// are `seadog-<owner>-<shortproj>-<token>`.)
pub fn validate_guest_name(name: &str) -> Result<(), Error> {
    if name.len() > 63 {
        return Err(Error::Validation(format!(
            "guest name '{name}' exceeds 63 chars"
        )));
    }
    // The regex's `[a-z0-9-]` class already forbids underscores and
    // uppercase, but call them out explicitly for a clearer message.
    if name.contains('_') {
        return Err(Error::Validation(format!(
            "guest name '{name}' must not contain underscores"
        )));
    }
    if name.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(Error::Validation(format!(
            "guest name '{name}' must be lowercase"
        )));
    }
    if name.ends_with('-') {
        return Err(Error::Validation(format!(
            "guest name '{name}' must not end with a hyphen"
        )));
    }
    // A leading hyphen is impossible given the mandatory `seadog-`
    // prefix, but the regex is the source of truth for the rest.
    if !name_re().is_match(name) {
        return Err(Error::Validation(format!(
            "guest name '{name}' is not a valid seadog DNS label"
        )));
    }
    Ok(())
}

/// A resolved image: the real OCI ref plus the effective mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImage {
    /// The allowlisted OCI ref (from the config, never caller-supplied).
    pub image_ref: String,
    /// The effective mode (requested, or the image's first listed mode).
    pub mode: Mode,
}

/// Resolve an allowlist image **name** (never an OCI ref) to its ref +
/// mode.
///
/// `name` must be a bare key in `config.images`; a caller passing an OCI
/// ref (e.g. `registry/x:tag`) does not match any key and is rejected —
/// this is the security boundary that prevents pulling arbitrary images.
/// If `requested_mode` is `Some`, it must be in the image's `modes`;
/// otherwise the first listed mode is used as the default.
pub fn resolve_image(
    name: &str,
    requested_mode: Option<Mode>,
    config: &Config,
) -> Result<ResolvedImage, Error> {
    let img = config.images.get(name).ok_or_else(|| {
        Error::Validation(format!(
            "image '{name}' is not in the allowlist (must be a bare allowlist name, not an OCI ref)"
        ))
    })?;

    let mode = match requested_mode {
        Some(m) => {
            if !img.modes.contains(&m) {
                return Err(Error::Validation(format!(
                    "mode '{}' not allowed for image '{name}' (allowed: {:?})",
                    m.as_str(),
                    img.modes
                )));
            }
            m
        }
        None => *img.modes.first().ok_or_else(|| {
            // Config::validate forbids empty modes, but be defensive.
            Error::Validation(format!("image '{name}' has no modes"))
        })?,
    };

    Ok(ResolvedImage {
        image_ref: img.image_ref.clone(),
        mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config() -> Config {
        let yaml = r#"
images:
  loom:
    ref: "registry.example.com/loom:1.0"
    modes: [lxc, vm]
  vmonly:
    ref: "registry.example.com/vmonly:2.0"
    modes: [vm]
"#;
        let c = Config::from_yaml_str(yaml).unwrap();
        c.validate().unwrap();
        c
    }

    #[test]
    fn vmid_in_and_out_of_range() {
        let c = config();
        assert!(validate_vmid(10000, &c).is_ok());
        assert!(validate_vmid(10500, &c).is_ok());
        assert!(validate_vmid(10999, &c).is_ok());
        assert!(validate_vmid(9999, &c).is_err());
        assert!(validate_vmid(11000, &c).is_err());
    }

    #[test]
    fn name_accepts_valid_seadog_label() {
        assert!(validate_guest_name("seadog-alice-proj-ab12").is_ok());
        assert!(validate_guest_name("seadog-a").is_ok());
    }

    #[test]
    fn name_rejects_underscore() {
        assert!(validate_guest_name("seadog-jei_proj").is_err());
    }

    #[test]
    fn name_rejects_uppercase() {
        assert!(validate_guest_name("seadog-Alice").is_err());
    }

    #[test]
    fn name_rejects_trailing_and_leading_hyphen() {
        assert!(validate_guest_name("seadog-alice-").is_err());
        // No seadog- prefix → leading hyphen / wrong family.
        assert!(validate_guest_name("-seadog-alice").is_err());
    }

    #[test]
    fn name_rejects_missing_prefix() {
        assert!(validate_guest_name("notseadog-alice").is_err());
        assert!(validate_guest_name("seadog").is_err());
    }

    #[test]
    fn name_rejects_over_63() {
        let long = format!("seadog-{}", "a".repeat(60));
        assert!(long.len() > 63);
        assert!(validate_guest_name(&long).is_err());
    }

    #[test]
    fn image_resolves_name_to_ref_and_default_mode() {
        let c = config();
        let r = resolve_image("loom", None, &c).unwrap();
        assert_eq!(r.image_ref, "registry.example.com/loom:1.0");
        // First listed mode is the default.
        assert_eq!(r.mode, Mode::Lxc);
    }

    #[test]
    fn image_rejects_unknown_name() {
        let c = config();
        assert!(resolve_image("nope", None, &c).is_err());
    }

    #[test]
    fn image_rejects_raw_oci_ref() {
        let c = config();
        // A caller-supplied OCI ref is not an allowlist key → rejected.
        assert!(resolve_image("registry.example.com/loom:1.0", None, &c).is_err());
    }

    #[test]
    fn image_enforces_mode_in_modes() {
        let c = config();
        // vmonly does not allow lxc.
        assert!(resolve_image("vmonly", Some(Mode::Lxc), &c).is_err());
        assert!(resolve_image("vmonly", Some(Mode::Vm), &c).is_ok());
        // loom allows both.
        assert_eq!(
            resolve_image("loom", Some(Mode::Vm), &c).unwrap().mode,
            Mode::Vm
        );
    }
}
