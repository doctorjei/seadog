//! Config-layer tests: parse the canonical example, apply defaults,
//! decode humantime durations, and fire validation errors.

use std::net::Ipv4Addr;
use std::time::Duration;

use seadog_core::config::Config;
use seadog_core::models::Mode;
use seadog_core::Error;

/// Path to the annotated deploy example, which doubles as the fixture.
const EXAMPLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/config.yaml.example"
);

#[test]
fn parses_annotated_example() {
    let text = std::fs::read_to_string(EXAMPLE).expect("read example");
    let cfg = Config::from_yaml_str(&text).expect("parse example");
    cfg.validate().expect("example must validate");

    assert!(cfg.reaper_enabled);
    // removed: vmid_range assertion (vmid allocation dropped; the stale
    // `vmid_range:` block is gone from the example and is now rejected).
    assert_eq!(
        cfg.allocation.ip_pool.range,
        [
            Ipv4Addr::new(192, 168, 99, 192),
            Ipv4Addr::new(192, 168, 99, 254)
        ]
    );
    assert_eq!(
        cfg.allocation.ip_pool.gateway,
        Ipv4Addr::new(192, 168, 99, 1)
    );
    assert_eq!(cfg.allocation.ip_pool.prefix, 24);
    assert_eq!(cfg.allocation.bridge, "vmbr0");
    assert_eq!(cfg.allocation.caps.max_lxc_per_owner, 8);
    assert_eq!(cfg.allocation.caps.max_vm_per_owner, 3);

    // Image allowlist: name -> {ref, modes[, user]}.
    let loom = cfg.images.get("loom").expect("loom present");
    assert_eq!(loom.image_ref, "ghcr.io/doctorjei/droste-loom:1.2.0");
    assert_eq!(loom.modes, vec![Mode::Lxc]);
    assert_eq!(loom.user.as_deref(), Some("droste"));
    let ci = cfg.images.get("ci").expect("ci present");
    assert_eq!(ci.modes, vec![Mode::Lxc, Mode::Vm]);
    assert_eq!(ci.user.as_deref(), Some("agent"));

    // Login-user resolution: per-image `user` wins; the top-level default is
    // "root"; `kento_path` is commented out → None.
    assert_eq!(cfg.default_user, "root");
    assert_eq!(cfg.kento_path, None);
    assert_eq!(cfg.login_user_for_image("loom"), "droste");
    assert_eq!(cfg.login_user_for_image("ci"), "agent");
    assert_eq!(
        cfg.login_user_for_ref("ghcr.io/doctorjei/droste-loom:1.2.0"),
        "droste"
    );

    // Owner override.
    let o = cfg.owners.get("ci").expect("owner override");
    assert_eq!(o.max_lxc, Some(12));
    assert_eq!(o.max_vm, None);

    // removed: identity weight/threshold assertions — the hardware-
    // fingerprint tie-breaker is gone (identity is now the injected
    // SEADOG_GUID anchor + native confirmers). The stale `identity:` block is
    // gone from the example and is now rejected.

    // notify nulls -> None.
    assert!(cfg.notify.journald);
    assert_eq!(cfg.notify.command, None);
    assert_eq!(cfg.notify.dir, None);
}

#[test]
fn humantime_durations_decode() {
    let text = std::fs::read_to_string(EXAMPLE).expect("read example");
    let cfg = Config::from_yaml_str(&text).expect("parse");

    assert_eq!(cfg.cadence.fast, Duration::from_secs(60));
    assert_eq!(cfg.cadence.idle, Duration::from_secs(60 * 60));
    assert_eq!(cfg.lifecycle.default_ttl, Duration::from_secs(3600)); // 1h
    assert_eq!(cfg.lifecycle.age_floor, Duration::from_secs(5 * 60));
    assert_eq!(cfg.retention.terminal, Duration::from_secs(7 * 24 * 3600));
    assert_eq!(cfg.notify.reescalate, Duration::from_secs(30 * 60));
}

#[test]
fn defaults_applied_when_omitted() {
    // A near-empty config: only the required-non-empty images map.
    let yaml = r#"
images:
  loom: { ref: ghcr.io/doctorjei/droste-loom:latest, modes: [lxc] }
"#;
    let cfg = Config::from_yaml_str(yaml).expect("parse sparse");
    cfg.validate().expect("sparse validates");

    assert!(cfg.reaper_enabled); // default true
    assert_eq!(cfg.cadence.fast, Duration::from_secs(60));
    assert_eq!(cfg.cadence.idle, Duration::from_secs(3600));
    // removed: vmid_range assertion (vmid allocation dropped).
    assert_eq!(
        cfg.allocation.ip_pool.range[0],
        Ipv4Addr::new(192, 168, 99, 192)
    );
    assert_eq!(cfg.allocation.caps.max_lxc_per_owner, 8);
    assert_eq!(cfg.allocation.bridge, "vmbr0"); // default applied when omitted
    assert_eq!(cfg.lifecycle.default_ttl, Duration::from_secs(3600));
    assert_eq!(cfg.lifecycle.herd_cap, 10);
    assert_eq!(cfg.retention.terminal, Duration::from_secs(7 * 24 * 3600));
    assert!(cfg.notify.journald);
    // removed: identity.threshold assertion (fingerprint tie-breaker gone).
}

#[test]
fn default_user_defaults_to_root_and_resolver_falls_back() {
    // No `default_user`, no per-image `user`: both default to "root".
    let yaml = r#"
images:
  loom: { ref: ghcr.io/doctorjei/droste-loom:latest, modes: [lxc] }
"#;
    let cfg = Config::from_yaml_str(yaml).expect("parse");
    cfg.validate().expect("validates");
    assert_eq!(cfg.default_user, "root");
    assert_eq!(cfg.images.get("loom").unwrap().user, None);
    // Image with no `user` falls back to default_user ("root").
    assert_eq!(cfg.login_user_for_image("loom"), "root");
    // Ultimate fallback: an unknown image name → default_user ("root").
    assert_eq!(cfg.login_user_for_image("nope"), "root");
    assert_eq!(cfg.login_user_for_ref("unmatched/ref:1"), "root");
}

#[test]
fn per_image_user_overrides_custom_default_user() {
    let yaml = r#"
default_user: agent
images:
  loom:    { ref: r/loom:1, modes: [lxc], user: droste }
  bare:    { ref: r/bare:1, modes: [vm] }
"#;
    let cfg = Config::from_yaml_str(yaml).expect("parse");
    cfg.validate().expect("validates");
    assert_eq!(cfg.default_user, "agent");
    // image.user wins.
    assert_eq!(cfg.login_user_for_image("loom"), "droste");
    // image without user falls back to the (custom) default_user.
    assert_eq!(cfg.login_user_for_image("bare"), "agent");
    assert_eq!(cfg.login_user_for_ref("r/bare:1"), "agent");
}

#[test]
fn kento_path_parses_and_validates() {
    // Default: absent → None.
    let none = Config::from_yaml_str("images:\n  loom: { ref: r/loom:1, modes: [lxc] }\n").unwrap();
    assert_eq!(none.kento_path, None);

    // Set to an absolute path → Some, validates.
    let some = Config::from_yaml_str(
        "kento_path: /usr/local/bin/kento\nimages:\n  loom: { ref: r/loom:1, modes: [lxc] }\n",
    )
    .unwrap();
    assert_eq!(some.kento_path.as_deref(), Some("/usr/local/bin/kento"));
    some.validate().expect("non-empty kento_path validates");

    // Empty kento_path is rejected by the validator (lenient otherwise).
    let empty = Config::from_yaml_str(
        "kento_path: \"\"\nimages:\n  loom: { ref: r/loom:1, modes: [lxc] }\n",
    )
    .unwrap();
    assert!(matches!(empty.validate(), Err(Error::ConfigValidation(_))));
}

// removed: rejects_bad_vmid_range + rejects_out_of_window_vmid_range — vmid
// allocation and its validation are gone (kento decouple). The accept-and-ignore
// shims for `vmid_range:` and `identity:` were removed in P6, so a stale block of
// either now fails to PARSE under `deny_unknown_fields` (confirmed below).
#[test]
fn stale_vmid_range_block_is_now_rejected() {
    let yaml = r#"
allocation:
  vmid_range: [10000, 10999]
images:
  loom: { ref: ghcr.io/doctorjei/droste-loom:1.2.0, modes: [lxc] }
"#;
    assert!(
        Config::from_yaml_str(yaml).is_err(),
        "a stale vmid_range block must now be rejected as an unknown field"
    );
}

#[test]
fn stale_identity_block_is_now_rejected() {
    let yaml = r#"
identity:
  threshold: 0.6
  weights:
    network: 3
images:
  loom: { ref: ghcr.io/doctorjei/droste-loom:1.2.0, modes: [lxc] }
"#;
    assert!(
        Config::from_yaml_str(yaml).is_err(),
        "a stale identity block must now be rejected as an unknown field"
    );
}

#[test]
fn nesting_ok_for_ref_revalidates_against_allowlist() {
    // The same OCI ref listed under two aliases with DIFFERENT allow_nesting,
    // plus a third entry that omits allow_nesting (⇒ false). The helper
    // re-validates a requested value by (ref, allow_nesting) pair.
    let yaml = r#"
images:
  plain:  { ref: r/stuff:1, modes: [vm], allow_nesting: false }
  nested: { ref: r/nested:1, modes: [vm], allow_nesting: true }
  bare:   { ref: r/bare:1, modes: [lxc] }
"#;
    let cfg = Config::from_yaml_str(yaml).expect("parse");
    cfg.validate().expect("validates");

    // allow_nesting: true entry — only `requested == true` matches its ref.
    assert!(cfg.nesting_ok_for_ref("r/nested:1", true));
    assert!(!cfg.nesting_ok_for_ref("r/nested:1", false));

    // allow_nesting: false entry — only `requested == false` matches.
    assert!(cfg.nesting_ok_for_ref("r/stuff:1", false));
    assert!(!cfg.nesting_ok_for_ref("r/stuff:1", true));

    // Omitted allow_nesting defaults to false: only false matches.
    assert!(cfg.nesting_ok_for_ref("r/bare:1", false));
    assert!(!cfg.nesting_ok_for_ref("r/bare:1", true));

    // A ref that matches no entry never validates, for either request.
    assert!(!cfg.nesting_ok_for_ref("r/unmatched:1", true));
    assert!(!cfg.nesting_ok_for_ref("r/unmatched:1", false));
}

#[test]
fn rejects_empty_images() {
    // images omitted entirely -> defaults to an empty map -> invalid.
    let yaml = "reaper_enabled: true\n";
    let cfg = Config::from_yaml_str(yaml).expect("parse");
    let err = cfg.validate().expect_err("empty images must fail");
    assert!(matches!(err, Error::ConfigValidation(_)), "{err:?}");
}

#[test]
fn rejects_same_ref_aliases_with_divergent_user() {
    // Two aliases sharing one ref but pinning DIFFERENT effective users:
    // login_user_for_ref would mis-attribute, so validate must reject.
    let diverge_user = r#"
images:
  a: { ref: r/same:1, modes: [vm], user: alice }
  b: { ref: r/same:1, modes: [vm], user: bob }
"#;
    let cfg = Config::from_yaml_str(diverge_user).expect("parse");
    let err = cfg.validate().expect_err("divergent user must fail");
    assert!(matches!(err, Error::ConfigValidation(_)), "{err:?}");

    // Diverging via the DEFAULT user vs an explicit one that differs from it:
    // alias `a` resolves to default_user "root", alias `b` pins "bob".
    let diverge_default = r#"
images:
  a: { ref: r/same:1, modes: [vm] }
  b: { ref: r/same:1, modes: [vm], user: bob }
"#;
    let cfg = Config::from_yaml_str(diverge_default).expect("parse");
    assert!(matches!(cfg.validate(), Err(Error::ConfigValidation(_))));
}

#[test]
fn accepts_same_ref_aliases_that_agree() {
    // Two aliases on one ref that AGREE on the effective user are fine (a
    // legitimate aliasing of the same image).
    let yaml = r#"
default_user: agent
images:
  a: { ref: r/same:1, modes: [vm], user: agent, allow_nesting: true }
  b: { ref: r/same:1, modes: [lxc], user: agent, allow_nesting: true }
"#;
    let cfg = Config::from_yaml_str(yaml).expect("parse");
    cfg.validate().expect("agreeing aliases must validate");

    // Agreement holds on the USER even when nesting DIFFERS: serving one ref
    // under a nesting-off and a nesting-on alias (same user) is the intended,
    // shipped feature that nesting_ok_for_ref relies on — validate must accept.
    let diverge_nesting_same_user = r#"
default_user: droste
images:
  stuffer:        { ref: r/stuffer:1, modes: [vm], allow_nesting: false }
  stuffer-nested: { ref: r/stuffer:1, modes: [vm], allow_nesting: true }
"#;
    let cfg = Config::from_yaml_str(diverge_nesting_same_user).expect("parse");
    cfg.validate()
        .expect("same-ref aliases differing only on nesting must validate");
    // And the by-ref nesting resolver distinguishes the two requests.
    assert!(cfg.nesting_ok_for_ref("r/stuffer:1", true));
    assert!(cfg.nesting_ok_for_ref("r/stuffer:1", false));

    // Agreement also holds when one relies on the default and the other pins
    // the same value explicitly (both resolve to "agent", nesting absent⇒false).
    let via_default = r#"
default_user: agent
images:
  a: { ref: r/same:1, modes: [vm] }
  b: { ref: r/same:1, modes: [lxc], user: agent }
"#;
    let cfg = Config::from_yaml_str(via_default).expect("parse");
    cfg.validate()
        .expect("default-resolved agreement must validate");
}

#[test]
fn max_ttl_defaults_to_7_days() {
    let yaml = r#"
images:
  loom: { ref: r/loom:1, modes: [lxc] }
"#;
    let cfg = Config::from_yaml_str(yaml).expect("parse");
    cfg.validate().expect("validates");
    assert_eq!(cfg.lifecycle.max_ttl, Duration::from_secs(7 * 24 * 3600));

    // Overridable via humantime.
    let custom = r#"
lifecycle:
  max_ttl: 2d
images:
  loom: { ref: r/loom:1, modes: [lxc] }
"#;
    let cfg = Config::from_yaml_str(custom).expect("parse");
    assert_eq!(cfg.lifecycle.max_ttl, Duration::from_secs(2 * 24 * 3600));
}

#[test]
fn rejects_malformed_ip_range() {
    let yaml = r#"
allocation:
  ip_pool:
    range: [192.168.99.254, 192.168.99.192]
images:
  loom: { ref: ghcr.io/doctorjei/droste-loom:latest, modes: [lxc] }
"#;
    let cfg = Config::from_yaml_str(yaml).expect("parse");
    assert!(matches!(cfg.validate(), Err(Error::ConfigValidation(_))));
}
