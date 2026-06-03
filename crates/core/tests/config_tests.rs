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
    assert_eq!(cfg.allocation.vmid_range, [10000, 10999]);
    assert_eq!(
        cfg.allocation.ip_pool.range,
        [
            Ipv4Addr::new(192, 168, 0, 192),
            Ipv4Addr::new(192, 168, 0, 254)
        ]
    );
    assert_eq!(
        cfg.allocation.ip_pool.gateway,
        Ipv4Addr::new(192, 168, 0, 1)
    );
    assert_eq!(cfg.allocation.ip_pool.prefix, 24);
    assert_eq!(cfg.allocation.caps.max_lxc_per_owner, 8);
    assert_eq!(cfg.allocation.caps.max_vm_per_owner, 3);

    // Image allowlist: name -> {ref, modes}.
    let loom = cfg.images.get("loom").expect("loom present");
    assert_eq!(loom.image_ref, "ghcr.io/doctorjei/droste:loom");
    assert_eq!(loom.modes, vec![Mode::Lxc]);
    let kani = cfg.images.get("kanibako").expect("kanibako present");
    assert_eq!(kani.modes, vec![Mode::Lxc, Mode::Vm]);

    // Owner override.
    let o = cfg.owners.get("kanibako").expect("owner override");
    assert_eq!(o.max_lxc, Some(12));
    assert_eq!(o.max_vm, None);

    // Identity weights.
    assert_eq!(cfg.identity.threshold, 0.6);
    assert_eq!(cfg.identity.weights.network, 3);
    assert_eq!(cfg.identity.weights.memory, 0);

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
  loom: { ref: ghcr.io/doctorjei/droste:loom, modes: [lxc] }
"#;
    let cfg = Config::from_yaml_str(yaml).expect("parse sparse");
    cfg.validate().expect("sparse validates");

    assert!(cfg.reaper_enabled); // default true
    assert_eq!(cfg.cadence.fast, Duration::from_secs(60));
    assert_eq!(cfg.cadence.idle, Duration::from_secs(3600));
    assert_eq!(cfg.allocation.vmid_range, [10000, 10999]);
    assert_eq!(
        cfg.allocation.ip_pool.range[0],
        Ipv4Addr::new(192, 168, 0, 192)
    );
    assert_eq!(cfg.allocation.caps.max_lxc_per_owner, 8);
    assert_eq!(cfg.lifecycle.default_ttl, Duration::from_secs(3600));
    assert_eq!(cfg.lifecycle.herd_cap, 10);
    assert_eq!(cfg.retention.terminal, Duration::from_secs(7 * 24 * 3600));
    assert!(cfg.notify.journald);
    assert_eq!(cfg.identity.threshold, 0.6);
}

#[test]
fn rejects_bad_vmid_range() {
    let yaml = r#"
allocation:
  vmid_range: [10999, 10000]
images:
  loom: { ref: ghcr.io/doctorjei/droste:loom, modes: [lxc] }
"#;
    let cfg = Config::from_yaml_str(yaml).expect("parse");
    let err = cfg.validate().expect_err("inverted range must fail");
    assert!(matches!(err, Error::ConfigValidation(_)), "{err:?}");
}

#[test]
fn rejects_out_of_window_vmid_range() {
    let yaml = r#"
allocation:
  vmid_range: [9000, 9999]
images:
  loom: { ref: ghcr.io/doctorjei/droste:loom, modes: [lxc] }
"#;
    let cfg = Config::from_yaml_str(yaml).expect("parse");
    assert!(matches!(cfg.validate(), Err(Error::ConfigValidation(_))));
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
fn rejects_malformed_ip_range() {
    let yaml = r#"
allocation:
  ip_pool:
    range: [192.168.0.254, 192.168.0.192]
images:
  loom: { ref: ghcr.io/doctorjei/droste:loom, modes: [lxc] }
"#;
    let cfg = Config::from_yaml_str(yaml).expect("parse");
    assert!(matches!(cfg.validate(), Err(Error::ConfigValidation(_))));
}
