//! The runtime bridge between seadog's logic and the `kento` runtime.
//!
//! [`Kento`] abstracts every operation the reaper/provisioner needs from
//! `kento` so the business logic can be exercised against an in-memory
//! [`FakeKento`] with **no real host** in the loop. The shelling-out
//! implementation, [`RealKento`], lives behind the `real-kento` cargo
//! feature so the library builds and tests with zero external tools by
//! default.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::models::Mode;
use crate::Error;

/// Operations seadog needs from the `kento` runtime.
///
/// Implementors must surface a quorum-loss / pmxcfs-read-only condition as
/// [`Error::QuorumLost`] so the reaper can stop cleanly instead of
/// spinning. Identity is now backend-neutral: kento exposes every signal
/// natively via `inspect --json`, so the bridge no longer reads PVE
/// `description`/config fields or pokes guest metadata.
pub trait Kento {
    /// Enumerate every kento instance, returning the signals the sweeper
    /// observes. `kento` only knows about kento-managed instances, so there
    /// is no vmid-range scan: the live set IS the kento list.
    fn list_instances(&self) -> Result<Vec<InstanceSignals>, Error>;

    /// Destroy the instance named `name` (LXC via `kento lxc destroy`, VM
    /// via `kento vm destroy`). `kento` removes **by instance name**, so its
    /// own overlay state is cleaned alongside the backend guest. The caller
    /// passes the name it read back from the **live instance list** during
    /// classification (never a caller-supplied name).
    fn teardown(&self, name: &str, mode: Mode) -> Result<(), Error>;

    /// Create a new instance from a fully-resolved [`ProvisionSpec`].
    ///
    /// `kento` owns networking, ssh-host-key injection and the initial
    /// start, and records the seadog identity anchor via injected env:
    /// `provision` shells `kento <mode> create --name … --network
    /// bridge=<bridge> --ip <ip>/<prefix> --gateway <gw> --env
    /// SEADOG_GUID=<guid> --env SEADOG_OWNER=<owner> --start [--mac <mac>
    /// ONLY for vm] <image-ref>`, then reads the realized signals back via
    /// `inspect --json` for the [`ProvisionOutcome`].
    ///
    /// `--mac` is **VM-only**: kento reports (and accepts) a MAC for VM
    /// modes only — it writes the `kento-mac` meta at create time for VMs
    /// and emits `mac` from `inspect --json` present-only, so an LXC has no
    /// MAC at all. [`ProvisionOutcome::mac`] is therefore `Some` for a VM
    /// (the passed `--mac`) and `None` for an LXC.
    fn provision(&self, spec: &ProvisionSpec) -> Result<ProvisionOutcome, Error>;
}

/// What the sweeper observes about one live kento instance, all sourced
/// from `kento inspect --json`. Replaces the PVE-era `GuestSignals`
/// (description-marker + hardware-fingerprint) with kento's native,
/// backend-neutral signal set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstanceSignals {
    /// Instance name — kento's primary key (seadog controls it; encodes the
    /// owner as `seadog-<owner>-<shortproj>-<token>`).
    pub name: String,
    /// Injected `SEADOG_GUID` env, read back via inspect. `None` ⇒ the
    /// instance carries no seadog anchor and is **foreign** (ignored).
    pub guid: Option<String>,
    /// Injected `SEADOG_OWNER` env, read back via inspect.
    pub owner: Option<String>,
    /// Realized MAC, when kento reports one (confirming-when-present).
    /// kento reports a MAC for **VM modes only** (it is written at create
    /// time for VMs and emitted from `inspect` present-only), so this is
    /// `None` for every LXC — that `None` is the designed sentinel
    /// identity treats as "nothing to confirm".
    pub mac: Option<String>,
    /// SSH host-key fingerprints, when kento reports them
    /// (confirming-when-present; a soft confirmer — regenerated keys must
    /// not strand an env).
    pub ssh_host_key_fps: Vec<String>,
    /// Image ref/name kento reports for the instance.
    pub image: String,
    /// kento-reported status text (informational).
    pub status: String,
    /// Backend family, collapsed to the backend-neutral [`Mode`]
    /// ([`Mode::Lxc`] / [`Mode::Vm`]). kento `inspect --json` (and `list
    /// --json`) emits an authoritative `type` field ∈ {`LXC`, `VM`} (always
    /// present: `info.py:97`) that is the unambiguous family signal: `VM` →
    /// [`Mode::Vm`], `LXC` → [`Mode::Lxc`]. The accompanying `mode` string is
    /// informational and serves only as a defensive fallback if `type` is ever
    /// missing/unrecognized. kento 1.5.3 normalizes that `mode` string to
    /// `pve-lxc` for a PVE-LXC (matching it across both `list --json` and
    /// `inspect --json`); the fallback's catch-all maps everything that isn't
    /// `vm`/`pve-vm` to the LXC family, so `pve` (older kento) OR `pve-lxc`
    /// (≥1.5.3) both resolve to [`Mode::Lxc`]. Lets reap recover an orphan's
    /// family precisely instead of guessing from the status text. Defaults to
    /// [`Mode::Lxc`] when kento reports nothing recognizable.
    pub mode: Mode,
    /// Backend vmid when kento exposes one (PVE backends only);
    /// informational, never an identity key.
    pub vmid: Option<u32>,
}

/// A fully-resolved provisioning request: every field has already been
/// re-validated by `seadog-priv` against its own config load. The MAC,
/// IP, name and GUID were allocated by the (untrusted) front-end but
/// re-checked here; `image_ref` is the allowlisted ref the server picked,
/// never a raw caller ref. No vmid: kento auto-assigns where the backend
/// has one (PVE), and seadog no longer allocates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionSpec {
    /// LXC or VM.
    pub mode: Mode,
    /// Allowlisted OCI image ref (server-resolved, never caller-supplied).
    pub image_ref: String,
    /// `seadog-…` guest name (re-validated DNS label).
    pub name: String,
    /// Assigned MAC (re-validated shape).
    pub mac: String,
    /// Leased IPv4 as a string (re-validated to parse).
    pub ip: String,
    /// IPv4 prefix length (CIDR bits) for the leased IP, from config.
    pub prefix: u8,
    /// Default gateway for the leased IP, from config.
    pub gateway: String,
    /// PVE bridge `kento` attaches the guest to (config `allocation.bridge`).
    pub bridge: String,
    /// Instance GUID minted by the front-end (injected as the
    /// `SEADOG_GUID` env — the create-time-immutable identity anchor).
    pub guid: String,
    /// Resolved owner (trusted from the front-end; injected as the
    /// `SEADOG_OWNER` env so the instance carries its owner natively).
    pub owner: String,
    /// Path to a root-owned file of the OWNER's authorized ssh pubkey line(s)
    /// (one `ssh-…` per line) to inject into the guest so the owner can log
    /// in. `None` → no key injection (`--ssh-key` omitted); the create still
    /// proceeds. The helper materializes this from its OWN authorized_keys by
    /// owner name and removes it after provision — it is never long-lived.
    pub ssh_key_file: Option<std::path::PathBuf>,
    /// The login user the injected key authorizes (`--ssh-key-user`). Ignored
    /// when `ssh_key_file` is `None`.
    pub ssh_key_user: String,
    /// Whether nesting is permitted for this instance — mode-agnostic (VM→VM
    /// nesting / nested virt, container→container nesting). Resolved by the
    /// front-end from the served image entry's `allow_nesting` and
    /// re-validated by the helper against the allowlist; pushed as
    /// `--allow-nesting` to `kento <mode> create` (UNCONDITIONAL on mode)
    /// when true, omitted when false.
    pub allow_nesting: bool,
}

/// What [`Kento::provision`] reports back, read from kento's `inspect
/// --json` after create: the realized MAC (kento reports it for **VM
/// modes only** — `Some` for a VM, `None` for an LXC), the SSH host-key
/// fingerprints, and the backend vmid when one exists (PVE backends;
/// `None` otherwise). The front-end records these on the DB row; identity
/// treats MAC and host-key fps as confirming-when-present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionOutcome {
    /// The MAC the realized instance carries: `Some` for a VM, `None` for
    /// an LXC (kento reports a MAC for VM modes only).
    pub mac: Option<String>,
    /// The realized SSH host-key fingerprints (empty if kento reports none).
    pub ssh_host_key_fps: Vec<String>,
    /// Backend vmid when kento exposes one (PVE backends); `None` otherwise.
    pub vmid: Option<u32>,
}

// --- Pure argv builders (ALWAYS compiled, NOT behind `real-kento`) ---
//
// The shelling-out `RealKento` spawn path (gated behind `real-kento`) calls
// these to assemble its argv, but the builders themselves are pure (no exec,
// no feature gate) so the EXACT emitted argv is type-checked and unit-testable
// in the default build — the spawn path stays the ONLY feature-gated piece.

/// Build the argv for `kento <mode> create …` from a [`ProvisionSpec`].
///
/// Single source of truth for the create argv: the `real-kento` spawn path
/// calls this and runs the result verbatim. Ordering, the optional
/// `--ssh-key …` block (omitted when no key file), the VM-only `--mac` block,
/// the unconditional-on-mode `--allow-nesting` flag, and the trailing image
/// positional are all fixed here.
pub fn provision_argv(spec: &ProvisionSpec) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        spec.mode.as_str().to_string(),
        "create".to_string(),
        "--name".to_string(),
        spec.name.clone(),
        "--network".to_string(),
        format!("bridge={}", spec.bridge),
        "--ip".to_string(),
        format!("{}/{}", spec.ip, spec.prefix),
        "--gateway".to_string(),
        spec.gateway.clone(),
        "--ssh-host-keys".to_string(),
        "--start".to_string(),
        "--env".to_string(),
        format!("SEADOG_GUID={}", spec.guid),
        "--env".to_string(),
        format!("SEADOG_OWNER={}", spec.owner),
    ];
    // Inject the OWNER's pubkey(s) so they can SSH into their env.
    // `--config-mode auto` lets kento pick injection (lxc) vs cloud-init (vm).
    // Omitted entirely when no key was materialized (fail-open).
    if let Some(key_file) = &spec.ssh_key_file {
        argv.push("--ssh-key".to_string());
        argv.push(key_file.to_string_lossy().into_owned());
        argv.push("--ssh-key-user".to_string());
        argv.push(spec.ssh_key_user.clone());
        argv.push("--config-mode".to_string());
        argv.push("auto".to_string());
    }
    // VM-only MAC: kento accepts --mac for VM modes only (it rejects it for
    // LXC) and likewise reports a `mac` from inspect for VMs only.
    if spec.mode == Mode::Vm {
        argv.push("--mac".to_string());
        argv.push(spec.mac.clone());
    }
    // Nesting: push `--allow-nesting` UNCONDITIONALLY on mode (unlike the
    // VM-only `--mac` block) — it is mode-agnostic. Omitted when false so
    // kento's own default applies.
    if spec.allow_nesting {
        argv.push("--allow-nesting".to_string());
    }
    // The image ref is the final positional argument.
    argv.push(spec.image_ref.clone());
    argv
}

/// Build the argv for `kento <mode> destroy -f <name>`.
///
/// `kento` destroys BY INSTANCE NAME (not vmid); `-f` forces a running
/// instance. `mode` selects the `lxc`/`vm` subcommand.
pub fn teardown_argv(name: &str, mode: Mode) -> Vec<String> {
    vec![
        mode.as_str().to_string(),
        "destroy".to_string(),
        "-f".to_string(),
        name.to_string(),
    ]
}

/// Build the argv for `kento inspect <name> --json`.
pub fn inspect_argv(name: &str) -> Vec<String> {
    vec![
        "inspect".to_string(),
        name.to_string(),
        "--json".to_string(),
    ]
}

/// Build the argv for `kento list --json`.
///
/// One enumerating call (kento 1.5.3+): it prints a JSON array of the same
/// per-object shape `inspect --json` emits, so the sweeper enumerates the live
/// set in a single shell-out instead of `list` + N× `inspect`.
pub fn list_json_argv() -> Vec<String> {
    vec!["list".to_string(), "--json".to_string()]
}

/// In-memory [`Kento`] for tests. Always compiled (not `#[cfg(test)]`) so
/// later integration tests in sibling crates can drive it too.
///
/// Tests populate [`FakeKento::instances`] via [`FakeKento::set_instances`],
/// then assert on [`FakeKento::teardowns`] to see exactly what got reaped.
/// Priming [`FakeKento::quorum_lost`] makes both `list_instances` and
/// `teardown` return [`Error::QuorumLost`], so the reaper's
/// stop-on-quorum-loss path is testable without a cluster.
#[derive(Default)]
pub struct FakeKento {
    inner: Mutex<FakeState>,
}

#[derive(Default)]
struct FakeState {
    instances: Vec<InstanceSignals>,
    /// Teardown calls recorded as `(name, mode)` — `kento` destroys by name.
    teardowns: Vec<(String, Mode)>,
    /// Provision calls recorded so tests can assert exact params.
    provisions: Vec<ProvisionSpec>,
    /// `allow_nesting` recorded per provision call, in order — mirrors
    /// `provisions` so tests can assert the boundary value reached the spec.
    provision_allow_nesting: Vec<bool>,
    /// When set, every op returns this quorum-loss message.
    quorum_lost: Option<String>,
    /// Optional per-name teardown failures (non-quorum), to test errors.
    teardown_fail: HashMap<String, String>,
    /// When set, `provision` returns this non-quorum [`Error::Kento`] message
    /// (e.g. the image-not-found / "kento does NOT auto-pull" class).
    /// Symmetric to `teardown_fail`; the quorum flag takes precedence (it is
    /// the global condition checked first).
    provision_fail: Option<String>,
    /// When set, `list_instances` returns this non-quorum [`Error::Kento`]
    /// message (a flaky `kento list`), to exercise the transient-failure path
    /// (e.g. the watch loop's log-and-continue). The quorum flag takes
    /// precedence (the global condition is checked first).
    list_fail: Option<String>,
}

impl FakeKento {
    /// A fresh fake with no instances.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the live instance list the sweeper will observe.
    pub fn set_instances(&self, instances: Vec<InstanceSignals>) {
        self.inner.lock().unwrap().instances = instances;
    }

    /// Prime a quorum-loss condition: every subsequent op fails with
    /// [`Error::QuorumLost`].
    pub fn set_quorum_lost(&self, msg: impl Into<String>) {
        self.inner.lock().unwrap().quorum_lost = Some(msg.into());
    }

    /// Make `teardown(name, _)` fail with a non-quorum error.
    pub fn fail_teardown(&self, name: impl Into<String>, msg: impl Into<String>) {
        self.inner
            .lock()
            .unwrap()
            .teardown_fail
            .insert(name.into(), msg.into());
    }

    /// Make `provision(_)` fail with a non-quorum [`Error::Kento`] carrying
    /// `msg` — the symmetric counterpart to [`FakeKento::fail_teardown`]. Use
    /// it to exercise the provision-failure path (e.g. the image-not-found /
    /// "kento does NOT auto-pull" class) without a real host. A primed
    /// quorum-loss still takes precedence (it is the global condition checked
    /// first), so [`FakeKento::set_quorum_lost`] surfaces on `provision` too.
    pub fn fail_provision(&self, msg: impl Into<String>) {
        self.inner.lock().unwrap().provision_fail = Some(msg.into());
    }

    /// Make `list_instances()` fail with a non-quorum [`Error::Kento`]
    /// carrying `msg` (a flaky `kento list`) — the symmetric counterpart to
    /// [`FakeKento::fail_teardown`] / [`FakeKento::fail_provision`]. Use it to
    /// exercise the transient list-failure path (e.g. the watch loop's
    /// log-and-continue) without a real host. A primed quorum-loss still takes
    /// precedence (it is the global condition checked first).
    pub fn fail_list(&self, msg: impl Into<String>) {
        self.inner.lock().unwrap().list_fail = Some(msg.into());
    }

    /// Clear a primed [`FakeKento::fail_list`] so a subsequent
    /// `list_instances()` succeeds — lets a test drive an error-then-recover
    /// sequence.
    pub fn clear_list_fail(&self) {
        self.inner.lock().unwrap().list_fail = None;
    }

    /// The teardown calls recorded so far, in order, as `(name, mode)`.
    pub fn teardowns(&self) -> Vec<(String, Mode)> {
        self.inner.lock().unwrap().teardowns.clone()
    }

    /// The provision calls recorded so far, in order.
    pub fn provisions(&self) -> Vec<ProvisionSpec> {
        self.inner.lock().unwrap().provisions.clone()
    }

    /// The `allow_nesting` flag recorded per provision call, in order —
    /// parallel to [`FakeKento::provisions`]. Lets tests assert the
    /// boundary-crossing nesting value reached the spec.
    pub fn provision_allow_nesting(&self) -> Vec<bool> {
        self.inner.lock().unwrap().provision_allow_nesting.clone()
    }
}

impl Kento for FakeKento {
    fn list_instances(&self) -> Result<Vec<InstanceSignals>, Error> {
        let st = self.inner.lock().unwrap();
        if let Some(msg) = &st.quorum_lost {
            return Err(Error::QuorumLost(msg.clone()));
        }
        // Non-quorum list failure hook (a flaky `kento list`). Checked AFTER
        // quorum so the global condition still wins; symmetric to
        // `teardown_fail` / `provision_fail`.
        if let Some(msg) = &st.list_fail {
            return Err(Error::Kento(msg.clone()));
        }
        // kento only knows kento instances — return the set list as-is, no
        // vmid-range filter.
        Ok(st.instances.clone())
    }

    fn teardown(&self, name: &str, mode: Mode) -> Result<(), Error> {
        let mut st = self.inner.lock().unwrap();
        if let Some(msg) = &st.quorum_lost {
            return Err(Error::QuorumLost(msg.clone()));
        }
        if let Some(msg) = st.teardown_fail.get(name).cloned() {
            return Err(Error::Kento(msg));
        }
        st.teardowns.push((name.to_string(), mode));
        // Remove the instance by name so a subsequent list_instances
        // reflects the destroy (kento removes by instance name).
        st.instances.retain(|i| i.name != name);
        Ok(())
    }

    fn provision(&self, spec: &ProvisionSpec) -> Result<ProvisionOutcome, Error> {
        let mut st = self.inner.lock().unwrap();
        if let Some(msg) = &st.quorum_lost {
            return Err(Error::QuorumLost(msg.clone()));
        }
        // Non-quorum provision failure hook (e.g. image-not-found / kento
        // does NOT auto-pull). Checked AFTER quorum so the global condition
        // still wins; symmetric to `teardown_fail`.
        if let Some(msg) = &st.provision_fail {
            return Err(Error::Kento(msg.clone()));
        }
        // kento reports the realized MAC for VM modes ONLY: a VM keeps the
        // passed `--mac`; an LXC has no MAC at all (kento writes the
        // `kento-mac` meta only for VMs and emits `mac` from inspect
        // present-only), so an LXC yields `None` — the designed sentinel.
        let effective_mac = match spec.mode {
            Mode::Vm => Some(spec.mac.clone()),
            Mode::Lxc => None,
        };
        // Synthesize a couple of stable host-key fingerprints.
        let fps = vec![
            format!("SHA256:fp-ed25519-{}", spec.name),
            format!("SHA256:fp-rsa-{}", spec.name),
        ];
        st.instances.push(InstanceSignals {
            name: spec.name.clone(),
            guid: Some(spec.guid.clone()),
            owner: Some(spec.owner.clone()),
            mac: effective_mac.clone(),
            ssh_host_key_fps: fps.clone(),
            image: spec.image_ref.clone(),
            status: "running".to_string(),
            // The realized instance carries the spec's mode (kento reports
            // it via inspect.mode).
            mode: spec.mode,
            // FakeKento has no PVE backend → no vmid.
            vmid: None,
        });
        st.provisions.push(spec.clone());
        st.provision_allow_nesting.push(spec.allow_nesting);
        Ok(ProvisionOutcome {
            mac: effective_mac,
            ssh_host_key_fps: fps,
            vmid: None,
        })
    }
}

// --- RealKento: behind the `real-kento` feature so the lib builds with
//     zero external tools by default. Not exercised by tests (no real host),
//     but it MUST compile under `--features real-kento`. ---
#[cfg(feature = "real-kento")]
pub use real::RealKento;

#[cfg(feature = "real-kento")]
mod real {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use wait_timeout::ChildExt;

    use super::*;

    /// Per-op hard timeout. `kento` (Python) shells out to lxc/qemu/pct/qm
    /// underneath and can wedge on a sick cluster; we kill on expiry rather
    /// than block the sweep forever.
    const OP_TIMEOUT: Duration = Duration::from_secs(30);

    /// Fixed PATH set before exec. We `env_clear()` and pin a known-good
    /// search path to avoid hijacking via the ambient environment. `kento`
    /// installs to `/usr/local/bin`, so the pinned path mirrors root's
    /// standard PATH and includes the `/usr/local` bins — all root-owned
    /// system dirs. (kento itself reaches the backend tools — pct/qm/lxc/
    /// qemu — so seadog only ever spawns `kento`.)
    const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

    /// Substrings that mark a pmxcfs quorum-loss / read-only condition.
    /// kento runs on PVE backends (kento-mode `pve`/`pve-vm`), where a corosym
    /// partition still drops pmxcfs to read-only and surfaces the same
    /// kernel/cluster wording through the failing `kento` invocation, so we
    /// keep mapping these to [`Error::QuorumLost`] (the sweep stops cleanly
    /// instead of spinning). On non-PVE backends these markers simply never
    /// appear, so the check is harmless there.
    const QUORUM_MARKERS: &[&str] = &[
        "no quorum",
        "cluster not ready",
        "Read-only file system",
        "permission denied - not part of cluster",
    ];

    /// The shelling-out [`Kento`]: runs `kento` as an argv vector (never a
    /// shell string), with a cleared environment, a pinned PATH, and a
    /// per-op hard timeout. No `pvesh`/`qm`/`pct` — every backend op goes
    /// through `kento`.
    #[derive(Debug)]
    pub struct RealKento {
        /// The program name/path used to invoke `kento`. Bare `"kento"`
        /// (resolved via [`SAFE_PATH`]) unless the config pins an absolute
        /// `kento_path`.
        kento_bin: String,
    }

    impl Default for RealKento {
        fn default() -> Self {
            RealKento {
                kento_bin: "kento".to_string(),
            }
        }
    }

    impl RealKento {
        /// Construct a `RealKento` invoking the bare `"kento"` (resolved via
        /// the pinned PATH).
        pub fn new() -> Self {
            Self::default()
        }

        /// Construct a `RealKento` honoring `config.kento_path`: when set, the
        /// `kento` binary is invoked by that absolute path; otherwise the bare
        /// `"kento"` name is used (resolved via [`SAFE_PATH`]).
        pub fn from_config(config: &crate::config::Config) -> Self {
            match &config.kento_path {
                Some(p) if !p.trim().is_empty() => RealKento {
                    kento_bin: p.clone(),
                },
                _ => Self::default(),
            }
        }

        /// Run `kento argv…` to completion under the safety harness,
        /// returning stdout. Maps a quorum-loss signature to
        /// [`Error::QuorumLost`] and a timeout to [`Error::Kento`].
        fn run(&self, argv: &[&str]) -> Result<String, Error> {
            let program = &self.kento_bin;
            let mut cmd = Command::new(program);
            cmd.args(argv)
                .env_clear()
                .env("PATH", SAFE_PATH)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());

            let mut child = cmd
                .spawn()
                .map_err(|e| Error::Kento(format!("spawn {program}: {e}")))?;

            let status = match child
                .wait_timeout(OP_TIMEOUT)
                .map_err(|e| Error::Kento(format!("wait {program}: {e}")))?
            {
                Some(status) => status,
                None => {
                    // Timed out: kill and surface, do not block forever.
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Error::Kento(format!(
                        "{program} timed out after {}s",
                        OP_TIMEOUT.as_secs()
                    )));
                }
            };

            let output = child
                .wait_with_output()
                .map_err(|e| Error::Kento(format!("collect {program}: {e}")))?;
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

            if !status.success() {
                let combined = format!("{stdout}\n{stderr}");
                if QUORUM_MARKERS
                    .iter()
                    .any(|m| combined.to_lowercase().contains(&m.to_lowercase()))
                {
                    return Err(Error::QuorumLost(format!(
                        "{program} reported quorum loss: {}",
                        stderr.trim()
                    )));
                }
                return Err(Error::Kento(format!(
                    "{program} exited {:?}: {}",
                    status.code(),
                    stderr.trim()
                )));
            }
            Ok(stdout)
        }
    }

    impl Kento for RealKento {
        fn list_instances(&self) -> Result<Vec<InstanceSignals>, Error> {
            // Strategy (kento-only — no pvesh/qm/pct): ONE `kento list --json`
            // call (kento 1.5.3+) enumerates every kento-managed instance as a
            // JSON array of the same per-object shape `inspect --json` emits, so
            // the sweeper reads the whole live set in a single shell-out — no
            // `list` + N× `inspect` fan-out, no vmid-range scan (`kento` only
            // sees its own instances, so the live set IS the kento list).
            //
            // Resilience semantics:
            //   - The WHOLE-call failure is GLOBAL: a failing `kento list`
            //     (exec error, or a quorum-loss surfacing as
            //     [`Error::QuorumLost`]) means we cannot see the live set at
            //     all, so the `?` propagates and the sweep ABORTS rather than
            //     reaping against an empty/partial view. A malformed top-level
            //     (non-array) is likewise untrustworthy whole output → it
            //     propagates as [`Error::Kento`], NOT an empty list.
            //   - A single non-object array element is per-element resilient:
            //     `parse_kento_list_json` logs + skips it and keeps the rest, so
            //     one bad element can't blind the reaper to every other env.
            // Parsing is the pure `parse_kento_list_json` (unit-tested on sample
            // output with no real command in the loop).
            let argv = list_json_argv();
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            let out = self.run(&argv)?;
            parse_kento_list_json(&out).map_err(Error::Kento)
        }

        fn teardown(&self, name: &str, mode: Mode) -> Result<(), Error> {
            // `kento` destroys BY INSTANCE NAME (not vmid), so its overlay
            // state is cleaned alongside the backend guest. `-f` forces a
            // running instance. The name is the one teardown read from the
            // live `kento list`. The argv is built by the pure (always-
            // compiled) `teardown_argv` so the spawn path runs it verbatim.
            let argv = teardown_argv(name, mode);
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            self.run(&argv).map(|_| ())
        }

        fn provision(&self, spec: &ProvisionSpec) -> Result<ProvisionOutcome, Error> {
            // kento OWNS networking/ssh/start: one `kento <mode> create`
            // attaches the bridge, assigns the IP/gateway, generates ssh host
            // keys, injects the owner key, and starts the guest. The seadog
            // identity anchor rides as injected env (`--env SEADOG_GUID=… --env
            // SEADOG_OWNER=…`) — create-time-immutable, replacing the old PVE
            // description marker. `--vmid` is omitted entirely (kento auto-
            // assigns where the backend has one). `--mac` is VM-ONLY (kento
            // rejects it for LXC). Then we read the realized signals back via
            // `kento inspect --json`. Not exercised by tests (no real host) but
            // MUST compile under `--features real-kento`.
            //
            // The create argv is built by the pure (always-compiled)
            // `provision_argv` so the spawn path runs it verbatim — the exact
            // ordering, the VM-only `--mac` block, the optional `--ssh-key`
            // block, and the `--allow-nesting` flag all live there.
            let argv = provision_argv(spec);
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            self.run(&argv)?;

            // Read the realized signals back. kento reports the MAC for VM
            // modes only (absent ⇒ None for an LXC), the host-key fps it
            // generated, and the vmid on PVE backends — exactly the fields the
            // front-end records. The inspect argv is likewise the pure
            // `inspect_argv`.
            let inspect = inspect_argv(&spec.name);
            let inspect: Vec<&str> = inspect.iter().map(String::as_str).collect();
            let json = self.run(&inspect)?;
            let signals = parse_kento_inspect(&json)
                .map_err(|e| Error::Kento(format!("parsing inspect {}: {e}", spec.name)))?;
            Ok(ProvisionOutcome {
                mac: signals.mac,
                ssh_host_key_fps: signals.ssh_host_key_fps,
                vmid: signals.vmid,
            })
        }
    }

    // --- Pure parsers (no exec): unit-testable on sample strings. ---

    /// Parse `kento inspect <name> --json` into [`InstanceSignals`].
    ///
    /// kento emits a stable dict (`json.dumps(data, indent=2)`); fields that
    /// are unset are simply absent (kento never emits an empty `mac`/`vmid`),
    /// so absence maps cleanly to `None`/empty. Mapping:
    /// - `guid` / `owner` ← the `environment[]` `KEY=VALUE` lines, keyed on
    ///   `SEADOG_GUID` / `SEADOG_OWNER`. Absent `SEADOG_GUID` ⇒ `None` ⇒ the
    ///   instance is **foreign** (no seadog anchor).
    /// - `mac` ← `.mac` (absent ⇒ `None`).
    /// - `ssh_host_key_fps` ← the values of the
    ///   `.ssh_host_key_fingerprints` `{type: fp}` dict, sorted for a stable
    ///   order (the map is unordered in JSON).
    /// - `image` ← `.image`; `status` ← `.status`.
    /// - family ← the authoritative `.type` ∈ {`LXC`, `VM`} (ALWAYS present:
    ///   kento `info.py:97`): `VM` → [`Mode::Vm`], `LXC` → [`Mode::Lxc`].
    ///   That `type` is the unambiguous family signal — immune to the
    ///   mode-string nuance below. `.mode` (the raw kento-mode string — kento
    ///   `info.py:96`; 1.5.3 normalizes a PVE-LXC to `pve-lxc`, matching it
    ///   across both `list --json` and `inspect --json`) is read as a
    ///   DEFENSIVE fallback used ONLY when `type` is missing/unrecognized:
    ///   `vm`/`pve-vm` → [`Mode::Vm`], everything else → [`Mode::Lxc`] (so
    ///   `pve` from older kento OR `pve-lxc` from ≥1.5.3 both resolve to Lxc).
    ///   reap uses the collapsed family to recover an orphan's mode precisely.
    /// - `vmid` ← `.vmid` (present only on PVE backends; informational).
    ///
    /// Parsing splits into the top-level `as_object()` check here and the
    /// infallible per-object extraction in `parse_signals_obj`, which `list
    /// --json` reuses verbatim per array element.
    pub fn parse_kento_inspect(json: &str) -> Result<InstanceSignals, String> {
        let value: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let obj = value
            .as_object()
            .ok_or_else(|| "expected a top-level JSON object".to_string())?;
        Ok(parse_signals_obj(obj))
    }

    /// Parse `kento list --json` into a [`Vec<InstanceSignals>`].
    ///
    /// kento 1.5.3+ prints a JSON ARRAY (`[]` when zero instances), one object
    /// per instance carrying the SAME keys/types `inspect --json` emits per
    /// object. This single enumerating call replaces the old columnar `list`
    /// plus N× `inspect` fan-out: each element is fed through the same
    /// `parse_signals_obj` extraction `parse_kento_inspect` uses, so a `list`
    /// row and an `inspect` of the same instance yield identical signals.
    ///
    /// Per-element resilient: a non-object element is logged + skipped (one bad
    /// element can't blind the reaper to every other env). The WHOLE-call
    /// failure (a non-array top level, an exec error, or a quorum-loss) is the
    /// caller's to handle — it propagates so the sweep aborts rather than
    /// reaping against an untrustworthy/partial view.
    pub fn parse_kento_list_json(json: &str) -> Result<Vec<InstanceSignals>, String> {
        let value: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let arr = value
            .as_array()
            .ok_or_else(|| "expected a top-level JSON array".to_string())?;

        let mut out = Vec::with_capacity(arr.len());
        for elem in arr {
            match elem.as_object() {
                Some(obj) => out.push(parse_signals_obj(obj)),
                None => {
                    // Per-element resilience: a non-object element is skipped
                    // (kento would have to break its own contract) so one bad
                    // element can't blind the reaper to every other instance.
                    tracing::warn!(
                        element = ?elem,
                        "skipping non-object element in kento list --json output"
                    );
                    continue;
                }
            }
        }
        Ok(out)
    }

    /// Extract the [`InstanceSignals`] from one already-parsed kento JSON
    /// object (an `inspect --json` dict, or one element of a `list --json`
    /// array — they share the same shape). Infallible: every field already
    /// defaults (absent ⇒ `None`/empty/`Mode::Lxc`), so there is nothing left
    /// to reject once the value is known to be an object.
    fn parse_signals_obj(obj: &serde_json::Map<String, serde_json::Value>) -> InstanceSignals {
        let str_field = |key: &str| -> Option<String> {
            obj.get(key)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .filter(|s| !s.is_empty())
        };

        let name = str_field("name").unwrap_or_default();
        let image = str_field("image").unwrap_or_default();
        let status = str_field("status").unwrap_or_default();
        let mac = str_field("mac");

        // Collapse the backend family to the neutral Mode on the AUTHORITATIVE
        // `.type` field (kento info.py:97 — ALWAYS present, ∈ {LXC, VM}): it is
        // the unambiguous family signal, immune to the raw `.mode` string's
        // nuance. `.type` is the primary path.
        //
        // DEFENSIVE fallback ONLY when `.type` is missing/unrecognized (kento
        // would have to break its own contract): fall back to the `.mode`
        // string — vm-family (`vm`/`pve-vm`) → Vm, everything else → Lxc. kento
        // 1.5.3 normalizes a PVE-LXC's `.mode` to `pve-lxc`; the catch-all maps
        // it (and bare `pve` from older kento) to Lxc, so the fallback is
        // version-agnostic.
        let mode = match str_field("type").as_deref() {
            Some("VM") => Mode::Vm,
            Some("LXC") => Mode::Lxc,
            _ => match str_field("mode").as_deref() {
                Some("vm") | Some("pve-vm") => Mode::Vm,
                _ => Mode::Lxc,
            },
        };

        // vmid is emitted as a JSON number (int) on PVE backends, absent
        // otherwise. Be lenient about a stringified vmid too.
        let vmid = obj.get("vmid").and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok()))
                .filter(|n| *n <= u32::MAX as u64)
                .map(|n| n as u32)
        });

        // environment[] is a list of "KEY=VALUE" strings (absent when no env
        // was injected). Pull SEADOG_GUID / SEADOG_OWNER out of it.
        let mut guid = None;
        let mut owner = None;
        if let Some(env) = obj.get("environment").and_then(|v| v.as_array()) {
            for item in env {
                let entry = match item.as_str() {
                    Some(s) => s,
                    None => continue,
                };
                let (key, val) = match entry.split_once('=') {
                    Some((k, v)) => (k, v),
                    None => continue,
                };
                match key {
                    "SEADOG_GUID" if !val.is_empty() => guid = Some(val.to_string()),
                    "SEADOG_OWNER" if !val.is_empty() => owner = Some(val.to_string()),
                    _ => {}
                }
            }
        }

        // ssh_host_key_fingerprints is a {type: fingerprint} map. Flatten its
        // values; sort for a deterministic order (JSON object order is not
        // guaranteed) so identity comparison and tests are stable.
        let mut ssh_host_key_fps = Vec::new();
        if let Some(fps) = obj
            .get("ssh_host_key_fingerprints")
            .and_then(|v| v.as_object())
        {
            for v in fps.values() {
                if let Some(s) = v.as_str() {
                    if !s.is_empty() {
                        // Ingest guard (defense-in-depth on kento-sourced data):
                        // these values are persisted comma-delimited
                        // (store::join_fps), so a comma would mis-split on read;
                        // ASCII whitespace/control chars corrupt log lines. Drop
                        // any value carrying a storage-hostile char and warn.
                        // Algorithm-agnostic: we guard ONLY on those chars, not
                        // on a SHA256: prefix or any base64 alphabet.
                        if s.bytes()
                            .any(|b| b == b',' || b.is_ascii_whitespace() || b.is_ascii_control())
                        {
                            tracing::warn!(
                                fingerprint = ?s,
                                "dropping ssh host-key fingerprint with storage-hostile char (comma/whitespace/control)"
                            );
                            continue;
                        }
                        ssh_host_key_fps.push(s.to_string());
                    }
                }
            }
            ssh_host_key_fps.sort();
        }

        InstanceSignals {
            name,
            guid,
            owner,
            mac,
            ssh_host_key_fps,
            image,
            status,
            mode,
            vmid,
        }
    }

    #[cfg(test)]
    mod parser_tests {
        use super::*;

        #[test]
        fn parse_list_json_two_instances_reuses_inspect_extraction() {
            // `kento list --json` prints an array of the SAME per-object shape
            // `inspect --json` emits, so each element flows through the shared
            // `parse_signals_obj` extraction. One PVE-LXC (1.5.3 `mode`
            // "pve-lxc", a vmid, host-key fps, the SEADOG anchor env, NO mac)
            // and one VM (`mode` "vm", a mac, stopped).
            let json = r#"[
                {
                    "name": "seadog-alice-proj-ab12",
                    "image": "registry/loom:1",
                    "mode": "pve-lxc",
                    "type": "LXC",
                    "status": "running",
                    "vmid": 10010,
                    "environment": [
                        "SEADOG_GUID=guid-abc",
                        "SEADOG_OWNER=alice",
                        "TERM=xterm"
                    ],
                    "ssh_host_key_fingerprints": {
                        "ed25519": "SHA256:aaa",
                        "rsa": "SHA256:bbb"
                    }
                },
                {
                    "name": "seadog-bob-proj-cd34",
                    "image": "registry/stuff:2",
                    "mode": "vm",
                    "type": "VM",
                    "status": "stopped",
                    "mac": "12:34:56:78:9a:bc",
                    "environment": ["SEADOG_GUID=g-bob", "SEADOG_OWNER=bob"],
                    "ssh_host_key_fingerprints": {}
                }
            ]"#;
            let v = parse_kento_list_json(json).unwrap();
            assert_eq!(v.len(), 2);

            // The PVE-LXC: `type` LXC ⇒ Lxc (1.5.3 `mode` "pve-lxc" agrees),
            // anchor env extracted, fps sorted, vmid parsed, NO mac.
            let lxc = &v[0];
            assert_eq!(lxc.name, "seadog-alice-proj-ab12");
            assert_eq!(lxc.mode, Mode::Lxc, "type LXC (mode pve-lxc) ⇒ Lxc");
            assert_eq!(lxc.guid.as_deref(), Some("guid-abc"));
            assert_eq!(lxc.owner.as_deref(), Some("alice"));
            assert_eq!(lxc.vmid, Some(10010));
            assert_eq!(lxc.mac, None, "LXC reports no mac ⇒ None");
            assert_eq!(
                lxc.ssh_host_key_fps,
                vec!["SHA256:aaa".to_string(), "SHA256:bbb".to_string()],
                "fps flattened + sorted"
            );

            // The VM: `type` VM ⇒ Vm, mac present, stopped.
            let vm = &v[1];
            assert_eq!(vm.name, "seadog-bob-proj-cd34");
            assert_eq!(vm.mode, Mode::Vm, "type VM ⇒ Vm");
            assert_eq!(vm.guid.as_deref(), Some("g-bob"));
            assert_eq!(vm.owner.as_deref(), Some("bob"));
            assert_eq!(vm.mac.as_deref(), Some("12:34:56:78:9a:bc"));
            assert_eq!(vm.status, "stopped");
            assert!(vm.ssh_host_key_fps.is_empty());
        }

        #[test]
        fn parse_list_json_empty_array_yields_empty_vec() {
            // The zero-instance case: an empty array ⇒ an empty Vec (NOT an
            // error — that is the well-formed "no live instances" signal).
            assert!(parse_kento_list_json("[]").unwrap().is_empty());
        }

        #[test]
        fn parse_list_json_non_array_top_level_is_err() {
            // A non-array top level means kento's whole output is untrustworthy:
            // it must Err (the caller propagates + aborts the sweep), NOT decay
            // to an empty list.
            assert!(parse_kento_list_json("{}").is_err());
            assert!(parse_kento_list_json("\"x\"").is_err());
            assert!(parse_kento_list_json("not json").is_err());
        }

        #[test]
        fn parse_list_json_skips_non_object_element() {
            // Per-element resilience: a non-object element (here a bare number)
            // is skipped, the valid object survives — one bad element can't
            // blind the reaper to every other instance.
            let json = r#"[
                {"name":"n","type":"LXC","mode":"lxc","environment":["SEADOG_GUID=g"]},
                42
            ]"#;
            let v = parse_kento_list_json(json).unwrap();
            assert_eq!(v.len(), 1, "the non-object 42 is skipped");
            assert_eq!(v[0].name, "n");
            assert_eq!(v[0].guid.as_deref(), Some("g"));
        }

        #[test]
        fn parse_list_json_carries_orphan_status() {
            // "orphan" is a list-only status (a kento instance with no backing
            // guest). It parses and rides through unchanged on `status`.
            let json = r#"[
                {"name":"ghost","type":"LXC","mode":"lxc","status":"orphan",
                 "environment":["SEADOG_GUID=g"]}
            ]"#;
            let v = parse_kento_list_json(json).unwrap();
            assert_eq!(v.len(), 1);
            assert_eq!(v[0].status, "orphan", "orphan status carried through");
        }

        #[test]
        fn parse_inspect_ours_maps_guid_owner_mac_fps() {
            // A kento instance seadog provisioned: SEADOG_GUID/SEADOG_OWNER in
            // environment[], a realized mac, a vmid (PVE backend), and two
            // host-key fingerprints. kento 1.5.3 reports a PVE-LXC's `mode` as
            // the normalized "pve-lxc".
            let json = r#"{
                "name": "seadog-alice-proj-ab12",
                "image": "registry/loom:1",
                "mode": "pve-lxc",
                "type": "LXC",
                "status": "running",
                "directory": "/var/lib/kento/lxc/10010",
                "state_directory": "/var/lib/kento/lxc/10010",
                "config_mode": "injection",
                "vmid": 10010,
                "network": "bridge=vmbr0",
                "mac": "aa:bb:cc:dd:ee:ff",
                "ssh_user": "root",
                "environment": [
                    "SEADOG_GUID=guid-abc",
                    "SEADOG_OWNER=alice",
                    "TERM=xterm"
                ],
                "layer_count": 3,
                "created": "2026-06-06 12:00:00",
                "ssh_host_key_fingerprints": {
                    "ecdsa": "SHA256:bbb",
                    "ed25519": "SHA256:aaa",
                    "rsa": "SHA256:ccc"
                },
                "qemu_args": [],
                "pve_args": []
            }"#;
            let s = parse_kento_inspect(json).unwrap();
            assert_eq!(s.name, "seadog-alice-proj-ab12");
            assert_eq!(s.guid.as_deref(), Some("guid-abc"));
            assert_eq!(s.owner.as_deref(), Some("alice"));
            assert_eq!(s.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
            assert_eq!(s.image, "registry/loom:1");
            assert_eq!(s.status, "running");
            assert_eq!(
                s.mode,
                Mode::Lxc,
                "`pve-lxc` mode + type LXC collapses to Lxc"
            );
            assert_eq!(s.vmid, Some(10010));
            // Flattened + sorted fingerprint values (map order not trusted).
            assert_eq!(
                s.ssh_host_key_fps,
                vec![
                    "SHA256:aaa".to_string(),
                    "SHA256:bbb".to_string(),
                    "SHA256:ccc".to_string(),
                ]
            );
        }

        #[test]
        fn parse_inspect_foreign_has_no_guid() {
            // A kento instance NOT created by seadog: no SEADOG_GUID env ⇒
            // guid None ⇒ classified Foreign. Also no mac, no vmid (a non-PVE
            // backend), and no host keys.
            let json = r#"{
                "name": "someones-box",
                "image": "docker.io/library/alpine:3",
                "mode": "lxc",
                "type": "LXC",
                "status": "stopped",
                "directory": "/var/lib/kento/lxc/someones-box",
                "state_directory": "/var/lib/kento/lxc/someones-box",
                "ssh_user": "root",
                "environment": ["FOO=bar"],
                "layer_count": 1,
                "created": "2026-06-06 09:00:00",
                "ssh_host_key_fingerprints": {},
                "qemu_args": [],
                "pve_args": []
            }"#;
            let s = parse_kento_inspect(json).unwrap();
            assert_eq!(s.name, "someones-box");
            assert_eq!(s.guid, None, "no SEADOG_GUID ⇒ foreign");
            assert_eq!(s.owner, None);
            assert_eq!(s.mac, None, "absent mac ⇒ None");
            assert!(s.ssh_host_key_fps.is_empty());
            assert_eq!(s.vmid, None, "non-PVE backend ⇒ no vmid");
            assert_eq!(s.status, "stopped");
            assert_eq!(s.mode, Mode::Lxc, "lxc mode ⇒ Lxc");
        }

        #[test]
        fn parse_inspect_no_environment_key_is_foreign() {
            // Some instances may carry no environment[] key at all (no env
            // ever injected). That must read as foreign, not error.
            let json = r#"{
                "name": "bare",
                "image": "img:1",
                "mode": "vm",
                "type": "VM",
                "status": "running",
                "directory": "/d",
                "state_directory": "/d",
                "ssh_user": "root",
                "layer_count": 0,
                "created": "2026-06-06 09:00:00",
                "ssh_host_key_fingerprints": {},
                "qemu_args": [],
                "pve_args": []
            }"#;
            let s = parse_kento_inspect(json).unwrap();
            assert_eq!(s.guid, None);
            assert_eq!(s.owner, None);
            assert_eq!(s.mode, Mode::Vm, "vm mode ⇒ Vm");
        }

        #[test]
        fn parse_inspect_type_drives_family_collapse() {
            // The authoritative `.type` field decides the family — even when
            // the `.mode` string is unrecognized or would point the other way.
            // type=VM ⇒ Vm regardless of an unknown/contradictory mode.
            let vm_by_type = r#"{"name":"n","mode":"weird-future-vm","type":"VM","environment":["SEADOG_GUID=g"]}"#;
            assert_eq!(
                parse_kento_inspect(vm_by_type).unwrap().mode,
                Mode::Vm,
                "type=VM drives the collapse to Vm even with an unknown mode string"
            );
            // type=LXC ⇒ Lxc.
            let lxc_by_type = r#"{"name":"n","mode":"weird-future-lxc","type":"LXC","environment":["SEADOG_GUID=g"]}"#;
            assert_eq!(parse_kento_inspect(lxc_by_type).unwrap().mode, Mode::Lxc);
            // PVE-LXC (kento 1.5.3 normalizes the `mode` to `pve-lxc`) +
            // type=LXC ⇒ Lxc.
            let pve_lxc =
                r#"{"name":"n","mode":"pve-lxc","type":"LXC","environment":["SEADOG_GUID=g"]}"#;
            assert_eq!(
                parse_kento_inspect(pve_lxc).unwrap().mode,
                Mode::Lxc,
                "`pve-lxc` mode + type=LXC ⇒ Lxc"
            );
            // Back-compat: a legacy bare `pve` mode (older kento, pre-1.5.3) +
            // type=LXC still ⇒ Lxc (the catch-all is version-agnostic).
            let legacy_pve =
                r#"{"name":"n","mode":"pve","type":"LXC","environment":["SEADOG_GUID=g"]}"#;
            assert_eq!(
                parse_kento_inspect(legacy_pve).unwrap().mode,
                Mode::Lxc,
                "legacy bare `pve` mode + type=LXC ⇒ Lxc (defensive back-compat)"
            );
            // PVE-VM: mode `pve-vm` + type=VM ⇒ Vm.
            let pve_vm =
                r#"{"name":"n","mode":"pve-vm","type":"VM","environment":["SEADOG_GUID=g"]}"#;
            assert_eq!(parse_kento_inspect(pve_vm).unwrap().mode, Mode::Vm);
        }

        #[test]
        fn parse_inspect_mode_fallback_when_type_missing() {
            // DEFENSIVE fallback: if kento ever omits/garbles the authoritative
            // `.type`, we fall back to the `.mode` string. No `.type` and no
            // `.mode` ⇒ safe Lxc default.
            let absent = r#"{"name":"n","environment":["SEADOG_GUID=g"]}"#;
            assert_eq!(parse_kento_inspect(absent).unwrap().mode, Mode::Lxc);
            // No `.type`, unrecognized `.mode` ⇒ Lxc default.
            let weird = r#"{"name":"n","mode":"podman","environment":["SEADOG_GUID=g"]}"#;
            assert_eq!(parse_kento_inspect(weird).unwrap().mode, Mode::Lxc);
            // No `.type`, `.mode`=vm ⇒ Vm via the fallback.
            let vm = r#"{"name":"n","mode":"vm","environment":["SEADOG_GUID=g"]}"#;
            assert_eq!(parse_kento_inspect(vm).unwrap().mode, Mode::Vm);
            // No `.type`, `.mode`=pve-vm ⇒ Vm via the fallback.
            let pve_vm = r#"{"name":"n","mode":"pve-vm","environment":["SEADOG_GUID=g"]}"#;
            assert_eq!(parse_kento_inspect(pve_vm).unwrap().mode, Mode::Vm);
            // No `.type`, `.mode`=pve (the real PVE-LXC mode) ⇒ Lxc via fallback.
            let pve = r#"{"name":"n","mode":"pve","environment":["SEADOG_GUID=g"]}"#;
            assert_eq!(parse_kento_inspect(pve).unwrap().mode, Mode::Lxc);
            // Unrecognized `.type` value also drops to the mode fallback.
            let bad_type =
                r#"{"name":"n","mode":"vm","type":"CONTAINER","environment":["SEADOG_GUID=g"]}"#;
            assert_eq!(
                parse_kento_inspect(bad_type).unwrap().mode,
                Mode::Vm,
                "unrecognized type ⇒ fall back to mode string (vm ⇒ Vm)"
            );
        }

        #[test]
        fn parse_inspect_empty_mac_is_none() {
            // Defensive: even if kento ever emitted an empty-string mac, it
            // must map to None (the confirming-when-present contract), not
            // Some("").
            let json = r#"{
                "name": "n",
                "image": "i",
                "mode": "vm",
                "type": "VM",
                "status": "running",
                "directory": "/d",
                "state_directory": "/d",
                "mac": "",
                "environment": ["SEADOG_GUID=g1", "SEADOG_OWNER="],
                "ssh_host_key_fingerprints": {"ed25519": "SHA256:only"}
            }"#;
            let s = parse_kento_inspect(json).unwrap();
            assert_eq!(s.mac, None, "empty mac ⇒ None");
            assert_eq!(s.guid.as_deref(), Some("g1"));
            assert_eq!(s.owner, None, "empty SEADOG_OWNER value ⇒ None");
            assert_eq!(s.ssh_host_key_fps, vec!["SHA256:only".to_string()]);
        }

        #[test]
        fn parse_inspect_vm_carries_passed_mac() {
            // A VM seadog created with --mac: kento reports it back.
            let json = r#"{
                "name": "seadog-bob-proj-cd34",
                "image": "registry/stuff:2",
                "mode": "vm",
                "type": "VM",
                "status": "running",
                "directory": "/d",
                "state_directory": "/d",
                "vmid": 10011,
                "mac": "12:34:56:78:9a:bc",
                "environment": ["SEADOG_OWNER=bob", "SEADOG_GUID=g-bob"],
                "ssh_host_key_fingerprints": {
                    "rsa": "SHA256:r",
                    "ed25519": "SHA256:e"
                }
            }"#;
            let s = parse_kento_inspect(json).unwrap();
            assert_eq!(s.guid.as_deref(), Some("g-bob"));
            assert_eq!(s.owner.as_deref(), Some("bob"));
            assert_eq!(s.mac.as_deref(), Some("12:34:56:78:9a:bc"));
            assert_eq!(s.mode, Mode::Vm);
            assert_eq!(s.vmid, Some(10011));
            assert_eq!(
                s.ssh_host_key_fps,
                vec!["SHA256:e".to_string(), "SHA256:r".to_string()]
            );
        }

        #[test]
        fn parse_inspect_drops_storage_hostile_fingerprint() {
            // A fingerprint value carrying a comma is storage-hostile: fps are
            // persisted comma-delimited (store::join_fps), so it would mis-split
            // on read. The ingest guard DROPS it (non-fatal) and keeps the clean
            // values, sorted. Algorithm-agnostic: only the hostile char matters.
            let json = r#"{
                "name": "seadog-eve-proj-ef56",
                "image": "registry/img:1",
                "mode": "lxc",
                "type": "LXC",
                "status": "running",
                "directory": "/d",
                "state_directory": "/d",
                "environment": ["SEADOG_GUID=g-eve"],
                "ssh_host_key_fingerprints": {
                    "ecdsa": "SHA256:bbb",
                    "ed25519": "SHA256:aaa,bbb",
                    "rsa": "SHA256:ccc"
                }
            }"#;
            let s = parse_kento_inspect(json).unwrap();
            // The comma-bearing value is dropped; the two clean values survive.
            assert_eq!(
                s.ssh_host_key_fps,
                vec!["SHA256:bbb".to_string(), "SHA256:ccc".to_string()],
                "comma-bearing fingerprint dropped; clean values retained and sorted"
            );
        }

        #[test]
        fn parse_inspect_rejects_non_object() {
            assert!(parse_kento_inspect("[]").is_err());
            assert!(parse_kento_inspect("not json").is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_lists_set_instances_and_records_teardowns() {
        let k = FakeKento::new();
        k.set_instances(vec![
            InstanceSignals {
                name: "seadog-a".into(),
                guid: Some("g-a".into()),
                ..Default::default()
            },
            InstanceSignals {
                name: "seadog-b".into(),
                guid: Some("g-b".into()),
                ..Default::default()
            },
        ]);
        // No vmid-range filter: the set list IS the live list.
        let listed = k.list_instances().unwrap();
        assert_eq!(listed.len(), 2);

        k.teardown("seadog-a", Mode::Vm).unwrap();
        assert_eq!(k.teardowns(), vec![("seadog-a".to_string(), Mode::Vm)]);
        // The torn-down instance is gone from a subsequent list.
        let listed = k.list_instances().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "seadog-b");
    }

    fn sample_spec(mode: Mode) -> ProvisionSpec {
        ProvisionSpec {
            mode,
            image_ref: "registry/loom:1".into(),
            name: "seadog-alice-proj-ab12".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ip: "192.168.99.200".into(),
            prefix: 24,
            gateway: "192.168.99.1".into(),
            bridge: "vmbr0".into(),
            guid: "guid-abc".into(),
            owner: "alice".into(),
            ssh_key_file: None,
            ssh_key_user: "root".into(),
            allow_nesting: false,
        }
    }

    #[test]
    fn fake_provision_realizes_classifiable_instance() {
        let k = FakeKento::new();
        let spec = sample_spec(Mode::Lxc);
        let outcome = k.provision(&spec).unwrap();
        assert_eq!(k.provisions(), vec![spec.clone()]);

        // The realized instance carries the injected GUID/owner anchor +
        // host-key fps. This spec is an LXC, so kento reports NO MAC: the
        // live signals and the outcome both carry `None` (the designed
        // LXC sentinel — kento reports a MAC for VM modes only).
        let listed = k.list_instances().unwrap();
        assert_eq!(listed.len(), 1);
        let i = &listed[0];
        assert_eq!(i.name, "seadog-alice-proj-ab12");
        assert_eq!(i.guid.as_deref(), Some("guid-abc"));
        assert_eq!(i.owner.as_deref(), Some("alice"));
        assert_eq!(i.mac, None, "LXC has no kento-reported MAC");
        assert_eq!(i.mac, outcome.mac);
        assert!(!i.ssh_host_key_fps.is_empty());
        assert_eq!(i.ssh_host_key_fps, outcome.ssh_host_key_fps);
        assert_eq!(i.mode, Mode::Lxc, "realized instance carries the spec mode");
        assert_eq!(outcome.vmid, None);

        // Teardown by the realized name removes it.
        k.teardown(&spec.name, Mode::Lxc).unwrap();
        assert!(k.list_instances().unwrap().is_empty());
    }

    #[test]
    fn fake_provision_records_allow_nesting() {
        // The boundary-crossing nesting flag is recorded per provision so a
        // test can assert it reached the spec. Default false; set true here.
        let k = FakeKento::new();
        let mut spec = sample_spec(Mode::Lxc);
        spec.allow_nesting = true;
        k.provision(&spec).unwrap();
        assert_eq!(k.provision_allow_nesting(), vec![true]);
        assert!(k.provisions()[0].allow_nesting);

        // A second, non-nesting provision appends a `false`, in order.
        let plain = sample_spec(Mode::Vm);
        k.provision(&plain).unwrap();
        assert_eq!(k.provision_allow_nesting(), vec![true, false]);
    }

    #[test]
    fn fake_provision_vm_keeps_passed_mac() {
        // VM path: --mac is honored, so the effective MAC is the spec's.
        let k = FakeKento::new();
        let spec = sample_spec(Mode::Vm);
        let outcome = k.provision(&spec).unwrap();
        assert_eq!(outcome.mac.as_deref(), Some(spec.mac.as_str()));
        let listed = k.list_instances().unwrap();
        assert_eq!(listed[0].mac.as_deref(), Some(spec.mac.as_str()));
    }

    #[test]
    fn fake_provision_lxc_reports_no_mac() {
        // kento reports a MAC for VM modes only: an LXC provision yields
        // `None` (the designed sentinel), both in the outcome and on the
        // realized live instance.
        let k = FakeKento::new();
        let lxc = sample_spec(Mode::Lxc);
        let out = k.provision(&lxc).unwrap();
        assert_eq!(out.mac, None, "LXC has no MAC");
        let listed = k.list_instances().unwrap();
        assert_eq!(listed[0].mac, None, "LXC live instance has no MAC");
    }

    #[test]
    fn fake_signals_quorum_loss() {
        let k = FakeKento::new();
        k.set_quorum_lost("no quorum");
        assert!(matches!(k.list_instances(), Err(Error::QuorumLost(_))));
        assert!(matches!(
            k.teardown("seadog-x", Mode::Vm),
            Err(Error::QuorumLost(_))
        ));
    }

    #[test]
    fn fake_teardown_failure_hook() {
        let k = FakeKento::new();
        k.set_instances(vec![InstanceSignals {
            name: "seadog-x".into(),
            guid: Some("g-x".into()),
            ..Default::default()
        }]);
        k.fail_teardown("seadog-x", "boom");
        assert!(matches!(
            k.teardown("seadog-x", Mode::Lxc),
            Err(Error::Kento(_))
        ));
        // The instance is still present (teardown failed).
        assert_eq!(k.list_instances().unwrap().len(), 1);
    }

    #[test]
    fn fake_provision_failure_hook() {
        // The symmetric counterpart to `fake_teardown_failure_hook`: a primed
        // `fail_provision` makes `provision` return Error::Kento (the
        // image-not-found / "kento does NOT auto-pull" class) and records NO
        // provision / realizes NO instance.
        let k = FakeKento::new();
        k.fail_provision("image not found: kento does not auto-pull");
        let spec = sample_spec(Mode::Lxc);
        assert!(matches!(k.provision(&spec), Err(Error::Kento(_))));
        // Nothing was provisioned or realized.
        assert!(k.provisions().is_empty());
        assert!(k.list_instances().unwrap().is_empty());
    }

    #[test]
    fn fake_provision_surfaces_quorum_loss() {
        // A primed quorum-loss surfaces on `provision` too (it is the global
        // condition, checked before the non-quorum failure hook), and as
        // QuorumLost — NOT mis-mapped to Error::Kento.
        let k = FakeKento::new();
        k.set_quorum_lost("no quorum");
        let spec = sample_spec(Mode::Lxc);
        assert!(matches!(k.provision(&spec), Err(Error::QuorumLost(_))));
        assert!(k.provisions().is_empty());
    }
}

// --- argv-builder regression guard ---
//
// REGRESSION GUARD ONLY. These tests pin the EXACT argv seadog emits TODAY,
// sourced directly from the always-compiled `provision_argv`/`teardown_argv`/
// `inspect_argv` builders (NOT from any doc comment — comments in this repo
// have drifted before, notably on `--mac` and the `pve`/`pve-lxc` mode
// strings). They do NOT verify the contract against real kento (e.g. 1.5.1):
// that the flags/positions seadog emits are the ones kento actually accepts is
// a SEPARATE validation against kento's own `--help`/source. Nothing here
// asserts or implies the argv "matches kento" or is "verified against kento" —
// it pins only what seadog emits, so an unintended change to the emitted argv
// trips a test instead of silently shipping.
//
// Always compiled (no `real-kento` gate): the builders are pure and gate-free,
// so this guard runs in the default build even though the spawn path that
// consumes them is feature-gated.
#[cfg(test)]
mod argv_tests {
    use super::*;
    use std::path::PathBuf;

    fn spec(mode: Mode) -> ProvisionSpec {
        ProvisionSpec {
            mode,
            image_ref: "registry.example.com/loom:1.0".into(),
            name: "seadog-alice-proj-ab12".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ip: "192.168.99.200".into(),
            prefix: 24,
            gateway: "192.168.99.1".into(),
            bridge: "vmbr0".into(),
            guid: "guid-abc".into(),
            owner: "alice".into(),
            ssh_key_file: None,
            ssh_key_user: "root".into(),
            allow_nesting: false,
        }
    }

    #[test]
    fn provision_argv_lxc_no_key_no_nesting() {
        // LXC, no ssh key, no nesting: NO `--mac` (VM-only), NO `--ssh-key`
        // block, NO `--allow-nesting`. Image ref is the trailing positional.
        let argv = provision_argv(&spec(Mode::Lxc));
        assert_eq!(
            argv,
            vec![
                "lxc",
                "create",
                "--name",
                "seadog-alice-proj-ab12",
                "--network",
                "bridge=vmbr0",
                "--ip",
                "192.168.99.200/24",
                "--gateway",
                "192.168.99.1",
                "--ssh-host-keys",
                "--start",
                "--env",
                "SEADOG_GUID=guid-abc",
                "--env",
                "SEADOG_OWNER=alice",
                "registry.example.com/loom:1.0",
            ]
        );
    }

    #[test]
    fn provision_argv_vm_no_key_no_nesting() {
        // VM, no ssh key, no nesting: same as LXC but with the VM-only `--mac`
        // block before the image positional.
        let argv = provision_argv(&spec(Mode::Vm));
        assert_eq!(
            argv,
            vec![
                "vm",
                "create",
                "--name",
                "seadog-alice-proj-ab12",
                "--network",
                "bridge=vmbr0",
                "--ip",
                "192.168.99.200/24",
                "--gateway",
                "192.168.99.1",
                "--ssh-host-keys",
                "--start",
                "--env",
                "SEADOG_GUID=guid-abc",
                "--env",
                "SEADOG_OWNER=alice",
                "--mac",
                "aa:bb:cc:dd:ee:ff",
                "registry.example.com/loom:1.0",
            ]
        );
    }

    #[test]
    fn provision_argv_lxc_with_ssh_key() {
        // LXC with an ssh key file: the `--ssh-key <file> --ssh-key-user <user>
        // --config-mode auto` block is inserted (after the envs, before the
        // image positional), still NO `--mac` (LXC).
        let mut s = spec(Mode::Lxc);
        s.ssh_key_file = Some(PathBuf::from("/run/seadog/ownerkey.tmp"));
        let argv = provision_argv(&s);
        assert_eq!(
            argv,
            vec![
                "lxc",
                "create",
                "--name",
                "seadog-alice-proj-ab12",
                "--network",
                "bridge=vmbr0",
                "--ip",
                "192.168.99.200/24",
                "--gateway",
                "192.168.99.1",
                "--ssh-host-keys",
                "--start",
                "--env",
                "SEADOG_GUID=guid-abc",
                "--env",
                "SEADOG_OWNER=alice",
                "--ssh-key",
                "/run/seadog/ownerkey.tmp",
                "--ssh-key-user",
                "root",
                "--config-mode",
                "auto",
                "registry.example.com/loom:1.0",
            ]
        );
    }

    #[test]
    fn provision_argv_vm_with_ssh_key_and_nesting() {
        // VM with both an ssh key and nesting: the `--ssh-key` block, then the
        // VM-only `--mac` block, then `--allow-nesting`, then the image
        // positional — pinning the full ordered interaction of all three.
        let mut s = spec(Mode::Vm);
        s.ssh_key_file = Some(PathBuf::from("/run/seadog/ownerkey.tmp"));
        s.allow_nesting = true;
        let argv = provision_argv(&s);
        assert_eq!(
            argv,
            vec![
                "vm",
                "create",
                "--name",
                "seadog-alice-proj-ab12",
                "--network",
                "bridge=vmbr0",
                "--ip",
                "192.168.99.200/24",
                "--gateway",
                "192.168.99.1",
                "--ssh-host-keys",
                "--start",
                "--env",
                "SEADOG_GUID=guid-abc",
                "--env",
                "SEADOG_OWNER=alice",
                "--ssh-key",
                "/run/seadog/ownerkey.tmp",
                "--ssh-key-user",
                "root",
                "--config-mode",
                "auto",
                "--mac",
                "aa:bb:cc:dd:ee:ff",
                "--allow-nesting",
                "registry.example.com/loom:1.0",
            ]
        );
    }

    #[test]
    fn provision_argv_lxc_with_nesting_has_no_mac() {
        // LXC with nesting: `--allow-nesting` is pushed (mode-agnostic) but
        // still NO `--mac` (the VM-only block) — guards the two flags don't
        // get conflated.
        let mut s = spec(Mode::Lxc);
        s.allow_nesting = true;
        let argv = provision_argv(&s);
        assert!(
            argv.iter().any(|a| a == "--allow-nesting"),
            "lxc nesting emits --allow-nesting"
        );
        assert!(!argv.iter().any(|a| a == "--mac"), "lxc never emits --mac");
        assert_eq!(
            argv.last().map(String::as_str),
            Some("registry.example.com/loom:1.0"),
            "image ref stays the trailing positional"
        );
    }

    #[test]
    fn teardown_argv_lxc_and_vm() {
        assert_eq!(
            teardown_argv("seadog-alice-proj-ab12", Mode::Lxc),
            vec!["lxc", "destroy", "-f", "seadog-alice-proj-ab12"]
        );
        assert_eq!(
            teardown_argv("seadog-bob-proj-cd34", Mode::Vm),
            vec!["vm", "destroy", "-f", "seadog-bob-proj-cd34"]
        );
    }

    #[test]
    fn inspect_argv_pins_json_form() {
        assert_eq!(
            inspect_argv("seadog-alice-proj-ab12"),
            vec!["inspect", "seadog-alice-proj-ab12", "--json"]
        );
    }

    #[test]
    fn list_json_argv_pins_json_form() {
        assert_eq!(list_json_argv(), vec!["list", "--json"]);
    }
}
