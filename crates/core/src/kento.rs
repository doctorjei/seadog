//! The runtime bridge between seadog's logic and the live PVE node.
//!
//! [`Kento`] abstracts every operation the reaper/provisioner needs from
//! `qm`/`pct`/`kento` so the business logic can be exercised against an
//! in-memory [`FakeKento`] with **no real PVE host** in the loop. The
//! shelling-out implementation, [`RealKento`], lives behind the
//! `real-kento` cargo feature so the library builds and tests with zero
//! external tools by default.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::identity::{GuestSignals, GUID_MARKER_PREFIX, OWNER_MARKER_PREFIX};
use crate::models::Mode;
use crate::Error;

/// Operations seadog needs from the PVE node.
///
/// Only [`Kento::list_guests`] and [`Kento::teardown`] carry real
/// behavior in this phase; the provisioning methods are declared with
/// minimal signatures for later phases to implement. Implementors must
/// surface a quorum-loss / pmxcfs-read-only condition as
/// [`Error::QuorumLost`] so the reaper can stop cleanly instead of
/// spinning.
pub trait Kento {
    /// Enumerate every guest whose vmid falls in the inclusive
    /// `vmid_range`, returning the signals the sweeper observes.
    fn list_guests(&self, vmid_range: (u32, u32)) -> Result<Vec<GuestSignals>, Error>;

    /// Destroy the guest at `vmid` (LXC via `pct`, VM via `qm`).
    fn teardown(&self, vmid: u32, mode: Mode) -> Result<(), Error>;

    /// Create a new guest from a fully-resolved [`ProvisionSpec`] and write
    /// the seadog guest-side markers (the `seadog-` name, the
    /// `seadog-guid:`/`seadog-owner:` description marker block, and the
    /// assigned MAC) so a later teardown can triangulate it against live
    /// PVE. The caller (`seadog-priv provision`) has already re-validated
    /// every field; this method only realizes the guest.
    fn provision(&self, spec: &ProvisionSpec) -> Result<(), Error>;

    /// Narrow metadata update on an **already-verified** seadog guest:
    /// optionally set the description and/or the TTL-deadline marker. The
    /// caller validates the target is in-range + seadog-marked first; this
    /// is `qm set`/`pct set`, never a general passthrough.
    fn set_meta(&self, vmid: u32, mode: Mode, meta: &MetaUpdate) -> Result<(), Error>;

    /// Start the in-guest sshd inside an **already-verified** seadog CT
    /// (loom ships sshd disabled). LXC-only — the caller validates the
    /// target is an in-range, seadog-marked container first. This is a
    /// narrow `pct exec … systemctl start ssh`, not a general
    /// `pct exec` passthrough.
    fn start_sshd(&self, vmid: u32) -> Result<(), Error>;
}

/// A fully-resolved provisioning request: every field has already been
/// re-validated by `seadog-priv` against its own config load. The MAC,
/// IP, vmid, name and GUID were allocated by the (untrusted) front-end but
/// re-checked here; `image_ref` is the allowlisted ref the server picked,
/// never a raw caller ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionSpec {
    /// Allocated Proxmox guest id (re-validated in-range).
    pub vmid: u32,
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
    /// Instance GUID minted by the front-end (written into the desc marker).
    pub guid: String,
    /// Resolved owner (trusted from the front-end; written into the desc
    /// marker so teardown can verify ownership against live PVE).
    pub owner: String,
}

impl ProvisionSpec {
    /// The guest `description` body seadog writes at create: the GUID and
    /// owner marker lines [`crate::identity`] greps back out. Kept here so
    /// `FakeKento` (markers in-memory) and `RealKento` (markers via
    /// `qm`/`pct set --description`) build an identical block.
    pub fn description_marker(&self) -> String {
        format!(
            "{GUID_MARKER_PREFIX}{guid}\n{OWNER_MARKER_PREFIX}{owner}",
            guid = self.guid,
            owner = self.owner,
        )
    }
}

/// A narrow metadata update for [`Kento::set_meta`]: any combination of a
/// new description and/or a TTL-deadline (unix epoch seconds). Both are
/// optional so a caller can touch just one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetaUpdate {
    /// Replacement description body, if updating it.
    pub description: Option<String>,
    /// TTL-deadline as a unix epoch second, if updating it.
    pub ttl_deadline: Option<i64>,
}

/// In-memory [`Kento`] for tests. Always compiled (not `#[cfg(test)]`) so
/// later integration tests in sibling crates can drive it too.
///
/// Tests populate [`FakeKento::guests`], then assert on
/// [`FakeKento::teardowns`] to see exactly what got reaped. Priming
/// [`FakeKento::quorum_lost`] makes both `list_guests` and `teardown`
/// return [`Error::QuorumLost`], so the reaper's stop-on-quorum-loss path
/// is testable without a cluster.
#[derive(Default)]
pub struct FakeKento {
    inner: Mutex<FakeState>,
}

#[derive(Default)]
struct FakeState {
    guests: Vec<GuestSignals>,
    teardowns: Vec<(u32, Mode)>,
    /// Provision calls recorded so tests can assert exact params.
    provisions: Vec<ProvisionSpec>,
    /// `set_meta` calls recorded, in order.
    set_metas: Vec<(u32, Mode, MetaUpdate)>,
    /// vmids `start_sshd` was called on, in order.
    sshd_starts: Vec<u32>,
    /// When set, every op returns this quorum-loss message.
    quorum_lost: Option<String>,
    /// Optional per-vmid teardown failures (non-quorum), to test errors.
    teardown_fail: HashMap<u32, String>,
}

impl FakeKento {
    /// A fresh fake with no guests.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the live guest list the sweeper will observe.
    pub fn set_guests(&self, guests: Vec<GuestSignals>) {
        self.inner.lock().unwrap().guests = guests;
    }

    /// Prime a quorum-loss condition: every subsequent op fails with
    /// [`Error::QuorumLost`].
    pub fn set_quorum_lost(&self, msg: impl Into<String>) {
        self.inner.lock().unwrap().quorum_lost = Some(msg.into());
    }

    /// Make `teardown(vmid, _)` fail with a non-quorum error.
    pub fn fail_teardown(&self, vmid: u32, msg: impl Into<String>) {
        self.inner
            .lock()
            .unwrap()
            .teardown_fail
            .insert(vmid, msg.into());
    }

    /// The teardown calls recorded so far, in order.
    pub fn teardowns(&self) -> Vec<(u32, Mode)> {
        self.inner.lock().unwrap().teardowns.clone()
    }

    /// The provision calls recorded so far, in order.
    pub fn provisions(&self) -> Vec<ProvisionSpec> {
        self.inner.lock().unwrap().provisions.clone()
    }

    /// The `set_meta` calls recorded so far, in order.
    pub fn set_metas(&self) -> Vec<(u32, Mode, MetaUpdate)> {
        self.inner.lock().unwrap().set_metas.clone()
    }

    /// The vmids `start_sshd` was called on, in order.
    pub fn sshd_starts(&self) -> Vec<u32> {
        self.inner.lock().unwrap().sshd_starts.clone()
    }
}

impl Kento for FakeKento {
    fn list_guests(&self, vmid_range: (u32, u32)) -> Result<Vec<GuestSignals>, Error> {
        let st = self.inner.lock().unwrap();
        if let Some(msg) = &st.quorum_lost {
            return Err(Error::QuorumLost(msg.clone()));
        }
        let (lo, hi) = vmid_range;
        Ok(st
            .guests
            .iter()
            .filter(|g| g.vmid >= lo && g.vmid <= hi)
            .cloned()
            .collect())
    }

    fn teardown(&self, vmid: u32, mode: Mode) -> Result<(), Error> {
        let mut st = self.inner.lock().unwrap();
        if let Some(msg) = &st.quorum_lost {
            return Err(Error::QuorumLost(msg.clone()));
        }
        if let Some(msg) = st.teardown_fail.get(&vmid).cloned() {
            return Err(Error::Kento(msg));
        }
        st.teardowns.push((vmid, mode));
        // Remove the guest so a subsequent list_guests reflects the destroy.
        st.guests.retain(|g| g.vmid != vmid);
        Ok(())
    }

    fn provision(&self, spec: &ProvisionSpec) -> Result<(), Error> {
        let mut st = self.inner.lock().unwrap();
        if let Some(msg) = &st.quorum_lost {
            return Err(Error::QuorumLost(msg.clone()));
        }
        // Realize the guest in-memory WITH the markers, so a later
        // teardown can triangulate it exactly as live PVE would present it.
        st.guests.push(GuestSignals {
            vmid: spec.vmid,
            name: Some(spec.name.clone()),
            description: Some(spec.description_marker()),
            mac: Some(spec.mac.clone()),
            fingerprint: Default::default(),
        });
        st.provisions.push(spec.clone());
        Ok(())
    }

    fn set_meta(&self, vmid: u32, mode: Mode, meta: &MetaUpdate) -> Result<(), Error> {
        let mut st = self.inner.lock().unwrap();
        if let Some(msg) = &st.quorum_lost {
            return Err(Error::QuorumLost(msg.clone()));
        }
        st.set_metas.push((vmid, mode, meta.clone()));
        Ok(())
    }

    fn start_sshd(&self, vmid: u32) -> Result<(), Error> {
        let mut st = self.inner.lock().unwrap();
        if let Some(msg) = &st.quorum_lost {
            return Err(Error::QuorumLost(msg.clone()));
        }
        st.sshd_starts.push(vmid);
        Ok(())
    }
}

// --- RealKento: behind the `real-kento` feature so the lib builds with
//     zero external tools by default. Not exercised by tests (no real PVE host),
//     but it MUST compile under `--features real-kento`. ---
#[cfg(feature = "real-kento")]
pub use real::RealKento;

#[cfg(feature = "real-kento")]
mod real {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use wait_timeout::ChildExt;

    use super::*;
    use crate::identity::Fingerprint;

    /// Per-op hard timeout. `qm`/`pct` are Perl and can wedge on a sick
    /// cluster; we kill on expiry rather than block the sweep forever.
    const OP_TIMEOUT: Duration = Duration::from_secs(30);

    /// Fixed PATH set before exec. `qm`/`pct` honor `PATH`/`PERL5LIB`, so
    /// we `env_clear()` and pin a known-good search path to avoid
    /// hijacking via the ambient environment.
    const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

    /// Substrings that mark a pmxcfs quorum-loss / read-only condition.
    const QUORUM_MARKERS: &[&str] = &[
        "no quorum",
        "cluster not ready",
        "Read-only file system",
        "permission denied - not part of cluster",
    ];

    /// The shelling-out [`Kento`]: runs `qm`/`pct`/`kento` as argv
    /// vectors (never a shell string), with a cleared environment, a
    /// pinned PATH, and a per-op hard timeout.
    #[derive(Debug, Default)]
    pub struct RealKento;

    impl RealKento {
        /// Construct a `RealKento`.
        pub fn new() -> Self {
            RealKento
        }

        /// Run `program argv…` to completion under the safety harness,
        /// returning stdout. Maps a quorum-loss signature to
        /// [`Error::QuorumLost`] and a timeout to [`Error::Kento`].
        fn run(&self, program: &str, argv: &[&str]) -> Result<String, Error> {
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
        fn list_guests(&self, vmid_range: (u32, u32)) -> Result<Vec<GuestSignals>, Error> {
            // Strategy (proven against the fake-PVE harness):
            //   1. `pvesh get /cluster/resources --output-format json` gives
            //      the authoritative vmid + type (qemu|lxc) list for the
            //      whole cluster. A quorum-loss surfaces here.
            //   2. For each in-range guest, read its full config via
            //      `qm config <vmid>` (VM) / `pct config <vmid>` (LXC) and
            //      parse it into the `GuestSignals` the sweeper triangulates
            //      on (name, description marker block, net0 MAC, fingerprint
            //      hardware fields).
            // The parsing is split into pure functions
            // (`parse_resources` / `parse_guest_config`) so it is unit-tested
            // on sample strings with no real command in the loop.
            let resources_json = self.run(
                "pvesh",
                &["get", "/cluster/resources", "--output-format", "json"],
            )?;
            let (lo, hi) = vmid_range;
            let entries = parse_resources(&resources_json)
                .map_err(|e| Error::Kento(format!("parsing /cluster/resources: {e}")))?;

            let mut out = Vec::new();
            for entry in entries {
                if entry.vmid < lo || entry.vmid > hi {
                    continue;
                }
                let vmid_s = entry.vmid.to_string();
                let config_text = match entry.mode {
                    Mode::Lxc => self.run("pct", &["config", &vmid_s])?,
                    Mode::Vm => self.run("qm", &["config", &vmid_s])?,
                };
                let signals = parse_guest_config(entry.vmid, &config_text);
                out.push(signals);
            }
            Ok(out)
        }

        fn teardown(&self, vmid: u32, mode: Mode) -> Result<(), Error> {
            let vmid = vmid.to_string();
            match mode {
                Mode::Lxc => self.run("pct", &["destroy", &vmid, "--purge"]).map(|_| ()),
                Mode::Vm => self.run("qm", &["destroy", &vmid, "--purge"]).map(|_| ()),
            }
        }

        fn provision(&self, spec: &ProvisionSpec) -> Result<(), Error> {
            // Realize the guest via `kento`, then stamp the seadog markers
            // onto it with `qm`/`pct set` so teardown can later triangulate.
            // Full templating lands in a later phase; here we only need the
            // safety-wrapped exec path to compile under `--features
            // real-kento`. Not exercised by tests (no real PVE host).
            let vmid = spec.vmid.to_string();
            let mode = match spec.mode {
                Mode::Lxc => "lxc",
                Mode::Vm => "vm",
            };
            self.run(
                "kento",
                &[
                    "create",
                    "--vmid",
                    &vmid,
                    "--mode",
                    mode,
                    "--image-ref",
                    &spec.image_ref,
                    "--name",
                    &spec.name,
                    "--mac",
                    &spec.mac,
                    "--ip",
                    &spec.ip,
                ],
            )?;
            let desc = spec.description_marker();
            match spec.mode {
                Mode::Lxc => self.run(
                    "pct",
                    &[
                        "set",
                        &vmid,
                        "--hostname",
                        &spec.name,
                        "--description",
                        &desc,
                    ],
                )?,
                Mode::Vm => self.run(
                    "qm",
                    &["set", &vmid, "--name", &spec.name, "--description", &desc],
                )?,
            };
            Ok(())
        }

        fn set_meta(&self, vmid: u32, mode: Mode, meta: &MetaUpdate) -> Result<(), Error> {
            let vmid = vmid.to_string();
            let mut args: Vec<String> = vec!["set".to_string(), vmid];
            if let Some(desc) = &meta.description {
                args.push("--description".to_string());
                args.push(desc.clone());
            }
            if let Some(ttl) = meta.ttl_deadline {
                // Carried in a tag so it survives PVE round-tripping.
                args.push("--tags".to_string());
                args.push(format!("seadog-ttl-{ttl}"));
            }
            if args.len() == 2 {
                // Nothing to set.
                return Ok(());
            }
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            match mode {
                Mode::Lxc => self.run("pct", &argv).map(|_| ()),
                Mode::Vm => self.run("qm", &argv).map(|_| ()),
            }
        }

        fn start_sshd(&self, vmid: u32) -> Result<(), Error> {
            let vmid = vmid.to_string();
            // Narrow exec: start the in-CT sshd only. LXC-only by contract.
            self.run("pct", &["exec", &vmid, "--", "systemctl", "start", "ssh"])
                .map(|_| ())
        }
    }

    // --- Pure parsers (no exec): unit-testable on sample strings. ---

    /// One in-range guest the resource enumeration found: its vmid and
    /// whether it is a VM (`qemu`) or a container (`lxc`), which selects
    /// `qm config` vs `pct config` for the per-guest read.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ResourceEntry {
        /// Proxmox guest id.
        pub vmid: u32,
        /// LXC or VM, mapped from the resource `type` field.
        pub mode: Mode,
    }

    /// Parse the JSON `pvesh get /cluster/resources --output-format json`
    /// emits into the (vmid, mode) list seadog needs. Only `type` ∈
    /// {`qemu`, `lxc`} rows that carry a `vmid` are kept; storage/node rows
    /// and any other type are skipped. Robust to extra fields PVE adds.
    pub fn parse_resources(json: &str) -> Result<Vec<ResourceEntry>, String> {
        let value: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let arr = value
            .as_array()
            .ok_or_else(|| "expected a top-level JSON array".to_string())?;
        let mut out = Vec::new();
        for item in arr {
            let ty = match item.get("type").and_then(|v| v.as_str()) {
                Some(t) => t,
                None => continue,
            };
            let mode = match ty {
                "qemu" => Mode::Vm,
                "lxc" => Mode::Lxc,
                // node / storage / sdn / pool rows have no vmid we care about.
                _ => continue,
            };
            // `vmid` is a number in the API output.
            let vmid = match item.get("vmid").and_then(|v| v.as_u64()) {
                Some(n) => n as u32,
                None => continue,
            };
            out.push(ResourceEntry { vmid, mode });
        }
        Ok(out)
    }

    /// Parse the `key: value` text `qm config <vmid>` / `pct config <vmid>`
    /// emit into [`GuestSignals`]. The two tools share enough of this format
    /// that one parser handles both:
    ///
    /// - **name**: `name:` (VM) or `hostname:` (CT).
    /// - **description**: `description:` — PVE URL-encodes newlines as `%0A`
    ///   when set via `--description`, so we percent-decode it back so the
    ///   `seadog-guid:`/`seadog-owner:` marker lines re-appear on their own
    ///   lines for [`crate::identity::extract_desc_guid`] etc.
    /// - **mac**: from `net0:` — the `hwaddr=<mac>` (CT) or the
    ///   `<model>=<mac>` leading token (VM).
    /// - **fingerprint**: bridge/vlan/model from `net0:`; disk geometry+size
    ///   from `scsi0:`/`rootfs:`; machine/bios/scsihw/memory/cores from their
    ///   own keys. Absent fields stay `None` (never read as a match).
    pub fn parse_guest_config(vmid: u32, text: &str) -> GuestSignals {
        let mut name = None;
        let mut hostname = None;
        let mut description = None;
        let mut net0 = None;
        let mut scsi0 = None;
        let mut rootfs = None;
        let mut fp = Fingerprint::default();

        for line in text.lines() {
            let line = line.trim_end();
            let (key, val) = match line.split_once(':') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => continue,
            };
            match key {
                "name" => name = nonempty(val),
                "hostname" => hostname = nonempty(val),
                "description" => description = nonempty(val).map(|v| pve_unescape(&v)),
                "net0" => net0 = nonempty(val),
                "scsi0" | "virtio0" | "sata0" | "ide0" => {
                    if scsi0.is_none() {
                        scsi0 = nonempty(val);
                    }
                }
                "rootfs" => rootfs = nonempty(val),
                "machine" => fp.machine_type = nonempty(val),
                "bios" => fp.bios = nonempty(val),
                "scsihw" => fp.scsihw = nonempty(val),
                "memory" => fp.memory = val.trim().parse::<u64>().ok(),
                "cores" => fp.cores = val.trim().parse::<u32>().ok(),
                _ => {}
            }
        }

        // Fill the network fingerprint + MAC from net0.
        let mut mac = None;
        if let Some(n) = &net0 {
            let parsed = parse_net0(n);
            mac = parsed.mac;
            fp.net_bridge = parsed.bridge;
            fp.net_vlan = parsed.vlan;
            fp.net_model = parsed.model;
        }

        // Disk geometry + size from the first disk-ish key we saw (VM) or
        // the rootfs (CT).
        if let Some(disk) = scsi0.as_ref().or(rootfs.as_ref()) {
            let parsed = parse_disk(disk);
            fp.disk_geometry = parsed.geometry;
            fp.disk_size = parsed.size_bytes;
        }

        GuestSignals {
            vmid,
            name: name.or(hostname),
            description,
            mac,
            fingerprint: fp,
        }
    }

    /// `Some(trimmed)` unless the value is empty.
    fn nonempty(v: &str) -> Option<String> {
        let v = v.trim();
        if v.is_empty() {
            None
        } else {
            Some(v.to_string())
        }
    }

    /// Decode the small set of percent-escapes PVE applies to a
    /// `--description` body (notably `%0A` for newline) so the marker lines
    /// split back out. Unknown/short escapes are left verbatim.
    fn pve_unescape(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hex = &s[i + 1..i + 3];
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// The pieces we pull out of a `net0:` line.
    struct Net0 {
        mac: Option<String>,
        bridge: Option<String>,
        vlan: Option<u32>,
        model: Option<String>,
    }

    /// Parse a PVE `net0:` value. Two shapes:
    /// - VM: `virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=10`
    /// - CT: `name=eth0,bridge=vmbr0,hwaddr=AA:BB:..,ip=...,tag=10,type=veth`
    fn parse_net0(val: &str) -> Net0 {
        let mut mac = None;
        let mut bridge = None;
        let mut vlan = None;
        let mut model = None;
        for part in val.split(',') {
            let part = part.trim();
            let (k, v) = match part.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => continue,
            };
            match k {
                "bridge" => bridge = nonempty(v),
                "tag" => vlan = v.parse::<u32>().ok(),
                "hwaddr" => mac = normalize_mac(v),
                // VM model token: `<model>=<mac>` (e.g. `virtio=AA:..`).
                "virtio" | "e1000" | "rtl8139" | "vmxnet3" | "i82551" | "i82557b" => {
                    model = nonempty(k);
                    if mac.is_none() {
                        mac = normalize_mac(v);
                    }
                }
                // CT NIC model is the `type=` (veth); record it as the model
                // only if we have not already learned a VM model token.
                "type" if model.is_none() => model = nonempty(v),
                _ => {}
            }
        }
        Net0 {
            mac,
            bridge,
            vlan,
            model,
        }
    }

    /// Lowercase a MAC if it looks like one, else `None`.
    fn normalize_mac(v: &str) -> Option<String> {
        let v = v.trim();
        if v.split(':').count() == 6 && v.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            Some(v.to_ascii_lowercase())
        } else {
            None
        }
    }

    /// What we read off a disk line.
    struct Disk {
        geometry: Option<String>,
        size_bytes: Option<u64>,
    }

    /// Parse a disk line like
    /// `local-lvm:vm-10010-disk-0,size=20G` (VM) or
    /// `local:10010/vm-10010-disk-0.raw,size=8G` (CT rootfs). The volume id
    /// (the first comma-field) is the geometry signature; `size=` is decoded
    /// to bytes.
    fn parse_disk(val: &str) -> Disk {
        let mut geometry = None;
        let mut size_bytes = None;
        for (i, part) in val.split(',').enumerate() {
            let part = part.trim();
            if i == 0 {
                geometry = nonempty(part);
                continue;
            }
            if let Some(sz) = part.strip_prefix("size=") {
                size_bytes = parse_size(sz);
            }
        }
        Disk {
            geometry,
            size_bytes,
        }
    }

    /// Decode a PVE size string (`512`, `8G`, `20480M`, `1T`, `100K`) to
    /// bytes. A bare number is bytes.
    fn parse_size(s: &str) -> Option<u64> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (num, mult): (&str, u64) = match s.chars().last() {
            Some('K') | Some('k') => (&s[..s.len() - 1], 1024),
            Some('M') | Some('m') => (&s[..s.len() - 1], 1024 * 1024),
            Some('G') | Some('g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
            Some('T') | Some('t') => (&s[..s.len() - 1], 1024 * 1024 * 1024 * 1024),
            _ => (s, 1),
        };
        num.trim().parse::<u64>().ok().map(|n| n * mult)
    }

    #[cfg(test)]
    mod parser_tests {
        use super::*;
        use crate::identity::{extract_desc_guid, extract_desc_owner};

        #[test]
        fn parse_resources_keeps_guests_skips_other_rows() {
            let json = r#"[
                {"type":"node","node":"pve","status":"online"},
                {"type":"storage","storage":"local","node":"pve"},
                {"type":"qemu","vmid":10010,"node":"pve","name":"seadog-a"},
                {"type":"lxc","vmid":10011,"node":"pve","name":"seadog-b"},
                {"type":"qemu","vmid":105,"node":"pve","name":"prod"},
                {"type":"pool","pool":"p"}
            ]"#;
            let entries = parse_resources(json).unwrap();
            assert_eq!(
                entries,
                vec![
                    ResourceEntry {
                        vmid: 10010,
                        mode: Mode::Vm
                    },
                    ResourceEntry {
                        vmid: 10011,
                        mode: Mode::Lxc
                    },
                    ResourceEntry {
                        vmid: 105,
                        mode: Mode::Vm
                    },
                ]
            );
        }

        #[test]
        fn parse_resources_rejects_non_array() {
            assert!(parse_resources("{}").is_err());
            assert!(parse_resources("not json").is_err());
        }

        #[test]
        fn parse_vm_config_populates_signals_and_fingerprint() {
            // A `qm config` dump, with the description percent-encoded the way
            // PVE round-trips a `--description` set with embedded newlines.
            let text = "\
boot: order=scsi0
cores: 2
description: seadog-guid%3Aguid-abc%0Aseadog-owner%3Aalice
machine: q35
memory: 2048
name: seadog-alice-proj-ab12
net0: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,tag=10
scsihw: virtio-scsi-pci
bios: seabios
scsi0: local-lvm:vm-10010-disk-0,size=20G
smbios1: uuid=...
";
            let g = parse_guest_config(10010, text);
            assert_eq!(g.vmid, 10010);
            assert_eq!(g.name.as_deref(), Some("seadog-alice-proj-ab12"));
            assert_eq!(g.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
            // Description decoded so the markers triangulate.
            assert_eq!(
                extract_desc_guid(g.description.as_deref()).as_deref(),
                Some("guid-abc")
            );
            assert_eq!(
                extract_desc_owner(g.description.as_deref()).as_deref(),
                Some("alice")
            );
            // Fingerprint fields.
            assert_eq!(g.fingerprint.net_bridge.as_deref(), Some("vmbr0"));
            assert_eq!(g.fingerprint.net_vlan, Some(10));
            assert_eq!(g.fingerprint.net_model.as_deref(), Some("virtio"));
            assert_eq!(g.fingerprint.machine_type.as_deref(), Some("q35"));
            assert_eq!(g.fingerprint.bios.as_deref(), Some("seabios"));
            assert_eq!(g.fingerprint.scsihw.as_deref(), Some("virtio-scsi-pci"));
            assert_eq!(g.fingerprint.memory, Some(2048));
            assert_eq!(g.fingerprint.cores, Some(2));
            assert_eq!(
                g.fingerprint.disk_geometry.as_deref(),
                Some("local-lvm:vm-10010-disk-0")
            );
            assert_eq!(g.fingerprint.disk_size, Some(20 * 1024 * 1024 * 1024));
        }

        #[test]
        fn parse_ct_config_uses_hostname_and_hwaddr() {
            // A `pct config` dump: hostname (not name), net0 with hwaddr,
            // rootfs (not scsi0).
            let text = "\
arch: amd64
cores: 2
description: seadog-guid%3Ag-ct%0Aseadog-owner%3Aalice
hostname: seadog-alice-proj-cd34
memory: 1024
net0: name=eth0,bridge=vmbr0,hwaddr=12:34:56:78:9A:BC,ip=dhcp,tag=20,type=veth
rootfs: local:10011/vm-10011-disk-0.raw,size=8G
";
            let g = parse_guest_config(10011, text);
            assert_eq!(g.name.as_deref(), Some("seadog-alice-proj-cd34"));
            assert_eq!(g.mac.as_deref(), Some("12:34:56:78:9a:bc"));
            assert_eq!(
                extract_desc_owner(g.description.as_deref()).as_deref(),
                Some("alice")
            );
            assert_eq!(g.fingerprint.net_bridge.as_deref(), Some("vmbr0"));
            assert_eq!(g.fingerprint.net_vlan, Some(20));
            assert_eq!(g.fingerprint.memory, Some(1024));
            assert_eq!(
                g.fingerprint.disk_geometry.as_deref(),
                Some("local:10011/vm-10011-disk-0.raw")
            );
            assert_eq!(g.fingerprint.disk_size, Some(8 * 1024 * 1024 * 1024));
        }

        #[test]
        fn parse_config_absent_fields_stay_none() {
            // A bare config with no markers, no net, no disk: everything
            // optional must be None so absence never reads as a match.
            let text = "cores: 1\nmemory: 512\n";
            let g = parse_guest_config(10010, text);
            assert_eq!(g.name, None);
            assert_eq!(g.description, None);
            assert_eq!(g.mac, None);
            assert_eq!(g.fingerprint.net_bridge, None);
            assert_eq!(g.fingerprint.disk_size, None);
            assert_eq!(g.fingerprint.memory, Some(512));
            assert_eq!(g.fingerprint.cores, Some(1));
        }

        #[test]
        fn parse_size_handles_units_and_bytes() {
            assert_eq!(parse_size("512"), Some(512));
            assert_eq!(parse_size("8G"), Some(8 * 1024 * 1024 * 1024));
            assert_eq!(parse_size("20480M"), Some(20480 * 1024 * 1024));
            assert_eq!(parse_size("1T"), Some(1024u64.pow(4)));
            assert_eq!(parse_size(""), None);
            assert_eq!(parse_size("notasize"), None);
        }

        #[test]
        fn unparseable_description_without_markers_is_kept_verbatim() {
            let text = "description: just a plain note\nname: seadog-x\n";
            let g = parse_guest_config(10010, text);
            assert_eq!(g.description.as_deref(), Some("just a plain note"));
            assert_eq!(extract_desc_guid(g.description.as_deref()), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_filters_by_range_and_records_teardowns() {
        let k = FakeKento::new();
        k.set_guests(vec![
            GuestSignals {
                vmid: 9999,
                ..Default::default()
            },
            GuestSignals {
                vmid: 10010,
                ..Default::default()
            },
            GuestSignals {
                vmid: 11000,
                ..Default::default()
            },
        ]);
        let listed = k.list_guests((10000, 10999)).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].vmid, 10010);

        k.teardown(10010, Mode::Vm).unwrap();
        assert_eq!(k.teardowns(), vec![(10010, Mode::Vm)]);
    }

    #[test]
    fn fake_provision_realizes_triangulatable_guest() {
        use crate::identity::{extract_desc_guid, extract_desc_owner};
        let k = FakeKento::new();
        let spec = ProvisionSpec {
            vmid: 10010,
            mode: Mode::Lxc,
            image_ref: "registry/loom:1".into(),
            name: "seadog-alice-proj-ab12".into(),
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ip: "192.168.99.200".into(),
            guid: "guid-abc".into(),
            owner: "alice".into(),
        };
        k.provision(&spec).unwrap();
        assert_eq!(k.provisions(), vec![spec.clone()]);

        // The realized guest carries every marker teardown triangulates on.
        let listed = k.list_guests((10000, 10999)).unwrap();
        assert_eq!(listed.len(), 1);
        let g = &listed[0];
        assert_eq!(g.name.as_deref(), Some("seadog-alice-proj-ab12"));
        assert_eq!(g.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(
            extract_desc_guid(g.description.as_deref()),
            Some("guid-abc".into())
        );
        assert_eq!(
            extract_desc_owner(g.description.as_deref()),
            Some("alice".into())
        );
    }

    #[test]
    fn fake_records_set_meta_and_sshd() {
        let k = FakeKento::new();
        let meta = MetaUpdate {
            description: Some("d".into()),
            ttl_deadline: Some(5000),
        };
        k.set_meta(10010, Mode::Vm, &meta).unwrap();
        k.start_sshd(10010).unwrap();
        assert_eq!(k.set_metas(), vec![(10010, Mode::Vm, meta)]);
        assert_eq!(k.sshd_starts(), vec![10010]);
    }

    #[test]
    fn fake_signals_quorum_loss() {
        let k = FakeKento::new();
        k.set_quorum_lost("no quorum");
        assert!(matches!(
            k.list_guests((10000, 10999)),
            Err(Error::QuorumLost(_))
        ));
        assert!(matches!(
            k.teardown(10010, Mode::Vm),
            Err(Error::QuorumLost(_))
        ));
    }
}
