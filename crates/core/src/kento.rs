//! The runtime bridge between seadog's logic and the live PVE node.
//!
//! [`Kento`] abstracts every operation the reaper/provisioner needs from
//! `qm`/`pct`/`kento` so the business logic can be exercised against an
//! in-memory [`FakeKento`] with **no real blue** in the loop. The
//! shelling-out implementation, [`RealKento`], lives behind the
//! `real-kento` cargo feature so the library builds and tests with zero
//! external tools by default.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::identity::GuestSignals;
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

    /// Provision a new guest. Implemented in a later phase.
    fn provision(&self, _spec: &ProvisionSpec) -> Result<(), Error> {
        Err(Error::Kento(
            "provision not implemented in this phase".into(),
        ))
    }

    /// Write seadog metadata (name/description GUID marker) onto a guest.
    /// Implemented in a later phase.
    fn set_meta(&self, _vmid: u32, _name: &str, _description: &str) -> Result<(), Error> {
        Err(Error::Kento(
            "set_meta not implemented in this phase".into(),
        ))
    }

    /// Start the in-guest sshd. Implemented in a later phase.
    fn start_sshd(&self, _vmid: u32, _mode: Mode) -> Result<(), Error> {
        Err(Error::Kento(
            "start_sshd not implemented in this phase".into(),
        ))
    }
}

/// Minimal provisioning request shape (filled out in a later phase).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionSpec {
    pub vmid: u32,
    pub mode: Mode,
    pub image_ref: String,
    pub name: String,
    pub mac: String,
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
        Ok(())
    }
}

// --- RealKento: behind the `real-kento` feature so the lib builds with
//     zero external tools by default. Not exercised by tests (no blue),
//     but it MUST compile under `--features real-kento`. ---
#[cfg(feature = "real-kento")]
pub use real::RealKento;

#[cfg(feature = "real-kento")]
mod real {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use wait_timeout::ChildExt;

    use super::*;

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
        fn list_guests(&self, _vmid_range: (u32, u32)) -> Result<Vec<GuestSignals>, Error> {
            // Full enumeration + parsing lands in a later phase; here we
            // only need the safety-wrapped exec path to compile. Probe
            // the cluster so a quorum-loss surfaces.
            let _ = self.run(
                "pvesh",
                &["get", "/cluster/resources", "--output-format", "json"],
            )?;
            Ok(Vec::new())
        }

        fn teardown(&self, vmid: u32, mode: Mode) -> Result<(), Error> {
            let vmid = vmid.to_string();
            match mode {
                Mode::Lxc => self.run("pct", &["destroy", &vmid, "--purge"]).map(|_| ()),
                Mode::Vm => self.run("qm", &["destroy", &vmid, "--purge"]).map(|_| ()),
            }
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
