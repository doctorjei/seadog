//! The root-privilege **bridge seam**.
//!
//! Root operations (`create`/`destroy` → PVE `qm`/`pct` via kento) cannot
//! run from this unprivileged binary. They are reached by shelling
//! `sudo /usr/lib/seadog/seadog-priv <verb> ...` — but the *front-end*
//! only ever calls [`elevate`], so the elevation primitive stays swappable
//! (real sudo in prod, a fake in tests). This file is the only place that
//! knows how elevation happens.
//!
//! **Phase 2b status:** wired. [`elevate`] actually shells the helper and
//! parses its JSON stdout; [`spawn_watcher`] fires the reaper detached.
//! All exec targets are env-overridable so tests drive a fake `seadog-priv`
//! with no real sudo (`$SEADOG_SUDO=""`).
//!
//! ## Exec target env knobs (defaults are the prod values)
//! - `$SEADOG_SUDO` — sudo program, default `"sudo"`. **Empty ⇒ skip sudo**
//!   (call the helper directly; how tests run unprivileged).
//! - `$SEADOG_PRIV_BIN` — helper path, default `/usr/lib/seadog/seadog-priv`.
//! - `$SEADOG_SETSID` — setsid program for the detached watcher, default
//!   `"setsid"`. Empty ⇒ skip the setsid prefix.
//! - `$SEADOG_WATCHER_LOCK` — flock path the watcher singleton-guards on,
//!   default `/run/seadog/watcher.lock`. The front-end may pre-check it to
//!   avoid a needless spawn, but the authoritative guard is the helper's
//!   own flock (Phase 3b).

use std::fmt;
use std::process::{Command, Stdio};

/// Default helper path; overridable by `$SEADOG_PRIV_BIN`.
const DEFAULT_PRIV_BIN: &str = "/usr/lib/seadog/seadog-priv";
/// Default sudo program; overridable by `$SEADOG_SUDO` (empty ⇒ skip).
const DEFAULT_SUDO: &str = "sudo";
/// Default setsid program; overridable by `$SEADOG_SETSID` (empty ⇒ skip).
const DEFAULT_SETSID: &str = "setsid";
/// Default watcher flock path; overridable by `$SEADOG_WATCHER_LOCK`.
const DEFAULT_WATCHER_LOCK: &str = "/run/seadog/watcher.lock";

/// Arguments handed to the privileged helper for one elevated verb.
///
/// Kept deliberately abstract: a verb name plus its already-validated,
/// positional+flag argv (the exact tokens `seadog-priv` will re-parse and
/// re-validate). The front-end builds this from clap-parsed values so the
/// untrusted SSH command text never reaches the helper unstructured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElevateArgs {
    /// The privileged verb (`provision`, `teardown`, …) as `seadog-priv`
    /// will see it.
    pub verb: String,
    /// The trusted, resolved owner the op runs on behalf of. Passed to the
    /// helper as an explicit `--owner <name>` arg (the helper re-validates
    /// everything but needs the resolved owner); never owner-supplied.
    pub owner: String,
    /// The validated argv tail (flags + positionals) for the helper.
    pub args: Vec<String>,
}

impl ElevateArgs {
    /// Construct an elevation request for `verb` on behalf of `owner`.
    pub fn new(verb: impl Into<String>, owner: impl Into<String>, args: Vec<String>) -> Self {
        ElevateArgs {
            verb: verb.into(),
            owner: owner.into(),
            args,
        }
    }
}

/// Error type for the elevation primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevateError {
    /// The helper could not be spawned at all (missing binary, exec error).
    Spawn { verb: String, message: String },
    /// The helper ran but exited non-zero. Carries its captured stderr and
    /// exit code so the front-end can surface a clear error.
    Helper {
        verb: String,
        code: Option<i32>,
        stderr: String,
    },
    /// The helper exited zero but its stdout was not the expected JSON.
    BadJson { verb: String, message: String },
}

impl fmt::Display for ElevateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElevateError::Spawn { verb, message } => {
                write!(
                    f,
                    "could not invoke privileged helper for '{verb}': {message}"
                )
            }
            ElevateError::Helper { verb, code, stderr } => {
                let code = code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".into());
                let stderr = stderr.trim();
                write!(
                    f,
                    "privileged helper '{verb}' failed (exit {code}): {stderr}"
                )
            }
            ElevateError::BadJson { verb, message } => write!(
                f,
                "privileged helper '{verb}' returned unparseable output: {message}"
            ),
        }
    }
}

impl std::error::Error for ElevateError {}

/// JSON-serializable result of an elevated op (what `seadog-priv` handed
/// back). The front-end re-emits `result` as the verb's JSON.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ElevateOutcome {
    /// The verb that ran.
    pub verb: String,
    /// The JSON value the helper emitted on stdout, parsed back for
    /// re-rendering by the calling verb.
    pub result: serde_json::Value,
}

/// Read an env var, falling back to `default`.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Build the full argv for one helper verb:
/// `[sudo?] <priv_bin> <verb> --owner <owner> <args...>`.
///
/// `sudo` empty ⇒ no sudo prefix (the test/unprivileged path). Pure over
/// its inputs (the env is read by [`build_argv`]) so it unit-tests without
/// touching process-global env vars.
fn build_argv_with(sudo: &str, priv_bin: &str, req: &ElevateArgs) -> Vec<String> {
    let mut argv = Vec::new();
    if !sudo.is_empty() {
        argv.push(sudo.to_string());
    }
    argv.push(priv_bin.to_string());
    argv.push(req.verb.clone());
    argv.push("--owner".to_string());
    argv.push(req.owner.clone());
    argv.extend(req.args.iter().cloned());
    argv
}

/// Build the helper argv, reading the sudo + helper-path env knobs.
fn build_argv(req: &ElevateArgs) -> Vec<String> {
    let sudo = env_or("SEADOG_SUDO", DEFAULT_SUDO);
    let priv_bin = env_or("SEADOG_PRIV_BIN", DEFAULT_PRIV_BIN);
    build_argv_with(&sudo, &priv_bin, req)
}

/// Run a privileged verb through the bridge.
///
/// Builds `[$SEADOG_SUDO?] $SEADOG_PRIV_BIN <verb> --owner <owner>
/// <args…>`, runs it to completion, and parses the helper's stdout as
/// JSON into an [`ElevateOutcome`]. A non-zero exit becomes
/// [`ElevateError::Helper`] carrying the captured stderr + code. The
/// front-end depends only on this signature, so swapping the
/// implementation (or a test fake on `$SEADOG_PRIV_BIN`) needs no caller
/// changes.
pub fn elevate(req: &ElevateArgs) -> Result<ElevateOutcome, ElevateError> {
    let argv = build_argv(req);
    // argv is never empty: even with sudo skipped, the helper path is
    // pushed first.
    let (program, rest) = argv.split_first().expect("argv has the helper program");

    let output = Command::new(program)
        .args(rest)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| ElevateError::Spawn {
            verb: req.verb.clone(),
            message: e.to_string(),
        })?;

    if !output.status.success() {
        return Err(ElevateError::Helper {
            verb: req.verb.clone(),
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value =
        serde_json::from_str(stdout.trim()).map_err(|e| ElevateError::BadJson {
            verb: req.verb.clone(),
            message: e.to_string(),
        })?;

    Ok(ElevateOutcome {
        verb: req.verb.clone(),
        result,
    })
}

/// Fire the reaper watcher detached, best-effort.
///
/// Spawns `[$SEADOG_SETSID?] [$SEADOG_SUDO?] $SEADOG_PRIV_BIN watch`
/// **without waiting** (the verb must not block on the reaper). The
/// authoritative at-most-one guard is the helper's own flock on
/// `$SEADOG_WATCHER_LOCK` (Phase 3b); here we only *optionally* pre-check
/// that lock to skip a pointless spawn.
///
/// **Best-effort:** any failure (spawn error, missing helper) is logged to
/// stderr and swallowed — it must NEVER fail the calling verb. This is the
/// "opportunistic reap" hook: an unprivileged front-end can't reap, so it
/// just ensures the root watcher is alive whenever the system is in use.
pub fn spawn_watcher() -> Result<(), ElevateError> {
    let setsid = env_or("SEADOG_SETSID", DEFAULT_SETSID);
    let sudo = env_or("SEADOG_SUDO", DEFAULT_SUDO);
    let priv_bin = env_or("SEADOG_PRIV_BIN", DEFAULT_PRIV_BIN);

    let mut argv: Vec<String> = Vec::new();
    if !setsid.is_empty() {
        argv.push(setsid);
    }
    if !sudo.is_empty() {
        argv.push(sudo);
    }
    argv.push(priv_bin);
    argv.push("watch".to_string());

    let (program, rest) = argv.split_first().expect("watcher argv has a program");

    // Detached: no wait, stdio to null so the child doesn't hold our
    // streams. We do not call `.wait()` — the watcher outlives this verb.
    match Command::new(program)
        .args(rest)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(_child) => Ok(()),
        Err(e) => {
            // Best-effort: log + swallow. Callers MUST ignore this — the
            // verb never fails because the watcher couldn't start.
            eprintln!("seadog: watcher spawn failed (continuing): {e}");
            Err(ElevateError::Spawn {
                verb: "watch".to_string(),
                message: e.to_string(),
            })
        }
    }
}

/// The flock path the watcher singleton-guards on (for an optional
/// front-end pre-check; the helper's own flock is authoritative).
#[allow(dead_code)]
pub fn watcher_lock_path() -> String {
    env_or("SEADOG_WATCHER_LOCK", DEFAULT_WATCHER_LOCK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_argv_skips_sudo_when_empty() {
        let req = ElevateArgs::new("provision", "alice", vec!["--image".into(), "loom".into()]);
        let argv = build_argv_with("", "/tmp/fake-priv", &req);
        assert_eq!(
            argv,
            vec![
                "/tmp/fake-priv".to_string(),
                "provision".to_string(),
                "--owner".to_string(),
                "alice".to_string(),
                "--image".to_string(),
                "loom".to_string(),
            ]
        );
    }

    #[test]
    fn build_argv_includes_sudo_when_set() {
        let req = ElevateArgs::new("teardown", "alice", vec!["g-123".into()]);
        let argv = build_argv_with("mysudo", "/tmp/fake-priv", &req);
        assert_eq!(
            argv,
            vec![
                "mysudo".to_string(),
                "/tmp/fake-priv".to_string(),
                "teardown".to_string(),
                "--owner".to_string(),
                "alice".to_string(),
                "g-123".to_string(),
            ]
        );
    }

    #[test]
    fn elevate_args_carries_owner_and_argv() {
        let req = ElevateArgs::new("teardown", "alice", vec!["g-123".into()]);
        assert_eq!(req.verb, "teardown");
        assert_eq!(req.owner, "alice");
        assert_eq!(req.args, vec!["g-123".to_string()]);
    }
}
