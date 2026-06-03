//! `seadog` — the unprivileged login-shell front-end.
//!
//! This binary is the **login shell** for the `testenv` system user
//! (git-shell pattern), invoked by sshd. It:
//!
//! 1. Resolves the real command string from `-c "<cmd>"` (how sshd runs a
//!    login shell for a non-interactive session) or `$SSH_ORIGINAL_COMMAND`
//!    (forced-command setups), then **tokenizes it with `shell-words`** —
//!    never by spawning a shell, so `ls; rm -rf /` is just literal tokens.
//! 2. Resolves the trusted **owner** from sshd context (`--owner` injected
//!    by the `authorized_keys` forced command, or the key-fingerprint
//!    fallback) — never from the user's command text. See [`owner`].
//! 3. Dispatches the verb against `core::store` (DB-only verbs) or routes
//!    elevated verbs through the [`elevate`] seam (stubbed in Phase 2a).
//! 4. Renders results as **pretty JSON** on stdout; errors as a JSON
//!    `{ "error": "…" }` object on stderr with a non-zero exit.
//!
//! It NEVER runs as root and does not call the bridge in this phase.

mod elevate;
mod owner;
mod verbs;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use seadog_core::{store, Config};
use serde_json::json;

use verbs::create::CreateArgs;
use verbs::Ctx;

/// Default config path; overridable by `$SEADOG_CONFIG` (tests + ops).
const DEFAULT_CONFIG: &str = "/etc/seadog/config.yaml";
/// Default DB path; overridable by `$SEADOG_DB` (tests + ops).
const DEFAULT_DB: &str = "/var/lib/seadog/seadog.db";

/// Top-level CLI. `--owner` is consumed *before* clap (it is trusted and
/// injected by sshd, see [`owner`]); clap parses only the verb + its args.
#[derive(Debug, Parser)]
#[command(
    name = "seadog",
    about = "seadog test-env provisioner (login-shell front-end)",
    disable_help_flag = false
)]
struct Cli {
    #[command(subcommand)]
    verb: Verb,
}

/// The verbs. `create`/`destroy` are elevated (route through the bridge);
/// the rest are DB-only.
#[derive(Debug, Subcommand)]
enum Verb {
    /// List the caller's active envs (`--all` for every env).
    Ls {
        /// Show every env (operator view), not just the caller's active.
        #[arg(long)]
        all: bool,
    },
    /// Show one env's metadata by its env-id (guid).
    Show {
        /// The env-id (guid PK).
        env_id: String,
    },
    /// Binary version, reaper heartbeat freshness, env counts.
    Health,
    /// Terminal envs within an optional time window (humantime duration).
    History {
        /// Window like `24h`/`7d`; omit for all history.
        window: Option<String>,
    },
    /// Aggregate env counts (by status / owner).
    Stats,
    /// Extend an env's hard-kill deadline (owner-scoped, DB-only).
    Extend {
        /// The env-id (guid) to extend — must be yours.
        env_id: String,
        /// How much to add (humantime, e.g. `30m`, `1h`).
        duration: String,
    },
    /// Acknowledge a notification for a vmid (suppress escalation).
    Ack {
        /// The vmid whose notification to acknowledge.
        vmid: u32,
    },
    /// Provision a new env (elevated — routes through the bridge).
    Create {
        /// Allowlist image name (e.g. `loom`); never an OCI ref.
        #[arg(long)]
        image: String,
        /// Mode override.
        #[arg(long, value_parser = ["lxc", "vm"])]
        mode: Option<String>,
        /// Hard-kill TTL override (humantime).
        #[arg(long)]
        ttl: Option<String>,
        /// Soft "expected done" duration override (humantime).
        #[arg(long)]
        duration: Option<String>,
    },
    /// Destroy an env now (elevated — routes through the bridge).
    Destroy {
        /// The env-id (guid) to tear down.
        env_id: String,
    },
}

fn main() -> ExitCode {
    // Keep the SQLite WAL/SHM sidecars group-writable (shared `seadog`
    // group) so the root reaper and this front-end can both write the DB.
    // Mirrors seadog-priv; must run before the DB is opened.
    unsafe { libc::umask(0o002) };

    match run() {
        Ok(value) => {
            // Pretty JSON to stdout; JSON-only is the project decision.
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into())
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            // Error envelope: a JSON object to stderr, non-zero exit.
            let obj = json!({ "error": e.to_string() });
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&obj)
                    .unwrap_or_else(|_| "{\"error\":\"unknown\"}".into())
            );
            ExitCode::FAILURE
        }
    }
}

/// The real entry: build argv from sshd context, resolve owner, dispatch.
fn run() -> anyhow::Result<serde_json::Value> {
    let raw: Vec<String> = std::env::args().collect();
    let argv = resolve_argv(&raw, |k| std::env::var(k).ok())?;

    // Trusted owner: `--owner <name>` (injected by the authorized_keys
    // forced command), else the key-fingerprint fallback. Never from the
    // user's command text.
    let (owner_flag, verb_argv) = owner::owner_from_args(&argv);
    let owner = match owner_flag {
        Some(o) => o,
        None => resolve_owner_fallback()
            .ok_or_else(|| anyhow::anyhow!("could not resolve owner (no --owner, no key match)"))?,
    };

    // Parse the verb argv with clap. `try_parse_from` wants argv0 first.
    let mut clap_argv = vec!["seadog".to_string()];
    clap_argv.extend(verb_argv);
    let cli = Cli::try_parse_from(&clap_argv).map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // Load config + open store (paths overridable for tests).
    let config = load_config()?;
    let db_path = std::env::var("SEADOG_DB").unwrap_or_else(|_| DEFAULT_DB.to_string());
    let conn = store::open(&db_path)?;

    let ctx = Ctx {
        owner,
        conn: &conn,
        config: &config,
        now_unix: seadog_core::now_unix(),
        db_path,
    };

    dispatch(&ctx, cli.verb)
}

/// Dispatch a parsed verb to its module.
fn dispatch(ctx: &Ctx, verb: Verb) -> anyhow::Result<serde_json::Value> {
    match verb {
        Verb::Ls { all } => verbs::ls::run(ctx, all),
        Verb::Show { env_id } => verbs::show::run(ctx, &env_id),
        Verb::Health => verbs::health::run(ctx),
        Verb::History { window } => {
            let secs = match window {
                Some(w) => Some(parse_duration_secs(&w)?),
                None => None,
            };
            verbs::history::run(ctx, secs)
        }
        Verb::Stats => verbs::stats::run(ctx),
        Verb::Extend { env_id, duration } => {
            let d = humantime::parse_duration(&duration)
                .map_err(|e| anyhow::anyhow!("invalid duration '{duration}': {e}"))?;
            verbs::extend::run(ctx, &env_id, d)
        }
        Verb::Ack { vmid } => verbs::ack::run(ctx, vmid),
        Verb::Create {
            image,
            mode,
            ttl,
            duration,
        } => verbs::create::run(
            ctx,
            &CreateArgs {
                image,
                mode,
                ttl,
                duration,
            },
        ),
        Verb::Destroy { env_id } => verbs::destroy::run(ctx, &env_id),
    }
}

/// Parse a humantime duration string into whole seconds (i64).
fn parse_duration_secs(s: &str) -> anyhow::Result<i64> {
    let d =
        humantime::parse_duration(s).map_err(|e| anyhow::anyhow!("invalid duration '{s}': {e}"))?;
    Ok(d.as_secs() as i64)
}

/// Load the config (path from `$SEADOG_CONFIG`, else the default). A
/// missing/unreadable config is a hard error — the front-end needs the
/// image allowlist + caps.
fn load_config() -> anyhow::Result<Config> {
    let path = std::env::var("SEADOG_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());
    let cfg = Config::from_path(&path)?;
    cfg.validate()?;
    Ok(cfg)
}

/// Resolve the trusted owner via the key-fingerprint fallback, reading
/// sshd's `$SSH_AUTH_INFO_0` and the user's `authorized_keys`. Used only
/// when no `--owner` was injected. Returns `None` if either is absent or
/// no key matches.
fn resolve_owner_fallback() -> Option<String> {
    let auth_info = std::env::var("SSH_AUTH_INFO_0").ok()?;
    let ak_path = std::env::var("SEADOG_AUTHORIZED_KEYS")
        .unwrap_or_else(|_| format!("{}/.ssh/authorized_keys", home_dir()));
    let authorized = std::fs::read_to_string(ak_path).ok()?;
    owner::resolve_owner_from_authinfo(&auth_info, &authorized)
}

/// Best-effort home dir for the authorized_keys fallback path.
fn home_dir() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/home/testenv".to_string())
}

/// Build the program argv from the raw process argv + an env lookup.
///
/// Pure over `(raw_argv, getenv)` so it is unit-testable without a real
/// sshd. The discriminator is whether `$SSH_ORIGINAL_COMMAND` is set, which
/// is true **iff** an `authorized_keys` forced command is in play:
///
/// 1. **Forced command (`SSH_ORIGINAL_COMMAND` set).** sshd runs the
///    root-controlled forced command through the login shell, so the real
///    invocation is e.g. `seadog -c "seadog --owner kanibako"` (login
///    shell = seadog) or `seadog --owner kanibako` (login shell = bash,
///    seadog exec'd directly), and the client's actual verb lands in
///    `$SSH_ORIGINAL_COMMAND`. The **verb** therefore comes from
///    tokenizing `$SSH_ORIGINAL_COMMAND` (client-controlled — used only as
///    the verb). The **trusted owner** comes from the forced command:
///    prefer a `--owner <name>` already in the real argv, else mine it out
///    of the `-c` payload (which here is the root forced command, so
///    mining `--owner` from it is safe).
///
/// 2. **Plain login shell (`SSH_ORIGINAL_COMMAND` unset).** No forced
///    command, so any `-c "<cmd>"` payload is the *client's* command. Its
///    tokens are the verb; we never mine `--owner` from it (untrusted) —
///    owner falls through to the fingerprint fallback. With no `-c`, the
///    remaining real argv is the verb directly (local-testing path).
///
/// In both cases the trusted owner pair (`--owner <val>`) is spliced to the
/// **front** of the verb tokens so [`owner::owner_from_args`] consumes the
/// trusted owner first; any client-supplied `--owner` lands later in the
/// verb argv where clap rejects it (never an override). An empty verb is an
/// error (this is not an interactive shell).
fn resolve_argv(
    raw: &[String],
    getenv: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<Vec<String>> {
    // Split the real argv tail into a trusted `--owner <name>` pair, a
    // `-c <cmd>` payload, and the leftover direct argv.
    let real_tail = &raw[raw.len().min(1)..];
    let (real_owner_pair, dash_c, direct) = scan_login_argv(real_tail);

    let (mut verb_tokens, owner_pair): (Vec<String>, Option<(String, String)>) =
        match getenv("SSH_ORIGINAL_COMMAND") {
            Some(orig) => {
                // Forced command in play. The verb is the client's
                // SSH_ORIGINAL_COMMAND (used only as a verb). The trusted
                // owner is the ROOT-controlled forced command: the
                // real-argv `--owner` (bash-as-login-shell wiring) or,
                // failing that, mined from the `-c` payload (the forced
                // command itself, safe to mine ONLY in this branch).
                let verb = shell_words::split(&orig)
                    .map_err(|e| anyhow::anyhow!("could not tokenize command: {e}"))?;
                let owner = match real_owner_pair {
                    Some(pair) => Some(pair),
                    None => dash_c.as_deref().and_then(owner_pair_from_cmd),
                };
                (verb, owner)
            }
            None => {
                // Plain login shell, no forced command. A `-c` payload is
                // the client command: tokenize it as the verb but NEVER
                // mine `--owner` from it. The owner pair (normally None)
                // is only the real-argv one.
                let verb = if let Some(cmd) = dash_c {
                    shell_words::split(&cmd)
                        .map_err(|e| anyhow::anyhow!("could not tokenize command: {e}"))?
                } else {
                    // Local-testing direct argv (owner pair already stripped).
                    direct
                };
                (verb, real_owner_pair)
            }
        };

    // Check verb emptiness BEFORE splicing the owner, so a no-command login
    // (e.g. `ssh testenv@vm`) gives the clean error rather than a clap
    // "missing subcommand" error.
    if verb_tokens.is_empty() {
        anyhow::bail!(
            "no command supplied (seadog is a non-interactive login shell; \
             use a verb like `ls`, `health`, or `create --image <name>`)"
        );
    }

    if let Some((flag, val)) = owner_pair {
        // Splice the trusted owner to the FRONT so `owner_from_args`
        // consumes it first; any client `--owner` lands later (rejected).
        let mut spliced = vec![flag, val];
        spliced.append(&mut verb_tokens);
        verb_tokens = spliced;
    }

    Ok(verb_tokens)
}

/// Mine the first trusted `--owner <name>` pair out of a command string by
/// tokenizing it and reusing [`owner::owner_from_args`]. Used ONLY for the
/// root-controlled forced-command `-c` payload (never client text).
/// Returns `None` if the string has no `--owner` or fails to tokenize.
fn owner_pair_from_cmd(cmd: &str) -> Option<(String, String)> {
    let toks = shell_words::split(cmd).ok()?;
    let (owner, _) = owner::owner_from_args(&toks);
    owner.map(|val| ("--owner".to_string(), val))
}

/// Scan a login-shell argv tail for a trusted `--owner <name>` pair and a
/// `-c <cmd>` payload. Returns `(owner_pair, dash_c_command, direct_argv)`
/// where `direct_argv` is the tail with the **first** `--owner <name>`
/// pair and any `-c <cmd>` removed — the verb argv for the local-testing
/// path. Only the first `--owner` is treated as trusted; a later one stays
/// in `direct_argv` (so it would land as an unknown verb arg, never an
/// owner override).
fn scan_login_argv(tail: &[String]) -> (Option<(String, String)>, Option<String>, Vec<String>) {
    let mut owner_pair = None;
    let mut dash_c = None;
    let mut direct = Vec::with_capacity(tail.len());
    let mut i = 0;
    while i < tail.len() {
        match tail[i].as_str() {
            "--owner" if owner_pair.is_none() => {
                if let Some(v) = tail.get(i + 1) {
                    owner_pair = Some(("--owner".to_string(), v.clone()));
                    i += 2;
                    continue;
                }
            }
            "-c" if dash_c.is_none() => {
                if let Some(v) = tail.get(i + 1) {
                    dash_c = Some(v.clone());
                    i += 2;
                    continue;
                }
            }
            other => {
                if owner_pair.is_none() {
                    if let Some(v) = other.strip_prefix("--owner=") {
                        owner_pair = Some(("--owner".to_string(), v.to_string()));
                        i += 1;
                        continue;
                    }
                }
            }
        }
        direct.push(tail[i].clone());
        i += 1;
    }
    (owner_pair, dash_c, direct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn dash_c_tokenizes_to_argv() {
        let raw = vec![
            "-seadog".to_string(),
            "-c".to_string(),
            "ls --all".to_string(),
        ];
        let argv = resolve_argv(&raw, no_env).unwrap();
        assert_eq!(argv, vec!["ls".to_string(), "--all".to_string()]);
    }

    #[test]
    fn ssh_original_command_tokenizes_to_argv() {
        let raw = vec!["-seadog".to_string()];
        let argv = resolve_argv(&raw, |k| {
            if k == "SSH_ORIGINAL_COMMAND" {
                Some("show abc".to_string())
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(argv, vec!["show".to_string(), "abc".to_string()]);
    }

    #[test]
    fn quoted_args_survive_tokenization() {
        let raw = vec![
            "-seadog".to_string(),
            "-c".to_string(),
            "create --image \"my image\"".to_string(),
        ];
        let argv = resolve_argv(&raw, no_env).unwrap();
        assert_eq!(
            argv,
            vec![
                "create".to_string(),
                "--image".to_string(),
                "my image".to_string()
            ]
        );
    }

    #[test]
    fn injection_string_is_literal_tokens_not_executed() {
        // `ls; rm -rf /` must tokenize to literal tokens — no shell ran.
        let raw = vec![
            "-seadog".to_string(),
            "-c".to_string(),
            "ls; rm -rf /".to_string(),
        ];
        let argv = resolve_argv(&raw, no_env).unwrap();
        // shell-words treats `;` as part of a token, not a separator.
        assert_eq!(
            argv,
            vec![
                "ls;".to_string(),
                "rm".to_string(),
                "-rf".to_string(),
                "/".to_string()
            ]
        );
        // And clap rejects it as an unknown verb (never executes anything).
        let mut clap_argv = vec!["seadog".to_string()];
        clap_argv.extend(argv);
        assert!(Cli::try_parse_from(&clap_argv).is_err());
    }

    #[test]
    fn owner_injected_before_dash_c_is_spliced_in() {
        // sshd forced-command form: `seadog --owner alice -c "ls"`.
        let raw = vec![
            "-seadog".to_string(),
            "--owner".to_string(),
            "alice".to_string(),
            "-c".to_string(),
            "ls --all".to_string(),
        ];
        let argv = resolve_argv(&raw, no_env).unwrap();
        assert_eq!(
            argv,
            vec![
                "--owner".to_string(),
                "alice".to_string(),
                "ls".to_string(),
                "--all".to_string()
            ]
        );
        // And owner resolution consumes it, leaving the verb argv.
        let (owner, rest) = owner::owner_from_args(&argv);
        assert_eq!(owner.as_deref(), Some("alice"));
        assert_eq!(rest, vec!["ls".to_string(), "--all".to_string()]);
    }

    #[test]
    fn owner_with_original_command() {
        // Forced-command setup: --owner on the login argv, real command in
        // SSH_ORIGINAL_COMMAND.
        let raw = vec![
            "-seadog".to_string(),
            "--owner".to_string(),
            "alice".to_string(),
        ];
        let argv = resolve_argv(&raw, |k| {
            if k == "SSH_ORIGINAL_COMMAND" {
                Some("health".to_string())
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(
            argv,
            vec![
                "--owner".to_string(),
                "alice".to_string(),
                "health".to_string()
            ]
        );
    }

    #[test]
    fn empty_command_is_error() {
        let raw = vec!["-seadog".to_string()];
        assert!(resolve_argv(&raw, no_env).is_err());
    }

    #[test]
    fn local_direct_argv_path() {
        // Local testing: `seadog ls --all` with no -c, no env.
        let raw = vec!["seadog".to_string(), "ls".to_string(), "--all".to_string()];
        let argv = resolve_argv(&raw, no_env).unwrap();
        assert_eq!(argv, vec!["ls".to_string(), "--all".to_string()]);
    }

    /// Build a `getenv` closure that returns `val` for `SSH_ORIGINAL_COMMAND`.
    fn orig_env(val: &'static str) -> impl Fn(&str) -> Option<String> {
        move |k: &str| {
            if k == "SSH_ORIGINAL_COMMAND" {
                Some(val.to_string())
            } else {
                None
            }
        }
    }

    #[test]
    fn forced_command_seadog_login_shell_mines_owner_from_dash_c() {
        // The bug: seadog IS the login shell, so the forced command runs as
        // `seadog -c "seadog --owner kanibako"` with the real verb in
        // SSH_ORIGINAL_COMMAND. Owner must be mined from the `-c` payload
        // (the root forced command), verb from SSH_ORIGINAL_COMMAND.
        let raw = vec![
            "-seadog".to_string(),
            "-c".to_string(),
            "seadog --owner kanibako".to_string(),
        ];
        let argv = resolve_argv(&raw, orig_env("health")).unwrap();
        assert_eq!(
            argv,
            vec![
                "--owner".to_string(),
                "kanibako".to_string(),
                "health".to_string()
            ]
        );
        // And owner resolution yields kanibako with verb `["health"]`.
        let (owner, verb) = owner::owner_from_args(&argv);
        assert_eq!(owner.as_deref(), Some("kanibako"));
        assert_eq!(verb, vec!["health".to_string()]);
    }

    #[test]
    fn forced_command_bash_login_shell_uses_real_owner() {
        // bash IS the login shell, so seadog is exec'd directly with
        // `--owner` in real argv; verb still comes from SSH_ORIGINAL_COMMAND.
        let raw = vec![
            "seadog".to_string(),
            "--owner".to_string(),
            "kanibako".to_string(),
        ];
        let argv = resolve_argv(&raw, orig_env("ls --all")).unwrap();
        assert_eq!(
            argv,
            vec![
                "--owner".to_string(),
                "kanibako".to_string(),
                "ls".to_string(),
                "--all".to_string()
            ]
        );
    }

    #[test]
    fn client_cannot_inject_owner_via_original_command() {
        // Forced command sets the trusted owner (`trusted`); the client
        // tries to override via SSH_ORIGINAL_COMMAND. The trusted owner is
        // spliced first and wins; the client `--owner attacker` survives as
        // literal verb tokens (clap would reject them — never an override).
        let raw = vec![
            "-seadog".to_string(),
            "-c".to_string(),
            "seadog --owner trusted".to_string(),
        ];
        let argv = resolve_argv(&raw, orig_env("ls --owner attacker")).unwrap();
        assert_eq!(&argv[..2], &["--owner".to_string(), "trusted".to_string()]);
        let (owner, verb) = owner::owner_from_args(&argv);
        assert_eq!(owner.as_deref(), Some("trusted"));
        assert!(verb.contains(&"--owner".to_string()));
        assert!(verb.contains(&"attacker".to_string()));
        // The trusted owner is never overridden by the client.
        assert_ne!(owner.as_deref(), Some("attacker"));
    }

    #[test]
    fn plain_login_shell_does_not_mine_owner() {
        // Regression: plain login shell (no SSH_ORIGINAL_COMMAND). The `-c`
        // payload is the client command — tokenized as verb, no owner mined.
        let raw = vec![
            "-seadog".to_string(),
            "-c".to_string(),
            "health".to_string(),
        ];
        let argv = resolve_argv(&raw, no_env).unwrap();
        assert_eq!(argv, vec!["health".to_string()]);
        let (owner, _) = owner::owner_from_args(&argv);
        assert_eq!(owner, None);
    }

    #[test]
    fn empty_original_command_with_forced_owner_is_error() {
        // Forced command present (owner kanibako) but the client supplied no
        // command: SSH_ORIGINAL_COMMAND is empty. Must bail with the clean
        // "no command supplied" error rather than splicing a verbless owner.
        let raw = vec![
            "-seadog".to_string(),
            "-c".to_string(),
            "seadog --owner kanibako".to_string(),
        ];
        let err = resolve_argv(&raw, orig_env("")).unwrap_err();
        assert!(err.to_string().contains("no command supplied"));
    }
}
