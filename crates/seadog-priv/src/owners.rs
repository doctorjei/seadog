//! `seadog-priv add-owner | list-owners | remove-owner` — root-side
//! management of the owner→key mapping in `/etc/seadog/authorized_keys`.
//!
//! This replaces hand-editing that root-owned file. The file is read,
//! mutated, and re-written **atomically** (temp file + `rename`) here, then
//! its mode (`0644`) and ownership (`root:root`) are re-asserted so a
//! managed edit can never relax them. All the pure line-building and
//! parsing lives in [`seadog_core::authkeys`]; this module is the thin
//! file-I/O shell around it (mirroring how `sweep`/`watch` wrap
//! `core::reap`).
//!
//! Unlike the PVE-touching verbs, these need neither a `Kento` backend nor
//! the DB — they operate purely on the authorized_keys file — so `main`'s
//! `dispatch` routes them straight here without the `kento`/`config` seam.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use serde_json::{json, Value};

use seadog_core::authkeys::{self, OwnerEntry};
use seadog_core::validate::validate_owner_name;

/// Default authorized_keys path; overridable by `$SEADOG_AUTHKEYS` (tests).
pub const DEFAULT_AUTHKEYS: &str = "/etc/seadog/authorized_keys";

/// The deployed front-end binary embedded in every forced-command line.
/// Matches `deploy/install.sh`'s `FRONTEND`, the sshd snippet, and
/// `seadog::owner`. Not env-overridable: it is the trusted contract.
const FRONTEND_BIN: &str = "/usr/lib/seadog/seadog";

/// Resolve the authorized_keys path (`$SEADOG_AUTHKEYS` override, else the
/// default), mirroring how `main` resolves `$SEADOG_CONFIG` and
/// `sweep`/`watch` resolve `$SEADOG_DB`.
fn authkeys_path() -> PathBuf {
    std::env::var_os("SEADOG_AUTHKEYS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_AUTHKEYS))
}

/// The directory the authorized_keys file lives in (root-owned in prod;
/// a per-test temp dir under `$SEADOG_AUTHKEYS`). Used as the root-only
/// scratch dir for the owner-key temp file `provision` injects. Falls back
/// to the path itself if it somehow has no parent.
pub fn authkeys_dir() -> PathBuf {
    let p = authkeys_path();
    p.parent().map(Path::to_path_buf).unwrap_or(p)
}

/// Read the authorized_keys file, treating a missing file as empty.
fn read_authkeys(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(anyhow!("reading {}: {e}", path.display())),
    }
}

/// Atomically replace `path` with `contents`, then re-assert mode `0644`
/// and ownership `root:root`.
///
/// The write goes to a temp file in the *same directory* (so `rename` is a
/// same-filesystem atomic swap), is flushed, and renamed over `path`. The
/// mode set is required to succeed; the `chown` to uid/gid 0 is best-effort
/// (it only succeeds when actually running as root in prod — under tests the
/// caller already owns the file, so a failure there is logged, not fatal).
fn atomic_write_root_0644(path: &Path, contents: &str) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("authorized_keys path {} has no parent", path.display()))?;
    let tmp = dir.join(format!(
        ".seadog-authkeys.{}.{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    // Scope the file handle so it is closed before the rename.
    {
        let mut f = std::fs::File::create(&tmp)
            .with_context(|| format!("creating temp file {}", tmp.display()))?;
        f.write_all(contents.as_bytes())
            .with_context(|| format!("writing temp file {}", tmp.display()))?;
        f.flush().ok();
        // fsync is optional; best-effort for durability.
        f.sync_all().ok();
    }

    // Mode/owner before the rename so the file is never world-readable in a
    // wrong mode under the final name even momentarily.
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))
        .with_context(|| format!("setting mode 0644 on {}", tmp.display()))?;
    // Best-effort chown to root:root. Non-root callers (tests) hit EPERM;
    // log and continue — the mode was already enforced above.
    if let Err(e) = chown_root(&tmp) {
        tracing::debug!("chown root:root on {} skipped: {e}", tmp.display());
    }

    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Best-effort `chown` of `path` to uid 0 / gid 0.
fn chown_root(path: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has NUL"))?;
    let rc = unsafe { libc::chown(c.as_ptr(), 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Return every authorized ssh **public-key body** (`<keytype> <blob>
/// [comment]`, no forced-command options) mapped to `owner` in the
/// root-owned authorized_keys file, in file order.
///
/// This re-derives the owner's key(s) from the helper's OWN
/// authorized_keys by owner *name* — it never accepts key material from the
/// front-end (the trust boundary). A missing file or an owner with no
/// managed lines yields an empty vec. Reuses the same parser
/// (`authkeys::parse_owner_line` / `key_body_of_line`) that backs
/// `add-owner`/`list-owners`/`remove-owner`.
pub fn owner_key_bodies(owner: &str) -> Result<Vec<String>> {
    let path = authkeys_path();
    let current = read_authkeys(&path)?;
    let mut out = Vec::new();
    for line in current.lines() {
        match authkeys::parse_owner_line(line) {
            Some(entry) if entry.owner == owner => {
                // Pull the bare `<keytype> <blob> [comment]` body back out of
                // the managed line (dropping the `command="…",restrict`
                // options) so kento receives a plain authorized_keys body.
                if let Some(body) = authkeys::key_body_of_line(line) {
                    out.push(body.trim().to_string());
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// `add-owner --owner <name> --key "<keytype> <blob> [comment]"`.
#[derive(Debug, Args)]
pub struct AddOwnerArgs {
    /// Trusted owner name (label-safe `[a-z0-9-]`).
    #[arg(long)]
    pub owner: String,
    /// The public-key body to authorize: `<keytype> <blob> [comment]`.
    #[arg(long)]
    pub key: String,
}

/// `list-owners` (no args).
#[derive(Debug, Args)]
pub struct ListOwnersArgs {}

/// `remove-owner --owner <name>`.
#[derive(Debug, Args)]
pub struct RemoveOwnerArgs {
    /// Owner whose managed line(s) to drop.
    #[arg(long)]
    pub owner: String,
}

/// Authorize a key for an owner (idempotent on the key blob).
///
/// Re-validates the owner name, requires a decodable blob, and refuses to
/// re-map a key that is already bound to a *different* owner. A same-owner
/// duplicate is a no-op success.
pub fn add_owner(args: &AddOwnerArgs) -> Result<Value> {
    validate_owner_name(&args.owner).map_err(anyhow::Error::from)?;
    // Structurally validate the key line BEFORE any file read: this rejects
    // an embedded newline (which would otherwise let `forced_command_line`
    // append a second, unrestricted authorized_keys entry) and any malformed
    // key body up front.
    authkeys::validate_key_line(&args.key).map_err(anyhow::Error::from)?;

    let blob = authkeys::key_blob(&args.key)
        .ok_or_else(|| anyhow!("key line has no decodable blob"))?
        .to_string();

    let path = authkeys_path();
    let current = read_authkeys(&path)?;

    // Idempotency / conflict check on the blob across managed lines.
    for line in current.lines() {
        if let Some(entry) = authkeys::parse_owner_line(line) {
            if entry.blob == blob {
                if entry.owner == args.owner {
                    return Ok(json!({
                        "ok": true,
                        "added": false,
                        "owner": args.owner,
                        "blob": blob,
                    }));
                }
                bail!("key already mapped to owner '{}'", entry.owner);
            }
        }
    }

    let new_line = authkeys::forced_command_line(FRONTEND_BIN, &args.owner, &args.key);
    let mut contents = current;
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(&new_line);
    contents.push('\n');

    atomic_write_root_0644(&path, &contents)?;

    Ok(json!({
        "ok": true,
        "added": true,
        "owner": args.owner,
        "blob": blob,
    }))
}

/// List every managed owner mapping. Missing file → empty list.
pub fn list_owners(_args: &ListOwnersArgs) -> Result<Value> {
    let path = authkeys_path();
    let current = read_authkeys(&path)?;

    let owners: Vec<Value> = current
        .lines()
        .filter_map(authkeys::parse_owner_line)
        .map(|e: OwnerEntry| {
            json!({
                "owner": e.owner,
                "type": e.key_type,
                "comment": e.comment,
                "blob": e.blob,
            })
        })
        .collect();

    Ok(json!({ "ok": true, "owners": owners }))
}

/// Remove all managed lines mapped to `args.owner`, preserving blank lines,
/// `#` comments, and any non-managed lines verbatim. A non-existent owner
/// yields `removed: 0` and success.
pub fn remove_owner(args: &RemoveOwnerArgs) -> Result<Value> {
    validate_owner_name(&args.owner).map_err(anyhow::Error::from)?;

    let path = authkeys_path();
    let current = read_authkeys(&path)?;

    let mut removed = 0usize;
    let mut kept: Vec<&str> = Vec::new();
    for line in current.lines() {
        match authkeys::parse_owner_line(line) {
            // Managed line for the target owner → drop it.
            Some(entry) if entry.owner == args.owner => removed += 1,
            // Any other line (managed-other-owner, blank, comment, plain) → keep.
            _ => kept.push(line),
        }
    }

    if removed > 0 {
        let mut contents = kept.join("\n");
        if !contents.is_empty() {
            contents.push('\n');
        }
        atomic_write_root_0644(&path, &contents)?;
    }

    Ok(json!({ "ok": true, "removed": removed }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `$SEADOG_AUTHKEYS` is process-global; serialize the tests that set it
    // so they don't race. Each test still uses a unique temp dir.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard: point `$SEADOG_AUTHKEYS` at a fresh temp file, restoring
    /// the prior value (and holding the env lock) until dropped. Mirrors
    /// `main`'s `test_support::TempEnv` save/restore discipline.
    struct AuthkeysEnv {
        dir: PathBuf,
        path: PathBuf,
        prev: Option<std::ffi::OsString>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl AuthkeysEnv {
        fn new() -> Self {
            let guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let unique = format!(
                "seadog-authkeys-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let dir = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("authorized_keys");
            let prev = std::env::var_os("SEADOG_AUTHKEYS");
            std::env::set_var("SEADOG_AUTHKEYS", &path);
            AuthkeysEnv {
                dir,
                path,
                prev,
                _guard: guard,
            }
        }

        fn write(&self, contents: &str) {
            std::fs::write(&self.path, contents).unwrap();
        }

        fn read(&self) -> String {
            std::fs::read_to_string(&self.path).unwrap_or_default()
        }
    }

    impl Drop for AuthkeysEnv {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("SEADOG_AUTHKEYS", v),
                None => std::env::remove_var("SEADOG_AUTHKEYS"),
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    const BLOB_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBVL8h1uvNvR2v2c0Yk6Yz0mYy8w0cZk6Q1yK0a8mDcL";
    const BLOB_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyOtherKeyOtherKeyOtherKeyOtherKeyZ";

    fn key(blob: &str, comment: &str) -> String {
        format!("ssh-ed25519 {blob} {comment}")
    }

    #[test]
    fn add_new_owner_then_present() {
        let env = AuthkeysEnv::new();
        let out = add_owner(&AddOwnerArgs {
            owner: "alice".into(),
            key: key(BLOB_A, "alice@host"),
        })
        .unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["added"], true);
        assert_eq!(out["owner"], "alice");

        let list = list_owners(&ListOwnersArgs {}).unwrap();
        let owners = list["owners"].as_array().unwrap();
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0]["owner"], "alice");
        assert_eq!(owners[0]["type"], "ssh-ed25519");
        assert_eq!(owners[0]["blob"], BLOB_A);
        assert_eq!(owners[0]["comment"], "alice@host");

        // The on-disk line is exactly the forced-command form.
        assert_eq!(
            env.read().trim_end(),
            format!(
                "command=\"/usr/lib/seadog/seadog --owner alice\",restrict ssh-ed25519 {BLOB_A} alice@host"
            )
        );
    }

    #[test]
    fn add_duplicate_same_owner_is_noop() {
        let _env = AuthkeysEnv::new();
        let args = AddOwnerArgs {
            owner: "alice".into(),
            key: key(BLOB_A, "alice@host"),
        };
        add_owner(&args).unwrap();
        let out = add_owner(&AddOwnerArgs {
            owner: "alice".into(),
            key: key(BLOB_A, "different-comment"),
        })
        .unwrap();
        assert_eq!(out["ok"], true);
        assert_eq!(out["added"], false);
        // Still only one line.
        let list = list_owners(&ListOwnersArgs {}).unwrap();
        assert_eq!(list["owners"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn add_duplicate_different_owner_errors() {
        let _env = AuthkeysEnv::new();
        add_owner(&AddOwnerArgs {
            owner: "alice".into(),
            key: key(BLOB_A, "alice@host"),
        })
        .unwrap();
        let err = add_owner(&AddOwnerArgs {
            owner: "bob".into(),
            key: key(BLOB_A, "bob@host"),
        })
        .unwrap_err();
        assert!(err.to_string().contains("already mapped to owner 'alice'"));
        // Not appended.
        let list = list_owners(&ListOwnersArgs {}).unwrap();
        assert_eq!(list["owners"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn add_with_bad_owner_name_errors() {
        let _env = AuthkeysEnv::new();
        assert!(add_owner(&AddOwnerArgs {
            owner: "Alice".into(),
            key: key(BLOB_A, "x"),
        })
        .is_err());
    }

    #[test]
    fn add_with_blobless_key_errors() {
        let _env = AuthkeysEnv::new();
        let err = add_owner(&AddOwnerArgs {
            owner: "alice".into(),
            key: "ssh-ed25519".into(),
        })
        .unwrap_err();
        // `validate_key_line` now catches the missing blob up front.
        assert!(err.to_string().contains("no key blob"));
    }

    #[test]
    fn add_with_embedded_newline_key_is_rejected_and_writes_nothing() {
        let env = AuthkeysEnv::new();
        // A key line carrying a SECOND, unrestricted authorized_keys entry
        // after an embedded newline must be refused outright.
        let evil = format!("ssh-ed25519 {BLOB_A}\nssh-rsa {BLOB_B} evil");
        let err = add_owner(&AddOwnerArgs {
            owner: "alice".into(),
            key: evil,
        })
        .unwrap_err();
        assert!(err.to_string().contains("control character"));
        // Nothing was written: the file stays absent (read() → empty string).
        assert!(!env.path.exists());
        assert_eq!(env.read(), "");
    }

    #[test]
    fn list_reflects_multiple_adds() {
        let _env = AuthkeysEnv::new();
        add_owner(&AddOwnerArgs {
            owner: "alice".into(),
            key: key(BLOB_A, "alice@host"),
        })
        .unwrap();
        add_owner(&AddOwnerArgs {
            owner: "bob".into(),
            key: key(BLOB_B, "bob@host"),
        })
        .unwrap();
        let list = list_owners(&ListOwnersArgs {}).unwrap();
        let owners = list["owners"].as_array().unwrap();
        assert_eq!(owners.len(), 2);
    }

    #[test]
    fn list_missing_file_is_empty() {
        let _env = AuthkeysEnv::new();
        // No file written.
        let list = list_owners(&ListOwnersArgs {}).unwrap();
        assert_eq!(list["owners"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn remove_drops_only_that_owner_and_counts() {
        let _env = AuthkeysEnv::new();
        add_owner(&AddOwnerArgs {
            owner: "alice".into(),
            key: key(BLOB_A, "alice@host"),
        })
        .unwrap();
        add_owner(&AddOwnerArgs {
            owner: "bob".into(),
            key: key(BLOB_B, "bob@host"),
        })
        .unwrap();
        let out = remove_owner(&RemoveOwnerArgs {
            owner: "alice".into(),
        })
        .unwrap();
        assert_eq!(out["removed"], 1);
        let list = list_owners(&ListOwnersArgs {}).unwrap();
        let owners = list["owners"].as_array().unwrap();
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0]["owner"], "bob");
    }

    #[test]
    fn remove_nonexistent_owner_is_zero() {
        let _env = AuthkeysEnv::new();
        add_owner(&AddOwnerArgs {
            owner: "alice".into(),
            key: key(BLOB_A, "alice@host"),
        })
        .unwrap();
        let out = remove_owner(&RemoveOwnerArgs {
            owner: "nobody".into(),
        })
        .unwrap();
        assert_eq!(out["removed"], 0);
        // alice still there.
        let list = list_owners(&ListOwnersArgs {}).unwrap();
        assert_eq!(list["owners"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn remove_preserves_comments_and_blanks() {
        let env = AuthkeysEnv::new();
        let managed_alice =
            authkeys::forced_command_line(FRONTEND_BIN, "alice", &key(BLOB_A, "alice@host"));
        let managed_bob =
            authkeys::forced_command_line(FRONTEND_BIN, "bob", &key(BLOB_B, "bob@host"));
        env.write(&format!(
            "# header comment\n\n{managed_alice}\n# mid comment\n{managed_bob}\n"
        ));

        let out = remove_owner(&RemoveOwnerArgs {
            owner: "alice".into(),
        })
        .unwrap();
        assert_eq!(out["removed"], 1);

        let contents = env.read();
        assert!(contents.contains("# header comment"));
        assert!(contents.contains("# mid comment"));
        assert!(contents.contains(&managed_bob));
        assert!(!contents.contains(BLOB_A));
        // The blank line between header and the first managed line survives.
        assert!(contents.starts_with("# header comment\n\n"));
    }

    #[test]
    fn add_reasserts_mode_0644() {
        let env = AuthkeysEnv::new();
        // Pre-create with a tight mode; the add must relax it back to 0644.
        env.write("");
        std::fs::set_permissions(&env.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        add_owner(&AddOwnerArgs {
            owner: "alice".into(),
            key: key(BLOB_A, "alice@host"),
        })
        .unwrap();
        let mode = std::fs::metadata(&env.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }
}
