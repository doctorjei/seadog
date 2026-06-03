//! Pure string logic for the root-owned `authorized_keys` file that maps
//! SSH keys to seadog *owners*.
//!
//! Each managed line is a forced-command entry of the exact form:
//!
//! ```text
//! command="<frontend_bin> --owner <name>",restrict <keytype> <blob> <comment>
//! ```
//!
//! which is byte-identical to what `deploy/install.sh` writes for the
//! bootstrap key. `seadog-priv`'s owner-management verbs build, parse, and
//! filter these lines; all of that string work lives here (no fs, no env)
//! so it unit-tests cleanly and so the **root** helper never has to link the
//! untrusted `seadog` front-end (whose `owner.rs` has the sibling parsing).
//!
//! These helpers deliberately mirror the pure parsing in
//! `crates/seadog/src/owner.rs` — they are reimplemented here (not shared
//! from `seadog`) to keep `seadog-priv` free of any `seadog` dependency.

/// Build a managed `authorized_keys` line for `owner` authenticating with
/// `key_line` (a `<keytype> <blob> [comment]` public-key body).
///
/// The result is exactly:
///
/// ```text
/// command="<frontend_bin> --owner <owner>",restrict <key_line>
/// ```
///
/// This is byte-identical to `deploy/install.sh`'s bootstrap line
/// (`command="${FRONTEND} --owner ${BOOTSTRAP_OWNER}",restrict ${BOOTSTRAP_KEY}`).
/// `restrict` implies `no-pty` + no forwarding. The caller is responsible
/// for validating `owner` (so it contains no quote/space) and `key_line`.
pub fn forced_command_line(frontend_bin: &str, owner: &str, key_line: &str) -> String {
    format!("command=\"{frontend_bin} --owner {owner}\",restrict {key_line}")
}

/// The base64 key blob — the whitespace-split **second** field — of a public
/// key body in `<keytype> <blob> [comment]` form. `None` if there is no
/// second field.
///
/// This works on a **bare** key line (as supplied to `add-owner`). For a
/// full managed `authorized_keys` line (which begins with a `command="…"`
/// options field), first locate the key body with [`key_body_of_line`] and
/// pass that.
pub fn key_blob(key_line: &str) -> Option<&str> {
    key_line.split_whitespace().nth(1)
}

/// Recognized SSH public-key type tokens (the leading token of a key body).
const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Validate that `key_line` is exactly **one** well-formed public-key body
/// of the form `<keytype> <blob> [comment]`.
///
/// This is the anti-injection guard for `add-owner`: because the line is
/// later interpolated into a forced-command `authorized_keys` entry (see
/// [`forced_command_line`]), an embedded newline would let a caller append a
/// SECOND, unrestricted `authorized_keys` line that bypasses the forced
/// command. To prevent that, the line must contain **no ASCII control
/// characters at all** (anything `< 0x20` — which covers `\n`, `\r`, `\t` —
/// or `0x7f`), then must split into a recognized [`KEY_TYPES`] keytype, a
/// non-empty base64 (`[A-Za-z0-9+/=]`) blob, and an optional free-form
/// comment.
pub fn validate_key_line(key_line: &str) -> Result<(), crate::Error> {
    // 1. Anti-injection: the line must be exactly one line with no control
    //    characters whatsoever (newline, carriage return, tab, etc.).
    if let Some(c) = key_line
        .chars()
        .find(|&c| (c as u32) < 0x20 || c == '\u{7f}')
    {
        return Err(crate::Error::Validation(format!(
            "key line must not contain control characters (found U+{:04X})",
            c as u32
        )));
    }

    let trimmed = key_line.trim();
    let mut fields = trimmed.split_whitespace();

    // 2. Field 0 must be a recognized key type.
    let key_type = fields
        .next()
        .ok_or_else(|| crate::Error::Validation("key line is empty (no key type)".to_string()))?;
    if !KEY_TYPES.contains(&key_type) {
        return Err(crate::Error::Validation(format!(
            "key line has unrecognized key type '{key_type}'"
        )));
    }

    // 3. Field 1 (the blob) must be present, non-empty, and base64 only.
    let blob = fields
        .next()
        .ok_or_else(|| crate::Error::Validation("key line has no key blob".to_string()))?;
    if blob.is_empty() {
        return Err(crate::Error::Validation(
            "key line has an empty key blob".to_string(),
        ));
    }
    if !blob
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return Err(crate::Error::Validation(format!(
            "key blob '{blob}' contains non-base64 characters"
        )));
    }

    // Field 2+ (comment) is unrestricted; the no-control-char rule above
    // already bars a newline from sneaking in there.
    Ok(())
}

/// Locate the `<keytype> <blob> [comment]` substring of an
/// `authorized_keys` line, skipping any leading options field (e.g.
/// `command="…",restrict`). Returns `None` if no recognizable key type is
/// found at a word boundary.
///
/// Mirrors `seadog::owner::key_body_of_authorized_line`. On a line that is
/// *already* a bare key body, this returns the whole (trimmed) line.
pub fn key_body_of_line(line: &str) -> Option<&str> {
    for kt in KEY_TYPES {
        if let Some(pos) = line.find(kt) {
            // Require the match to start at a word boundary so a keytype
            // that appears inside the options field (e.g. inside a quoted
            // command) is not mistaken for the key body.
            let ok = pos == 0
                || line[..pos]
                    .chars()
                    .next_back()
                    .map(|c| c.is_whitespace() || c == ',' || c == '"')
                    .unwrap_or(false);
            if ok {
                return Some(&line[pos..]);
            }
        }
    }
    None
}

/// Parse the trusted `--owner <name>` out of a managed line's forced
/// `command="…"`. `None` if the line has no `command="… --owner X …"`.
///
/// Mirrors `seadog::owner::owner_in_authorized_line`.
fn owner_in_line(line: &str) -> Option<String> {
    let start = line.find("command=\"")? + "command=\"".len();
    let tail = &line[start..];
    let end = tail.find('"')?;
    let cmd = &tail[..end];
    let toks: Vec<&str> = cmd.split_whitespace().collect();
    for (i, t) in toks.iter().enumerate() {
        if *t == "--owner" {
            return toks.get(i + 1).map(|s| s.to_string());
        }
        if let Some(v) = t.strip_prefix("--owner=") {
            return Some(v.to_string());
        }
    }
    None
}

/// A parsed managed `authorized_keys` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerEntry {
    /// The trusted owner from the forced `command="… --owner <owner> …"`.
    pub owner: String,
    /// The SSH key type (e.g. `ssh-ed25519`).
    pub key_type: String,
    /// The base64 key blob (field 2 of the key body).
    pub blob: String,
    /// The trailing key comment, if present.
    pub comment: Option<String>,
}

/// Parse a single managed `authorized_keys` line into an [`OwnerEntry`].
///
/// Returns `None` for a blank line, a `#` comment line, or any line that is
/// not a well-formed managed entry (no `--owner`, or no decodable key body
/// with a blob). The line may carry extra option fields beyond `restrict`;
/// only the `command="…"` owner and the key body are read.
pub fn parse_owner_line(line: &str) -> Option<OwnerEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let owner = owner_in_line(line)?;
    let body = key_body_of_line(line)?;
    let mut fields = body.split_whitespace();
    let key_type = fields.next()?.to_string();
    let blob = fields.next()?.to_string();
    // Everything after the blob is the comment (which itself may contain
    // whitespace); preserve it verbatim if present.
    let rest = body
        .splitn(3, char::is_whitespace)
        .nth(2)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Some(OwnerEntry {
        owner,
        key_type,
        blob,
        comment: rest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRONTEND: &str = "/usr/lib/seadog/seadog";
    const BLOB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBVL8h1uvNvR2v2c0Yk6Yz0mYy8w0cZk6Q1yK0a8mDcL";

    #[test]
    fn forced_command_line_matches_install_sh_format() {
        let key = format!("ssh-ed25519 {BLOB} alice@host");
        let line = forced_command_line(FRONTEND, "alice", &key);
        assert_eq!(
            line,
            format!(
                "command=\"/usr/lib/seadog/seadog --owner alice\",restrict ssh-ed25519 {BLOB} alice@host"
            )
        );
    }

    #[test]
    fn key_blob_extracts_second_field() {
        let key = format!("ssh-ed25519 {BLOB} alice@host");
        assert_eq!(key_blob(&key), Some(BLOB));
    }

    #[test]
    fn key_blob_none_when_absent() {
        assert_eq!(key_blob("ssh-ed25519"), None);
        assert_eq!(key_blob(""), None);
    }

    #[test]
    fn validate_key_line_accepts_normal_lines() {
        // With and without a comment.
        assert!(validate_key_line(&format!("ssh-ed25519 {BLOB}")).is_ok());
        assert!(validate_key_line(&format!("ssh-ed25519 {BLOB} alice@host")).is_ok());
        // Multi-word comments are fine.
        assert!(validate_key_line(&format!("ssh-ed25519 {BLOB} my key on host")).is_ok());
    }

    #[test]
    fn validate_key_line_rejects_embedded_newline() {
        // The core anti-injection case: a second authorized_keys line.
        let evil = format!("ssh-ed25519 {BLOB}\nssh-rsa {BLOB} evil");
        assert!(validate_key_line(&evil).is_err());
    }

    #[test]
    fn validate_key_line_rejects_embedded_carriage_return() {
        let evil = format!("ssh-ed25519 {BLOB}\rssh-rsa {BLOB} evil");
        assert!(validate_key_line(&evil).is_err());
    }

    #[test]
    fn validate_key_line_rejects_embedded_tab() {
        let evil = format!("ssh-ed25519 {BLOB}\tnext");
        assert!(validate_key_line(&evil).is_err());
    }

    #[test]
    fn validate_key_line_rejects_unknown_keytype() {
        assert!(validate_key_line(&format!("ssh-bogus {BLOB}")).is_err());
    }

    #[test]
    fn validate_key_line_rejects_missing_blob() {
        assert!(validate_key_line("ssh-ed25519").is_err());
        assert!(validate_key_line("").is_err());
    }

    #[test]
    fn validate_key_line_rejects_non_base64_blob() {
        // `!` is not a base64 character.
        assert!(validate_key_line("ssh-ed25519 AAAA!notbase64").is_err());
        // A comment with odd chars is fine, but the blob itself must be clean.
        assert!(validate_key_line("ssh-ed25519 bad$blob comment").is_err());
    }

    #[test]
    fn key_body_of_line_finds_body_after_options() {
        let line = format!("command=\"x --owner alice\",restrict ssh-ed25519 {BLOB} c@h");
        let body = key_body_of_line(&line).unwrap();
        assert_eq!(body, format!("ssh-ed25519 {BLOB} c@h"));
    }

    #[test]
    fn key_body_of_line_on_bare_body_is_identity() {
        let body = format!("ssh-ed25519 {BLOB} c@h");
        assert_eq!(key_body_of_line(&body), Some(body.as_str()));
    }

    #[test]
    fn parse_round_trips_a_built_line() {
        let key = format!("ssh-ed25519 {BLOB} alice@host");
        let line = forced_command_line(FRONTEND, "alice", &key);
        let e = parse_owner_line(&line).unwrap();
        assert_eq!(e.owner, "alice");
        assert_eq!(e.key_type, "ssh-ed25519");
        assert_eq!(e.blob, BLOB);
        assert_eq!(e.comment.as_deref(), Some("alice@host"));
    }

    #[test]
    fn parse_tolerates_commentless_key() {
        let key = format!("ssh-ed25519 {BLOB}");
        let line = forced_command_line(FRONTEND, "bob", &key);
        let e = parse_owner_line(&line).unwrap();
        assert_eq!(e.owner, "bob");
        assert_eq!(e.blob, BLOB);
        assert_eq!(e.comment, None);
    }

    #[test]
    fn parse_tolerates_extra_option_fields() {
        let line = format!(
            "command=\"/usr/lib/seadog/seadog --owner team-a\",no-pty,no-X11-forwarding,restrict ssh-ed25519 {BLOB} team-a@h"
        );
        let e = parse_owner_line(&line).unwrap();
        assert_eq!(e.owner, "team-a");
        assert_eq!(e.blob, BLOB);
        assert_eq!(e.comment.as_deref(), Some("team-a@h"));
    }

    #[test]
    fn parse_preserves_multiword_comment() {
        let line = format!(
            "command=\"/usr/lib/seadog/seadog --owner c\",restrict ssh-ed25519 {BLOB} my key on host"
        );
        let e = parse_owner_line(&line).unwrap();
        assert_eq!(e.comment.as_deref(), Some("my key on host"));
    }

    #[test]
    fn parse_rejects_blank_and_comment_and_plain_lines() {
        assert!(parse_owner_line("").is_none());
        assert!(parse_owner_line("   ").is_none());
        assert!(parse_owner_line("# a comment").is_none());
        // A plain key line with no forced command has no owner → None.
        assert!(parse_owner_line(&format!("ssh-ed25519 {BLOB} x@h")).is_none());
    }

    #[test]
    fn parse_rejects_owner_line_with_no_blob() {
        // Forced command present but the key body has no second field.
        let line = "command=\"/usr/lib/seadog/seadog --owner alice\",restrict ssh-ed25519";
        assert!(parse_owner_line(line).is_none());
    }

    #[test]
    fn parse_honors_owner_equals_form() {
        let line = format!(
            "command=\"/usr/lib/seadog/seadog --owner=eve\",restrict ssh-ed25519 {BLOB} eve@h"
        );
        let e = parse_owner_line(&line).unwrap();
        assert_eq!(e.owner, "eve");
    }
}
