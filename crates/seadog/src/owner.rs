//! Owner resolution — trusted because sshd, not the user, determines it.
//!
//! The owner is *never* taken from the user's command text. Two paths,
//! both pure functions over strings so they unit-test without sshd:
//!
//! 1. **Forced-command convention (primary).** Each `authorized_keys`
//!    line is:
//!
//!    ```text
//!    command="/usr/lib/seadog/seadog --owner <name>",no-pty,no-X11-forwarding,… <keytype> <base64> <comment>
//!    ```
//!
//!    sshd runs exactly that command on auth, so our argv gains a trusted
//!    `--owner <name>` (consumed at the top level, before the verb) and
//!    the user's real command lands in `$SSH_ORIGINAL_COMMAND`. This is
//!    the contract Phase 4's sshd snippet + authorized_keys generator must
//!    honor. See [`owner_from_args`].
//!
//! 2. **Fingerprint fallback.** Without a forced `--owner` (e.g. a plain
//!    `AuthorizedKeysFile` setup), we map the *authenticating* key — sshd
//!    exposes it in `$SSH_AUTH_INFO_0` — to its `authorized_keys` line by
//!    SHA256 fingerprint, and read that line's `--owner` value. See
//!    [`resolve_owner_from_authinfo`].
//!
//! Either way the owner comes from which key authenticated, never from
//! the command.

use sha2::{Digest, Sha256};

/// Extract a trusted top-level `--owner <name>` from a raw argv, returning
/// `(owner, remaining_argv)`. The `--owner` flag and its value are removed
/// so the remaining argv is the user's verb + args. Only the first
/// `--owner` is honored; any later one is left in place (so it would land
/// as an unknown arg to a verb, never silently override the trusted one).
///
/// `argv` here is the *program's* argv tail (after argv0), i.e. what clap
/// would otherwise parse. Returns `None` owner when no `--owner` is
/// present (caller then falls back to fingerprint resolution).
pub fn owner_from_args(argv: &[String]) -> (Option<String>, Vec<String>) {
    let mut owner = None;
    let mut rest = Vec::with_capacity(argv.len());
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if owner.is_none() && a == "--owner" {
            if let Some(val) = argv.get(i + 1) {
                owner = Some(val.clone());
                i += 2;
                continue;
            }
            // `--owner` with no value: drop it, leave owner None.
            i += 1;
            continue;
        }
        if owner.is_none() {
            if let Some(val) = a.strip_prefix("--owner=") {
                owner = Some(val.to_string());
                i += 1;
                continue;
            }
        }
        rest.push(a.clone());
        i += 1;
    }
    (owner, rest)
}

/// Compute the OpenSSH SHA256 fingerprint (`SHA256:<base64-no-pad>`) of a
/// public key given in `authorized_keys`/`SSH_AUTH_INFO_0` form
/// (`<keytype> <base64-blob> [comment]`). The fingerprint is over the
/// **raw key blob** (the base64-decoded second field), matching
/// `ssh-keygen -lf`. Returns `None` if the line has no decodable blob.
pub fn key_fingerprint(key_line: &str) -> Option<String> {
    let blob_b64 = key_line.split_whitespace().nth(1)?;
    let blob = base64::decode_standard(blob_b64)?;
    let digest = Sha256::digest(&blob);
    // OpenSSH renders the fingerprint as unpadded standard base64.
    let enc = base64::encode_standard_nopad(&digest);
    Some(format!("SHA256:{enc}"))
}

/// Parse the `--owner <name>` out of a single `authorized_keys` line's
/// forced `command="…"`. Returns `None` if the line has no
/// `command="… --owner X …"`.
fn owner_in_authorized_line(line: &str) -> Option<String> {
    // Find command="...": the value is from the first quote to the next.
    let start = line.find("command=\"")? + "command=\"".len();
    let tail = &line[start..];
    let end = tail.find('"')?;
    let cmd = &tail[..end];
    // The command is a shell-quoted string, but the `--owner <name>` we
    // emit is always a plain token pair, so a whitespace split suffices.
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

/// Fingerprint-fallback owner resolution.
///
/// `ssh_auth_info0` is the value of `$SSH_AUTH_INFO_0` — sshd writes one
/// line per auth method; for publickey auth the relevant line is
/// `publickey <keytype> <base64-blob>`. `authorized_keys` is the full
/// file contents. We fingerprint the authenticating key, find the
/// `authorized_keys` line whose key fingerprint matches, and return that
/// line's forced-command `--owner` value.
///
/// Pure over both strings (no fs, no env) so it is directly unit-testable.
pub fn resolve_owner_from_authinfo(ssh_auth_info0: &str, authorized_keys: &str) -> Option<String> {
    // The auth-info publickey line is `publickey <type> <blob> [opts...]`.
    // Strip a leading `publickey` token so `key_fingerprint` sees
    // `<type> <blob>` like an authorized_keys key body.
    let auth_line = ssh_auth_info0
        .lines()
        .find(|l| l.trim_start().starts_with("publickey"))
        .unwrap_or(ssh_auth_info0);
    let key_body = auth_line
        .trim_start()
        .strip_prefix("publickey")
        .map(str::trim_start)
        .unwrap_or(auth_line);
    let target_fp = key_fingerprint(key_body)?;

    for line in authorized_keys.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // An authorized_keys line is `[options] <keytype> <blob> [comment]`.
        // Options can't contain spaces unquoted except inside command="…",
        // so locate the key body by finding the keytype token.
        if let Some(body) = key_body_of_authorized_line(line) {
            if let Some(fp) = key_fingerprint(body) {
                if fp == target_fp {
                    return owner_in_authorized_line(line);
                }
            }
        }
    }
    None
}

/// Locate the `<keytype> <blob> [comment]` substring of an
/// `authorized_keys` line, skipping any leading options field. Returns
/// `None` if no recognizable key type is found.
fn key_body_of_authorized_line(line: &str) -> Option<&str> {
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
    for kt in KEY_TYPES {
        if let Some(pos) = line.find(kt) {
            // Guard against matching a keytype that appears inside the
            // options field: require it to start at a word boundary
            // (start of line or preceded by whitespace/comma).
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

/// Minimal standard-base64 helpers (avoid pulling a heavy base64 crate for
/// two call sites). Kept private; only the public API above is used
/// elsewhere.
mod base64 {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Decode standard base64 (with or without `=` padding). Returns
    /// `None` on any invalid character.
    pub fn decode_standard(s: &str) -> Option<Vec<u8>> {
        let mut rev = [255u8; 256];
        for (i, &c) in STD.iter().enumerate() {
            rev[c as usize] = i as u8;
        }
        let mut out = Vec::with_capacity(s.len() / 4 * 3);
        let mut buf = 0u32;
        let mut bits = 0u32;
        for ch in s.bytes() {
            if ch == b'=' || ch.is_ascii_whitespace() {
                continue;
            }
            let v = rev[ch as usize];
            if v == 255 {
                return None;
            }
            buf = (buf << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        Some(out)
    }

    /// Encode bytes as standard base64 without padding.
    pub fn encode_standard_nopad(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        let mut chunks = data.chunks_exact(3);
        for c in &mut chunks {
            let n = (c[0] as u32) << 16 | (c[1] as u32) << 8 | c[2] as u32;
            out.push(STD[(n >> 18 & 63) as usize] as char);
            out.push(STD[(n >> 12 & 63) as usize] as char);
            out.push(STD[(n >> 6 & 63) as usize] as char);
            out.push(STD[(n & 63) as usize] as char);
        }
        let rem = chunks.remainder();
        match rem.len() {
            1 => {
                let n = (rem[0] as u32) << 16;
                out.push(STD[(n >> 18 & 63) as usize] as char);
                out.push(STD[(n >> 12 & 63) as usize] as char);
            }
            2 => {
                let n = (rem[0] as u32) << 16 | (rem[1] as u32) << 8;
                out.push(STD[(n >> 18 & 63) as usize] as char);
                out.push(STD[(n >> 12 & 63) as usize] as char);
                out.push(STD[(n >> 6 & 63) as usize] as char);
            }
            _ => {}
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_from_args_honored_and_consumed() {
        let argv = vec![
            "--owner".to_string(),
            "kanibako".to_string(),
            "ls".to_string(),
            "--all".to_string(),
        ];
        let (owner, rest) = owner_from_args(&argv);
        assert_eq!(owner.as_deref(), Some("kanibako"));
        assert_eq!(rest, vec!["ls".to_string(), "--all".to_string()]);
    }

    #[test]
    fn owner_from_args_equals_form() {
        let argv = vec!["--owner=jei".to_string(), "ls".to_string()];
        let (owner, rest) = owner_from_args(&argv);
        assert_eq!(owner.as_deref(), Some("jei"));
        assert_eq!(rest, vec!["ls".to_string()]);
    }

    #[test]
    fn owner_cannot_be_set_from_verb_args_after_first() {
        // A user-injected second `--owner` is NOT consumed as trusted; it
        // stays in the verb argv (where clap rejects it), so it can never
        // override the trusted owner.
        let argv = vec![
            "--owner".to_string(),
            "trusted".to_string(),
            "ls".to_string(),
            "--owner".to_string(),
            "attacker".to_string(),
        ];
        let (owner, rest) = owner_from_args(&argv);
        assert_eq!(owner.as_deref(), Some("trusted"));
        assert!(rest.contains(&"--owner".to_string()));
        assert!(rest.contains(&"attacker".to_string()));
    }

    #[test]
    fn no_owner_flag_yields_none() {
        let argv = vec!["ls".to_string()];
        let (owner, rest) = owner_from_args(&argv);
        assert_eq!(owner, None);
        assert_eq!(rest, argv);
    }

    // A real ed25519 public key (sample, generated for the test only).
    const TEST_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBVL8h1uvNvR2v2c0Yk6Yz0mYy8w0cZk6Q1yK0a8mDcL test@host";

    #[test]
    fn fingerprint_is_stable_sha256_form() {
        let fp = key_fingerprint(TEST_KEY).expect("decodable");
        assert!(fp.starts_with("SHA256:"));
        // No padding, base64 chars only.
        let body = &fp["SHA256:".len()..];
        assert!(!body.contains('='));
        assert!(body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
    }

    #[test]
    fn resolve_owner_from_authinfo_matches_by_fingerprint() {
        // The blob in SSH_AUTH_INFO_0 is the same key as one authorized line.
        let blob = "AAAAC3NzaC1lZDI1NTE5AAAAIBVL8h1uvNvR2v2c0Yk6Yz0mYy8w0cZk6Q1yK0a8mDcL";
        let auth_info = format!("publickey ssh-ed25519 {blob}");
        // Authorized_keys with two lines; only the second matches.
        let other = "AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyOtherKeyOtherKeyOtherKeyOtherKeyZ";
        let authorized = format!(
            "command=\"/usr/lib/seadog/seadog --owner alice\",no-pty ssh-ed25519 {other} alice@h\n\
             command=\"/usr/lib/seadog/seadog --owner kanibako\",no-pty,no-X11-forwarding ssh-ed25519 {blob} kani@h\n"
        );
        let owner = resolve_owner_from_authinfo(&auth_info, &authorized);
        assert_eq!(owner.as_deref(), Some("kanibako"));
    }

    #[test]
    fn resolve_owner_no_match_is_none() {
        let auth_info =
            "publickey ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBVL8h1uvNvR2v2c0Yk6Yz0mYy8w0cZk6Q1yK0a8mDcL";
        let authorized =
            "command=\"/usr/lib/seadog/seadog --owner alice\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyOtherKeyOtherKeyOtherKeyOtherKeyZ alice@h\n";
        assert_eq!(resolve_owner_from_authinfo(auth_info, authorized), None);
    }
}
