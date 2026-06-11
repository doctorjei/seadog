//! `create` — provision a new env. **Elevated** (PVE op), so the actual
//! guest creation routes through the [`elevate`](crate::elevate) seam.
//!
//! ## Who allocates (locked design decision)
//! **The front-end allocates**, not the helper. On `create` the flow is:
//!
//! 1. Resolve + validate the image against the allowlist (bare name only).
//! 2. Cap-check the owner's active envs of that mode.
//! 3. Atomically allocate a vmid + IP and **write the `Active` DB row
//!    locally** (the testenv DB is front-end-writable; `core::alloc`).
//! 4. Elevate `provision` with the already-allocated params. The helper
//!    (`seadog-priv provision`, Phase 3a) *receives* those params and
//!    creates the guest; it does NOT re-allocate.
//!
//! ## Rollback on helper failure
//! If `provision` fails, the row we just inserted is marked **`Vanished`**
//! so the vmid/IP lease frees immediately (allocation only counts `Active`
//! rows). We keep the row (as `Vanished`) rather than deleting it so the
//! failed attempt is visible in history; either way the lease is released.

use anyhow::{anyhow, Result};
use rand::Rng;
use serde_json::{json, Value};

use seadog_core::alloc::{self, NewEnv};
use seadog_core::models::Mode;
use seadog_core::store;
use seadog_core::validate;
use seadog_core::EnvStatus;

use super::Ctx;
use crate::elevate::{elevate, spawn_watcher, ElevateArgs};

/// Parsed `create` arguments (clap-populated in `main`).
#[derive(Debug, Clone)]
pub struct CreateArgs {
    /// Allowlist image *name* (e.g. `loom`) — never an OCI ref.
    pub image: String,
    /// Optional explicit mode (`lxc`/`vm`); defaults to the image's first
    /// allowed mode.
    pub mode: Option<String>,
    /// Optional hard-kill TTL override (humantime string).
    pub ttl: Option<String>,
    /// Optional soft "expected done" duration override (humantime string).
    pub duration: Option<String>,
}

/// `create --image <name> [--mode lxc|vm] [--ttl <dur>] [--duration <dur>]`.
pub fn run(ctx: &Ctx, args: &CreateArgs) -> Result<Value> {
    // Opportunistic reap hook: ensure the root watcher is alive whenever
    // someone is actively mutating the system. Best-effort — never blocks
    // or fails the verb.
    let _ = spawn_watcher();

    // 1. Resolve + validate the image (bare allowlist name → ref + mode).
    let requested_mode = match &args.mode {
        Some(m) => Some(
            Mode::from_str_opt(m).ok_or_else(|| anyhow!("invalid mode '{m}' (expected lxc|vm)"))?,
        ),
        None => None,
    };
    let resolved = validate::resolve_image(&args.image, requested_mode, ctx.config)?;
    let mode = resolved.mode;

    // 2. Compute deadlines from overrides or lifecycle defaults.
    let ttl_secs = match &args.ttl {
        Some(s) => parse_secs(s)?,
        None => ctx.config.lifecycle.default_ttl.as_secs() as i64,
    };
    let dur_secs = match &args.duration {
        Some(s) => parse_secs(s)?,
        None => ctx.config.lifecycle.default_duration.as_secs() as i64,
    };
    let ttl_deadline = ctx
        .now_unix
        .checked_add(ttl_secs)
        .ok_or_else(|| anyhow!("ttl deadline overflows"))?;
    let soft_deadline = ctx
        .now_unix
        .checked_add(dur_secs)
        .ok_or_else(|| anyhow!("soft deadline overflows"))?;

    // 3. Cap check: count the owner's Active envs of this mode against the
    //    per-owner cap (with any config override). Reject BEFORE allocating
    //    so a capped owner never consumes a slot or shells the helper.
    let cap = mode_cap(ctx, mode);
    let active_of_mode = store::list_by_owner(ctx.conn, &ctx.owner)?
        .into_iter()
        .filter(|e| e.status == EnvStatus::Active && e.mode == mode)
        .count() as u32;
    if active_of_mode >= cap {
        return Err(anyhow!(
            "owner '{}' is at the {} cap ({active_of_mode}/{cap}); destroy an env first",
            ctx.owner,
            mode.as_str()
        ));
    }

    // 4. Mint identifiers + allocate the slot and insert the Active row.
    let guid = uuid::Uuid::new_v4().to_string();
    let mac = mint_mac();
    let name = mint_guest_name(&ctx.owner, &args.image)?;

    let [ip_lo, ip_hi] = ctx.config.allocation.ip_pool.range;

    // `core::alloc::allocate` needs a writable connection; `ctx.conn` is a
    // shared borrow, so open a fresh writable handle on the same DB (WAL
    // makes the second handle safe).
    let mut wconn = store::open(&ctx.db_path)?;
    let allocation = alloc::allocate(
        &mut wconn,
        (ip_lo, ip_hi),
        &NewEnv {
            guid: &guid,
            mode,
            owner: &ctx.owner,
            image: &args.image,
            name: &name,
            mac: &mac,
            created_at: ctx.now_unix,
            ttl_deadline,
            soft_deadline,
        },
    )?;

    // 5. Elevate `provision` with the allocated params. The helper
    //    re-validates everything; it does NOT re-allocate.
    //
    // `allow_nesting` is advisory at the front-end: read it from the served
    // alias's catalog entry (the user-supplied alias is fine to read config
    // with — the helper independently re-validates via `nesting_ok_for_ref`).
    // Absent entry / absent field ⇒ false.
    let allow_nesting = ctx
        .config
        .images
        .get(&args.image)
        .and_then(|i| i.allow_nesting)
        .unwrap_or(false);
    let argv = vec![
        "--guid".to_string(),
        guid.clone(),
        "--ip".to_string(),
        allocation.ip.to_string(),
        "--mac".to_string(),
        mac.clone(),
        "--name".to_string(),
        name.clone(),
        "--mode".to_string(),
        mode.as_str().to_string(),
        "--image-ref".to_string(),
        resolved.image_ref.clone(),
        "--allow-nesting".to_string(),
        allow_nesting.to_string(),
    ];
    let req = ElevateArgs::new("provision", ctx.owner.clone(), argv);

    match elevate(&req) {
        Ok(outcome) => {
            // The helper reports the realized provision signals it read back
            // from kento `inspect`:
            //   - `mac`: the EFFECTIVE mac the guest carries. kento reports a
            //     MAC for VM modes only, so for a VM it is the minted MAC (a
            //     JSON string); for an LXC kento reports no MAC, so the helper
            //     emits JSON `null`/absent and we record `""` ("no MAC
            //     recorded") rather than the fictional minted MAC. Identity
            //     then treats MAC as confirming-when-present.
            //   - `ssh_host_key_fps`: an array of host-key fingerprints (soft
            //     confirmer); absent ⇒ empty.
            //   - `vmid`: the backend vmid where one exists (PVE); JSON
            //     `null`/absent for backend-neutral runtimes (kept as None).
            // Record all three on the row in one UPDATE. Best-effort: a
            // recording failure is not fatal to the create.
            let effective_mac: &str = outcome
                .result
                .get("mac")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let fps: Vec<String> = outcome
                .result
                .get("ssh_host_key_fps")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let vmid: Option<u32> = outcome
                .result
                .get("vmid")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32);
            if let Err(e) = store::set_provision_signals(&wconn, &guid, effective_mac, &fps, vmid) {
                eprintln!("seadog: recording provision signals for '{guid}' failed: {e}");
            }
            Ok(json!({
                "id": guid,
                "ip": allocation.ip.to_string(),
                "name": name,
                "vmid": vmid,
                "mode": mode.as_str(),
                "mac": effective_mac,
                "ttl_deadline": ttl_deadline,
            }))
        }
        Err(e) => {
            // Rollback: mark the row Vanished so the lease frees. Best-effort
            // — if the rollback itself fails we still surface the original
            // provision error (the reaper will reconcile a stuck Active row
            // against live PVE later).
            if let Err(re) = store::mark_vanished(&wconn, &guid) {
                eprintln!("seadog: rollback of '{guid}' failed: {re}");
            }
            Err(anyhow!(e))
        }
    }
}

/// The per-owner cap for `mode`, applying any `config.owners[owner]`
/// override on top of the global `allocation.caps`.
fn mode_cap(ctx: &Ctx, mode: Mode) -> u32 {
    let caps = &ctx.config.allocation.caps;
    let ov = ctx.config.owners.get(&ctx.owner);
    match mode {
        Mode::Lxc => ov.and_then(|o| o.max_lxc).unwrap_or(caps.max_lxc_per_owner),
        Mode::Vm => ov.and_then(|o| o.max_vm).unwrap_or(caps.max_vm_per_owner),
    }
}

/// Parse a humantime duration string into whole seconds (i64).
fn parse_secs(s: &str) -> Result<i64> {
    let d = humantime::parse_duration(s).map_err(|e| anyhow!("invalid duration '{s}': {e}"))?;
    i64::try_from(d.as_secs()).map_err(|_| anyhow!("duration '{s}' is too large"))
}

/// Mint a locally-administered unicast MAC (`x2:..` — the
/// locally-administered bit set, the multicast bit clear) with five random
/// octets, lowercase colon-separated. Format matches the PVE `net0`
/// `hwaddr=` form.
fn mint_mac() -> String {
    let mut rng = rand::thread_rng();
    // First octet: locally administered (bit 1 set), unicast (bit 0 clear).
    let first: u8 = (rng.gen::<u8>() & 0xfc) | 0x02;
    let rest: [u8; 5] = rng.gen();
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        first, rest[0], rest[1], rest[2], rest[3], rest[4]
    )
}

/// Mint a guest name `seadog-<owner>-<shortproj>-<token>` that passes
/// [`validate::validate_guest_name`] (strict DNS label, ≤63, lowercase, no
/// underscore). We derive a sanitized short owner + image label and append
/// a random 6-char base36 token for uniqueness, then truncate the whole
/// thing to 63 chars on a safe boundary.
fn mint_guest_name(owner: &str, image: &str) -> Result<String> {
    let owner_label = dns_label(owner);
    let proj_label = dns_label(image);
    let token = mint_token(6);

    // `seadog-` + owner + `-` + proj + `-` + token, then bound to 63.
    let mut name = format!("seadog-{owner_label}-{proj_label}-{token}");
    if name.len() > 63 {
        name.truncate(63);
        // A truncation must not leave a trailing hyphen (invalid label).
        while name.ends_with('-') {
            name.pop();
        }
    }
    validate::validate_guest_name(&name)
        .map_err(|e| anyhow!("could not mint a valid guest name from '{owner}'/'{image}': {e}"))?;
    Ok(name)
}

/// Sanitize an arbitrary string into a short DNS-label fragment: lowercase,
/// `[a-z0-9-]` only (other chars dropped), collapsed leading/trailing
/// hyphens, capped at 12 chars. Empty input yields `x` so the surrounding
/// name still has a non-empty segment.
fn dns_label(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().flat_map(|c| c.to_lowercase()) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if (c == '-' || c == '_' || c == ' ' || c == '.') && !out.ends_with('-') {
            out.push('-');
        }
        if out.len() >= 12 {
            break;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "x".to_string()
    } else {
        trimmed
    }
}

/// A random lowercase base36 token of `n` chars (collision-resistant
/// enough for a per-create suffix; uniqueness is ultimately the `guid`).
fn mint_token(n: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}
