#!/usr/bin/env bash
# Shared helpers for the fake `kento` harness.
#
# This file is SOURCED by the `kento` shim, never executed directly. It owns
# the single JSON instance-table state file ($FAKE_KENTO_STATE) that the shim
# reads/writes through `jq`, plus the formatters that reproduce the exact
# `kento list` (columnar) / `kento inspect --json` output shapes the real
# RealKento parsers consume (`crates/core/src/kento.rs`). See README.md for
# the schema + knobs.
#
# kento is backend-neutral and addresses instances BY NAME (never a vmid),
# so the table is keyed on the instance name. The seadog identity anchor
# (SEADOG_GUID / SEADOG_OWNER) rides in each instance's `environment[]` list,
# exactly as kento exposes injected env via `inspect`.

set -euo pipefail

# Resolve the state file path (default under /tmp) and make sure it + its
# parent exist with an empty instance table, so a first read never fails.
fake_kento_state() {
  printf '%s' "${FAKE_KENTO_STATE:-/tmp/fake-kento/state.json}"
}

ensure_state() {
  local f
  f="$(fake_kento_state)"
  mkdir -p "$(dirname "$f")"
  if [ ! -s "$f" ]; then
    printf '%s\n' '{"instances":[]}' >"$f"
    chmod 0666 "$f" 2>/dev/null || true
  fi
}

# Emit a pmxcfs read-only / no-quorum error and exit non-zero when the
# $FAKE_KENTO_QUORUM_LOST knob is set, so the reaper's quorum-loss path is
# exercisable. kento runs on PVE backends too (kento-mode `pve`/`pve-vm`), where a
# corosync partition still drops pmxcfs to read-only and surfaces the same
# wording through the failing `kento` invocation. The message substring
# ("Read-only file system") matches RealKento::QUORUM_MARKERS.
quorum_guard() {
  if [ -n "${FAKE_KENTO_QUORUM_LOST:-}" ]; then
    printf 'kento: error: cfs-locked operation - Read-only file system (no quorum?)\n' >&2
    exit 2
  fi
}

# Read the whole state object on stdout.
read_state() {
  ensure_state
  cat "$(fake_kento_state)"
}

# Atomically replace the state with stdin (write to a temp + mv). The state
# file is kept world-writable (0666): RealKento::run() env_clear()s before
# exec, so the shim runs under whatever uid invoked the helper (often root
# via sudo) AND the soak driver (unprivileged) also rewrites it to inject
# instances — both must be able to replace it.
write_state() {
  local f tmp
  f="$(fake_kento_state)"
  tmp="${f}.tmp.$$"
  cat >"$tmp"
  chmod 0666 "$tmp" 2>/dev/null || true
  mv "$tmp" "$f"
}

# Does an instance with this name exist? (0 = yes, 1 = no)
instance_exists() {
  local name="$1"
  read_state | jq -e --arg n "$name" '.instances | any(.name == $n)' >/dev/null
}

# Add (or replace) an instance row. The instance is passed as a compact JSON
# object on stdin and upserted by its `.name` (kento's primary key).
upsert_instance() {
  local obj
  obj="$(cat)"
  read_state | jq --argjson new "$obj" '(.instances |= map(select(.name != $new.name))) | .instances += [$new]' | write_state
}

# Remove an instance row by name.
remove_instance() {
  local name="$1"
  read_state | jq --arg n "$name" '.instances |= map(select(.name != $n))' | write_state
}
