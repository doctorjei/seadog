#!/usr/bin/env bash
# Shared helpers for the fake-PVE shims (qm/pct/kento/pvesh).
#
# This file is SOURCED by the shims, never executed directly. It owns the
# single JSON guest-table state file ($FAKE_PVE_STATE) that every shim
# reads/writes through `jq`, plus the formatters that reproduce the exact
# `qm config`/`pct config`/`pvesh get /cluster/resources` output shapes the
# real RealKento parser consumes. See README.md for the schema + knobs.

set -euo pipefail

# Resolve the state file path (default under /tmp) and make sure it + its
# parent exist with an empty guest table, so a first read never fails.
fake_pve_state() {
  printf '%s' "${FAKE_PVE_STATE:-/tmp/fake-pve/state.json}"
}

ensure_state() {
  local f
  f="$(fake_pve_state)"
  mkdir -p "$(dirname "$f")"
  if [ ! -s "$f" ]; then
    printf '%s\n' '{"guests":[]}' >"$f"
    chmod 0666 "$f" 2>/dev/null || true
  fi
}

# Emit the pmxcfs read-only / no-quorum error and exit non-zero when the
# $FAKE_PVE_QUORUM_LOST knob is set, so the reaper's quorum-loss path is
# exercisable. The message substring matches RealKento::QUORUM_MARKERS.
quorum_guard() {
  if [ -n "${FAKE_PVE_QUORUM_LOST:-}" ]; then
    printf 'error: cfs-locked operation - Read-only file system (no quorum?)\n' >&2
    exit 2
  fi
}

# Read the whole state object on stdout.
read_state() {
  ensure_state
  cat "$(fake_pve_state)"
}

# Atomically replace the state with stdin (write to a temp + mv). The state
# file is kept world-writable (0666): RealKento::run() env_clear()s before
# exec, so the shims run under whatever uid invoked the helper (often root
# via sudo) AND the soak driver (unprivileged) also rewrites it to inject
# guests — both must be able to replace it.
write_state() {
  local f tmp
  f="$(fake_pve_state)"
  tmp="${f}.tmp.$$"
  cat >"$tmp"
  chmod 0666 "$tmp" 2>/dev/null || true
  mv "$tmp" "$f"
}

# Does a guest with this vmid exist? (0 = yes, 1 = no)
guest_exists() {
  local vmid="$1"
  read_state | jq -e --argjson v "$vmid" '.guests | any(.vmid == $v)' >/dev/null
}

# Look up a guest's mode ("lxc"|"vm") by vmid; empty if absent.
guest_mode() {
  local vmid="$1"
  read_state | jq -r --argjson v "$vmid" '.guests[] | select(.vmid == $v) | .mode'
}

# Add (or replace) a guest row. Args are passed as KEY=VALUE pairs after the
# vmid+mode; numeric fields (vlan/memory/cores/disk_size) are coerced to JSON
# numbers, everything else stays a string. Unset optional fields are null.
upsert_guest() {
  local vmid="$1" mode="$2"
  shift 2
  local name="" description="" mac="" tags="" bridge="" model="" vlan="null"
  local machine="" bios="" scsihw="" memory="null" cores="null"
  local disk_geometry="" disk_size="null"
  local pair key val
  for pair in "$@"; do
    key="${pair%%=*}"
    val="${pair#*=}"
    case "$key" in
      name) name="$val" ;;
      description) description="$val" ;;
      mac) mac="$val" ;;
      tags) tags="$val" ;;
      bridge) bridge="$val" ;;
      model) model="$val" ;;
      vlan) vlan="$val" ;;
      machine) machine="$val" ;;
      bios) bios="$val" ;;
      scsihw) scsihw="$val" ;;
      memory) memory="$val" ;;
      cores) cores="$val" ;;
      disk_geometry) disk_geometry="$val" ;;
      disk_size) disk_size="$val" ;;
    esac
  done
  read_state | jq --argjson v "$vmid" --arg mode "$mode" --arg name "$name" --arg description "$description" --arg mac "$mac" --arg tags "$tags" --arg bridge "$bridge" --arg model "$model" --argjson vlan "$vlan" --arg machine "$machine" --arg bios "$bios" --arg scsihw "$scsihw" --argjson memory "$memory" --argjson cores "$cores" --arg disk_geometry "$disk_geometry" --argjson disk_size "$disk_size" '(.guests |= map(select(.vmid != $v))) | .guests += [{vmid:$v, mode:$mode, name:$name, description:$description, mac:$mac, tags:$tags, bridge:$bridge, model:$model, vlan:$vlan, machine:$machine, bios:$bios, scsihw:$scsihw, memory:$memory, cores:$cores, disk_geometry:$disk_geometry, disk_size:$disk_size}]' | write_state
}

# Mutate a single field on an existing guest (used by `set`).
set_guest_field() {
  local vmid="$1" key="$2" val="$3"
  read_state | jq --argjson v "$vmid" --arg k "$key" --arg val "$val" '(.guests[] | select(.vmid == $v))[$k] |= $val' | write_state
}

# Append a tag (comma-joined) to an existing guest.
add_guest_tag() {
  local vmid="$1" tag="$2"
  read_state | jq --argjson v "$vmid" --arg t "$tag" '(.guests[] | select(.vmid == $v) | .tags) |= (if . == "" then $t else . + "," + $t end)' | write_state
}

# Remove a guest row by vmid.
remove_guest() {
  local vmid="$1"
  read_state | jq --argjson v "$vmid" '.guests |= map(select(.vmid != $v))' | write_state
}

# PVE percent-encodes a `--description` body (notably newline -> %0A and
# `:` -> %3A) when it round-trips it through the config. Reproduce that so
# the RealKento parser's pve_unescape path is exercised end-to-end.
pve_escape_desc() {
  local s="$1"
  s="${s//%/%25}"
  s="${s//:/%3A}"
  s="${s//$'\n'/%0A}"
  printf '%s' "$s"
}

# Build the `net0:` config line for a guest from its row (stdin = one guest
# JSON object). VM form: `<model>=<mac>,bridge=..,tag=..`. CT form:
# `name=eth0,bridge=..,hwaddr=..,tag=..,type=veth`.
emit_net0_line() {
  local mode="$1" model="$2" mac="$3" bridge="$4" vlan="$5"
  local line=""
  if [ -z "$mac" ] && [ -z "$bridge" ]; then
    return 0
  fi
  if [ "$mode" = "lxc" ]; then
    line="name=eth0"
    if [ -n "$bridge" ]; then line="${line},bridge=${bridge}"; fi
    if [ -n "$mac" ]; then line="${line},hwaddr=${mac}"; fi
    if [ "$vlan" != "null" ] && [ -n "$vlan" ]; then line="${line},tag=${vlan}"; fi
    line="${line},type=veth"
  else
    local m="${model:-virtio}"
    line="${m}=${mac}"
    if [ -n "$bridge" ]; then line="${line},bridge=${bridge}"; fi
    if [ "$vlan" != "null" ] && [ -n "$vlan" ]; then line="${line},tag=${vlan}"; fi
  fi
  printf 'net0: %s\n' "$line"
}

# Print one guest's `qm config`/`pct config` text for vmid $1. The key set
# mirrors what RealKento::parse_guest_config reads. Exits 1 (with a realistic
# message) when the guest is absent.
emit_guest_config() {
  local vmid="$1"
  if ! guest_exists "$vmid"; then
    printf 'Configuration file for guest %s does not exist\n' "$vmid" >&2
    return 1
  fi
  local g mode name description mac tags bridge model vlan machine bios scsihw memory cores disk_geometry disk_size
  g="$(read_state | jq -c --argjson v "$vmid" '.guests[] | select(.vmid == $v)')"
  mode="$(printf '%s' "$g" | jq -r '.mode')"
  name="$(printf '%s' "$g" | jq -r '.name')"
  description="$(printf '%s' "$g" | jq -r '.description')"
  mac="$(printf '%s' "$g" | jq -r '.mac')"
  tags="$(printf '%s' "$g" | jq -r '.tags')"
  bridge="$(printf '%s' "$g" | jq -r '.bridge')"
  model="$(printf '%s' "$g" | jq -r '.model')"
  vlan="$(printf '%s' "$g" | jq -r '.vlan')"
  machine="$(printf '%s' "$g" | jq -r '.machine')"
  bios="$(printf '%s' "$g" | jq -r '.bios')"
  scsihw="$(printf '%s' "$g" | jq -r '.scsihw')"
  memory="$(printf '%s' "$g" | jq -r '.memory')"
  cores="$(printf '%s' "$g" | jq -r '.cores')"
  disk_geometry="$(printf '%s' "$g" | jq -r '.disk_geometry')"
  disk_size="$(printf '%s' "$g" | jq -r '.disk_size')"

  if [ "$mode" = "lxc" ]; then
    printf 'arch: amd64\n'
    if [ -n "$name" ]; then printf 'hostname: %s\n' "$name"; fi
  elif [ -n "$name" ]; then
    printf 'name: %s\n' "$name"
  fi
  if [ "$cores" != "null" ]; then printf 'cores: %s\n' "$cores"; fi
  if [ -n "$description" ]; then printf 'description: %s\n' "$(pve_escape_desc "$description")"; fi
  if [ -n "$bios" ]; then printf 'bios: %s\n' "$bios"; fi
  if [ -n "$machine" ]; then printf 'machine: %s\n' "$machine"; fi
  if [ "$memory" != "null" ]; then printf 'memory: %s\n' "$memory"; fi
  emit_net0_line "$mode" "$model" "$mac" "$bridge" "$vlan"
  if [ -n "$scsihw" ]; then printf 'scsihw: %s\n' "$scsihw"; fi
  if [ -n "$disk_geometry" ]; then
    if [ "$mode" = "lxc" ]; then
      if [ "$disk_size" != "null" ]; then printf 'rootfs: %s,size=%s\n' "$disk_geometry" "$(bytes_to_size "$disk_size")"; else printf 'rootfs: %s\n' "$disk_geometry"; fi
    elif [ "$disk_size" != "null" ]; then
      printf 'scsi0: %s,size=%s\n' "$disk_geometry" "$(bytes_to_size "$disk_size")"
    else
      printf 'scsi0: %s\n' "$disk_geometry"
    fi
  fi
  if [ -n "$tags" ]; then printf 'tags: %s\n' "$tags"; fi
}

# Convert a byte count to a `<n>G` string when it divides evenly into GiB,
# else emit raw bytes (the parser handles both forms).
bytes_to_size() {
  local b="$1" gib=$((1024 * 1024 * 1024))
  if [ "$((b % gib))" -eq 0 ]; then
    printf '%sG' "$((b / gib))"
  else
    printf '%s' "$b"
  fi
}

# Emit the `pvesh get /cluster/resources --output-format json` array: one
# node row, then a qemu/lxc row per guest. RealKento::parse_resources keeps
# only the qemu/lxc rows with a vmid.
emit_cluster_resources() {
  read_state | jq -c '[{type:"node", node:"fake", status:"online"}] + (.guests | map({type:(if .mode == "lxc" then "lxc" else "qemu" end), vmid:.vmid, node:"fake", name:.name, status:"running"}))'
}
