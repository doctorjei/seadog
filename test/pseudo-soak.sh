#!/usr/bin/env bash
# pseudo-soak — drive the REAL seadog binaries through a full lifecycle
# against the fake-PVE shims (test/fake-pve), with NO real PVE and NO sshd.
#
# It proves RealKento (the feature-gated qm/pct/kento/pvesh backend) end to
# end: list_guests enumeration + parsing, provision, teardown triangulation,
# the sweep reap path, anomaly/heads-up survival, the out-of-range refusal,
# and the watch flock singleton.
#
# seadog-priv has an euid==0 guard, so its verbs run as real root via
# `sudo env ... seadog-priv <verb>` (sudoers env_reset means the SEADOG_*/
# FAKE_PVE_STATE env must be passed explicitly through `sudo env`). The
# front-end `seadog` runs unprivileged with $SEADOG_SUDO=sudo so it elevates
# the same way prod does.
#
# Usage: test/pseudo-soak.sh [BUILD_DIR]
#   BUILD_DIR: dir holding the built `seadog` + `seadog-priv` (default:
#              target/debug, built with --features real-kento for the helper).
#
# Re-runnable + idempotent: it cleans its own temp sandbox each run.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAKE_PVE_DIR="${REPO_DIR}/test/fake-pve"
BUILD_DIR="${1:-${REPO_DIR}/target/debug}"

PASS=0
FAIL=0

pass() {
  printf 'PASS: %s\n' "$1"
  PASS=$((PASS + 1))
}

fail() {
  printf 'FAIL: %s\n' "$1"
  FAIL=$((FAIL + 1))
}

# --- 1. Build the binaries (helper needs --features real-kento) ---
build() {
  printf '== building binaries ==\n'
  # shellcheck source=/dev/null
  . "$HOME/.cargo/env"
  ( cd "$REPO_DIR" && cargo build --features real-kento -p seadog-priv )
  ( cd "$REPO_DIR" && cargo build -p seadog )
}

# --- 2. Sandbox: temp config/db/lock/state + fakes on PATH ---
SANDBOX=""
setup() {
  SANDBOX="$(mktemp -d /tmp/seadog-soak.XXXXXX)"
  export SEADOG_CONFIG="${SANDBOX}/config.yaml"
  export SEADOG_DB="${SANDBOX}/seadog.db"
  export SEADOG_WATCHER_LOCK="${SANDBOX}/watcher.lock"
  export SEADOG_AUTHORIZED_KEYS="${SANDBOX}/authorized_keys"
  # RealKento::run() env_clear()s before exec, so the fake shims it spawns can
  # NOT see a sandbox-specific $FAKE_PVE_STATE — they fall back to the shims'
  # built-in default. So we pin BOTH sides to that exact default path and let
  # our own (unprivileged) inspection/injection use the same file. It is kept
  # world-writable by the shims so the root-run helper and this driver can
  # both replace it.
  export FAKE_PVE_STATE="/tmp/fake-pve/state.json"
  # Front-end elevation knobs: our built helper, no setsid (so the watcher
  # child stays in our process group and we can reason about it).
  export SEADOG_PRIV_BIN="${BUILD_DIR}/seadog-priv"
  export SEADOG_SETSID=""
  # RealKento::run also pins PATH=/usr/sbin:/usr/bin:/sbin:/bin (SAFE_PATH),
  # so it ALWAYS resolves qm/pct/kento/pvesh from there, ignoring our PATH. To
  # exercise the real helper against the fakes we must make the fakes
  # reachable on that fixed path: symlink them into /usr/sbin (where real
  # qm/pct live on a PVE node). Removed again by cleanup.
  install_fakes_on_safe_path
  # Env that must survive `sudo` (env_reset) to reach the helper itself. (The
  # fakes get env_cleared anyway, hence the fixed FAKE_PVE_STATE above.)
  PRESERVE_ENV="SEADOG_CONFIG,SEADOG_DB,SEADOG_WATCHER_LOCK"
  # The front-end treats $SEADOG_SUDO as a single argv token, so a multi-word
  # `sudo --preserve-env=…` cannot go there. Drop a one-program wrapper that
  # IS that sudo invocation and point the front-end at it.
  SUDO_WRAP="${SANDBOX}/sudo-preserve"
  printf '#!/usr/bin/env bash\nexec sudo --preserve-env=%s "$@"\n' "$PRESERVE_ENV" >"$SUDO_WRAP"
  chmod +x "$SUDO_WRAP"
  export SEADOG_SUDO="$SUDO_WRAP"
  # Reset the shared fake state (a prior run may have left it root-owned, so
  # remove via sudo) and recreate it world-writable.
  sudo rm -rf "$(dirname "$FAKE_PVE_STATE")"
  mkdir -p "$(dirname "$FAKE_PVE_STATE")"
  printf '%s\n' '{"guests":[]}' >"$FAKE_PVE_STATE"
  chmod 0666 "$FAKE_PVE_STATE"
  : >"$SEADOG_AUTHORIZED_KEYS"
  write_config

  # The front-end's `create`/`destroy` fire an opportunistic `watch` via
  # spawn_watcher(). To keep that detached reaper from racing our explicit
  # sweeps (it would reap the same expired env from under us), we HOLD the
  # watcher flock for the whole soak on fd 9 — every spawned watcher then
  # observes AlreadyHeld and exits immediately without sweeping. We release
  # it only for the dedicated watch-singleton scenario.
  : >"$SEADOG_WATCHER_LOCK"
  chmod 0666 "$SEADOG_WATCHER_LOCK"
  exec 9>"$SEADOG_WATCHER_LOCK"
  flock -n 9 || true
}

# Release the soak-held watcher flock so the watch-singleton scenario can
# exercise acquisition itself.
release_watcher_lock() {
  flock -u 9 2>/dev/null || true
  exec 9>&- 2>/dev/null || true
}

# The SAFE_PATH dir RealKento pins; the fakes are symlinked here so the real
# helper finds them. /usr/sbin is in RealKento's SAFE_PATH and is where the
# real qm/pct live, so this mirrors prod resolution.
SAFE_BIN="/usr/sbin"
FAKE_SHIMS="qm pct kento pvesh"
install_fakes_on_safe_path() {
  local shim
  for shim in $FAKE_SHIMS; do
    sudo ln -sf "${FAKE_PVE_DIR}/${shim}" "${SAFE_BIN}/${shim}"
  done
}
remove_fakes_from_safe_path() {
  local shim
  for shim in $FAKE_SHIMS; do
    # Only remove if it is OUR symlink into the fake dir (never a real tool).
    if [ -L "${SAFE_BIN}/${shim}" ] && [ "$(readlink "${SAFE_BIN}/${shim}")" = "${FAKE_PVE_DIR}/${shim}" ]; then
      sudo rm -f "${SAFE_BIN}/${shim}"
    fi
  done
}

write_config() {
  cat >"$SEADOG_CONFIG" <<'YAML'
reaper_enabled: true
cadence:
  fast: 0s
  idle: 60m
allocation:
  vmid_range: [10000, 10999]
  ip_pool:
    range: [192.168.0.192, 192.168.0.254]
    gateway: 192.168.0.1
    prefix: 24
  caps:
    max_lxc_per_owner: 8
    max_vm_per_owner: 3
images:
  loom: { ref: "registry.example.com/loom:1.0", modes: [lxc] }
owners: {}
identity:
  threshold: 0.6
  weights:
    network: 3
    disk: 3
    machine: 2
    memory: 0
    cores: 0
lifecycle:
  age_floor: 5m
  default_duration: 30m
  default_ttl: 1h
  grace: 10m
  herd_cap: 10
retention:
  terminal: 7d
notify:
  journald: true
  command: null
  dir: null
  reescalate: 30m
YAML
}

cleanup() {
  remove_fakes_from_safe_path 2>/dev/null || true
  # The shared fake state may be root-owned (helper wrote it under sudo).
  if [ -n "${FAKE_PVE_STATE:-}" ]; then
    sudo rm -rf "$(dirname "$FAKE_PVE_STATE")" 2>/dev/null || true
  fi
  if [ -n "$SANDBOX" ] && [ -d "$SANDBOX" ]; then
    rm -rf "$SANDBOX"
  fi
}
trap cleanup EXIT

# Run seadog-priv as REAL root, preserving the sandbox env across `sudo`
# (sudoers env_reset drops it otherwise). Echoes the helper's stdout.
priv() {
  local rc=0
  sudo --preserve-env="$PRESERVE_ENV" "${SEADOG_PRIV_BIN}" "$@" || rc=$?
  # Root may have created root-owned WAL/SHM sidecars; keep the whole DB set
  # world-writable so the agent front-end + our sqlite3 reads can still touch
  # the shared WAL (prod uses a shared `seadog` group for the same reason).
  share_db_perms
  return "$rc"
}

# Make the DB consistent + shareable across the agent/root uid boundary.
#
# The front-end (agent) and the helper (root) run as different uids on
# separate sqlite connections. A row the agent commits lives in the -wal
# until checkpointed; the root helper opening the DB may not observe those
# uncheckpointed frames reliably across the uid boundary. So we (a) fold the
# WAL into the main DB file (TRUNCATE checkpoint) so the main file is
# authoritative, and (b) keep the DB + sidecars world-writable (prod uses a
# shared `seadog` group for the same reason). Best-effort + sudo because root
# may own freshly-created sidecars.
share_db_perms() {
  sudo chmod 0666 "$SEADOG_DB" "${SEADOG_DB}-wal" "${SEADOG_DB}-shm" 2>/dev/null || true
  if [ -f "$SEADOG_DB" ]; then
    sqlite3 "$SEADOG_DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
  fi
}

# Run the unprivileged front-end (owner injected, as sshd would).
frontend() {
  local owner="$1"
  shift
  "${BUILD_DIR}/seadog" --owner "$owner" "$@"
}

# jq helpers over the fake guest table.
guest_count() {
  jq '.guests | length' "$FAKE_PVE_STATE"
}
guest_exists_in_table() {
  jq -e --argjson v "$1" '.guests | any(.vmid == $v)' "$FAKE_PVE_STATE" >/dev/null
}
db_status() {
  sqlite3 "$SEADOG_DB" "SELECT status FROM envs WHERE guid='$1';"
}

# ---------------------------------------------------------------------------
main() {
  build
  setup
  printf '\n== scenario: create via front-end ==\n'

  # (a) front-end create --image loom: allocates, writes DB row, elevates
  #     provision → guest appears in the fake table with markers.
  local create_json guid vmid
  if create_json="$(frontend jei create --image loom 2>/dev/null)"; then
    share_db_perms
    guid="$(printf '%s' "$create_json" | jq -r '.id')"
    vmid="$(printf '%s' "$create_json" | jq -r '.vmid')"
    if guest_exists_in_table "$vmid"; then
      pass "create: guest vmid $vmid present in fake table"
    else
      fail "create: guest vmid $vmid missing from fake table"
    fi
    # Markers: seadog- name + desc-GUID + desc-owner + correct MAC.
    local g_name g_desc g_mac db_mac
    g_name="$(jq -r --argjson v "$vmid" '.guests[] | select(.vmid==$v) | .name' "$FAKE_PVE_STATE")"
    g_desc="$(jq -r --argjson v "$vmid" '.guests[] | select(.vmid==$v) | .description' "$FAKE_PVE_STATE")"
    g_mac="$(jq -r --argjson v "$vmid" '.guests[] | select(.vmid==$v) | .mac' "$FAKE_PVE_STATE")"
    db_mac="$(sqlite3 "$SEADOG_DB" "SELECT mac FROM envs WHERE guid='$guid';")"
    if [[ "$g_name" == seadog-* ]]; then pass "create: guest has seadog- name ($g_name)"; else fail "create: guest name not seadog- ($g_name)"; fi
    if printf '%s' "$g_desc" | grep -q "seadog-guid:$guid"; then pass "create: desc carries guid marker"; else fail "create: desc missing guid marker"; fi
    if printf '%s' "$g_desc" | grep -q "seadog-owner:jei"; then pass "create: desc carries owner marker"; else fail "create: desc missing owner marker"; fi
    if [ "$g_mac" = "$db_mac" ] && [ -n "$g_mac" ]; then pass "create: guest MAC matches DB row ($g_mac)"; else fail "create: MAC mismatch (table=$g_mac db=$db_mac)"; fi
    if [ "$(db_status "$guid")" = "active" ]; then pass "create: DB row is active"; else fail "create: DB row not active"; fi
  else
    fail "create: front-end create failed"
    summary
    return
  fi

  printf '\n== scenario: sweep reaps an expired unanimous env ==\n'
  # Age the row relative to wall-clock `now` (the sweep uses wall-clock):
  # created well before the age floor, ttl already in the past.
  local now created_old ttl_past
  now="$(date +%s)"
  created_old=$((now - 7200))
  ttl_past=$((now - 100))
  sqlite3 "$SEADOG_DB" "UPDATE envs SET created_at=$created_old, ttl_deadline=$ttl_past, soft_deadline=$((ttl_past - 600)) WHERE guid='$guid';"
  share_db_perms
  local sweep_json
  sweep_json="$(priv sweep 2>/dev/null)"
  if [ "$(printf '%s' "$sweep_json" | jq -r '.reaped')" = "1" ]; then pass "sweep: reaped count is 1"; else fail "sweep: reaped count not 1 ($sweep_json)"; fi
  if ! guest_exists_in_table "$vmid"; then pass "sweep: guest torn down in fake table"; else fail "sweep: guest still present after reap"; fi
  if [ "$(db_status "$guid")" = "reaped" ]; then pass "sweep: DB row marked reaped"; else fail "sweep: DB row not reaped ($(db_status "$guid"))"; fi

  printf '\n== scenario: anomaly + foreign survive a sweep ==\n'
  # Re-create one real env to keep an active lease present.
  create_json="$(frontend jei create --image loom 2>/dev/null)"
  share_db_perms
  guid="$(printf '%s' "$create_json" | jq -r '.id')"
  vmid="$(printf '%s' "$create_json" | jq -r '.vmid')"
  # Inject a renamed/clobbered ANOMALY: a seadog DB row whose live guest has
  # had its name clobbered (no seadog- prefix) → desc-clobber/rename anomaly,
  # flagged not destroyed. Seed a DB row + a matching-but-renamed table guest.
  local anom_vmid=10050
  sqlite3 "$SEADOG_DB" "INSERT INTO envs (guid,vmid,mode,owner,image,name,ip,mac,created_at,ttl_deadline,soft_deadline,status) VALUES ('anomaly-guid',$anom_vmid,'lxc','jei','loom','seadog-jei-anom-aa11','192.168.0.210','de:ad:be:ef:00:11',$created_old,$ttl_past,$((ttl_past - 600)),'active');"
  jq --argjson v "$anom_vmid" '.guests += [{vmid:$v, mode:"lxc", name:"CLOBBERED-NAME", description:"seadog-guid:anomaly-guid\nseadog-owner:jei", mac:"de:ad:be:ef:00:11", tags:"", bridge:"vmbr0", model:"veth", vlan:null, machine:"", bios:"", scsihw:"", memory:1024, cores:2, disk_geometry:"local:anom", disk_size:null}]' "$FAKE_PVE_STATE" >"${FAKE_PVE_STATE}.t" && mv "${FAKE_PVE_STATE}.t" "$FAKE_PVE_STATE"
  # Inject a FOREIGN in-range guest: no seadog marker at all → heads-up,
  # never touched.
  local foreign_vmid=10060
  jq --argjson v "$foreign_vmid" '.guests += [{vmid:$v, mode:"vm", name:"someones-prod-db", description:"not ours", mac:"11:22:33:44:55:66", tags:"", bridge:"vmbr0", model:"virtio", vlan:null, machine:"q35", bios:"seabios", scsihw:"virtio-scsi-pci", memory:2048, cores:2, disk_geometry:"local-lvm:x", disk_size:null}]' "$FAKE_PVE_STATE" >"${FAKE_PVE_STATE}.t" && mv "${FAKE_PVE_STATE}.t" "$FAKE_PVE_STATE"
  share_db_perms

  sweep_json="$(priv sweep 2>/dev/null)"
  if [ "$(printf '%s' "$sweep_json" | jq -r '.flagged')" -ge 1 ]; then pass "sweep: anomaly flagged (flagged>=1)"; else fail "sweep: anomaly not flagged ($sweep_json)"; fi
  if [ "$(printf '%s' "$sweep_json" | jq -r '.heads_up')" -ge 1 ]; then pass "sweep: foreign heads-up (heads_up>=1)"; else fail "sweep: foreign not heads-up ($sweep_json)"; fi
  if guest_exists_in_table "$anom_vmid"; then pass "sweep: anomaly guest survives ($anom_vmid)"; else fail "sweep: anomaly guest was destroyed"; fi
  if guest_exists_in_table "$foreign_vmid"; then pass "sweep: foreign guest survives ($foreign_vmid)"; else fail "sweep: foreign guest was destroyed"; fi

  printf '\n== scenario: teardown of out-of-range vmid is refused ==\n'
  # Put a guest at 105 (a production vmid, out of range) in the table.
  jq '.guests += [{vmid:105, mode:"vm", name:"prod-critical", description:"seadog-guid:x\nseadog-owner:jei", mac:"aa:aa:aa:aa:aa:aa", tags:"", bridge:"vmbr0", model:"virtio", vlan:null, machine:"q35", bios:"seabios", scsihw:"virtio-scsi-pci", memory:2048, cores:2, disk_geometry:"local-lvm:x", disk_size:null}]' "$FAKE_PVE_STATE" >"${FAKE_PVE_STATE}.t" && mv "${FAKE_PVE_STATE}.t" "$FAKE_PVE_STATE"
  if priv teardown --owner jei --guid x --vmid 105 --mode vm >/dev/null 2>&1; then
    fail "teardown: out-of-range vmid 105 was NOT refused"
  else
    pass "teardown: out-of-range vmid 105 refused"
  fi
  if guest_exists_in_table 105; then pass "teardown: vmid 105 guest untouched"; else fail "teardown: vmid 105 guest was destroyed"; fi

  printf '\n== scenario: watch flock singleton (at most one runs) ==\n'
  # Drain every Active lease first so a watcher that DOES win the flock
  # self-extinguishes on its first (idle) tick instead of looping forever
  # (cadence.fast=0). With zero active envs the loop body runs once + exits.
  sqlite3 "$SEADOG_DB" "UPDATE envs SET status='reaped' WHERE status='active';"
  share_db_perms

  # (1) Deterministic guard: the soak already HOLDS the watcher flock (fd 9
  #     from setup), so a `watch` launched now MUST observe AlreadyHeld and
  #     report already-running.
  local held_json held_watcher
  held_json="$(timeout 30 sudo --preserve-env="$PRESERVE_ENV" "$SEADOG_PRIV_BIN" watch 2>/dev/null || true)"
  held_watcher="$(printf '%s' "$held_json" | jq -r '.watcher' 2>/dev/null || true)"
  if [ "$held_watcher" = "already-running" ]; then pass "watch: a watcher blocked while the lock is held reports already-running"; else fail "watch: overlapping watcher did not report already-running ($held_json)"; fi

  # Now release the soak-held lock so the next invocations can acquire it.
  release_watcher_lock

  # (2) Two overlapping invocations: with the lock now free at most one may
  #     run; the flock guarantees they never both run the loop concurrently.
  local out_a out_b
  ( timeout 30 sudo --preserve-env="$PRESERVE_ENV" "$SEADOG_PRIV_BIN" watch >"${SANDBOX}/watch_a.json" 2>/dev/null ) &
  local pid_a=$!
  ( timeout 30 sudo --preserve-env="$PRESERVE_ENV" "$SEADOG_PRIV_BIN" watch >"${SANDBOX}/watch_b.json" 2>/dev/null ) &
  local pid_b=$!
  wait "$pid_a" || true
  wait "$pid_b" || true
  out_a="$(cat "${SANDBOX}/watch_a.json" 2>/dev/null || true)"
  out_b="$(cat "${SANDBOX}/watch_b.json" 2>/dev/null || true)"
  local ran_count
  ran_count=0
  for out in "$out_a" "$out_b"; do
    local w
    w="$(printf '%s' "$out" | jq -r '.watcher' 2>/dev/null || true)"
    if [ "$w" = "ran" ]; then ran_count=$((ran_count + 1)); fi
  done
  # Both can legitimately report "ran" if they happen to run sequentially
  # (each released the lock before the next took it); what must NEVER happen
  # is two concurrent loops, which the (1) guard already proved is rejected.
  if [ "$ran_count" -ge 1 ]; then pass "watch: a watcher ran the loop when the lock was free (ran=$ran_count)"; else fail "watch: no watcher ran the loop"; fi

  summary
}

summary() {
  printf '\n========================================\n'
  printf 'pseudo-soak summary: %d passed, %d failed\n' "$PASS" "$FAIL"
  printf '========================================\n'
  if [ "$FAIL" -ne 0 ]; then
    exit 1
  fi
}

main "$@"
