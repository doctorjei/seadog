#!/usr/bin/env bash
# pseudo-soak — drive the REAL seadog binaries through a full lifecycle
# against the fake `kento` shim (test/fake-kento), with NO real backend and NO
# sshd.
#
# It proves RealKento (the feature-gated kento backend) end to end:
# `kento list` enumeration + parsing, `kento inspect --json` signal parsing,
# provision (create + read-back), teardown triangulation, the sweep reap
# path, anomaly/foreign survival, the owner-mismatch teardown refusal, and the
# watch flock singleton.
#
# seadog is kento-native: ALL guest ops route through the `kento` CLI, which
# addresses instances BY NAME (never a vmid) and carries the seadog identity
# anchor in injected env (SEADOG_GUID / SEADOG_OWNER), read back via `kento
# inspect --json`. The fake `kento` records each created instance into a shared
# JSON instance table so a create -> list/inspect -> destroy roundtrip works.
#
# seadog-priv has an euid==0 guard, so its verbs run as real root via
# `sudo env ... seadog-priv <verb>` (sudoers env_reset means the SEADOG_*/
# FAKE_KENTO_STATE env must be passed explicitly through `sudo env`). The
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
FAKE_KENTO_DIR="${REPO_DIR}/test/fake-kento"
BUILD_DIR="${1:-${REPO_DIR}/target/debug}"

# Source the fake's shared lib so instance injection reuses the SAME
# upsert-by-name `jq` filter the shim itself uses (single source of truth for
# the table's write semantics — no duplicated filter to drift). It owns
# read_state/write_state/upsert_instance/remove_instance over $FAKE_KENTO_STATE.
# shellcheck source=test/fake-kento/_lib.sh
. "${FAKE_KENTO_DIR}/_lib.sh"

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

# --- 2. Sandbox: temp config/db/lock/state + fake kento on PATH ---
SANDBOX=""
setup() {
  SANDBOX="$(mktemp -d /tmp/seadog-soak.XXXXXX)"
  export SEADOG_CONFIG="${SANDBOX}/config.yaml"
  export SEADOG_DB="${SANDBOX}/seadog.db"
  export SEADOG_WATCHER_LOCK="${SANDBOX}/watcher.lock"
  export SEADOG_AUTHORIZED_KEYS="${SANDBOX}/authorized_keys"
  # RealKento::run() env_clear()s before exec, so the fake `kento` it spawns
  # can NOT see a sandbox-specific $FAKE_KENTO_STATE — it falls back to the
  # shim's built-in default. So we pin BOTH sides to that exact default path
  # and let our own (unprivileged) inspection/injection use the same file. It
  # is kept world-writable by the shim so the root-run helper and this driver
  # can both replace it.
  export FAKE_KENTO_STATE="/tmp/fake-kento/state.json"
  # Front-end elevation knobs: our built helper, no setsid (so the watcher
  # child stays in our process group and we can reason about it).
  export SEADOG_PRIV_BIN="${BUILD_DIR}/seadog-priv"
  export SEADOG_SETSID=""
  # RealKento::run also pins PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:
  # /usr/bin:/sbin:/bin (SAFE_PATH), so it ALWAYS resolves `kento` from there,
  # ignoring our PATH. To exercise the real helper against the fake we must
  # make the fake reachable on that fixed path: symlink it into /usr/local/bin
  # (where `kento` installs on a real host). Removed again by cleanup.
  install_fakes_on_safe_path
  # Env that must survive `sudo` (env_reset) to reach the helper itself. (The
  # fake gets env_cleared anyway, hence the fixed FAKE_KENTO_STATE above.)
  PRESERVE_ENV="SEADOG_CONFIG,SEADOG_DB,SEADOG_WATCHER_LOCK"
  # The front-end treats $SEADOG_SUDO as a single argv token, so a multi-word
  # `sudo --preserve-env=…` cannot go there. Drop a one-program wrapper that
  # IS that sudo invocation and point the front-end at it.
  SUDO_WRAP="${SANDBOX}/sudo-preserve"
  printf '#!/usr/bin/env bash\nexec sudo --preserve-env=%s "$@"\n' "$PRESERVE_ENV" >"$SUDO_WRAP"
  chmod +x "$SUDO_WRAP"
  export SEADOG_SUDO="$SUDO_WRAP"
  # Reset the shared fake state (a prior run may have left it root-owned, so
  # remove via sudo) and recreate it world-writable as an empty instance table.
  sudo rm -rf "$(dirname "$FAKE_KENTO_STATE")"
  mkdir -p "$(dirname "$FAKE_KENTO_STATE")"
  printf '%s\n' '{"instances":[]}' >"$FAKE_KENTO_STATE"
  chmod 0666 "$FAKE_KENTO_STATE"
  : >"$SEADOG_AUTHORIZED_KEYS"
  write_config

  # The front-end's `create`/`destroy` fire an opportunistic `watch` via
  # spawn_watcher(). To keep that detached reaper from racing our explicit
  # sweeps (it would reap the same expired env from under us), we HOLD the
  # watcher flock for the whole soak on fd 9 — every spawned watcher then
  # observes AlreadyHeld and exits immediately without sweeping. An explicit
  # `priv sweep` still runs (it stands in for a wedged watcher and overrides —
  # see `priv_sweep`); we release the hold only for the dedicated
  # watch-singleton scenario.
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

# The SAFE_PATH dir RealKento pins; the fake `kento` is symlinked here so the
# real helper finds it. /usr/local/bin is in RealKento's SAFE_PATH and is
# where `kento` installs on a real host, so this mirrors prod resolution.
SAFE_BIN="/usr/local/bin"
FAKE_SHIMS="kento"
# The EXACT SAFE_PATH RealKento pins before exec (crates/core/src/kento.rs:
# `const SAFE_PATH`). RealKento env_clear()s and resolves `kento` from THIS
# path, so a real `kento` anywhere on it would be the one our root-run helper
# actually spawns — the disposable-host guard must scan all of these dirs, not
# just the one we install into.
SAFE_PATH_DIRS="/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin"

# Disposable-host guard. This test symlinks a fake `kento` into /usr/local/bin
# and runs seadog-priv as real root — catastrophic on a real seadog/kento host
# (it would let the soak's destroys reach genuine guests). Before ANY host
# mutation, refuse to run if a real `kento` already lives ANYWHERE on the
# SAFE_PATH RealKento resolves from (not just our install dir), unless it is
# already OUR own symlink into ${FAKE_KENTO_DIR} (so a re-run after a clean
# prior run still passes). Uses the same ownership test as
# remove_fakes_from_safe_path.
assert_disposable_host() {
  local tool dir path
  for tool in $FAKE_SHIMS; do
    for dir in $SAFE_PATH_DIRS; do
      path="${dir}/${tool}"
      if [ -e "$path" ] || [ -L "$path" ]; then
        # Our own symlink into the fake dir (only ever installed in $SAFE_BIN)
        # is fine — a clean re-run leaves it behind.
        if [ -L "$path" ] && [ "$(readlink "$path")" = "${FAKE_KENTO_DIR}/${tool}" ]; then
          continue
        fi
        printf "pseudo-soak: refusing to run — found a real '%s' at %s (on RealKento's SAFE_PATH). This test symlinks a fake kento into %s and runs seadog-priv as real root; it is for DISPOSABLE hosts only (CI ephemeral runners), never a real seadog/kento host.\n" "$tool" "$path" "$SAFE_BIN" >&2
        exit 1
      fi
    done
  done
}
install_fakes_on_safe_path() {
  local shim
  for shim in $FAKE_SHIMS; do
    sudo ln -sf "${FAKE_KENTO_DIR}/${shim}" "${SAFE_BIN}/${shim}"
  done
}
remove_fakes_from_safe_path() {
  local shim
  for shim in $FAKE_SHIMS; do
    # Only remove if it is OUR symlink into the fake dir (never a real tool).
    if [ -L "${SAFE_BIN}/${shim}" ] && [ "$(readlink "${SAFE_BIN}/${shim}")" = "${FAKE_KENTO_DIR}/${shim}" ]; then
      sudo rm -f "${SAFE_BIN}/${shim}"
    fi
  done
}

write_config() {
  cat >"$SEADOG_CONFIG" <<'YAML'
reaper_enabled: true
cadence:
  fast: 30s
  idle: 60m
allocation:
  bridge: vmbr0
  ip_pool:
    range: [192.168.0.192, 192.168.0.254]
    gateway: 192.168.0.1
    prefix: 24
  caps:
    max_lxc_per_owner: 8
    max_vm_per_owner: 3
images:
  loom: { ref: "registry.example.com/loom:1.0", modes: [lxc] }
  vmimg: { ref: "registry.example.com/vmimg:1.0", modes: [vm] }
owners: {}
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
  if [ -n "${FAKE_KENTO_STATE:-}" ]; then
    sudo rm -rf "$(dirname "$FAKE_KENTO_STATE")" 2>/dev/null || true
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

# Run an explicit one-shot `priv sweep`.
#
# The sweep is flock-gated: it takes the SAME watcher lock so it never races a
# concurrent watcher reap. The soak HOLDS that lock on fd 9 for the whole run
# (to suppress the opportunistic watchers the front-end spawns), so the
# one-shot sees the lock AlreadyHeld and decides via heartbeat staleness:
# - **fresh** heartbeat (`now - last_sweep_at <= 3× cadence.fast`) ⇒ it
#   assumes a healthy watcher is actively reaping and SKIPS ("watcher active");
# - **stale/absent** heartbeat ⇒ it assumes a wedged watcher and OVERRIDES,
#   running the sweep anyway (the failure-domain-diverse backstop).
# Our fd-9 holder is NOT a real watcher and never writes a heartbeat, so we
# stand in for a wedged one: age the heartbeat well into the past before the
# sweep so the gating deterministically takes the override path and runs.
# `cadence.fast` is a NONZERO 30s (threshold = 3×30 = 90s), so a heartbeat
# pinned to epoch 0 is unambiguously stale relative to wall-clock `now` and the
# override path is deterministic (no same-second "fresh" race). The dedicated
# `honest flock-gating` scenario below exercises the fresh→SKIP arm too.
priv_sweep() {
  sqlite3 "$SEADOG_DB" "INSERT INTO heartbeat (id, last_sweep_at) VALUES (0, 0) ON CONFLICT(id) DO UPDATE SET last_sweep_at = 0;"
  share_db_perms
  priv sweep
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

# --- jq/sqlite helpers over the fake kento instance table + the DB ---

# How many instances does the fake kento table hold?
instance_count() {
  jq '.instances | length' "$FAKE_KENTO_STATE"
}
# Does an instance with this NAME exist in the fake kento table? (kento's key)
instance_exists_in_table() {
  jq -e --arg n "$1" '.instances | any(.name == $n)' "$FAKE_KENTO_STATE" >/dev/null
}
# A field of the instance NAMEd $1 (e.g. mac, mode, image, status).
instance_field() {
  jq -r --arg n "$1" --arg f "$2" '.instances[] | select(.name == $n) | .[$f]' "$FAKE_KENTO_STATE"
}
# A SEADOG_* env value of the instance NAMEd $1 (e.g. SEADOG_GUID).
instance_env() {
  jq -r --arg n "$1" --arg k "$2" \
    '.instances[] | select(.name == $n) | .environment[] | select(startswith($k + "=")) | sub("^[^=]*="; "")' \
    "$FAKE_KENTO_STATE"
}
db_status() {
  sqlite3 "$SEADOG_DB" "SELECT status FROM envs WHERE guid='$1';"
}

# Inject a raw instance object (compact JSON on stdin) into the fake kento
# table. Delegates to the shim's OWN `upsert_instance` (sourced from _lib.sh)
# so the upsert-by-name `jq` filter lives in exactly one place.
inject_instance() {
  upsert_instance
  chmod 0666 "$FAKE_KENTO_STATE" 2>/dev/null || true
}

# Fixture builder: emit a compact instance JSON object on stdout for the
# `kento inspect`/`list` schema, so the schema lives in ONE place instead of
# being copy-pasted as inline literals at each injection site.
#
#   make_instance <name> [jq-override-expr]
#
# Produces the base shape every injected instance shares (running, with the
# stable host-key fp dict). The optional second arg is a `jq` expression
# applied to the base object to set/override fields — e.g.
# '.mode="pve" | .vmid=10042 | .environment=["SEADOG_GUID=g"]'. `mac` is
# present-only (omitted by default — the LXC sentinel); add it via the
# override when modeling a VM.
make_instance() {
  local name="$1" override="${2:-.}"
  jq -nc --arg n "$name" \
    '{name:$n, mode:"lxc", image:"registry.example.com/loom:1.0", status:"running",
      environment:[], ssh_host_key_fingerprints:{ed25519:("SHA256:fp-ed25519-"+$n)}}' |
    jq -c "$override"
}

# ---------------------------------------------------------------------------
main() {
  assert_disposable_host
  build
  setup
  printf '\n== scenario: create via front-end ==\n'

  # (a) front-end create --image loom: allocates, writes DB row, elevates
  #     provision → instance appears in the fake kento table with the seadog
  #     identity anchor (SEADOG_GUID / SEADOG_OWNER) in injected env.
  local create_json guid name
  if create_json="$(frontend jei create --image loom 2>/dev/null)"; then
    share_db_perms
    guid="$(printf '%s' "$create_json" | jq -r '.id')"
    name="$(printf '%s' "$create_json" | jq -r '.name')"
    if instance_exists_in_table "$name"; then
      pass "create: instance $name present in fake kento table"
    else
      fail "create: instance $name missing from fake kento table"
    fi
    # Anchor + signals: seadog- name, SEADOG_GUID/SEADOG_OWNER injected env.
    # `loom` is an LXC, and kento reports a MAC for VM modes ONLY — so an LXC
    # has NO mac. Assert the `mac` field is ABSENT on the live inspect AND the
    # DB row records the empty "no MAC recorded" sentinel (NOT a fictional MAC).
    local i_guid i_owner i_mac db_mac
    i_guid="$(instance_env "$name" SEADOG_GUID)"
    i_owner="$(instance_env "$name" SEADOG_OWNER)"
    # `instance_field` prints jq `null` (→ literal "null") when the field is
    # absent; an LXC has no mac key, so we expect exactly that.
    i_mac="$(instance_field "$name" mac)"
    db_mac="$(sqlite3 "$SEADOG_DB" "SELECT mac FROM envs WHERE guid='$guid';")"
    if [[ "$name" == seadog-* ]]; then pass "create: instance has seadog- name ($name)"; else fail "create: instance name not seadog- ($name)"; fi
    if [ "$i_guid" = "$guid" ]; then pass "create: env carries SEADOG_GUID anchor"; else fail "create: SEADOG_GUID anchor mismatch (env=$i_guid guid=$guid)"; fi
    if [ "$i_owner" = "jei" ]; then pass "create: env carries SEADOG_OWNER anchor"; else fail "create: SEADOG_OWNER anchor wrong ($i_owner)"; fi
    if [ "$i_mac" = "null" ]; then pass "create(lxc): live instance has NO mac field (kento reports MAC for VM only)"; else fail "create(lxc): live instance should have no mac, got '$i_mac'"; fi
    if [ -z "$db_mac" ]; then pass "create(lxc): DB row records no MAC (empty sentinel)"; else fail "create(lxc): DB row MAC should be empty, got '$db_mac'"; fi
    if [ "$(db_status "$guid")" = "active" ]; then pass "create: DB row is active"; else fail "create: DB row not active"; fi
  else
    fail "create: front-end create failed"
    summary
    return
  fi

  printf '\n== scenario: VM create round-trips its MAC ==\n'
  # A VM keeps the passed `--mac`: kento accepts it (VM-only) and reports it
  # back via inspect, so the live instance AND the DB row carry that exact MAC.
  local vm_json vm_guid vm_name vm_i_mac vm_db_mac
  if vm_json="$(frontend jei create --image vmimg --mode vm 2>/dev/null)"; then
    share_db_perms
    vm_guid="$(printf '%s' "$vm_json" | jq -r '.id')"
    vm_name="$(printf '%s' "$vm_json" | jq -r '.name')"
    vm_i_mac="$(instance_field "$vm_name" mac)"
    vm_db_mac="$(sqlite3 "$SEADOG_DB" "SELECT mac FROM envs WHERE guid='$vm_guid';")"
    if [ -n "$vm_db_mac" ] && [ "$vm_i_mac" = "$vm_db_mac" ]; then
      pass "create(vm): live + DB MAC agree and are non-empty ($vm_i_mac)"
    else
      fail "create(vm): VM MAC should be non-empty + agree (live=$vm_i_mac db=$vm_db_mac)"
    fi
    # Tear the VM down so it does not perturb later sweep/herd assertions.
    priv teardown --owner jei --guid "$vm_guid" --mode vm >/dev/null 2>&1 || true
  else
    fail "create(vm): front-end VM create failed"
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
  sweep_json="$(priv_sweep)"
  if [ "$(printf '%s' "$sweep_json" | jq -r '.reaped')" = "1" ]; then pass "sweep: reaped count is 1"; else fail "sweep: reaped count not 1 ($sweep_json)"; fi
  if ! instance_exists_in_table "$name"; then pass "sweep: instance torn down in fake kento table"; else fail "sweep: instance still present after reap"; fi
  if [ "$(db_status "$guid")" = "reaped" ]; then pass "sweep: DB row marked reaped"; else fail "sweep: DB row not reaped ($(db_status "$guid"))"; fi

  printf '\n== scenario: anomaly + foreign survive a sweep ==\n'
  # Re-create one real env to keep an active lease present.
  create_json="$(frontend jei create --image loom 2>/dev/null)"
  share_db_perms
  guid="$(printf '%s' "$create_json" | jq -r '.id')"
  name="$(printf '%s' "$create_json" | jq -r '.name')"
  # Inject a renamed/clobbered ANOMALY: a seadog DB row whose live instance
  # has had its NAME clobbered (no longer matches the row) → NameMismatch
  # anomaly, flagged not destroyed. Seed a DB row + a matching-by-guid but
  # renamed live instance carrying the SEADOG_GUID anchor. (LXC ⇒ no mac on the
  # row OR the live instance — kento reports a MAC for VM only.)
  sqlite3 "$SEADOG_DB" "INSERT INTO envs (guid,vmid,mode,owner,image,name,ip,mac,created_at,ttl_deadline,soft_deadline,status) VALUES ('anomaly-guid',NULL,'lxc','jei','loom','seadog-jei-anom-aa11','192.168.0.210','',$created_old,$ttl_past,$((ttl_past - 600)),'active');"
  make_instance "CLOBBERED-NAME" \
    '.environment=["SEADOG_GUID=anomaly-guid","SEADOG_OWNER=jei"]' | inject_instance
  # Inject a FOREIGN instance: no SEADOG_GUID anchor at all → ignored entirely
  # (kento-native foreign is a no-op, never touched, never re-adopted). It is a
  # VM, so it carries a mac (VM modes report one).
  make_instance "someones-prod-db" \
    '.mode="vm" | .image="someone/else:prod" | .mac="11:22:33:44:55:66" | .environment=["FOO=bar"] | .ssh_host_key_fingerprints={}' | inject_instance
  share_db_perms

  sweep_json="$(priv_sweep)"
  if [ "$(printf '%s' "$sweep_json" | jq -r '.flagged')" -ge 1 ]; then pass "sweep: anomaly flagged (flagged>=1)"; else fail "sweep: anomaly not flagged ($sweep_json)"; fi
  if instance_exists_in_table "CLOBBERED-NAME"; then pass "sweep: anomaly instance survives (CLOBBERED-NAME)"; else fail "sweep: anomaly instance was destroyed"; fi
  if instance_exists_in_table "someones-prod-db"; then pass "sweep: foreign instance survives (someones-prod-db)"; else fail "sweep: foreign instance was destroyed"; fi
  # Foreign is a SILENT no-op (Classification::Foreign => {} in core::reap): it
  # is never re-adopted. Assert it did NOT mint a new Active DB row (no row at
  # all for its name) and was NOT counted in this sweep's `flagged`/`readopted`.
  local foreign_rows readopted_n
  foreign_rows="$(sqlite3 "$SEADOG_DB" "SELECT count(*) FROM envs WHERE name='someones-prod-db';")"
  if [ "$foreign_rows" = "0" ]; then pass "sweep: foreign instance was NOT re-adopted (no DB row)"; else fail "sweep: foreign instance gained a DB row ($foreign_rows)"; fi
  readopted_n="$(printf '%s' "$sweep_json" | jq -r '.readopted')"
  # Only the clobbered anomaly should account for the flag; nothing was
  # re-adopted this tick (the anomaly already has a row, the foreign is ignored).
  if [ "$readopted_n" = "0" ]; then pass "sweep: nothing re-adopted (foreign stays foreign)"; else fail "sweep: unexpected re-adoption ($sweep_json)"; fi
  # The freshly re-created real env is inside its age floor, so it is NOT
  # reaped this tick — it must still be live (proves the sweep didn't over-reap).
  if instance_exists_in_table "$name"; then pass "sweep: in-window real env untouched ($name)"; else fail "sweep: in-window real env was reaped"; fi

  printf '\n== scenario: a ghost instance does NOT blind the sweep ==\n'
  # Resilience contract (kento.rs::RealKento::list_instances): a per-instance
  # `kento inspect` failure (a "ghost" present in `kento list` but with no
  # backing guest — exit 255 on a real host) must be LOGGED + SKIPPED, never
  # abort the whole sweep. Prove it by placing a ghost ALONGSIDE a healthy
  # EXPIRED env and asserting the sweep still runs and reaps the healthy one:
  #   - healthy: a fresh Active DB row + matching live instance, ttl in the
  #     past + created before the age floor ⇒ ReapEligible ⇒ reaped;
  #   - ghost:   a live instance carrying `_inspect_fail` (the fake's
  #     inspect-exits-255 marker) + a SEADOG_GUID but NO DB row. With a
  #     WORKING inspect it would re-adopt as an orphan; because inspect FAILS
  #     it is skipped instead — so it neither aborts the sweep nor gains a row.
  # If list_instances were still all-or-nothing, the ghost's failing inspect
  # would propagate and the sweep would reap NOTHING (the healthy env would
  # survive) — that is exactly what this scenario rules out.
  local ghost_guid healthy_guid healthy_name
  ghost_guid="ghost-no-backing-guid"
  healthy_guid="healthy-expired-guid"
  healthy_name="seadog-jei-healthy-gh01"
  sqlite3 "$SEADOG_DB" "INSERT INTO envs (guid,vmid,mode,owner,image,name,ip,mac,created_at,ttl_deadline,soft_deadline,status) VALUES ('$healthy_guid',NULL,'lxc','jei','loom','$healthy_name','192.168.0.230','',$created_old,$ttl_past,$((ttl_past - 600)),'active');"
  make_instance "$healthy_name" \
    '.environment=["SEADOG_GUID='"$healthy_guid"'","SEADOG_OWNER=jei"]' | inject_instance
  # The ghost: appears in `kento list`, but its inspect exits non-zero.
  make_instance "seadog-jei-ghost-gh02" \
    '._inspect_fail=true | .environment=["SEADOG_GUID='"$ghost_guid"'","SEADOG_OWNER=jei"]' | inject_instance
  share_db_perms
  # Sanity: the ghost's inspect really does fail (the injected marker works),
  # so the assertions below test resilience, not a no-op fake.
  if ! /usr/local/bin/kento inspect "seadog-jei-ghost-gh02" --json >/dev/null 2>&1; then
    pass "ghost: fake kento inspect exits non-zero for the ghost"
  else
    fail "ghost: fake kento inspect unexpectedly succeeded for the ghost"
  fi
  local ghost_sweep_rc=0
  sweep_json="$(priv_sweep)" || ghost_sweep_rc=$?
  # 1. Non-abort: the sweep completed and emitted its JSON outcome.
  if [ "$ghost_sweep_rc" -eq 0 ] && printf '%s' "$sweep_json" | jq -e '.reaped' >/dev/null 2>&1; then
    pass "ghost: sweep did NOT abort (completed with an outcome despite the ghost)"
  else
    fail "ghost: sweep aborted or emitted no outcome (rc=$ghost_sweep_rc json=$sweep_json)"
  fi
  # 2. The healthy expired env WAS evaluated + reaped (the sweep saw past the
  #    ghost) — both the live instance and the DB row reflect the reap.
  if ! instance_exists_in_table "$healthy_name"; then pass "ghost: healthy expired env was still reaped (skip didn't blind the sweep)"; else fail "ghost: healthy expired env survived (the ghost blinded the sweep)"; fi
  if [ "$(db_status "$healthy_guid")" = "reaped" ]; then pass "ghost: healthy env's DB row marked reaped"; else fail "ghost: healthy env DB row not reaped ($(db_status "$healthy_guid"))"; fi
  # 3. The ghost was SKIPPED: it has no DB row and was NOT re-adopted (a
  #    working inspect would have orphaned+re-adopted it onto a fresh row).
  local ghost_rows
  ghost_rows="$(sqlite3 "$SEADOG_DB" "SELECT count(*) FROM envs WHERE guid='$ghost_guid';")"
  if [ "$ghost_rows" = "0" ]; then pass "ghost: skipped instance gained no DB row (not re-adopted)"; else fail "ghost: skipped instance was re-adopted ($ghost_rows rows)"; fi
  # Clean the ghost so it does not perturb later sweeps (it would be skipped
  # every tick, but the watch-singleton drain reasons about active leases).
  remove_instance "seadog-jei-ghost-gh02"
  chmod 0666 "$FAKE_KENTO_STATE" 2>/dev/null || true

  printf '\n== scenario: teardown by another owner is refused ==\n'
  # seadog-priv teardown is GUID-driven and re-validates owner against the DB
  # row. A request from a DIFFERENT owner (bob) for jei's env must be refused
  # with NO destroy — the critical security gate. The live instance for $guid
  # must survive. Capture stderr and assert it is the SPECIFIC owner-mismatch
  # gate (teardown.rs: "... (owner mismatch)"), so an unrelated error can't
  # masquerade as a pass.
  local mm_err mm_rc
  mm_rc=0
  mm_err="$(priv teardown --owner bob --guid "$guid" --mode lxc 2>&1 >/dev/null)" || mm_rc=$?
  if [ "$mm_rc" -ne 0 ] && printf '%s' "$mm_err" | grep -q 'owner mismatch'; then
    pass "teardown: another owner's request refused at the owner-mismatch gate"
  else
    fail "teardown: owner-mismatch refusal wrong (rc=$mm_rc err=$mm_err)"
  fi
  if instance_exists_in_table "$name"; then pass "teardown: jei's instance untouched ($name)"; else fail "teardown: jei's instance was destroyed"; fi

  printf '\n== scenario: teardown of an unknown guid (no DB row) is refused ==\n'
  # Cross-authority/unleased teardown: a guid with NO matching DB row must be
  # refused by the real seadog-priv with NO destroy (teardown.rs gate (1),
  # modeled on `no_db_row_is_refused`). We inject a LIVE instance carrying an
  # unknown guid (so the refusal can't be the trivial "already-gone" path) and
  # assert the refusal is the SPECIFIC no-such-lease gate ("unknown lease") and
  # that the live instance is untouched.
  make_instance "unleased-box" \
    '.environment=["SEADOG_GUID=ghost-guid","SEADOG_OWNER=jei"]' | inject_instance
  share_db_perms
  local nr_err nr_rc
  nr_rc=0
  nr_err="$(priv teardown --owner jei --guid ghost-guid --mode lxc 2>&1 >/dev/null)" || nr_rc=$?
  if [ "$nr_rc" -ne 0 ] && printf '%s' "$nr_err" | grep -q 'unknown lease'; then
    pass "teardown: unknown-guid request refused at the no-such-lease gate"
  else
    fail "teardown: no-DB-row refusal wrong (rc=$nr_rc err=$nr_err)"
  fi
  if instance_exists_in_table "unleased-box"; then pass "teardown: unleased live instance untouched (no destroy)"; else fail "teardown: unleased instance was destroyed"; fi
  # Clean the injected unleased instance so it does not perturb later sweeps.
  remove_instance "unleased-box"
  chmod 0666 "$FAKE_KENTO_STATE" 2>/dev/null || true

  printf '\n== scenario: pve (PVE-LXC) mode + vmid parse round-trip ==\n'
  # Exercise parse_kento_inspect's type-driven family collapse + vmid
  # extraction (kento.rs): inject a live instance reporting the REAL PVE-LXC
  # kento-mode `pve` (kento promotes PVE-LXC to bare `pve`, NOT `pve-lxc`; the
  # shim synthesizes the authoritative `type:"LXC"` for it) and a numeric
  # `vmid`, carrying a SEADOG_GUID but with NO DB row → the sweep classifies it
  # as an orphan and RE-ADOPTS it onto a fresh Active row. Because seadog parsed
  # the inspect, the re-adopted row must record Mode::Lxc (the type-LXC
  # collapse over bare `pve`) and the extracted vmid — proving both parse paths.
  make_instance "seadog-jei-pve-bb22" \
    '.mode="pve" | .vmid=10042 | .environment=["SEADOG_GUID=pve-guid","SEADOG_OWNER=jei"]' | inject_instance
  share_db_perms
  sweep_json="$(priv_sweep)"
  local pve_mode pve_vmid
  pve_mode="$(sqlite3 "$SEADOG_DB" "SELECT mode FROM envs WHERE guid='pve-guid';")"
  pve_vmid="$(sqlite3 "$SEADOG_DB" "SELECT vmid FROM envs WHERE guid='pve-guid';")"
  if [ "$pve_mode" = "lxc" ]; then pass "pve: bare-pve mode + type LXC parsed + collapsed to Mode::Lxc on the re-adopted row"; else fail "pve: mode not collapsed to lxc (got '$pve_mode')"; fi
  if [ "$pve_vmid" = "10042" ]; then pass "pve: vmid 10042 extracted + recorded"; else fail "pve: vmid not recorded (got '$pve_vmid')"; fi
  # Tear it down so it does not linger into the watch-singleton drain.
  priv teardown --owner jei --guid pve-guid --mode lxc >/dev/null 2>&1 || true

  printf '\n== scenario: honest flock-gating (fresh skips, aged overrides) ==\n'
  # cadence.fast is a NONZERO 30s ⇒ the stale-watcher threshold is 3×30=90s.
  # The soak HOLDS the watcher flock (fd 9), so a one-shot `priv sweep` sees
  # AlreadyHeld and decides via heartbeat staleness. Seed an expired env and
  # drive BOTH arms by moving ONLY the heartbeat:
  #   (a) FRESH heartbeat (now) ⇒ a healthy watcher is assumed active ⇒ the
  #       sweep SKIPS ("watcher active"), no reap.
  #   (b) AGED heartbeat (now - 10000 ≫ 90s) ⇒ a wedged watcher ⇒ the sweep
  #       OVERRIDES and runs, reaping the env.
  local fg_guid fg_json
  fg_guid="flock-gate-guid"
  sqlite3 "$SEADOG_DB" "INSERT INTO envs (guid,vmid,mode,owner,image,name,ip,mac,created_at,ttl_deadline,soft_deadline,status) VALUES ('$fg_guid',NULL,'lxc','jei','loom','seadog-jei-flockgate','192.168.0.220','',$created_old,$ttl_past,$((ttl_past - 600)),'active');"
  make_instance "seadog-jei-flockgate" \
    '.environment=["SEADOG_GUID='"$fg_guid"'","SEADOG_OWNER=jei"]' | inject_instance
  share_db_perms
  # (a) Fresh heartbeat ⇒ SKIP. Use wall-clock now so it is well within 90s.
  sqlite3 "$SEADOG_DB" "INSERT INTO heartbeat (id, last_sweep_at) VALUES (0, $(date +%s)) ON CONFLICT(id) DO UPDATE SET last_sweep_at = $(date +%s);"
  share_db_perms
  fg_json="$(priv sweep)"
  if [ "$(printf '%s' "$fg_json" | jq -r '.skipped // empty')" = "watcher active" ]; then pass "flock-gating: fresh heartbeat SKIPS (watcher active)"; else fail "flock-gating: fresh heartbeat did not skip ($fg_json)"; fi
  if [ "$(printf '%s' "$fg_json" | jq -r '.reaped')" = "0" ] && instance_exists_in_table "seadog-jei-flockgate"; then pass "flock-gating: skip left the expired env untouched"; else fail "flock-gating: skip still reaped ($fg_json)"; fi
  # (b) Aged heartbeat ⇒ OVERRIDE + reap.
  sqlite3 "$SEADOG_DB" "INSERT INTO heartbeat (id, last_sweep_at) VALUES (0, 0) ON CONFLICT(id) DO UPDATE SET last_sweep_at = 0;"
  share_db_perms
  fg_json="$(priv sweep)"
  if [ "$(printf '%s' "$fg_json" | jq -r '.overrode_stale_watcher // empty')" = "true" ]; then pass "flock-gating: aged heartbeat OVERRIDES the wedged watcher"; else fail "flock-gating: aged heartbeat did not override ($fg_json)"; fi
  if [ "$(printf '%s' "$fg_json" | jq -r '.reaped')" -ge 1 ] && ! instance_exists_in_table "seadog-jei-flockgate"; then pass "flock-gating: override reaped the expired env"; else fail "flock-gating: override did not reap ($fg_json)"; fi

  printf '\n== scenario: teardown by the owner destroys the env ==\n'
  # The rightful owner tears it down: GUID + owner + live-name all agree, so
  # the helper destroys by the live instance name (read from `kento list`).
  if priv teardown --owner jei --guid "$guid" --mode lxc >/dev/null 2>&1; then
    pass "teardown: owner request succeeded"
  else
    fail "teardown: owner request failed"
  fi
  if ! instance_exists_in_table "$name"; then pass "teardown: owner's instance destroyed ($name)"; else fail "teardown: owner's instance survived a valid teardown"; fi

  printf '\n== scenario: watch flock singleton (at most one runs) ==\n'
  # Drain every Active lease first so a watcher that DOES win the flock
  # self-extinguishes on its first (idle) tick instead of looping forever.
  # With zero active envs the loop body runs once + exits regardless of the
  # (nonzero) fast cadence.
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
