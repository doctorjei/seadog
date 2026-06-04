#!/usr/bin/env bash
#
# seadog installer — RUN ON THE PROXMOX HOST AS root. Idempotent: safe to
# re-run; every step guards before acting.
#
# Usage:
#   sudo ./deploy/install.sh [BUILD_DIR] [BOOTSTRAP_KEY] [BOOTSTRAP_OWNER]
#   ./deploy/install.sh --version
#   sudo ./deploy/install.sh --uninstall [--purge]
#   ./deploy/install.sh --help
#
# Positional install args:
#   BUILD_DIR        dir holding the two static-musl binaries
#                    (default: target/x86_64-unknown-linux-musl/release,
#                    or — when run from an unpacked release tarball — the
#                    dir alongside this deploy/ tree that holds the binaries)
#   BOOTSTRAP_KEY    a public key line to authorize, e.g.
#                    "ssh-ed25519 AAAA... alice@host"  (optional)
#   BOOTSTRAP_OWNER  the trusted owner name for that key (optional)
#
# Flags:
#   --version        print the version of the seadog binary that will be /
#                    is installed, then exit (does NOT require root).
#   --uninstall      reverse the non-data install steps (PRESERVES the
#                    config, authorized_keys, DB, testenv user + seadog
#                    group). Requires root.
#   --purge          with --uninstall, ALSO remove the data + identity
#                    (config, authorized_keys, DB, testenv user, seadog
#                    group, /etc/shells line). Requires root.
#   -h, --help       show this help and exit.
#
# Bootstrap key/owner may also come from $SEADOG_BOOTSTRAP_KEY and
# $SEADOG_BOOTSTRAP_OWNER. They are appended to the root-owned
# /etc/seadog/authorized_keys as a forced-command line; re-running never
# double-adds the same key.

set -euo pipefail

# --- paths / constants (canonical; keep in sync with the binaries) ---
LIBDIR="/usr/lib/seadog"
ETCDIR="/etc/seadog"
VARDIR="/var/lib/seadog"
RUNDIR="/run/seadog"
CONFIG="${ETCDIR}/config.yaml"
AUTHKEYS="${ETCDIR}/authorized_keys"
DB="${VARDIR}/seadog.db"
USER_NAME="testenv"
GROUP_NAME="seadog"
FRONTEND="${LIBDIR}/seadog"
PRIV="${LIBDIR}/seadog-priv"

# Drop-in / unit files we install (used by both install + uninstall).
SUDOERS_FILE="/etc/sudoers.d/seadog"
TMPFILES_FILE="/etc/tmpfiles.d/seadog.conf"
SSHD_DROPIN="/etc/ssh/sshd_config.d/seadog.conf"
SWEEPER_SERVICE="/etc/systemd/system/seadog-sweeper.service"
SWEEPER_TIMER="/etc/systemd/system/seadog-sweeper-idle.timer"

log() { printf 'seadog-install: %s\n' "$*"; }
die() { printf 'seadog-install: ERROR: %s\n' "$*" >&2; exit 1; }

# --- locate ourselves so relative repo paths resolve regardless of cwd ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
  sed -n '3,35p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# ====================================================================
# Flag parsing. Recognized --flags are stripped here; anything left is
# fed to the existing positional handling (BUILD_DIR/KEY/OWNER) so the
# bare/positional install path stays byte-for-byte equivalent to before.
# ====================================================================
DO_VERSION=0
DO_UNINSTALL=0
DO_PURGE=0
POSITIONAL=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) DO_VERSION=1; shift ;;
    --uninstall) DO_UNINSTALL=1; shift ;;
    --purge) DO_PURGE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; while [ "$#" -gt 0 ]; do POSITIONAL+=("$1"); shift; done ;;
    -*) die "unknown flag: $1 (try --help)" ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

# --- resolve BUILD_DIR with run-from-unpacked-tarball auto-detection ---
# An explicit positional BUILD_DIR always wins. Otherwise prefer the dev
# layout (binaries under target/...); if that has no seadog binary but the
# binaries sit directly beside this deploy/ tree (the unpacked release
# tarball: seadog-<ver>-x86_64-musl/{seadog,seadog-priv,deploy/}), use
# REPO_DIR.
DEFAULT_BUILD_DIR="${REPO_DIR}/target/x86_64-unknown-linux-musl/release"
if [ ! -x "${DEFAULT_BUILD_DIR}/seadog" ] && [ -x "${REPO_DIR}/seadog" ] && [ -x "${REPO_DIR}/seadog-priv" ]; then
  DEFAULT_BUILD_DIR="${REPO_DIR}"
fi
BUILD_DIR="${1:-${DEFAULT_BUILD_DIR}}"
BOOTSTRAP_KEY="${2:-${SEADOG_BOOTSTRAP_KEY:-}}"
BOOTSTRAP_OWNER="${3:-${SEADOG_BOOTSTRAP_OWNER:-}}"

# ====================================================================
# --version: print the version of the seadog build about to be / already
# installed. Prefer the build-dir binaries (the ones this run would
# install), else the installed ones. Does NOT require root.
#
# NB: the front-end `seadog` binary is the SSH login-shell entrypoint and
# does NOT honor a clap --version flag (it treats argv as session input
# and demands an owner). Its companion `seadog-priv` IS clap-derived,
# carries the SAME crate version, and answers `--version` cleanly — so we
# query that. We fall back to the front-end only if seadog-priv is missing.
# ====================================================================
if [ "${DO_VERSION}" -eq 1 ]; then
  ver_bin=""
  ver_src=""
  if [ -x "${BUILD_DIR}/seadog-priv" ]; then
    ver_bin="${BUILD_DIR}/seadog-priv"; ver_src="build dir ${BUILD_DIR}"
  elif [ -x "${PRIV}" ]; then
    ver_bin="${PRIV}"; ver_src="installed ${LIBDIR}"
  elif [ -x "${BUILD_DIR}/seadog" ]; then
    ver_bin="${BUILD_DIR}/seadog"; ver_src="build dir ${BUILD_DIR}"
  elif [ -x "${FRONTEND}" ]; then
    ver_bin="${FRONTEND}"; ver_src="installed ${LIBDIR}"
  else
    die "no seadog binary found (looked in ${BUILD_DIR} and ${LIBDIR})"
  fi
  if ver_out="$("${ver_bin}" --version 2>/dev/null)" && [ -n "${ver_out}" ]; then
    log "version (${ver_src}): ${ver_out}"
  else
    die "found ${ver_bin} but it did not report a version (got: '${ver_out:-}')"
  fi
  exit 0
fi

# --purge alone is meaningless: it only augments --uninstall.
if [ "${DO_PURGE}" -eq 1 ] && [ "${DO_UNINSTALL}" -eq 0 ]; then
  die "--purge only applies with --uninstall; use: sudo $(basename "$0") --uninstall --purge"
fi

# ====================================================================
# --uninstall [--purge]: guarded reversal of the install. Each step is
# idempotent and never errors if the target is already absent.
# ====================================================================
if [ "${DO_UNINSTALL}" -eq 1 ]; then
  [ "$(id -u)" -eq 0 ] || die "--uninstall must run as root"

  # 1. systemd timer/service: disable + stop, then remove the unit files.
  if systemctl list-unit-files seadog-sweeper-idle.timer >/dev/null 2>&1; then
    systemctl disable --now seadog-sweeper-idle.timer >/dev/null 2>&1 || true
  fi
  systemctl stop seadog-sweeper.service >/dev/null 2>&1 || true
  rm -f "${SWEEPER_TIMER}" "${SWEEPER_SERVICE}"
  systemctl daemon-reload >/dev/null 2>&1 || true
  log "removed seadog-sweeper timer + service (if present)"

  # 2. sshd drop-in: remove, re-validate, best-effort reload.
  if [ -e "${SSHD_DROPIN}" ]; then
    rm -f "${SSHD_DROPIN}"
    if sshd -t >/dev/null 2>&1; then
      systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || log "could not reload sshd automatically — reload it manually"
    else
      log "WARNING: sshd -t failed after removing the snippet; check /etc/ssh/sshd_config.d"
    fi
    log "removed ${SSHD_DROPIN} + reloaded sshd"
  else
    log "${SSHD_DROPIN} already absent"
  fi

  # 3. sudoers drop-in.
  rm -f "${SUDOERS_FILE}"
  log "removed ${SUDOERS_FILE} (if present)"

  # 4. tmpfiles + the runtime dir.
  rm -f "${TMPFILES_FILE}"
  rm -rf "${RUNDIR}"
  log "removed ${TMPFILES_FILE} + ${RUNDIR} (if present)"

  # 5. installed binaries (+ the lib dir if now empty).
  rm -f "${FRONTEND}" "${PRIV}"
  rmdir "${LIBDIR}" >/dev/null 2>&1 || true
  log "removed installed binaries from ${LIBDIR}"

  if [ "${DO_PURGE}" -eq 1 ]; then
    # --- purge: also remove data + identity. ---
    # Drop the /etc/shells line for the front-end (reverse of the add).
    if [ -f /etc/shells ] && grep -qxF "${FRONTEND}" /etc/shells 2>/dev/null; then
      grep -vxF "${FRONTEND}" /etc/shells > /etc/shells.seadog-tmp && mv /etc/shells.seadog-tmp /etc/shells
      log "removed ${FRONTEND} from /etc/shells"
    fi
    # Point testenv's shell away from the (now-removed) front-end before
    # deleting, so we never leave a dangling shell reference.
    if id -u "${USER_NAME}" >/dev/null 2>&1; then
      usermod -s /usr/sbin/nologin "${USER_NAME}" >/dev/null 2>&1 || true
      # Do NOT --remove the home: /var/lib/seadog is shared/seadog-owned and
      # removed explicitly below.
      userdel "${USER_NAME}" >/dev/null 2>&1 || true
      log "deleted user ${USER_NAME}"
    fi
    # Data + identity dirs.
    rm -rf "${ETCDIR}" "${VARDIR}"
    log "removed ${ETCDIR} + ${VARDIR} (config, authorized_keys, DB)"
    # Group, only if it has no remaining members.
    if getent group "${GROUP_NAME}" >/dev/null 2>&1; then
      members="$(getent group "${GROUP_NAME}" | cut -d: -f4)"
      if [ -z "${members}" ]; then
        groupdel "${GROUP_NAME}" >/dev/null 2>&1 || true
        log "deleted group ${GROUP_NAME}"
      else
        log "group ${GROUP_NAME} still has members (${members}); left in place"
      fi
    fi
    cat <<EOF

seadog PURGE complete. EVERYTHING was removed:
  - systemd timer/service, sshd drop-in, sudoers, tmpfiles, /run/seadog
  - installed binaries (${LIBDIR})
  - config + authorized_keys (${ETCDIR})
  - database (${VARDIR})
  - user ${USER_NAME}, group ${GROUP_NAME} (if memberless), /etc/shells line
EOF
    exit 0
  fi

  cat <<EOF

seadog uninstall complete (data preserved).

  REMOVED:
    - seadog-sweeper-idle.timer + seadog-sweeper.service
    - ${SSHD_DROPIN}
    - ${SUDOERS_FILE}
    - ${TMPFILES_FILE} + ${RUNDIR}
    - binaries (${FRONTEND}, ${PRIV})
  PRESERVED:
    - ${CONFIG} + ${AUTHKEYS} (${ETCDIR})
    - ${DB} (${VARDIR})
    - user ${USER_NAME}, group ${GROUP_NAME}, /etc/shells line

To fully wipe data + identity too, run:  sudo $(basename "$0") --uninstall --purge
EOF
  exit 0
fi

[ "$(id -u)" -eq 0 ] || die "must run as root (on the Proxmox host)"

# ====================================================================
# 1. Users, groups, directories.
# ====================================================================
getent group "${GROUP_NAME}" >/dev/null 2>&1 || groupadd --system "${GROUP_NAME}"
log "group ${GROUP_NAME} present"

if ! id -u "${USER_NAME}" >/dev/null 2>&1; then
  useradd --system --gid "${GROUP_NAME}" --home-dir "${VARDIR}" --no-create-home --shell /usr/sbin/nologin "${USER_NAME}"
  log "created system user ${USER_NAME}"
else
  log "user ${USER_NAME} present"
fi
# Ensure membership in the shared group (idempotent).
id -nG "${USER_NAME}" | tr ' ' '\n' | grep -qx "${GROUP_NAME}" || usermod -aG "${GROUP_NAME}" "${USER_NAME}"

install -d -m 0755 -o root -g root "${LIBDIR}"
install -d -m 0755 -o root -g root "${ETCDIR}"
# /var/lib/seadog is SETGID group seadog: both root (helper/sweeper) and
# testenv (front-end) write the DB + its -wal/-shm sidecars, and a
# root-created -wal must stay group-writable for the testenv reader. The
# setgid bit makes new files inherit group seadog; the install of the DB
# below also relaxes the WAL files' group perms.
install -d -m 2775 -o root -g "${GROUP_NAME}" "${VARDIR}"
log "directories present (/var/lib/seadog is setgid ${GROUP_NAME})"

# ====================================================================
# 2. Binaries, /etc/shells, login shell.
# ====================================================================
[ -x "${BUILD_DIR}/seadog" ] || die "front-end binary not found at ${BUILD_DIR}/seadog (build first: cargo build --release --target x86_64-unknown-linux-musl)"
[ -x "${BUILD_DIR}/seadog-priv" ] || die "helper binary not found at ${BUILD_DIR}/seadog-priv"

install -m 0755 -o root -g root "${BUILD_DIR}/seadog" "${FRONTEND}"
install -m 0755 -o root -g root "${BUILD_DIR}/seadog-priv" "${PRIV}"
log "installed binaries to ${LIBDIR}"

grep -qxF "${FRONTEND}" /etc/shells 2>/dev/null || printf '%s\n' "${FRONTEND}" >>/etc/shells
log "${FRONTEND} listed in /etc/shells"

# Set testenv's login shell to the front-end (the git-shell pattern).
if [ "$(getent passwd "${USER_NAME}" | cut -d: -f7)" != "${FRONTEND}" ]; then
  usermod -s "${FRONTEND}" "${USER_NAME}"
  log "set ${USER_NAME} login shell to ${FRONTEND}"
else
  log "${USER_NAME} login shell already ${FRONTEND}"
fi

# ====================================================================
# 3. sudoers, tmpfiles, systemd units.
# ====================================================================
install -m 0440 -o root -g root "${SCRIPT_DIR}/sudoers.d/seadog" /etc/sudoers.d/seadog
visudo -cf /etc/sudoers.d/seadog >/dev/null || die "sudoers drop-in failed visudo -cf; removed nothing — fix and re-run"
log "installed + verified /etc/sudoers.d/seadog"

install -m 0644 -o root -g root "${SCRIPT_DIR}/tmpfiles.d/seadog.conf" /etc/tmpfiles.d/seadog.conf
systemd-tmpfiles --create /etc/tmpfiles.d/seadog.conf
log "installed tmpfiles + created /run/seadog"

install -m 0644 -o root -g root "${SCRIPT_DIR}/systemd/seadog-sweeper.service" /etc/systemd/system/seadog-sweeper.service
install -m 0644 -o root -g root "${SCRIPT_DIR}/systemd/seadog-sweeper-idle.timer" /etc/systemd/system/seadog-sweeper-idle.timer
systemctl daemon-reload
systemctl enable --now seadog-sweeper-idle.timer
log "installed + enabled seadog-sweeper-idle.timer"

# ====================================================================
# 4. sshd snippet.
# ====================================================================
install -d -m 0755 -o root -g root /etc/ssh/sshd_config.d
install -m 0644 -o root -g root "${SCRIPT_DIR}/sshd-snippet.conf" /etc/ssh/sshd_config.d/seadog.conf
sshd -t || die "sshd -t failed after installing snippet; fix /etc/ssh/sshd_config.d/seadog.conf"
systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || log "could not reload sshd automatically — reload it manually"
log "installed sshd snippet + reloaded sshd"

# ====================================================================
# 5. config.yaml (only if absent).
# ====================================================================
if [ ! -f "${CONFIG}" ]; then
  install -m 0644 -o root -g root "${SCRIPT_DIR}/config.yaml.example" "${CONFIG}"
  log "installed default config to ${CONFIG} (review it!)"
else
  log "config ${CONFIG} exists; left untouched"
fi

# ====================================================================
# 6. DB ownership + authorized_keys bootstrap.
# ====================================================================
# The binaries create the schema on first open; we only need the file +
# dir ownership right so the front-end (testenv) can write. Create an
# empty DB owned testenv:seadog if absent (the WAL/SHM sidecars inherit
# group seadog via the setgid dir). We do NOT pre-create a schema here.
if [ ! -e "${DB}" ]; then
  install -m 0664 -o "${USER_NAME}" -g "${GROUP_NAME}" /dev/null "${DB}"
  log "initialized empty ${DB} owned ${USER_NAME}:${GROUP_NAME} (schema created by the binaries on first open)"
else
  # Re-assert ownership/perms idempotently in case of drift.
  chown "${USER_NAME}:${GROUP_NAME}" "${DB}"
  chmod 0664 "${DB}"
  log "DB ${DB} exists; ownership re-asserted ${USER_NAME}:${GROUP_NAME}"
fi

# Root-owned authorized_keys (0644). testenv must NOT be able to edit its
# own owner mapping, so this is root:root, not testenv-writable.
if [ ! -f "${AUTHKEYS}" ]; then
  install -m 0644 -o root -g root /dev/null "${AUTHKEYS}"
  log "created empty root-owned ${AUTHKEYS}"
else
  chown root:root "${AUTHKEYS}"
  chmod 0644 "${AUTHKEYS}"
fi

if [ -n "${BOOTSTRAP_KEY}" ] && [ -n "${BOOTSTRAP_OWNER}" ]; then
  # Build the forced-command line. `restrict` implies no-pty + no-*-fwd.
  LINE="command=\"${FRONTEND} --owner ${BOOTSTRAP_OWNER}\",restrict ${BOOTSTRAP_KEY}"
  # Idempotent: match on the key blob (field 2 of the key portion) so we
  # don't double-add even if the owner/comment differs. Extract the blob.
  BLOB="$(printf '%s\n' "${BOOTSTRAP_KEY}" | awk '{print $2}')"
  if [ -n "${BLOB}" ] && grep -qF "${BLOB}" "${AUTHKEYS}"; then
    log "bootstrap key already authorized; not re-adding"
  else
    printf '%s\n' "${LINE}" >>"${AUTHKEYS}"
    log "authorized bootstrap owner '${BOOTSTRAP_OWNER}'"
  fi
elif [ -n "${BOOTSTRAP_KEY}${BOOTSTRAP_OWNER}" ]; then
  log "WARNING: provide BOTH a bootstrap key and owner to authorize one; skipping"
fi

# ====================================================================
# Summary + manual follow-ups.
# ====================================================================
cat <<EOF

seadog install complete.

  binaries : ${FRONTEND}, ${PRIV}
  config   : ${CONFIG}
  db       : ${DB}  (owner ${USER_NAME}:${GROUP_NAME})
  authkeys : ${AUTHKEYS}  (root:root 0644)
  timer    : seadog-sweeper-idle.timer (enabled)
  runtime  : /run/seadog (tmpfiles)

Manual follow-ups:
  - Review ${CONFIG} (image allowlist, IP pool, caps).
  - Authorize each owner with the seadog-priv owner verbs (they manage
    ${AUTHKEYS} root-owned, atomically, 0644):
      sudo ${PRIV} add-owner --owner <name> --key "<keytype> <blob> <comment>"
      sudo ${PRIV} list-owners
      sudo ${PRIV} remove-owner --owner <name>
    (or re-run this installer with BOOTSTRAP_KEY + BOOTSTRAP_OWNER.)
  - Confirm sshd picked up /etc/ssh/sshd_config.d/seadog.conf.
  - Smoke test from a client:  ssh ${USER_NAME}@<pve-host> health
EOF
