#!/usr/bin/env bash
#
# seadog installer — RUN ON blue AS root (coordinated with the cluster
# instance). Idempotent: safe to re-run; every step guards before acting.
#
# Usage:
#   sudo ./deploy/install.sh [BUILD_DIR] [BOOTSTRAP_KEY] [BOOTSTRAP_OWNER]
#
#   BUILD_DIR        dir holding the two static-musl binaries
#                    (default: target/x86_64-unknown-linux-musl/release)
#   BOOTSTRAP_KEY    a public key line to authorize, e.g.
#                    "ssh-ed25519 AAAA... kani@host"  (optional)
#   BOOTSTRAP_OWNER  the trusted owner name for that key (optional)
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
CONFIG="${ETCDIR}/config.yaml"
AUTHKEYS="${ETCDIR}/authorized_keys"
DB="${VARDIR}/seadog.db"
USER_NAME="testenv"
GROUP_NAME="seadog"
FRONTEND="${LIBDIR}/seadog"
PRIV="${LIBDIR}/seadog-priv"

# --- locate ourselves so relative repo paths resolve regardless of cwd ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

BUILD_DIR="${1:-${REPO_DIR}/target/x86_64-unknown-linux-musl/release}"
BOOTSTRAP_KEY="${2:-${SEADOG_BOOTSTRAP_KEY:-}}"
BOOTSTRAP_OWNER="${3:-${SEADOG_BOOTSTRAP_OWNER:-}}"

log() { printf 'seadog-install: %s\n' "$*"; }
die() { printf 'seadog-install: ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (on blue)"

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
  - Authorize each owner by appending a forced-command line to
    ${AUTHKEYS} (root-owned). Format:
      command="${FRONTEND} --owner <name>",restrict <keytype> <blob> <comment>
    (or re-run this installer with BOOTSTRAP_KEY + BOOTSTRAP_OWNER.)
  - Confirm sshd picked up /etc/ssh/sshd_config.d/seadog.conf.
  - Smoke test from a client:  ssh ${USER_NAME}@blue health
EOF
