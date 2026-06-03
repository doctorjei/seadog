#!/usr/bin/env bash
#
# seadog backup — RUN ON blue (nightly via cron/systemd-timer, as root).
#
# Snapshots the WAL-mode SQLite DB CONSISTENTLY using sqlite3's online
# backup API (`.backup`) — NEVER a raw `cp`, which can capture a torn DB
# while the front-end / sweeper are mid-write. Writes a timestamped copy
# to a local backups/ dir, then mirrors it off-host to a configurable
# destination. Keeps a 7-day rolling window in both places.
#
# Tolerates the off-host dest being unavailable: it logs and keeps the
# local copy so the next run can still mirror.
#
# Env knobs:
#   SEADOG_DB        DB path     (default /var/lib/seadog/seadog.db)
#   SEADOG_BACKUP_LOCAL  local backups dir (default /var/lib/seadog/backups)
#   SEADOG_BACKUP_DEST   off-host dest     (default /mnt/share/seadog-backups)
#   SEADOG_BACKUP_KEEP_DAYS  rolling window in days (default 7)

set -euo pipefail

DB="${SEADOG_DB:-/var/lib/seadog/seadog.db}"
LOCAL_DIR="${SEADOG_BACKUP_LOCAL:-/var/lib/seadog/backups}"
DEST_DIR="${SEADOG_BACKUP_DEST:-/mnt/share/seadog-backups}"
KEEP_DAYS="${SEADOG_BACKUP_KEEP_DAYS:-7}"

log() { printf 'seadog-backup: %s\n' "$*"; }
die() { printf 'seadog-backup: ERROR: %s\n' "$*" >&2; exit 1; }

command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 not found (needed for a consistent WAL-mode backup)"
[ -f "${DB}" ] || die "DB not found at ${DB}"

install -d -m 0750 "${LOCAL_DIR}"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SNAP="${LOCAL_DIR}/seadog-${STAMP}.db"

# Consistent snapshot via the online backup API. `.backup` copies a
# transactionally-consistent image even while writers hold the WAL.
sqlite3 "${DB}" ".backup '${SNAP}'" || die "sqlite3 .backup failed"
chmod 0640 "${SNAP}"
log "wrote local snapshot ${SNAP}"

# Mirror off-host. Tolerate an unavailable dest (NFS down, share gone).
if install -d -m 0750 "${DEST_DIR}" 2>/dev/null && cp -p "${SNAP}" "${DEST_DIR}/" 2>/dev/null; then
  log "mirrored to ${DEST_DIR}"
  # Prune the off-host window too (best-effort).
  find "${DEST_DIR}" -maxdepth 1 -type f -name 'seadog-*.db' -mtime "+${KEEP_DAYS}" -delete 2>/dev/null || true
else
  log "WARNING: off-host dest ${DEST_DIR} unavailable; kept local copy only"
fi

# Prune the local rolling window (always; -mtime +N = strictly older).
find "${LOCAL_DIR}" -maxdepth 1 -type f -name 'seadog-*.db' -mtime "+${KEEP_DAYS}" -delete 2>/dev/null || true
log "pruned snapshots older than ${KEEP_DAYS} days"

log "backup complete"
