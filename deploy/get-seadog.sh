#!/usr/bin/env bash
#
# seadog bootstrap fetcher — `curl -fsSL <url> | bash`-style installer.
#
# Usage:
#   curl -fsSL https://.../get-seadog.sh | bash
#   curl -fsSL https://.../get-seadog.sh | bash -s -- [BOOTSTRAP_KEY] [BOOTSTRAP_OWNER]
#   ./deploy/get-seadog.sh [--version vX.Y.Z] [-- INSTALL_ARGS...]
#   ./deploy/get-seadog.sh --help
#
# Pipe to `bash`, not `sh`: this script uses bash features (arrays), and on
# Debian/Proxmox /bin/sh is dash. (Run as a file, the shebang handles it.)
#
# Downloads the seadog release tarball + SHA256SUMS, verifies the tarball's
# checksum, unpacks it, and runs the bundled deploy/install.sh as root
# (re-exec via sudo if needed). Any extra args are forwarded to install.sh
# (e.g. a bootstrap key + owner).
#
# Flags / env knobs:
#   --version vX.Y.Z       pin a release (default: the latest release).
#   $SEADOG_VERSION        same as --version (the flag wins if both set).
#   $SEADOG_RELEASE_BASE   release base URL
#                          (default: https://github.com/doctorjei/seadog/releases).
#                          Override hook for local simulate-testing: point it
#                          at a local http server serving the release layout.
#
# SECURITY NOTE: SHA256SUMS is fetched from the SAME origin as the tarball,
# so verifying the tarball against it is trust-on-first-use (TOFU) integrity
# only — it catches truncated/corrupted downloads and a tampered tarball
# served alongside an untampered sums file, but it is NOT a substitute for
# real signature verification (an attacker who controls the origin controls
# both files). Pin a version and verify out-of-band for stronger guarantees.

set -euo pipefail

REPO="doctorjei/seadog"
RELEASE_BASE="${SEADOG_RELEASE_BASE:-https://github.com/${REPO}/releases}"
VERSION="${SEADOG_VERSION:-}"

log() { printf 'get-seadog: %s\n' "$*"; }
die() { printf 'get-seadog: ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '3,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# --- parse flags; everything after -- (or any leftover) is forwarded. ---
INSTALL_ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) shift; [ "$#" -gt 0 ] || die "--version needs a value (e.g. v1.2.3)"; VERSION="$1"; shift ;;
    --version=*) VERSION="${1#--version=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; while [ "$#" -gt 0 ]; do INSTALL_ARGS+=("$1"); shift; done ;;
    *) INSTALL_ARGS+=("$1"); shift ;;
  esac
done

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

# --- resolve the version: when unpinned, follow .../latest to its tag. ---
if [ -z "${VERSION}" ]; then
  log "no version pinned; resolving latest from ${RELEASE_BASE}/latest"
  # GitHub redirects /releases/latest to /releases/tag/<ver>; the final URL
  # ends in the tag. curl -w prints the effective URL after redirects.
  latest_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "${RELEASE_BASE}/latest")" || die "could not resolve latest release from ${RELEASE_BASE}/latest"
  VERSION="${latest_url##*/}"
  [ -n "${VERSION}" ] || die "could not parse latest version from '${latest_url}'"
fi
log "target version: ${VERSION}"

TARBALL="seadog-${VERSION#v}-x86_64-musl.tar.gz"
DL_BASE="${RELEASE_BASE}/download/${VERSION}"

# --- temp workspace, cleaned on any exit. ---
WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "${WORKDIR}"; }
trap cleanup EXIT

log "downloading ${TARBALL} + SHA256SUMS from ${DL_BASE}"
curl -fsSL -o "${WORKDIR}/${TARBALL}" "${DL_BASE}/${TARBALL}" || die "failed to download ${TARBALL}"
curl -fsSL -o "${WORKDIR}/SHA256SUMS" "${DL_BASE}/SHA256SUMS" || die "failed to download SHA256SUMS"

# --- verify the tarball against its line in SHA256SUMS. ---
expected="$(awk -v f="${TARBALL}" '$2 == f || $2 == "*" f {print $1}' "${WORKDIR}/SHA256SUMS")"
[ -n "${expected}" ] || die "SHA256SUMS has no entry for ${TARBALL}"
actual="$(sha256sum "${WORKDIR}/${TARBALL}" | awk '{print $1}')"
if [ "${expected}" != "${actual}" ]; then
  die "SHA256 mismatch for ${TARBALL}: expected ${expected}, got ${actual} — refusing to install"
fi
log "checksum OK (${actual})"

# --- unpack + locate the bundled installer. ---
tar -xzf "${WORKDIR}/${TARBALL}" -C "${WORKDIR}" || die "failed to extract ${TARBALL}"
INSTALLER="$(find "${WORKDIR}" -maxdepth 3 -name install.sh -path '*/deploy/install.sh' | head -1)"
if [ -z "${INSTALLER}" ] || [ ! -x "${INSTALLER}" ]; then
  die "deploy/install.sh not found (or not executable) in the unpacked tarball"
fi
log "unpacked; running installer: ${INSTALLER}"

# --- run install.sh as root, forwarding any extra args. ---
if [ "$(id -u)" -eq 0 ]; then
  "${INSTALLER}" "${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}"
else
  command -v sudo >/dev/null 2>&1 || die "not root and sudo not found; re-run as root"
  log "not root; re-executing installer via sudo"
  sudo "${INSTALLER}" "${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}"
fi

log "done — seadog ${VERSION} installed from ${TARBALL}"
