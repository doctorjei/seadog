#!/usr/bin/env bash
#
# rpm-smoke.sh — install the seadog .rpm in a Fedora container, assert the
# scriptlets reach the same end-state as the .deb / install.sh, then remove
# it and assert a clean teardown. RUN INSIDE a disposable Fedora container
# (see the `rpm-smoke` CI job); it mutates users/dirs/system files.
#
# Arg 1: path to the seadog-<ver>-1.x86_64.rpm.
#
# NOT exercised here (no PID1 systemd / no sshd in a plain container, same
# caveat as the local rpm inspection): `systemctl enable --now` of the timer
# and the sshd reload. The %post guards both with `|| true`, so dnf install
# still succeeds; this script validates everything the declarative
# sysusers/tmpfiles glue creates plus the %postun teardown.

set -euo pipefail

RPM="${1:?usage: rpm-smoke.sh <path-to-rpm>}"

LIBDIR="/usr/lib/seadog"
ETCDIR="/etc/seadog"
VARDIR="/var/lib/seadog"
FRONTEND="${LIBDIR}/seadog"

pass() { printf 'rpm-smoke: PASS: %s\n' "$*"; }
fail() { printf 'rpm-smoke: FAIL: %s\n' "$*" >&2; exit 1; }

# shadow-utils gives userdel/groupdel for the teardown assertions; systemd
# (a package Requires) brings systemd-sysusers/systemd-tmpfiles for %post.
echo "rpm-smoke: ensuring shadow-utils is present"
rpm -q shadow-utils >/dev/null 2>&1 || dnf install -y shadow-utils >/dev/null 2>&1 || true

echo "=== dnf install the rpm (pulls the systemd dependency) ==="
dnf install -y "${RPM}"

echo "=== assert install end-state ==="
id testenv >/dev/null 2>&1 || fail "testenv user not created (systemd-sysusers)"
pass "testenv user present"
getent group seadog >/dev/null 2>&1 || fail "seadog group not created"
pass "seadog group present"

# /var/lib/seadog: created by tmpfiles as 2775 root:seadog.
mode="$(stat -c '%a' "${VARDIR}")"
owner="$(stat -c '%U:%G' "${VARDIR}")"
[ "${mode}" = "2775" ] || fail "${VARDIR} mode is ${mode}, expected 2775"
[ "${owner}" = "root:seadog" ] || fail "${VARDIR} owner is ${owner}, expected root:seadog"
pass "${VARDIR} is 2775 root:seadog (tmpfiles)"

for f in "${LIBDIR}/seadog" "${LIBDIR}/seadog-priv" /etc/sudoers.d/seadog /etc/ssh/sshd_config.d/seadog.conf /lib/systemd/system/seadog-sweeper.service /lib/systemd/system/seadog-sweeper-idle.timer /usr/lib/tmpfiles.d/seadog.conf /usr/lib/sysusers.d/seadog.conf "${ETCDIR}/config.yaml" /usr/bin/seadog-wrapper; do
  [ -e "${f}" ] || fail "packaged file missing: ${f}"
done
pass "all packaged files present"

grep -qxF "${FRONTEND}" /etc/shells || fail "${FRONTEND} not registered in /etc/shells"
pass "${FRONTEND} in /etc/shells"

[ -f "${ETCDIR}/authorized_keys" ] || fail "authorized_keys not created by %post"
ak_owner="$(stat -c '%U:%G' "${ETCDIR}/authorized_keys")"
[ "${ak_owner}" = "root:root" ] || fail "authorized_keys owner ${ak_owner}, expected root:root"
pass "authorized_keys present root:root"

[ -e "${VARDIR}/seadog.db" ] || fail "seadog.db not created by %post"
db_owner="$(stat -c '%U:%G' "${VARDIR}/seadog.db")"
[ "${db_owner}" = "testenv:seadog" ] || fail "seadog.db owner ${db_owner}, expected testenv:seadog"
pass "seadog.db present testenv:seadog"

# The binary answers --version (sanity that the musl binary runs on Fedora).
ver="$("${LIBDIR}/seadog-priv" --version 2>/dev/null || true)"
[ -n "${ver}" ] || fail "seadog-priv --version produced no output"
pass "seadog-priv runs on Fedora: ${ver}"

echo "rpm-smoke: NOTE: systemctl enable + sshd reload are NOT exercised (no PID1 systemd/sshd in the container)"

echo "=== dnf remove + assert teardown (%postun = final removal) ==="
dnf remove -y seadog

if id testenv >/dev/null 2>&1; then fail "testenv user survived removal"; else pass "testenv user removed"; fi
if getent group seadog >/dev/null 2>&1; then fail "seadog group survived removal"; else pass "seadog group removed"; fi
if [ -e "${ETCDIR}" ]; then fail "${ETCDIR} survived removal"; else pass "${ETCDIR} removed"; fi
if [ -e "${VARDIR}" ]; then fail "${VARDIR} survived removal"; else pass "${VARDIR} removed"; fi
if grep -qxF "${FRONTEND}" /etc/shells; then fail "${FRONTEND} survived in /etc/shells"; else pass "/etc/shells line removed"; fi

echo "rpm-smoke: ALL CHECKS PASSED"
