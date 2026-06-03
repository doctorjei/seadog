# seadog .rpm %postun — reverse the install glue on final removal only.
#
# RPM $1 semantics: 0 = final removal, 1 = upgrade (leftover from the old
# version — do nothing). On final removal strip the /etc/shells entry,
# remove per-deployment state, and delete the user/group. RPM has no
# remove-vs-purge split, so this matches the .deb *purge* behavior (final
# removal of an rpm = full teardown). Best-effort + idempotent.

LIBDIR="/usr/lib/seadog"
ETCDIR="/etc/seadog"
VARDIR="/var/lib/seadog"
FRONTEND="${LIBDIR}/seadog"
USER_NAME="testenv"
GROUP_NAME="seadog"

if [ "$1" = "0" ]; then
    # 1. Drop the login-shell registration (portable sed; no remove-shell
    # on Fedora). Escape / for the sed address.
    if [ -f /etc/shells ]; then
        esc=$(printf '%s\n' "${FRONTEND}" | sed 's/[\/&]/\\&/g')
        sed -i "\|^${esc}\$|d" /etc/shells 2>/dev/null || true
    fi

    # 2. Remove per-deployment state.
    rm -rf "${ETCDIR}" "${VARDIR}" || true

    # 3. Delete the user then the group (user owns the gid as primary group).
    if command -v userdel >/dev/null 2>&1; then
        userdel "${USER_NAME}" >/dev/null 2>&1 || true
    fi
    if command -v groupdel >/dev/null 2>&1; then
        groupdel "${GROUP_NAME}" >/dev/null 2>&1 || true
    fi

    # 4. Let systemd forget the removed units.
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
fi
