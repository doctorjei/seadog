# seadog .rpm %post — declarative-first install glue (mirrors the .deb postinst).
#
# RPM scriptlet $1 semantics: 1 = first install, 2 = upgrade. We run the
# same idempotent steps in both cases. Best-effort throughout.

LIBDIR="/usr/lib/seadog"
ETCDIR="/etc/seadog"
VARDIR="/var/lib/seadog"
FRONTEND="${LIBDIR}/seadog"
AUTHKEYS="${ETCDIR}/authorized_keys"
DB="${VARDIR}/seadog.db"
USER_NAME="testenv"
GROUP_NAME="seadog"

# 1. Declarative user/group + runtime dir.
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers /usr/lib/sysusers.d/seadog.conf || true
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/seadog.conf || true
fi

# 2. /var/lib/seadog setgid group seadog (2775 root:seadog).
chgrp "${GROUP_NAME}" "${VARDIR}" 2>/dev/null || true
chmod 2775 "${VARDIR}" 2>/dev/null || true

# 3. Register the front-end as a valid login shell. Fedora ships no
# add-shell, so append portably (grep-guarded) instead.
if [ -f /etc/shells ]; then
    grep -qxF "${FRONTEND}" /etc/shells || printf '%s\n' "${FRONTEND}" >>/etc/shells || true
else
    printf '%s\n' "${FRONTEND}" >/etc/shells || true
fi

# 4. Per-deployment files (never package content). Create only if absent.
if [ ! -f "${AUTHKEYS}" ]; then
    install -m 0644 -o root -g root /dev/null "${AUTHKEYS}" || true
fi
if [ ! -e "${DB}" ] && id -u "${USER_NAME}" >/dev/null 2>&1; then
    install -m 0664 -o "${USER_NAME}" -g "${GROUP_NAME}" /dev/null "${DB}" || true
fi

# 5. systemd: reload units + enable/start the backstop timer.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable --now seadog-sweeper-idle.timer || true
fi

# 6. sshd: only reload if the merged config validates.
if command -v sshd >/dev/null 2>&1 && sshd -t >/dev/null 2>&1; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
fi
