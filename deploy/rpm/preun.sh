# seadog .rpm %preun — stop the timer/service on final removal only.
#
# RPM $1 semantics: 0 = final removal (package going away), 1 = upgrade
# (the new version's %post re-enables). Only disable on $1 == 0 so an
# upgrade doesn't tear the timer down. Best-effort.

if [ "$1" = "0" ]; then
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now seadog-sweeper-idle.timer seadog-sweeper.service \
            >/dev/null 2>&1 || true
    fi
fi
