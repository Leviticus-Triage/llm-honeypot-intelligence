#!/usr/bin/env bash
# install.sh — install/refresh the persistent honeypot-sync systemd user timer.
#
# Idempotent. Run on the ai-workstation as the deploy user:
#   ./deploy/systemd/install.sh
#
# What it does:
#   1. Enables linger (so user timers run without an active login).
#   2. Installs the .service/.timer/.failure units into ~/.config/systemd/user.
#   3. Removes the legacy crontab entry (prevents double-runs).
#   4. Enables + starts the timer.
#
# Rollback: ./deploy/systemd/install.sh --uninstall
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UNIT_DIR="${HOME}/.config/systemd/user"
UNITS=(honeypot-sync.service honeypot-sync.timer honeypot-sync-failure.service)
CRON_MARKER="sync-to-github.sh"

uninstall() {
    echo "[install] Uninstalling honeypot-sync timer ..."
    systemctl --user disable --now honeypot-sync.timer 2>/dev/null || true
    for u in "${UNITS[@]}"; do rm -f "${UNIT_DIR}/${u}"; done
    systemctl --user daemon-reload
    echo "[install] Removed. (Re-add cron manually if you want the old behaviour.)"
    exit 0
}
[ "${1:-}" = "--uninstall" ] && uninstall

echo "[install] 1/4 enabling linger ..."
loginctl enable-linger "$USER" 2>/dev/null || echo "[install]   (linger already on or needs admin — continuing)"

echo "[install] 2/4 installing units into ${UNIT_DIR} ..."
mkdir -p "$UNIT_DIR"
for u in "${UNITS[@]}"; do
    install -m 0644 "${SCRIPT_DIR}/${u}" "${UNIT_DIR}/${u}"
    echo "[install]   ${u}"
done

echo "[install] 3/4 removing legacy crontab entry (if present) ..."
if crontab -l 2>/dev/null | grep -q "$CRON_MARKER"; then
    # grep -v exits 1 when it filters out *every* line (e.g. the sync line was
    # the only entry). Capture into a var with a guard so `set -e`/pipefail
    # don't abort, then reload (empty input clears the crontab cleanly).
    new_cron="$(crontab -l 2>/dev/null | grep -v "$CRON_MARKER" || true)"
    printf '%s\n' "$new_cron" | crontab - 2>/dev/null || true
    echo "[install]   removed cron line containing '${CRON_MARKER}'"
else
    echo "[install]   no matching cron line"
fi

echo "[install] 4/4 enabling + starting timer ..."
systemctl --user daemon-reload
systemctl --user enable --now honeypot-sync.timer

echo "[install] Done. Next runs:"
systemctl --user list-timers honeypot-sync.timer --no-pager 2>/dev/null || true
