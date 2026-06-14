#!/usr/bin/env bash
# One-time setup on T-Pot (VM400): hourly ipset blocklist apply with 12h auto-expire.
# Run as admin with sudo:
#   cd ~/tpotce/custom && sudo bash setup-blocklist-timer.sh
set -euo pipefail

CUSTOM_DIR="$(cd "$(dirname "$0")" && pwd)"
UNIT_DIR="/etc/systemd/system"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo bash $0"
    exit 1
fi

chmod +x "${CUSTOM_DIR}/apply-ipset-temp-blocklist.sh" 2>/dev/null || true

cat > "${UNIT_DIR}/honeypot-blocklist-apply.service" <<EOF
[Unit]
Description=Apply LLM honeypot 24h temporary IP blocklist (ipset)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${CUSTOM_DIR}/apply-ipset-temp-blocklist.sh
EOF

cat > "${UNIT_DIR}/honeypot-blocklist-apply.timer" <<'EOF'
[Unit]
Description=Hourly honeypot blocklist apply (24h ipset timeout)

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=180

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now honeypot-blocklist-apply.timer
systemctl start honeypot-blocklist-apply.service

echo "OK: honeypot-blocklist-apply.timer enabled (12h ipset bans by default, hourly refresh)"
systemctl list-timers honeypot-blocklist-apply.timer --no-pager

# Optional fail2ban (if installed)
if command -v fail2ban-client &>/dev/null; then
    mkdir -p /etc/fail2ban/jail.d /etc/fail2ban/filter.d
    [ -f "${CUSTOM_DIR}/honeypot-osint.local" ] && cp "${CUSTOM_DIR}/honeypot-osint.local" /etc/fail2ban/jail.d/
    [ -f "${CUSTOM_DIR}/honeypot-osint.conf" ] && cp "${CUSTOM_DIR}/honeypot-osint.conf" /etc/fail2ban/filter.d/
    systemctl enable --now fail2ban 2>/dev/null || true
    systemctl reload fail2ban 2>/dev/null || true
    echo "fail2ban jail honeypot-osint installed (bantime from jail config)"
fi
