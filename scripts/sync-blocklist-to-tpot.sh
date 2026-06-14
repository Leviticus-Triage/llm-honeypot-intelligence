#!/usr/bin/env bash
#
# Sync 12h temporary blocklist + apply scripts from the rule generator to T-Pot.
# Uses ipset timeout (auto-expire) — works without fail2ban.
#
# Target files land in ~/tpotce/custom/ (same pattern as noise_ips.csv).
# Applying the blocklist requires root: run once on T-Pot:
#   sudo ./deploy/tpot/setup-blocklist-timer.sh
#
# Env overrides:
#   TPOT_HOST (default admin@192.168.2.22), TPOT_PORT (64295),
#   CONTAINER (ollama-rule-generator), TPOT_DIR (tpotce/custom)
set -euo pipefail

LOG="${HOME}/blocklist-sync.log"
TPOT_HOST="${TPOT_HOST:-admin@192.168.2.22}"
TPOT_PORT="${TPOT_PORT:-64295}"
TPOT_DIR="${TPOT_DIR:-tpotce/custom}"
CONTAINER="${CONTAINER:-ollama-rule-generator}"
SRC_BASE="/data/ollama-proxy/generated-rules/fail2ban"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log() { printf '[blocklist-sync %s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"; }

copy_one() {
    local name="$1"
    if docker cp "${CONTAINER}:${SRC_BASE}/${name}" "${TMP}/${name}" 2>/dev/null; then
        return 0
    fi
    log "WARN: missing ${SRC_BASE}/${name} in ${CONTAINER}"
    return 1
}

if ! copy_one "blocklist_honeypot_osint.txt"; then
    log "ERROR: no blocklist yet — rule generator run pending?"
    exit 1
fi
copy_one "apply-ipset-temp-blocklist.sh" || true
copy_one "jail.d/honeypot-osint.local" || true
copy_one "filter.d/honeypot-osint.conf" || true
copy_one "deploy-honeypot-blocklist.sh" || true

# Flatten jail/filter for T-Pot custom dir
[ -f "${TMP}/jail.d/honeypot-osint.local" ] && cp "${TMP}/jail.d/honeypot-osint.local" "${TMP}/honeypot-osint.local"
[ -f "${TMP}/filter.d/honeypot-osint.conf" ] && cp "${TMP}/filter.d/honeypot-osint.conf" "${TMP}/honeypot-osint.conf"

lines="$(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "${TMP}/blocklist_honeypot_osint.txt" 2>/dev/null || echo 0)"

RSYNC_SSH="ssh -p ${TPOT_PORT} -o BatchMode=yes -o ConnectTimeout=10"
for f in blocklist_honeypot_osint.txt apply-ipset-temp-blocklist.sh honeypot-osint.local honeypot-osint.conf deploy-honeypot-blocklist.sh; do
    [ -f "${TMP}/${f}" ] || continue
    if rsync -az -c --inplace -e "$RSYNC_SSH" "${TMP}/${f}" "${TPOT_HOST}:${TPOT_DIR}/${f}" 2>>"$LOG"; then
        log "Synced ${f} -> ${TPOT_HOST}:${TPOT_DIR}/${f}"
    else
        log "ERROR: rsync ${f} failed"
        exit 1
    fi
done

# Install root timer helper if not present
if [ -f "$(dirname "$0")/../deploy/tpot/setup-blocklist-timer.sh" ]; then
    rsync -az -e "$RSYNC_SSH" \
        "$(dirname "$0")/../deploy/tpot/setup-blocklist-timer.sh" \
        "$(dirname "$0")/../deploy/tpot/honeypot-blocklist-apply.service" \
        "$(dirname "$0")/../deploy/tpot/honeypot-blocklist-apply.timer" \
        "${TPOT_HOST}:~/tpotce/custom/" 2>>"$LOG" || true
fi

log "Done: ${lines} IPs in blocklist_honeypot_osint.txt"
