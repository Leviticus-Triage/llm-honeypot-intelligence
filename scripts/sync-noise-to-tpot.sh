#!/usr/bin/env bash
#
# Sync the ML-detected noise IP list (noise_ips.csv) from the proxy stack to the
# T-Pot VM so Logstash's `translate` filter can tag those IPs as noise at ingest.
#
# Context:
#   - heuristic-detector writes noise_ips.csv into the docker volume
#     ollama-threat-output (host: VM 200 / ai-workstation).
#   - Logstash on the T-Pot VM mounts custom/noise_ips.csv :ro and reloads the
#     translate dictionary every ~300s (no restart needed on update).
#
# Runs hourly on VM 200 via noise-csv-sync.timer (systemd --user).
#
# Overridable via environment:
#   TPOT_HOST (default admin@192.168.2.22), TPOT_PORT (64295),
#   TPOT_CSV (tpotce/custom/noise_ips.csv), CONTAINER (ollama-heuristic-detector)
set -euo pipefail

LOG="${HOME}/noise-csv-sync.log"
TPOT_HOST="${TPOT_HOST:-admin@192.168.2.22}"
TPOT_PORT="${TPOT_PORT:-64295}"
TPOT_CSV="${TPOT_CSV:-tpotce/custom/noise_ips.csv}"
CONTAINER="${CONTAINER:-ollama-heuristic-detector}"
SRC_CSV="/data/ollama-proxy/threat-intel/noise_ips.csv"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

log() { printf '[noise-sync %s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"; }

# 1. Extract the CSV from the docker volume (danii is in the docker group; no sudo).
if ! docker cp "${CONTAINER}:${SRC_CSV}" "$TMP" 2>/dev/null; then
    log "ERROR: docker cp ${SRC_CSV} from ${CONTAINER} failed (detector run yet?)"
    exit 1
fi

# An empty list is legitimate (no benign IPs in the window) — still sync it so a
# previously populated dictionary gets cleared when noise subsides.
lines="$(grep -c ',noise' "$TMP" 2>/dev/null || echo 0)"

# 2. Sync to the T-Pot VM. -c (checksum) skips the transfer when unchanged, which
#    avoids needless Logstash dictionary reloads.
if rsync -az -c \
        -e "ssh -p ${TPOT_PORT} -o BatchMode=yes -o ConnectTimeout=10" \
        "$TMP" "${TPOT_HOST}:${TPOT_CSV}" 2>>"$LOG"; then
    log "Synced noise_ips.csv (${lines} IPs) -> ${TPOT_HOST}:${TPOT_CSV}"
else
    log "ERROR: rsync to ${TPOT_HOST}:${TPOT_CSV} failed"
    exit 1
fi
