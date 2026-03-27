#!/usr/bin/env bash
# sync-to-github.sh – Auto-sync generated rules & threat intel to GitHub
#
# Reads latest outputs from Docker volumes and pushes to the repo.
# Designed to run via cron every 6 hours.
#
# Usage:
#   ./scripts/sync-to-github.sh
#
# Cron entry:
#   0 */6 * * * /path/to/llm-honeypot-intelligence/scripts/sync-to-github.sh >> /var/log/honeypot-sync.log 2>&1

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOCK_FILE="$REPO_DIR/.sync-lock"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LOG_PREFIX="[sync $TIMESTAMP]"

RULES_VOLUME="ollama-rules-output"
THREAT_VOLUME="ollama-threat-output"

RULES_DEST="$REPO_DIR/rules"
THREAT_DEST="$REPO_DIR/threat-intel"

PRIVATE_IP_PATTERN='192\.168\.[0-9]+\.[0-9]+'

log() { echo "$LOG_PREFIX $*"; }
err() { echo "$LOG_PREFIX ERROR: $*" >&2; }

cleanup() { rm -f "$LOCK_FILE"; }
trap cleanup EXIT

if [ -f "$LOCK_FILE" ]; then
    pid=$(cat "$LOCK_FILE" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        err "Another sync is running (PID $pid). Exiting."
        exit 0
    fi
    log "Stale lock file found, removing."
fi
echo $$ > "$LOCK_FILE"

# ---------- Helper: copy from Docker volume via temporary container ----------

copy_from_volume() {
    local volume="$1"
    local dest="$2"
    local tmpdir

    if ! docker volume inspect "$volume" &>/dev/null; then
        log "Volume $volume does not exist, skipping."
        return 1
    fi

    tmpdir=$(mktemp -d)
    docker run --rm -v "${volume}:/source:ro" -v "${tmpdir}:/dest" \
        alpine:3.19 sh -c 'cp -r /source/* /dest/ && chmod -R a+rw /dest/ 2>/dev/null || true'

    if [ -z "$(ls -A "$tmpdir" 2>/dev/null)" ]; then
        log "Volume $volume is empty, skipping."
        rm -rf "$tmpdir"
        return 1
    fi

    echo "$tmpdir"
}

# ---------- Helper: sanitize files (strip private IPs) ----------

sanitize_dir() {
    local dir="$1"
    find "$dir" -type f \( -name "*.json" -o -name "*.txt" -o -name "*.md" \
        -o -name "*.rules" -o -name "*.yml" -o -name "*.yar" \
        -o -name "*.sh" -o -name "*.nft" \) -exec \
        sed -i -E "s/${PRIVATE_IP_PATTERN}/[REDACTED]/g" {} +
}

# ---------- Sync generated rules ----------

log "Syncing generated rules from volume: $RULES_VOLUME"

rules_tmp=$(copy_from_volume "$RULES_VOLUME" "$RULES_DEST") || true

if [ -n "${rules_tmp:-}" ] && [ -d "${rules_tmp:-}" ]; then
    # Merge full generator layout: latest/, archive/<run>/, root mirror, reports/, manifest, etc.
    # rsync without --delete keeps repo-only files (e.g. suricata/c2-detection.rules, *-peak-run*).
    rsync -a "$rules_tmp/" "$RULES_DEST/"
    log "  Rules tree synced (latest/, archive/, root mirror, reports)"

    sanitize_dir "$RULES_DEST"
    rm -rf "$rules_tmp"
else
    log "No rules to sync."
fi

# ---------- Sync threat intel ----------

log "Syncing threat intel from volume: $THREAT_VOLUME"

threat_tmp=$(copy_from_volume "$THREAT_VOLUME" "$THREAT_DEST") || true

if [ -n "${threat_tmp:-}" ] && [ -d "${threat_tmp:-}" ]; then
    [ -f "$threat_tmp/ip_reputation.json" ]  && cp -f "$threat_tmp/ip_reputation.json"  "$THREAT_DEST/ip-reputation.json"
    [ -f "$threat_tmp/campaigns.json" ]      && cp -f "$threat_tmp/campaigns.json"      "$THREAT_DEST/campaigns.json"
    [ -f "$threat_tmp/dynamic_blocklist.txt" ] && cp -f "$threat_tmp/dynamic_blocklist.txt" "$THREAT_DEST/dynamic-blocklist.txt"
    [ -f "$threat_tmp/alerts.json" ]         && cp -f "$threat_tmp/alerts.json"         "$THREAT_DEST/alerts.json"
    [ -f "$threat_tmp/threat_summary.json" ] && cp -f "$threat_tmp/threat_summary.json" "$THREAT_DEST/threat-summary.json"

    sanitize_dir "$THREAT_DEST"
    rm -rf "$threat_tmp"
    log "  Threat intel synced"
else
    log "No threat intel to sync."
fi

# ---------- Count changes for commit message ----------

cd "$REPO_DIR"

suricata_count=$(find "$RULES_DEST/suricata" -name "*.rules" -newer "$RULES_DEST/.last-sync" 2>/dev/null | wc -l || echo 0)
sigma_count=$(find "$RULES_DEST/sigma" -name "*.yml" 2>/dev/null | wc -l || echo 0)
yara_count=$(find "$RULES_DEST/yara" -name "*.yar" 2>/dev/null | wc -l || echo 0)
ioc_count=0
ioc_file="$RULES_DEST/iocs/ioc_list.json"
[ -f "$ioc_file" ] || ioc_file="$RULES_DEST/latest/iocs/ioc_list.json"
if [ -f "$ioc_file" ]; then
    ioc_count=$(python3 -c "import json; d=json.load(open('$ioc_file')); print(len(d) if isinstance(d,list) else len(d.get('indicators',d.get('iocs',[]))))" 2>/dev/null || echo "?")
fi

touch "$RULES_DEST/.last-sync"

# ---------- Git commit and push ----------

changes=$(git status --porcelain 2>/dev/null | wc -l)

if [ "$changes" -eq 0 ]; then
    log "No changes to commit."
    exit 0
fi

git add rules/ threat-intel/
git commit -m "$(cat <<EOF
rules: auto-sync $TIMESTAMP

Suricata: $suricata_count files | Sigma: $sigma_count | YARA: $yara_count | IOCs: $ioc_count
EOF
)" --quiet

if git remote get-url origin &>/dev/null; then
    git push --quiet
    log "Pushed to GitHub."
else
    log "No remote configured, commit only (local)."
fi

log "Sync complete."
