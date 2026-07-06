#!/usr/bin/env bash
# Health checks for T-Pot ECS + custom stack readiness.
#
#   sudo ./verify.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/cloud.env}"
[[ -f "${ENV_FILE}" ]] && load_cloud_env "${ENV_FILE}"

TPOTCE_DIR="${TPOTCE_DIR:-/home/${DEPLOY_USER:-ubuntu}/tpotce}"
fail=0

log "=== verify.sh (tpot-cloud) ==="

if [[ -d "${TPOTCE_DIR}/.git" || -f "${TPOTCE_DIR}/.env" ]]; then
  log "OK  tpotce directory ${TPOTCE_DIR}"
else
  warn "FAIL tpotce not installed"
  fail=$((fail + 1))
fi

if docker ps --format '{{.Names}}' 2>/dev/null | grep -qE 'elasticsearch|tpot'; then
  log "OK  docker honeypot stack running"
  docker ps --format 'table {{.Names}}\t{{.Status}}' | head -15
else
  warn "FAIL no T-Pot containers running"
  fail=$((fail + 1))
fi

if [[ -n "${ES_URL:-}" && "${ES_URL}" != *YOUR_* ]]; then
  if curl -fsSk -u "${ES_USER:-}:${ES_PASS:-}" "${ES_URL}/_cluster/health" >/dev/null 2>&1; then
    log "OK  Elasticsearch ${ES_URL}"
  else
    warn "FAIL Elasticsearch not reachable (check ES_URL / credentials)"
    fail=$((fail + 1))
  fi
else
  log "SKIP ES (cloud.env ES_URL not configured)"
fi

PROXY_URL="${AI_PROXY_URL:-}"
if [[ -n "${PROXY_URL}" ]]; then
  if curl -fsS --max-time 8 "${PROXY_URL}/proxy/health" >/dev/null 2>&1; then
    log "OK  ai-cloud proxy ${PROXY_URL}"
  else
    warn "FAIL cannot reach ai-cloud proxy — check VPC + UFW"
    fail=$((fail + 1))
  fi
fi

[[ -f "${TPOTCE_DIR}/docker-compose.override.yml" ]] && log "OK  docker-compose.override.yml" || warn "SKIP custom override"

exit "${fail}"
