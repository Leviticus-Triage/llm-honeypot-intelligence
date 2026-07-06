#!/usr/bin/env bash
# Point Beelzebub/Galah at the cloud Ollama proxy (ai-cloud ECS).
#
#   sudo ./wire-llm.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/cloud.env}"
require_root
require_env_file "${ENV_FILE}"
load_cloud_env "${ENV_FILE}"

TPOTCE_DIR="${TPOTCE_DIR:-/home/${DEPLOY_USER:-ubuntu}/tpotce}"
ENV_PATH="${TPOTCE_DIR}/.env"
[[ -f "${ENV_PATH}" ]] || die "Missing ${ENV_PATH} — complete official tpotce install first"

PROXY_URL="${AI_PROXY_URL:-http://${AI_STACK_PRIVATE_IP:-${AI_STACK_PUBLIC_IP}}:${AI_STACK_PROXY_PORT:-11435}}"
BEE_MODEL="${BEELZEBUB_OLLAMA_MODEL:-dolphin-llama3:8b}"
GALAH_MODEL="${GALAH_LLM_MODEL:-dolphin-llama3:8b}"

log "=== wire-llm.sh ==="
log "Proxy URL: ${PROXY_URL}"

cp -f "${ENV_PATH}" "${ENV_PATH}.bak.$(date +%Y%m%d-%H%M%S)"

set_kv() {
  local key="$1" val="$2"
  if grep -q "^${key}=" "${ENV_PATH}"; then
    sed -i "s|^${key}=.*|${key}=${val}|" "${ENV_PATH}"
  else
    echo "${key}=${val}" >> "${ENV_PATH}"
  fi
}

set_kv BEELZEBUB_LLM_HOST "${PROXY_URL}/api/chat"
set_kv GALAH_LLM_SERVER_URL "${PROXY_URL}"
set_kv BEELZEBUB_OLLAMA_MODEL "${BEE_MODEL}"
set_kv GALAH_LLM_MODEL "${GALAH_MODEL}"

grep -E '^BEELZEBUB_LLM_HOST|^GALAH_LLM_SERVER_URL|^BEELZEBUB_OLLAMA_MODEL|^GALAH_LLM_MODEL' "${ENV_PATH}"

log "Testing proxy reachability from this host..."
if curl -fsS --max-time 10 "${PROXY_URL}/proxy/health" 2>/dev/null; then
  echo
  log "Proxy OK — recreating beelzebub + galah"
  run_as_deploy_user "cd '${TPOTCE_DIR}' && docker compose up -d --force-recreate beelzebub galah"
else
  warn "Cannot reach ${PROXY_URL}/proxy/health — .env updated but containers NOT recreated"
  warn "Fix VPC routing / OTC security groups / ai-cloud UFW, then:"
  warn "  cd ${TPOTCE_DIR} && docker compose up -d --force-recreate beelzebub galah"
  exit 2
fi

log "=== wire-llm.sh complete ==="
