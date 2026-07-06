#!/usr/bin/env bash
# Apply llm-honeypot-intelligence custom mods after official tpotce install.
#
#   sudo ./deploy-custom.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/cloud.env}"
require_root
require_env_file "${ENV_FILE}"
load_cloud_env "${ENV_FILE}"

DEPLOY_USER="${DEPLOY_USER:-ubuntu}"
TPOTCE_DIR="${TPOTCE_DIR:-/home/${DEPLOY_USER}/tpotce}"
CUSTOM_SRC="${SCRIPT_DIR}/custom"
CUSTOM_DST="${CUSTOM_DIR:-${TPOTCE_DIR}/custom}"

[[ -d "${TPOTCE_DIR}" ]] || die "tpotce not found at ${TPOTCE_DIR} — run install.sh + official tpotce install first"

log "=== deploy-custom.sh ==="

install -d -o "${DEPLOY_USER}" -g "${DEPLOY_USER}" "${CUSTOM_DST}"

# Custom directory (noise csv, blocklist helpers, logstash filter copy target)
rsync -a "${CUSTOM_SRC}/" "${CUSTOM_DST}/"
chown -R "${DEPLOY_USER}:${DEPLOY_USER}" "${CUSTOM_DST}"

# docker-compose.override.yml at tpotce root
if [[ -f "${CUSTOM_SRC}/docker-compose.override.yml" ]]; then
  install -o "${DEPLOY_USER}" -g "${DEPLOY_USER}" -m 0644 \
    "${CUSTOM_SRC}/docker-compose.override.yml" "${TPOTCE_DIR}/docker-compose.override.yml"
  log "Installed docker-compose.override.yml"
fi

# Logstash noise filter — tpotce custom mount pattern
if [[ -f "${CUSTOM_SRC}/logstash-noise-filter.conf" ]]; then
  install -o "${DEPLOY_USER}" -g "${DEPLOY_USER}" -m 0644 \
    "${CUSTOM_SRC}/logstash-noise-filter.conf" "${CUSTOM_DST}/logstash-noise-filter.conf"
  log "Installed custom/logstash-noise-filter.conf (mount via tpotce custom hooks if needed)"
fi

# Blocklist timer from llm-honeypot-intelligence
LLM_REPO=""
for candidate in "${SCRIPT_DIR}/../llm-honeypot-intelligence" "${SCRIPT_DIR}/../.." "${SCRIPT_DIR}/.."; do
  [[ -d "${candidate}/deploy/tpot" ]] && { LLM_REPO="${candidate}"; break; }
done
if [[ -n "${LLM_REPO}" && -f "${LLM_REPO}/deploy/tpot/setup-blocklist-timer.sh" ]]; then
  rsync -a "${LLM_REPO}/deploy/tpot/" "${CUSTOM_DST}/"
  chmod +x "${CUSTOM_DST}/setup-blocklist-timer.sh" 2>/dev/null || true
  log "Copied deploy/tpot blocklist timer scripts"
fi

# Recreate stack if already running
if [[ -f "${TPOTCE_DIR}/.env" ]]; then
  log "Recreating T-Pot compose stack with custom overrides..."
  run_as_deploy_user "cd '${TPOTCE_DIR}' && docker compose up -d"
else
  warn "No ${TPOTCE_DIR}/.env yet — run official tpotce install.sh first, then re-run deploy-custom.sh"
fi

# ES noise ILM (best-effort after ES is up)
if [[ -f "${SCRIPT_DIR}/scripts/setup-es-noise-ilm.sh" ]]; then
  ES_URL="${ES_URL:-}" ES_USER="${ES_USER:-}" ES_PASS="${ES_PASS:-}" \
    bash "${SCRIPT_DIR}/scripts/setup-es-noise-ilm.sh" || warn "ILM setup skipped (ES not ready or creds missing)"
fi

log "=== deploy-custom.sh complete ==="
