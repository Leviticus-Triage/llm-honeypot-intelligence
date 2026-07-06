#!/usr/bin/env bash
# Prepare a fresh Ubuntu ECS for T-Pot (tpotce) — run BEFORE official tpotce install.sh.
#
#   sudo ./install.sh
#   cd ~/tpotce && sudo ./install.sh   # official Telekom installer (interactive)
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

log "=== tpot-cloud-deploy install (host prep) ==="

# --- Hardware sanity (tpotce minimum) ---
mem_gb="$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)"
disk_gb="$(df -BG / | awk 'NR==2 {gsub(/G/,"",$4); print $4}')"
log "RAM: ${mem_gb} GiB, free disk: ${disk_gb} GiB"
[[ "${mem_gb}" -ge 7 ]] || warn "T-Pot recommends >= 8 GiB RAM"
[[ "${disk_gb}" -ge 200 ]] || warn "T-Pot recommends >= 250 GiB disk"

# --- Base packages ---
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git curl ca-certificates jq ufw

# --- Guest tuning (zram + swap — from former VM 400 profile) ---
if [[ -f "${SCRIPT_DIR}/scripts/guest-tuning.sh" ]]; then
  log "Applying guest-tuning (zram + swapfile)"
  bash "${SCRIPT_DIR}/scripts/guest-tuning.sh"
fi

# --- Clone tpotce ---
if [[ "${CLONE_TPOTCE:-true}" == "true" ]]; then
  if [[ -d "${TPOTCE_DIR}/.git" ]]; then
    log "tpotce already cloned — git pull"
    run_as_deploy_user "cd '${TPOTCE_DIR}' && git pull --ff-only" || warn "git pull failed"
  else
    log "Cloning ${TPOTCE_REPO}"
    run_as_deploy_user "git clone --depth 1 -b '${TPOTCE_BRANCH:-master}' '${TPOTCE_REPO}' '${TPOTCE_DIR}'"
  fi
fi

# --- UFW baseline (honeypot ports opened by tpotce install) ---
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 64295/tcp comment 'T-Pot SSH'
ufw allow 64297/tcp comment 'T-Pot Web/ES'
ufw --force enable

install -d -o "${DEPLOY_USER}" -g "${DEPLOY_USER}" "${DEPLOY_BUNDLE_DIR:-/home/${DEPLOY_USER}/tpot-cloud-deploy}"

log "=== install.sh complete ==="
log "Next: cd ${TPOTCE_DIR} && sudo ./install.sh  (official T-Pot — choose HIVE, set WEB_USER password)"
log "Then:  cd ${DEPLOY_BUNDLE_DIR:-~/tpot-cloud-deploy} && sudo ./deploy-custom.sh && sudo ./wire-llm.sh"
