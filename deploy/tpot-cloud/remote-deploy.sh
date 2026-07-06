#!/usr/bin/env bash
# Push tpot-cloud-deploy (+ llm-honeypot-intelligence deploy assets) to a remote T-Pot ECS.
#
# From Blade (NOT on the VPS, NOT with sudo):
#   cd /mnt/docker-ssd/cursor-Projekts/Sec-Systems
#   ./tpot-cloud-deploy/remote-deploy.sh ubuntu@NEW.TPOT.IP
#   ./tpot-cloud-deploy/remote-deploy.sh ai-tpot --install-only
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEC_SYSTEMS="$(cd "${SCRIPT_DIR}/.." && pwd)"

REMOTE="${1:-}"
MODE="${2:-all}"
[[ -n "${REMOTE}" ]] || {
  echo "Usage: $0 <ssh-target> [--install-only|--bundle-only]" >&2
  exit 1
}

REMOTE_DIR="${REMOTE_DIR:-~/tpot-cloud-deploy}"
INSTALL_ONLY=false
BUNDLE_ONLY=false
[[ "${MODE}" == "--install-only" ]] && INSTALL_ONLY=true
[[ "${MODE}" == "--bundle-only" ]] && BUNDLE_ONLY=true

resolve_identity_file() {
  if [[ -n "${SSH_IDENTITY_FILE:-}" && -f "${SSH_IDENTITY_FILE}" ]]; then
    echo "${SSH_IDENTITY_FILE}"
    return
  fi
  local f
  while IFS= read -r f; do
    f="${f/#\~/$HOME}"
    [[ -f "${f}" ]] && { echo "${f}"; return; }
  done < <(ssh -G "${REMOTE}" 2>/dev/null | awk '/^identityfile / {print $2}')
  echo ""
}

IDENTITY_FILE="$(resolve_identity_file)"
SSH_BASE=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
if [[ -n "${IDENTITY_FILE}" ]]; then
  SSH_BASE+=(-i "${IDENTITY_FILE}" -o IdentitiesOnly=yes)
  export RSYNC_RSH="ssh -i ${IDENTITY_FILE} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
else
  export RSYNC_RSH="ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
fi

echo "[remote-deploy] tpot-cloud-deploy -> ${REMOTE}:${REMOTE_DIR}"

"${SSH_BASE[@]}" "${REMOTE}" "mkdir -p ${REMOTE_DIR}"

rsync -az --delete \
  --exclude 'cloud.env' \
  --exclude '.git' \
  "${SCRIPT_DIR}/" "${REMOTE}:${REMOTE_DIR}/"

# Optional: stage llm-honeypot-intelligence deploy/tpot helpers
if [[ -d "${SEC_SYSTEMS}/llm-honeypot-intelligence/deploy/tpot" ]]; then
  "${SSH_BASE[@]}" "${REMOTE}" "mkdir -p ${REMOTE_DIR}/llm-honeypot-intelligence/deploy/tpot"
  rsync -az \
    "${SEC_SYSTEMS}/llm-honeypot-intelligence/deploy/tpot/" \
    "${REMOTE}:${REMOTE_DIR}/llm-honeypot-intelligence/deploy/tpot/"
fi

"${SSH_BASE[@]}" "${REMOTE}" bash -s <<REMOTE
set -euo pipefail
cd ${REMOTE_DIR}
chmod +x install.sh deploy-custom.sh wire-llm.sh verify.sh connect-ai-stack.sh lib/common.sh scripts/*.sh 2>/dev/null || true
if [[ ! -f cloud.env ]]; then
  cp cloud.env.example cloud.env
  echo "[remote-deploy] Created cloud.env — edit TPOT_PUBLIC_IP + AI_STACK_* before install"
fi
REMOTE

[[ "${BUNDLE_ONLY}" == true ]] && { echo "[remote-deploy] bundle-only done"; exit 0; }

if [[ "${INSTALL_ONLY}" != true ]]; then
  echo "[remote-deploy] Run official tpotce install manually after install.sh (see README)"
fi

if [[ "${INSTALL_ONLY}" != true && "${BUNDLE_ONLY}" != true ]]; then
  "${SSH_BASE[@]}" -t "${REMOTE}" "cd ${REMOTE_DIR} && sudo ./install.sh"
fi

echo "[remote-deploy] done"
echo ""
echo "On the T-Pot ECS:"
echo "  1) Edit ~/tpot-cloud-deploy/cloud.env (IPs, AI proxy URL)"
echo "  2) cd ~/tpotce && sudo ./install.sh   # official Telekom installer"
echo "  3) cd ~/tpot-cloud-deploy && sudo ./deploy-custom.sh && sudo ./wire-llm.sh"
echo ""
echo "From Blade (both servers up):"
echo "  ./tpot-cloud-deploy/connect-ai-stack.sh ${REMOTE} ai-cloud"
