#!/usr/bin/env bash
# Wire both ECS instances after T-Pot is live — run from Blade (NOT on the VPS).
#
#   cd Sec-Systems
#   ./tpot-cloud-deploy/connect-ai-stack.sh ai-tpot ai-cloud
#
# Updates ai-cloud cloud.env (ES_*) and redeploys proxy; runs wire-llm.sh on T-Pot.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEC_SYSTEMS="$(cd "${SCRIPT_DIR}/.." && pwd)"

TPOT_SSH="${1:-}"
AI_SSH="${2:-ai-cloud}"
[[ -n "${TPOT_SSH}" ]] || {
  echo "Usage: $0 <tpot-ssh-target> [ai-ssh-target]" >&2
  echo "  e.g. $0 ubuntu@NEW.TPOT.IP ai-cloud" >&2
  exit 1
}

TPOT_IP="$(ssh -o BatchMode=yes -G "${TPOT_SSH}" 2>/dev/null | awk '/^hostname /{print $2}')"
[[ -n "${TPOT_IP}" ]] || TPOT_IP="${TPOT_SSH#*@}"

log() { echo "[connect-ai-stack] $*"; }

log "1) Read ES credentials from T-Pot ${TPOT_SSH}..."
read -r ES_USER ES_PASS <<EOF
$(ssh -o BatchMode=yes "${TPOT_SSH}" "grep -E '^WEB_USER=|^WEB_PASSWORD=' ~/tpotce/.env 2>/dev/null | head -2 | cut -d= -f2" | paste -sd' ' -)
EOF
[[ -n "${ES_USER}" && -n "${ES_PASS}" ]] || {
  echo "[connect-ai-stack] ERROR: Could not read WEB_USER/WEB_PASSWORD from ~/tpotce/.env on T-Pot" >&2
  echo "Set ES_USER/ES_PASS in tpot-cloud-deploy/cloud.env manually and re-run." >&2
  exit 1
}

ES_URL="https://${TPOT_IP}:64297/es"

log "2) Patch ai-cloud cloud.env (ES_URL, TPOT_VM_IP)..."
ssh -o BatchMode=yes "${AI_SSH}" "python3 << 'PY'
from pathlib import Path
p = Path.home() / 'ai-workstation-cloud-deploy/Sec-Systems/ai-workstation-cloud/cloud.env'
text = p.read_text()
updates = {
  'ES_URL': '${ES_URL}',
  'ES_USER': '${ES_USER}',
  'ES_PASS': '${ES_PASS}',
  'TPOT_VM_IP': '${TPOT_IP}',
}
lines = []
seen = set()
for line in text.splitlines():
    if '=' in line and not line.strip().startswith('#'):
        k = line.split('=',1)[0]
        if k in updates:
            lines.append(f\"{k}={updates[k]}\")
            seen.add(k)
            continue
    lines.append(line)
for k,v in updates.items():
    if k not in seen:
        lines.append(f\"{k}={v}\")
p.write_text('\\n'.join(lines) + '\\n')
print('patched', ', '.join(updates.keys()))
PY"

log "3) Redeploy ollama-proxy on ai-cloud..."
ssh -o BatchMode=yes -t "${AI_SSH}" "cd ~/ai-workstation-cloud-deploy/Sec-Systems/ai-workstation-cloud && sudo ENV_FILE=./cloud.env ./deploy.sh" || true

log "4) Wire LLM on T-Pot..."
ssh -o BatchMode=yes -t "${TPOT_SSH}" "cd ~/tpot-cloud-deploy && sudo ./wire-llm.sh"

log "5) Verify ES from ai-cloud..."
ssh -o BatchMode=yes "${AI_SSH}" "curl -fsSk -u '${ES_USER}:${ES_PASS}' '${ES_URL}/_cluster/health' | head -c 200; echo"
ssh -o BatchMode=yes "${AI_SSH}" "curl -fsS http://127.0.0.1:11435/proxy/health"

log "=== connect-ai-stack complete ==="
