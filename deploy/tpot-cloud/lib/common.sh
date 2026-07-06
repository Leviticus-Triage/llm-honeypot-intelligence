#!/usr/bin/env bash
# Shared helpers for tpot-cloud-deploy (mirrors ai-workstation-cloud patterns).
set -euo pipefail

log()  { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
warn() { printf '[%s] WARN %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
die()  { printf '[%s] ERROR %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; exit 1; }

require_root() {
  [[ "${EUID}" -ne 0 ]] || return 0
  die "Run as root (sudo $0 ...)"
}

require_env_file() {
  local env_file="${1:?}"
  [[ -f "${env_file}" ]] || die "Missing config: ${env_file} — copy cloud.env.example to cloud.env and edit."
}

load_cloud_env() {
  local env_file="${1:?}"
  set -a
  # shellcheck disable=SC1090
  source "${env_file}"
  set +a
}

deploy_user_home() {
  local user="${DEPLOY_USER:-ubuntu}"
  getent passwd "${user}" >/dev/null 2>&1 || die "User ${user} does not exist"
  eval echo "~${user}"
}

run_as_deploy_user() {
  local user="${DEPLOY_USER:-ubuntu}"
  sudo -u "${user}" -H bash -lc "$*"
}

wait_for_url() {
  local url="$1"
  local retries="${2:-60}"
  local delay="${3:-3}"
  local i
  for ((i = 1; i <= retries; i++)); do
    if curl -fsSk --connect-timeout 5 "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${delay}"
  done
  return 1
}
