#!/usr/bin/env bash
# Verify SpiderFoot scan egress goes through Tor (not the home IP).
set -euo pipefail

CONTAINER="${1:-spiderfoot-toolbox}"
HOST_IP="$(curl -fsS --max-time 10 https://ifconfig.me 2>/dev/null || echo unknown)"

echo "Host (VM200) egress IP: ${HOST_IP}"
echo "Checking ${CONTAINER}..."

TOR_JSON="$(docker exec "${CONTAINER}" curl -fsS --max-time 20 -x socks5h://127.0.0.1:9050 https://check.torproject.org/api/ip)"
echo "Tor check: ${TOR_JSON}"

if echo "${TOR_JSON}" | grep -q '"IsTor":true'; then
    echo "OK: container can reach Tor."
else
    echo "FAIL: Tor SOCKS not working."
    exit 1
fi

SF_IP="$(docker exec "${CONTAINER}" curl -fsS --max-time 20 https://ifconfig.me || true)"
echo "Container transparent egress IP: ${SF_IP:-unreachable}"

if [ -n "${SF_IP:-}" ] && [ "${SF_IP}" != "${HOST_IP}" ]; then
    echo "OK: scan egress IP differs from host (tunnel active)."
else
    echo "WARN: egress IP equals host or check failed — investigate iptables/tor-gateway."
    exit 1
fi
