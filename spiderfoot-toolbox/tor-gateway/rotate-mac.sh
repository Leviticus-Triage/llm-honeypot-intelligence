#!/bin/sh
# Mandatory MAC rotation on the container egress interface (LAN link-layer).
set -eu

IFACE="${MAC_INTERFACE:-eth0}"
MIN_SEC="${MAC_ROTATE_MIN_SEC:-8}"
MAX_SEC="${MAC_ROTATE_MAX_SEC:-15}"

rand_between() {
    awk -v min="$1" -v max="$2" 'BEGIN{srand(); print int(min + rand() * (max - min + 1))}'
}

wait_for_iface() {
    for _ in $(seq 1 30); do
        if ip link show "${IFACE}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "rotate-mac: interface ${IFACE} not found"
    exit 1
}

wait_for_iface

while true; do
    if ! ip link show "${IFACE}" up 2>/dev/null | grep -q "state UP"; then
        ip link set "${IFACE}" up 2>/dev/null || true
    fi
    if macchanger -r "${IFACE}" >/dev/null 2>&1; then
        echo "rotate-mac: new random MAC on ${IFACE} ($(cat /sys/class/net/${IFACE}/address 2>/dev/null || echo unknown))"
    else
        echo "rotate-mac: WARN macchanger failed on ${IFACE}"
        exit 1
    fi
    sleep "$(rand_between "${MIN_SEC}" "${MAX_SEC}")"
done
