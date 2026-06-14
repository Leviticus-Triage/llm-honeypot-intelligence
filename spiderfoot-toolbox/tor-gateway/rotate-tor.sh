#!/bin/sh
# Mandatory Tor exit rotation via CONTROL SIGNAL NEWNYM every 30–60s.
set -eu

MIN_SEC="${TOR_ROTATE_MIN_SEC:-30}"
MAX_SEC="${TOR_ROTATE_MAX_SEC:-60}"
COOKIE_FILE="/var/lib/tor/control_auth_cookie"
CONTROL_HOST="${TOR_CONTROL_HOST:-127.0.0.1}"
CONTROL_PORT="${TOR_CONTROL_PORT:-9051}"

rand_between() {
    awk -v min="$1" -v max="$2" 'BEGIN{srand(); print int(min + rand() * (max - min + 1))}'
}

wait_for_cookie() {
    for _ in $(seq 1 120); do
        if [ -r "${COOKIE_FILE}" ]; then
            return 0
        fi
        sleep 1
    done
    echo "rotate-tor: control cookie not available"
    exit 1
}

send_newnym() {
    cookie_hex="$(od -An -tx1 "${COOKIE_FILE}" | tr -d ' \n')"
    if [ -z "${cookie_hex}" ]; then
        echo "rotate-tor: empty control cookie"
        return 1
    fi
    printf 'AUTHENTICATE %s\nSIGNAL NEWNYM\nQUIT\n' "${cookie_hex}" \
        | nc -w 8 "${CONTROL_HOST}" "${CONTROL_PORT}" 2>/dev/null \
        | grep -q "250 OK"
}

wait_for_cookie

while true; do
    if send_newnym; then
        echo "rotate-tor: SIGNAL NEWNYM ok ($(date -Iseconds 2>/dev/null || date))"
    else
        echo "rotate-tor: NEWNYM failed — exiting"
        exit 1
    fi
    sleep "$(rand_between "${MIN_SEC}" "${MAX_SEC}")"
done
