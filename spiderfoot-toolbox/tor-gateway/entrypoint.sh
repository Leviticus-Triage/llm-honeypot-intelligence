#!/bin/sh
# Transparent Tor egress + mandatory MAC/Tor exit rotation for SpiderFoot scans.
set -eu

TOR_TRANS_PORT="${TOR_TRANS_PORT:-9040}"
TOR_DNS_PORT="${TOR_DNS_PORT:-9053}"
TOR_UID="$(id -u tor 2>/dev/null || echo 100)"
LAN_CIDRS="${LAN_CIDRS:-192.168.0.0/16 10.0.0.0/8 172.16.0.0/12 127.0.0.0/8}"

MAC_ROT_PID=""
TOR_ROT_PID=""

cleanup() {
    [ -n "${MAC_ROT_PID}" ] && kill "${MAC_ROT_PID}" 2>/dev/null || true
    [ -n "${TOR_ROT_PID}" ] && kill "${TOR_ROT_PID}" 2>/dev/null || true
    [ -n "${TOR_PID:-}" ] && kill "${TOR_PID}" 2>/dev/null || true
}
trap cleanup INT TERM

setup_iptables() {
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD DROP

    iptables -t nat -A OUTPUT -m owner --uid-owner "${TOR_UID}" -j RETURN

    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports "${TOR_DNS_PORT}"
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports "${TOR_DNS_PORT}"

    for cidr in ${LAN_CIDRS}; do
        iptables -t nat -A OUTPUT -p tcp -d "${cidr}" -j RETURN
    done
    iptables -t nat -A OUTPUT -p tcp --dport "${TOR_TRANS_PORT}" -j RETURN
    iptables -t nat -A OUTPUT -p tcp --dport "${TOR_DNS_PORT}" -j RETURN
    iptables -t nat -A OUTPUT -p tcp --dport 9050 -j RETURN
    iptables -t nat -A OUTPUT -p tcp --dport 9051 -j RETURN
    iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports "${TOR_TRANS_PORT}"

    for cidr in ${LAN_CIDRS}; do
        iptables -A OUTPUT -p udp -d "${cidr}" -j ACCEPT
        iptables -A OUTPUT -p icmp -d "${cidr}" -j ACCEPT
    done
    iptables -A OUTPUT -p udp -j DROP
}

start_mandatory_rotators() {
    echo "Starting mandatory MAC rotator (${MAC_ROTATE_MIN_SEC:-8}-${MAC_ROTATE_MAX_SEC:-15}s)..."
    /rotate-mac.sh &
    MAC_ROT_PID=$!

    echo "Starting mandatory Tor exit rotator (${TOR_ROTATE_MIN_SEC:-30}-${TOR_ROTATE_MAX_SEC:-60}s)..."
    /rotate-tor.sh &
    TOR_ROT_PID=$!

    sleep 2
    if ! kill -0 "${MAC_ROT_PID}" 2>/dev/null; then
        echo "FATAL: MAC rotator failed to start"
        exit 1
    fi
    if ! kill -0 "${TOR_ROT_PID}" 2>/dev/null; then
        echo "FATAL: Tor rotator failed to start"
        exit 1
    fi
    echo "Mandatory rotators active."
}

watchdog() {
    while kill -0 "${TOR_PID}" 2>/dev/null; do
        if ! kill -0 "${MAC_ROT_PID}" 2>/dev/null; then
            echo "FATAL: MAC rotator died — stopping gateway (no scans without rotation)"
            exit 1
        fi
        if ! kill -0 "${TOR_ROT_PID}" 2>/dev/null; then
            echo "FATAL: Tor rotator died — stopping gateway (no scans without rotation)"
            exit 1
        fi
        sleep 5
    done
    wait "${TOR_PID}"
}

echo "Starting Tor (bootstrap without intercept rules)..."
su -s /bin/sh tor -c "tor -f /etc/tor/torrc" &
TOR_PID=$!

echo "Waiting for Tor bootstrap..."
ready=0
for i in $(seq 1 150); do
    if curl -fsS --max-time 5 -x socks5h://127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null | grep -q '"IsTor":true'; then
        ready=1
        break
    fi
    if ! kill -0 "${TOR_PID}" 2>/dev/null; then
        echo "ERROR: tor process exited during bootstrap"
        exit 1
    fi
    sleep 2
done

if [ "$ready" -ne 1 ]; then
    echo "ERROR: Tor failed to bootstrap within 300s"
    exit 1
fi

echo "Tor bootstrapped — enabling transparent proxy iptables."
setup_iptables
start_mandatory_rotators
echo "Tor egress ready (MAC + exit rotation enforced)."

watchdog
