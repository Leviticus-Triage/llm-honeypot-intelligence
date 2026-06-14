#!/bin/sh
# Transparent Tor egress for containers sharing this network namespace.
set -eu

TOR_TRANS_PORT="${TOR_TRANS_PORT:-9040}"
TOR_DNS_PORT="${TOR_DNS_PORT:-9053}"
TOR_UID="$(id -u tor 2>/dev/null || echo 100)"
LAN_CIDRS="${LAN_CIDRS:-192.168.0.0/16 10.0.0.0/8 172.16.0.0/12 127.0.0.0/8}"

setup_iptables() {
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD DROP

    # Never intercept Tor daemon traffic (must reach relays directly).
    iptables -t nat -A OUTPUT -m owner --uid-owner "${TOR_UID}" -j RETURN

    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports "${TOR_DNS_PORT}"
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports "${TOR_DNS_PORT}"

    for cidr in ${LAN_CIDRS}; do
        iptables -t nat -A OUTPUT -p tcp -d "${cidr}" -j RETURN
    done
    iptables -t nat -A OUTPUT -p tcp --dport "${TOR_TRANS_PORT}" -j RETURN
    iptables -t nat -A OUTPUT -p tcp --dport "${TOR_DNS_PORT}" -j RETURN
    iptables -t nat -A OUTPUT -p tcp --dport 9050 -j RETURN
    iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports "${TOR_TRANS_PORT}"

    for cidr in ${LAN_CIDRS}; do
        iptables -A OUTPUT -p udp -d "${cidr}" -j ACCEPT
        iptables -A OUTPUT -p icmp -d "${cidr}" -j ACCEPT
    done
    iptables -A OUTPUT -p udp -j DROP
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
    kill "${TOR_PID}" 2>/dev/null || true
    exit 1
fi

echo "Tor bootstrapped — enabling transparent proxy iptables."
setup_iptables
echo "Tor egress ready."

wait "${TOR_PID}"
