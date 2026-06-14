FROM alpine:3.20
RUN apk add --no-cache tor iptables ip6tables curl bind-tools macchanger iproute2 netcat-openbsd \
    && mkdir -p /var/lib/tor \
    && chown tor:tor /var/lib/tor \
    && chmod 700 /var/lib/tor
COPY torrc /etc/tor/torrc
COPY entrypoint.sh rotate-mac.sh rotate-tor.sh /
RUN chmod +x /entrypoint.sh /rotate-mac.sh /rotate-tor.sh
HEALTHCHECK --interval=25s --timeout=15s --start-period=240s --retries=5 \
    CMD pgrep -f /rotate-mac.sh >/dev/null \
    && pgrep -f /rotate-tor.sh >/dev/null \
    && curl -fsS --max-time 12 -x socks5h://127.0.0.1:9050 https://check.torproject.org/api/ip | grep -q '"IsTor":true'
ENTRYPOINT ["/entrypoint.sh"]
