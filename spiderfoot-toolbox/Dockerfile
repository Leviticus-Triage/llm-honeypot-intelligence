# SpiderFoot "full" — dedicated OSINT/scanning instance with all CLI tools.
#
# Strategy: take the EXACT SpiderFoot application from the T-Pot image (so the
# modules/UI/option keys match what runs on the honeypot VM), but run it on
# Debian where every tool is easy to install. Tool paths are pre-seeded at
# startup (see entrypoint.sh) so the "Tool - X" modules work out of the box.
#
# Modernised from SpiderFoot's official Dockerfile.full (which had bit-rotted:
# apt-key, nodesource 17, nuclei 2.6.5). Tool versions are chosen to match the
# module invocation syntax (nuclei v2 `-json`, legacy python trufflehog `--regex`).

# ---- Stage 0: SpiderFoot application source (identical to T-Pot) ----
FROM ghcr.io/telekom-security/spiderfoot:24.04.1 AS sfsrc

# ---- Stage 1: Debian runtime with all tools ----
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Europe/Berlin \
    VIRTUAL_ENV=/opt/venv \
    SPIDERFOOT_DATA=/var/lib/spiderfoot \
    SPIDERFOOT_LOGS=/var/lib/spiderfoot/log \
    SPIDERFOOT_CACHE=/var/lib/spiderfoot/cache \
    PUPPETEER_SKIP_DOWNLOAD=1
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# --- Base + apt-installable tools (nmap, nbtscan, onesixtyone) + ruby for WhatWeb ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git unzip xz-utils libcap2-bin \
        openssl procps bsdmainutils dnsutils coreutils tzdata \
        nmap nbtscan onesixtyone \
        ruby ruby-dev build-essential \
    && ln -sf /usr/share/zoneinfo/Europe/Berlin /etc/localtime \
    && echo Europe/Berlin > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

# --- Node.js 20 LTS (retire.js + wappalyzer CLI) ---
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g retire \
    && npm cache clean --force \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

# --- WhatWeb (Ruby) ---
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb /tools/WhatWeb \
    && gem install --no-document rchardet json \
    && ( cd /tools/WhatWeb && bundle install || true )

# --- Nuclei v2.9.15 (module uses the v2 `-json` flag) + templates ---
RUN NUCLEI_VER=2.9.15 \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" -O /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /tools nuclei \
    && rm -f /tmp/nuclei.zip \
    && git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /tools/nuclei-templates

# --- testssl.sh ---
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /tools/testssl.sh

# --- Wappalyzer (Node CLI) — best effort, non-fatal ---
# AliasIO/wappalyzer was archived/made private. Use a maintained public fork.
# A fully functional run still needs a headless browser (Chromium), which is
# intentionally NOT bundled here to protect VM 200 disk; the path is still seeded.
RUN ( git clone --depth 1 https://github.com/dochne/wappalyzer.git /tools/wappalyzer \
      && cd /tools/wappalyzer && npm install ) \
    || echo "WARN: wappalyzer setup incomplete (needs Chromium follow-up to run)"

# --- User ---
RUN groupadd spiderfoot \
    && useradd -m -g spiderfoot -d /home/spiderfoot -s /usr/sbin/nologin -c "SpiderFoot User" spiderfoot

# --- SpiderFoot application (from T-Pot image) ---
COPY --from=sfsrc /home/spiderfoot /home/spiderfoot

# --- Build deps for pycairo (no wheel available); placed late to keep earlier
#     tool layers cached ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcairo2-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# --- Python venv: SpiderFoot deps + python tools ---
# The fork's requirements.txt is incomplete for a from-scratch pip install, so we
# pin the exact, proven dependency set captured from the working T-Pot container.
COPY requirements-full.txt /tmp/requirements-full.txt
# setuptools+wheel must be installed explicitly (Python 3.12 venvs no longer ship
# setuptools, which legacy sdists like pygexf/ipaddr/PyPDF2 need to build).
RUN python -m venv "$VIRTUAL_ENV" \
    && pip install --no-cache-dir -U pip setuptools wheel \
    && pip install --no-cache-dir -r /tmp/requirements-full.txt \
    && pip install --no-cache-dir dnstwist wafw00f snallygaster trufflehog

# --- CMSeeK (Python, cloned) ---
RUN git clone --depth 1 https://github.com/Tuhinshubhra/CMSeeK /tools/CMSeeK \
    && pip install --no-cache-dir -r /tools/CMSeeK/requirements.txt \
    && mkdir -p /tools/CMSeeK/Results

# --- Let nmap use raw sockets as non-root (combined with cap_add in compose) ---
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap || true

# --- Data dirs + ownership ---
# Only chown writable paths. Root-owned tool dirs (/opt/venv, /tools/nuclei-templates,
# wappalyzer node_modules) stay read-only for the non-root user — avoids a slow,
# image-bloating overlayfs copy-up of tens of thousands of files. /home/spiderfoot
# is the user's HOME (tools write dotfiles there); CMSeeK writes to its Results dir.
RUN mkdir -p "$SPIDERFOOT_DATA" "$SPIDERFOOT_LOGS" "$SPIDERFOOT_CACHE" /tools/CMSeeK/Results \
    && chown -R spiderfoot:spiderfoot "$SPIDERFOOT_DATA" /home/spiderfoot /tools/CMSeeK

COPY --chown=spiderfoot:spiderfoot entrypoint.sh /entrypoint.sh
COPY --chown=spiderfoot:spiderfoot import-spiderfoot-cfg.py /opt/import-spiderfoot-cfg.py
RUN chmod +x /entrypoint.sh /opt/import-spiderfoot-cfg.py

WORKDIR /home/spiderfoot
USER spiderfoot
EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:5001/spiderfoot/',timeout=5); sys.exit(0 if r.status in (200,301,302) else 1)" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
