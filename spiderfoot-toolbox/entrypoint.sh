#!/bin/sh
# Seed the SpiderFoot "Tool - X" module binary paths into the config DB so the
# tools work without manual setup, then launch the web UI. Re-runs on every
# start (idempotent) so paths stay correct even after a factory reset.
set -e

python - <<'PY' || echo "WARN: tool-path seeding failed (UI will still start)"
from spiderfoot import SpiderFootDb
db = SpiderFootDb({"__database": "/var/lib/spiderfoot/spiderfoot.db"})
db.configSet({
    "_socks1type": "TOR",
    "_socks2addr": "127.0.0.1",
    "_socks3port": "9050",
    "sfp_tool_dnstwist:dnstwistpath": "/opt/venv/bin/dnstwist",
    "sfp_tool_cmseek:cmseekpath": "/tools/CMSeeK/cmseek.py",
    "sfp_tool_whatweb:whatweb_path": "/tools/WhatWeb/whatweb",
    "sfp_tool_wafw00f:wafw00f_path": "/opt/venv/bin/wafw00f",
    "sfp_tool_onesixtyone:onesixtyone_path": "/usr/bin/onesixtyone",
    "sfp_tool_retirejs:retirejs_path": "/usr/bin/retire",
    "sfp_tool_testsslsh:testsslsh_path": "/tools/testssl.sh/testssl.sh",
    "sfp_tool_snallygaster:snallygaster_path": "/opt/venv/bin/snallygaster",
    "sfp_tool_trufflehog:trufflehog_path": "/opt/venv/bin/trufflehog",
    "sfp_tool_nuclei:nuclei_path": "/tools/nuclei",
    "sfp_tool_nuclei:template_path": "/tools/nuclei-templates",
    "sfp_tool_wappalyzer:wappalyzer_path": "/tools/wappalyzer/src/drivers/npm/cli.js",
    "sfp_tool_wappalyzer:node_path": "/usr/bin/node",
    "sfp_tool_nbtscan:nbtscan_path": "/usr/bin/nbtscan",
    "sfp_tool_nmap:nmappath": "/usr/bin/nmap",
})
print("Seeded tool paths into SpiderFoot config.")
PY

# Optional API/module config export (never commit secrets/ to git).
for cfg in /run/spiderfoot-secrets/SpiderFoot.cfg /run/spiderfoot-secrets/*.cfg; do
    if [ -f "$cfg" ]; then
        python /opt/import-spiderfoot-cfg.py "$cfg" || echo "WARN: API config import failed for $cfg"
        break
    fi
done

exec python sf.py -l 0.0.0.0:5001
