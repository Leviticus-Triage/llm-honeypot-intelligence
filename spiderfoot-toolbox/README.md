# SpiderFoot Toolbox (dedicated, tool-equipped)

A standalone SpiderFoot instance with all CLI scanning/OSINT tools installed and
their module paths **pre-configured**. Runs on **VM 200 (ai-workstation)** so the
scanning load and outbound scan traffic stay **off the T-Pot honeypot VM**.

- UI: `http://192.168.2.116:5001`
- The T-Pot SpiderFoot (`https://192.168.2.22:64297/spiderfoot`) is left unchanged.

## Why a separate instance

SpiderFoot runs the "Tool - X" modules as **local subprocesses**, so the tool
binaries must live where SpiderFoot runs. The T-Pot SpiderFoot container only
persists `.spiderfoot` (settings) — installed tools would be lost on every T-Pot
update, and active scanning shouldn't originate from the honeypot's IP. A
dedicated, version-controlled image on VM 200 solves all three.

The SpiderFoot application itself is copied from the exact T-Pot image
(`ghcr.io/telekom-security/spiderfoot:24.04.1`) so modules/UI/option keys match,
but it runs on Debian where the tools install cleanly.

## Tools + pre-seeded paths

Seeded on every container start by `entrypoint.sh` (idempotent):

| Module | Binary path | Source |
|--------|-------------|--------|
| sfp_tool_nmap | `/usr/bin/nmap` | apt (file-caps for non-root raw scans) |
| sfp_tool_nbtscan | `/usr/bin/nbtscan` | apt |
| sfp_tool_onesixtyone | `/usr/bin/onesixtyone` | apt |
| sfp_tool_whatweb | `/tools/WhatWeb/whatweb` | git (Ruby) |
| sfp_tool_nuclei | `/tools/nuclei` + `/tools/nuclei-templates` | release v2.9.15 + git |
| sfp_tool_testsslsh | `/tools/testssl.sh/testssl.sh` | git |
| sfp_tool_dnstwist | `/opt/venv/bin/dnstwist` | pip |
| sfp_tool_wafw00f | `/opt/venv/bin/wafw00f` | pip |
| sfp_tool_snallygaster | `/opt/venv/bin/snallygaster` | pip |
| sfp_tool_trufflehog | `/opt/venv/bin/trufflehog` | pip (legacy v2, matches `--regex`) |
| sfp_tool_cmseek | `/tools/CMSeeK/cmseek.py` | git (Python) |
| sfp_tool_retirejs | `/usr/bin/retire` | npm |
| sfp_tool_wappalyzer | `/tools/wappalyzer/src/drivers/npm/cli.js` | git/npm (see notes) |

## Deploy / update

```bash
docker compose up -d --build      # build + (re)start
docker compose logs -f spiderfoot # watch
```

## Notes

- **nmap**: binary has `cap_net_raw,cap_net_admin` file-caps and the container
  adds those capabilities, so SYN/OS scans work without running as root.
- **nuclei**: pinned to v2.9.15 to match the module's `-json` flag. Templates are
  cloned at build (latest); some newer templates target the v3 engine and may be
  skipped. Bumping to nuclei v3 would require patching the module's `-json`→`-jsonl`.
- **trufflehog**: legacy Python v2 (the module uses `--regex/--entropy`, which the
  modern Go v3 dropped).
- **wappalyzer**: The original AliasIO npm CLI (`cli.js`) no longer exists in
  public forks (dochne/wappalyzer is extension-only). The module path is seeded
  but the file is missing — disable **Tool - Wappalyzer** in scans until a
  compatible CLI adapter is added (e.g. `simple-wappalyzer` + Chromium).
- **Auth**: SpiderFoot 4 ships without auth. Keep on the trusted LAN or put a
  reverse proxy / `passwd` file in front before any wider exposure.
