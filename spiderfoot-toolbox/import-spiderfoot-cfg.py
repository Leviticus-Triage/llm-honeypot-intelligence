#!/usr/bin/env python3
"""Import a SpiderFoot .cfg export (API keys + module opts) into the toolbox DB."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from sflib import SpiderFoot
from spiderfoot import SpiderFootDb, SpiderFootHelpers

DB_PATH = "/var/lib/spiderfoot/spiderfoot.db"
MOD_DIR = "/home/spiderfoot/modules/"

TOOL_PATHS = {
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
}


def load_default_config() -> dict:
    sf_config = {
        "_debug": False,
        "_maxthreads": 3,
        "__logging": True,
        "__outputfilter": None,
        "_useragent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) "
            "Gecko/20100101 Firefox/62.0"
        ),
        "_dnsserver": "",
        "_fetchtimeout": 5,
        "_internettlds": "https://publicsuffix.org/list/effective_tld_names.dat",
        "_internettlds_cache": 72,
        "_genericusers": ",".join(
            SpiderFootHelpers.usernamesFromWordlists(["generic-usernames"])
        ),
        "__database": DB_PATH,
        "__modules__": None,
        "__correlationrules__": None,
        "_socks1type": "",
        "_socks2addr": "",
        "_socks3port": "",
        "_socks4user": "",
        "_socks5pwd": "",
    }
    sf_config["__modules__"] = SpiderFootHelpers.loadModulesAsDict(
        MOD_DIR, ["sfp_template.py"]
    )
    return sf_config


def parse_cfg(path: Path) -> dict[str, str]:
    opts: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        opts[key.strip()] = val.strip()
    return opts


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} /path/to/SpiderFoot.cfg", file=sys.stderr)
        return 2

    cfg_file = Path(sys.argv[1])
    if not cfg_file.is_file():
        print(f"File not found: {cfg_file}", file=sys.stderr)
        return 1

    useropts = parse_cfg(cfg_file)
    sf_config = load_default_config()
    dbh = SpiderFootDb(sf_config)
    sf = SpiderFoot(sf_config)
    current = sf.configUnserialize(dbh.configGet(), sf_config)
    merged = sf.configUnserialize(useropts, current)
    serialized = sf.configSerialize(merged)
    serialized.update(TOOL_PATHS)
    dbh.configSet(serialized)

    filled = sum(1 for v in useropts.values() if v)
    api_filled = sum(1 for k, v in useropts.items() if v and "api_key" in k)
    print(
        f"Imported {len(useropts)} options "
        f"({filled} non-empty, {api_filled} API keys set)."
    )
    print(f"DB config entries: {len(dbh.configGet())}")
    return 0


if __name__ == "__main__":
    os.chdir("/home/spiderfoot")
    raise SystemExit(main())
