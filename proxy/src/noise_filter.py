"""
Ingress noise filter — short-circuit known scanner/noise before LLM upstream calls.

Reads noise_ips.json from heuristic detector output and applies lightweight
in-memory heuristics (rate limit, junk prompts). Fail-open: uncertain traffic
still reaches the LLM.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import defaultdict, deque
from pathlib import Path

logger = logging.getLogger("ollama-proxy.noise_filter")

DEFAULT_CANNED = "root@web-prod-03:~# "
JUNK_PROMPT_RE = re.compile(
    r"^(ping|test|hello|hi|help|\?|GET /|HEAD /|\s*)$",
    re.IGNORECASE,
)


class NoiseFilter:
    def __init__(self) -> None:
        self.enabled = os.environ.get("NOISE_FILTER_ENABLED", "1").lower() not in (
            "0", "false", "no", "off",
        )
        self.noise_path = Path(
            os.environ.get("NOISE_IPS_PATH", "/data/ollama-proxy/threat-intel/noise_ips.json")
        )
        self.reload_interval_s = int(os.environ.get("NOISE_FILTER_RELOAD_S", "300"))
        self.rate_window_s = int(os.environ.get("NOISE_RATE_WINDOW_S", "60"))
        self.rate_limit = int(os.environ.get("NOISE_RATE_LIMIT", "30"))
        self.canned_response = os.environ.get("NOISE_CANNED_RESPONSE", DEFAULT_CANNED)

        self._noise_ips: set[str] = set()
        self._last_reload = 0.0
        self._hits_by_reason: dict[str, int] = defaultdict(int)
        self._total_shortcircuits = 0
        self._ip_events: dict[str, deque[float]] = defaultdict(deque)

    def stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "noise_ips_loaded": len(self._noise_ips),
            "total_shortcircuits": self._total_shortcircuits,
            "hits_by_reason": dict(self._hits_by_reason),
            "noise_ips_path": str(self.noise_path),
        }

    def _reload_if_needed(self) -> None:
        now = time.time()
        if now - self._last_reload < self.reload_interval_s:
            return
        self._last_reload = now
        if not self.noise_path.exists():
            return
        try:
            with open(self.noise_path) as f:
                payload = json.load(f)
            ips = {entry["ip"] for entry in payload.get("ips", []) if entry.get("ip")}
            if ips != self._noise_ips:
                logger.info("Noise filter reloaded: %d IPs", len(ips))
            self._noise_ips = ips
        except Exception:
            logger.exception("Failed to reload noise_ips.json")

    def _rate_limited(self, src_ip: str) -> bool:
        if not src_ip:
            return False
        now = time.time()
        q = self._ip_events[src_ip]
        while q and now - q[0] > self.rate_window_s:
            q.popleft()
        q.append(now)
        return len(q) > self.rate_limit

    def _is_junk_prompt(self, prompt_text: str) -> bool:
        text = (prompt_text or "").strip()
        if len(text) < 2:
            return True
        if len(text) > 500:
            return False
        return bool(JUNK_PROMPT_RE.match(text))

    def check(self, src_ip: str, prompt_text: str) -> tuple[bool, str, str]:
        """
        Returns (should_shortcircuit, canned_response, reason).
        Fail-open when disabled or uncertain.
        """
        if not self.enabled:
            return False, "", ""

        self._reload_if_needed()

        if src_ip in self._noise_ips:
            self._record("noise_ip_list")
            return True, self.canned_response, "noise_ip_list"

        if self._rate_limited(src_ip):
            self._record("rate_limit")
            return True, self.canned_response, "rate_limit"

        if self._is_junk_prompt(prompt_text):
            self._record("junk_prompt")
            return True, self.canned_response, "junk_prompt"

        return False, "", ""

    def _record(self, reason: str) -> None:
        self._total_shortcircuits += 1
        self._hits_by_reason[reason] += 1
