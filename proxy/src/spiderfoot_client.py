"""
SpiderFoot REST API client for automated footprint scans.

SpiderFoot runs at SPIDERFOOT_URL (default http://127.0.0.1:5001/spiderfoot).
All five startscan form fields are required; usecase must be capitalized
(Passive, Footprint, Investigate, all).
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("ollama-proxy.spiderfoot")

SPIDERFOOT_URL = os.environ.get(
    "SPIDERFOOT_URL", "http://127.0.0.1:5001/spiderfoot"
).rstrip("/")

# Passive modules that work reasonably through Tor for IP targets.
PASSIVE_IP_MODULES = os.environ.get(
    "SPIDERFOOT_PASSIVE_MODULES",
    "sfp_dnsresolve,sfp_whois,sfp_ripe,sfp_bgpview,sfp_robtex,"
    "sfp_ipinfo,sfp_onyphe,sfp_shodan,sfp_greynoise,sfp_abuseipdb",
)


class SpiderFootError(Exception):
    """Raised when SpiderFoot API returns an error response."""


class SpiderFootClient:
    """Async HTTP client for SpiderFoot web UI API."""

    def __init__(
        self,
        base_url: str = SPIDERFOOT_URL,
        timeout: float = 60.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def ping(self) -> bool:
        """Return True if SpiderFoot responds."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(
                    f"{self.base_url}/ping",
                    headers={"Accept": "application/json"},
                )
                return r.status_code == 200
        except Exception as exc:
            logger.warning("SpiderFoot ping failed: %s", exc)
            return False

    async def start_scan(
        self,
        target: str,
        scan_name: str,
        *,
        usecase: str = "Passive",
        modulelist: str = "",
        typelist: str = "",
    ) -> str:
        """
        Start a scan and return the scan ID (8-char hex).

        For IP targets prefer Passive usecase with PASSIVE_IP_MODULES.
        """
        if usecase == "Passive" and not modulelist:
            modulelist = PASSIVE_IP_MODULES

        payload = {
            "scanname": scan_name,
            "scantarget": target,
            "modulelist": modulelist,
            "typelist": typelist,
            "usecase": usecase,
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            r = await client.post(
                f"{self.base_url}/startscan",
                data=payload,
                headers={"Accept": "application/json"},
            )

        if r.status_code != 200:
            raise SpiderFootError(
                f"startscan HTTP {r.status_code}: {r.text[:300]}"
            )

        body = r.text.strip()

        # JSON array: ["SUCCESS", "A1B2C3D4"] or ["ERROR", "message"]
        try:
            data = r.json()
            if isinstance(data, list) and len(data) >= 2:
                status, scan_id = str(data[0]).upper(), str(data[1])
                if status == "SUCCESS" and len(scan_id) == 8:
                    return scan_id.upper()
                if status != "SUCCESS":
                    raise SpiderFootError(f"startscan rejected: {data}")
            if isinstance(data, list) and len(data) == 1:
                candidate = str(data[0]).upper()
                if len(candidate) == 8 and all(c in "0123456789ABCDEF" for c in candidate):
                    return candidate
            if isinstance(data, dict) and data.get("id"):
                return str(data["id"]).upper()
        except SpiderFootError:
            raise
        except Exception:
            pass

        # Bare scan id like "A1B2C3D4"
        if len(body) == 8 and all(c in "0123456789ABCDEF" for c in body.upper()):
            return body.upper()

        if "error" in body.lower() or "invalid" in body.lower():
            raise SpiderFootError(f"startscan rejected: {body[:300]}")

        raise SpiderFootError(f"Unexpected startscan response: {body[:300]}")

    @staticmethod
    def parse_scan_status(data: list) -> dict[str, Any]:
        """
        Normalize scanstatus JSON.

        SpiderFoot 4.x returns a flat list:
          [name, target, started, created?, ended, status, risk_counts]
        Older docs showed nested lists — handle both.
        """
        if not data:
            return {"status": "UNKNOWN", "raw": data}

        row = data[0] if data and isinstance(data[0], list) else data
        if not isinstance(row, list) or len(row) < 6:
            return {"status": "UNKNOWN", "raw": data}

        status = str(row[5]).upper()
        return {
            "name": row[0] if len(row) > 0 else "",
            "target": row[1] if len(row) > 1 else "",
            "started": row[2] if len(row) > 2 else "",
            "ended": row[4] if len(row) > 4 else "",
            "status": status,
            "raw": data,
        }

    async def get_scan_status(self, scan_id: str) -> str:
        """Return uppercase scan status string (RUNNING, FINISHED, STARTING, ...)."""
        data = await self._fetch_scan_status(scan_id)
        return self.parse_scan_status(data).get("status", "UNKNOWN")

    async def _fetch_scan_status(self, scan_id: str) -> list:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(
                f"{self.base_url}/scanstatus",
                params={"id": scan_id},
                headers={"Accept": "application/json"},
            )

        if r.status_code != 200:
            raise SpiderFootError(
                f"scanstatus HTTP {r.status_code}: {r.text[:200]}"
            )

        data = r.json()
        if not isinstance(data, list):
            raise SpiderFootError(f"Unexpected scanstatus: {data!r}")
        return data

    async def scan_status(self, scan_id: str) -> list[list[Any]]:
        """
        Return raw scanstatus JSON (flat list in SpiderFoot 4.x).

        Prefer get_scan_status() for polling.
        """
        return await self._fetch_scan_status(scan_id)

    async def wait_for_scan(
        self,
        scan_id: str,
        *,
        poll_interval: float = 30.0,
        timeout: float = 3600.0,
    ) -> str:
        """Poll until scan finishes. Returns final status string."""
        elapsed = 0.0
        while elapsed < timeout:
            status = await self.get_scan_status(scan_id)
            logger.info("Scan %s status: %s (%.0fs)", scan_id, status, elapsed)

            if status in ("FINISHED", "FINISHED-ERROR"):
                return status
            if status.startswith("ABORT") or status.startswith("ERROR"):
                return status

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        raise SpiderFootError(f"Scan {scan_id} timed out after {timeout}s")

    async def export_json(self, scan_id: str) -> list[dict]:
        """Export scan results as JSON event list."""
        async with httpx.AsyncClient(timeout=120.0) as client:
            r = await client.post(
                f"{self.base_url}/scanexportjsonmulti",
                data={"ids": scan_id},
                headers={"Accept": "application/json"},
            )

        if r.status_code != 200:
            raise SpiderFootError(
                f"scanexportjsonmulti HTTP {r.status_code}: {r.text[:200]}"
            )

        data = r.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("events", data.get("data", []))
        return []

    async def stop_scan(self, scan_id: str) -> None:
        """Abort a running scan."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            await client.get(
                f"{self.base_url}/stopscan",
                params={"id": scan_id},
                headers={"Accept": "application/json"},
            )
