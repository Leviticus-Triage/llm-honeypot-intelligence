from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Optional

import httpx

logger = logging.getLogger("rule-validator.llm_judge")

PROXY_URL = os.environ.get("PROXY_URL", "http://localhost:11435").rstrip("/")
VALIDATOR_TIMEOUT = float(os.environ.get("VALIDATOR_TIMEOUT", "200"))
LLM_RETRY_MAX = int(os.environ.get("VALIDATOR_RETRY_MAX", "4"))
LLM_RETRY_BACKOFF = float(os.environ.get("VALIDATOR_RETRY_BACKOFF", "3.0"))
LLM_MIN_SPACING = float(os.environ.get("VALIDATOR_MIN_SPACING", "1.5"))

_last_request_ts: float = 0.0
_spacing_lock = asyncio.Lock()


async def _pace() -> None:
    global _last_request_ts
    async with _spacing_lock:
        now = time.monotonic()
        delta = now - _last_request_ts
        if delta < LLM_MIN_SPACING:
            await asyncio.sleep(LLM_MIN_SPACING - delta)
        _last_request_ts = time.monotonic()


SYSTEM_PROMPT = """You are a senior detection-engineering reviewer. You audit
automatically generated security rules (Sigma, YARA, Suricata, STIX) produced
by a honeypot analytics system. For each new rule you must judge:

1. Syntax correctness — line references if broken.
2. Logical integrity — every referenced selection / string / sid is defined.
3. Duplicate proximity to the reference rules provided.
4. False-positive risk — what legitimate traffic this rule could match.
5. MITRE ATT&CK mapping plausibility.

Respond with EXACTLY ONE JSON object and nothing else. No prose before or
after. No markdown code fences. Schema:

{
  "ok": bool,
  "confidence": number in [0,1],
  "issues": [{"severity": "low|medium|high", "category": string, "message": string}],
  "suggested_fixes": [string],
  "fp_risk": "low|medium|high",
  "mitre_alignment": "ok|partial|none"
}
"""


def _build_user_prompt(rule_type: str, rule_text: str, neighbors: list[str] | None) -> str:
    neighbors = neighbors or []
    parts = [f"=== new {rule_type} rule ===", rule_text.strip()]
    if neighbors:
        parts.append(f"\n=== {len(neighbors)} most similar existing rules (cosine > 0.85) ===")
        for i, n in enumerate(neighbors, 1):
            parts.append(f"\n--- neighbor {i} ---\n{n.strip()}")
    else:
        parts.append("\n=== no similar existing rules found ===")
    return "\n".join(parts)


def _extract_json(text: str) -> Optional[dict]:
    if not text:
        return None
    text = text.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            pass

    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start : i + 1]
                try:
                    return json.loads(candidate)
                except Exception:
                    return None
    return None


def _normalise_verdict(verdict: dict) -> dict:
    out = {
        "ok": bool(verdict.get("ok", False)),
        "confidence": float(verdict.get("confidence", 0.0) or 0.0),
        "issues": verdict.get("issues") or [],
        "suggested_fixes": verdict.get("suggested_fixes") or [],
        "fp_risk": str(verdict.get("fp_risk", "medium")).lower(),
        "mitre_alignment": str(verdict.get("mitre_alignment", "partial")).lower(),
    }
    if out["confidence"] < 0:
        out["confidence"] = 0.0
    elif out["confidence"] > 1:
        out["confidence"] = 1.0
    if out["fp_risk"] not in {"low", "medium", "high"}:
        out["fp_risk"] = "medium"
    if out["mitre_alignment"] not in {"ok", "partial", "none"}:
        out["mitre_alignment"] = "partial"
    if not isinstance(out["issues"], list):
        out["issues"] = []
    if not isinstance(out["suggested_fixes"], list):
        out["suggested_fixes"] = []
    return out


async def review_rule(
    rule_type: str,
    rule_text: str,
    neighbors: list[str] | None = None,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict:
    body = {
        "model": "placeholder",
        "stream": False,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(rule_type, rule_text, neighbors)},
        ],
        "options": {"num_predict": 512},
    }
    headers = {"X-LLM-Task": "rule_validate", "Content-Type": "application/json"}

    own_client = False
    if client is None:
        client = httpx.AsyncClient(timeout=VALIDATOR_TIMEOUT)
        own_client = True

    try:
        resp = None
        content = ""
        for attempt in range(1, LLM_RETRY_MAX + 1):
            await _pace()
            resp = await client.post(f"{PROXY_URL}/api/chat", json=body, headers=headers)
            if resp.status_code in (503, 429, 502, 504):
                wait = LLM_RETRY_BACKOFF * attempt
                logger.warning(
                    "LLM proxy returned %s on attempt %d/%d; backing off %.1fs",
                    resp.status_code,
                    attempt,
                    LLM_RETRY_MAX,
                    wait,
                )
                if attempt < LLM_RETRY_MAX:
                    await asyncio.sleep(wait)
                    continue
            data = resp.json() if resp.status_code < 500 else {}
            if isinstance(data, dict):
                msg = data.get("message") or {}
                content = msg.get("content") if isinstance(msg, dict) else ""
            break

        verdict = _extract_json(content or "")
        if verdict is None:
            logger.warning(
                "LLM returned non-JSON for %s rule (status=%s, len=%d); abstaining",
                rule_type,
                resp.status_code if resp is not None else "n/a",
                len(content or ""),
            )
            return {
                "ok": False,
                "confidence": 0.0,
                "issues": [
                    {
                        "severity": "high",
                        "category": "llm_noncompliant",
                        "message": "model returned non-JSON or empty body",
                    }
                ],
                "suggested_fixes": [],
                "fp_risk": "medium",
                "mitre_alignment": "partial",
                "_raw_preview": (content or "")[:400],
            }
        return _normalise_verdict(verdict)
    except Exception as e:
        logger.error("LLM judge call failed for %s rule: %s", rule_type, e)
        return {
            "ok": False,
            "confidence": 0.0,
            "issues": [
                {
                    "severity": "high",
                    "category": "llm_unreachable",
                    "message": f"{type(e).__name__}: {e}",
                }
            ],
            "suggested_fixes": [],
            "fp_risk": "medium",
            "mitre_alignment": "partial",
        }
    finally:
        if own_client:
            await client.aclose()
