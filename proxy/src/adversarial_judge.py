"""
Adversarial Response Judge (Phase 3.3).

Second LLM ("critic") rates every honeypot response for realism against the
prompt that produced it. Scores are cached by response_hash so a given
(model, prompt, response) triple is only judged once — the judge is slow and
relatively expensive compared to the honeypot's real-time traffic.

Design decisions:
- Runs OUT-OF-BAND from the reward aggregator (same 15 min cycle), so it never
  adds latency to the honeypot hot path.
- Calls the proxy with `X-LLM-Task: adversarial_critique`, which routes to
  `llama3.2:3b` and bypasses cache.
- Results are persisted to SQLite `response_judgements` (cache) and surfaced as
  a new field `plausibility_score` on the reward document for ES/Kibana.
- NOT yet mixed into `total_reward`. We first collect a few days of data, then
  decide a weight. Until then `total_reward` is unchanged and downstream
  consumers (cache ranking, dashboards) see a new observability field only.

Judge rubric (0.0 = implausible, 1.0 = indistinguishable from a real host):
- 1.0  Looks exactly like a real Linux shell / HTTP server / service response
       with correct syntax, plausible filesystem paths, realistic error text.
- 0.7  Mostly plausible, minor inconsistencies (wrong uid/hostname, slightly
       off whitespace, missing `echo $?` semantics).
- 0.4  Clearly LLM-generated but topically correct (prose-style answer where a
       one-liner is expected).
- 0.1  Breaks character ("As an AI ..."), explanations of commands, disclaimers.
- 0.0  Explicit honeypot tell-offs ("you are in a honeypot").
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger("adversarial-judge")

PROXY_URL = os.environ.get("PROXY_URL", "http://localhost:11435")
JUDGE_TIMEOUT = float(os.environ.get("JUDGE_TIMEOUT", "90"))
JUDGE_BATCH_LIMIT = int(os.environ.get("JUDGE_BATCH_LIMIT", "100"))
JUDGE_ENABLED = os.environ.get("JUDGE_ENABLED", "true").lower() in {"1", "true", "yes"}
JUDGE_MAX_PROMPT_CHARS = int(os.environ.get("JUDGE_MAX_PROMPT_CHARS", "1500"))
JUDGE_MAX_RESPONSE_CHARS = int(os.environ.get("JUDGE_MAX_RESPONSE_CHARS", "2000"))

CRITIC_MODEL = "llama3.2:3b"

# System prompt is terse; the critic has to be fast and consistent.
_SYSTEM_PROMPT = (
    "You are a red-team deception analyst. You receive (a) an attacker's "
    "input to a Linux honeypot and (b) the honeypot's reply. Rate how "
    "realistic the reply is as output from a REAL Linux host / service — "
    "NOT how helpful, safe, or polite. Return STRICT JSON: "
    '{"plausibility": <float 0.0-1.0>, "tells": [<short reasons why it looks '
    'fake, or empty list if plausible>]}. If the reply breaks character '
    "(\"as an AI\", disclaimers, explanations), score ≤ 0.2. If the reply "
    "names itself a honeypot or mentions fake/trap, score 0.0. If syntax, "
    "paths, and error text match a real host, score ≥ 0.8."
)

_USER_TEMPLATE = (
    "ATTACKER INPUT:\n{prompt}\n\n"
    "HONEYPOT REPLY:\n{response}\n\n"
    "Return JSON with keys plausibility (0.0-1.0) and tells (array of "
    "short strings). No other fields."
)

# Regex fallback: the critic sometimes wraps JSON in prose.
_JSON_SPAN_RE = re.compile(r"\{[\s\S]*?\}", re.MULTILINE)


@dataclass
class Judgement:
    response_hash: str
    plausibility: float
    reasons: list[str]
    critic_model: str


def _clamp01(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


def _truncate(text: str, n: int) -> str:
    t = text or ""
    if len(t) <= n:
        return t
    return t[: n - 1] + "…"


def _parse_judge_output(raw: str) -> Optional[tuple[float, list[str]]]:
    if not raw:
        return None
    candidates: list[str] = []
    stripped = raw.strip()
    candidates.append(stripped)
    candidates.extend(_JSON_SPAN_RE.findall(stripped))
    for c in candidates:
        try:
            obj = json.loads(c)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        if "plausibility" not in obj:
            continue
        try:
            p = _clamp01(float(obj["plausibility"]))
        except (TypeError, ValueError):
            continue
        tells_raw = obj.get("tells", [])
        if isinstance(tells_raw, list):
            reasons = [str(x)[:120] for x in tells_raw if x]
        elif isinstance(tells_raw, str):
            reasons = [tells_raw[:120]] if tells_raw else []
        else:
            reasons = []
        return p, reasons[:5]
    return None


async def judge_response(
    client: httpx.AsyncClient,
    prompt_text: str,
    response_text: str,
) -> Optional[Judgement]:
    """
    Call the critic LLM via the proxy. Returns None on transport/parse errors;
    caller decides whether to retry or skip.
    """
    payload = {
        "model": CRITIC_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {
                "role": "user",
                "content": _USER_TEMPLATE.format(
                    prompt=_truncate(prompt_text, JUDGE_MAX_PROMPT_CHARS),
                    response=_truncate(response_text, JUDGE_MAX_RESPONSE_CHARS),
                ),
            },
        ],
        "stream": False,
    }
    headers = {"X-LLM-Task": "adversarial_critique"}
    try:
        resp = await client.post(
            f"{PROXY_URL}/api/chat",
            json=payload,
            headers=headers,
            timeout=JUDGE_TIMEOUT,
        )
    except httpx.ReadTimeout:
        logger.warning("Judge timeout after %.0fs", JUDGE_TIMEOUT)
        return None
    except httpx.HTTPError as e:
        logger.warning("Judge transport error: %s", e)
        return None

    if resp.status_code != 200:
        logger.warning("Judge upstream %s: %s", resp.status_code, resp.text[:200])
        return None

    try:
        data = resp.json()
    except Exception:
        logger.warning("Judge non-JSON HTTP body: %s", resp.text[:200])
        return None

    content = ""
    msg = data.get("message") or {}
    if isinstance(msg, dict):
        content = msg.get("content") or ""
    if not content:
        content = data.get("response") or ""
    parsed = _parse_judge_output(content)
    if parsed is None:
        logger.warning("Judge returned unparseable content: %r", content[:200])
        return None
    plausibility, reasons = parsed
    return Judgement(
        response_hash="",  # caller fills in
        plausibility=plausibility,
        reasons=reasons,
        critic_model=CRITIC_MODEL,
    )


# ---------------------------------------------------------------------------
# SQLite persistence layer — cached by response_hash so we never re-judge the
# same (model, prompt, response) triple. The table is initialised in models.py.
# ---------------------------------------------------------------------------

def get_cached_judgement(db_path: str, response_hash: str) -> Optional[Judgement]:
    if not response_hash:
        return None
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT response_hash, plausibility, reasons, critic_model "
                "FROM response_judgements WHERE response_hash = ?",
                (response_hash,),
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.OperationalError as e:
        logger.debug("get_cached_judgement: %s", e)
        return None
    if not row:
        return None
    reasons: list[str]
    try:
        parsed = json.loads(row["reasons"] or "[]")
        reasons = list(parsed) if isinstance(parsed, list) else []
    except Exception:
        reasons = []
    return Judgement(
        response_hash=row["response_hash"],
        plausibility=float(row["plausibility"]),
        reasons=reasons,
        critic_model=row["critic_model"] or "",
    )


def upsert_judgement(
    db_path: str,
    response_hash: str,
    model: str,
    judgement: Judgement,
) -> None:
    if not response_hash:
        return
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        conn.execute(
            "INSERT INTO response_judgements("
            "response_hash, plausibility, model, reasons, critic_model, judged_at"
            ") VALUES (?, ?, ?, ?, ?, datetime('now')) "
            "ON CONFLICT(response_hash) DO UPDATE SET "
            "plausibility=excluded.plausibility, "
            "model=excluded.model, "
            "reasons=excluded.reasons, "
            "critic_model=excluded.critic_model, "
            "judged_at=datetime('now')",
            (
                response_hash,
                judgement.plausibility,
                model or "",
                json.dumps(judgement.reasons, ensure_ascii=False),
                judgement.critic_model,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def judgement_stats(db_path: str) -> dict:
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        try:
            row = conn.execute(
                "SELECT COUNT(*), AVG(plausibility), MIN(plausibility), "
                "MAX(plausibility) FROM response_judgements"
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return {"count": 0, "avg": None, "min": None, "max": None}
    count, avg, mn, mx = row
    return {
        "count": int(count or 0),
        "avg": round(float(avg), 4) if avg is not None else None,
        "min": float(mn) if mn is not None else None,
        "max": float(mx) if mx is not None else None,
    }
