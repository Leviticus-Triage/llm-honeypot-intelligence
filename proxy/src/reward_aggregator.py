"""
Reward Aggregator (Phase 5).

Builds response-level rewards from CVE session telemetry and writes:
- Elasticsearch index: honeypot-response-rewards
- Local SQLite table: response_rewards (used by cache ranking)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

import httpx

from .es_client import es_client_kwargs

from . import adversarial_judge as aj

logger = logging.getLogger("reward-aggregator")

ES_URL = os.environ.get("ES_URL", "https://localhost:64297/es")
ES_USER = os.environ.get("ES_USER", "")
ES_PASS = os.environ.get("ES_PASS", "")

DB_PATH = os.environ.get("CACHE_DB", "/data/ollama-proxy/cache.db")
REWARD_INDEX = os.environ.get("REWARD_INDEX", "honeypot-response-rewards")

WINDOW_MINUTES = int(os.environ.get("REWARD_WINDOW_MINUTES", "30"))
SESSION_GAP_SECONDS = int(os.environ.get("REWARD_SESSION_GAP_SECONDS", "300"))

VALIDATED_RULES_DIR = Path(
    os.environ.get("VALIDATED_RULES_DIR", "/data/ollama-proxy/validated-rules/approved")
)
RULES_DIR = Path(os.environ.get("RULES_DIR", "/data/ollama-proxy/generated-rules/latest"))

PATTERNS_NEG = [
    r"\bhoneypot\b",
    r"\bhoney[- ]?pot\b",
    r"this is a trap",
    r"looks like a honeypot",
    r"\bfake\s+(?:system|host|shell|server)\b",
    r"\bnot a real\b",
    r"i can see the flag",
    r"i'm out",
    r"\bfoobar\b",
]

PATTERNS_POS_RECON = [
    r"\buname\b",
    r"\bwhoami\b",
    r"\bid\s*$",
    r"\bhostname\b",
    r"\buptime\b",
    r"\blast\b",
    r"\bw\s*$",
    r"\blscpu\b",
    r"\bfree\s+-?m\b",
    r"\bdf\s+-?h\b",
    r"cat\s+/etc/passwd",
    r"cat\s+/etc/shadow",
    r"cat\s+/proc/cpuinfo",
    r"cat\s+/proc/version",
    r"cat\s+/etc/os-release",
    r"\bls\s+-l?a?h?\s+/",
    r"\benv\s*$",
]

PATTERNS_POS_DOWNLOAD = [
    r"\bwget\b",
    r"\bcurl\s+.*https?://",
    r"curl\s+.+\.(?:sh|py|bin|elf|exe|zip|tar|tgz)",
    r"\btftp\b",
    r"\bscp\b",
    r"\brsync\b",
]

PATTERNS_POS_EXEC = [
    r"chmod\s+\+?x",
    r"chmod\s+[0-7]{3,4}",
    r"\b\.?/tmp/\S+",
    r"\bbash\s+-[ciles]{1,4}\b",
    r"\bsh\s+-[ciles]{1,4}\b",
    r"\bpython\s+-c\b",
    r"\bperl\s+-e\b",
]

PATTERNS_POS_PERSIST = [
    r"\.ssh/authorized_keys",
    r"crontab\s+-[le]",
    r"/etc/cron\.d/",
    r"systemctl\s+enable",
    r"\bupdate-rc\.d\b",
    r"/etc/rc\.local",
    r"/etc/init\.d/",
]

PATTERNS_POS_EXFIL = [
    r"rm\s+/var/log",
    r"history\s+-c",
    r"/dev/null\s*2>&1",
    r"nohup\s+",
    r"\bnc\s+-[lpv]+",
    r"\b/dev/tcp/",
    r"\bbase64\s+-d\b",
]

PATTERNS_POS_PRIVESC = [
    r"\bsudo\s+",
    r"\bsu\s+root\b",
    r"setuid",
    r"\bpasswd\s+root\b",
    r"pkexec",
]

# Weight per category — richer exploit activity = stronger "unmasked" signal
POS_CATEGORIES: list[tuple[str, float, list[str]]] = [
    ("recon", 0.20, PATTERNS_POS_RECON),
    ("download", 0.40, PATTERNS_POS_DOWNLOAD),
    ("execution", 0.35, PATTERNS_POS_EXEC),
    ("persistence", 0.55, PATTERNS_POS_PERSIST),
    ("exfil", 0.45, PATTERNS_POS_EXFIL),
    ("privesc", 0.50, PATTERNS_POS_PRIVESC),
]

NEG_RE = [re.compile(p, re.IGNORECASE) for p in PATTERNS_NEG]
POS_CATEGORY_RE: list[tuple[str, float, list[re.Pattern]]] = [
    (name, weight, [re.compile(p, re.IGNORECASE) for p in patterns])
    for name, weight, patterns in POS_CATEGORIES
]
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


@dataclass
class SessionEvent:
    ts: datetime
    src_ip: str
    cve_id: str
    serve_log_id: int
    prompt_text: str
    response_text: str


@dataclass
class RewardRecord:
    session_id: str
    serve_log_id: int
    response_id: int | None
    response_hash: str
    model: str
    cve_tag: str
    reward_a: float
    reward_b: float
    reward_c: float
    total_reward: float
    ts: datetime
    prompt_text: str = ""
    response_text: str = ""
    # Plausibility score from the adversarial critic (0.0-1.0). -1.0 means
    # "not judged yet" — distinguishable from a legitimate 0.0 ("implausible").
    plausibility_score: float = -1.0

    def to_es_doc(self) -> dict:
        doc = {
            "@timestamp": self.ts.isoformat(),
            "response_hash": self.response_hash,
            "session_id": self.session_id,
            "model": self.model,
            "cve_tag": self.cve_tag,
            "serve_log_id": self.serve_log_id,
            "response_id": self.response_id,
            "reward_a_engagement": self.reward_a,
            "reward_b_unmasked": self.reward_b,
            "reward_c_rule_yield": self.reward_c,
            "total_reward": self.total_reward,
        }
        if self.plausibility_score >= 0.0:
            doc["plausibility_score"] = round(self.plausibility_score, 4)
        return doc


def _clamp01(v: float) -> float:
    return max(0.0, min(1.0, v))


def _reward_engagement(duration_s: float, cmd_cnt: int) -> float:
    return _clamp01((0.3 * (duration_s / 300.0)) + (0.7 * (cmd_cnt / 15.0)))


def _reward_unmasking(text: str) -> float:
    """
    Data-driven unmasking score on [-1, +1]:
      - Explicit "you're a honeypot"-style tell-offs => -1
      - Category-weighted sum of attacker behaviours (recon / download /
        execution / persistence / exfil / privesc), cumulative across
        the whole session text, saturates at +1.
      - Returns 0 only if nothing observed at all (neutral).
    """
    t = text or ""
    if any(r.search(t) for r in NEG_RE):
        return -1.0
    score = 0.0
    seen: set[str] = set()
    for name, weight, compiled in POS_CATEGORY_RE:
        for r in compiled:
            if r.search(t):
                if name not in seen:
                    score += weight
                    seen.add(name)
                break
    return _clamp01(score)


def _total_reward(a: float, b: float, c: float) -> float:
    return 0.40 * a + 0.35 * b + 0.25 * c


def _response_hash(model: str, prompt_text: str, response_text: str) -> str:
    raw = f"{model}\n{prompt_text}\n{response_text}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def _scan_cves_from_rules(paths: Iterable[Path]) -> set[str]:
    """
    Collect CVE identifiers mentioned by any generated/validated artifact:
      - Any rule file text (sigma/yara/suricata/stix/ioc)
      - manifest.json "cves_covered" explicit list
      - directory names under cve/<CVE-ID>/
    Conservative fail-soft: errors per-file are ignored.
    """
    found: set[str] = set()
    for p in paths:
        if not p.exists():
            continue
        if p.is_file():
            files = [p]
        else:
            files = [x for x in p.rglob("*") if x.is_file()]
            # Consider any directory named like a CVE as explicit coverage
            for d in p.rglob("*"):
                if d.is_dir() and CVE_RE.fullmatch(d.name or ""):
                    found.add(d.name.upper())
        for f in files:
            if f.suffix.lower() not in {".yml", ".yaml", ".json", ".yar", ".yara",
                                         ".rules", ".txt", ".md", ".conf"}:
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for m in CVE_RE.findall(text):
                found.add(m.upper())
            if f.name == "manifest.json":
                try:
                    data = json.loads(text)
                except Exception:
                    data = None
                if isinstance(data, dict):
                    for key in ("cves_covered", "cve_coverage", "cves"):
                        cves = data.get(key) or []
                        if isinstance(cves, list):
                            for c in cves:
                                if isinstance(c, str) and CVE_RE.search(c):
                                    found.add(c.upper())
    return found


def _lookup_local_response(serve_log_id: int) -> tuple[int | None, str, str, str]:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT sl.response_id, pc.model, pc.prompt_text, r.response_text "
            "FROM serve_log sl "
            "JOIN responses r ON r.id = sl.response_id "
            "JOIN prompt_cache pc ON pc.id = r.prompt_cache_id "
            "WHERE sl.id = ?",
            (serve_log_id,),
        ).fetchone()
        if not row:
            return None, "", "", ""
        return int(row["response_id"]), row["model"] or "", row["prompt_text"] or "", row["response_text"] or ""
    finally:
        conn.close()


async def _es_search(index: str, body: dict) -> dict:
    async with httpx.AsyncClient(**es_client_kwargs(30.0)) as client:
        resp = await client.post(f"{ES_URL}/{index}/_search", json=body)
        if resp.status_code != 200:
            logger.warning("ES search failed on %s: %s", index, resp.text[:200])
            return {"hits": {"hits": []}}
        return resp.json()


async def _ensure_reward_index() -> None:
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "response_hash": {"type": "keyword"},
                "session_id": {"type": "keyword"},
                "model": {"type": "keyword"},
                "cve_tag": {"type": "keyword"},
                "serve_log_id": {"type": "long"},
                "response_id": {"type": "long"},
                "reward_a_engagement": {"type": "float"},
                "reward_b_unmasked": {"type": "float"},
                "reward_c_rule_yield": {"type": "float"},
                "total_reward": {"type": "float"},
                "plausibility_score": {"type": "float"},
            }
        }
    }
    async with httpx.AsyncClient(**es_client_kwargs(30.0)) as client:
        head = await client.head(f"{ES_URL}/{REWARD_INDEX}")
        if head.status_code == 200:
            return
        resp = await client.put(f"{ES_URL}/{REWARD_INDEX}", json=mapping)
        if resp.status_code in (200, 201):
            logger.info("Created index %s", REWARD_INDEX)
        elif resp.status_code == 400 and "resource_already_exists" in resp.text:
            return
        else:
            logger.warning("Reward index create returned %s: %s", resp.status_code, resp.text[:200])


async def fetch_cve_events(*, since_minutes: int) -> list[SessionEvent]:
    since = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
    body = {
        "size": 2000,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"exists": {"field": "serve_log_id"}},
                    {"exists": {"field": "cve_id"}},
                ]
            }
        },
        "sort": [{"@timestamp": "asc"}],
        "_source": ["@timestamp", "src_ip", "cve_id", "serve_log_id", "prompt_text", "response_text"],
    }
    data = await _es_search("honeypot-cve-sessions", body)
    out: list[SessionEvent] = []
    for hit in data.get("hits", {}).get("hits", []):
        s = hit.get("_source", {})
        ts = s.get("@timestamp")
        src_ip = s.get("src_ip", "")
        cve_id = (s.get("cve_id", "") or "").upper()
        sid = s.get("serve_log_id")
        if not ts or not src_ip or not cve_id or sid is None:
            continue
        try:
            tsv = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except Exception:
            continue
        out.append(
            SessionEvent(
                ts=tsv,
                src_ip=src_ip,
                cve_id=cve_id,
                serve_log_id=int(sid),
                prompt_text=str(s.get("prompt_text", "") or ""),
                response_text=str(s.get("response_text", "") or ""),
            )
        )
    return out


def build_sessions(events: list[SessionEvent]) -> list[tuple[str, list[SessionEvent]]]:
    if not events:
        return []
    sessions: list[tuple[str, list[SessionEvent]]] = []
    groups: dict[tuple[str, str], list[SessionEvent]] = {}
    for e in events:
        groups.setdefault((e.src_ip, e.cve_id), []).append(e)
    for (src_ip, cve_id), evs in groups.items():
        evs.sort(key=lambda x: x.ts)
        chunk: list[SessionEvent] = []
        start_ts = evs[0].ts
        prev = evs[0].ts
        for e in evs:
            if chunk and (e.ts - prev).total_seconds() > SESSION_GAP_SECONDS:
                session_id = hashlib.sha1(
                    f"{src_ip}|{cve_id}|{int(start_ts.timestamp())}".encode("utf-8")
                ).hexdigest()[:24]
                sessions.append((session_id, chunk))
                chunk = []
                start_ts = e.ts
            chunk.append(e)
            prev = e.ts
        if chunk:
            session_id = hashlib.sha1(
                f"{src_ip}|{cve_id}|{int(start_ts.timestamp())}".encode("utf-8")
            ).hexdigest()[:24]
            sessions.append((session_id, chunk))
    return sessions


def compute_records(sessions: list[tuple[str, list[SessionEvent]]], cves_with_rules: set[str]) -> list[RewardRecord]:
    records: list[RewardRecord] = []
    for session_id, evs in sessions:
        evs_sorted = sorted(evs, key=lambda x: x.ts)
        start_ts = evs_sorted[0].ts
        end_ts = evs_sorted[-1].ts
        duration = max(1.0, (end_ts - start_ts).total_seconds())
        cmd_cnt = len(evs_sorted)
        reward_a = _reward_engagement(duration, cmd_cnt)
        session_blob = "\n".join(
            [(e.prompt_text or "") for e in evs_sorted]
        )
        reward_b = _reward_unmasking(session_blob)
        cve_tag = evs_sorted[0].cve_id
        reward_c = 1.0 if cve_tag in cves_with_rules else 0.0
        total = _total_reward(reward_a, reward_b, reward_c)

        for e in evs_sorted:
            response_id, model, prompt_text, response_text = _lookup_local_response(e.serve_log_id)
            model_v = model or "openchat"
            prompt_v = prompt_text or e.prompt_text
            response_v = response_text or e.response_text
            r_hash = _response_hash(model_v, prompt_v, response_v)
            records.append(
                RewardRecord(
                    session_id=session_id,
                    serve_log_id=e.serve_log_id,
                    response_id=response_id,
                    response_hash=r_hash,
                    model=model_v,
                    cve_tag=cve_tag,
                    reward_a=round(reward_a, 4),
                    reward_b=round(reward_b, 4),
                    reward_c=round(reward_c, 4),
                    total_reward=round(total, 4),
                    ts=e.ts,
                    prompt_text=prompt_v,
                    response_text=response_v,
                )
            )
    return records


def upsert_local_rewards(records: list[RewardRecord]) -> int:
    if not records:
        return 0
    conn = sqlite3.connect(DB_PATH, timeout=10)
    try:
        updated = 0
        for r in records:
            if r.response_id is None:
                continue
            # plausibility_score is optional: only overwrite when we have a
            # fresh score (>=0); preserve previous value otherwise.
            if r.plausibility_score >= 0.0:
                conn.execute(
                    "INSERT INTO response_rewards("
                    "response_id, response_hash, session_id, model, cve_tag, "
                    "reward_a_engagement, reward_b_unmasked, reward_c_rule_yield, "
                    "total_reward, plausibility_score, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now')) "
                    "ON CONFLICT(response_id) DO UPDATE SET "
                    "response_hash=excluded.response_hash, "
                    "session_id=excluded.session_id, "
                    "model=excluded.model, "
                    "cve_tag=excluded.cve_tag, "
                    "reward_a_engagement=excluded.reward_a_engagement, "
                    "reward_b_unmasked=excluded.reward_b_unmasked, "
                    "reward_c_rule_yield=excluded.reward_c_rule_yield, "
                    "total_reward=excluded.total_reward, "
                    "plausibility_score=excluded.plausibility_score, "
                    "updated_at=datetime('now')",
                    (
                        r.response_id,
                        r.response_hash,
                        r.session_id,
                        r.model,
                        r.cve_tag,
                        r.reward_a,
                        r.reward_b,
                        r.reward_c,
                        r.total_reward,
                        r.plausibility_score,
                    ),
                )
            else:
                conn.execute(
                    "INSERT INTO response_rewards("
                    "response_id, response_hash, session_id, model, cve_tag, "
                    "reward_a_engagement, reward_b_unmasked, reward_c_rule_yield, "
                    "total_reward, updated_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now')) "
                    "ON CONFLICT(response_id) DO UPDATE SET "
                    "response_hash=excluded.response_hash, "
                    "session_id=excluded.session_id, "
                    "model=excluded.model, "
                    "cve_tag=excluded.cve_tag, "
                    "reward_a_engagement=excluded.reward_a_engagement, "
                    "reward_b_unmasked=excluded.reward_b_unmasked, "
                    "reward_c_rule_yield=excluded.reward_c_rule_yield, "
                    "total_reward=excluded.total_reward, "
                    "updated_at=datetime('now')",
                    (
                        r.response_id,
                        r.response_hash,
                        r.session_id,
                        r.model,
                        r.cve_tag,
                        r.reward_a,
                        r.reward_b,
                        r.reward_c,
                        r.total_reward,
                    ),
                )
            updated += 1
        conn.commit()
        return updated
    finally:
        conn.close()


async def push_rewards_to_es(records: list[RewardRecord]) -> int:
    if not records:
        return 0
    bulk = []
    for r in records:
        doc_id = f"{r.session_id}-{r.serve_log_id}"
        bulk.append(json.dumps({"index": {"_index": REWARD_INDEX, "_id": doc_id}}))
        bulk.append(json.dumps(r.to_es_doc()))
    payload = "\n".join(bulk) + "\n"
    async with httpx.AsyncClient(**es_client_kwargs(60.0)) as client:
        resp = await client.post(
            f"{ES_URL}/_bulk",
            content=payload,
            headers={"Content-Type": "application/x-ndjson"},
        )
        if resp.status_code not in (200, 201):
            logger.warning("Reward bulk push failed: %s", resp.text[:200])
            return 0
        return len(records)


async def judge_records(records: list[RewardRecord]) -> dict:
    """
    Annotate records with adversarial plausibility scores.
    Cache hits are free; cache misses call the critic LLM via the proxy.
    Bounded by JUDGE_BATCH_LIMIT so a single cycle can never stall the
    aggregator loop if the critic is slow or Ollama cold-loads the model.

    Mutates `records` in-place: sets r.plausibility_score for every record
    whose response_hash is present in (or newly added to) the judgement cache.
    Returns a small summary dict.
    """
    if not aj.JUDGE_ENABLED:
        return {"enabled": False, "hit": 0, "miss": 0, "judged": 0, "skipped": 0}

    hits = miss = judged = skipped = errors = 0
    # Pre-fill from cache: cheap local SQLite reads first, so we minimise the
    # critic-LLM calls to just the records we have never seen.
    need_judge: list[RewardRecord] = []
    seen_hashes: set[str] = set()
    for r in records:
        if not r.response_hash:
            continue
        cached = aj.get_cached_judgement(DB_PATH, r.response_hash)
        if cached is not None:
            r.plausibility_score = cached.plausibility
            hits += 1
            continue
        if r.response_hash in seen_hashes:
            # Same hash already queued for judging; copy the score post-loop.
            need_judge_hashes = {x.response_hash for x in need_judge}
            if r.response_hash in need_judge_hashes:
                continue
        if not r.response_text:
            # Nothing to judge; keep plausibility_score == -1.0 (unscored).
            skipped += 1
            continue
        need_judge.append(r)
        seen_hashes.add(r.response_hash)
        miss += 1

    if not need_judge:
        return {"enabled": True, "hit": hits, "miss": 0, "judged": 0,
                "skipped": skipped, "errors": 0, "limit": aj.JUDGE_BATCH_LIMIT}

    to_judge = need_judge[: aj.JUDGE_BATCH_LIMIT]
    remainder = len(need_judge) - len(to_judge)

    async with httpx.AsyncClient(timeout=aj.JUDGE_TIMEOUT + 10.0) as client:
        for r in to_judge:
            try:
                j = await aj.judge_response(client, r.prompt_text, r.response_text)
            except Exception as e:
                logger.warning("Judge crash for response_hash=%s: %s",
                               r.response_hash[:12], e)
                errors += 1
                continue
            if j is None:
                errors += 1
                continue
            j.response_hash = r.response_hash
            r.plausibility_score = j.plausibility
            aj.upsert_judgement(DB_PATH, r.response_hash, r.model, j)
            judged += 1

    # Propagate fresh scores back to any OTHER records that share a hash we
    # just judged (same response served twice in the same cycle).
    score_by_hash = {r.response_hash: r.plausibility_score for r in to_judge
                     if r.plausibility_score >= 0.0}
    if score_by_hash:
        for r in records:
            if r.plausibility_score < 0.0 and r.response_hash in score_by_hash:
                r.plausibility_score = score_by_hash[r.response_hash]

    return {
        "enabled": True,
        "hit": hits,
        "miss": miss,
        "judged": judged,
        "skipped": skipped,
        "errors": errors,
        "deferred": remainder,
        "limit": aj.JUDGE_BATCH_LIMIT,
    }


async def run_reward_cycle(*, since_minutes: int = WINDOW_MINUTES) -> dict:
    await _ensure_reward_index()
    events = await fetch_cve_events(since_minutes=since_minutes)
    if not events:
        return {"events": 0, "sessions": 0, "local_updates": 0, "es_docs": 0}

    cves_with_rules = _scan_cves_from_rules([VALIDATED_RULES_DIR, RULES_DIR])
    sessions = build_sessions(events)
    records = compute_records(sessions, cves_with_rules)

    # Adversarial judging runs BEFORE persistence so SQLite + ES both get the
    # fresh plausibility score in the same cycle.
    judge_summary = await judge_records(records)

    local_updates = upsert_local_rewards(records)
    es_docs = await push_rewards_to_es(records)
    summary = {
        "events": len(events),
        "sessions": len(sessions),
        "records": len(records),
        "local_updates": local_updates,
        "es_docs": es_docs,
        "rules_cve_count": len(cves_with_rules),
        "judge": judge_summary,
    }
    logger.info("Reward cycle summary: %s", summary)
    return summary
