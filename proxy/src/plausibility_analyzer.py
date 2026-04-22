"""
Plausibility Analyzer (Roadmap 3.3 follow-up).

Runs once per day from the reward aggregator. Its job:

  1. Decide whether we have enough adversarial-judge data to derive a
     defensible weight for mixing `plausibility_score` into `total_reward`.
  2. If the gate is OPEN, produce a full Markdown report with:
       - Coverage summary (count / days / stddev / per-model breakdown)
       - Pearson correlations between plausibility and each of reward A/B/C
       - Recommended blend weight (conservative default, capped)
       - Triage list: top-N low-plausibility responses with critic reasons
  3. If the gate is CLOSED, emit a short "not yet ready" status line
     describing exactly what is missing. No noise in the output dir.

Design principle: the analyzer NEVER applies the recommendation
automatically. It writes the report, a human reads it, and decides.
This mirrors how `calibrate_thresholds.py` is used elsewhere in the
project — computer suggests, human applies.
"""

from __future__ import annotations

import json
import logging
import math
import os
import sqlite3
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("plausibility-analyzer")

# ---------------------------------------------------------------------------
# Configuration — conservative defaults so the gate stays CLOSED until we
# genuinely have enough signal to avoid snap judgements on early noise.
# ---------------------------------------------------------------------------
MIN_JUDGEMENTS = int(os.environ.get("PLAUSIBILITY_MIN_JUDGEMENTS", "300"))
MIN_CALENDAR_DAYS = int(os.environ.get("PLAUSIBILITY_MIN_DAYS", "3"))
MIN_STDDEV = float(os.environ.get("PLAUSIBILITY_MIN_STDDEV", "0.10"))
TRIAGE_TOP_N = int(os.environ.get("PLAUSIBILITY_TRIAGE_TOP_N", "20"))
REPORT_DIR = Path(os.environ.get(
    "PLAUSIBILITY_REPORT_DIR", "/data/ollama-proxy/reports"
))
# Conservative max weight cap for the recommended blend. We do NOT propose a
# weight larger than this even if plausibility correlates perfectly — a new
# signal should never dominate the ensemble on first introduction.
MAX_RECOMMENDED_WEIGHT = float(os.environ.get(
    "PLAUSIBILITY_MAX_RECOMMENDED_WEIGHT", "0.20"
))


@dataclass
class ReadinessStatus:
    ready: bool
    judgements: int
    calendar_days: int
    stddev: float
    missing: list[str]

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalysisResult:
    status: ReadinessStatus
    generated_at: str
    stats: Optional[dict] = None
    correlations: Optional[dict] = None
    per_model: Optional[list[dict]] = None
    recommended_weight: Optional[float] = None
    recommendation_note: Optional[str] = None
    triage: Optional[list[dict]] = None
    report_path: Optional[str] = None


# ---------------------------------------------------------------------------
# Gate evaluation
# ---------------------------------------------------------------------------

def _readiness(db_path: str) -> ReadinessStatus:
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM response_judgements"
        ).fetchone()[0]
        if count == 0:
            return ReadinessStatus(False, 0, 0, 0.0,
                                   ["no judgements recorded yet"])

        # stddev via two-pass (SQLite has no STDDEV built-in without ext).
        avg = conn.execute(
            "SELECT AVG(plausibility) FROM response_judgements"
        ).fetchone()[0] or 0.0
        var_sum = conn.execute(
            "SELECT SUM((plausibility - ?) * (plausibility - ?)) "
            "FROM response_judgements", (avg, avg)
        ).fetchone()[0] or 0.0
        stddev = math.sqrt(var_sum / max(1, count))

        day_rows = conn.execute(
            "SELECT DISTINCT substr(judged_at, 1, 10) FROM response_judgements"
        ).fetchall()
        calendar_days = len(day_rows)
    finally:
        conn.close()

    missing: list[str] = []
    if count < MIN_JUDGEMENTS:
        missing.append(f"need {MIN_JUDGEMENTS - count} more judgements "
                       f"({count}/{MIN_JUDGEMENTS})")
    if calendar_days < MIN_CALENDAR_DAYS:
        missing.append(f"need {MIN_CALENDAR_DAYS - calendar_days} more "
                       f"calendar days of data "
                       f"({calendar_days}/{MIN_CALENDAR_DAYS})")
    if stddev < MIN_STDDEV:
        missing.append(f"stddev too low ({stddev:.3f} < {MIN_STDDEV}) — "
                       "the critic is returning almost constant scores")

    return ReadinessStatus(
        ready=not missing,
        judgements=count,
        calendar_days=calendar_days,
        stddev=round(stddev, 4),
        missing=missing,
    )


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def _pearson(xs: list[float], ys: list[float]) -> Optional[float]:
    n = len(xs)
    if n < 3 or n != len(ys):
        return None
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den_x = math.sqrt(sum((x - mean_x) ** 2 for x in xs))
    den_y = math.sqrt(sum((y - mean_y) ** 2 for y in ys))
    if den_x == 0.0 or den_y == 0.0:
        return None
    return num / (den_x * den_y)


def _percentiles(values: list[float]) -> dict:
    if not values:
        return {}
    s = sorted(values)

    def pct(p: float) -> float:
        if not s:
            return 0.0
        k = (len(s) - 1) * p
        f = int(math.floor(k))
        c = int(math.ceil(k))
        if f == c:
            return s[f]
        return s[f] + (s[c] - s[f]) * (k - f)

    return {
        "p10": round(pct(0.10), 4),
        "p50": round(pct(0.50), 4),
        "p90": round(pct(0.90), 4),
        "p99": round(pct(0.99), 4),
    }


def _collect_samples(db_path: str) -> list[dict]:
    """
    Join response_rewards with response_judgements so we get
    (plausibility, reward_a, reward_b, reward_c, model, cve_tag) per row.
    Rows without a judgement are excluded.
    """
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT rr.response_id, rr.response_hash, rr.model, rr.cve_tag, "
            "       rj.plausibility, "
            "       rr.reward_a_engagement AS a, "
            "       rr.reward_b_unmasked AS b, "
            "       rr.reward_c_rule_yield AS c, "
            "       rr.total_reward AS total "
            "FROM response_rewards rr "
            "JOIN response_judgements rj ON rj.response_hash = rr.response_hash "
            "WHERE rr.plausibility_score >= 0"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _per_model_breakdown(samples: list[dict]) -> list[dict]:
    by_model: dict[str, list[dict]] = {}
    for s in samples:
        by_model.setdefault(s.get("model") or "unknown", []).append(s)
    out: list[dict] = []
    for model, rows in sorted(by_model.items()):
        ps = [r["plausibility"] for r in rows]
        out.append({
            "model": model,
            "count": len(rows),
            "avg_plausibility": round(sum(ps) / len(ps), 4) if ps else 0.0,
            "min": round(min(ps), 4) if ps else 0.0,
            "max": round(max(ps), 4) if ps else 0.0,
        })
    return out


def _triage(db_path: str, limit: int) -> list[dict]:
    """
    Collect the N lowest-plausibility judgements, enriched with the prompt /
    response snippets from the proxy cache. Dedupes by response_hash, so
    popular (served-many-times) bad responses bubble up.
    """
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT rj.response_hash, rj.plausibility, rj.reasons, "
            "       rj.critic_model, rj.model, "
            "       (SELECT COUNT(*) FROM response_rewards rr "
            "        WHERE rr.response_hash = rj.response_hash) AS times_served "
            "FROM response_judgements rj "
            "ORDER BY rj.plausibility ASC, times_served DESC "
            "LIMIT ?", (limit,)
        ).fetchall()

        out: list[dict] = []
        for r in rows:
            # Pull one representative prompt/response pair for the hash.
            snippet = conn.execute(
                "SELECT pc.prompt_text, resp.response_text "
                "FROM responses resp "
                "JOIN prompt_cache pc ON pc.id = resp.prompt_cache_id "
                "JOIN response_rewards rr ON rr.response_id = resp.id "
                "WHERE rr.response_hash = ? LIMIT 1",
                (r["response_hash"],)
            ).fetchone()
            try:
                reasons = json.loads(r["reasons"] or "[]")
                if not isinstance(reasons, list):
                    reasons = []
            except Exception:
                reasons = []
            out.append({
                "response_hash": r["response_hash"],
                "plausibility": round(float(r["plausibility"]), 4),
                "reasons": reasons,
                "critic_model": r["critic_model"] or "",
                "honeypot_model": r["model"] or "",
                "times_served": int(r["times_served"] or 0),
                "prompt_excerpt": (snippet["prompt_text"] or "")[:240] if snippet else "",
                "response_excerpt": (snippet["response_text"] or "")[:240] if snippet else "",
            })
        return out
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Recommendation logic
# ---------------------------------------------------------------------------

def _recommend_weight(correlations: dict, stats: dict) -> tuple[float, str]:
    """
    Suggest a conservative blend weight for plausibility in total_reward.

    Heuristic:
      - Start at 0.10 (a new signal should never dominate on day 1).
      - +0.05 if plausibility is MEANINGFULLY independent of reward A/B/C
        (no |r| > 0.6), because it's adding truly new information.
      - -0.05 if |r| with any of A/B/C is very high (>0.8): the signal
        duplicates an existing one; low value added.
      - Cap at MAX_RECOMMENDED_WEIGHT (default 0.20).

    Returns (weight, human-readable rationale).
    """
    base = 0.10
    rationale = ["base weight 0.10 for new signal (safety default)"]

    corrs = [correlations.get(k) for k in ("reward_a", "reward_b", "reward_c")]
    corrs_abs = [abs(c) for c in corrs if c is not None]
    max_abs = max(corrs_abs) if corrs_abs else 0.0

    if corrs_abs and max_abs < 0.6:
        base += 0.05
        rationale.append(
            f"independence bonus +0.05 (max |r| with A/B/C = {max_abs:.2f} < 0.60)"
        )
    if max_abs > 0.8:
        base -= 0.05
        rationale.append(
            f"redundancy penalty -0.05 (max |r| with A/B/C = {max_abs:.2f} > 0.80)"
        )

    # Widely-spread plausibility scores => signal is more informative.
    p90 = stats.get("percentiles", {}).get("p90", 0.0)
    p10 = stats.get("percentiles", {}).get("p10", 0.0)
    if (p90 - p10) >= 0.5:
        rationale.append(
            f"spread bonus kept (p90-p10 = {p90 - p10:.2f} >= 0.50)"
        )
    else:
        rationale.append(
            f"narrow spread noted (p90-p10 = {p90 - p10:.2f} < 0.50) — "
            "weight stays conservative"
        )

    weight = max(0.05, min(MAX_RECOMMENDED_WEIGHT, base))
    return round(weight, 2), " | ".join(rationale)


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def _render_markdown(result: AnalysisResult) -> str:
    ts = result.generated_at
    st = result.status
    lines: list[str] = []
    lines.append(f"# Plausibility Analysis — {ts}")
    lines.append("")
    lines.append("## Readiness gate")
    lines.append("")
    lines.append(f"- Judgements: **{st.judgements}** (min {MIN_JUDGEMENTS})")
    lines.append(f"- Calendar days: **{st.calendar_days}** "
                 f"(min {MIN_CALENDAR_DAYS})")
    lines.append(f"- StdDev: **{st.stddev}** (min {MIN_STDDEV})")
    lines.append(f"- Ready: **{'YES' if st.ready else 'NO'}**")
    if st.missing:
        lines.append("")
        lines.append("**Still missing:**")
        for m in st.missing:
            lines.append(f"- {m}")
        return "\n".join(lines) + "\n"

    stats = result.stats or {}
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    lines.append(f"- Mean plausibility: **{stats.get('mean')}**")
    pct = stats.get("percentiles", {})
    lines.append(f"- Percentiles: p10={pct.get('p10')}, "
                 f"p50={pct.get('p50')}, p90={pct.get('p90')}, "
                 f"p99={pct.get('p99')}")
    lines.append(f"- Joined reward rows: {stats.get('sample_count')}")

    per_model = result.per_model or []
    if per_model:
        lines.append("")
        lines.append("### Per-honeypot-model breakdown")
        lines.append("")
        lines.append("| model | count | avg | min | max |")
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        for m in per_model:
            lines.append(
                f"| {m['model']} | {m['count']} | "
                f"{m['avg_plausibility']} | {m['min']} | {m['max']} |"
            )

    corrs = result.correlations or {}
    lines.append("")
    lines.append("## Correlations (Pearson r)")
    lines.append("")
    for k, v in corrs.items():
        v_str = "n/a" if v is None else f"{v:+.3f}"
        lines.append(f"- plausibility ↔ {k}: **{v_str}**")

    lines.append("")
    lines.append("## Recommendation")
    lines.append("")
    lines.append(f"- **Suggested blend weight for plausibility in "
                 f"`total_reward`: {result.recommended_weight}**")
    lines.append(f"- Rationale: {result.recommendation_note}")
    lines.append("")
    lines.append("If you accept, rebalance the existing weights so all four "
                 "sum to 1.0 and update `_total_reward()` in "
                 "`proxy/src/reward_aggregator.py`. Example (starting from "
                 "0.40/0.35/0.25 for A/B/C):")
    lines.append("")
    w = result.recommended_weight or 0.1
    scale = 1.0 - w
    new_a = round(0.40 * scale, 3)
    new_b = round(0.35 * scale, 3)
    new_c = round(0.25 * scale, 3)
    lines.append("```python")
    lines.append(
        "def _total_reward(a, b, c, d):"
    )
    lines.append(
        f"    return {new_a}*a + {new_b}*b + {new_c}*c + {w}*d"
    )
    lines.append("```")

    triage = result.triage or []
    if triage:
        lines.append("")
        lines.append(f"## Low-plausibility triage (top {len(triage)})")
        lines.append("")
        for t in triage:
            lines.append(
                f"### {t['plausibility']:.2f}  "
                f"(served {t['times_served']}× by {t['honeypot_model']})"
            )
            if t.get("reasons"):
                lines.append("- critic tells: " + "; ".join(t["reasons"]))
            lines.append(f"- prompt excerpt: `{t['prompt_excerpt']}`")
            lines.append(f"- response excerpt: `{t['response_excerpt']}`")
            lines.append("")

    return "\n".join(lines) + "\n"


def _write_outputs(result: AnalysisResult) -> str:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = result.generated_at.replace(":", "").replace("-", "").replace("T", "-").split("+")[0][:15]
    md_path = REPORT_DIR / f"plausibility-{stamp}.md"
    json_path = REPORT_DIR / f"plausibility-{stamp}.json"
    md_path.write_text(_render_markdown(result), encoding="utf-8")
    json_path.write_text(
        json.dumps({
            **asdict(result),
            "status": result.status.as_dict(),
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # Convenience symlink to the latest report.
    latest = REPORT_DIR / "plausibility-latest.md"
    try:
        if latest.exists() or latest.is_symlink():
            latest.unlink()
        latest.symlink_to(md_path.name)
    except OSError:
        # Filesystem without symlink support — copy instead.
        latest.write_text(md_path.read_text(encoding="utf-8"), encoding="utf-8")
    return str(md_path)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_analysis(db_path: str) -> AnalysisResult:
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    status = _readiness(db_path)

    if not status.ready:
        logger.info(
            "Plausibility analyzer: gate CLOSED — %s",
            "; ".join(status.missing) or "no data",
        )
        return AnalysisResult(status=status, generated_at=generated_at)

    samples = _collect_samples(db_path)
    plausibilities = [s["plausibility"] for s in samples]
    stats = {
        "sample_count": len(samples),
        "mean": round(sum(plausibilities) / len(plausibilities), 4)
                if plausibilities else 0.0,
        "percentiles": _percentiles(plausibilities),
    }
    correlations = {
        "reward_a": _pearson(plausibilities, [s["a"] for s in samples]),
        "reward_b": _pearson(plausibilities, [s["b"] for s in samples]),
        "reward_c": _pearson(plausibilities, [s["c"] for s in samples]),
        "total_reward": _pearson(plausibilities, [s["total"] for s in samples]),
    }
    per_model = _per_model_breakdown(samples)
    triage = _triage(db_path, TRIAGE_TOP_N)
    weight, note = _recommend_weight(correlations, stats)

    result = AnalysisResult(
        status=status,
        generated_at=generated_at,
        stats=stats,
        correlations={k: (round(v, 4) if v is not None else None)
                      for k, v in correlations.items()},
        per_model=per_model,
        recommended_weight=weight,
        recommendation_note=note,
        triage=triage,
    )
    result.report_path = _write_outputs(result)
    logger.info(
        "Plausibility analyzer: report written to %s "
        "(weight=%.2f, samples=%d, days=%d, stddev=%.3f)",
        result.report_path, weight, status.judgements,
        status.calendar_days, status.stddev,
    )
    return result
