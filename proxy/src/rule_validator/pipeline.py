from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

import httpx

from .dedupe import DedupeNeighbor, RuleDedupeIndex
from .llm_judge import review_rule
from .static_checks import CheckResult, detect_rule_type, validate_rule


DEFAULT_LLM_CONF_THRESHOLD = 0.70

DEST_OUTPUT = "output"
DEST_OUTPUT_WARN_FP = "output_warn_fp"
DEST_REJECTED_STATIC = "rejected/static"
DEST_REJECTED_LLM = "rejected/llm"
DEST_REJECTED_REVIEW = "rejected/review"
DEST_REJECTED_DUPLICATE = "rejected/duplicate"


@dataclass
class ValidationVerdict:
    path: str
    rule_type: str
    static_ok: bool
    llm_ok: bool
    llm_confidence: float
    fp_risk: str
    destination: str
    issues: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    suggested_fixes: list[str] = field(default_factory=list)
    mitre_alignment: str = "partial"
    static_duration_ms: float = 0.0
    llm_duration_ms: float = 0.0
    llm_raw_preview: Optional[str] = None
    dedupe_score: Optional[float] = None
    dedupe_neighbor_hash: Optional[str] = None
    dedupe_neighbor_path: Optional[str] = None
    dedupe_rule_hash: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        if d.get("llm_raw_preview") is None:
            d.pop("llm_raw_preview", None)
        return d


def decide(
    static_res: CheckResult,
    llm_verdict: dict,
    *,
    llm_conf_threshold: float = DEFAULT_LLM_CONF_THRESHOLD,
) -> str:
    if not static_res.ok:
        return DEST_REJECTED_STATIC

    llm_ok = bool(llm_verdict.get("ok"))
    if not llm_ok:
        return DEST_REJECTED_LLM

    conf = float(llm_verdict.get("confidence", 0.0) or 0.0)
    if conf < llm_conf_threshold:
        return DEST_REJECTED_REVIEW

    if str(llm_verdict.get("fp_risk", "medium")).lower() == "high":
        return DEST_OUTPUT_WARN_FP

    return DEST_OUTPUT


async def validate_file(
    path: Path,
    *,
    neighbors: Optional[list[str]] = None,
    client: Optional[httpx.AsyncClient] = None,
    llm_conf_threshold: float = DEFAULT_LLM_CONF_THRESHOLD,
    skip_llm: bool = False,
    dedupe_index: Optional[RuleDedupeIndex] = None,
) -> ValidationVerdict:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    rule_type = detect_rule_type(path, text)
    if rule_type is None:
        return ValidationVerdict(
            path=str(path),
            rule_type="unknown",
            static_ok=False,
            llm_ok=False,
            llm_confidence=0.0,
            fp_risk="medium",
            destination=DEST_REJECTED_STATIC,
            issues=[
                {
                    "severity": "high",
                    "category": "unknown_type",
                    "message": f"Cannot infer rule type from '{path.name}'",
                }
            ],
        )

    t0 = time.monotonic()
    static = validate_rule(text, rule_type)
    static_ms = (time.monotonic() - t0) * 1000

    dedupe_rule_hash: Optional[str] = None
    neighbors_for_llm: list[str] = list(neighbors or [])

    if static.ok and dedupe_index is not None:
        try:
            is_dup, dedupe_rule_hash, _, dedupe_neighbors = await dedupe_index.is_duplicate(
                text,
                rule_type,
                client=client,
            )
            if not neighbors_for_llm and dedupe_neighbors:
                neighbors_for_llm = [n.rule_text for n in dedupe_neighbors]
            if is_dup and dedupe_neighbors:
                top = dedupe_neighbors[0]
                return ValidationVerdict(
                    path=str(path),
                    rule_type=rule_type,
                    static_ok=True,
                    llm_ok=False,
                    llm_confidence=0.0,
                    fp_risk="medium",
                    destination=DEST_REJECTED_DUPLICATE,
                    issues=[
                        {
                            "severity": "high",
                            "category": "duplicate_rule",
                            "message": f"Cosine similarity {top.score:.3f} >= {dedupe_index.threshold:.2f} against {top.rule_hash}",
                            "stage": "dedupe",
                        }
                    ],
                    warnings=list(static.warnings),
                    suggested_fixes=["merge as variant of existing rule or raise threshold"],
                    mitre_alignment="partial",
                    static_duration_ms=static_ms,
                    llm_duration_ms=0.0,
                    dedupe_score=top.score,
                    dedupe_neighbor_hash=top.rule_hash,
                    dedupe_neighbor_path=top.source_path,
                    dedupe_rule_hash=dedupe_rule_hash,
                )
        except Exception as e:
            static.warnings.append(
                {
                    "severity": "low",
                    "category": "dedupe_unavailable",
                    "message": f"{type(e).__name__}: {e}",
                }
            )

    if not static.ok or skip_llm:
        llm_verdict = {
            "ok": False if not static.ok else True,
            "confidence": 0.0,
            "issues": [],
            "suggested_fixes": [],
            "fp_risk": "medium",
            "mitre_alignment": "partial",
        }
        llm_ms = 0.0
    else:
        t0 = time.monotonic()
        llm_verdict = await review_rule(rule_type, text, neighbors_for_llm, client=client)
        llm_ms = (time.monotonic() - t0) * 1000

    destination = decide(static, llm_verdict, llm_conf_threshold=llm_conf_threshold)

    merged_issues: list[dict] = []
    for issue in static.issues:
        merged_issues.append({**issue, "stage": "static"})
    for issue in llm_verdict.get("issues", []) or []:
        merged_issues.append({**issue, "stage": "llm"})

    return ValidationVerdict(
        path=str(path),
        rule_type=rule_type,
        static_ok=static.ok,
        llm_ok=bool(llm_verdict.get("ok", False)),
        llm_confidence=float(llm_verdict.get("confidence", 0.0) or 0.0),
        fp_risk=str(llm_verdict.get("fp_risk", "medium")).lower(),
        destination=destination,
        issues=merged_issues,
        warnings=list(static.warnings),
        suggested_fixes=list(llm_verdict.get("suggested_fixes") or []),
        mitre_alignment=str(llm_verdict.get("mitre_alignment", "partial")).lower(),
        static_duration_ms=static_ms,
        llm_duration_ms=llm_ms,
        llm_raw_preview=llm_verdict.get("_raw_preview"),
        dedupe_rule_hash=dedupe_rule_hash,
    )
