#!/usr/bin/env python3
"""
Threshold calibrator for the rule-validator pipeline (Phase 2.5).

Rather than keeping LLM_CONF_THRESHOLD and DEDUPE_THRESHOLD as hand-picked
magic numbers, this script replays the *.issues.json sidecars already written
by run_rule_validator.py and searches for the threshold pair that maximises
recall on approved rules subject to a hard upper bound on false-positive rate.

Design references (offline, no extra LLM calls required):
- Deconvolute `yara-gen`, "Automatically Generate YARA Rules for LLM Security
  at Scale" (2026-01): holdout-based precision/recall sweep with a hard FP cap.
- Bertiger et al., PMLR 299:222 (2025): holdout-set methodology for evaluating
  LLM-generated cybersecurity rules.
- Aman's AI Journal, data-filtering primer: embedding-cosine near-duplicate
  cutoff ~0.90 (our current 0.985 is extremely conservative).

Selection rule: both recommendations pick the *median* of the top-scoring
plateau rather than the plateau edge. With sparse ground truth the precision/
recall curve is almost always flat across a wide threshold band; an argmax-
style pick sits on the edge and is one distribution-drift event away from
falling off the cliff. The median keeps the validator safely in the middle.

Inputs (all read-only):
- VALIDATED_DIR/approved/**/*.issues.json
- VALIDATED_DIR/rejected/**/*.issues.json
- Optional per-rule label at <rule_path>.label.json with the shape:
    {"label": "tp" | "fp", "note": "..."}
  If missing, a proxy label is inferred (see `_proxy_label`).

Output:
- VALIDATED_DIR/.state/calibration.json  — machine-readable sweep result
- VALIDATED_DIR/.state/calibration.md    — human-readable report

Usage:
    python calibrate_thresholds.py                 # use env defaults
    MAX_FP_RATE=0.05 python calibrate_thresholds.py
    VALIDATED_DIR=/tmp/vr python calibrate_thresholds.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from src.rule_validator.pipeline import (
    DEST_OUTPUT,
    DEST_OUTPUT_WARN_FP,
    DEST_REJECTED_DUPLICATE,
    DEST_REJECTED_LLM,
    DEST_REJECTED_REVIEW,
    DEST_REJECTED_STATIC,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [calibrate] %(levelname)s: %(message)s",
)
logger = logging.getLogger("calibrate")

VALIDATED_DIR = Path(os.environ.get("VALIDATED_DIR", "/data/ollama-proxy/validated-rules"))
REPORT_JSON = VALIDATED_DIR / ".state" / "calibration.json"
REPORT_MD = VALIDATED_DIR / ".state" / "calibration.md"

# Sweep grids. Narrow enough to be cheap, wide enough to cover sane values.
CONF_GRID = [round(0.50 + 0.025 * i, 3) for i in range(19)]          # 0.500 .. 0.950
DEDUPE_GRID = [round(0.85 + 0.01 * i, 3) for i in range(15)]          # 0.850 .. 0.990

# Hard cap on false-positive rate when picking the recommended LLM threshold.
# Matches the `--set engine.score_threshold` + FP-cap pattern yara-gen uses.
MAX_FP_RATE = float(os.environ.get("MAX_FP_RATE", "0.05"))
# If embedding-based dedupe catches >= this fraction of known duplicates at a
# given cutoff, that cutoff is a candidate for the recommendation.
MIN_DEDUPE_RECALL = float(os.environ.get("MIN_DEDUPE_RECALL", "0.80"))


@dataclass
class Sample:
    """One rule + its recorded verdict, used as a replay item."""

    path: str                       # original rule path
    rule_type: str                  # yara/sigma/yml/json/...
    llm_confidence: float
    fp_risk: str                    # low/medium/high
    static_ok: bool
    llm_ok: bool
    destination: str                # stored decision
    dedupe_score: Optional[float]   # embedding-cosine similarity to nearest neighbour
    label: str                      # tp | fp | unknown

    @property
    def is_labelled(self) -> bool:
        return self.label in ("tp", "fp")


def _iter_sidecars(root: Path) -> Iterable[Path]:
    if not root.is_dir():
        return []
    yield from sorted(root.rglob("*.issues.json"))


def _load_label(rule_path: Path) -> Optional[str]:
    """Operator-provided ground truth, if any."""
    candidate = rule_path.with_suffix(rule_path.suffix + ".label.json")
    if not candidate.is_file():
        return None
    try:
        data = json.loads(candidate.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning("label file unreadable %s: %s", candidate, e)
        return None
    label = str(data.get("label", "")).lower()
    return label if label in ("tp", "fp") else None


def _rule_path_from_sidecar(sidecar: Path) -> Path:
    """Return the validated rule path for a `<rule>.issues.json` sidecar."""
    suffix = ".issues.json"
    if sidecar.name.endswith(suffix):
        return sidecar.with_name(sidecar.name[: -len(suffix)])
    return sidecar


def _proxy_label(verdict: dict) -> str:
    """
    Heuristic label used only when no *.label.json is provided.

    - rejected by static checks  -> fp   (structurally broken rule)
    - rejected as duplicate      -> unknown (not a quality signal, just redundancy)
    - approved + fp_risk != high -> tp   (passed both static + LLM gates cleanly)
    - anything else              -> unknown
    """
    destination = verdict.get("destination", "")
    if destination == DEST_REJECTED_STATIC:
        return "fp"
    if destination == DEST_REJECTED_DUPLICATE:
        return "unknown"
    if destination in (DEST_OUTPUT, DEST_OUTPUT_WARN_FP):
        fp_risk = str(verdict.get("fp_risk", "medium")).lower()
        if fp_risk != "high":
            return "tp"
    return "unknown"


def _collect_samples() -> list[Sample]:
    samples: list[Sample] = []
    for sidecar in _iter_sidecars(VALIDATED_DIR):
        try:
            verdict = json.loads(sidecar.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("bad sidecar %s: %s", sidecar, e)
            continue

        # In mirror mode, labels are written next to the validated rule copy
        # (same folder as the sidecar), while `source_path` usually points to
        # generated-rules/latest. Prefer the sidecar-adjacent rule path first.
        mirrored_rule_path = _rule_path_from_sidecar(sidecar)
        source_rule_path = Path(str(verdict.get("source_path") or verdict.get("path") or ""))

        label = _load_label(mirrored_rule_path) if mirrored_rule_path else None
        if label is None and source_rule_path:
            label = _load_label(source_rule_path)
        if label is None:
            label = _proxy_label(verdict)

        samples.append(
            Sample(
                path=str(mirrored_rule_path or source_rule_path),
                rule_type=str(verdict.get("rule_type", "unknown")),
                llm_confidence=float(verdict.get("llm_confidence", 0.0) or 0.0),
                fp_risk=str(verdict.get("fp_risk", "medium")).lower(),
                static_ok=bool(verdict.get("static_ok", False)),
                llm_ok=bool(verdict.get("llm_ok", False)),
                destination=str(verdict.get("destination", "")),
                dedupe_score=(
                    float(verdict["dedupe_score"])
                    if verdict.get("dedupe_score") is not None
                    else None
                ),
                label=label,
            )
        )
    return samples


def _replay_decision(sample: Sample, conf_threshold: float) -> str:
    """Mirror of pipeline.decide() but from already-recorded fields."""
    if not sample.static_ok:
        return DEST_REJECTED_STATIC
    if not sample.llm_ok:
        return DEST_REJECTED_LLM
    if sample.llm_confidence < conf_threshold:
        return DEST_REJECTED_REVIEW
    if sample.fp_risk == "high":
        return DEST_OUTPUT_WARN_FP
    return DEST_OUTPUT


def _sweep_conf(samples: list[Sample]) -> list[dict]:
    """For each conf threshold, compute precision/recall/FP-rate on labelled samples."""
    labelled = [s for s in samples if s.is_labelled]
    pos = sum(1 for s in labelled if s.label == "tp")
    neg = sum(1 for s in labelled if s.label == "fp")
    if pos == 0 or neg == 0:
        logger.warning(
            "insufficient ground truth for LLM sweep (tp=%d, fp=%d); "
            "add *.label.json files to get meaningful numbers",
            pos, neg,
        )

    rows: list[dict] = []
    for t in CONF_GRID:
        tp = fp = tn = fn = 0
        for s in labelled:
            approved = _replay_decision(s, t) in (DEST_OUTPUT, DEST_OUTPUT_WARN_FP)
            if s.label == "tp" and approved:
                tp += 1
            elif s.label == "tp" and not approved:
                fn += 1
            elif s.label == "fp" and approved:
                fp += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        rows.append({
            "threshold": t,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "fp_rate": round(fp_rate, 4),
            "f1": round(f1, 4),
        })
    return rows


def _recommend_conf(rows: list[dict]) -> Optional[float]:
    """
    Pick a threshold in the *middle* of the precision/recall plateau.

    Among rows with fp_rate <= MAX_FP_RATE AND recall > 0, find the best
    (recall, f1) tuple and return the median threshold of all rows tied on
    that tuple. Sitting mid-plateau gives a safety margin against concept
    drift and generator-model shifts — picking the plateau edge (as a naive
    argmax does) leaves the validator one embedding-distribution-change
    away from a recall cliff.
    """
    feasible = [r for r in rows if r["fp_rate"] <= MAX_FP_RATE and r["recall"] > 0]
    if not feasible:
        return None
    best_score = max((r["recall"], r["f1"]) for r in feasible)
    plateau = sorted(
        (r for r in feasible if (r["recall"], r["f1"]) == best_score),
        key=lambda r: r["threshold"],
    )
    return plateau[len(plateau) // 2]["threshold"]


def _sweep_dedupe(samples: list[Sample]) -> list[dict]:
    """
    Embedding-cosine cutoff sweep.

    Uses recorded dedupe_score values. A lower cutoff catches more duplicates
    but risks dropping legitimate variants. We report how many *currently
    approved* rules would have been flagged as duplicate at each cutoff, and
    how many *currently rejected-as-duplicate* rules would have been kept.
    """
    scored = [s for s in samples if s.dedupe_score is not None]
    rows: list[dict] = []
    for cutoff in DEDUPE_GRID:
        would_drop_approved = sum(
            1 for s in scored
            if s.destination in (DEST_OUTPUT, DEST_OUTPUT_WARN_FP)
            and s.dedupe_score is not None
            and s.dedupe_score >= cutoff
        )
        would_keep_rejected = sum(
            1 for s in scored
            if s.destination == DEST_REJECTED_DUPLICATE
            and s.dedupe_score is not None
            and s.dedupe_score < cutoff
        )
        total_rejected_dupes = sum(
            1 for s in scored if s.destination == DEST_REJECTED_DUPLICATE
        )
        dedupe_recall = (
            (total_rejected_dupes - would_keep_rejected) / total_rejected_dupes
            if total_rejected_dupes else 0.0
        )
        rows.append({
            "cutoff": cutoff,
            "would_drop_currently_approved": would_drop_approved,
            "would_keep_currently_duplicate": would_keep_rejected,
            "retained_dedupe_recall": round(dedupe_recall, 4),
        })
    return rows


def _recommend_dedupe(rows: list[dict]) -> Optional[float]:
    """
    Pick a dedupe cutoff in the *middle* of the full-recall plateau.

    Among cutoffs where retained_dedupe_recall >= MIN_DEDUPE_RECALL AND
    would_drop_currently_approved == 0, find the maximum retained-recall
    value and return the median cutoff of all rows tied at that value.
    Mid-plateau sitting avoids regressions when the rule-generator model
    or the embedding distribution drifts — picking the lowest feasible
    cutoff (edge) would be one drift-event away from false-merging
    legitimate variants.
    """
    feasible = [
        r for r in rows
        if r["retained_dedupe_recall"] >= MIN_DEDUPE_RECALL
        and r["would_drop_currently_approved"] == 0
    ]
    if not feasible:
        return None
    best_recall = max(r["retained_dedupe_recall"] for r in feasible)
    plateau = sorted(
        (r for r in feasible if r["retained_dedupe_recall"] == best_recall),
        key=lambda r: r["cutoff"],
    )
    return plateau[len(plateau) // 2]["cutoff"]


def _render_markdown(
    samples: list[Sample],
    conf_rows: list[dict],
    dedupe_rows: list[dict],
    conf_rec: Optional[float],
    dedupe_rec: Optional[float],
) -> str:
    labelled = [s for s in samples if s.is_labelled]
    lines = [
        "# Rule Validator — Threshold Calibration Report",
        "",
        f"- Total samples replayed: **{len(samples)}**",
        f"- Labelled (tp|fp): **{len(labelled)}** "
        f"(tp={sum(1 for s in labelled if s.label == 'tp')}, "
        f"fp={sum(1 for s in labelled if s.label == 'fp')})",
        f"- MAX_FP_RATE cap: `{MAX_FP_RATE}`",
        f"- MIN_DEDUPE_RECALL floor: `{MIN_DEDUPE_RECALL}`",
        "",
        "## Recommendations (plateau-median pick)",
        "",
        "Both recommendations are the median of the top-scoring plateau, not the "
        "plateau edge — this gives a safety margin against concept drift. If the "
        "plateau collapses to a single row, the lone feasible value is returned.",
        "",
        f"- `LLM_CONF_THRESHOLD` → **{conf_rec if conf_rec is not None else 'insufficient data'}**",
        f"- `DEDUPE_THRESHOLD` → **{dedupe_rec if dedupe_rec is not None else 'insufficient data'}**",
        "",
        "## LLM confidence sweep",
        "",
        "| threshold | precision | recall | fp_rate | f1 | tp | fp | tn | fn |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in conf_rows:
        lines.append(
            f"| {r['threshold']:.3f} | {r['precision']:.3f} | {r['recall']:.3f} | "
            f"{r['fp_rate']:.3f} | {r['f1']:.3f} | {r['tp']} | {r['fp']} | "
            f"{r['tn']} | {r['fn']} |"
        )
    lines += [
        "",
        "## Dedupe cutoff sweep",
        "",
        "| cutoff | would_drop_currently_approved | would_keep_currently_duplicate | retained_recall |",
        "| --- | --- | --- | --- |",
    ]
    for r in dedupe_rows:
        lines.append(
            f"| {r['cutoff']:.3f} | {r['would_drop_currently_approved']} | "
            f"{r['would_keep_currently_duplicate']} | {r['retained_dedupe_recall']:.3f} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="Print report to stdout, don't write files.")
    args = parser.parse_args(argv)

    logger.info("calibrating from %s (max_fp_rate=%.3f)", VALIDATED_DIR, MAX_FP_RATE)
    samples = _collect_samples()
    if not samples:
        logger.error("no sidecars found under %s/approved or %s/rejected",
                     VALIDATED_DIR, VALIDATED_DIR)
        return 1
    logger.info("loaded %d samples", len(samples))

    conf_rows = _sweep_conf(samples)
    dedupe_rows = _sweep_dedupe(samples)
    conf_rec = _recommend_conf(conf_rows)
    dedupe_rec = _recommend_dedupe(dedupe_rows)

    logger.info("recommended LLM_CONF_THRESHOLD=%s  DEDUPE_THRESHOLD=%s",
                conf_rec, dedupe_rec)

    payload = {
        "validated_dir": str(VALIDATED_DIR),
        "max_fp_rate": MAX_FP_RATE,
        "min_dedupe_recall": MIN_DEDUPE_RECALL,
        "sample_count": len(samples),
        "labelled_count": sum(1 for s in samples if s.is_labelled),
        "llm_conf_sweep": conf_rows,
        "dedupe_sweep": dedupe_rows,
        "recommendation": {
            "LLM_CONF_THRESHOLD": conf_rec,
            "DEDUPE_THRESHOLD": dedupe_rec,
        },
    }
    markdown = _render_markdown(samples, conf_rows, dedupe_rows, conf_rec, dedupe_rec)

    if args.dry_run:
        print(markdown)
        return 0

    REPORT_JSON.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    REPORT_MD.write_text(markdown, encoding="utf-8")
    logger.info("wrote %s and %s", REPORT_JSON, REPORT_MD)
    return 0


if __name__ == "__main__":
    sys.exit(main())
