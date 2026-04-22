#!/usr/bin/env python3
"""
Interactive/batch label helper for validator sidecars (Phase 2.5).

Goal:
- Increase ground-truth coverage for `calibrate_thresholds.py`.
- Keep labels local as `<rule>.label.json` next to each validated rule.

Examples:
  # Show dataset stats for rejected/review queue
  python label_rules.py --summary

  # Interactively label up to 30 review items
  python label_rules.py --interactive --limit 30

  # Batch-label filtered subset (dry run first)
  python label_rules.py --subset review --contains "powershell" --set fp --dry-run
  python label_rules.py --subset review --contains "powershell" --set fp --note "manual triage 2026-04-22"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

VALIDATED_DIR = Path(os.environ.get("VALIDATED_DIR", "/data/ollama-proxy/validated-rules"))
SUPPORTED = {".yml", ".yaml", ".yar", ".yara", ".rules", ".json"}
LABELS = {"tp", "fp"}


@dataclass
class Item:
    sidecar_path: Path
    rule_path: Path
    destination: str
    rule_type: str
    llm_confidence: float
    fp_risk: str
    static_ok: bool
    llm_ok: bool
    current_label: Optional[str]


def _iter_sidecars(base: Path, subset: str) -> Iterable[Path]:
    if subset == "review":
        roots = [base / "rejected" / "review"]
    elif subset == "approved":
        roots = [base / "approved"]
    elif subset == "rejected":
        roots = [base / "rejected"]
    else:
        roots = [base / "approved", base / "rejected"]
    for root in roots:
        if root.is_dir():
            yield from sorted(root.rglob("*.issues.json"))


def _rule_path_from_sidecar(sidecar: Path) -> Path:
    suffix = ".issues.json"
    if sidecar.name.endswith(suffix):
        return sidecar.with_name(sidecar.name[: -len(suffix)])
    return sidecar


def _label_path(rule_path: Path) -> Path:
    return rule_path.with_suffix(rule_path.suffix + ".label.json")


def _read_label(rule_path: Path) -> Optional[str]:
    p = _label_path(rule_path)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    v = str(data.get("label", "")).lower()
    return v if v in LABELS else None


def _load_item(sidecar: Path) -> Optional[Item]:
    try:
        verdict = json.loads(sidecar.read_text(encoding="utf-8"))
    except Exception:
        return None
    rule_path = _rule_path_from_sidecar(sidecar)
    if rule_path.suffix.lower() not in SUPPORTED:
        return None
    return Item(
        sidecar_path=sidecar,
        rule_path=rule_path,
        destination=str(verdict.get("destination", "")),
        rule_type=str(verdict.get("rule_type", "unknown")),
        llm_confidence=float(verdict.get("llm_confidence", 0.0) or 0.0),
        fp_risk=str(verdict.get("fp_risk", "unknown")).lower(),
        static_ok=bool(verdict.get("static_ok", False)),
        llm_ok=bool(verdict.get("llm_ok", False)),
        current_label=_read_label(rule_path),
    )


def _collect(
    subset: str,
    only_unlabeled: bool,
    contains: Optional[str],
    destination: Optional[str],
    fp_risk: Optional[str],
) -> list[Item]:
    items: list[Item] = []
    for sidecar in _iter_sidecars(VALIDATED_DIR, subset):
        it = _load_item(sidecar)
        if not it:
            continue
        if only_unlabeled and it.current_label in LABELS:
            continue
        if contains:
            needle = contains.lower()
            hay = f"{it.rule_path} {it.destination} {it.rule_type} {it.fp_risk}".lower()
            if needle not in hay:
                continue
        if destination and it.destination != destination:
            continue
        if fp_risk and it.fp_risk != fp_risk:
            continue
        items.append(it)
    return items


def _write_label(item: Item, label: str, note: str, dry_run: bool) -> None:
    payload = {
        "label": label,
        "note": note,
        "labeled_at": datetime.now(timezone.utc).isoformat(),
        "source": "label_rules.py",
        "rule_path": str(item.rule_path),
    }
    p = _label_path(item.rule_path)
    if dry_run:
        print(f"[dry-run] {p} <= {json.dumps(payload, ensure_ascii=False)}")
        return
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _summary(items: list[Item], subset: str) -> int:
    total = len(items)
    by_dest: dict[str, int] = {}
    by_type: dict[str, int] = {}
    labels: dict[str, int] = {"tp": 0, "fp": 0, "unlabeled": 0}
    for i in items:
        by_dest[i.destination] = by_dest.get(i.destination, 0) + 1
        by_type[i.rule_type] = by_type.get(i.rule_type, 0) + 1
        if i.current_label in ("tp", "fp"):
            labels[i.current_label] += 1
        else:
            labels["unlabeled"] += 1
    print(f"validated_dir={VALIDATED_DIR}")
    print(f"subset={subset}")
    print(f"items={total}")
    print(f"labels={labels}")
    print("by_destination=" + json.dumps(by_dest, sort_keys=True))
    print("by_rule_type=" + json.dumps(by_type, sort_keys=True))
    return 0


def _preview_rule(path: Path, max_lines: int = 12, max_chars: int = 900) -> str:
    if not path.is_file():
        return "<rule file missing>"
    txt = path.read_text(encoding="utf-8", errors="replace")
    lines = txt.splitlines()[:max_lines]
    out = "\n".join(lines)
    if len(out) > max_chars:
        out = out[:max_chars] + "\n... [truncated]"
    return out


def _interactive(items: list[Item], limit: int, note: str, dry_run: bool) -> int:
    shown = 0
    labelled = 0
    for i, item in enumerate(items, 1):
        if shown >= limit:
            break
        shown += 1
        print("\n" + "=" * 88)
        print(f"[{shown}/{min(limit, len(items))}] {item.rule_path}")
        print(
            f"destination={item.destination} type={item.rule_type} "
            f"conf={item.llm_confidence:.3f} fp_risk={item.fp_risk} "
            f"static_ok={item.static_ok} llm_ok={item.llm_ok} "
            f"current_label={item.current_label or '-'}"
        )
        print("-" * 88)
        print(_preview_rule(item.rule_path))
        while True:
            ans = input("\nlabel? [t]p / [f]p / [s]kip / [q]uit: ").strip().lower()
            if ans in {"q", "quit"}:
                print(f"stopped: labelled={labelled}, seen={shown}")
                return 0
            if ans in {"s", "skip", ""}:
                break
            if ans in {"t", "tp", "f", "fp"}:
                label = "tp" if ans.startswith("t") else "fp"
                _write_label(item, label=label, note=note, dry_run=dry_run)
                labelled += 1
                break
            print("invalid input, expected: t/f/s/q")
    print(f"done: labelled={labelled}, seen={shown}")
    return 0


def _batch_set(items: list[Item], set_label: str, note: str, dry_run: bool, limit: int) -> int:
    if set_label not in LABELS:
        print(f"invalid --set value: {set_label}", file=sys.stderr)
        return 2
    changed = 0
    for item in items[:limit]:
        _write_label(item, label=set_label, note=note, dry_run=dry_run)
        changed += 1
    print(f"batch complete: label={set_label} changed={changed} dry_run={dry_run}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--subset", choices=["review", "approved", "rejected", "all"], default="review")
    p.add_argument("--contains", default=None, help="Case-insensitive filter on path/meta.")
    p.add_argument("--destination", default=None, help="Exact destination filter, e.g. output or rejected/static.")
    p.add_argument("--fp-risk", choices=["low", "medium", "high"], default=None, help="Exact fp_risk filter.")
    p.add_argument("--include-labeled", action="store_true", help="Include already labeled items.")
    p.add_argument("--summary", action="store_true", help="Print dataset stats and exit.")
    p.add_argument("--interactive", action="store_true", help="Interactive tp/fp triage mode.")
    p.add_argument("--set", choices=["tp", "fp"], dest="set_label", default=None, help="Batch assign this label.")
    p.add_argument("--note", default="manual triage", help="Saved into label file.")
    p.add_argument("--limit", type=int, default=50, help="Max number of items to process.")
    p.add_argument("--dry-run", action="store_true", help="Print changes without writing.")
    args = p.parse_args(argv)

    items = _collect(
        subset=args.subset,
        only_unlabeled=not args.include_labeled,
        contains=args.contains,
        destination=args.destination,
        fp_risk=args.fp_risk,
    )

    if args.summary:
        # Summary should include full label coverage, regardless of include-labeled.
        all_items = _collect(
            subset=args.subset,
            only_unlabeled=False,
            contains=args.contains,
            destination=args.destination,
            fp_risk=args.fp_risk,
        )
        return _summary(all_items, args.subset)

    if args.set_label:
        return _batch_set(items, set_label=args.set_label, note=args.note, dry_run=args.dry_run, limit=args.limit)

    # Default mode is interactive if no explicit action is requested.
    return _interactive(items, limit=args.limit, note=args.note, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
