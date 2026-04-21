#!/usr/bin/env python3
"""
Rule Validator runner (Phase 2).

Default mode is "mirror" so the existing rule-generator can stay untouched:
- read from generated-rules/latest/
- evaluate each file with static checks + LLM judge
- write a validated copy to validated-rules/approved|rejected
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Iterable

import httpx

from src.rule_validator import validate_file
from src.rule_validator.dedupe import RuleDedupeIndex

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [rule-validator] %(levelname)s: %(message)s",
)
logger = logging.getLogger("rule-validator")

MODE = os.environ.get("VALIDATOR_MODE", "mirror").lower()
INTERVAL = int(os.environ.get("VALIDATOR_INTERVAL", "300"))
LLM_CONF_THRESHOLD = float(os.environ.get("LLM_CONF_THRESHOLD", "0.70"))
SKIP_LLM = os.environ.get("SKIP_LLM", "false").lower() in {"1", "true", "yes"}
ONESHOT = os.environ.get("ONESHOT", "false").lower() in {"1", "true", "yes"}
VALIDATOR_TIMEOUT = float(os.environ.get("VALIDATOR_TIMEOUT", "200"))
DEDUPE_THRESHOLD = float(os.environ.get("DEDUPE_THRESHOLD", "0.985"))
DEDUPE_MIN_JACCARD = float(os.environ.get("DEDUPE_MIN_JACCARD", "0.80"))
DEDUPE_DB_PATH = os.environ.get("DEDUPE_DB_PATH", "/data/ollama-proxy/rule_embeddings.sqlite")
DEDUPE_EMBED_MODEL = os.environ.get("DEDUPE_EMBED_MODEL", "nomic-embed-text")

SOURCE_DIR = Path(os.environ.get("SOURCE_DIR", "/data/ollama-proxy/generated-rules/latest"))
VALIDATED_DIR = Path(os.environ.get("VALIDATED_DIR", "/data/ollama-proxy/validated-rules"))

RULES_ROOT = Path(os.environ.get("RULES_ROOT", "/data/ollama-proxy/generated-rules"))
PENDING_DIR = RULES_ROOT / "pending"
P_APPROVED = RULES_ROOT / "approved"
P_REJECTED = RULES_ROOT / "rejected"

SUPPORTED_SUFFIXES = {".yml", ".yaml", ".yar", ".yara", ".rules", ".json"}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_source(src: Path) -> Iterable[Path]:
    if not src.is_dir():
        return []
    for p in sorted(src.rglob("*")):
        if p.is_file() and p.suffix.lower() in SUPPORTED_SUFFIXES:
            yield p


def _mirror_target_dir(destination: str, rule_type: str) -> Path:
    if destination in ("output", "output_warn_fp"):
        return VALIDATED_DIR / "approved" / rule_type
    if destination == "rejected/static":
        return VALIDATED_DIR / "rejected" / "static" / rule_type
    if destination == "rejected/llm":
        return VALIDATED_DIR / "rejected" / "llm" / rule_type
    if destination == "rejected/duplicate":
        return VALIDATED_DIR / "rejected" / "duplicate" / rule_type
    return VALIDATED_DIR / "rejected" / "review" / rule_type


def _load_hash_index() -> dict:
    idx_path = VALIDATED_DIR / ".state" / "hash_index.json"
    if idx_path.is_file():
        try:
            return json.loads(idx_path.read_text(encoding="utf-8"))
        except Exception:
            logger.warning("hash index unreadable, starting fresh")
    return {}


def _save_hash_index(idx: dict) -> None:
    idx_path = VALIDATED_DIR / ".state" / "hash_index.json"
    idx_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = idx_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(idx, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(idx_path)


def _ensure_mirror_dirs() -> None:
    for sub in ("approved", "rejected/static", "rejected/llm", "rejected/duplicate", "rejected/review", ".state"):
        (VALIDATED_DIR / sub).mkdir(parents=True, exist_ok=True)


async def _cycle_mirror() -> dict:
    _ensure_mirror_dirs()
    files = list(_iter_source(SOURCE_DIR))
    if not files:
        return {"mode": "mirror", "processed": 0}

    hash_index = _load_hash_index()
    summary: dict = {
        "mode": "mirror",
        "processed": 0,
        "skipped": 0,
        "approved": 0,
        "approved_warn_fp": 0,
        "rejected_static": 0,
        "rejected_llm": 0,
        "rejected_duplicate": 0,
        "rejected_review": 0,
        "failures": 0,
        "by_type": {},
    }

    dedupe_index = RuleDedupeIndex(
        db_path=DEDUPE_DB_PATH,
        threshold=DEDUPE_THRESHOLD,
        embed_model=DEDUPE_EMBED_MODEL,
        min_jaccard=DEDUPE_MIN_JACCARD,
    )

    async with httpx.AsyncClient(timeout=VALIDATOR_TIMEOUT) as client:
        for src in files:
            try:
                h = _sha256(src)
            except Exception as e:
                summary["failures"] += 1
                logger.exception("hashing failed for %s: %s", src, e)
                continue

            cache_key = f"{src}:{h}"
            prev = hash_index.get(cache_key)
            if prev and Path(prev.get("target", "")).exists():
                summary["skipped"] += 1
                continue

            try:
                verdict = await validate_file(
                    src,
                    client=client,
                    llm_conf_threshold=LLM_CONF_THRESHOLD,
                    skip_llm=SKIP_LLM,
                    dedupe_index=dedupe_index,
                )
            except Exception as e:
                summary["failures"] += 1
                logger.exception("validation crashed on %s: %s", src, e)
                continue

            summary["processed"] += 1
            summary["by_type"].setdefault(verdict.rule_type, {"approved": 0, "rejected": 0})

            dst_dir = _mirror_target_dir(verdict.destination, verdict.rule_type)
            dst_dir.mkdir(parents=True, exist_ok=True)
            dst = dst_dir / src.name
            if dst.exists():
                dst = dst.with_name(f"{int(time.time())}-{dst.name}")
            try:
                shutil.copy2(src, dst)
                sidecar_data = verdict.to_dict()
                sidecar_data["source_sha256"] = h
                sidecar_data["source_path"] = str(src)
                sidecar = dst.with_suffix(dst.suffix + ".issues.json")
                sidecar.write_text(json.dumps(sidecar_data, indent=2, ensure_ascii=False), encoding="utf-8")
            except Exception as e:
                summary["failures"] += 1
                logger.exception("copy failed for %s -> %s: %s", src, dst, e)
                continue

            hash_index[cache_key] = {
                "source": str(src),
                "target": str(dst),
                "destination": verdict.destination,
                "rule_type": verdict.rule_type,
                "llm_confidence": verdict.llm_confidence,
                "fp_risk": verdict.fp_risk,
                "dedupe_score": verdict.dedupe_score,
                "ts": int(time.time()),
            }

            if verdict.destination in ("output", "output_warn_fp"):
                logger.info(
                    "APPROVE %-10s %-7s conf=%.2f fp=%-6s -> %s",
                    verdict.rule_type,
                    verdict.destination,
                    verdict.llm_confidence,
                    verdict.fp_risk,
                    dst,
                )
                summary["approved"] += 1
                if verdict.destination == "output_warn_fp":
                    summary["approved_warn_fp"] += 1
                summary["by_type"][verdict.rule_type]["approved"] += 1
                # Persist embedding for future dedupe checks.
                try:
                    if verdict.dedupe_rule_hash:
                        text = src.read_text(encoding="utf-8", errors="replace")
                        _, emb, _ = await dedupe_index.find_neighbors(
                            text,
                            verdict.rule_type,
                            top_k=1,
                            client=client,
                        )
                        dedupe_index.store_embedding(
                            rule_hash=verdict.dedupe_rule_hash,
                            rule_type=verdict.rule_type,
                            source_path=str(src),
                            rule_text=text,
                            embedding=emb,
                        )
                except Exception as e:
                    logger.warning("dedupe embedding store failed for %s: %s", src, e)
            else:
                logger.warning(
                    "REJECT  %-10s %-15s conf=%.2f fp=%-6s -> %s",
                    verdict.rule_type,
                    verdict.destination,
                    verdict.llm_confidence,
                    verdict.fp_risk,
                    dst,
                )
                key = {
                    "rejected/static": "rejected_static",
                    "rejected/llm": "rejected_llm",
                    "rejected/duplicate": "rejected_duplicate",
                    "rejected/review": "rejected_review",
                }[verdict.destination]
                summary[key] += 1
                summary["by_type"][verdict.rule_type]["rejected"] += 1

    _save_hash_index(hash_index)
    logger.info("mirror cycle: %s", json.dumps(summary))
    return summary


def _ensure_pending_dirs() -> None:
    for d in (PENDING_DIR, P_APPROVED, P_REJECTED / "static", P_REJECTED / "llm", P_REJECTED / "duplicate", P_REJECTED / "review"):
        d.mkdir(parents=True, exist_ok=True)


def _pending_target(destination: str, rule_type: str) -> Path:
    if destination in ("output", "output_warn_fp"):
        return P_APPROVED / rule_type
    sub = destination.split("/", 1)[1]
    return P_REJECTED / sub / rule_type


async def _cycle_pending() -> dict:
    _ensure_pending_dirs()
    files = list(_iter_source(PENDING_DIR))
    summary: dict = {
        "mode": "pending",
        "processed": 0,
        "approved": 0,
        "rejected_static": 0,
        "rejected_llm": 0,
        "rejected_duplicate": 0,
        "rejected_review": 0,
        "failures": 0,
    }
    if not files:
        return summary

    dedupe_index = RuleDedupeIndex(
        db_path=DEDUPE_DB_PATH,
        threshold=DEDUPE_THRESHOLD,
        embed_model=DEDUPE_EMBED_MODEL,
        min_jaccard=DEDUPE_MIN_JACCARD,
    )

    async with httpx.AsyncClient(timeout=VALIDATOR_TIMEOUT) as client:
        for src in files:
            try:
                verdict = await validate_file(
                    src,
                    client=client,
                    llm_conf_threshold=LLM_CONF_THRESHOLD,
                    skip_llm=SKIP_LLM,
                    dedupe_index=dedupe_index,
                )
            except Exception as e:
                summary["failures"] += 1
                logger.exception("validation crashed on %s: %s", src, e)
                continue

            summary["processed"] += 1
            dst_dir = _pending_target(verdict.destination, verdict.rule_type)
            dst_dir.mkdir(parents=True, exist_ok=True)
            dst = dst_dir / src.name
            if dst.exists():
                dst = dst.with_name(f"{int(time.time())}-{dst.name}")
            try:
                shutil.move(str(src), str(dst))
                sidecar = dst.with_suffix(dst.suffix + ".issues.json")
                sidecar.write_text(json.dumps(verdict.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
            except Exception as e:
                summary["failures"] += 1
                logger.exception("move failed for %s: %s", src, e)
                continue

            if verdict.destination in ("output", "output_warn_fp"):
                summary["approved"] += 1
                try:
                    if verdict.dedupe_rule_hash:
                        text = dst.read_text(encoding="utf-8", errors="replace")
                        _, emb, _ = await dedupe_index.find_neighbors(
                            text,
                            verdict.rule_type,
                            top_k=1,
                            client=client,
                        )
                        dedupe_index.store_embedding(
                            rule_hash=verdict.dedupe_rule_hash,
                            rule_type=verdict.rule_type,
                            source_path=str(dst),
                            rule_text=text,
                            embedding=emb,
                        )
                except Exception as e:
                    logger.warning("dedupe embedding store failed for %s: %s", dst, e)
            else:
                summary[
                    {
                        "rejected/static": "rejected_static",
                        "rejected/llm": "rejected_llm",
                        "rejected/duplicate": "rejected_duplicate",
                        "rejected/review": "rejected_review",
                    }[verdict.destination]
                ] += 1

    logger.info("pending cycle: %s", json.dumps(summary))
    return summary


async def _process_once() -> dict:
    if MODE == "pending":
        return await _cycle_pending()
    return await _cycle_mirror()


async def _main() -> int:
    logger.info(
        "rule-validator starting: mode=%s interval=%ss skip_llm=%s conf>=%.2f",
        MODE,
        INTERVAL,
        SKIP_LLM,
        LLM_CONF_THRESHOLD,
    )
    if MODE not in ("mirror", "pending"):
        logger.error("unknown VALIDATOR_MODE=%s", MODE)
        return 2

    if ONESHOT:
        await _process_once()
        return 0

    while True:
        try:
            await _process_once()
        except Exception as e:
            logger.exception("cycle failed: %s", e)
        await asyncio.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(_main()))
    except KeyboardInterrupt:
        sys.exit(0)
