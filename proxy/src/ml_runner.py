"""
Offline ML Runner (Phase 6).

Implements:
- Dataset export from honeypot-cve-sessions
- IsolationForest training
- LightGBM One-vs-Rest training (fallback to sklearn if unavailable)
- Inference + bulk update of ml_* fields in honeypot-cve-sessions
"""

from __future__ import annotations

import json
import logging
import math
import os
import pickle
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import numpy as np
import zlib

logger = logging.getLogger("ml-runner")

ES_URL = os.environ.get("ES_URL", "https://localhost:64297/es")
ES_USER = os.environ.get("ES_USER", "")
ES_PASS = os.environ.get("ES_PASS", "")

DATASET_DIR = Path(os.environ.get("DATASET_DIR", "/data/ml-runner/datasets"))
MODEL_DIR = Path(os.environ.get("MODEL_DIR", "/data/ml-runner/models"))
SOURCE_INDEX = os.environ.get("ML_SOURCE_INDEX", "honeypot-cve-sessions")

EXPORT_HOURS = int(os.environ.get("ML_EXPORT_HOURS", "720"))  # 30d
INFER_HOURS = int(os.environ.get("ML_INFER_HOURS", "24"))
MAX_EXPORT_DOCS = int(os.environ.get("ML_MAX_EXPORT_DOCS", "50000"))
MAX_INFER_DOCS = int(os.environ.get("ML_MAX_INFER_DOCS", "5000"))

BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{20,}={0,2})")
URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
NON_PRINTABLE_RE = re.compile(r"[^\x20-\x7E]")

NUMERIC_FEATURES = [
    "session_duration",
    "cmd_count",
    "unique_cmds",
    "payload_len",
    "payload_entropy_byte",
    "payload_entropy_bigram",
    "non_printable_ratio",
    "base64_score",
    "url_count",
    "cve_tag_present",
    "hour_of_day",
    "prompt_len",
    "response_len",
]

# Command/text feature-hashing:
# For CVE-classification the pure numeric surface (length, entropy, …) is not
# enough — different CVEs share very similar shell-probe shape. We add a
# fixed-size feature-hashed bag of command tokens + bigrams so the classifier
# can learn per-CVE command signatures (e.g. "overlayfs", "sudo -u#",
# "CVE-2024-1086"…) without blowing up the feature space.
HASH_DIMS = int(os.environ.get("ML_HASH_DIMS", "128"))
TOKEN_SPLIT_RE = re.compile(r"[\s;&|`$()<>\"'\\]+")
CLASSIFIER_TOP_K = int(os.environ.get("ML_CLASSIFIER_TOP_K", "3"))
CLASSIFIER_PROBA_FLOOR = float(os.environ.get("ML_CLASSIFIER_PROBA_FLOOR", "0.15"))


def _command_tokens(text: str) -> list[str]:
    """Coarse shell/URL/CVE tokens from prompt or full session blob.

    We deliberately keep short tokens (3+ chars) and skip pure digits so the
    hashing bucket has signal, not noise.
    """
    if not text:
        return []
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        for tok in TOKEN_SPLIT_RE.split(line):
            tok = tok.strip().lower()
            if 3 <= len(tok) <= 48 and not tok.isdigit():
                out.append(tok)
    return out


def _tok_hash(tok: str, n_dims: int) -> int:
    """Deterministic hash across Python processes (Python's hash() is not)."""
    return zlib.crc32(tok.encode("utf-8", "ignore")) % n_dims


def _hash_features(text: str, n_dims: int = HASH_DIMS) -> np.ndarray:
    """Feature-hash trick: count unigrams + bigrams into fixed-size vector."""
    vec = np.zeros(n_dims, dtype=np.float32)
    toks = _command_tokens(text)
    if not toks:
        return vec
    for t in toks:
        vec[_tok_hash(t, n_dims)] += 1.0
    for a, b in zip(toks, toks[1:]):
        vec[_tok_hash(a + "\x01" + b, n_dims)] += 0.5
    vmax = vec.max()
    if vmax > 0:
        vec /= vmax
    return vec


def _auth():
    return (ES_USER, ES_PASS) if ES_USER else None


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((v / total) * math.log2(v / total) for v in freq.values())


def _bigram_entropy(text: str) -> float:
    if len(text) < 2:
        return 0.0
    grams = [text[i : i + 2] for i in range(len(text) - 1)]
    return _entropy("".join(grams))


def _extract_features(doc: dict[str, Any]) -> dict[str, Any]:
    prompt = str(doc.get("prompt_text", "") or "")
    response = str(doc.get("response_text", "") or "")
    cve_id = str(doc.get("cve_id", "") or "")

    merged = (prompt + "\n" + response).strip()
    lines = [x.strip() for x in prompt.splitlines() if x.strip()]
    unique_lines = len(set(lines))

    non_print = len(NON_PRINTABLE_RE.findall(merged))
    base64_hits = BASE64_RE.findall(merged)
    urls = URL_RE.findall(merged)

    ts = str(doc.get("@timestamp", "") or "")
    hour_of_day = 0
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hour_of_day = dt.hour
        except Exception:
            pass

    # Keep only prompt for the hashing channel — response is LLM-generated and
    # would pollute the attacker-signature space.
    return {
        "session_duration": float(doc.get("duration_s", 0.0) or 0.0),
        "cmd_count": float(len(lines)),
        "unique_cmds": float(unique_lines),
        "payload_len": float(len(merged)),
        "payload_entropy_byte": float(_entropy(merged)),
        "payload_entropy_bigram": float(_bigram_entropy(merged)),
        "non_printable_ratio": float(non_print / max(len(merged), 1)),
        "base64_score": float(sum(len(x) for x in base64_hits) / max(len(merged), 1)),
        "url_count": float(len(urls)),
        "cve_tag_present": float(1.0 if cve_id else 0.0),
        "hour_of_day": float(hour_of_day),
        "prompt_len": float(len(prompt)),
        "response_len": float(len(response)),
        "label_cve": cve_id,
        "_text_for_hash": prompt[:4000],
    }


def _matrix(rows: list[dict[str, Any]]) -> np.ndarray:
    m = np.zeros((len(rows), len(NUMERIC_FEATURES)), dtype=np.float32)
    for i, row in enumerate(rows):
        for j, k in enumerate(NUMERIC_FEATURES):
            m[i, j] = float(row.get(k, 0.0) or 0.0)
    return m


def _hash_matrix(rows: list[dict[str, Any]], n_dims: int = HASH_DIMS) -> np.ndarray:
    """Feature-hashed command/token matrix. Used by the classifier, not by
    IsolationForest (too high-cardinal to help anomaly scoring)."""
    m = np.zeros((len(rows), n_dims), dtype=np.float32)
    for i, row in enumerate(rows):
        m[i] = _hash_features(str(row.get("_text_for_hash") or ""), n_dims)
    return m


async def _es_search(index: str, body: dict[str, Any]) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=60.0, verify=False, auth=_auth()) as client:
        resp = await client.post(f"{ES_URL}/{index}/_search", json=body)
        if resp.status_code != 200:
            logger.warning("ES search failed on %s: %s", index, resp.text[:200])
            return {"hits": {"hits": []}}
        return resp.json()


async def export_trainset(*, since_hours: int = EXPORT_HOURS, max_docs: int = MAX_EXPORT_DOCS) -> dict:
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
    body = {
        "size": min(max_docs, 10000),
        "query": {"bool": {"must": [{"range": {"@timestamp": {"gte": since}}}]}},
        "sort": [{"@timestamp": "desc"}],
        "_source": ["@timestamp", "prompt_text", "response_text", "cve_id", "src_ip", "serve_log_id"],
    }
    data = await _es_search(SOURCE_INDEX, body)
    hits = data.get("hits", {}).get("hits", [])
    rows: list[dict[str, Any]] = []
    for h in hits:
        src = h.get("_source", {})
        feat = _extract_features(src)
        feat["_id"] = h.get("_id")
        feat["src_ip"] = str(src.get("src_ip", "") or "")
        feat["serve_log_id"] = src.get("serve_log_id")
        feat["@timestamp"] = src.get("@timestamp")
        rows.append(feat)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    out = DATASET_DIR / f"trainset_{ts}.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    latest = DATASET_DIR / "latest_trainset.jsonl"
    latest.write_text(out.read_text(encoding="utf-8"), encoding="utf-8")
    summary = {"rows": len(rows), "path": str(out)}
    logger.info("Exported dataset: %s", summary)
    return summary


def _load_latest_dataset() -> list[dict[str, Any]]:
    path = DATASET_DIR / "latest_trainset.jsonl"
    if not path.is_file():
        raise FileNotFoundError(f"dataset missing: {path}")
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def train_isoforest() -> dict:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import RobustScaler

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    rows = _load_latest_dataset()
    if len(rows) < 50:
        raise RuntimeError(f"insufficient rows for IsoForest: {len(rows)}")
    x = _matrix(rows)
    # RobustScaler gives heavy-tailed honeypot data a saner feature scale than
    # StandardScaler (which gets pulled around by outliers and squishes the
    # main cluster into ~0, then every decision_function comes out near 0 too).
    scaler = RobustScaler(with_centering=True, with_scaling=True)
    x_scaled = scaler.fit_transform(x)
    clf = IsolationForest(
        n_estimators=300,
        contamination=0.10,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(x_scaled)
    raw = -clf.decision_function(x_scaled)
    median = float(np.median(raw))
    # Percentile references for robust 0..1 normalisation at inference time.
    p05 = float(np.quantile(raw, 0.05))
    p50 = float(np.quantile(raw, 0.50))
    p95 = float(np.quantile(raw, 0.95))
    p99 = float(np.quantile(raw, 0.99))
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    out = MODEL_DIR / f"isoforest_v{ts}.pkl"
    with out.open("wb") as f:
        pickle.dump(
            {
                "scaler": scaler,
                "model": clf,
                "features": NUMERIC_FEATURES,
                "norm": {"p05": p05, "p50": p50, "p95": p95, "p99": p99,
                         "median": median},
            },
            f,
        )
    current = MODEL_DIR / "current_isoforest.pkl"
    current.write_bytes(out.read_bytes())
    summary = {"rows": len(rows), "path": str(out),
               "p05": p05, "p50": p50, "p95": p95, "p99": p99}
    logger.info("Trained IsoForest: %s", summary)
    return summary


def train_lgbm() -> dict:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    rows = _load_latest_dataset()
    labeled = [r for r in rows if r.get("label_cve")]
    if len(labeled) < 100:
        raise RuntimeError(f"insufficient labeled rows for classifier: {len(labeled)}")
    # Drop extremely rare classes (< 5 samples) — LightGBM/RF handle them badly
    # and they pollute the feature space with near-zero prior.
    counts: dict[str, int] = {}
    for r in labeled:
        k = str(r.get("label_cve") or "")
        counts[k] = counts.get(k, 0) + 1
    labeled = [r for r in labeled if counts.get(str(r.get("label_cve") or ""), 0) >= 5]
    if len(labeled) < 100:
        raise RuntimeError(
            f"insufficient labeled rows after rare-class filter: {len(labeled)}"
        )
    x_num = _matrix(labeled)
    x_hash = _hash_matrix(labeled, HASH_DIMS)
    labels = [str(r.get("label_cve") or "") for r in labeled]
    unique = sorted(set(labels))

    from sklearn.multiclass import OneVsRestClassifier
    from sklearn.preprocessing import MultiLabelBinarizer, StandardScaler

    mlb = MultiLabelBinarizer(classes=unique)
    y = mlb.fit_transform([[lbl] for lbl in labels])
    scaler = StandardScaler()
    # Scale ONLY the numeric channel; hash features are already in [0,1] and
    # scaling them across the whole dataset would spread the zero-background
    # into meaningless noise.
    x_num_scaled = scaler.fit_transform(x_num)
    x_scaled = np.concatenate([x_num_scaled, x_hash], axis=1)

    estimator_name = "lightgbm"
    try:
        from lightgbm import LGBMClassifier

        base = LGBMClassifier(
            n_estimators=250,
            learning_rate=0.05,
            num_leaves=63,
            feature_fraction=0.8,
            # Dominant-class correction: without this the classifier collapses
            # to always predicting CVE-2024-6387 (≈80 % of sessions).
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
            verbose=-1,
        )
    except Exception as e:
        from sklearn.ensemble import RandomForestClassifier

        estimator_name = "random_forest_fallback"
        logger.warning("LightGBM unavailable, using RandomForest fallback: %s", e)
        base = RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
    clf = OneVsRestClassifier(base)
    clf.fit(x_scaled, y)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    out = MODEL_DIR / f"lgbm_ovr_v{ts}.pkl"
    with out.open("wb") as f:
        pickle.dump(
            {
                "scaler": scaler,
                "model": clf,
                "mlb": mlb,
                "features": NUMERIC_FEATURES,
                "estimator_name": estimator_name,
                "hash_dims": HASH_DIMS,
                "top_k": CLASSIFIER_TOP_K,
                "proba_floor": CLASSIFIER_PROBA_FLOOR,
            },
            f,
        )
    current = MODEL_DIR / "current_lgbm.pkl"
    current.write_bytes(out.read_bytes())
    summary = {
        "rows": len(labeled), "classes": len(unique), "path": str(out),
        "estimator": estimator_name, "hash_dims": HASH_DIMS,
    }
    logger.info("Trained classifier: %s", summary)
    return summary


async def infer_and_update(*, since_hours: int = INFER_HOURS, max_docs: int = MAX_INFER_DOCS) -> dict:
    iso_path = MODEL_DIR / "current_isoforest.pkl"
    clf_path = MODEL_DIR / "current_lgbm.pkl"
    if not iso_path.is_file() or not clf_path.is_file():
        raise FileNotFoundError("current models missing (current_isoforest.pkl/current_lgbm.pkl)")
    iso = pickle.loads(iso_path.read_bytes())
    clf = pickle.loads(clf_path.read_bytes())

    since = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
    body = {
        "size": min(max_docs, 10000),
        "query": {"bool": {"must": [{"range": {"@timestamp": {"gte": since}}}]}},
        "sort": [{"@timestamp": "desc"}],
        "_source": ["@timestamp", "prompt_text", "response_text", "cve_id", "src_ip", "serve_log_id"],
    }
    data = await _es_search(SOURCE_INDEX, body)
    hits = data.get("hits", {}).get("hits", [])
    if not hits:
        return {"updated": 0, "docs": 0}

    feat_rows = [_extract_features(h.get("_source", {})) for h in hits]
    x = _matrix(feat_rows)

    x_iso = iso["scaler"].transform(x)
    anomaly_raw = -iso["model"].decision_function(x_iso)

    norm = iso.get("norm") or {}
    p50 = float(norm.get("p50", 0.0))
    p95 = float(norm.get("p95", p50 + 1e-6))
    p99 = float(norm.get("p99", p95 + 1e-6))
    # Piecewise-linear rescale:
    #   raw <= p50  -> 0.0..0.30 (normal traffic)
    #   p50..p95    -> 0.30..0.70
    #   p95..p99    -> 0.70..0.95
    #   > p99       -> clamp to 0.99
    anomaly_score = np.zeros_like(anomaly_raw)
    for i, v in enumerate(anomaly_raw):
        if v <= p50:
            span = max(p50 - float(norm.get("p05", p50 - 1e-6)), 1e-6)
            anomaly_score[i] = max(0.0, 0.30 * (v - float(norm.get("p05", p50 - 1e-6))) / span)
        elif v <= p95:
            anomaly_score[i] = 0.30 + 0.40 * (v - p50) / max(p95 - p50, 1e-6)
        elif v <= p99:
            anomaly_score[i] = 0.70 + 0.25 * (v - p95) / max(p99 - p95, 1e-6)
        else:
            anomaly_score[i] = 0.99

    # Classifier: numeric features scaled + hashed command features appended.
    # Backward-compatible: legacy models without hash_dims still work.
    hash_dims = int(clf.get("hash_dims") or 0)
    x_num_scaled = clf["scaler"].transform(x)
    if hash_dims > 0:
        x_hash = _hash_matrix(feat_rows, hash_dims)
        x_clf = np.concatenate([x_num_scaled, x_hash], axis=1)
    else:
        x_clf = x_num_scaled

    classes = list(clf["mlb"].classes_)
    top_k = int(clf.get("top_k") or CLASSIFIER_TOP_K)
    proba_floor = float(clf.get("proba_floor") or CLASSIFIER_PROBA_FLOOR)

    # OvR → predict_proba returns (n, n_classes). We rank per row, keep the
    # top-K classes whose proba is above the floor, and emit them as tags +
    # a structured ml_classifier_top list so Kibana can show per-CVE confidence.
    try:
        proba = clf["model"].predict_proba(x_clf)
    except Exception as e:
        logger.warning("predict_proba failed (%s), falling back to predict", e)
        proba = None

    if proba is None:
        pred = clf["model"].predict(x_clf)
        tag_rows = [
            [classes[j] for j, v in enumerate(p.tolist()) if int(v) == 1]
            for p in pred
        ]
        top_rows: list[list[dict[str, float]]] = [[] for _ in tag_rows]
    else:
        proba = np.asarray(proba, dtype=np.float32)
        tag_rows = []
        top_rows = []
        for row in proba:
            order = np.argsort(-row)
            picked = [
                (classes[j], float(row[j]))
                for j in order[:top_k]
                if float(row[j]) >= proba_floor
            ]
            if not picked and order.size:
                j = int(order[0])
                picked = [(classes[j], float(row[j]))]
            tag_rows.append([p[0] for p in picked])
            top_rows.append([
                {"cve": cve, "proba": round(p, 4)} for cve, p in picked
            ])

    lines: list[str] = []
    for i, h in enumerate(hits):
        doc_id = h.get("_id")
        if not doc_id:
            continue
        lines.append(json.dumps({"update": {"_index": SOURCE_INDEX, "_id": doc_id}}))
        lines.append(
            json.dumps(
                {
                    "doc": {
                        "ml_anomaly_score": float(anomaly_score[i]),
                        "ml_classifier_tags": tag_rows[i],
                        "ml_classifier_top": top_rows[i],
                        "ml_classifier_top1_proba": (
                            top_rows[i][0]["proba"] if top_rows[i] else 0.0
                        ),
                        "ml_model_version": {
                            "isoforest": "current_isoforest.pkl",
                            "classifier": "current_lgbm.pkl",
                        },
                    }
                }
            )
        )
    if not lines:
        return {"updated": 0, "docs": len(hits)}
    # Chunk to stay below the nginx/ES body limit (≈1 MB default). Each doc
    # update is ~2 lines of ndjson — 1000 pairs = 2000 lines stays comfortably
    # under 1 MB even with top_k and ml_classifier_top objects.
    chunk_size_pairs = int(os.environ.get("ML_BULK_CHUNK_PAIRS", "1000"))
    updated = 0
    async with httpx.AsyncClient(timeout=120.0, verify=False, auth=_auth()) as client:
        for start in range(0, len(lines), chunk_size_pairs * 2):
            chunk = lines[start: start + chunk_size_pairs * 2]
            payload = "\n".join(chunk) + "\n"
            resp = await client.post(
                f"{ES_URL}/_bulk",
                content=payload,
                headers={"Content-Type": "application/x-ndjson"},
            )
            if resp.status_code not in (200, 201):
                raise RuntimeError(
                    f"bulk update failed: {resp.status_code} {resp.text[:200]}"
                )
            updated += len(chunk) // 2
    summary = {"updated": updated, "docs": len(hits)}
    logger.info("Inference update summary: %s", summary)
    return summary
