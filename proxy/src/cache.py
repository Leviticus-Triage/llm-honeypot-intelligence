"""
Hybrid cache: exact hash lookup + semantic similarity fallback.
"""

import hashlib
import json
import logging
import random
import struct
from datetime import datetime
from typing import Optional

import numpy as np

from .models import get_db

logger = logging.getLogger("ollama-proxy.cache")


def compute_prompt_hash(messages: list, model: str) -> str:
    """Compute a deterministic hash of the prompt messages + model."""
    # Use only user/system messages for hashing (ignore assistant history)
    key_parts = []
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        key_parts.append(f"{role}:{content}")
    key_parts.append(f"model:{model}")
    raw = "\n".join(key_parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def extract_user_prompt(messages: list) -> str:
    """Extract the meaningful user prompt text for embedding."""
    user_msgs = [m["content"] for m in messages if m.get("role") == "user"]
    return user_msgs[-1] if user_msgs else ""


def serialize_embedding(embedding: list[float]) -> bytes:
    """Serialize embedding to compact binary format."""
    return struct.pack(f"{len(embedding)}f", *embedding)


def deserialize_embedding(data: bytes) -> np.ndarray:
    """Deserialize binary embedding to numpy array."""
    count = len(data) // 4
    return np.array(struct.unpack(f"{count}f", data), dtype=np.float32)


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Compute cosine similarity between two vectors."""
    dot = np.dot(a, b)
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(dot / (norm_a * norm_b))


class HybridCache:
    """Hybrid exact + semantic cache for Ollama responses."""

    def __init__(
        self,
        semantic_threshold: float = 0.85,
        exploration_rate: float = 0.15,
        embed_fn=None,
    ):
        self.semantic_threshold = semantic_threshold
        self.exploration_rate = exploration_rate
        self.embed_fn = embed_fn  # async callable: prompt_text -> list[float]
        self._stats = {"hits_exact": 0, "hits_semantic": 0, "misses": 0}

    @property
    def stats(self) -> dict:
        total = sum(self._stats.values())
        hit_rate = (
            (self._stats["hits_exact"] + self._stats["hits_semantic"]) / total
            if total > 0
            else 0.0
        )
        return {**self._stats, "total": total, "hit_rate": round(hit_rate, 3)}

    def exact_lookup(self, prompt_hash: str, src_ip: str = "", cve_meta: dict = None) -> Optional[dict]:
        """Look up an exact cached response by prompt hash."""
        with get_db() as conn:
            row = conn.execute(
                "SELECT id FROM prompt_cache WHERE prompt_hash = ?",
                (prompt_hash,),
            ).fetchone()
            if not row:
                return None
            prompt_id = row["id"]
            return self._pick_response(conn, prompt_id, prompt_hash, src_ip, cve_meta)

    async def semantic_lookup(self, prompt_text: str, src_ip: str = "", cve_meta: dict = None) -> Optional[dict]:
        """Find a semantically similar cached prompt and return its best response.

        CVE-aware: only matches against prompts with the same CVE profile
        to prevent cross-contamination (e.g. FortiGate response for Cisco session).
        """
        if not self.embed_fn:
            return None

        try:
            query_emb = await self.embed_fn(prompt_text)
        except Exception as e:
            logger.warning("Embedding failed: %s", e)
            return None

        query_vec = np.array(query_emb, dtype=np.float32)
        cve_id = (cve_meta or {}).get("cve_id", "")

        with get_db() as conn:
            if cve_id:
                rows = conn.execute(
                    "SELECT id, prompt_hash, prompt_embedding FROM prompt_cache "
                    "WHERE prompt_embedding IS NOT NULL AND cve_id = ?",
                    (cve_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, prompt_hash, prompt_embedding FROM prompt_cache "
                    "WHERE prompt_embedding IS NOT NULL AND (cve_id = '' OR cve_id IS NULL)"
                ).fetchall()

        best_sim = 0.0
        best_row = None
        for row in rows:
            cached_vec = deserialize_embedding(row["prompt_embedding"])
            sim = cosine_similarity(query_vec, cached_vec)
            if sim > best_sim:
                best_sim = sim
                best_row = row

        if best_row and best_sim >= self.semantic_threshold:
            logger.info(
                "Semantic hit: similarity=%.3f hash=%s",
                best_sim,
                best_row["prompt_hash"][:12],
            )
            with get_db() as conn:
                return self._pick_response(
                    conn, best_row["id"], best_row["prompt_hash"], src_ip, cve_meta
                )

        return None

    def _pick_response(self, conn, prompt_id: int, prompt_hash: str, src_ip: str = "", cve_meta: dict = None) -> Optional[dict]:
        """Pick a response using weighted random selection based on engagement scores."""
        responses = conn.execute(
            "SELECT id, response_text, engagement_score, times_served "
            "FROM responses WHERE prompt_cache_id = ? ORDER BY engagement_score DESC",
            (prompt_id,),
        ).fetchall()

        if not responses:
            return None

        # Softmax-weighted selection based on engagement scores
        scores = [max(r["engagement_score"], 0.01) for r in responses]
        total_score = sum(scores)
        weights = [s / total_score for s in scores]

        chosen = random.choices(responses, weights=weights, k=1)[0]

        # Update serve stats
        now = datetime.utcnow().isoformat()
        conn.execute(
            "UPDATE responses SET times_served = times_served + 1, last_served = ? "
            "WHERE id = ?",
            (now, chosen["id"]),
        )

        # Include CVE metadata in serve_log if present
        cve_id = (cve_meta or {}).get("cve_id", "")
        cve_vendor = (cve_meta or {}).get("cve_vendor", "")
        cve_product = (cve_meta or {}).get("cve_product", "")
        conn.execute(
            "INSERT INTO serve_log (response_id, served_at, prompt_hash, src_ip, cve_id, cve_vendor, cve_product) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (chosen["id"], now, prompt_hash, src_ip, cve_id, cve_vendor, cve_product),
        )

        return {
            "response_id": chosen["id"],
            "response_text": chosen["response_text"],
            "source": "cache",
            "engagement_score": chosen["engagement_score"],
        }

    async def store(
        self,
        prompt_hash: str,
        prompt_text: str,
        model: str,
        response_text: str,
        src_ip: str = "",
        cve_meta: dict = None,
    ) -> int:
        """Store a new prompt + response in the cache and log the serve event.

        Also creates a serve_log entry so RL scoring can track first-time
        responses (not just cache hits). CVE metadata is stored in both
        prompt_cache (for CVE-aware semantic matching) and serve_log
        (for CVE session push to ES).
        """
        embedding_blob = None
        if self.embed_fn:
            try:
                emb = await self.embed_fn(prompt_text)
                embedding_blob = serialize_embedding(emb)
            except Exception as e:
                logger.warning("Failed to compute embedding for storage: %s", e)

        cve_id = (cve_meta or {}).get("cve_id", "")
        cve_vendor = (cve_meta or {}).get("cve_vendor", "")
        cve_product = (cve_meta or {}).get("cve_product", "")

        with get_db() as conn:
            # Upsert prompt
            existing = conn.execute(
                "SELECT id FROM prompt_cache WHERE prompt_hash = ?",
                (prompt_hash,),
            ).fetchone()

            if existing:
                prompt_id = existing["id"]
                # Update embedding if we have one now and didn't before
                if embedding_blob:
                    conn.execute(
                        "UPDATE prompt_cache SET prompt_embedding = ? "
                        "WHERE id = ? AND prompt_embedding IS NULL",
                        (embedding_blob, prompt_id),
                    )
                # Update CVE tag if we have one now
                if cve_id:
                    conn.execute(
                        "UPDATE prompt_cache SET cve_id = ? WHERE id = ? AND (cve_id = '' OR cve_id IS NULL)",
                        (cve_id, prompt_id),
                    )
            else:
                cur = conn.execute(
                    "INSERT INTO prompt_cache (prompt_hash, prompt_text, prompt_embedding, model, cve_id) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (prompt_hash, prompt_text, embedding_blob, model, cve_id),
                )
                prompt_id = cur.lastrowid

            # Store response
            cur = conn.execute(
                "INSERT INTO responses (prompt_cache_id, response_text) VALUES (?, ?)",
                (prompt_id, response_text),
            )
            resp_id = cur.lastrowid

            # Create serve_log entry for this first-serve (cache miss)
            # This ensures RL can score responses that were generated fresh
            now = datetime.utcnow().isoformat()
            conn.execute(
                "INSERT INTO serve_log (response_id, served_at, prompt_hash, src_ip, cve_id, cve_vendor, cve_product) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (resp_id, now, prompt_hash, src_ip, cve_id, cve_vendor, cve_product),
            )

            return resp_id

    def should_explore(self) -> bool:
        """Return True if we should bypass cache and call Ollama for exploration."""
        return random.random() < self.exploration_rate
