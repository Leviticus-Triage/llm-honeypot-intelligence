from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx
import numpy as np


@dataclass
class DedupeNeighbor:
    rule_hash: str
    score: float
    source_path: str
    rule_text: str


class RuleDedupeIndex:
    def __init__(
        self,
        *,
        db_path: str,
        proxy_url: Optional[str] = None,
        embed_model: str = "nomic-embed-text",
        threshold: float = 0.93,
        min_jaccard: float = 0.80,
    ):
        self.db_path = db_path
        self.proxy_url = (proxy_url or os.environ.get("PROXY_URL", "http://localhost:11435")).rstrip("/")
        self.embed_model = embed_model
        self.threshold = threshold
        self.min_jaccard = min_jaccard
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        p = Path(self.db_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rules (
                  rule_hash TEXT PRIMARY KEY,
                  rule_type TEXT NOT NULL,
                  source_path TEXT NOT NULL,
                  rule_text TEXT NOT NULL,
                  embedding BLOB NOT NULL,
                  created_at INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rules_type ON rules(rule_type)")
            conn.commit()

    @staticmethod
    def _rule_hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    @staticmethod
    def _pack(v: list[float]) -> bytes:
        return np.asarray(v, dtype=np.float32).tobytes()

    @staticmethod
    def _unpack(b: bytes) -> np.ndarray:
        return np.frombuffer(b, dtype=np.float32)

    @staticmethod
    def _cosine(a: np.ndarray, b: np.ndarray) -> float:
        na = np.linalg.norm(a)
        nb = np.linalg.norm(b)
        if na == 0 or nb == 0:
            return 0.0
        return float(np.dot(a, b) / (na * nb))

    @staticmethod
    def _line_jaccard(a: str, b: str) -> float:
        la = {x.strip() for x in a.splitlines() if x.strip()}
        lb = {x.strip() for x in b.splitlines() if x.strip()}
        if not la or not lb:
            return 0.0
        inter = len(la & lb)
        union = len(la | lb)
        return inter / union if union else 0.0

    async def _embed(self, text: str, client: Optional[httpx.AsyncClient] = None) -> list[float]:
        own = False
        if client is None:
            client = httpx.AsyncClient(timeout=60.0)
            own = True
        try:
            resp = await client.post(
                f"{self.proxy_url}/api/embeddings",
                json={"model": self.embed_model, "prompt": text},
            )
            resp.raise_for_status()
            data = resp.json()
            emb = data.get("embedding") or []
            if not emb:
                raise ValueError("empty embedding response")
            return emb
        finally:
            if own:
                await client.aclose()

    def _load_candidates(self, rule_type: str) -> list[sqlite3.Row]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT rule_hash, source_path, rule_text, embedding FROM rules WHERE rule_type = ?",
                (rule_type,),
            ).fetchall()
        return rows

    async def find_neighbors(
        self,
        text: str,
        rule_type: str,
        *,
        top_k: int = 5,
        client: Optional[httpx.AsyncClient] = None,
    ) -> tuple[str, np.ndarray, list[DedupeNeighbor]]:
        rule_hash = self._rule_hash(text)
        emb = np.asarray(await self._embed(text, client=client), dtype=np.float32)
        candidates = self._load_candidates(rule_type)
        scored: list[DedupeNeighbor] = []
        for row in candidates:
            score = self._cosine(emb, self._unpack(row["embedding"]))
            scored.append(
                DedupeNeighbor(
                    rule_hash=row["rule_hash"],
                    score=score,
                    source_path=row["source_path"],
                    rule_text=row["rule_text"],
                )
            )
        scored.sort(key=lambda x: x.score, reverse=True)
        return rule_hash, emb, scored[:top_k]

    async def is_duplicate(
        self,
        text: str,
        rule_type: str,
        *,
        client: Optional[httpx.AsyncClient] = None,
    ) -> tuple[bool, str, np.ndarray, list[DedupeNeighbor]]:
        rule_hash, emb, neighbors = await self.find_neighbors(text, rule_type, client=client)
        if neighbors:
            top = neighbors[0]
            jac = self._line_jaccard(text, top.rule_text)
            if top.score >= self.threshold and jac >= self.min_jaccard:
                return True, rule_hash, emb, neighbors
        return False, rule_hash, emb, neighbors

    def store_embedding(
        self,
        *,
        rule_hash: str,
        rule_type: str,
        source_path: str,
        rule_text: str,
        embedding: np.ndarray,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO rules(rule_hash, rule_type, source_path, rule_text, embedding, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    rule_hash,
                    rule_type,
                    source_path,
                    rule_text,
                    self._pack(embedding.tolist()),
                    int(time.time()),
                ),
            )
            conn.commit()
