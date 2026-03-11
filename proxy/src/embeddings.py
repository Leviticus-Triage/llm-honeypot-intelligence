"""
Embedding computation via the upstream Ollama /api/embeddings endpoint.
"""

import logging
from typing import Optional

import httpx

logger = logging.getLogger("ollama-proxy.embeddings")

_client: Optional[httpx.AsyncClient] = None
_upstream_url: str = "http://localhost:11434"
_model: str = "nomic-embed-text"


def configure(upstream_url: str, model: str):
    """Configure the embedding module."""
    global _upstream_url, _model
    _upstream_url = upstream_url.rstrip("/")
    _model = model


def get_client() -> httpx.AsyncClient:
    """Get or create the async HTTP client."""
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=30.0)
    return _client


async def compute_embedding(text: str) -> list[float]:
    """Compute embedding for a text string using Ollama's embedding API."""
    client = get_client()
    resp = await client.post(
        f"{_upstream_url}/api/embeddings",
        json={"model": _model, "prompt": text},
    )
    resp.raise_for_status()
    data = resp.json()
    embedding = data.get("embedding", [])
    if not embedding:
        raise ValueError(f"Empty embedding returned for text: {text[:50]}...")
    return embedding


async def ensure_model_available():
    """Pull the embedding model if not already available."""
    client = get_client()
    try:
        # Check if model exists
        resp = await client.post(
            f"{_upstream_url}/api/show",
            json={"name": _model},
        )
        if resp.status_code == 200:
            logger.info("Embedding model '%s' is available", _model)
            return True
    except Exception:
        pass

    logger.info("Pulling embedding model '%s'...", _model)
    try:
        resp = await client.post(
            f"{_upstream_url}/api/pull",
            json={"name": _model, "stream": False},
            timeout=300.0,
        )
        if resp.status_code == 200:
            logger.info("Embedding model '%s' pulled successfully", _model)
            return True
        else:
            logger.warning(
                "Failed to pull embedding model: %s %s",
                resp.status_code,
                resp.text[:200],
            )
            return False
    except Exception as e:
        logger.warning("Failed to pull embedding model: %s", e)
        return False


async def shutdown():
    """Close the HTTP client."""
    global _client
    if _client:
        await _client.aclose()
        _client = None
