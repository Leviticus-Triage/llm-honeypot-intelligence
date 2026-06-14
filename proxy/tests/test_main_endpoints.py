from __future__ import annotations

import importlib
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.responses import JSONResponse, Response
from httpx import ASGITransport

from proxy.src import main as main_mod
from proxy.src import models as models_mod


@pytest.fixture
def mock_upstream_app() -> FastAPI:
    app = FastAPI()

    @app.get("/")
    async def root():
        return Response(content="Ollama is running", media_type="text/plain")

    @app.post("/api/show")
    async def show(_body: dict):
        return JSONResponse({"name": "nomic-embed-text", "status": "ok"})

    @app.post("/api/pull")
    async def pull(body: dict):
        return JSONResponse({"status": "success", "name": body.get("name", "")})

    @app.post("/api/chat")
    async def chat(body: dict):
        model = body.get("model", "")
        messages = body.get("messages", [])
        user_text = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                user_text = msg.get("content", "")
                break
        if body.get("stream") is True:
            return JSONResponse({"error": "stream mode not supported in test upstream"}, status_code=400)
        return JSONResponse(
            {
                "model": model,
                "created_at": "",
                "message": {
                    "role": "assistant",
                    "content": f"mock response to: {user_text}",
                },
                "done": True,
                "done_reason": "stop",
            }
        )

    @app.post("/api/embeddings")
    async def embeddings(body: dict):
        prompt = body.get("prompt", "")
        base = float((sum(ord(c) for c in prompt) % 10) + 1)
        return JSONResponse({"embedding": [base, base / 2, base / 3]})

    @app.post("/api/generate")
    async def generate(body: dict):
        return JSONResponse(
            {
                "model": body.get("model", ""),
                "response": f"generated:{body.get('prompt', '')}",
                "done": True,
            }
        )

    @app.get("/api/tags")
    async def tags():
        return JSONResponse({"models": [{"name": "openchat"}, {"name": "nomic-embed-text"}]})

    return app


@pytest_asyncio.fixture
async def main_client(tmp_path: Path, mock_upstream_app: FastAPI):
    db_path = tmp_path / "cache.db"
    cfg_path = tmp_path / "test_config.yaml"
    cfg_path.write_text(
        "\n".join(
            [
                "ollama_upstream: \"http://upstream.test\"",
                "listen_port: 11435",
                f"cache_db: \"{db_path}\"",
                "embedding_model: \"nomic-embed-text\"",
                "semantic_threshold: 0.85",
                "exploration_rate: 0.0",
                "log_level: \"INFO\"",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    import os

    os.environ["CONFIG_PATH"] = str(cfg_path)
    os.environ["CACHE_DB"] = str(db_path)
    # Cache tests must reach upstream + persist to SQLite; noise filter treats
    # short probes like "hello" as junk and never stores them.
    os.environ["NOISE_FILTER_ENABLED"] = "0"

    reloaded = importlib.reload(main_mod)
    models_mod.DB_PATH = str(db_path)

    upstream_transport = ASGITransport(app=mock_upstream_app)

    async def fake_ensure_model_available():
        return True

    async def fake_compute_embedding(text: str):
        return [float(len(text) or 1.0), 1.0, 0.5]

    original_ensure = reloaded.ensure_model_available
    original_compute = reloaded.compute_embedding
    original_async_client = reloaded.httpx.AsyncClient

    class _RoutedAsyncClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            base_url = kwargs.get("base_url")
            if str(base_url).rstrip("/") == "http://upstream.test":
                kwargs["transport"] = upstream_transport
            super().__init__(*args, **kwargs)

    reloaded.ensure_model_available = fake_ensure_model_available
    reloaded.compute_embedding = fake_compute_embedding
    reloaded.httpx.AsyncClient = _RoutedAsyncClient

    async with reloaded.app.router.lifespan_context(reloaded.app):
        transport = ASGITransport(app=reloaded.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://proxy.test",
        ) as client:
            yield client

    reloaded.ensure_model_available = original_ensure
    reloaded.compute_embedding = original_compute
    reloaded.httpx.AsyncClient = original_async_client


@pytest.mark.asyncio
async def test_proxy_health_returns_200_when_upstream_reachable(main_client: httpx.AsyncClient):
    resp = await main_client.get("/proxy/health")
    assert resp.status_code == 200
    assert resp.json()["upstream_reachable"] is True


@pytest.mark.asyncio
async def test_admin_warmup_returns_ok(main_client: httpx.AsyncClient):
    """Warmup should succeed against the mock upstream without needing
    a real Ollama. The mock returns 200 on /api/chat, so the warmup
    helper must report ok=True and include the resolved model."""
    resp = await main_client.post("/admin/warmup?task=honeypot_response")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list) and len(body) == 1
    entry = body[0]
    assert entry["task"] == "honeypot_response"
    assert entry["ok"] is True
    assert entry["status"] == 200
    assert "elapsed_ms" in entry


@pytest.mark.asyncio
async def test_admin_warmup_all_tasks_when_no_query(main_client: httpx.AsyncClient):
    """POST /admin/warmup without ?task=... should warm every task
    that has a payload defined in _WARMUP_PAYLOADS."""
    resp = await main_client.post("/admin/warmup")
    assert resp.status_code == 200
    body = resp.json()
    tasks = {entry["task"] for entry in body}
    assert {"honeypot_response", "rule_validate",
            "adversarial_critique", "rule_dedupe_embed"}.issubset(tasks)


@pytest.mark.asyncio
async def test_api_chat_routes_through_cache_and_returns_ollama_shape(main_client: httpx.AsyncClient):
    payload = {
        "model": "openchat",
        "stream": False,
        "messages": [{"role": "user", "content": "uname -a"}],
    }

    first = await main_client.post("/api/chat", json=payload)
    assert first.status_code == 200
    first_data = first.json()
    assert first_data["message"]["role"] == "assistant"
    assert "done" in first_data

    second = await main_client.post("/api/chat", json=payload)
    assert second.status_code == 200
    second_data = second.json()
    assert second_data["message"]["content"] == first_data["message"]["content"]

    stats = await main_client.get("/proxy/stats")
    assert stats.status_code == 200
    stats_data = stats.json()
    assert stats_data["database"]["total_prompts"] >= 1
    assert stats_data["database"]["total_responses"] >= 1
    assert stats_data["session_cache"]["hits_exact"] >= 1


@pytest.mark.asyncio
async def test_api_embeddings_forwards_through_router(main_client: httpx.AsyncClient):
    resp = await main_client.post(
        "/api/embeddings",
        json={"model": "nomic-embed-text", "prompt": "abc"},
        headers={"X-LLM-Task": "rule_dedupe_embed"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "embedding" in data
    assert isinstance(data["embedding"], list)


@pytest.mark.asyncio
async def test_api_passthrough_rejects_unknown_paths(main_client: httpx.AsyncClient):
    resp = await main_client.get("/api/../../etc/passwd")
    assert resp.status_code in (400, 404)


@pytest.mark.asyncio
async def test_api_passthrough_allows_tags(main_client: httpx.AsyncClient):
    resp = await main_client.get("/api/tags")
    assert resp.status_code == 200
