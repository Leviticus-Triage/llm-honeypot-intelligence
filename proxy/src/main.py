"""
Ollama Proxy - Transparent caching proxy for Ollama API with RL-based response selection.

Sits between honeypots and Ollama, providing:
- Exact + semantic response caching
- Engagement-based response ranking (RL)
- Exploration vs exploitation balance
"""

import json
import logging
import os
import time
from contextlib import asynccontextmanager

import httpx
import yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from .cache import HybridCache, compute_prompt_hash, extract_user_prompt
from .cve_engine import CVEEngine
from .embeddings import (
    compute_embedding,
    configure as configure_embeddings,
    ensure_model_available,
    shutdown as shutdown_embeddings,
)
from .models import get_cache_stats, init_db

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CONFIG_PATH = os.environ.get("CONFIG_PATH", "/app/config.yaml")

def load_config() -> dict:
    defaults = {
        "ollama_upstream": "http://localhost:11434",
        "listen_port": 11435,
        "cache_db": "/data/ollama-proxy/cache.db",
        "embedding_model": "nomic-embed-text",
        "semantic_threshold": 0.85,
        "exploration_rate": 0.15,
        "log_level": "INFO",
    }
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            file_cfg = yaml.safe_load(f) or {}
        defaults.update(file_cfg)
    # Environment overrides
    for key in defaults:
        env_val = os.environ.get(f"PROXY_{key.upper()}")
        if env_val is not None:
            if isinstance(defaults[key], float):
                defaults[key] = float(env_val)
            elif isinstance(defaults[key], int):
                defaults[key] = int(env_val)
            else:
                defaults[key] = env_val
    return defaults


config = load_config()

logging.basicConfig(
    level=getattr(logging, config["log_level"].upper(), logging.INFO),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("ollama-proxy")

# Set DB path from config
os.environ["CACHE_DB"] = config["cache_db"]

# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------

UPSTREAM = config["ollama_upstream"].rstrip("/")
http_client: httpx.AsyncClient = None
cache: HybridCache = None
cve_engine: CVEEngine = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client, cache, cve_engine

    logger.info("Starting Ollama Proxy")
    logger.info("  Upstream: %s", UPSTREAM)
    logger.info("  Cache DB: %s", config['cache_db'])
    logger.info("  Semantic threshold: %s", config['semantic_threshold'])
    logger.info("  Exploration rate: %s", config['exploration_rate'])

    # Init DB
    init_db()

    # Init HTTP client for upstream Ollama
    # read=300s because Ollama may need to cold-load a model into GPU RAM
    http_client = httpx.AsyncClient(
        base_url=UPSTREAM,
        timeout=httpx.Timeout(connect=10.0, read=300.0, write=10.0, pool=10.0),
    )

    # Configure embeddings
    configure_embeddings(UPSTREAM, config["embedding_model"])

    # Init cache
    cache = HybridCache(
        semantic_threshold=config["semantic_threshold"],
        exploration_rate=config["exploration_rate"],
        embed_fn=compute_embedding,
    )

    # Try to ensure embedding model is available (non-blocking)
    try:
        available = await ensure_model_available()
        if not available:
            logger.warning(
                "Embedding model not available - semantic cache disabled until pulled"
            )
            cache.embed_fn = None
    except Exception as e:
        logger.warning("Could not check embedding model: %s", e)
        cache.embed_fn = None

    # Init CVE Engine
    cve_enabled = config.get("cve_engine_enabled", True)
    cve_engine = CVEEngine(enabled=cve_enabled)
    from .cve_templates import ALL_CVE_PROFILES
    logger.info("  CVE Engine: %s (%d profiles loaded)",
                "enabled" if cve_enabled else "disabled", len(ALL_CVE_PROFILES))

    stats = get_cache_stats()
    logger.info("Cache loaded: %d prompts, %d responses", stats["total_prompts"], stats["total_responses"])

    yield

    # Shutdown
    await http_client.aclose()
    await shutdown_embeddings()
    logger.info("Ollama Proxy stopped")


app = FastAPI(title="Ollama Proxy", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Health / Stats endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    """Mimic Ollama's root endpoint."""
    return Response(content="Ollama is running", media_type="text/plain")


@app.get("/proxy/stats")
async def proxy_stats():
    """Return proxy cache statistics."""
    db_stats = get_cache_stats()
    cache_stats = cache.stats if cache else {}
    return JSONResponse({
        "proxy": "ollama-proxy",
        "upstream": UPSTREAM,
        "database": db_stats,
        "session_cache": cache_stats,
        "config": {
            "semantic_threshold": config["semantic_threshold"],
            "exploration_rate": config["exploration_rate"],
            "embedding_model": config["embedding_model"],
        },
    })


@app.get("/proxy/health")
async def health():
    """Health check."""
    try:
        resp = await http_client.get("/")
        upstream_ok = resp.status_code == 200
    except Exception:
        upstream_ok = False
    return JSONResponse({
        "status": "ok" if upstream_ok else "degraded",
        "upstream_reachable": upstream_ok,
    })


@app.get("/proxy/rules")
async def rules_status():
    """Return latest rule generation status."""
    import json as _json
    from pathlib import Path
    rules_dir = Path(os.environ.get("RULES_DIR", "/data/ollama-proxy/generated-rules"))
    summary_path = rules_dir / "latest_summary.json"
    manifest_path = rules_dir / "manifest.json"
    if summary_path.exists():
        with open(summary_path) as f:
            return JSONResponse(_json.load(f))
    elif manifest_path.exists():
        with open(manifest_path) as f:
            return JSONResponse(_json.load(f))
    return JSONResponse({"status": "no_rules_generated_yet"})


@app.get("/proxy/threats")
async def threats_status():
    """Return latest ML heuristic detection results."""
    import json as _json
    from pathlib import Path
    threat_dir = Path(os.environ.get("THREAT_DIR", "/data/ollama-proxy/threat-intel"))
    summary_path = threat_dir / "threat_summary.json"
    if summary_path.exists():
        with open(summary_path) as f:
            return JSONResponse(_json.load(f))
    return JSONResponse({"status": "no_analysis_yet"})


@app.get("/proxy/threats/alerts")
async def threats_alerts():
    """Return current predictive alerts."""
    import json as _json
    from pathlib import Path
    threat_dir = Path(os.environ.get("THREAT_DIR", "/data/ollama-proxy/threat-intel"))
    alerts_path = threat_dir / "alerts.json"
    if alerts_path.exists():
        with open(alerts_path) as f:
            return JSONResponse(_json.load(f))
    return JSONResponse([])


@app.get("/proxy/threats/reputation")
async def threats_reputation():
    """Return IP reputation database."""
    import json as _json
    from pathlib import Path
    threat_dir = Path(os.environ.get("THREAT_DIR", "/data/ollama-proxy/threat-intel"))
    rep_path = threat_dir / "ip_reputation.json"
    if rep_path.exists():
        with open(rep_path) as f:
            return JSONResponse(_json.load(f))
    return JSONResponse({})


@app.get("/proxy/threats/campaigns")
async def threats_campaigns():
    """Return identified attack campaigns."""
    import json as _json
    from pathlib import Path
    threat_dir = Path(os.environ.get("THREAT_DIR", "/data/ollama-proxy/threat-intel"))
    camp_path = threat_dir / "campaigns.json"
    if camp_path.exists():
        with open(camp_path) as f:
            return JSONResponse(_json.load(f))
    return JSONResponse([])


# ---------------------------------------------------------------------------
# CVE Engine endpoints
# ---------------------------------------------------------------------------

@app.get("/proxy/cve/stats")
async def cve_stats():
    """Return CVE engine statistics."""
    if not cve_engine:
        return JSONResponse({"status": "not_initialized"})
    from .cve_templates import ALL_CVE_PROFILES
    return JSONResponse({
        "enabled": cve_engine.enabled,
        "profiles_loaded": len(ALL_CVE_PROFILES),
        "stats": cve_engine.stats,
    })


@app.get("/proxy/cve/sessions")
async def cve_sessions():
    """Return active CVE sessions."""
    if not cve_engine:
        return JSONResponse([])
    return JSONResponse(cve_engine.get_all_sessions())


@app.get("/proxy/cve/profiles")
async def cve_profiles():
    """Return summary of all loaded CVE profiles."""
    from .cve_templates import ALL_CVE_PROFILES
    return JSONResponse([
        {
            "cve_id": p.cve_id,
            "severity": p.severity,
            "cvss_score": p.cvss_score,
            "vendor": p.vendor,
            "product": p.product,
            "protocol": p.protocol,
            "description": p.description,
            "mitre_techniques": p.mitre_techniques,
        }
        for p in ALL_CVE_PROFILES
    ])


# ---------------------------------------------------------------------------
# Ollama API: /api/chat (main cached endpoint)
# ---------------------------------------------------------------------------

@app.post("/api/chat")
async def api_chat(request: Request):
    """
    Handle Ollama /api/chat requests with caching and CVE prompt enhancement.

    Flow:
    1. Parse request, extract IP
    2. CVE Engine: enhance system prompt with CVE-specific context
    3. Compute hash on enhanced messages
    4. Check exact cache -> if hit, return cached (weighted by engagement score)
    5. Check semantic cache -> if hit, return cached
    6. Forward to upstream Ollama
    7. Cache response
    8. Return to client
    """
    body = await request.json()
    messages = body.get("messages", [])
    model = body.get("model", "")
    stream = body.get("stream", False)

    # Extract source IP for RL tracking
    src_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if not src_ip:
        src_ip = request.client.host if request.client else ""

    # We only cache non-streaming requests (honeypots typically don't stream)
    # For streaming, pass through directly
    if stream:
        return await _proxy_stream(request, body)

    # CVE Engine: enhance the system prompt with CVE-specific context
    cve_profile = None
    if cve_engine and cve_engine.enabled:
        messages, cve_profile = cve_engine.enhance_messages(messages, src_ip)
        if cve_profile:
            body = {**body, "messages": messages}

    prompt_hash = compute_prompt_hash(messages, model)
    prompt_text = extract_user_prompt(messages)
    t0 = time.time()

    # Build CVE metadata for serve_log tagging
    cve_meta = {}
    if cve_profile:
        cve_meta = {
            "cve_id": cve_profile.cve_id,
            "cve_vendor": cve_profile.vendor,
            "cve_product": cve_profile.product,
        }

    # Exploration: occasionally bypass cache to generate fresh responses
    if not cache.should_explore():
        # Step 1: Exact cache lookup
        cached = cache.exact_lookup(prompt_hash, src_ip=src_ip, cve_meta=cve_meta)
        if cached:
            cache._stats["hits_exact"] += 1
            elapsed = (time.time() - t0) * 1000
            cve_tag = f" cve={cve_profile.cve_id}" if cve_profile else ""
            logger.info(
                "EXACT HIT [%.0fms] hash=%s resp_id=%d score=%.2f ip=%s%s",
                elapsed,
                prompt_hash[:12],
                cached["response_id"],
                cached.get("engagement_score", 0),
                src_ip[:15],
                cve_tag,
            )
            return _build_chat_response(cached["response_text"], model)

        # Step 2: Semantic cache lookup
        if prompt_text and cache.embed_fn:
            cached = await cache.semantic_lookup(prompt_text, src_ip=src_ip, cve_meta=cve_meta)
            if cached:
                cache._stats["hits_semantic"] += 1
                elapsed = (time.time() - t0) * 1000
                cve_tag = f" cve={cve_profile.cve_id}" if cve_profile else ""
                logger.info(
                    "SEMANTIC HIT [%.0fms] resp_id=%d score=%.2f ip=%s%s",
                    elapsed,
                    cached["response_id"],
                    cached.get("engagement_score", 0),
                    src_ip[:15],
                    cve_tag,
                )
                return _build_chat_response(cached["response_text"], model)
    else:
        logger.debug("EXPLORE: bypassing cache for fresh generation")

    # Step 3: Cache miss - forward to upstream Ollama
    cache._stats["misses"] += 1
    try:
        resp = await http_client.post(
            "/api/chat",
            json={**body, "stream": False},
        )
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPStatusError as e:
        logger.error("Upstream error: %s %s", e.response.status_code, e.response.text[:200])
        return JSONResponse(
            status_code=e.response.status_code,
            content={"error": f"Upstream Ollama error: {e.response.status_code}"},
        )
    except Exception as e:
        logger.error("Upstream connection failed: %s", e)
        # Fallback: try cache even during exploration if upstream is down
        cached = cache.exact_lookup(prompt_hash, cve_meta=cve_meta)
        if cached:
            logger.info("FALLBACK to cache (upstream down)")
            return _build_chat_response(cached["response_text"], model)
        return JSONResponse(
            status_code=502,
            content={"error": f"Upstream Ollama unavailable: {str(e)}"},
        )

    # Extract response text
    response_text = ""
    if "message" in data:
        response_text = data["message"].get("content", "")

    # Step 4: Cache the response
    elapsed = (time.time() - t0) * 1000
    if response_text:
        resp_id = await cache.store(
            prompt_hash, prompt_text, model, response_text,
            src_ip=src_ip, cve_meta=cve_meta,
        )
        cve_tag = f" cve={cve_profile.cve_id}" if cve_profile else ""
        logger.info(
            "MISS -> CACHED [%.0fms] hash=%s resp_id=%d len=%d%s",
            elapsed,
            prompt_hash[:12],
            resp_id,
            len(response_text),
            cve_tag,
        )
    else:
        logger.warning("Empty response from Ollama, not caching")

    return JSONResponse(content=data)


async def _proxy_stream(request: Request, body: dict):
    """Pass through streaming requests without caching."""
    async def stream_generator():
        async with http_client.stream(
            "POST", "/api/chat", json=body
        ) as resp:
            async for chunk in resp.aiter_bytes():
                yield chunk

    return StreamingResponse(stream_generator(), media_type="application/x-ndjson")


def _build_chat_response(content: str, model: str) -> JSONResponse:
    """Build an Ollama-compatible /api/chat response from cached content."""
    return JSONResponse(content={
        "model": model,
        "created_at": "",
        "message": {
            "role": "assistant",
            "content": content,
        },
        "done": True,
        "done_reason": "stop",
        "total_duration": 0,
        "load_duration": 0,
        "prompt_eval_count": 0,
        "prompt_eval_duration": 0,
        "eval_count": 0,
        "eval_duration": 0,
    })


# ---------------------------------------------------------------------------
# Ollama API: passthrough for all other endpoints
# ---------------------------------------------------------------------------

@app.post("/api/generate")
async def api_generate(request: Request):
    """Passthrough /api/generate - could be cached in future."""
    body = await request.json()
    try:
        resp = await http_client.post("/api/generate", json={**body, "stream": False})
        return JSONResponse(status_code=resp.status_code, content=resp.json())
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": str(e)})


@app.post("/api/embeddings")
async def api_embeddings(request: Request):
    """Passthrough /api/embeddings."""
    body = await request.json()
    try:
        resp = await http_client.post("/api/embeddings", json=body)
        return JSONResponse(status_code=resp.status_code, content=resp.json())
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": str(e)})


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def api_passthrough(request: Request, path: str):
    """Passthrough for any other /api/* endpoints."""
    method = request.method
    try:
        if method in ("POST", "PUT"):
            body = await request.body()
            resp = await http_client.request(
                method, f"/api/{path}",
                content=body,
                headers={"Content-Type": request.headers.get("Content-Type", "application/json")},
            )
        else:
            resp = await http_client.request(method, f"/api/{path}")
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type=resp.headers.get("content-type"),
        )
    except Exception as e:
        return JSONResponse(status_code=502, content={"error": str(e)})
