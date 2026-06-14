"""
Ollama Proxy - Transparent caching proxy for Ollama API with RL-based response selection.

Sits between honeypots and Ollama, providing:
- Exact + semantic response caching
- Engagement-based response ranking (RL)
- Exploration vs exploitation balance
"""

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager

import httpx
import yaml
from fastapi import FastAPI, HTTPException, Request, Response
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
from .task_router import TaskRouter
from .noise_filter import NoiseFilter

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
task_router: TaskRouter = None
noise_filter: NoiseFilter = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client, cache, cve_engine, task_router, noise_filter

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

    # Init Task Router (multi-LLM routing based on X-LLM-Task header / _task field)
    task_router = TaskRouter(config)

    noise_filter = NoiseFilter()
    logger.info("  Noise filter: %s", "enabled" if noise_filter.enabled else "disabled")

    stats = get_cache_stats()
    logger.info("Cache loaded: %d prompts, %d responses", stats["total_prompts"], stats["total_responses"])

    # Kick off background model warmup. This runs outside the critical path —
    # the proxy is already serving requests while warmup progresses, so a slow
    # first-request cold-load on honeypot_response traffic is converted into a
    # background one-time pay. Disable with PROXY_WARMUP_ON_STARTUP=0.
    if os.environ.get("PROXY_WARMUP_ON_STARTUP", "1") == "1":
        asyncio.create_task(_warmup_models_background())

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
    noise_stats = noise_filter.stats() if noise_filter else {}
    return JSONResponse({
        "proxy": "ollama-proxy",
        "upstream": UPSTREAM,
        "database": db_stats,
        "session_cache": cache_stats,
        "noise_filter": noise_stats,
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
# Admin: model warmup
# ---------------------------------------------------------------------------

# Per-task payload used to trigger an Ollama cold-load. Responses are
# discarded; we only care that the model gets resident in VRAM before real
# traffic arrives. Kept tiny on purpose.
# Cold-load can take longer than the per-task runtime timeout when a VRAM
# swap is required (e.g. switching from llama3.1:8b to another model on a
# 12GB card). Use a generous warmup floor so we don't report false-positive
# timeouts during startup. Runtime timeouts for real traffic are unaffected
# — they come from routing.timeout.
_WARMUP_FLOOR_SECS = 240.0


_WARMUP_PAYLOADS: dict[str, tuple[str, dict]] = {
    "honeypot_response": (
        "/api/chat",
        {
            "stream": False,
            "messages": [
                {"role": "user", "content": "echo warmup"},
            ],
            "options": {"num_predict": 4, "temperature": 0.0},
        },
    ),
    "rule_validate": (
        "/api/chat",
        {
            "stream": False,
            "messages": [
                {"role": "user", "content": "Respond with {}"},
            ],
            "options": {"num_predict": 4, "temperature": 0.0, "format": "json"},
        },
    ),
    "adversarial_critique": (
        "/api/chat",
        {
            "stream": False,
            "messages": [
                {"role": "user", "content": "Respond with {}"},
            ],
            "options": {"num_predict": 4, "temperature": 0.0, "format": "json"},
        },
    ),
    "rule_dedupe_embed": (
        "/api/embeddings",
        {"prompt": "warmup"},
    ),
}


async def _warmup_one(task: str) -> dict:
    """Fire a single minimal request at the model assigned to ``task``."""
    if not task_router:
        return {"task": task, "ok": False, "reason": "router_not_initialised"}
    if task not in _WARMUP_PAYLOADS:
        return {"task": task, "ok": False, "reason": "no_warmup_payload_defined"}

    path, body_template = _WARMUP_PAYLOADS[task]
    body = {**body_template}
    # Spoof the header on the local apply() call so the router treats it as
    # explicit (triggers model override + option merge).
    fake_headers = {"x-llm-task": task}
    routing = task_router.apply(fake_headers, body)

    timeout = httpx.Timeout(
        connect=10.0,
        read=max(_WARMUP_FLOOR_SECS, float(routing.timeout or _WARMUP_FLOOR_SECS)),
        write=10.0,
        pool=10.0,
    )
    t0 = time.time()
    try:
        resp = await http_client.post(path, json=body, timeout=timeout)
        elapsed = (time.time() - t0) * 1000
        ok = 200 <= resp.status_code < 300
        return {
            "task": task,
            "model": routing.resolved_model,
            "ok": ok,
            "status": resp.status_code,
            "elapsed_ms": round(elapsed, 1),
        }
    except Exception:
        logger.exception("Warmup failed for task %s", task)
        return {
            "task": task,
            "model": routing.resolved_model,
            "ok": False,
            "reason": "upstream_unavailable",
        }


async def _warmup_models_background() -> None:
    """
    Warm only the primary honeypot traffic model on startup.

    Rationale: Ollama serialises all requests on a single GPU. Warming a
    large model (e.g. llama3.1:8b, 96s cold-load) at startup would block
    honeypot_response traffic and cause 30s timeout 502s on live
    attackers — the exact failure mode #2 just introduced detection for.
    Secondary models (rule_validate, adversarial_critique,
    rule_dedupe_embed) are warmed lazily on their first real use, and
    can be prewarmed on demand via POST /admin/warmup?task=<name>.
    """
    await asyncio.sleep(5.0)
    primary = "honeypot_response"
    logger.info("Warmup: starting background warmup for primary task=%s", primary)
    result = await _warmup_one(primary)
    if result.get("ok"):
        logger.info("Warmup: %s ok model=%s elapsed=%sms",
                    primary, result.get("model"), result.get("elapsed_ms"))
    else:
        logger.warning("Warmup: %s failed model=%s reason=%s",
                       primary, result.get("model"),
                       result.get("reason") or result.get("status"))


@app.post("/admin/warmup")
async def admin_warmup(request: Request):
    """
    Trigger model warmup on demand.

    Query params:
      ?task=<name>  — warm a single task (e.g. honeypot_response)
      (omitted)     — warm all tasks that have a warmup payload

    Returns a JSON array with one object per task showing resolved model,
    elapsed_ms, and ok/reason. This endpoint is intentionally non-auth'd
    but lives under /admin/* so a reverse proxy can ACL it.
    """
    params = dict(request.query_params)
    task = params.get("task")
    if task:
        result = await _warmup_one(task)
        return JSONResponse([result])
    results = []
    for t in _WARMUP_PAYLOADS:
        results.append(await _warmup_one(t))
    return JSONResponse(results)


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

    # Multi-LLM Task Routing: resolve task -> model + option defaults.
    # Mutates body in place; no-op if caller did not specify a task.
    routing = task_router.apply(request.headers, body) if task_router else None

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

    # For non-honeypot tasks (rule_generate, rule_validate, ...) bypass the
    # cache entirely: rules are per-session, deterministic, and must not leak
    # across callers. Forward straight upstream with per-task timeout.
    if routing and routing.explicit and routing.task != "honeypot_response":
        return await _forward_direct("/api/chat", body, routing)

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

    # Noise ingress filter — short-circuit known scanners before LLM call
    if noise_filter and prompt_text:
        short, canned, reason = noise_filter.check(src_ip, prompt_text)
        if short:
            elapsed = (time.time() - t0) * 1000
            logger.info(
                "NOISE SHORTCIRCUIT [%.0fms] reason=%s ip=%s",
                elapsed, reason, src_ip[:15],
            )
            return _build_chat_response(canned, model)

    # Step 3: Cache miss - forward to upstream Ollama.
    # Honour the task-specific read timeout from the router (e.g. 30s for
    # honeypot_response); fall back to the shared client default (300s) so
    # rule_validate / adversarial_critique / embeddings keep their long
    # read window needed for cold-load recovery.
    cache._stats["misses"] += 1
    post_kwargs: dict = {"json": {**body, "stream": False}}
    if routing and routing.timeout:
        post_kwargs["timeout"] = httpx.Timeout(
            connect=10.0,
            read=float(routing.timeout),
            write=10.0,
            pool=10.0,
        )
    try:
        resp = await http_client.post("/api/chat", **post_kwargs)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPStatusError as e:
        logger.error("Upstream error: %s %s", e.response.status_code, e.response.text[:200])
        return JSONResponse(
            status_code=e.response.status_code,
            content={"error": f"Upstream Ollama error: {e.response.status_code}"},
        )
    except Exception:
        logger.exception("Upstream connection failed for /api/chat")
        # Fallback: try cache even during exploration if upstream is down
        cached = cache.exact_lookup(prompt_hash, cve_meta=cve_meta)
        if cached:
            logger.info("FALLBACK to cache (upstream down)")
            return _build_chat_response(cached["response_text"], model)
        return JSONResponse(
            status_code=502,
            content={"error": "upstream unavailable"},
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
    """Passthrough /api/generate with task routing (no cache)."""
    body = await request.json()
    routing = task_router.apply(request.headers, body) if task_router else None
    return await _forward_direct("/api/generate", body, routing)


async def _forward_direct(path: str, body: dict, routing=None) -> JSONResponse:
    """Forward a request straight to Ollama, honouring the task-specific timeout."""
    # `stream: False` is only meaningful for chat/generate. The embeddings
    # endpoint has no stream concept; Ollama accepts extra fields in most
    # versions, but keeping the body clean avoids unexpected side effects
    # if the upstream is swapped for a stricter OpenAI-compatible server.
    if path in ("/api/chat", "/api/generate"):
        body = {**body, "stream": False}
    timeout = httpx.Timeout(
        connect=10.0,
        read=float(routing.timeout) if routing and routing.timeout else 300.0,
        write=10.0,
        pool=10.0,
    )
    try:
        resp = await http_client.post(path, json=body, timeout=timeout)
        try:
            content = resp.json()
        except Exception:
            content = {"error": "upstream returned non-JSON", "raw": resp.text[:500]}
        return JSONResponse(status_code=resp.status_code, content=content)
    except httpx.HTTPStatusError as e:
        logger.error("Upstream error on %s: %s", path, e.response.status_code)
        return JSONResponse(
            status_code=e.response.status_code,
            content={"error": f"Upstream Ollama error: {e.response.status_code}"},
        )
    except httpx.TimeoutException:
        logger.exception("Upstream timeout on %s", path)
        return JSONResponse(status_code=504, content={"error": "upstream timeout"})
    except Exception:
        logger.exception("Upstream connection failed on %s", path)
        return JSONResponse(status_code=502, content={"error": "upstream unavailable"})


@app.post("/api/embeddings")
async def api_embeddings(request: Request):
    """
    Passthrough /api/embeddings with task routing.

    Router is applied for every request so that keep_alive and the
    embedding model can be centrally configured. For the typical
    ``rule_dedupe_embed`` caller, this also consolidates timeout and
    resident-model policy with /api/chat. Callers that want the legacy
    raw passthrough can simply omit the X-LLM-Task header AND send no
    ``messages`` field — apply() is a no-op on chat-specific logic for
    embedding bodies (no ``messages`` means the system-anchor branch is
    skipped automatically).
    """
    body = await request.json()
    routing = task_router.apply(request.headers, body) if task_router else None
    return await _forward_direct("/api/embeddings", body, routing)


# Fixed upstream paths for allowlisted Ollama /api/* segments (no user input in URL).
_OLLAMA_UPSTREAM_BY_SEGMENT: dict[str, str] = {
    "bearer": "/api/bearer",
    "chat": "/api/chat",
    "copy": "/api/copy",
    "create": "/api/create",
    "delete": "/api/delete",
    "embed": "/api/embed",
    "embeddings": "/api/embeddings",
    "generate": "/api/generate",
    "ps": "/api/ps",
    "pull": "/api/pull",
    "push": "/api/push",
    "show": "/api/show",
    "tags": "/api/tags",
    "version": "/api/version",
}


def _resolve_ollama_upstream(segment: str) -> str:
    if not segment or segment != segment.strip() or "/" in segment or ".." in segment:
        raise HTTPException(status_code=400, detail="invalid api path")
    upstream = _OLLAMA_UPSTREAM_BY_SEGMENT.get(segment)
    if upstream is None:
        raise HTTPException(status_code=404, detail="api path not allowed")
    return upstream


@app.api_route("/api/{segment}", methods=["GET", "POST", "PUT", "DELETE"])
async def api_passthrough(request: Request, segment: str):
    """Passthrough for allowlisted single-segment Ollama /api/* endpoints only."""
    upstream = _resolve_ollama_upstream(segment)
    method = request.method
    try:
        if method in ("POST", "PUT"):
            body = await request.body()
            resp = await http_client.request(
                method,
                upstream,
                content=body,
                headers={"Content-Type": request.headers.get("Content-Type", "application/json")},
            )
        else:
            resp = await http_client.request(method, upstream)
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type=resp.headers.get("content-type"),
        )
    except Exception:
        logger.exception("Upstream passthrough failed for %s", upstream)
        return JSONResponse(status_code=502, content={"error": "upstream unavailable"})
