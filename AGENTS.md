# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

LLM Honeypot Intelligence — a Python/FastAPI platform under `proxy/`. All custom code lives in `proxy/src/`, tests in `proxy/tests/`. No monorepo; one product.

### Standard commands

| Action | Command | Notes |
|--------|---------|-------|
| Lint | `ruff check proxy/` | Config in `pyproject.toml`; CI pins `ruff==0.15.11` |
| Test | `pytest proxy/tests/ -v` | Set `CONFIG_PATH` and `CACHE_DB` env vars (see below) |
| Run proxy (dev) | `uvicorn src.main:app --host 0.0.0.0 --port 11435 --reload` | Run from `proxy/` directory |

### Environment variables for local dev

The proxy reads `CONFIG_PATH` (defaults to `/app/config.yaml`) and `CACHE_DB` (defaults to `/data/ollama-proxy/cache.db`). For local runs outside Docker, override them:

```bash
export CONFIG_PATH=/workspace/proxy/config.yaml
export CACHE_DB=/tmp/ollama-proxy/cache.db
export PROXY_WARMUP_ON_STARTUP=0   # skip model warmup when no Ollama is running
```

Create the cache directory first: `mkdir -p /tmp/ollama-proxy`.

### Non-obvious caveats

- **No Ollama required for dev/test.** The proxy starts and serves health/stats/CVE endpoints without an upstream Ollama server. The health endpoint returns `"status": "degraded"` (not an error); chat/generate endpoints return a clean JSON error. All 25 unit tests pass without Ollama.
- **`$HOME/.local/bin` must be on PATH** for `ruff`, `pytest`, `uvicorn` after `pip install --user`. The update script handles this, but if running interactively add `export PATH="$HOME/.local/bin:$PATH"`.
- **Config files in `proxy/`.** The example files (`config.yaml.example`, `.env.example`) must be copied to `config.yaml` and `.env` before Docker-based runs. For local dev, only `config.yaml` is needed (the `.env` file is for Docker Compose).
- **Tests need the `proxy/` parent on `sys.path`.** The `conftest.py` handles this via path manipulation; just run `pytest proxy/tests/` from the repo root.
