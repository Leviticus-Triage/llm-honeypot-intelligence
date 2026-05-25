# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

LLM Honeypot Intelligence — a Python 3.12 FastAPI application in `proxy/src/`. No frontend, no Node.js. See `README.md` for full architecture.

### Running commands

- **Lint:** `ruff check proxy/` (CI uses `ruff==0.15.11`)
- **Test:** `pytest proxy/tests/ -v` (25 unit tests, all mock external services)
- **Dev server:** `CACHE_DB=/data/ollama-proxy/cache.db CONFIG_PATH=/workspace/proxy/config.yaml PYTHONPATH=/workspace uvicorn proxy.src.main:app --host 0.0.0.0 --port 11435 --reload`

### Gotchas

- `ruff` and `pytest` install to `~/.local/bin`; ensure `PATH` includes it (`export PATH="$HOME/.local/bin:$PATH"`).
- The SQLite cache directory `/data/ollama-proxy/` must exist and be writable before starting the server. Create it with `sudo mkdir -p /data/ollama-proxy && sudo chmod 777 /data/ollama-proxy`.
- The dev server starts in `degraded` status because Ollama (upstream LLM) is not available — this is expected in cloud agent environments. All proxy endpoints still respond normally.
- Config file: copy `proxy/config.yaml.example` → `proxy/config.yaml` for local dev. The `CONFIG_PATH` env var overrides the default `/app/config.yaml`.
- `CACHE_DB` env var must be set before import if you want a non-default SQLite path; `models.py` reads it at module load time.
- External services (Elasticsearch, Ollama, T-Pot) are **not required** for lint, tests, or basic server startup.
