# Kibana dashboard exports

NDJSON exports for the LLM Honeypot Intelligence platform. Import via Kibana **Stack Management → Saved Objects → Import**.

| File | Kiosk panel |
|------|-------------|
| `llm-honeypot-intelligence.ndjson` | LLM Honeypot Intelligence dashboard |
| `cve-dashboard.ndjson` | CVE honeypot sessions |
| `c2-dashboard.ndjson` | C2 & covert channels |

**Live public view** (sanitized screenshots, no Kibana access): [https://exodus-hensen.site/kiosk/](https://exodus-hensen.site/kiosk/)

See [docs/LIVE-KIOSK.md](../docs/LIVE-KIOSK.md) for the capture pipeline and embed snippet.

## `setup-attack-class.sh`

Requires Elasticsearch credentials via environment variables or a local
`dashboards/.env.local` file (copy from [`.env.example`](.env.example); never commit
real credentials).
