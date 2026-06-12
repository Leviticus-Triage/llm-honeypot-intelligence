# Live threat kiosk (public read-only view)

**URL:** [https://exodus-hensen.site/kiosk/](https://exodus-hensen.site/kiosk/)

Near-live, **read-only** showcase of the production honeypot — attack map plus three Kibana dashboards — without exposing T-Pot, Elasticsearch, Kibana, internal IPs, or stack fingerprints. Suitable for LinkedIn posts, portfolio pages, conference demos, and GitHub visitors who want to *see* the platform in action before cloning the repo.

## What you see

| Panel | Source dashboard | Content |
|-------|------------------|---------|
| **Global Attack Map** | T-Pot world map | Live attack origins and volume |
| **LLM Honeypot Intelligence** | `llm-honeypot-intelligence` | RL scores, cache hits, deception metrics |
| **CVE Honeypot Sessions** | CVE dashboard | Profile hits across 34 CVE templates |
| **C2 & Covert Channels** | C2 dashboard | Beaconing, DNS tunneling, behavioral indicators |

The viewer auto-refreshes screenshots every few seconds and shows rolling counters (attacks per 1m / 1h / 24h) from sanitized `meta.json` metadata.

## Security model

| Layer | Public | Hidden |
|-------|--------|--------|
| Capture agent | Outbound LAN only (screenshots) | No inbound access to honeypot or ES |
| Published files | Static PNG + HTML + JSON | No APIs, auth, or backend |
| Edge (nginx) | `/kiosk/` static route, strict CSP | Origin host, Proxmox, internal topology |
| Sanitization | Generic labels, no URL bar, no hostnames | Beelzebub/Galah/Ollama/T-Pot branding stripped |

This is **not** a live iframe into Kibana. Playwright captures viewport-only PNGs on a private schedule; only those sanitized images are published.

## Embed on your site

Same-origin iframe (works on `exodus-hensen.site`; other sites may need `frame-ancestors` updates):

```html
<section style="width:100%;max-width:1280px;margin:2rem auto;">
  <h2>Live Threat Intelligence</h2>
  <p>Read-only attack map and detection dashboards — refreshed every minute.</p>
  <iframe
    src="https://exodus-hensen.site/kiosk/"
    title="Live Threat Intelligence Kiosk"
    width="100%"
    height="920"
    style="border:0;border-radius:12px;background:#07090d;"
    loading="lazy"
    referrerpolicy="no-referrer"
    sandbox="allow-scripts"
  ></iframe>
</section>
```

Copy-paste variant: [docs/embed/kiosk-embed.html](embed/kiosk-embed.html)

## Relation to this repository

| Artifact | Location |
|----------|----------|
| Kibana dashboard exports | `dashboards/*.ndjson` |
| Live public viewer | Hosted at [exodus-hensen.site/kiosk/](https://exodus-hensen.site/kiosk/) |
| Capture/publish stack | Operated separately (Playwright + rsync); not required to consume rules or deploy the proxy |

To deploy your own kiosk, you need a T-Pot instance with the dashboards imported, a capture host with LAN access to Kibana, and a static web origin. The capture pipeline lives in the parent Sec-Systems monorepo under `kiosk/` (not shipped in this rules/proxy repo).

## Quick links

- **Open kiosk:** [https://exodus-hensen.site/kiosk/](https://exodus-hensen.site/kiosk/)
- **Rules feed (6h sync):** [rules/latest_summary.json](../rules/latest_summary.json)
- **Dashboard imports:** [dashboards/](../dashboards/)
