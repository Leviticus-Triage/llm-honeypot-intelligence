# tpot-cloud-deploy — T-Pot HIVE on OTC ECS (ohne Proxmox)

Deploy-Paket für die **zweite Cloud-VM**: offizielles [telekom-security/tpotce](https://github.com/telekom-security/tpotce) plus Custom-Mods aus [llm-honeypot-intelligence](https://github.com/Leviticus-Triage/llm-honeypot-intelligence).

Ersetzt die verlorene Homelab-VM **400** (`192.168.2.22`). **Proxmox ist tot** — nicht mehr Teil des Plans.

## Zwei-Server-Architektur

| Server | Rolle | Status |
|--------|-------|--------|
| **ai-cloud** `80.158.17.220` | Ollama, ollama-proxy, SpiderFoot, WireGuard | ✅ läuft |
| **ai-tpot** (neue ECS) | T-Pot HIVE, ES, Kibana, Honeypots | ⏳ vorbereitet |

```
Internet ──→ T-Pot ECS (tpotce)
                 ├─ Beelzebub/Galah ──→ http://10.164.18.68:11435 (ai-cloud proxy)
                 └─ Elasticsearch ←── ai-cloud (rl-scorer, rule-generator, …)
```

## Was dieses Paket enthält

| Datei | Zweck |
|-------|--------|
| `install.sh` | Host-Prep: Swap/zram, tpotce clone, UFW-Basis |
| `deploy-custom.sh` | Custom-Overrides, Logstash-Noise-Filter, Blocklist-Timer |
| `wire-llm.sh` | `BEELZEBUB_*` / `GALAH_*` → ai-cloud Proxy |
| `connect-ai-stack.sh` | Von Blade: beide Server verdrahten |
| `remote-deploy.sh` | rsync Paket auf neue ECS |
| `verify.sh` | Health-Checks |
| `custom/` | `docker-compose.override.yml`, `noise_ips.csv`, Logstash-Filter |
| `docs/DAY1-CHECKLIST.md` | Schritt-für-Schritt wenn ECS da ist |

## Heute vorbereiten (ohne zweite ECS)

```bash
cd /mnt/docker-ssd/cursor-Projekts/Sec-Systems

# Paket lokal prüfen
ls tpot-cloud-deploy/

# Optional: cloud.env mit Platzhaltern anlegen
cp tpot-cloud-deploy/cloud.env.example tpot-cloud-deploy/cloud.env.local-prep
```

## Morgen: ECS anlegen + deployen

```bash
# 1) Bundle auf neue VM
./tpot-cloud-deploy/remote-deploy.sh ubuntu@NEUE.IP --install-only

# 2) Auf der VM: offizieller T-Pot-Installer
ssh ai-tpot
cd ~/tpotce && sudo ./install.sh

# 3) Custom + LLM
cd ~/tpot-cloud-deploy && sudo ./deploy-custom.sh && sudo ./wire-llm.sh

# 4) Von Blade: ai-cloud anbinden
./tpot-cloud-deploy/connect-ai-stack.sh ai-tpot ai-cloud
```

Vollständige Checkliste: **[docs/DAY1-CHECKLIST.md](docs/DAY1-CHECKLIST.md)**

## cloud.env (wichtigste Variablen)

| Variable | Beispiel |
|----------|----------|
| `TPOT_PUBLIC_IP` | Öffentliche IP der neuen ECS |
| `AI_STACK_PRIVATE_IP` | `10.164.18.68` (ai-cloud VPC) |
| `AI_PROXY_URL` | `http://10.164.18.68:11435` |
| `ES_URL` | `https://NEUE.IP:64297/es` (nach tpotce install) |

## Verwandte Pakete

- **AI-Stack:** `../ai-workstation-cloud/` (bereits auf ai-cloud)
- **Proxy-Quellcode:** `../llm-honeypot-intelligence/proxy/`
- **GitHub Projekt-Doku:** [KI-test-dev](https://github.com/dgskjeuj/KI-test-dev)
