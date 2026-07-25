# Cloud deployment — LLM Honeypot Intelligence (OTC, ohne Proxmox)

**Stand:** 2026-07-06

Homelab Proxmox + VM 400 (`192.168.2.22`) sind seit **2026-07-25** wieder **primär** (siehe `Sec-Systems/docs/TPOT-PROXMOX-REBUILD-2026-07.md`). OTC bleibt **optionaler Standby**-Pfad: zwei ECS-Instanzen in derselben VPC.

## Architektur

| ECS | Rolle | Paket | Status |
|-----|-------|-------|--------|
| **ai-cloud** `80.158.17.220` | Ollama, ollama-proxy, SpiderFoot, WireGuard | `Sec-Systems/ai-workstation-cloud/` | ✅ Live |
| **ai-tpot** (neue ECS) | T-Pot HIVE ([tpotce](https://github.com/telekom-security/tpotce)) | `deploy/tpot-cloud/` | ⏳ Vorbereitet |

```
Internet → T-Pot ECS (honeypots, ES :64297)
              ├─ Beelzebub/Galah → http://10.164.18.68:11435 (ai-cloud proxy)
              └─ Elasticsearch ←── ai-cloud (rl-scorer, rule-generator, …)
```

## Deploy-Pfade

### AI-Stack (ai-cloud) — bereits deployed

```bash
cd Sec-Systems
./ai-workstation-cloud/remote-deploy.sh ai-cloud
```

Siehe auch: [KI-test-dev docs](https://github.com/dgskjeuj/KI-test-dev/blob/main/docs/CLOUD-DEPLOY-STATUS.md).

### T-Pot-Stack (zweite ECS) — vorbereitet

```bash
cd Sec-Systems
./tpot-cloud-deploy/remote-deploy.sh ubuntu@NEUE.TPOT.IP --install-only
# auf der ECS: cd ~/tpotce && sudo ./install.sh
# dann: cd ~/tpot-cloud-deploy && sudo ./deploy-custom.sh && sudo ./wire-llm.sh
./tpot-cloud-deploy/connect-ai-stack.sh ai-tpot ai-cloud
```

Vollständige Checkliste: **[deploy/tpot-cloud/docs/DAY1-CHECKLIST.md](../deploy/tpot-cloud/docs/DAY1-CHECKLIST.md)**

## Custom-Mods in diesem Repo

| Pfad | Zweck |
|------|--------|
| `proxy/` | Ollama Smart Proxy (läuft auf ai-cloud) |
| `deploy/tpot/` | Blocklist-Timer für T-Pot `custom/` |
| `deploy/tpot-cloud/` | Komplettes OTC T-Pot Deploy-Paket |
| `deploy/systemd/` | GitHub rules-sync Timer (ai-cloud) |
| `spiderfoot-toolbox/` | SpiderFoot (läuft auf ai-cloud) |
| `scripts/sync-noise-to-tpot.sh` | Noise-CSV ai-cloud → T-Pot |

## ES / LLM Konfiguration (nach T-Pot Go-Live)

**ai-cloud** `cloud.env` (gitignored):

```
ES_URL=https://<TPOT-PUBLIC-IP>:64297/es
TPOT_VM_IP=<TPOT-PUBLIC-IP>
```

**T-Pot** `~/tpotce/.env` (via `wire-llm.sh`):

```
BEELZEBUB_LLM_HOST=http://10.164.18.68:11435/api/chat
GALAH_LLM_SERVER_URL=http://10.164.18.68:11435
```

## Verwandte Doku

- [setup-guide.md](setup-guide.md) — generische Install-Anleitung
- [CUSTOM-LLM-STACK-DEPLOYMENT.md](../../docs/CUSTOM-LLM-STACK-DEPLOYMENT.md) — historisch + Cloud-Update
- [OPTIMIZATION-ROADMAP.md](OPTIMIZATION-ROADMAP.md) — Custom-Mods (Noise, ddospot, …)
