# Day-1 Checklist — Zweite OTC-ECS für T-Pot

**Vorbereitet:** alles unter `Sec-Systems/tpot-cloud-deploy/`  
**AI-Stack:** bereits auf `ai-cloud` (`80.158.17.220`)

---

## Phase 0 — Heute (ohne zweite ECS)

- [x] `tpot-cloud-deploy/` Paket erstellt
- [ ] `cloud.env` lokal vorbereiten (IPs als Platzhalter OK)
- [ ] OTC Security Group Regeln für T-Pot notieren (siehe unten)
- [ ] SSH-Key für neue ECS bereit (`~/.ssh/...`, ggf. gleicher KP wie ai-cloud)

---

## Phase 1 — OTC ECS anlegen

| Spec | Minimum | Empfohlen |
|------|---------|-----------|
| RAM | 8 GiB | 16 GiB |
| Disk | 250 GiB | 500 GiB |
| OS | Ubuntu 22.04/24.04 LTS | |
| Netz | **Gleiche VPC** wie ai-cloud | für `10.164.x` Private-IP Routing |

**Security Group (eingehend):**

| Port | Protokoll | Quelle | Zweck |
|------|-----------|--------|-------|
| 22 | TCP | Admin-IP | SSH |
| 64295 | TCP | Admin-IP | T-Pot SSH |
| 64297 | TCP | Admin-IP + ai-cloud private IP | Web UI / ES |
| 0-65535 | TCP/UDP | `0.0.0.0/0` | Honeypot-Sensoren (tpotce öffnet viele Ports) |

> Honeypots brauchen öffentliche Erreichbarkeit — das ist gewollt. Admin-Ports einschränken.

**ai-cloud SG ergänzen:**

| Port | Quelle | Zweck |
|------|--------|-------|
| 11435 | T-Pot private IP / VPC | LLM-Proxy von Beelzebub/Galah |

---

## Phase 2 — Bundle übertragen (von Blade)

```bash
cd /mnt/docker-ssd/cursor-Projekts/Sec-Systems

# Nur Dateien kopieren (ohne install):
./tpot-cloud-deploy/remote-deploy.sh ubuntu@NEUE.TPOT.IP --bundle-only

# Oder mit Host-Prep:
./tpot-cloud-deploy/remote-deploy.sh ubuntu@NEUE.TPOT.IP --install-only
```

`~/.ssh/config` Eintrag anlegen:

```
Host ai-tpot
  HostName NEUE.TPOT.IP
  User ubuntu
  IdentityFile ~/.ssh/Vpc-6a8e-test-dev-AI_KP.pem
```

---

## Phase 3 — Auf der T-Pot ECS

```bash
ssh ai-tpot
nano ~/tpot-cloud-deploy/cloud.env
#   TPOT_PUBLIC_IP=...
#   AI_STACK_PRIVATE_IP=10.164.18.68
#   AI_PROXY_URL=http://10.164.18.68:11435

cd ~/tpot-cloud-deploy && sudo ./install.sh

# Offizieller Telekom-Installer (interaktiv, ~30-60 min):
cd ~/tpotce && sudo ./install.sh
# → HIVE wählen, WEB_USER + Passwort setzen

# Nach Install: ES-Creds in cloud.env eintragen
nano ~/tpot-cloud-deploy/cloud.env
# ES_USER / ES_PASS aus ~/tpotce/.env (WEB_USER / WEB_PASSWORD)

cd ~/tpot-cloud-deploy
sudo ./deploy-custom.sh
sudo ./wire-llm.sh
sudo ./verify.sh
```

---

## Phase 4 — Beide Server verbinden (von Blade)

```bash
cd /mnt/docker-ssd/cursor-Projekts/Sec-Systems
./tpot-cloud-deploy/connect-ai-stack.sh ai-tpot ai-cloud
```

Das Script:

1. Liest ES-Credentials von T-Pot
2. Patcht `ai-cloud` `cloud.env` (`ES_URL`, `TPOT_VM_IP`)
3. Redeployt ollama-proxy
4. Verifiziert ES + Proxy

---

## Phase 5 — Sync-Timer auf ai-cloud (optional, nach Go-Live)

Auf `ai-cloud` in `~/stacks/ollama-proxy/.env` oder systemd user units:

- `scripts/sync-noise-to-tpot.sh` — `TPOT_HOST=admin@NEUE.IP`
- `scripts/sync-blocklist-to-tpot.sh`
- `deploy/systemd/noise-csv-sync.timer`

---

## Architektur (Ziel)

```
Internet → [T-Pot ECS] honeypots → ES :64297
                │                        ↑
                │ Beelzebub/Galah        │ rule-generator, rl-scorer, …
                └──────→ [ai-cloud] ollama-proxy :11435 → Ollama
```

**Kein Proxmox. Kein 192.168.2.22.**
