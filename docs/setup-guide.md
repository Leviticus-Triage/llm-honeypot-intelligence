# Setup Guide

Complete deployment guide for the LLM Honeypot Intelligence platform.

---

## Prerequisites

### Hardware requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| T-Pot VM | 8 GB RAM, 4 cores, 250 GB disk | 16 GB RAM, 8 cores, 500 GB disk |
| Host (Proxy) | 4 GB RAM, 2 cores | 8 GB RAM, 4 cores, GPU for Ollama |
| Network | Public IP or port forwarding for honeypot ports | Dedicated subnet |

### Software requirements

- **T-Pot:** [Installation guide](https://github.com/telekom-security/tpotce)
- **Ollama:** [Install](https://ollama.ai) + pull a model (`ollama pull llama3`)
- **Docker:** v24+ with Compose v2
- **Python:** 3.10+
- **Git:** for repository sync

---

## Step 1: Deploy T-Pot

Follow the official T-Pot installation guide. Ensure:

1. The VM is accessible from the host machine
2. Elasticsearch is reachable (default: `https://<vm-ip>:64297/es`)
3. Web credentials are configured (used by the proxy stack)
4. Honeypots are running and receiving traffic

Verify Elasticsearch access:

```bash
curl -sk -u "$ES_USER:$ES_PASS" "https://<vm-ip>:64297/es/_cluster/health" | python3 -m json.tool
```

Expected: `"status": "green"` or `"yellow"`.

---

## Step 2: Install Ollama

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3
```

Verify:

```bash
curl -s http://localhost:11434/api/tags | python3 -m json.tool
```

---

## Step 3: Deploy the proxy stack

```bash
git clone https://github.com/Leviticus-Triage/llm-honeypot-intelligence.git
cd llm-honeypot-intelligence/proxy

# Configure
cp .env.example .env
```

Edit `.env`:

```
ES_URL=https://192.168.x.x:64297/es
ES_USER=your_web_user
ES_PASS=your_web_password
TPOT_VM_IP=192.168.x.x
```

Optionally adjust `config.yaml.example`:

```bash
cp config.yaml.example config.yaml
# Edit semantic_threshold, exploration_rate, etc.
```

Launch:

```bash
docker compose up -d
```

Verify all 5 containers are running:

```bash
docker compose ps
```

Expected output:

```
NAME                         STATUS
ollama-proxy                 Up (healthy)
ollama-rl-scorer             Up
ollama-rule-generator        Up
ollama-heuristic-detector    Up
ollama-c2-detector           Up
```

---

## Step 4: Configure honeypots to use the proxy

### Beelzebub (SSH)

In the Beelzebub configuration, change the Ollama endpoint:

```yaml
# Before:
ollama_host: "http://localhost:11434"

# After:
ollama_host: "http://<host-ip>:11435"
```

### Galah (HTTP)

In the Galah configuration:

```yaml
# Before:
llm_host: "http://localhost:11434"

# After:
llm_host: "http://<host-ip>:11435"
```

The proxy is fully transparent -- it accepts the same API format as Ollama
and forwards requests after caching and CVE enhancement.

---

## Step 5: Configure auto-sync to GitHub

### Create the GitHub repository

```bash
gh repo create llm-honeypot-intelligence --public \
  --description "Distributed honeypot intelligence with LLM-powered deception and automated detection engineering"
```

### Set up the remote

```bash
cd /path/to/llm-honeypot-intelligence
git remote add origin git@github.com:Leviticus-Triage/llm-honeypot-intelligence.git
git push -u origin main
```

### Configure the sync script

The sync script at `scripts/sync-to-github.sh` is already configured with
sensible defaults. It reads from Docker volumes `ollama-rules-output` and
`ollama-threat-output`.

### Install the cron job

```bash
crontab -e
```

Add:

```
0 */6 * * * /path/to/llm-honeypot-intelligence/scripts/sync-to-github.sh >> /var/log/honeypot-sync.log 2>&1
```

### Verify the sync

Run manually:

```bash
/path/to/llm-honeypot-intelligence/scripts/sync-to-github.sh
```

Check logs:

```bash
tail -f /var/log/honeypot-sync.log
```

---

## Step 6: Import Kibana dashboards

```bash
cd dashboards/
chmod +x setup-attack-class.sh
./setup-attack-class.sh
```

Or import manually via Kibana UI:

1. Navigate to **Stack Management → Saved Objects**
2. Click **Import**
3. Select the `.ndjson` files one by one

---

## Troubleshooting

### Proxy returns 502

- Check if Ollama is running: `curl http://localhost:11434/api/tags`
- Check proxy logs: `docker logs ollama-proxy`

### RL scorer shows authentication errors

- Verify `ES_USER` and `ES_PASS` in `.env`
- Ensure the web user has read access to `logstash-*` indices

### Rule generator produces no output

- Check if there is recent data in Elasticsearch
- Verify the `RULEGEN_SINCE_HOURS` setting (default: 24)
- Check logs: `docker logs ollama-rule-generator`

### Sync script fails

- Ensure Docker volumes exist: `docker volume ls | grep ollama`
- Ensure SSH key is configured for GitHub push
- Check permissions on the repo directory

### Elasticsearch disk full

- T-Pot data grows fast. Monitor disk usage and expand as needed
- Consider adjusting T-Pot's data retention settings
- See the [T-Pot FAQ](https://github.com/telekom-security/tpotce#faq) for
  disk management
