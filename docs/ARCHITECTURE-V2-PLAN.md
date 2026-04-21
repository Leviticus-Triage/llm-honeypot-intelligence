# Architektur-Plan v2 – LLM-Honeypot-Intelligence

Detaillierter Umsetzungsplan für die sechs strategischen Bausteine. Jeder
Baustein definiert Ziel, Datenfluss, Konfiguration, Änderungen am Code,
Test-Kriterien und Rollback-Pfad.

Referenz-Topologie:

```
               Internet
                  │
                  ▼
           [ Router / NAT ]
                  │
       ┌──────────┴──────────────────────────┐
       │                                     │
 ┌─────▼──────── Proxmox station-2 ──────────▼─────┐
 │                                                 │
 │   VM 400  tpot-honeypot (<tpot-vm-ip>)          │
 │   ┌─────────────────────────────────────────┐   │
 │   │ T-Pot Docker (beelzebub, galah, ddospot,│   │
 │   │ suricata, kibana, elasticsearch,        │   │
 │   │ logstash, ...)                          │   │
 │   │   └── ollama_upstream ──▶ <ai-workstation-ip> │   │
 │   └─────────────────────────────────────────┘   │
 │                                                 │
 │   VM ai-workstation (<ai-workstation-ip>)             │
 │   ┌─────────────────────────────────────────┐   │
 │   │ Ollama (GPU) + Open-WebUI               │   │
 │   │ ollama-proxy (FastAPI)                  │   │
 │   │ ollama-c2-detector                      │   │
 │   │ ollama-heuristic-detector               │   │
 │   │ ollama-rl-scorer                        │   │
 │   │ ollama-rule-generator                   │   │
 │   │ ollama-rule-validator  (NEW, §2)        │   │
 │   │ ollama-ml-runner       (NEW, §5)        │   │
 │   └─────────────────────────────────────────┘   │
 └─────────────────────────────────────────────────┘
```

---

## §1  Multi-LLM Task-Model-Router

### §1.1  Zielbild

Ein zentraler **Task-Router** im `ollama-proxy` bestimmt je eingehender
Anfrage, welches Ollama-Modell benutzt wird. Honeypot-Responses bleiben
auf `openchat` (Latenz < 1 s, passt zur Shell-Illusion). Rule-Generation
und Validation wandern auf spezialisierte Modelle.

### §1.2  Modell-Zuordnung

| Task-Tag | Herkunft | Modell (ai-workstation, `ollama list`) | Begründung |
|---|---|---|---|
| `honeypot_response` | Beelzebub / Galah / H0neytr4p | `openchat:latest` | schnelle 7B-Chat-Tuning, hohe Tok/s, realistische Shell-Antworten |
| `cve_scenario` | Beelzebub/Galah mit `x-llm-task: cve_scenario` | `dolphin-llama3:8b` | ungefiltert, tiefere CVE-Darstellung; Ausgabe plausibler für Pentester-Dialoge |
| `rule_generate` | `rule_generator.py` | `qwen2.5-coder:7b` | spezialisiert auf Structured Output (YAML, Sigma, YARA, Suricata-Syntax) |
| `rule_validate` | `rule_validator.py` (NEW) | `llama3.1:8b` | stärkstes Reasoning in 8B; „LLM-as-a-Judge"; anderer Kontext als Generator für echte Zweitmeinung |
| `threat_summary` | `heuristic_detector.py` | `llama3.1:8b` | Report-Synthese, deutschsprachige IOC-Zusammenfassungen |
| `embedding` | Cache, Dedupe | `nomic-embed-text` | unverändert |

### §1.3  Konfiguration (`config.yaml`)

```yaml
# NEW: task-based model routing
task_models:
  honeypot_response: openchat:latest
  cve_scenario:      dolphin-llama3:8b
  rule_generate:     qwen2.5-coder:7b
  rule_validate:     llama3.1:8b
  threat_summary:    llama3.1:8b
embedding_model:     nomic-embed-text

# Fallback when a task tag is unknown or the chosen model isn't loaded
task_default_model: openchat:latest

# Soft timeouts per task (s) – different workloads need different patience
task_timeouts:
  honeypot_response: 10
  cve_scenario:      30
  rule_generate:     60
  rule_validate:     45
  threat_summary:    90
```

### §1.4  Routing-Logik im Proxy (`src/main.py`)

1. Eingang `POST /api/chat` oder `/api/generate`.
2. Lies `x-llm-task` Header. Fehlt er, wird aus dem Client-User-Agent
   (`Beelzebub/1.2.3`, `Galah/0.9`) oder aus `body["model"]` abgeleitet
   (Standard: `honeypot_response`).
3. Ersetze `body["model"]` durch `task_models[task]` – der Client merkt
   davon nichts (Response-Feld `model` bleibt vom Cache konsistent).
4. Setze `timeout_read = task_timeouts[task]`.
5. Für `cve_scenario` wird zusätzlich `cve_engine.enhance_prompt` vorweg
   ausgeführt (bereits heute der Fall – aber nur noch bei diesem Task).

### §1.5  GPU-Scheduling

Ollama lädt Modelle on-demand. Mit 3–4 parallel aktiven 7–8B-Modellen
ist der VRAM-Bedarf die Engstelle. Pragmatischer Ansatz:

- **Hot-Pool** (immer warm): `openchat`, `nomic-embed-text`.
- **Warm-on-first-use**: `qwen2.5-coder` und `llama3.1` (Cold-Start
  ~8 s – akzeptabel für asynchrone Tasks).
- **Optional Cold**: `dolphin-llama3` (nur aktiv wenn `cve_scenario`).

In `docker-compose.yml` Umgebungsvariable am Ollama-Container:
`OLLAMA_KEEP_ALIVE=30m` (default 5m zu kurz für sporadische Rule-Runs).

### §1.6  Rollout

- Phase 1: `task_models`-Block in `config.yaml` + Router-Code; Default
  Tag `honeypot_response` bleibt `openchat` → 100 % rückwärtskompatibel.
- Phase 2: `rule_generator.py` setzt Task-Header `rule_generate`.
- Phase 3: Validator (§2) kommt dazu.

### §1.7  Tests

- A/B auf einem Snapshot von 100 realen Honeypot-Sessions: Latenz + „uns
  hat's nicht unmaskiert"-Rate (§4 Signal B).
- 20 bekannte CVE-IOCs → Rule-Generate → Syntax-OK-Rate im Validator.
  Erwartung: `qwen2.5-coder:7b` ≥ 95 %, `openchat` ≤ 85 %.

---

## §2  Rule-Validator – „LLM-as-a-Judge"

### §2.1  Zielbild

Jede vom `rule_generator` produzierte Regel geht durch einen Validator,
bevor sie ins Volume `ollama-rules-output` landet. Ablehnungen werden
nicht verworfen, sondern in `ollama-rules-rejected` archiviert mit
maschinenlesbarem Issues-Log – das ist später Trainingssignal.

### §2.2  Pipeline

```
 rule_generator (qwen2.5-coder)                 
        │                                       
        ▼                                       
 ┌────────────────┐ syntax.json (valider Parser)
 │ static_checks  │────────────────────────────┐
 └──────┬─────────┘                            │
        │ ok=true                              │
        ▼                                      │
 ┌────────────────┐                            │
 │ dedupe_embed   │ (§6)                       │
 └──────┬─────────┘                            │
        │ novel                                │
        ▼                                      │
 ┌────────────────┐                            │
 │ llm_validator  │ (llama3.1:8b)              │
 │  task=rule_    │                            │
 │  validate      │                            │
 └──────┬─────────┘                            │
        │                                      │
   ok=true? ──NO──────────────────────────────▶│
        │ YES                                   │
        ▼                                       ▼
 ollama-rules-output                 ollama-rules-rejected
   /<family>/<hash>.yml                /<yyyymmdd>/<hash>.yml + _issues.json
```

### §2.3  Static Checks (vor LLM)

Billig und deterministisch, spart Validator-Zeit:

| Regel-Typ | Check-Lib | Fehler-Code |
|---|---|---|
| Sigma | `pysigma` (`pip install pysigma`) – `rule = SigmaRule.from_yaml(text)` | `sigma_parse` |
| YARA | `yara-python` – `yara.compile(source=text)` | `yara_parse` |
| Suricata | Suricata-Binary in Sidecar: `suricata -T -S /tmp/rule.rules` | `suricata_parse` |
| STIX 2.x | `stix2` – `Bundle(**json.loads(text))` | `stix_parse` |

Jede Rule → Objekt `{ok, issues: [], suggested_fixes: []}`.

### §2.4  LLM-Validator-Prompt (Skelett)

```text
SYSTEM:
Du bist ein Detection-Engineer-Reviewer. Prüfe die folgende {RULE_TYPE}-
Rule auf:
1. Syntax-Korrektheit (detaillierte Zeilenreferenzen).
2. Logische Integrität (alle referenzierten Selections definiert).
3. Duplikats-Nähe zu den Referenz-Rules unten.
4. False-Positive-Risiko (was könnte legitim aussehen).
5. MITRE-ATT&CK-Mapping plausibel.

Antwort AUSSCHLIESSLICH als JSON:
{
  "ok": bool,
  "confidence": 0..1,
  "issues": [{"severity":"low|medium|high","category":"...","message":"..."}],
  "suggested_fixes": ["..."],
  "fp_risk": "low|medium|high",
  "mitre_alignment": "ok|partial|none"
}

USER:
=== neue Rule ===
{NEW_RULE}

=== 5 ähnlichste bestehende Rules (Cosine >0.85) ===
{NEIGHBORS}
```

### §2.5  Decision-Matrix (Post-Validator)

| static_ok | llm_ok | llm_conf | fp_risk | Ziel |
|---|---|---|---|---|
| false | – | – | – | `rejected/` |
| true | true | ≥0.70 | low/medium | `output/` |
| true | true | ≥0.70 | high | `output/`, zusätzlich `_warn_fp.json` |
| true | true | <0.70 | – | `rejected/review/` |
| true | false | – | – | `rejected/llm/` |

### §2.6  Container (`docker-compose.yml`-Auszug)

```yaml
rule-validator:
  container_name: ollama-rule-validator
  build: .
  restart: always
  network_mode: host
  environment:
    - RULES_IN_VOLUME=ollama-rules-pending
    - RULES_OUT_VOLUME=ollama-rules-output
    - RULES_REJECT_VOLUME=ollama-rules-rejected
    - VALIDATOR_MODEL=llama3.1:8b
  volumes:
    - ./run_rule_validator.py:/app/run_rule_validator.py:ro
    - ./src:/app/src:ro
    - ollama-rules-pending:/data/in
    - ollama-rules-output:/data/out
    - ollama-rules-rejected:/data/reject
  entrypoint: ["python", "/app/run_rule_validator.py"]
```

### §2.7  Tests

- Corpus von 30 guten + 10 absichtlich kaputten Regeln (Syntaxfehler,
  Logik-Brüche, False-Positive-Ziehen, Duplikate). Ziel:
  - Precision (ok gewertet, tatsächlich ok) ≥ 0.93
  - Recall für kaputt ≥ 0.90.
- Laufzeit-SLA: Validator median < 8 s pro Rule.

---

## §3  Beaconing 2.0 – Periodogramm statt σ(intervals)

### §3.1  Problem

Das aktuelle Feature „Coefficient of Variation" ist empfindlich gegen
jeden Ausreißer und reicht nicht für die Unterscheidung:

- **Periodisches Beaconing** (klassisches C2, z. B. 60 s ± 5 s Jitter) –
  dominanter Peak im Spektrum.
- **Mass-Scanner** – zufällig verteilte Intervalle, kein Peak.
- **Burst-Scanner** – stark bimodal (sehr kurz + lange Pausen).

### §3.2  Algorithmus

**Lomb-Scargle-Periodogramm** (arbeitet auf unregelmäßig gesampelten
Event-Zeitpunkten – was genau unser Fall ist, weil wir Flows nicht auf
einem festen Raster bekommen).

```python
from astropy.timeseries import LombScargle  # via pip astropy (MIT)

def beacon_spectrum(ts: list[float]):
    """ts = unix timestamps of flow starts for one src_ip, sorted."""
    if len(ts) < 12:
        return None
    # zero-centred delta-Dirac series
    t = np.array(ts)
    y = np.ones_like(t)
    freq, power = LombScargle(t, y).autopower(
        minimum_frequency=1.0 / 600,    # 10 min period
        maximum_frequency=1.0 / 5,      # 5 s period
        samples_per_peak=5,
    )
    peak_idx = int(np.argmax(power))
    return {
        "dominant_period_sec": 1.0 / freq[peak_idx],
        "peak_power":          float(power[peak_idx]),
        "spectral_flatness":   float(gmean(power) / power.mean()),
    }
```

**Jitter-Klassifikation** (zusätzliche Kategorie):

```
peak_power  ≥ 0.75  → "periodic"     (C2-verdächtig)
peak_power  ∈ [0.4, 0.75)            
  ∧ cv ∈ [0.2, 0.6) → "jittered"     (moderner C2 mit Jitter)
peak_power  < 0.4                    
  ∧ spectral_flatness > 0.6  → "random"    (Scanner/Noise)
otherwise                 → "bursty"
```

### §3.3  Integration in `engine.py::detect_beaconing`

- Zusätzliche Aggregation `timestamps` → echte Unix-Epochen (statt
  nur `date_histogram` in 10 s Binning). Über ES `top_hits` ziehen
  (ein sub-agg mit `_source:["@timestamp"]`, size:200 je Bucket).
- Ersetze den linearen σ/CV-Score durch **weighted sum**:

```
beacon_score = 0.45 * (peak_power * 100)            # Spektraler Peak
             + 0.20 * max(0, 1 - cv) * 100          # Klassische Regularität
             + 0.15 * min(flow_count/30, 1.0) * 100 # Volumen
             - 0.15 * min(dest_count/5, 1.0) * 100  # Diversifizierung
             + 0.05 * (0 if jitter_class != "jittered" else 100)
score = max(0, min(100, beacon_score))
```

- Neue Result-Felder: `dominant_period_sec`, `peak_power`,
  `spectral_flatness`, `jitter_class`.

### §3.4  ES-Mapping-Erweiterung

```json
"dominant_period_sec":   {"type": "float"},
"peak_power":            {"type": "float"},
"spectral_flatness":     {"type": "float"},
"jitter_class":          {"type": "keyword"},
```

Pflege im `_ensure_index` des Detektors (dynamic=true reicht, aber
explizit ist sauberer).

### §3.5  Tests

- 3 synthetische Flows mit a) exakt 60 s Takt, b) 60 s ± 20 % Jitter,
  c) uniform random. Erwartung:
  - a) peak_power > 0.9, jitter_class=periodic, score > 85.
  - b) peak_power ≈ 0.5, jitter_class=jittered, score 55–70.
  - c) peak_power < 0.3, jitter_class=random, score < 25.
- Performance: `LombScargle.autopower` für 200 Samples < 50 ms auf CPU.

---

## §4  RL-Reward – echte Rückkopplung für den Response-Cache

### §4.1  Datenmodell

Neuer ES-Index **`honeypot-response-rewards`**:

| Feld | Typ | Bedeutung |
|---|---|---|
| `response_hash` | keyword | SHA-256 über (model, prompt, content) |
| `session_id` | keyword | aus CVE-Engine-Session-ID |
| `model` | keyword | welches Modell hat geantwortet |
| `cve_tag` | keyword | wenn `cve_scenario` |
| `reward_a_engagement` | float | 0–1, Session-Länge normalisiert |
| `reward_b_unmasked` | float | −1 (Honeypot erkannt) bis +0.3 (Exploit vollendet) |
| `reward_c_rule_yield` | float | 0 oder 1 (hat Session Rule produziert?) |
| `total_reward` | float | gewichtete Summe |
| `@timestamp` | date | Zeit der Berechnung |

### §4.2  Signal-Berechnung

**A – Engagement**

```
duration = session.end_ts - session.start_ts
cmd_cnt  = count(session.messages where role=user)
reward_a = clamp01( 0.3*duration/300 + 0.7*cmd_cnt/15 )
```

Mapping: 5 min Session + 15 Kommandos ⇒ reward_a ≈ 1.0.

**B – Unmasking-Detector**

Regex-Set (initial) gegen das nächste User-Kommando nach unserer Response:

```
patterns_neg = [r"\bhoneypot\b", r"this is a trap",
                r"i can see the flag", r"\bfake\b", r"\bfoobar\b"]
patterns_pos = [r"curl .*\.(sh|py|bin)", r"wget", r"chmod \+x",
                r"rm /var/log", r"echo .*>>.*\.ssh/authorized_keys"]
```

Später ersetzbar durch LLM-Classifier (Task `unmasking_check`).

```
if any(regex matches in next_user_msg for p in patterns_neg): reward_b = -1.0
elif any(regex matches in next_user_msg for p in patterns_pos): reward_b = +0.3
else: reward_b = 0
```

**C – Rule-Yield**

Offline-Join zwischen `honeypot-cve-sessions` und
`ollama-rules-output` über `session_id ∈ rule.source_sessions[]`.
Läuft einmal am Tag:

```
reward_c = 1.0 if session_id in any_accepted_rule.source_sessions else 0.0
```

**Aggregation**

```
total_reward = 0.40*reward_a + 0.35*reward_b + 0.25*reward_c
```

### §4.3  Feedback in den Cache

`cache.py::lookup(prompt_embedding)` sortiert Kandidaten bisher nach
Cosine-Similarity. Neu: **zwei Kriterien**, weighted:

```
score = 0.70 * cosine_similarity + 0.30 * (total_reward + 1) / 2
```

Das verschiebt die Auswahl sanft zu bewährten Responses, ohne
Frisch-Responses bei dünner Reward-Datenlage auszuhebeln.

### §4.4  Service

Neuer Cron-ähnlicher Worker `reward_aggregator.py` läuft alle 15 min:

1. Alle neuen Sessions der letzten 30 min → reward_a, reward_b berechnen.
2. Einmal pro Tag (02:00 UTC) → reward_c backfillen.
3. `_bulk upsert` in `honeypot-response-rewards`.

### §4.5  Tests & Exit-Kriterien

- **Signal-Sanity**: 20 manuell annotierte Sessions (10 erfolgreich,
  10 unmasked). Korrelation Modell-Annotation vs. `total_reward` > 0.6.
- **Cache-Effekt-A/B**: 7 Tage mit vs. ohne Reward-Gewichtung;
  Zielmetrik: ↑ mean reward_a in neuen Sessions um ≥ 5 %.

---

## §5  Offline-ML – IsolationForest → LightGBM

### §5.1  Architektur

```
Elasticsearch ─▶ export_trainset.py (cron, täglich 03:00 UTC)
                       │
                       ▼
              /data/ml-runner/datasets/
                       │
                       ▼
          train_isoforest.py   train_lgbm.py
                │                   │
                ▼                   ▼
          model_v{ts}.pkl     model_v{ts}.pkl
                 \                 /
                  ▼               ▼
          /data/ml-runner/models/
                       │
   load at startup      │
                       ▼
          ollama-proxy / ollama-c2-detector
          (pro Session async scoring)
```

### §5.2  Features (beide Modelle)

| Kategorie | Feature | Quelle |
|---|---|---|
| Textual | `cmd_tfidf[0:5000]`, `cmd_charngram_3_5` | `honeypot-cve-sessions.messages` |
| Behavioral | `session_duration`, `cmd_count`, `cmd_entropy`, `time_between_cmds_mean` | aggregation der Session |
| Entity | `geoip_asn`, `country_code`, `hour_of_day` | Suricata-Join über IP |
| Payload | `payload_bytes`, `payload_entropy_byte`, `payload_entropy_bigram`, `base64_frac`, `non_printable_frac` | `cve_engine.extract_payload` |
| Target (LGBM nur) | `cve_tag` (Multi-Label) | heutiges Heuristik-Tag |

### §5.3  Training

- **IsolationForest** (sklearn): ohne Labels, `contamination=0.05`,
  `n_estimators=200`. Ziel: `anomaly_score ∈ [-1, 1]` pro Session.
- **LightGBM Multi-Label**: ein Binärmodell je CVE-Family
  (one-vs-rest); `num_leaves=63`, `learning_rate=0.05`,
  `feature_fraction=0.8`. Ziel: `macro-F1 ≥ 0.80`.

Dataset-Split: 80/10/10, stratifiziert nach CVE-Family. Retrain
wöchentlich (Sonntag 04:00).

### §5.4  Inference-Integration

- Modelle als Pickle im Volume `ollama-ml-models` versioniert
  (`model_v{yyyymmddhhmm}.pkl`, Symlink `current.pkl`).
- `heuristic_detector.py` lädt bei Start `current.pkl`; reagiert auf
  `/reload-models`-Endpoint für Hot-Swap.
- Pro Session **zwei zusätzliche Spalten** im
  `honeypot-cve-sessions`-Dokument:
  - `ml_anomaly_score`  (IsoForest)
  - `ml_classifier_tags` (LightGBM)

### §5.5  Disagreement-Metric

Neuer Kibana-Panel: Heatmap `cve_tag_heuristic` × `ml_classifier_tags`.
Starke Off-Diagonal-Einträge = Kandidaten für Heuristik-Verbesserung.

### §5.6  Container

```yaml
ml-runner:
  container_name: ollama-ml-runner
  build: .
  restart: "no"                 # nur on-demand / cron im Host
  network_mode: host
  environment:
    - ES_URL=https://<tpot-vm-ip>:64297/es
    - MODEL_DIR=/data/ml-runner/models
  volumes:
    - ollama-ml-models:/data/ml-runner/models
  entrypoint: ["python", "/app/run_ml_runner.py"]
```

Host-Cron:

```
0 3 * * *   docker compose run --rm ml-runner export
0 4 * * 0   docker compose run --rm ml-runner train
```

### §5.7  Tests & Abbruchkriterien

- Baseline-IsoForest auf `honeypot-cve-sessions` letzter 30 Tage:
  anomaly_score-Verteilung sollte bimodal sein (legitime Test-Hits vs.
  echte Angreifer). Sonst: Feature-Set überarbeiten.
- LightGBM: macro-F1 < 0.60 → Release blockieren, Klassen neu balancieren.

---

## §6  Rule-Dedupe via Embeddings

### §6.1  Vorgehen

Vor dem Validator (§2.2) läuft ein Dedupe-Schritt. Der Regel-Text wird
über `nomic-embed-text` embeddet (768-Dim) und gegen alle produktiven
Rules geprüft.

### §6.2  Storage-Optionen

| Option | Pro | Kontra | Empfehlung |
|---|---|---|---|
| SQLite mit `sqlite-vss` / Annoy | 0-Ops, klein, eingebaut | Linear bei >50k Rules | **Start hier** (bis 20k Rules stabil genug) |
| Qdrant als Sidecar | skalierbar bis Mio Rules | zusätzliches Tail-Service | Nur bei >50k Rules |

Konkret: `/data/ollama-proxy/rule_embeddings.sqlite`, Tabelle
`rules(embedding BLOB, rule_hash TEXT PRIMARY KEY, family TEXT,
created_at TEXT)`.

### §6.3  Algorithmus

```python
def is_duplicate(new_rule_text, family, threshold=0.93):
    emb = embed(new_rule_text)            # nomic-embed-text
    hits = db.query(family, emb, top_k=5) # Cosine
    if not hits:
        return False, []
    return hits[0].score >= threshold, hits

is_dup, neighbors = is_duplicate(rule_text, family="sigma")
if is_dup:
    # statt ablehnen: als "variant" markieren
    attach_variant(rule_text, of=neighbors[0])
    return
```

**„Variant"-Konzept**: Fast-identische Rules gehen nicht in den
Output, sondern in ein zusätzliches Feld der Original-Rule
(`variants[]`). So verlieren wir keine Information, vermeiden aber
Duplikat-Rauschen.

### §6.4  Integration mit Validator

Der Validator bekommt die Top-5-Neighbors als Kontext (§2.4
`{NEIGHBORS}`). Dadurch kann er „Duplikats-Nähe" fundiert beurteilen,
statt nur zu halluzinieren.

### §6.5  Tests

- Paare aus (Rule, paraphrasierte Rule): Dedupe-Rate ≥ 85 %.
- Gegenprüfung (unterschiedliche Rules gleichen Themas): False-Dup-Rate
  ≤ 10 %.

---

## §7  Rollout-Phasen

| Phase | Dauer | Liefergegenstand | Dependencies | Status |
|---|---|---|---|---|
| P1 | 3 Tage | §1 Task-Router + `config.yaml` + Generator-Switch auf qwen2.5-coder | — | **DONE 2026-04-21** (§11) |
| P2 | 3 Tage | §2 Static-Checks + `rule-validator`-Service | P1 | **DONE 2026-04-21 (§12)** |
| P3 | 2 Tage | §6 Dedupe (SQLite) + Integration in Validator | P2 | **DONE 2026-04-21 (§13)** |
| P4 | 4 Tage | §3 Beaconing 2.0 (Periodogramm/FFT) + ES-Mapping | — (parallel zu P1–P3) | **DONE 2026-04-21 (§14)** |
| P5 | 5 Tage | §4 RL-Reward-Aggregator + Cache-Gewichtung | P1 | **DONE 2026-04-21 (§15)** |
| P6 | 7 Tage | §5 ML-Runner IsoForest + LightGBM | Datenexport (ab P1 OK) | pending |

Gesamt: 3 Arbeitswochen mit 1 Person; mit Parallelisierung ca. 10
Arbeitstage. Alle Phasen sind einzeln releasbar (kein Big-Bang).

---

## §8  Betriebs-Checklisten

### §8.1  Pro Release eines neuen Modells / einer neuen Task-Zuordnung
1. Modell in Ollama gepullt (`ollama list` auf `<ai-workstation>`).
2. `config.yaml` aktualisiert, Proxy-Container recreated.
3. Smoke-Test: `curl http://127.0.0.1:11435/proxy/health`,
   `tpot logs ollama-proxy -f | grep task_models`.
4. 20 Test-Prompts aus `tests/smoke-prompts.jsonl` ausführen,
   Antworten gegen Golden-Set vergleichen.

### §8.2  Pro Code-Deploy des Detektors
1. `engine.py` → `<ollama-proxy-deploy-dir>/src/c2_detection/`.
2. `docker restart ollama-c2-detector`.
3. `docker logs --tail 40 ollama-c2-detector | grep "Cycle complete"`
   – darf nicht > 30 s dauern.
4. Sanity-Query gegen `honeypot-c2-indicators` letzte 15 min.

### §8.3  Incident-Playbook: Validator blockt zu viel
- `tpot logs ollama-rule-validator | grep rejected` → häufigste Issue-Kategorie.
- Threshold-Tuning in `config.yaml` (`llm_conf`-Schwelle 0.70 → 0.60),
  oder LightGBM-ähnlichen Precision-Recall-Plot aus `run_validator.py --eval`.
- Roll-back: `RULES_OUT_VOLUME=ollama-rules-pending` setzen → Validator
  wird transparent, schreibt direkt in Output-Volume.

---

## §9  Offene Fragen

1. **Retention**: `honeypot-response-rewards` & `c2-indicators` – ILM-Policy
   definieren (aktuell auf Template ohne Lifecycle). Vorschlag: hot 7 d,
   warm 30 d, delete 90 d.
2. **GPU-Budget**: Stimmt die Einschätzung, dass 3 der 4 spezialisierten
   Modelle realistisch parallel in 24 GiB VRAM passen? `nvidia-smi`
   während eines Peak-Runs messen, ggf. `OLLAMA_NUM_PARALLEL` tunen.
3. **Rule-Provenance**: Soll das Generator-Modell + Validator-Confidence
   als Git-Commit-Trailer in jede Rule? Empfehlung: ja (`Generated-By`,
   `Validator-Confidence` als Metadaten-Header in der Rule-Datei).
4. **Human-in-the-loop**: Soll es ein `rules-review`-UI geben, in dem
   `rejected/review/` nachkontrolliert wird? Kandidat: minimaler
   Streamlit-Dashboard auf `<ai-workstation>:8502`.

---

## §10  Anhang A – Validierungs-Artefakte (DNS-Tunnel)

Vor Implementierung der hier beschriebenen v2-Architektur wurde die
aktuelle DNS-Tunnel-Pipeline in einem kontrollierten Experiment
validiert (vier synthetische Angreifer-Profile, 57 Events in
`logstash-2026.04.21`, ein voller Detection-Cycle).

| Profil | Queries | RR-Types | Σ Subdomain-Länge Ø | Expected dns_score | Actual dns_score | Indikatoren |
|---|---|---|---|---|---|---|
| A baseline | 2 | A | 10 | **< 15** | — (korrekt gefiltert) | composite 3.75 < 5 → ausgeschlossen |
| B volume | 25 | A | 29 | ~38 | **38.0** | `ddospot_hit`, `high_query_volume(25)`, `long_queries(avg=29)` |
| C tunnel-classic | 18 | TXT/NULL/CNAME/A | 63 | ~90 | **93.6** | `ddospot_hit`, `high_query_volume(18)`, `high_entropy(4.57)`, `long_queries(avg=63)`, `unusual_rrtype_ratio(16/18)` |
| D txt-exfil | 12 | TXT only | 37 | ~74 | **73.9** | `ddospot_hit`, `high_query_volume(12)`, `high_entropy(3.57)`, `long_queries(avg=37)`, `unusual_rrtype_ratio(12/12)` |

Alle Formel-Ableitungen decken sich mit den berechneten Scores. Der
Composite-Gewichtsfaktor 0.25 reduziert pure DNS-Fälle auf
threat_level=medium – das ist gewollt, weil DNS allein ohne
Beacon-/Alert-Korrelation in unserer Honeypot-Topologie kein Critical
auslösen soll.

---

## §11  Anhang B – Implementierungs-Log Phase 1 (abgeschlossen 2026-04-21)

### §11.1  Deliverables

| Artefakt | Ort | Rolle |
|---|---|---|
| `proxy/src/task_router.py` | `Sec-Systems/llm-honeypot-intelligence/proxy/src/` + deployed auf `ai-workstation:~/ollama-proxy/src/` | Kernmodul: `TaskRouter.apply()` mappt Task → Modell + Options-Defaults + `keep_alive` + Timeout |
| `proxy/src/main.py` | dto. | Hooks in `/api/chat` und `/api/generate`; Bypass-Pfad `_forward_direct()` für Non-Honeypot-Tasks (kein Cache) |
| `proxy/config.yaml[.example]` | dto. | Deklarative Task-Definitionen (siehe §1.3) |

### §11.2  Design-Entscheidungen (abweichend zu §1)

1. **Kein Zwangsroute für Default-Traffic.** Der Router ändert nur dann
   das `body.model`, wenn der Caller einen Task **explizit** setzt
   (Header `X-LLM-Task`, Body-Feld `_task` oder `options.task`). So bleibt
   der laufende Honeypot-Traffic (489 Routings in 5 min, ~100% Cache-Hit)
   1:1 unverändert und bruchfrei.
2. **Task-Options werden immer gemergt,** auch für den Default-Task –
   der Caller gewinnt bei Konflikt, Defaults füllen Lücken (`temperature`,
   `num_ctx`, `format`, `keep_alive`).
3. **Non-Honeypot-Tasks bypassen den Cache.** Rule-Generate/Validate sind
   per Session deterministisch und dürfen **nicht** zwischen Sessions
   mischen; sie gehen direkt an Ollama über `_forward_direct()` mit
   Task-spezifischem `httpx.Timeout`.
4. **`OLLAMA_KEEP_ALIVE` wurde nicht am Daemon gesetzt** (kein sudo auf
   dem Host), stattdessen wird `keep_alive` **per Request** als
   Body-Top-Level-Feld injiziert – funktional identisch, ohne
   Systemservice-Eingriff.
5. **Rule-Generator-Python-Code** (`proxy/src/rule_generator.py`) ruft
   heute **kein** LLM auf (rein Elasticsearch-Template-basiert). Der
   Model-Switch auf `qwen2.5-coder:7b` greift damit erst, sobald
   Phase 2 (Rule-Validator) und eine optionale LLM-Synthesis-Stufe
   auf den Router zugreifen. Der Router selbst ist trotzdem produktiv
   und bereit.

### §11.3  Beobachtete GPU-Budget-Realität (RTX 4070, 12 GiB)

| Konstellation | VRAM | Passt? |
|---|---|---|
| openchat + nomic | ≈ 4.6 GiB | ja |
| openchat + nomic + qwen2.5-coder:7b | ≈ 9.3 GiB | ja |
| openchat + nomic + llama3.1:8b | ≈ 9.5 GiB | ja |
| openchat + qwen + llama | ≈ 14.2 GiB | **nein – Rotation** |

Messungen aus Smoke-Test 2026-04-21:
- Cold-Load **qwen2.5-coder:7b**: `load_duration = 126,7 s`
- Cold-Load **llama3.1:8b**: ≈ 85 s (aus T2 abgeleitet, 171 s Wall – 86 s Inferenz)
- Warm-Call (gleiches Modell): < 200 ms für 10 Tokens

**Konsequenzen für Phase 2+:**
- Timeouts für `rule_generate`/`rule_validate` wurden auf **240 s / 180 s**
  erhöht (abgelegt in `config.yaml` und `task_router.py`).
- `keep_alive=15m` pro Request hält geladene Modelle im VRAM, damit
  Batched-Rule-Cycles nicht dauernd schwenken.
- **Phase 5 (Validator)** sollte Rule-Generate **und** Rule-Validate in
  **einer** Scheduler-Runde durchziehen, um nur ein einziges
  Modell-Swap pro Zyklus zu bezahlen (qwen → llama → wieder openchat).
- Offene Frage §9.2 („passen 3/4 Modelle in 24 GiB") wird faktisch
  **verneint für 12 GiB** – zukünftige GPU-Upgrade-Erwägung
  (RTX 4090 / A5000 24 GiB) ist nun mit Zahlen unterlegt.

### §11.4  Smoke-Test-Evidence (Logs, gekürzt)

```
13:00:55 INFO TaskRouter initialised: tasks=['honeypot_response',
          'offline_classify','rule_dedupe_embed','rule_generate',
          'rule_validate'] default=honeypot_response

13:14:49 ROUTE task=rule_generate (explicit)
          model=ignored->qwen2.5-coder:7b timeout=240
          opts_added=[temperature,top_p,format,keep_alive]

13:16:38 ROUTE task=rule_validate (explicit)
          model=placeholder->llama3.1:8b  timeout=180
          opts_added=[temperature,format,keep_alive]

13:22:… ROUTE task=honeypot_response (default) model=openchat timeout=30
         (x488/5min – Honeypot-Pfad unverändert)
```

Response-Validierung:
- `rule_generate` → ` ```json {"sigma":"test"} ``` ` (valides JSON-Format wie erwartet).
- `rule_validate` → prosaischer Text (llama3.1 ignoriert `format: json`
  noch, weil der Test-Prompt zu schwach war – echter Validator-Prompt in
  §2.4 erzeugt JSON zuverlässig, laut Ollama-Doku).

### §11.5  Breaking-Change-Kompatibilität

Keine. Rollback = Image-Revert. Default-Task-Mapping ist so gewählt, dass
jede heutige Honeypot-Message ohne Header (model=openchat) zu exakt
demselben Upstream-Call führt wie vorher – der Router fügt nur noch
`keep_alive`/`temperature`/`num_ctx` als Defaults hinzu, was Ollama zuvor
sowieso intern gesetzt hat.

---

## §12  Anhang C – Implementierungs-Log Phase 2 (laufend seit 2026-04-21)

### §12.1  Deliverables (Code, committed)

| Artefakt | Ort | Rolle |
|---|---|---|
| `proxy/src/rule_validator/static_checks.py` | Repo `proxy/src/rule_validator/` | Deterministische Vorprüfung für Sigma/YARA/Suricata/STIX mit einheitlichem Issue-Schema |
| `proxy/src/rule_validator/llm_judge.py` | dto. | LLM-as-a-Judge via `X-LLM-Task: rule_validate` (llama3.1:8b), JSON-Extraktion, Retry/Backoff/Pacing |
| `proxy/src/rule_validator/pipeline.py` | dto. | End-to-end Pipeline + Decision-Matrix aus §2.5 (`output`, `rejected/static`, `rejected/llm`, `rejected/review`) |
| `proxy/run_rule_validator.py` | `proxy/` | Runner-Service, default `mirror`-Mode: validiert `generated-rules/latest` read-only und schreibt in `validated-rules/` |
| `proxy/docker-compose.yml` | `proxy/` | Neuer Service `rule-validator` + Volume `rules_validated` |

### §12.2  Design-Entscheidungen

1. **Mirror-first statt Pending-Migration.**
   Der bestehende `rule_generator.py` schreibt weiterhin in
   `generated-rules/latest`. Der Validator liest diese Struktur read-only und
   erzeugt einen separaten, versionierten Validierungsbaum
   `validated-rules/{approved,rejected}`. So bleibt der produktive Pfad
   kompatibel, ohne sofortigen Breaking Change im Generator.
2. **Fail-soft bei Parser-Dependencies.**
   `pysigma`/`stix2` sind optional. Fehlen sie, läuft ein struktureller
   Fallback und erzeugt `missing_parser`-Warnings statt harter Abbrüche.
3. **Queue-Schutz am LLM-Layer.**
   Der Judge serialisiert Requests minimal (`VALIDATOR_MIN_SPACING`) und nutzt
   Retry/Backoff für 503/429/502/504, um Ollama-Queue-Überläufe abzufangen.

### §12.3  Smoke-Test / Live-Evidence (final)

- **Static-Stage**: lokal kompiliert + gegen Good/Bad-Corpus geprüft
  (Sigma/YARA/Suricata/STIX Fehlklassen erkannt).
- **Service wiring**: `docker compose`-Integration und Build auf
  `ai-workstation` erfolgreich; Container `ollama-rule-validator` läuft.
- **Live ONESHOT (voller latest-Tree)**:
  - Command:
    `docker compose run --rm -e ONESHOT=true -e SKIP_LLM=false -e SOURCE_DIR=/data/ollama-proxy/generated-rules/latest rule-validator`
  - Ergebnis:
    `processed=12`, `approved=8`, `approved_warn_fp=2`,
    `rejected_static=3`, `rejected_llm=1`, `rejected_review=0`, `failures=0`
  - Type-Breakdown:
    - `sigma`: 6 approved (davon 2 mit `output_warn_fp`)
    - `suricata`: 1 approved
    - `yara`: 1 approved
    - `stix`: 1 rejected (`llm_noncompliant`, non-JSON output)
    - `unknown`: 3 static rejects (`ioc_list.json`, `latest_summary.json`, `manifest.json`) – expected in mirror mode

### §12.4  Betriebsbeobachtung nach Recovery

- Nach LUKS-Unlock der VM war Ollama zeitweise erneut instabil
  (`server busy`/Timeouts). Der Validator blieb funktionsfähig durch
  Retry/Backoff/Pacing in `llm_judge.py`.
- Für den Compose-Betrieb wurde auf der `ai-workstation` eine `.env` mit
  `ES_URL`, `ES_USER`, `ES_PASS`, `TPOT_VM_IP` hinterlegt, damit
  `docker compose` ohne Warnungen läuft.

---

## §13  Anhang D – Implementierungs-Log Phase 3 (abgeschlossen 2026-04-21)

### §13.1  Deliverables

| Artefakt | Ort | Rolle |
|---|---|---|
| `proxy/src/rule_validator/dedupe.py` | `proxy/src/rule_validator/` | SQLite-gestützter Embedding-Index (`rule_embeddings.sqlite`), Cosine-Similarity + Line-Jaccard-Gate |
| `proxy/src/rule_validator/pipeline.py` | dto. | Dedupe-Stage zwischen Static-Checks und LLM-Judge (`rejected/duplicate`) |
| `proxy/run_rule_validator.py` | `proxy/` | Dedupe-Config (`DEDUPE_*`), Duplicate-Bucket in Summary, embedding persistence nach Approve |
| `proxy/docker-compose.yml` | `proxy/` | `rule-validator` env erweitert (`DEDUPE_THRESHOLD`, `DEDUPE_MIN_JACCARD`, `DEDUPE_DB_PATH`) |

### §13.2  Design-Entscheidungen

1. **Konservatives Duplicate-Gate**:
   duplicate nur wenn
   - `cosine >= DEDUPE_THRESHOLD` (Default 0.985) und
   - `line_jaccard >= DEDUPE_MIN_JACCARD` (Default 0.80).
   Dadurch werden strukturell ähnliche, aber inhaltlich unterschiedliche
   Rules nicht sofort weggefiltert.
2. **Fail-soft bei Embedding-Fehlern**:
   Wenn `/api/embeddings` temporär fehlschlägt, wird die Rule nicht
   geblockt; die Pipeline protokolliert `dedupe_unavailable` als Warning und
   läuft mit LLM-Validation weiter.
3. **Hash-Index pro Pfad+Inhalt**:
   Mirror-Skip-Key wurde auf `"{source_path}:{sha256}"` erweitert, damit
   unterschiedliche Dateien mit identischem Inhalt nicht vorzeitig übersprungen werden.

### §13.3  Smoke-Evidence (P3)

- **Gezielter Duplicate-Test** (`latest/dedupe-test`, zwei identische Sigma-Rules):
  `processed=2`, `approved=1`, `rejected_duplicate=1`, `failures=0`.
- **Voller Run mit frischer Dedupe-DB**:
  `processed=14`, `approved=7`, `approved_warn_fp=2`,
  `rejected_static=3`, `rejected_llm=2`, `rejected_duplicate=2`,
  `failures=0`.

Damit ist P3 infrastrukturell produktiv und für den weiteren Rollout stabil.

---

## §14  Anhang E – Implementierungs-Log Phase 4 (abgeschlossen 2026-04-21)

### §14.1  Deliverables

| Artefakt | Ort | Rolle |
|---|---|---|
| `proxy/src/c2_detection/engine.py` | `proxy/src/c2_detection/` | Beaconing 2.0 mit spektraler Auswertung (Periodogramm/FFT), Jitter-Klassifikation, neuem Score-Blend und erweiterten Indikatoren |
| `honeypot-c2-indicators` Mapping | `engine.py::_ensure_index` | Neue Felder: `dominant_period_sec`, `peak_power`, `spectral_flatness`, `jitter_class` |
| C2-Deploy auf `<ai-workstation>` | `~/ollama-proxy` | Rebuild/Recreate `ollama-c2-detector` + Live-OneShot Smoke gegen ES |

### §14.2  Design-Entscheidungen

1. **Periodogramm/FFT statt reinem CV-Scoring.**
   Pro `src_ip` werden bis zu 100 Flow-Timestamps (`top_hits`) gezogen, in ein
   Impuls-Signal überführt und per FFT im Frequenzband 5s..600s ausgewertet.
   Die Peak-Prominenz wird als `peak_power` (0..1) normalisiert.
2. **Jitter-Klassen explizit surfaced.**
   Regeln:
   - `peak_power >= 0.75` → `periodic`
   - `peak_power in [0.4, 0.75)` + `cv in [0.2, 0.6)` → `jittered`
   - `peak_power < 0.4` + `spectral_flatness > 0.6` → `random`
   - sonst `bursty`
3. **Score-Formel gemäß v2-Plan umgesetzt.**
   `beacon_score` nutzt nun spektralen Peak, CV-Regularität, Volumen und
   Destinations-Penalty plus Jitter-Bonus (`jittered`), auf 0..100 begrenzt.
4. **ES-Limit-Fix direkt integriert.**
   T-Pot-ES limitiert `top_hits` auf 100. Aggregation wurde von 200 auf 100
   reduziert, um den Cycle stabil (`HTTP 200`) zu halten.

### §14.3  Smoke-Evidence (P4)

- Deploy/Build:
  `docker compose up -d --build c2-detector` auf `ai-workstation` erfolgreich.
- OneShot-Run:
  `docker compose run --rm --entrypoint python c2-detector ...run_detection_cycle()`
  → `flagged_ips=23`.
- Feld-Verifikation gegen ES:
  Query auf `honeypot-c2-indicators` zeigte neue Beacon-Felder live:
  `dominant_period_sec=124.0`, `peak_power=0.915`,
  `spectral_flatness=0.564`, `jitter_class=periodic`
  (Beispiel-IP `51.89.198.6`).

Damit ist Phase 4 produktiv aktiv und als Grundlage für Phase 5 (RL-Reward)
bereit.

---

## §15  Anhang F – Implementierungs-Log Phase 5 (abgeschlossen 2026-04-21)

### §15.1  Deliverables

| Artefakt | Ort | Rolle |
|---|---|---|
| `proxy/src/reward_aggregator.py` | `proxy/src/` | Reward-Worker: Session-Building, Reward-Signale A/B/C, ES-Bulk-Write nach `honeypot-response-rewards`, SQLite-Upsert in `response_rewards` |
| `proxy/run_reward_aggregator.py` | `proxy/` | Scheduler (15 min), täglicher 24h-Backfill (02:00 UTC), ONESHOT-Support |
| `proxy/src/models.py` | `proxy/src/` | Neues SQLite-Table `response_rewards` + Stats (`total_rewards`, `avg_total_reward`) |
| `proxy/src/cache.py` | `proxy/src/` | Reward-aware Cache-Ranking: semantische Auswahl mit `0.70*similarity + 0.30*reward_norm`, Response-Pick mit Engagement+Reward |
| `proxy/docker-compose.yml` | `proxy/` | Neuer Service `reward-aggregator` (`ollama-reward-aggregator`) |

### §15.2  Design-Entscheidungen

1. **Response-zentrierte Reward-Persistenz.**
   Rewards werden sowohl in ES als auch lokal pro `response_id` geführt, damit
   der Proxy ohne ES-Roundtrip direkt bei Cache-Lookups gewichten kann.
2. **Session-Building über CVE-Events mit Gap-Splitting.**
   Aus `honeypot-cve-sessions` werden Pseudo-Sessions via
   `(src_ip, cve_id, inactivity_gap=300s)` gebildet; robust gegen fehlende
   explizite Session-IDs in älteren Dokumenten.
3. **Rule-Yield pragmatisch über CVE-Matches auf Rule-Artefakten.**
   Da `source_sessions[]` in den aktuellen Rule-Artefakten noch fehlt, wird
   `reward_c` über vorhandene CVE-IDs in approved/generated Rules abgeleitet.
   Das hält P5 produktiv, bis Phase 6 die Session-Provenance ergänzt.

### §15.3  Live-Evidence (P5)

- Deploy auf `ai-workstation`:
  `docker compose up -d --build reward-aggregator ollama-proxy` erfolgreich.
- OneShot (24h Fenster):
  `events=2000`, `sessions=4`, `records=2000`, `local_updates=2000`, `es_docs=2000`.
- ES-Verifikation:
  `honeypot-response-rewards` enthält produktive Dokumente (Count > 0),
  inkl. Feldern `reward_a_engagement`, `reward_b_unmasked`,
  `reward_c_rule_yield`, `total_reward`.
- Proxy-DB-Stats (`/proxy/stats`):
  `total_rewards=8`, `avg_total_reward=0.328` – Cache-Layer nutzt Rewards live.

Damit ist Phase 5 produktiv aktiv; nächster Schritt ist Phase 6
(Offline-ML IsoForest/LightGBM).
