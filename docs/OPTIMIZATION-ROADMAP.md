# Optimierungs-Roadmap – LLM-Honeypot-Intelligence-Stack

Stand 2026-04-21. Basis: 2,3 Mio. CVE-Sessions in `honeypot-cve-sessions`,
>200 Mio. Suricata-Flows in `logstash-*`, aktiver C2-Detektor auf
`<ai-workstation-ip>`, T-Pot VM 400 auf Proxmox (`<tpot-vm-ip>`).

Das Ziel: aus den bisher generisch wirkenden Heuristiken eine Pipeline
bauen, die hochqualitative, validierte Regeln (Sigma / YARA / Suricata /
STIX-IOCs) erzeugt – mit echtem Feedback-Loop.

---

## 0. Was heute schon erledigt ist

| Thema | Zustand | Commit-Hinweis |
|-------|---------|----------------|
| Kibana CVE-Dashboard-Import | ✅ Re-Import überschrieben, 15 Saved-Objects | `cve-dashboard.ndjson` via `saved_objects/_import` |
| Ddospot-Honeypot | ✅ UDP 53/123/19/1900 aktiv, Events in ES | `docker-compose.override.yml` in T-Pot VM |
| ES-Feldlimit `logstash-*` | ✅ 1000 → 3000 (live + template) | `_index_template/logstash` |
| C2-Detektor DNS-Pfad | ✅ zieht jetzt auch `type:Ddospot` | `engine.py::detect_dns_anomalies` |
| Beaconing-Sättigung | ✅ `sample_confidence` gewichtet CV<br>→ Scores jetzt 83–91 statt uniform 100 | `engine.py::detect_beaconing` |
| C2-Indicator-Details | ✅ reichhaltige Indikatoren (`interval`, `cv`, `single_dest`, `rapid_retry`, …) | dito |
| `tpot` CLI auf `ai-workstation` | ✅ Proxmox-VM-Control via SSH+`qm`, `dashboards-import`, `ssh`, Remote-Logs | `scripts/tpot` |
| Phase 2 Rule-Validator (LLM-as-a-Judge) | ✅ Live auf `<ai-workstation>`: ONESHOT gelaufen (`processed=12`, `approved=8`, `rejected_static=3`, `rejected_llm=1`) | `proxy/src/rule_validator/*`, `proxy/run_rule_validator.py` |
| Phase 3 Rule-Dedupe (Embeddings + SQLite) | ✅ Live: `rejected/duplicate` aktiv, konservatives Gate (`cos>=0.985` + `jaccard>=0.80`) | `proxy/src/rule_validator/dedupe.py`, `proxy/run_rule_validator.py` |
| Phase 4 Beaconing 2.0 (Periodogramm/FFT + Jitter-Klassen) | ✅ Live auf `<ai-workstation>`: `c2-detector` rebuilt, OneShot `flagged_ips=23`, neue Felder in ES (`dominant_period_sec`, `peak_power`, `spectral_flatness`, `jitter_class`) sichtbar | `proxy/src/c2_detection/engine.py` |
| Phase 5 RL-Reward-Aggregator + Cache-Gewichtung | ✅ Live auf `<ai-workstation>`: Reward-Index aktiv (`honeypot-response-rewards`), SQLite `response_rewards` befuellt, Cache-Ranking reward-aware | `proxy/src/reward_aggregator.py`, `proxy/src/cache.py`, `proxy/src/models.py`, `proxy/run_reward_aggregator.py` |
| Phase 6 Offline-ML Runner (IsoForest + Classifier) | ✅ Live auf `<ai-workstation>`: `ml-runner` Export/Train/Infer erfolgreich, `honeypot-cve-sessions` mit `ml_anomaly_score` + `ml_classifier_tags` angereichert | `proxy/src/ml_runner.py`, `proxy/run_ml_runner.py`, `proxy/docker-compose.yml` |

---

## 1. Kurzfristig (1–2 Tage, hohe Wirkung)

### 1.1 Beaconing-Qualität weiter anheben (Phase 4 DONE)
Die Spektral-Erweiterung ist live: statt reinem CV werden jetzt periodische Peaks
im Intervall-Signal gewertet (Periodogramm/FFT), inklusive `jitter_class`.
Zusätzliche Verbesserungen für den nächsten Feinschliff:

- **Asset-Context** einziehen. Private/reservierte Ranges raus – ✅ schon da.
Zusätzlich: IPs, die Suricata selbst als bekannte Scanner/ET-Shadowserver
markiert, bekommen eigenen `detection_type="known_scanner"` statt
`beaconing`, damit sie die C2-Top-List nicht dominieren.
- **Known-Scanner-Entzerrung** als eigener Layer (`detection_type=known_scanner`),
  damit Internet-Scanner die Beaconing-Top-List weniger dominieren.
- **Schwellwert-Tuning per Label-Samples**: `peak_power`/`spectral_flatness`-Grenzen
  gegen kuratierten True/False-Positiv-Korpus feinjustieren.

### 1.2 DNS-Tunnel-Scoring: echte Signale statt Ddospot-Hit
Der aktuelle Ddospot-Bonus `+15` ist ein Platzhalter. Sobald echte externe
Queries reinkommen, nutzen:

- **Payload-Shannon-Entropy** über die vollständige Subdomain (bereits da)
*plus* **Bigramm-Entropy** (gegen Wörterbuch-Maskierung).
- **NXDOMAIN-Ratio** je Src-IP (nur Suricata-seitig verfügbar).
- **Record-Type-Distribution**: >20 % TXT/NULL/CNAME ist starker Indikator.

### 1.3 Heuristic-Detector → Isolation Forest Baseline
`heuristic_detector.py` nutzt heute harte Schwellen. Ersatz: ein
sklearn-`IsolationForest` als zweiter Layer, trainiert offline auf allen
Sessions der letzten 30 Tage, monatlich re-trainiert. Features:

```
session_duration, cmd_count, unique_cmds, payload_len,
payload_entropy_byte, payload_entropy_bigram, cve_tag_present,
non_printable_ratio, base64_score, url_count
```

Output: `anomaly_score ∈ [-1, 1]` → als zusätzliche Spalte in
`honeypot-cve-sessions` und `honeypot-c2-indicators` schreiben, NICHT
das Heuristik-Flag ersetzen (beide fusionieren).

### 1.4 Kibana: Time-Window der DNS-Tunneling-Lens anpassen
Das Panel steht heute auf „letzte 24 h". Da Ddospot erst heute läuft,
wirkt es leer. Panel-Default **temporär** auf `now-2h` stellen, bis
genug Daten da sind. (UI-Fix, kein Code.)

---

## 2. Mittelfristig (1–2 Wochen)

### 2.1 Multi-LLM-Architektur – Begründung

**Ja, openchat ist für den Response-Pfad gut, aber nicht für
Rule-Generation.** openchat ist auf Konversation getuned; die Ausgabe
für Sigma/YARA-Regeln ist zwar lauffähig, aber syntaktisch oft zu frei.
Empfohlene Aufteilung (alle Modelle sind auf `<ai-workstation-ip>` bereits
installiert – Check via `ollama list`):

| Aufgabe | Heute | Empfehlung | Grund |
|---------|-------|------------|-------|
| Beelzebub/Galah-Response (Honeypot-Antworten) | `openchat:latest` | **bleibt `openchat`** | klein, schnell (~200 Tok/s), realistische Shell-Antworten, 7B reicht |
| CVE-Szenario-Injection (realistischer Exploit-Dialog) | `openchat` | **`dolphin-llama3:8b`** | ungefilterte Exploit-Payloads, tieferes CVE-Wissen |
| **Sigma/YARA/Suricata-Generator** | openchat via `rule_generator.py` | **`qwen2.5-coder:7b`** | strukturierter Code-Output, deutlich weniger Halluzinationen bei DSLs |
| Threat-Intel-Zusammenfassung / IOC-Clustering | nicht vorhanden | **`llama3.1:8b`** | bestes Reasoning in der 8B-Klasse für deutschsprachige Reports |
| **Meta-Validator** (zweite Meinung vor Rule-Commit) | nicht vorhanden | **`llama3.1:8b`** (anderer Kontext als Generator) | LLM-as-a-Judge: syntax + logisch konsistent, keine Duplikate |
| Embedding (Cache, Similarity) | `nomic-embed-text` | bleibt | State-of-the-Art OS-Embedding für 768-Dim |

Umsetzung (klein): `config.yaml` um `task_models:`-Mapping erweitern,
`rule_generator.py` bekommt einen Parameter `model=`, der per Default
`qwen2.5-coder:7b` zieht. Ressourcen: auf dem ai-workstation-GPU-Budget
passt jeweils 1 Modell gleichzeitig in VRAM – Ollama lädt on demand;
akzeptabel, weil Rule-Generation asynchron läuft.

### 2.2 Validator-Stage („Second Opinion")
Nach jeder Rule-Generierung ein zweiter Prompt an `llama3.1:8b`:

```
Prüfe die folgende Sigma-Rule auf:
1. Syntax (YAML valide, Felder korrekt),
2. Logische Integrität (Condition referenziert definierte Selections),
3. Duplikatscheck gegen die letzten 500 Rules (Liste anbei),
4. False-Positive-Risiko (warum könnte das unter legitimem Traffic feuern?)
Antwort: JSON mit {ok: bool, issues: [str], suggested_fixes: [str]}.
```

Nur Rules mit `ok=true` gehen ins Volume `ollama-rules-output`; Rest
geht in `ollama-rules-rejected` mit Issues-Log.

### 2.3 RL-Scorer echten Reward geben
`rl_scorer.py` schreibt heute CVE-Sessions nach Elasticsearch, benutzt
aber nur eine Pseudo-Reward-Funktion. Richtige Reward-Kette:

1. **Signal A – Attacker-Engagement**: Session-Länge, #Follow-up-Commands
(lange Session = plausibler Response).
2. **Signal B – Honeypot-Unmasking**: falls der Gegner nach unserer
Antwort weg ist ODER „i know this is a honeypot"-Patterns sendet ⇒
starker negativer Reward.
3. **Signal C – Rule-Yield**: wurde aus dem Session-Cluster später eine
validierte Regel? ⇒ positiver Reward zurück auf den Response.

Speichern in neuem Index `honeypot-response-rewards`, Felder
`response_hash, reward_a, reward_b, reward_c, total_reward`. Der Proxy
zieht beim nächsten Cache-Lookup bevorzugt Antworten mit hohem
`total_reward`.

**Status (21.04.2026): DONE als Phase 5.**
- Neuer Service `reward-aggregator` laeuft alle 15 min.
- Reward-Signale A/B/C werden berechnet und in ES + SQLite persistiert.
- Cache nutzt live Reward-Gewichtung in semantischer Prompt-Auswahl
  (`0.70 similarity + 0.30 reward_norm`) und im Response-Pick.

### 2.4 Rule-Dedupe via Embeddings
`nomic-embed-text` (bereits installiert) → Embedding der Regel-Beschreibung
vor Commit → Cosine-Similarity <0.93 gegen die letzten 1000 Rules. Blocker
gegen „neue Rule, aber inhaltlich identisch". Indexiert in SQLite (lokal)
oder Qdrant (wenn wir auf eine echte Vector-DB wollen).

---

## 3. Längerfristig (4–6 Wochen)

### 3.1 Supervised Classifier für Session-Intent
Mit den bestehenden 2,3 M CVE-Sessions hast du den seltensten Engpass
endlich nicht: Daten. Vorschlag:

1. **Label-Quelle**: die CVE-Tags der Engine sind schon eine schwache
Supervision (`cve_tags` in `honeypot-cve-sessions`).
2. **Feature-Extraction**: Kombination aus (a) Textual-Features der
Commands (TF-IDF, char-ngrams 3–5), (b) Behavioral (ts-diffs,
cmd_entropy), (c) Entity-Features (geoip_asn, time_of_day).
3. **Modell**: LightGBM Multi-Label (pro CVE-Family je ein Head), Ziel
`macro-F1 > 0.80`. Training offline; in Produktion nur Inference.
4. **Shipping**: Modell-Pickle in Volume `ollama-proxy-data`, geladen
beim Proxy-Start; Vorhersage läuft parallel zur Heuristic. Beide
Output-Spalten (`cve_heuristic_tag`, `cve_classifier_tag`) getrennt
speichern, damit man Disagreement messen kann.

**Status (21.04.2026): DONE als Phase 6 (Batch-Variante).**
- Neuer `ml-runner` Service mit Commands `export`, `train`, `infer`.
- Trainierte Modelle liegen versioniert in `ollama-ml-models`.
- Inference schreibt direkt in `honeypot-cve-sessions`:
  `ml_anomaly_score`, `ml_classifier_tags`, `ml_model_version`.

### 3.2 Rule-Pipeline mit DVC / MLflow-Tracking
Rules sind heute Files im Volume. Für Nachvollziehbarkeit:

- Jedes Rule-Set in Git (bereits halb da via `sync-to-github.sh`).
- Parallel Metriken in MLflow/DVC: welche Rule hat wie viele Hits
in der Suricata-Produktion (gibt's zwar nicht, aber in unserer
Honeypot-Fabric als Näherung), welcher Generator-Model-Run hat
welche Rules erzeugt.
- Hitrate-getriebener Feedback-Loop: nach 14 Tagen Rules mit
`hits=0 AND age>14d` automatisch in `archive/deprecated/` schieben.

### 3.3 Adversarial-Testing der Honeypot-Antworten
Wir simulieren Angreifer selbst – zweiter Ollama-Agent (klein, z. B.
`llama3.2:3b`) bekommt Session-Kontext und prüft, ob die vom
Haupt-Honeypot generierte Antwort „glaubwürdig" ist. Score als
zusätzliches Signal in den RL-Loop (Absatz 2.3).

### 3.4 Dashboards erweitern
Drei neue Panels im CVE-Dashboard:

- **Rule-Yield-Rate**: Sessions-per-CVE vs. Rules-per-CVE pro Woche.
- **Model-Disagreement-Heatmap**: Heuristik vs. Classifier.
- **Reward-Distribution**: Histogramm `total_reward` (sollte
rechtslastig verschoben sein, wenn wir besser werden).

---

## 4. Modell-Entscheidung – kurz

**TL;DR**: `openchat` behalten für Honeypot-Responses, aber für
**Rule-Generation** auf `qwen2.5-coder:7b` wechseln und einen
**Validator-Call** mit `llama3.1:8b` dazwischen setzen. Das ist der
größte Qualitätshebel bei kleinstem Ressourcen-Preis (alle drei
Modelle laufen schon auf `<ai-workstation>`).

Wenn das zufriedenstellend läuft, experimentell `qwen2.5:14b-instruct`
herunterladen und A/B gegen 7B – lohnt sich nur, wenn VRAM reicht.

---

## 5. Reihenfolge / Empfohlener Ablauf

1. **Sofort**: 1.4 Panel-Zeitraum fixen (5 min UI-Änderung).
2. **Woche 1**: 1.1 Periodogramm + 1.2 DNS-Payload-Entropy + 2.1 Task-Model-Split
für `rule_generator.py`.
3. **Woche 2**: 2.2 Validator-Stage, 2.4 Rule-Dedupe.
4. **Woche 3–4**: 1.3 IsolationForest-Baseline + 3.1 LightGBM-Classifier.
5. **Woche 5+**: 2.3 Echter RL-Reward, 3.3 Adversarial-Agent, 3.4 Dashboards.

---

## 6. Dokumentation-Hooks

- `docs/results.md` – nach jeder größeren Änderung neue Zeile mit
Metriken (mean composite_score, rule_count, ok_rate).
- `rules/README.md` – bei Model-Umstellung vermerken, mit welchem
Generator-Modell und Validator-Modell jede Rule erzeugt wurde.
- `notion` – High-Level-Zusammenfassung pro Phase.
