#!/usr/bin/env bash
# Create ILM policy for logstash-noise-* indices (3-day retention). Run on T-Pot ECS after ES is up.
set -euo pipefail

ES_BASE="${ES_URL:-https://127.0.0.1:64297/es}"
ES_BASE="${ES_BASE%/es}"
ES_USER="${ES_USER:-}"
ES_PASS="${ES_PASS:-}"
CURL_AUTH=()
[[ -n "${ES_USER}" && -n "${ES_PASS}" ]] && CURL_AUTH=(-u "${ES_USER}:${ES_PASS}")

echo "[noise-ilm] Applying policy to ${ES_BASE} ..."

curl -fsSk "${CURL_AUTH[@]}" -X PUT "${ES_BASE}/_ilm/policy/logstash-noise-3d" \
  -H 'Content-Type: application/json' \
  -d '{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": { "max_age": "1d", "max_primary_shard_size": "10gb" }
        }
      },
      "delete": {
        "min_age": "3d",
        "actions": { "delete": {} }
      }
    }
  }
}'

curl -fsSk "${CURL_AUTH[@]}" -X PUT "${ES_BASE}/_index_template/logstash-noise-template" \
  -H 'Content-Type: application/json' \
  -d '{
  "index_patterns": ["logstash-noise-*"],
  "template": {
    "settings": {
      "index.lifecycle.name": "logstash-noise-3d",
      "index.lifecycle.rollover_alias": "logstash-noise",
      "number_of_shards": 1,
      "number_of_replicas": 0
    }
  },
  "priority": 200
}'

echo "[noise-ilm] done"
