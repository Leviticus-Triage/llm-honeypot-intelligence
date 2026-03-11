#!/bin/bash
# =============================================================================
# Setup attack_class runtime field in Elasticsearch
# =============================================================================
# This script adds a runtime field to the logstash-* index template that
# classifies each event as: mass_scanner, recon, targeted, or llm_engaged.
#
# Safe to re-run. Does not modify Logstash or existing data.
# Works at query time on ALL existing and future data.
#
# v2: Improved classification logic:
# - Beelzebub with output -> llm_engaged
# - Galah with response.body + msg:"successfulResponse" -> llm_engaged
# - Galah without response -> targeted (still an attack attempt)
# - More scanner IPs from known services
# - Non-honeypot types (Suricata, P0f, Fatt, NGINX) classified as recon
# =============================================================================

ES_URL="${ES_URL:-https://192.168.2.22:64297/es}"
ES_USER="${ES_USER:-exodus}"
ES_PASS="${ES_PASS:-3x0du5...!#}"

CURL="curl -sk -u ${ES_USER}:${ES_PASS}"

echo "=== Setting up attack_class runtime field (v2) ==="
echo "  ES: $ES_URL"

# The Painless script for runtime field classification
# Uses .keyword subfields for all text fields
RUNTIME_SCRIPT='String type = ""; if (doc.containsKey("type.keyword") && doc["type.keyword"].size() > 0) type = doc["type.keyword"].value; String src_ip = ""; if (doc.containsKey("src_ip.keyword") && doc["src_ip.keyword"].size() > 0) src_ip = doc["src_ip.keyword"].value; String ip_rep = ""; if (doc.containsKey("ip_rep.keyword") && doc["ip_rep.keyword"].size() > 0) ip_rep = doc["ip_rep.keyword"].value; boolean isLLM = type.equals("Beelzebub") || type.equals("Galah"); if (ip_rep.length() > 0 && (ip_rep.contains("mass scanner") || ip_rep.contains("bot"))) { emit("mass_scanner"); return; } if (src_ip.startsWith("71.6.135.") || src_ip.startsWith("71.6.146.") || src_ip.startsWith("71.6.147.") || src_ip.startsWith("71.6.158.") || src_ip.startsWith("71.6.199.") || src_ip.startsWith("162.142.125.") || src_ip.startsWith("167.94.") || src_ip.startsWith("167.248.") || src_ip.startsWith("198.235.24.") || src_ip.startsWith("206.168.34.") || src_ip.startsWith("35.203.") || src_ip.startsWith("34.118.") || src_ip.startsWith("34.100.") || src_ip.startsWith("64.62.197.") || src_ip.startsWith("205.210.31.") || src_ip.startsWith("74.82.47.") || src_ip.startsWith("184.105.") || src_ip.startsWith("66.240.192.") || src_ip.startsWith("66.240.205.") || src_ip.startsWith("78.128.113.") || src_ip.startsWith("80.82.77.") || src_ip.startsWith("93.120.27.") || src_ip.startsWith("94.102.49.") || src_ip.startsWith("185.142.236.") || src_ip.startsWith("198.20.69.") || src_ip.startsWith("198.20.70.") || src_ip.startsWith("198.20.87.") || src_ip.startsWith("198.20.99.")) { emit("mass_scanner"); return; } if (type.equals("Beelzebub")) { boolean hasOutput = doc.containsKey("output.keyword") && doc["output.keyword"].size() > 0; if (hasOutput) { emit("llm_engaged"); return; } boolean hasInput = doc.containsKey("input.keyword") && doc["input.keyword"].size() > 0; if (hasInput) { emit("targeted"); return; } emit("recon"); return; } if (type.equals("Galah")) { boolean hasBody = doc.containsKey("response.body.keyword") && doc["response.body.keyword"].size() > 0; String msg = ""; if (doc.containsKey("msg.keyword") && doc["msg.keyword"].size() > 0) msg = doc["msg.keyword"].value; if (hasBody && msg.equals("successfulResponse")) { emit("llm_engaged"); return; } emit("targeted"); return; } boolean hasInput = doc.containsKey("input.keyword") && doc["input.keyword"].size() > 0; if (hasInput) { emit("targeted"); return; } emit("recon");'

# Step 1: Create component template
echo ""
echo "1/3 Creating component template with attack_class runtime field..."

python3 -c "
import json, sys
script = '''$RUNTIME_SCRIPT'''
body = {'template': {'mappings': {'runtime': {'attack_class': {'type': 'keyword', 'script': {'source': script}}}}}}
print(json.dumps(body))
" | $CURL -X PUT "${ES_URL}/_component_template/attack_class_runtime" \
  -H 'Content-Type: application/json' \
  -d @-

echo ""

# Step 2: Apply directly to existing indices
echo "2/3 Applying runtime field to existing logstash-* indices..."

python3 -c "
import json
script = '''$RUNTIME_SCRIPT'''
body = {'runtime': {'attack_class': {'type': 'keyword', 'script': {'source': script}}}}
print(json.dumps(body))
" | $CURL -X PUT "${ES_URL}/logstash-*/_mapping" \
  -H 'Content-Type: application/json' \
  -d @-
echo ""

# Step 3: Add to index template for future indices
echo "3/3 Updating logstash index template..."

$CURL -X PUT "${ES_URL}/_index_template/logstash_with_attack_class" \
  -H 'Content-Type: application/json' \
  -d '{
  "index_patterns": ["logstash-*"],
  "composed_of": ["attack_class_runtime"],
  "priority": 200,
  "template": {
    "settings": {
      "number_of_shards": 1
    }
  }
}'
echo ""

# Test
echo ""
echo "=== Testing attack_class field ==="
RESULT=$($CURL -s "${ES_URL}/logstash-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d '{"aggs":{"by_class":{"terms":{"field":"attack_class","size":10}}}}')

echo "$RESULT" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for b in d.get('aggregations',{}).get('by_class',{}).get('buckets',[]):
    print(f'  {b[\"key\"]:20s} {b[\"doc_count\"]:>12,}')
" 2>&1

echo ""
echo "Done! attack_class field active on all logstash-* indices."
echo "Values: mass_scanner, recon, targeted, llm_engaged"
