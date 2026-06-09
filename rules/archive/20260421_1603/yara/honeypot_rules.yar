// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260421_1603
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-04-21"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "1000"
        unique_patterns = "5"
    strings:
        $s0 = "uname -s -m" ascii nocase
        $s1 = "uname -m" ascii nocase
        $s2 = "uname -a" ascii nocase
        $s3 = "uname -s -v -n -r -m" ascii nocase
        $s4 = "/bin/./uname -s -v -n -r -m" ascii nocase
    condition:
        any of them
}