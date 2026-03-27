// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260325_1358
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-25"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "445"
        unique_patterns = "12"
    strings:
        $s0 = "dmidecode -s processor-version 2>/dev/null" ascii nocase
        $s1 = "cat /proc/cpuinfo" ascii nocase
        $s2 = "last 2>/dev/null" ascii nocase
        $s3 = "uname -a" ascii nocase
        $s4 = "uname -p 2>/dev/null" ascii nocase
        $s5 = "gpu_info=$( (lspci 2>/dev/null" ascii nocase
        $s6 = "uname -s -v -n -m 2>/dev/null" ascii nocase
        $s7 = "echo \"GPU:$gpu_info" ascii nocase
        $s8 = "nproc 2>/dev/null" ascii nocase
        $s9 = "uname -m 2>/dev/null" ascii nocase
        $s10 = "cat /proc/uptime 2>/dev/null" ascii nocase
        $s11 = "echo \"LAST:$last_output" ascii nocase
    condition:
        any of them
}

rule Honeypot_DataCollection {
    meta:
        description = "LLM Honeypot Intelligence - DataCollection pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-25"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "1"
    strings:
        $s0 = "locate D877F783D5D3EF8Cs" ascii nocase
    condition:
        any of them
}