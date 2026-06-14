// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260614_0804
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-14"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2020"
        unique_patterns = "12"
    strings:
        $s0 = "echo \"GPU:$gpu_info" ascii nocase
        $s1 = "ls --help 2>&1" ascii nocase
        $s2 = "dmidecode -s processor-version 2>/dev/null" ascii nocase
        $s3 = "uname -m 2>/dev/null" ascii nocase
        $s4 = "nproc --all" ascii nocase
        $s5 = "nvidia-smi -q" ascii nocase
        $s6 = "nproc 2>/dev/null" ascii nocase
        $s7 = "which ps 2>/dev/null" ascii nocase
        $s8 = "/bin/./uname -s -v -n -r -m" ascii nocase
        $s9 = "uname -s -v -n -m 2>/dev/null" ascii nocase
        $s10 = "echo \"UPTIME:$uptime" ascii nocase
        $s11 = "cat /proc/uptime 2>/dev/null" ascii nocase
    condition:
        any of them
}

rule Honeypot_ToolDownload {
    meta:
        description = "LLM Honeypot Intelligence - ToolDownload pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-14"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "4"
        unique_patterns = "1"
    strings:
        $s0 = "curl -s --connect-timeout 2 ipinfo.io/country 2>/dev/null" ascii nocase
    condition:
        any of them
}