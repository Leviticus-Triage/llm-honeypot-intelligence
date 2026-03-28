// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260328_0937
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-28"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2847"
        unique_patterns = "12"
    strings:
        $s0 = "Hardware\" /proc/cpuinfo" ascii nocase
        $s1 = "ps -ef" ascii nocase
        $s2 = "grep -i nvidia) 2>/dev/null" ascii nocase
        $s3 = "lspci" ascii nocase
        $s4 = "uname -p 2>/dev/null" ascii nocase
        $s5 = "/bin/./uname -s -v -n -r -m" ascii nocase
        $s6 = "ifconfig" ascii nocase
        $s7 = "echo \"UNAME:$uname" ascii nocase
        $s8 = "lscpu 2>/dev/null" ascii nocase
        $s9 = "last 2>/dev/null" ascii nocase
        $s10 = "echo \"LAST:$last_output" ascii nocase
        $s11 = "nvidia-smi -q" ascii nocase
    condition:
        any of them
}

rule Honeypot_ToolDownload {
    meta:
        description = "LLM Honeypot Intelligence - ToolDownload pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-28"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "5"
        unique_patterns = "3"
    strings:
        $s0 = "wget --no-check-certificate -qO- https://31.57.216.121/sh" ascii nocase
        $s1 = "curl -sk https://31.57.216.121/sh" ascii nocase
        $s2 = "scp -t /bin/xu43r3rhs64ruxlmet4ngmhj8z" ascii nocase
    condition:
        any of them
}

rule Honeypot_DataCollection {
    meta:
        description = "LLM Honeypot Intelligence - DataCollection pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-28"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "1"
    strings:
        $s0 = "locate D877F783D5D3EF8Cs" ascii nocase
    condition:
        any of them
}