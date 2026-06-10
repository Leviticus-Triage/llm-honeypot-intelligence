// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260610_0605
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-10"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "1015"
        unique_patterns = "12"
    strings:
        $s0 = "uname -n" ascii nocase
        $s1 = "ps aux" ascii nocase
        $s2 = "kill -9 $pid 2>/dev/null" ascii nocase
        $s3 = "nproc" ascii nocase
        $s4 = "uptime" ascii nocase
        $s5 = "uname -s -v -n -r -m" ascii nocase
        $s6 = "uname -m" ascii nocase
        $s7 = "nvidia-smi -q" ascii nocase
        $s8 = "uname -a" ascii nocase
        $s9 = "lscpu" ascii nocase
        $s10 = "lspci" ascii nocase
        $s11 = "uname -r" ascii nocase
    condition:
        any of them
}

rule Honeypot_Persistence {
    meta:
        description = "LLM Honeypot Intelligence - Persistence pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-10"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "39"
        unique_patterns = "1"
    strings:
        $s0 = "crontab -r" ascii nocase
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
        event_count = "172"
        unique_patterns = "12"
    strings:
        $s0 = "curl ipinfo.io/org" ascii nocase
        $s1 = "scp -qt \"/tmp/BNJlmgJt" ascii nocase
        $s2 = "scp -qt \"/dev/shm/qgKpOPqY" ascii nocase
        $s3 = "scp -qt \"/dev/shm/uPWFMCim" ascii nocase
        $s4 = "scp -qt \"/var/tmp/hdDoVWiF" ascii nocase
        $s5 = "scp -qt \"/var/tmp/QVNgdjAP" ascii nocase
        $s6 = "scp -qt \"/var/tmp/BNJlmgJt" ascii nocase
        $s7 = "scp -qt \"/var/tmp/hyQMmwro" ascii nocase
        $s8 = "scp -qt \"/var/tmp/LWaDdmKD" ascii nocase
        $s9 = "scp -qt \"/var/tmp/HPhlkviJ" ascii nocase
        $s10 = "scp -qt \"/dev/shm/ZpRQCSfY" ascii nocase
        $s11 = "scp -qt \"/tmp/qgKpOPqY" ascii nocase
    condition:
        any of them
}