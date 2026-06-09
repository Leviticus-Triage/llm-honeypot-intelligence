// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260414_1148
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-04-14"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "1004"
        unique_patterns = "12"
    strings:
        $s0 = "uname -a" ascii nocase
        $s1 = "lspci" ascii nocase
        $s2 = "kill -9 $pid 2>/dev/null" ascii nocase
        $s3 = "lscpu" ascii nocase
        $s4 = "uptime -p" ascii nocase
        $s5 = "nproc --all" ascii nocase
        $s6 = "uname -m" ascii nocase
        $s7 = "uptime" ascii nocase
        $s8 = "nvidia-smi -q" ascii nocase
        $s9 = "uname -s -m" ascii nocase
        $s10 = "nproc" ascii nocase
        $s11 = "uname -n" ascii nocase
    condition:
        any of them
}

rule Honeypot_Persistence {
    meta:
        description = "LLM Honeypot Intelligence - Persistence pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-04-14"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "9"
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
        date = "2026-04-14"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "69"
        unique_patterns = "12"
    strings:
        $s0 = "scp -qt \"/dev/shm/wxRxEdHR" ascii nocase
        $s1 = "scp -qt \"/tmp/YXgFiVHZ" ascii nocase
        $s2 = "scp -qt \"/var/tmp/njEmzmlF" ascii nocase
        $s3 = "scp -qt \"/tmp/njEmzmlF" ascii nocase
        $s4 = "scp -qt \"/dev/shm/YXgFiVHZ" ascii nocase
        $s5 = "scp -qt \"/var/tmp/vstzwavn" ascii nocase
        $s6 = "scp -qt \"/var/tmp/wxRxEdHR" ascii nocase
        $s7 = "scp -qt \"/dev/shm/xOjPSMpn" ascii nocase
        $s8 = "scp -qt \"/var/tmp/YXgFiVHZ" ascii nocase
        $s9 = "scp -qt \"/tmp/xOjPSMpn" ascii nocase
        $s10 = "scp -qt \"/var/tmp/xOjPSMpn" ascii nocase
        $s11 = "scp -qt \"/tmp/wxRxEdHR" ascii nocase
    condition:
        any of them
}