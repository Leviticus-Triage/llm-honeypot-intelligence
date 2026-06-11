// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260611_1410
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-11"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "996"
        unique_patterns = "12"
    strings:
        $s0 = "lspci" ascii nocase
        $s1 = "uname -r" ascii nocase
        $s2 = "uname -m" ascii nocase
        $s3 = "nvidia-smi -q" ascii nocase
        $s4 = "echo cw > /tmp/d.log" ascii nocase
        $s5 = "ps aux" ascii nocase
        $s6 = "uptime" ascii nocase
        $s7 = "nproc" ascii nocase
        $s8 = "uname -a" ascii nocase
        $s9 = "lscpu" ascii nocase
        $s10 = "kill -9 $pid 2>/dev/null" ascii nocase
        $s11 = "uname -n" ascii nocase
    condition:
        any of them
}

rule Honeypot_Persistence {
    meta:
        description = "LLM Honeypot Intelligence - Persistence pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-11"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "19"
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
        date = "2026-06-11"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "136"
        unique_patterns = "12"
    strings:
        $s0 = "scp -qt \"/var/tmp/isAjkxaK" ascii nocase
        $s1 = "scp -qt \"/var/tmp/uQKhLBsT" ascii nocase
        $s2 = "scp -qt \"/dev/shm/WYapxxyu" ascii nocase
        $s3 = "curl ipinfo.io/org" ascii nocase
        $s4 = "scp -qt \"/tmp/isAjkxaK" ascii nocase
        $s5 = "scp -qt \"/var/tmp/bnvNKYGu" ascii nocase
        $s6 = "scp -qt \"/var/tmp/XUAcnsJa" ascii nocase
        $s7 = "scp -qt \"/var/tmp/rlZfzyaT" ascii nocase
        $s8 = "scp -qt \"/dev/shm/cjWesWdE" ascii nocase
        $s9 = "scp -qt \"/dev/shm/hhNXNRSh" ascii nocase
        $s10 = "scp -qt \"/dev/shm/puVVyWSc" ascii nocase
        $s11 = "scp -qt \"/dev/shm/bnvNKYGu" ascii nocase
    condition:
        any of them
}