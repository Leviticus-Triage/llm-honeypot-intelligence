// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260611_0809
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_CredentialTheft {
    meta:
        description = "LLM Honeypot Intelligence - CredentialTheft pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-11"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "6"
        unique_patterns = "2"
    strings:
        $s0 = "cat /etc/passwd 2>/dev/null" ascii nocase
        $s1 = "cat /etc/shadow 2>/dev/null" ascii nocase
    condition:
        any of them
}

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-11"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "927"
        unique_patterns = "12"
    strings:
        $s0 = "uname -r" ascii nocase
        $s1 = "ps aux" ascii nocase
        $s2 = "uptime" ascii nocase
        $s3 = "uname -a" ascii nocase
        $s4 = "cat /proc/cpuinfo" ascii nocase
        $s5 = "ip addr show 2>/dev/null" ascii nocase
        $s6 = "uname -m" ascii nocase
        $s7 = "cat /proc/version 2>/dev/null" ascii nocase
        $s8 = "uname -n" ascii nocase
        $s9 = "uname -s -m" ascii nocase
        $s10 = "whoami" ascii nocase
        $s11 = "nvidia-smi -q" ascii nocase
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
        event_count = "21"
        unique_patterns = "2"
    strings:
        $s0 = "crontab -r" ascii nocase
        $s1 = "systemctl list-units --type=service --state=running 2>/dev/null" ascii nocase
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
        event_count = "125"
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