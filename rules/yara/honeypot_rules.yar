// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260610_1523
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_CredentialTheft {
    meta:
        description = "LLM Honeypot Intelligence - CredentialTheft pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-10"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "4"
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
        date = "2026-06-10"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "965"
        unique_patterns = "12"
    strings:
        $s0 = "uname -s -v -n -r -m" ascii nocase
        $s1 = "ip route show 2>/dev/null" ascii nocase
        $s2 = "cat /proc/cpuinfo" ascii nocase
        $s3 = "uname -s -m" ascii nocase
        $s4 = "nproc" ascii nocase
        $s5 = "kill -9 $pid 2>/dev/null" ascii nocase
        $s6 = "lspci" ascii nocase
        $s7 = "uname -r" ascii nocase
        $s8 = "uname -m" ascii nocase
        $s9 = "ps aux" ascii nocase
        $s10 = "hostname" ascii nocase
        $s11 = "uptime" ascii nocase
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
        event_count = "38"
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
        date = "2026-06-10"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "161"
        unique_patterns = "12"
    strings:
        $s0 = "scp -qt \"/var/tmp/hdDoVWiF" ascii nocase
        $s1 = "scp -qt \"/dev/shm/rQVchyAz" ascii nocase
        $s2 = "scp -qt \"/dev/shm/LWaDdmKD" ascii nocase
        $s3 = "scp -qt \"/tmp/YEssrtBj" ascii nocase
        $s4 = "scp -qt \"/tmp/yloGCuos" ascii nocase
        $s5 = "scp -qt \"/tmp/NCXUNYAO" ascii nocase
        $s6 = "scp -qt \"/tmp/hdDoVWiF" ascii nocase
        $s7 = "scp -qt \"/dev/shm/hdDoVWiF" ascii nocase
        $s8 = "scp -qt \"/dev/shm/EudxNXcS" ascii nocase
        $s9 = "scp -qt \"/dev/shm/WnqGShwL" ascii nocase
        $s10 = "scp -qt \"/dev/shm/xPznKZxY" ascii nocase
        $s11 = "scp -qt \"/var/tmp/bMDUJtYC" ascii nocase
    condition:
        any of them
}