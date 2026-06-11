// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260611_0209
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
        event_count = "926"
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
        event_count = "35"
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
        event_count = "158"
        unique_patterns = "12"
    strings:
        $s0 = "scp -qt \"/tmp/hllDiTEh" ascii nocase
        $s1 = "scp -qt \"/tmp/uiyZliqG" ascii nocase
        $s2 = "scp -qt \"/var/tmp/LijMNGmc" ascii nocase
        $s3 = "scp -qt \"/tmp/mTaAcjOR" ascii nocase
        $s4 = "scp -qt \"/tmp/gegrlQPR" ascii nocase
        $s5 = "scp -qt \"/var/tmp/XPrKPXZl" ascii nocase
        $s6 = "scp -qt \"/dev/shm/QKpRzdfK" ascii nocase
        $s7 = "scp -qt \"/tmp/zgkSAUeC" ascii nocase
        $s8 = "scp -qt \"/var/tmp/iABBYIfE" ascii nocase
        $s9 = "scp -qt \"/var/tmp/jltHvVFt" ascii nocase
        $s10 = "scp -qt \"/dev/shm/sQxeAikl" ascii nocase
        $s11 = "scp -qt \"/tmp/ptmgvGbk" ascii nocase
    condition:
        any of them
}