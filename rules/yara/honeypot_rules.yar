// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260302_0740
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-02"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "1106"
        unique_patterns = "12"
    strings:
        $s0 = "lspci 2>/dev/null" ascii nocase
        $s1 = "kill -9 $pid 2>/dev/null" ascii nocase
        $s2 = "nvidia-smi -q" ascii nocase
        $s3 = "echo \"UPTIME:$uptime" ascii nocase
        $s4 = "echo \"ARCH:$arch" ascii nocase
        $s5 = "echo \"GPU:$gpu_info" ascii nocase
        $s6 = "dmidecode -s processor-version 2>/dev/null" ascii nocase
        $s7 = "uname -s -v -n -r -m" ascii nocase
        $s8 = "Hardware\" /proc/cpuinfo" ascii nocase
        $s9 = "nproc 2>/dev/null" ascii nocase
        $s10 = "echo \"UNAME:$uname" ascii nocase
        $s11 = "uname -p 2>/dev/null" ascii nocase
    condition:
        any of them
}

rule Honeypot_Persistence {
    meta:
        description = "LLM Honeypot Intelligence - Persistence pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-02"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "11"
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
        date = "2026-03-02"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "119"
        unique_patterns = "12"
    strings:
        $s0 = "scp -qt \"/var/tmp/afwlZnfp" ascii nocase
        $s1 = "scp -qt \"/dev/shm/vowsGiID" ascii nocase
        $s2 = "scp -qt \"/dev/shm/QcYboytJ" ascii nocase
        $s3 = "scp -qt \"/dev/shm/uBJTtvJJ" ascii nocase
        $s4 = "scp -qt \"/tmp/JEhfkQaw" ascii nocase
        $s5 = "scp -qt \"/var/tmp/JEhfkQaw" ascii nocase
        $s6 = "scp -qt \"/dev/shm/LYWReJFh" ascii nocase
        $s7 = "scp -qt \"/var/tmp/whaUYKtW" ascii nocase
        $s8 = "scp -qt \"/dev/shm/PlZQJNQz" ascii nocase
        $s9 = "scp -qt \"/dev/shm/afwlZnfp" ascii nocase
        $s10 = "scp -qt \"/tmp/vowsGiID" ascii nocase
        $s11 = "scp -qt \"/dev/shm/JEhfkQaw" ascii nocase
    condition:
        any of them
}

rule Honeypot_HTTP_ConfigTheft {
    meta:
        description = "LLM Honeypot Intelligence - HTTP Configuration file theft paths"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-02"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
    strings:
        $u0 = "/.env.development" ascii nocase
        $u1 = "/www/.env.prod" ascii nocase
    condition:
        any of them
}