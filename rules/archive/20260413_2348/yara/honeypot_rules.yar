// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260413_2348
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-04-13"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "1005"
        unique_patterns = "12"
    strings:
        $s0 = "lspci" ascii nocase
        $s1 = "kill -9 $pid 2>/dev/null" ascii nocase
        $s2 = "lscpu" ascii nocase
        $s3 = "uptime -p" ascii nocase
        $s4 = "nproc --all" ascii nocase
        $s5 = "uname -m" ascii nocase
        $s6 = "uptime" ascii nocase
        $s7 = "nvidia-smi -q" ascii nocase
        $s8 = "uname -s -m" ascii nocase
        $s9 = "nproc" ascii nocase
        $s10 = "uname -n" ascii nocase
        $s11 = "uname -s -v -n -r -m" ascii nocase
    condition:
        any of them
}

rule Honeypot_Persistence {
    meta:
        description = "LLM Honeypot Intelligence - Persistence pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-04-13"
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
        date = "2026-04-13"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "121"
        unique_patterns = "12"
    strings:
        $s0 = "scp -qt \"/dev/shm/wxRxEdHR" ascii nocase
        $s1 = "scp -qt \"/tmp/YXgFiVHZ" ascii nocase
        $s2 = "scp -qt \"/dev/shm/tkuzdOqW" ascii nocase
        $s3 = "scp -qt \"/var/tmp/njEmzmlF" ascii nocase
        $s4 = "scp -qt \"/var/tmp/GTrPtNDL" ascii nocase
        $s5 = "scp -qt \"/tmp/naNirqoI" ascii nocase
        $s6 = "scp -qt \"/tmp/njEmzmlF" ascii nocase
        $s7 = "scp -qt \"/var/tmp/lCQUgUCQ" ascii nocase
        $s8 = "scp -qt \"/tmp/MGsSTmiJ" ascii nocase
        $s9 = "scp -qt \"/var/tmp/tkuzdOqW" ascii nocase
        $s10 = "scp -qt \"/tmp/eHZMJvMa" ascii nocase
        $s11 = "scp -qt \"/dev/shm/lCQUgUCQ" ascii nocase
    condition:
        any of them
}