// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260402_0942
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_CredentialTheft {
    meta:
        description = "LLM Honeypot Intelligence - CredentialTheft pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-04-02"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "12"
        unique_patterns = "5"
    strings:
        $s0 = "rm -rf .ssh" ascii nocase
        $s1 = "chattr -ia .ssh" ascii nocase
        $s2 = "mkdir .ssh" ascii nocase
        $s3 = "chmod -R go= ~/.ssh" ascii nocase
        $s4 = "lockr -ia .ssh" ascii nocase
    condition:
        any of them
}

rule Honeypot_ToolDownload {
    meta:
        description = "LLM Honeypot Intelligence - ToolDownload pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-04-02"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "2"
    strings:
        $s0 = "wget --no-check-certificate -qO- https://31.57.216.121/sh" ascii nocase
        $s1 = "curl -sk https://31.57.216.121/sh" ascii nocase
    condition:
        any of them
}