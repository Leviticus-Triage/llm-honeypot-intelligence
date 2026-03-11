// LLM Honeypot Intelligence Platform - YARA Rules
// Generated: 20260215_1349
// Source: Elasticsearch honeypot data (24h window)

rule Honeypot_SystemRecon {
    meta:
        description = "LLM Honeypot Intelligence - SystemRecon pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-02-15"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "12201"
        unique_patterns = "12"
    strings:
        $s0 = "ps -ef" ascii nocase
        $s1 = "kill -9 $pid 2>/dev/null" ascii nocase
        $s2 = "uname -s -v -n -m 2>/dev/null" ascii nocase
        $s3 = "cat /proc/uptime 2>/dev/null" ascii nocase
        $s4 = "echo \"UNAME:$uname" ascii nocase
        $s5 = "echo \"UPTIME:$uptime" ascii nocase
        $s6 = "ifconfig" ascii nocase
        $s7 = "lscpu" ascii nocase
        $s8 = "uname -p 2>/dev/null" ascii nocase
        $s9 = "lscpu 2>/dev/null" ascii nocase
        $s10 = "uname -n" ascii nocase
        $s11 = "grep -i nvidia) 2>/dev/null" ascii nocase
    condition:
        any of them
}

rule Honeypot_Persistence {
    meta:
        description = "LLM Honeypot Intelligence - Persistence pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-02-15"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "9"
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
        date = "2026-02-15"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "50"
        unique_patterns = "12"
    strings:
        $s0 = "scp -qt \"/dev/shm/xLhGRxQJ" ascii nocase
        $s1 = "scp -qt \"/tmp/akPIGbtN" ascii nocase
        $s2 = "scp -qt \"/var/tmp/hEAdmLis" ascii nocase
        $s3 = "scp -qt \"/tmp/HLttdLAF" ascii nocase
        $s4 = "scp -qt \"/dev/shm/PwKWbHBM" ascii nocase
        $s5 = "scp -qt \"/tmp/xLhGRxQJ" ascii nocase
        $s6 = "scp -qt \"/dev/shm/HLttdLAF" ascii nocase
        $s7 = "scp -qt \"/dev/shm/ghWWWucC" ascii nocase
        $s8 = "scp -qt \"/dev/shm/hEAdmLis" ascii nocase
        $s9 = "curl ipinfo.io/org" ascii nocase
        $s10 = "scp -qt \"/tmp/WmGQnzhU" ascii nocase
        $s11 = "scp -qt \"/dev/shm/xMqUsaGY" ascii nocase
    condition:
        any of them
}

rule Honeypot_DataCollection {
    meta:
        description = "LLM Honeypot Intelligence - DataCollection pattern detection"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-02-15"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "2"
        unique_patterns = "1"
    strings:
        $s0 = "locate D877F783D5D3EF8Cs" ascii nocase
    condition:
        any of them
}

rule Honeypot_HTTP_MalwareDownload {
    meta:
        description = "LLM Honeypot Intelligence - HTTP Malware download URLs"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-02-15"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "3"
    strings:
        $u0 = "https://rifserp.oss-ap-southeast-1.aliyuncs.com/kuaiian-34.zip" ascii nocase
        $u1 = "https://zmnop7ut.oss-cn-hongkong.aliyuncs.com/kuaiian-34.zip" ascii nocase
        $u2 = "https://lkuaisliesn.oss-cn-hongkong.aliyuncs.com/kuailenesipc_64.zip" ascii nocase
    condition:
        any of them
}

rule Honeypot_HTTP_ConfigTheft {
    meta:
        description = "LLM Honeypot Intelligence - HTTP Configuration file theft paths"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-02-15"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "8"
    strings:
        $u0 = "/.env.local" ascii nocase
        $u1 = "/app/.env" ascii nocase
        $u2 = "/config.json" ascii nocase
        $u3 = "/.env.development" ascii nocase
        $u4 = "/.env.production" ascii nocase
        $u5 = "/.aws/credentials" ascii nocase
        $u6 = "/.env" ascii nocase
        $u7 = "/.env.staging" ascii nocase
    condition:
        any of them
}

rule Honeypot_HTTP_WebRCE {
    meta:
        description = "LLM Honeypot Intelligence - HTTP Remote code execution attempt paths"
        author = "LLM Honeypot Intelligence Platform"
        date = "2026-02-15"
        source = "honeypot_auto_generated"
        confidence = "high"
        event_count = "6"
    strings:
        $u0 = "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh" ascii nocase
        $u1 = "/demo/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" ascii nocase
        $u2 = "/vendor/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" ascii nocase
        $u3 = "/cgi-bin/luci/" ascii nocase
        $u4 = "/workspace/drupal/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" ascii nocase
        $u5 = "/phpunit/src/Util/PHP/eval-stdin.php" ascii nocase
    condition:
        any of them
}