from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


RULE_TYPE_BY_EXT: dict[str, str] = {
    ".yml": "sigma",
    ".yaml": "sigma",
    ".yar": "yara",
    ".yara": "yara",
    ".rules": "suricata",
    ".json": "stix",
}


@dataclass
class CheckResult:
    ok: bool
    rule_type: str
    issues: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)

    def add_issue(self, severity: str, category: str, message: str) -> None:
        self.issues.append({"severity": severity, "category": category, "message": message})
        if severity == "high":
            self.ok = False

    def add_warning(self, category: str, message: str) -> None:
        self.warnings.append({"severity": "low", "category": category, "message": message})


_SIGMA_REQUIRED_TOP = {"title", "logsource", "detection"}
_SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}


def check_sigma(text: str) -> CheckResult:
    res = CheckResult(ok=True, rule_type="sigma")

    try:
        from sigma.rule import SigmaRule  # type: ignore
        try:
            SigmaRule.from_yaml(text)
        except Exception as e:
            res.add_issue("high", "sigma_parse", f"pysigma parser rejected the rule: {e}")
            return res
    except ImportError:
        res.add_warning("missing_parser", "pysigma not installed; using structural fallback")

    try:
        import yaml
        data = yaml.safe_load(text)
    except Exception as e:
        res.add_issue("high", "yaml_parse", f"YAML parse error: {e}")
        return res

    if not isinstance(data, dict):
        res.add_issue("high", "yaml_parse", "Top-level YAML must be a mapping")
        return res

    missing = _SIGMA_REQUIRED_TOP - set(data.keys())
    if missing:
        res.add_issue("high", "sigma_schema", f"Missing required keys: {sorted(missing)}")

    logsource = data.get("logsource")
    if not isinstance(logsource, dict) or not any(
        k in logsource for k in ("product", "service", "category")
    ):
        res.add_issue("high", "sigma_schema", "logsource must have product/service/category")

    detection = data.get("detection")
    if not isinstance(detection, dict):
        res.add_issue("high", "sigma_schema", "detection block missing or not a mapping")
    else:
        if "condition" not in detection:
            res.add_issue("high", "sigma_schema", "detection.condition is missing")
        for name, sel in detection.items():
            if name == "condition":
                continue
            if sel in (None, {}, []):
                res.add_issue("medium", "sigma_schema", f"selection '{name}' is empty")

    level = data.get("level")
    if level and str(level).lower() not in _SIGMA_LEVELS:
        res.add_issue("medium", "sigma_schema", f"level '{level}' not in {sorted(_SIGMA_LEVELS)}")

    if "tags" in data and not isinstance(data["tags"], list):
        res.add_issue("low", "sigma_schema", "tags must be a list")

    return res


_YARA_RULE_RE = re.compile(r"(?ms)^\s*rule\s+(\w+)\s*(?::\s*[\w\s]+)?\s*\{(.*?)\n\}\s*$")
_YARA_STRINGS_RE = re.compile(r"(?s)^\s*strings\s*:\s*(.*?)(?=^\s*(?:condition|meta|strings)\s*:|\Z)", re.MULTILINE)
_YARA_CONDITION_RE = re.compile(r"(?s)^\s*condition\s*:\s*(.*?)(?=^\s*(?:meta|strings|condition)\s*:|\Z)", re.MULTILINE)


def check_yara(text: str) -> CheckResult:
    res = CheckResult(ok=True, rule_type="yara")

    matches = _YARA_RULE_RE.findall(text)
    if not matches:
        res.add_issue("high", "yara_parse", "No 'rule <name> { ... }' block found")
        return res

    seen_names: set[str] = set()
    for name, body in matches:
        if name in seen_names:
            res.add_issue("high", "yara_dup", f"Duplicate rule name: {name}")
        seen_names.add(name)

        if not _YARA_CONDITION_RE.search(body):
            res.add_issue("high", "yara_schema", f"rule '{name}': missing condition block")

        if body.count("{") != body.count("}"):
            res.add_issue("high", "yara_parse", f"rule '{name}': unbalanced braces")

        sm = _YARA_STRINGS_RE.search(body)
        if sm:
            strings_body = sm.group(1)
            for lineno, line in enumerate(strings_body.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("//"):
                    continue
                if not re.match(r"^\$[A-Za-z0-9_]+\s*=", stripped):
                    res.add_issue(
                        "medium",
                        "yara_strings",
                        f"rule '{name}' strings line {lineno} does not match '$id = ...': {stripped[:60]}",
                    )

    return res


_SURICATA_ACTION = r"(alert|drop|reject|pass|log)"
_SURICATA_PROTO = r"(tcp|udp|icmp|ip|http|tls|dns|ssh|ftp|smtp|snmp|dhcp|ikev2|smb|nfs|ntp|tftp|modbus|dnp3|enip|sip|krb5|rdp|rfb|imap|pop3|ja3|ja4)"
_SURICATA_RULE_RE = re.compile(
    r"^\s*" + _SURICATA_ACTION + r"\s+" + _SURICATA_PROTO +
    r"\s+\S+\s+\S+\s+(->|<>|<-)\s+\S+\s+\S+\s*\((.*)\)\s*$",
    re.IGNORECASE,
)
_SURICATA_REQUIRED_OPTS = {"sid", "msg"}


def check_suricata(text: str) -> CheckResult:
    res = CheckResult(ok=True, rule_type="suricata")

    rules = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not rules:
        res.add_issue("high", "suricata_parse", "File contains no non-comment lines")
        return res

    seen_sids: set[str] = set()
    for lineno, line in enumerate(rules, 1):
        m = _SURICATA_RULE_RE.match(line)
        if not m:
            res.add_issue("high", "suricata_parse", f"line {lineno}: does not match rule shape")
            continue

        opts = m.group(4)
        opts_lower = opts.lower()
        missing = [k for k in _SURICATA_REQUIRED_OPTS if k + ":" not in opts_lower]
        if missing:
            res.add_issue("high", "suricata_schema", f"line {lineno}: missing options {missing}")

        sid_match = re.search(r"sid\s*:\s*(\d+)", opts)
        if sid_match:
            sid = sid_match.group(1)
            if sid in seen_sids:
                res.add_issue("high", "suricata_dup", f"line {lineno}: duplicate sid {sid}")
            seen_sids.add(sid)
            if int(sid) < 1000000:
                res.add_warning("suricata_sid_range", f"line {lineno}: sid {sid} below local range (>=1_000_000)")

    return res


def check_stix(text: str) -> CheckResult:
    res = CheckResult(ok=True, rule_type="stix")

    import json
    try:
        data = json.loads(text)
    except Exception as e:
        res.add_issue("high", "stix_parse", f"JSON parse error: {e}")
        return res

    try:
        import stix2  # type: ignore
        try:
            if isinstance(data, dict) and data.get("type") == "bundle":
                stix2.parse(data, allow_custom=True)
            else:
                res.add_issue("high", "stix_schema", "Top-level object is not a STIX bundle")
        except Exception as e:
            res.add_issue("high", "stix_parse", f"stix2 parser rejected the bundle: {e}")
            return res
    except ImportError:
        res.add_warning("missing_parser", "stix2 not installed; using structural fallback")

    if not isinstance(data, dict) or data.get("type") != "bundle":
        res.add_issue("high", "stix_schema", "Top-level object is not a STIX bundle")
        return res
    if "objects" not in data or not isinstance(data["objects"], list):
        res.add_issue("high", "stix_schema", "bundle.objects missing or not a list")
    else:
        for idx, obj in enumerate(data["objects"]):
            if not isinstance(obj, dict) or "type" not in obj or "id" not in obj:
                res.add_issue("high", "stix_schema", f"object[{idx}] missing type/id")

    return res


_CHECKS: dict[str, Callable[[str], CheckResult]] = {
    "sigma": check_sigma,
    "yara": check_yara,
    "suricata": check_suricata,
    "stix": check_stix,
}


def detect_rule_type(path: Path | str, text: str | None = None) -> str | None:
    path = Path(path)
    t = RULE_TYPE_BY_EXT.get(path.suffix.lower())
    if t:
        if t == "stix" and text is not None and '"type": "bundle"' not in text:
            return None
        return t
    return None


def validate_rule(text: str, rule_type: str) -> CheckResult:
    checker = _CHECKS.get(rule_type)
    if checker is None:
        res = CheckResult(ok=False, rule_type=rule_type)
        res.add_issue("high", "unknown_type", f"No static checker for rule type '{rule_type}'")
        return res
    return checker(text)
