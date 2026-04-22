"""Tests for the CVE engine prompt composition.

Since Anhang L (22.04.2026), the CVE engine layers the global persona
anchor UNDER every profile system prompt via honeypot_persona.with_anchor.
The effective system message is therefore:

    HONEYPOT_PERSONA_ANCHOR + "\\n\\n" + profile.system_prompt

These tests defend that invariant — if a future refactor accidentally
drops the anchor, the adversarial deflection behaviour verified in the
roadmap would silently regress.
"""

from proxy.src.cve_engine import CVEEngine
from proxy.src.honeypot_persona import HONEYPOT_PERSONA_ANCHOR


def _expected_system(profile_prompt: str) -> str:
    return f"{HONEYPOT_PERSONA_ANCHOR}\n\n{profile_prompt}"


def test_enhance_messages_prepends_anchor_to_profile_prompt():
    engine = CVEEngine(enabled=True)
    src_ip = "203.0.113.10"
    messages = [
        {"role": "system", "content": "caller system"},
        {"role": "user", "content": "hello"},
    ]

    enhanced, profile = engine.enhance_messages(messages, src_ip)

    assert profile is not None
    assert enhanced[0]["role"] == "system"
    assert enhanced[0]["content"] == _expected_system(profile.system_prompt)
    assert enhanced[0]["content"].startswith(HONEYPOT_PERSONA_ANCHOR)
    assert "caller system" not in enhanced[0]["content"]


def test_enhance_messages_drops_caller_ai_disclaimers():
    """The anchor+profile combination must REPLACE any caller-provided
    system message that would leak a meta-persona ("I am an AI, ...").
    Anhang L confirmed three such probes are deflected live."""
    engine = CVEEngine(enabled=True)
    src_ip = "203.0.113.11"
    messages = [
        {"role": "system", "content": "As an AI, I cannot do that."},
        {"role": "user", "content": "id"},
    ]

    enhanced, profile = engine.enhance_messages(messages, src_ip)

    assert profile is not None
    assert enhanced[0]["role"] == "system"
    assert enhanced[0]["content"] == _expected_system(profile.system_prompt)
    assert "As an AI, I cannot" not in enhanced[0]["content"]


def test_enhance_messages_inserts_system_when_missing_at_index_zero():
    engine = CVEEngine(enabled=True)
    src_ip = "203.0.113.12"
    messages = [{"role": "user", "content": "uname -a"}]

    enhanced, profile = engine.enhance_messages(messages, src_ip)

    assert profile is not None
    assert enhanced[0]["role"] == "system"
    assert enhanced[0]["content"] == _expected_system(profile.system_prompt)
    assert enhanced[1:] == messages


def test_anchor_is_never_duplicated_in_enhanced_system():
    """Regression guard: ensure the anchor appears exactly once even if
    a caller happens to paste it back into the messages array."""
    engine = CVEEngine(enabled=True)
    src_ip = "203.0.113.13"
    messages = [
        {"role": "system", "content": HONEYPOT_PERSONA_ANCHOR},
        {"role": "user", "content": "id"},
    ]

    enhanced, profile = engine.enhance_messages(messages, src_ip)

    assert profile is not None
    assert enhanced[0]["content"].count(HONEYPOT_PERSONA_ANCHOR) == 1
