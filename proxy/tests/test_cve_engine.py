from proxy.src.cve_engine import CVEEngine


def test_enhance_messages_replaces_system_with_profile_prompt():
    engine = CVEEngine(enabled=True)
    src_ip = "203.0.113.10"
    messages = [
        {"role": "system", "content": "caller system"},
        {"role": "user", "content": "hello"},
    ]

    enhanced, profile = engine.enhance_messages(messages, src_ip)

    assert profile is not None
    assert enhanced[0]["role"] == "system"
    assert enhanced[0]["content"] == profile.system_prompt
    assert enhanced[0]["content"] != "caller system"


def test_enhance_messages_replaces_caller_system_anchor_wins():
    engine = CVEEngine(enabled=True)
    src_ip = "203.0.113.11"
    messages = [
        {"role": "system", "content": "As an AI, I cannot..."},
        {"role": "user", "content": "id"},
    ]

    enhanced, profile = engine.enhance_messages(messages, src_ip)

    assert profile is not None
    assert enhanced[0]["role"] == "system"
    assert enhanced[0]["content"] == profile.system_prompt
    assert "As an AI, I cannot" not in enhanced[0]["content"]


def test_enhance_messages_inserts_system_when_missing_at_index_zero():
    engine = CVEEngine(enabled=True)
    src_ip = "203.0.113.12"
    messages = [{"role": "user", "content": "uname -a"}]

    enhanced, profile = engine.enhance_messages(messages, src_ip)

    assert profile is not None
    assert enhanced[0]["role"] == "system"
    assert enhanced[0]["content"] == profile.system_prompt
    assert enhanced[1:] == messages
