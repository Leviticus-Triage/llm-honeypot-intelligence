from proxy.src.task_router import DEFAULT_TASK_OPTIONS, TaskRouter


def _router() -> TaskRouter:
    return TaskRouter(config={})


def test_explicit_task_via_header_resolves_model():
    router = _router()
    body = {"model": "caller-model", "options": {}}
    decision = router.apply({"x-llm-task": "rule_generate"}, body)

    assert decision.explicit is True
    assert decision.task == "rule_generate"
    assert body["model"] == "qwen2.5-coder:7b"
    assert decision.resolved_model == "qwen2.5-coder:7b"


def test_implicit_task_falls_back_without_model_override():
    router = _router()
    body = {"model": "legacy-model", "options": {}}
    decision = router.apply({}, body)

    assert decision.explicit is False
    assert decision.task == router.default_task
    assert body["model"] == "legacy-model"
    assert decision.resolved_model == "legacy-model"


def test_caller_options_win_on_conflict():
    router = _router()
    body = {"model": "foo", "options": {"temperature": 0.99}}
    router.apply({"x-llm-task": "honeypot_response"}, body)

    assert body["options"]["temperature"] == 0.99
    assert body["options"]["num_ctx"] == DEFAULT_TASK_OPTIONS["honeypot_response"]["num_ctx"]


def test_keep_alive_injected_only_when_missing():
    router = _router()

    body_missing = {"model": "foo", "options": {}}
    router.apply({"x-llm-task": "rule_validate"}, body_missing)
    assert body_missing["keep_alive"] == "15m"

    body_present = {"model": "foo", "options": {}, "keep_alive": "1m"}
    router.apply({"x-llm-task": "rule_validate"}, body_present)
    assert body_present["keep_alive"] == "1m"


def test_routing_timeout_uses_per_task_value():
    router = _router()
    body = {"model": "foo", "options": {}}
    decision = router.apply({"x-llm-task": "rule_generate"}, body)
    assert decision.timeout == 240.0


def test_system_anchor_injection_only_when_no_system():
    """Router must NOT clobber a caller-provided system message, but must
    insert the anchor as a fallback when none is present. This defends
    the invariant documented in Anhang L (exactly one source of truth
    for the persona per request)."""
    router = _router()

    with_system = {
        "messages": [
            {"role": "system", "content": "existing"},
            {"role": "user", "content": "id"},
        ],
        "model": "foo",
        "options": {},
    }
    router.apply({"x-llm-task": "honeypot_response"}, with_system)
    assert with_system["messages"][0]["content"] == "existing"
    assert len(with_system["messages"]) == 2  # nothing was added

    without_system = {
        "messages": [{"role": "user", "content": "id"}],
        "model": "foo",
        "options": {},
    }
    decision = router.apply({"x-llm-task": "honeypot_response"}, without_system)
    assert without_system["messages"][0]["role"] == "system"
    assert without_system["messages"][0]["content"]  # non-empty
    assert "system_anchor" in decision.applied_option_defaults


def test_system_anchor_not_injected_for_non_primary_tasks():
    """Only honeypot_response has a fallback anchor; other tasks either
    don't need one (rule_validate supplies its own) or must stay
    pass-through (rule_dedupe_embed, offline_classify)."""
    router = _router()
    body = {"messages": [{"role": "user", "content": "x"}], "options": {}}
    decision = router.apply({"x-llm-task": "rule_validate"}, body)
    assert all(m["role"] != "system" for m in body["messages"])
    assert "system_anchor" not in decision.applied_option_defaults


def test_system_anchor_not_injected_for_embeddings():
    # /api/embeddings payloads do not contain "messages"; router should not add any.
    router = _router()
    body = {"model": "nomic-embed-text", "prompt": "abc"}
    router.apply({"x-llm-task": "rule_dedupe_embed"}, body)

    assert "messages" not in body
