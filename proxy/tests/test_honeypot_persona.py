from proxy.src.honeypot_persona import HONEYPOT_PERSONA_ANCHOR, with_anchor


def test_with_anchor_empty_returns_anchor_verbatim():
    assert with_anchor("") == HONEYPOT_PERSONA_ANCHOR
    assert with_anchor(None) == HONEYPOT_PERSONA_ANCHOR  # type: ignore[arg-type]


def test_with_anchor_strips_surrounding_whitespace_before_concat():
    assert with_anchor("  foo  ") == f"{HONEYPOT_PERSONA_ANCHOR}\n\nfoo"


def test_with_anchor_foo_concatenates_anchor_and_text():
    assert with_anchor("foo") == f"{HONEYPOT_PERSONA_ANCHOR}\n\nfoo"


def test_anchor_contains_invariant_keywords():
    """Regression guard: these substrings define the anchor's purpose.
    If any of them disappear, the anchor has drifted and may no longer
    defend against the adversarial probes we tested in Anhang L."""
    lower = HONEYPOT_PERSONA_ANCHOR.lower()
    for keyword in ("never", "honeypot", "ai", "in-character"):
        assert keyword in lower, f"missing anchor invariant: {keyword!r}"
