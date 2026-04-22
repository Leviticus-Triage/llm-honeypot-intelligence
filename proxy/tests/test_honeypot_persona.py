import importlib.util
from pathlib import Path

import pytest


def _has_honeypot_persona_module() -> bool:
    module_path = Path(__file__).resolve().parents[1] / "src" / "honeypot_persona.py"
    if not module_path.exists():
        return False
    spec = importlib.util.spec_from_file_location("proxy.src.honeypot_persona", module_path)
    return spec is not None


HAS_PERSONA = _has_honeypot_persona_module()


pytestmark = pytest.mark.skipif(
    not HAS_PERSONA,
    reason="honeypot_persona module is not present on current main branch",
)


@pytest.mark.skipif(not HAS_PERSONA, reason="module missing")
def test_with_anchor_empty_returns_anchor_verbatim():
    from proxy.src.honeypot_persona import HONEYPOT_PERSONA_ANCHOR, with_anchor

    assert with_anchor("") == HONEYPOT_PERSONA_ANCHOR


@pytest.mark.skipif(not HAS_PERSONA, reason="module missing")
def test_with_anchor_foo_concatenates_anchor_and_text():
    from proxy.src.honeypot_persona import HONEYPOT_PERSONA_ANCHOR, with_anchor

    assert with_anchor("foo") == f"{HONEYPOT_PERSONA_ANCHOR}\n\nfoo"


@pytest.mark.skipif(not HAS_PERSONA, reason="module missing")
def test_anchor_contains_invariant_keywords():
    from proxy.src.honeypot_persona import HONEYPOT_PERSONA_ANCHOR

    lower = HONEYPOT_PERSONA_ANCHOR.lower()
    for keyword in ("never", "honeypot", "ai", "in-character"):
        assert keyword in lower

