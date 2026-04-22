import asyncio

from proxy.src import adversarial_judge as aj
from proxy.src import reward_aggregator as ra


def test_parse_judge_output_well_formed_json():
    raw = '{"plausibility": 0.87, "tells": ["none"]}'
    parsed = aj._parse_judge_output(raw)
    assert parsed is not None
    plausibility, tells = parsed
    assert plausibility == 0.87
    assert tells == ["none"]


def test_parse_judge_output_json_with_noise():
    raw = 'header noise {"plausibility": 0.55, "tells": ["minor format drift"]} footer noise'
    parsed = aj._parse_judge_output(raw)
    assert parsed is not None
    plausibility, tells = parsed
    assert plausibility == 0.55
    assert tells == ["minor format drift"]


def test_parse_judge_output_unparseable_returns_none():
    assert aj._parse_judge_output("<<< not json at all >>>") is None


def test_cache_hit_path_does_not_call_llm(monkeypatch):
    rec = ra.RewardRecord(
        session_id="s1",
        serve_log_id=1,
        response_id=1,
        response_hash="hash-1",
        model="openchat",
        cve_tag="CVE-2024-55591",
        reward_a=0.1,
        reward_b=0.2,
        reward_c=0.3,
        total_reward=0.2,
        ts=ra.datetime.now(ra.timezone.utc),
        prompt_text="whoami",
        response_text="root",
    )

    cached = aj.Judgement(
        response_hash="hash-1",
        plausibility=0.93,
        reasons=["looks real"],
        critic_model="llama3.2:3b",
    )

    monkeypatch.setattr(ra.aj, "JUDGE_ENABLED", True)
    monkeypatch.setattr(ra.aj, "JUDGE_BATCH_LIMIT", 100)
    monkeypatch.setattr(ra.aj, "JUDGE_TIMEOUT", 1)
    monkeypatch.setattr(ra, "DB_PATH", "/tmp/nonexistent.db")
    monkeypatch.setattr(ra.aj, "get_cached_judgement", lambda _db, _hash: cached)

    async def explode_if_called(*args, **kwargs):
        raise AssertionError("judge_response must not be called on cache hit")

    monkeypatch.setattr(ra.aj, "judge_response", explode_if_called)

    summary = asyncio.run(ra.judge_records([rec]))

    assert summary["enabled"] is True
    assert summary["hit"] == 1
    assert summary["miss"] == 0
    assert summary["judged"] == 0
    assert summary["errors"] == 0
    assert rec.plausibility_score == 0.93
