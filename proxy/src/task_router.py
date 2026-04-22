"""
Task-Router for Ollama-Proxy
----------------------------
Maps logical "tasks" (honeypot_response, rule_generate, rule_validate, ...)
to concrete Ollama models + option defaults + timeouts.

Design goals:
- Non-invasive: if no task is specified, the request is forwarded unchanged.
  Existing honeypot traffic (model="openchat") behaves exactly as before.
- Explicit override: callers set either the `X-LLM-Task` HTTP header,
  a top-level `_task` field, or `options.task` in the request body.
- Defaults merge: task-specific options (temperature, num_ctx, format, ...)
  are applied as defaults; caller values win when both are present.
- Self-cleaning: router-internal fields (`_task`, `options.task`) are stripped
  before the request is forwarded upstream, so Ollama never sees them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

logger = logging.getLogger("ollama-proxy.task_router")


DEFAULT_TASK_MODELS: dict[str, str] = {
    # ACTIVE — used by api_chat (honeypot traffic, implicit default).
    "honeypot_response": "openchat",
    # RESERVED — no in-tree caller yet. The current rule generation path
    # (`src/rule_generator.py`) is template-driven, not LLM-driven. Kept
    # here so a future LLM-backed generator can flip one header
    # (X-LLM-Task: rule_generate) and inherit model/options/timeout/
    # keep_alive without touching the router. If you remove this, also
    # remove the matching entries in DEFAULT_TASK_OPTIONS /
    # _TIMEOUTS / _KEEP_ALIVE below.
    "rule_generate": "qwen2.5-coder:7b",
    # ACTIVE — used by rule_validator.llm_judge.review_rule.
    "rule_validate": "llama3.1:8b",
    # ACTIVE — used by rule_validator.dedupe (embeddings).
    "rule_dedupe_embed": "nomic-embed-text",
    # RESERVED — no in-tree caller yet. Placeholder for the offline
    # classifier phase (Roadmap 3.1 follow-up). Currently the classifier
    # runs purely on LightGBM/RandomForest features, no LLM fallback. If
    # you remove this, also drop the matching option/timeout/keep_alive.
    "offline_classify": "dolphin-llama3:8b",
    # ACTIVE — used by adversarial_judge.judge_response. Small, fast
    # model that rates honeypot-response realism. Runs out-of-band from
    # the reward aggregator, so it must NOT block real traffic.
    "adversarial_critique": "llama3.2:3b",
}

DEFAULT_TASK_OPTIONS: dict[str, dict[str, Any]] = {
    "honeypot_response": {
        # Keep current behaviour; honeypots already send their own options.
        # These only kick in when the caller omits them.
        "temperature": 0.7,
        "num_ctx": 4096,
    },
    "rule_generate": {
        "temperature": 0.1,
        "top_p": 0.9,
        "num_ctx": 8192,
        "format": "json",
    },
    "rule_validate": {
        "temperature": 0.0,
        "num_ctx": 8192,
        "format": "json",
    },
    "rule_dedupe_embed": {},
    "offline_classify": {
        "temperature": 0.2,
        "num_ctx": 4096,
        "format": "json",
    },
    "adversarial_critique": {
        "temperature": 0.0,
        "num_ctx": 4096,
        "format": "json",
    },
}

DEFAULT_TASK_TIMEOUTS: dict[str, float] = {
    # Worst-case including cold-load on a 12GB GPU where task-models are rotated
    # (measured: qwen2.5-coder cold-load ~127s, llama3.1:8b ~90s).
    "honeypot_response": 30.0,
    "rule_generate": 240.0,
    "rule_validate": 180.0,
    "rule_dedupe_embed": 15.0,
    "offline_classify": 180.0,
    # Small critic — cold-load llama3.2:3b is ~20-30s on a 12GB GPU.
    "adversarial_critique": 90.0,
}

# Ollama top-level `keep_alive` per task — how long the model stays resident in
# VRAM after the last request. Large values reduce cold-load thrashing when we
# bounce between tasks/models on the same GPU.
DEFAULT_TASK_KEEP_ALIVE: dict[str, str] = {
    "honeypot_response": "30m",
    "rule_generate": "15m",
    "rule_validate": "15m",
    "rule_dedupe_embed": "30m",
    "offline_classify": "10m",
    "adversarial_critique": "10m",
}


# System-prompt anchor per task. The router only injects these as a FALLBACK
# — specifically when the request has no system message at all. For tasks
# whose callers already construct their own rich system prompt (rule_validate
# via SYSTEM_PROMPT, adversarial_critique via _SYSTEM_PROMPT), the router
# must NOT override or duplicate. For honeypot_response, the CVE engine owns
# the system prompt on the cache-miss path and composes it WITH the anchor
# (see cve_engine.enhance_messages + honeypot_persona.with_anchor). The
# router here is the fallback for the less common case of traffic that
# bypasses the CVE engine entirely (e.g. dev smoke tests against the proxy
# with no CVE profile match).
#
# Rule: if a caller already supplies a system message, leave it alone.
DEFAULT_TASK_SYSTEM_PROMPTS: dict[str, str] = {}
try:
    # Imported lazily to avoid a hard import cycle on module load order.
    from .honeypot_persona import HONEYPOT_PERSONA_ANCHOR as _ANCHOR
    DEFAULT_TASK_SYSTEM_PROMPTS["honeypot_response"] = _ANCHOR
except ImportError:  # pragma: no cover — module always ships together
    pass


@dataclass(frozen=True)
class RoutingDecision:
    task: str
    explicit: bool
    original_model: str
    resolved_model: str
    timeout: Optional[float]
    applied_option_defaults: list[str]

    def log_line(self) -> str:
        tag = "explicit" if self.explicit else "default"
        if self.original_model != self.resolved_model:
            model_part = f"{self.original_model}->{self.resolved_model}"
        else:
            model_part = self.resolved_model
        opts = ",".join(self.applied_option_defaults) if self.applied_option_defaults else "-"
        return f"task={self.task} ({tag}) model={model_part} timeout={self.timeout} opts_added=[{opts}]"


class TaskRouter:
    """Resolve (headers, body) -> routing decision and mutate body in place."""

    HEADER_NAME = "x-llm-task"

    def __init__(self, config: Mapping[str, Any]):
        user_models = dict(config.get("task_models") or {})
        user_options = dict(config.get("task_options") or {})
        user_timeouts = dict(config.get("task_timeouts") or {})

        self.task_models: dict[str, str] = {**DEFAULT_TASK_MODELS, **user_models}
        self.task_options: dict[str, dict[str, Any]] = {
            **{k: dict(v) for k, v in DEFAULT_TASK_OPTIONS.items()},
            **{k: dict(v) for k, v in user_options.items()},
        }
        self.task_timeouts: dict[str, float] = {**DEFAULT_TASK_TIMEOUTS, **user_timeouts}
        user_keep_alive = dict(config.get("task_keep_alive") or {})
        self.task_keep_alive: dict[str, str] = {**DEFAULT_TASK_KEEP_ALIVE, **user_keep_alive}
        user_system_prompts = dict(config.get("task_system_prompts") or {})
        self.task_system_prompts: dict[str, str] = {
            **DEFAULT_TASK_SYSTEM_PROMPTS, **user_system_prompts
        }
        self.default_task: str = str(config.get("default_task") or "honeypot_response")

        logger.info(
            "TaskRouter initialised: tasks=%s default=%s",
            sorted(self.task_models.keys()),
            self.default_task,
        )

    def _detect_task(self, headers: Mapping[str, str], body: dict) -> Tuple[Optional[str], bool]:
        header_val = None
        try:
            header_val = headers.get(self.HEADER_NAME)
        except AttributeError:
            for k, v in headers.items():
                if k.lower() == self.HEADER_NAME:
                    header_val = v
                    break
        if header_val:
            return header_val.strip(), True

        body_task = body.get("_task")
        if isinstance(body_task, str) and body_task.strip():
            return body_task.strip(), True

        opts = body.get("options")
        if isinstance(opts, dict):
            opt_task = opts.get("task")
            if isinstance(opt_task, str) and opt_task.strip():
                return opt_task.strip(), True

        return None, False

    def apply(self, headers: Mapping[str, str], body: dict) -> RoutingDecision:
        """
        Mutate ``body`` in place: strip router fields, merge option defaults,
        optionally override ``model``. Return the routing decision for logging.
        """
        detected, explicit = self._detect_task(headers, body)
        task = detected if detected else self.default_task

        # Strip router-internal fields so they don't leak upstream
        body.pop("_task", None)
        opts = body.get("options")
        if isinstance(opts, dict):
            opts.pop("task", None)

        original_model = str(body.get("model") or "")
        mapped_model = self.task_models.get(task)
        resolved_model = original_model

        # Only override the model if the caller was explicit about the task.
        # This keeps legacy honeypot traffic 100% unchanged.
        if explicit and mapped_model:
            body["model"] = mapped_model
            resolved_model = mapped_model

        # Merge option defaults (caller wins on conflict).
        applied: list[str] = []
        defaults = self.task_options.get(task, {})
        if defaults:
            existing = body.get("options")
            if not isinstance(existing, dict):
                existing = {}
            for k, v in defaults.items():
                if k not in existing:
                    existing[k] = v
                    applied.append(k)
            if existing:
                body["options"] = existing

        # Top-level keep_alive default (caller wins if already set)
        if "keep_alive" not in body:
            keep = self.task_keep_alive.get(task)
            if keep:
                body["keep_alive"] = keep
                applied.append("keep_alive")

        # System-prompt fallback. ONLY inject when there is no system
        # message at all — otherwise we trust the caller / CVE engine
        # to have composed the correct one. The anchor is harmless on
        # endpoints that ignore messages (embeddings), but we also skip
        # injection entirely when "messages" is absent or not a list.
        messages = body.get("messages")
        if isinstance(messages, list):
            has_system = any(
                isinstance(m, dict) and m.get("role") == "system"
                for m in messages
            )
            if not has_system:
                anchor = self.task_system_prompts.get(task)
                if anchor:
                    messages.insert(0, {"role": "system", "content": anchor})
                    applied.append("system_anchor")

        timeout = self.task_timeouts.get(task)

        decision = RoutingDecision(
            task=task,
            explicit=explicit,
            original_model=original_model,
            resolved_model=resolved_model,
            timeout=timeout,
            applied_option_defaults=applied,
        )
        logger.info("ROUTE %s", decision.log_line())
        return decision
