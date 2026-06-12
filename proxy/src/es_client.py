"""Shared Elasticsearch HTTP client settings (TLS + auth)."""

from __future__ import annotations

import os
from typing import Union

import certifi
import httpx

VerifySetting = Union[bool, str]


def es_auth() -> httpx.BasicAuth | None:
    user = os.environ.get("ES_USER", "")
    password = os.environ.get("ES_PASS", "")
    if user and password:
        return httpx.BasicAuth(user, password)
    return None


def es_verify() -> VerifySetting:
    """TLS verification for T-Pot/nginx ES endpoints.

    Prefer ES_CA_BUNDLE (path to nginx/ES CA PEM). Falls back to certifi.
    Set ES_INSECURE=1 only for local dev without a CA file.
    """
    if os.environ.get("ES_INSECURE", "").lower() in ("1", "true", "yes"):
        return False
    return os.environ.get("ES_CA_BUNDLE") or certifi.where()


def es_client_kwargs(timeout: float = 30.0) -> dict:
    return {
        "timeout": timeout,
        "verify": es_verify(),
        "auth": es_auth(),
    }
