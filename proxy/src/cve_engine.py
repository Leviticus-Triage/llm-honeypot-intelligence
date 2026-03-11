"""
CVE Engine - Session routing, prompt enhancement, and CVE tagging.

Intercepts Ollama /api/chat requests and replaces/enhances the system prompt
with CVE-specific context so the LLM responds as a realistic vulnerable system.
"""

import logging
import re
import time
import threading
from dataclasses import dataclass, field
from typing import Optional

from .cve_templates import (
    ALL_CVE_PROFILES,
    SSH_PROFILES,
    HTTP_PROFILES,
    CVEProfile,
)

logger = logging.getLogger("ollama-proxy.cve-engine")


@dataclass
class CVESession:
    """Tracks a CVE profile assignment for an active session."""
    profile: CVEProfile
    src_ip: str
    first_seen: float
    last_seen: float
    request_count: int = 0
    commands: list[str] = field(default_factory=list)


class CVEEngine:
    """
    Routes honeypot sessions to CVE profiles and enhances LLM prompts.

    - Assigns each new session (by src_ip) a CVE profile
    - Replaces the default system prompt with CVE-specific instructions
    - Tags requests with CVE metadata for Elasticsearch indexing
    """

    SESSION_TIMEOUT = 300  # 5 minutes of inactivity = new session

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._sessions: dict[str, CVESession] = {}
        self._lock = threading.Lock()
        self._ssh_index = 0
        self._http_index = 0
        self._stats = {
            "sessions_created": 0,
            "pattern_matches": 0,
            "rotation_assigns": 0,
            "prompts_enhanced": 0,
        }

    @property
    def stats(self) -> dict:
        return {**self._stats, "active_sessions": len(self._sessions)}

    def _detect_protocol(self, messages: list[dict]) -> str:
        """Detect whether this is an SSH (Beelzebub) or HTTP (Galah) request."""
        system_msg = ""
        user_msg = ""
        for m in messages:
            if m.get("role") == "system":
                system_msg += m.get("content", "")
            elif m.get("role") == "user":
                user_msg += m.get("content", "")

        combined = (system_msg + " " + user_msg).lower()

        # Galah sends HTTP context: method, URI, headers
        if any(kw in combined for kw in [
            "http request", "get /", "post /", "put /", "delete /",
            "host:", "user-agent:", "http/1.", "content-type:",
            "method:", "uri:", "headers:", "accept:",
        ]):
            return "http"

        return "ssh"

    def _match_pattern(self, text: str, profiles: list[CVEProfile]) -> Optional[CVEProfile]:
        """Match input text against CVE attack signatures."""
        for profile in profiles:
            for pattern in profile.attack_signatures:
                if re.search(pattern, text):
                    return profile
        return None

    def _rotate_profile(self, protocol: str) -> CVEProfile:
        """Round-robin select the next CVE profile for the given protocol."""
        with self._lock:
            if protocol == "ssh":
                if not SSH_PROFILES:
                    return ALL_CVE_PROFILES[0]
                profile = SSH_PROFILES[self._ssh_index % len(SSH_PROFILES)]
                self._ssh_index += 1
                return profile
            else:
                if not HTTP_PROFILES:
                    return ALL_CVE_PROFILES[0]
                profile = HTTP_PROFILES[self._http_index % len(HTTP_PROFILES)]
                self._http_index += 1
                return profile

    def _get_or_create_session(
        self, src_ip: str, messages: list[dict]
    ) -> CVESession:
        """Get existing session or create a new one for this src_ip."""
        now = time.time()

        # Check for existing active session
        if src_ip in self._sessions:
            session = self._sessions[src_ip]
            if now - session.last_seen < self.SESSION_TIMEOUT:
                session.last_seen = now
                session.request_count += 1
                return session
            # Session expired, remove it
            del self._sessions[src_ip]

        # Detect protocol
        protocol = self._detect_protocol(messages)

        # Extract text for pattern matching
        user_text = " ".join(
            m.get("content", "") for m in messages if m.get("role") == "user"
        )

        # Try pattern matching first
        pool = SSH_PROFILES if protocol == "ssh" else HTTP_PROFILES
        profile = self._match_pattern(user_text, pool)

        if profile:
            self._stats["pattern_matches"] += 1
            logger.info(
                "CVE pattern match: %s -> %s (%s)",
                src_ip[:15], profile.cve_id, profile.product,
            )
        else:
            # Rotation fallback
            profile = self._rotate_profile(protocol)
            self._stats["rotation_assigns"] += 1
            logger.info(
                "CVE rotation assign: %s -> %s (%s) [%s]",
                src_ip[:15], profile.cve_id, profile.product, protocol,
            )

        session = CVESession(
            profile=profile,
            src_ip=src_ip,
            first_seen=now,
            last_seen=now,
            request_count=1,
        )
        self._sessions[src_ip] = session
        self._stats["sessions_created"] += 1
        return session

    def enhance_messages(
        self, messages: list[dict], src_ip: str
    ) -> tuple[list[dict], Optional[CVEProfile]]:
        """
        Enhance the chat messages with CVE-specific system prompt.

        Returns (enhanced_messages, matched_profile).
        If engine is disabled, returns (original_messages, None).
        """
        if not self.enabled:
            return messages, None

        session = self._get_or_create_session(src_ip, messages)
        profile = session.profile

        # Track the user command for session history
        for m in messages:
            if m.get("role") == "user" and m.get("content"):
                cmd = m["content"][:200]
                if cmd not in session.commands[-5:] if session.commands else True:
                    session.commands.append(cmd)

        # Check if a different CVE pattern now matches better (mid-session pivot)
        if session.request_count > 1:
            user_text = " ".join(
                m.get("content", "") for m in messages if m.get("role") == "user"
            )
            protocol = self._detect_protocol(messages)
            pool = SSH_PROFILES if protocol == "ssh" else HTTP_PROFILES
            better_match = self._match_pattern(user_text, pool)
            if better_match and better_match.cve_id != profile.cve_id:
                logger.info(
                    "CVE mid-session pivot: %s -> %s (was %s)",
                    src_ip[:15], better_match.cve_id, profile.cve_id,
                )
                session.profile = better_match
                profile = better_match
                self._stats["pattern_matches"] += 1

        # Build enhanced messages
        enhanced = []
        system_replaced = False

        for msg in messages:
            if msg.get("role") == "system" and not system_replaced:
                # Replace the default system prompt with CVE-specific one
                enhanced.append({
                    "role": "system",
                    "content": profile.system_prompt,
                })
                system_replaced = True
            else:
                enhanced.append(msg)

        # If no system message existed, prepend one
        if not system_replaced:
            enhanced.insert(0, {
                "role": "system",
                "content": profile.system_prompt,
            })

        self._stats["prompts_enhanced"] += 1
        return enhanced, profile

    def get_session_info(self, src_ip: str) -> Optional[dict]:
        """Get current session info for an IP."""
        session = self._sessions.get(src_ip)
        if not session:
            return None
        return {
            "cve_id": session.profile.cve_id,
            "vendor": session.profile.vendor,
            "product": session.profile.product,
            "severity": session.profile.severity,
            "cvss_score": session.profile.cvss_score,
            "protocol": session.profile.protocol,
            "request_count": session.request_count,
            "commands": session.commands[-10:],
            "mitre_techniques": session.profile.mitre_techniques,
            "duration_seconds": time.time() - session.first_seen,
        }

    def cleanup_expired(self):
        """Remove expired sessions from memory."""
        now = time.time()
        expired = [
            ip for ip, s in self._sessions.items()
            if now - s.last_seen > self.SESSION_TIMEOUT * 2
        ]
        for ip in expired:
            del self._sessions[ip]
        if expired:
            logger.debug("Cleaned up %d expired CVE sessions", len(expired))

    def get_all_sessions(self) -> list[dict]:
        """Return all active sessions for monitoring."""
        result = []
        for ip, session in self._sessions.items():
            result.append({
                "src_ip": ip,
                "cve_id": session.profile.cve_id,
                "vendor": session.profile.vendor,
                "product": session.profile.product,
                "protocol": session.profile.protocol,
                "request_count": session.request_count,
                "first_seen": session.first_seen,
                "last_seen": session.last_seen,
                "commands": session.commands[-5:],
            })
        return result
