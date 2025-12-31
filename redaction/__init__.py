"""
Redaction Module - Data sanitization for AWS Log Sentinel

This module provides an extensible framework for redacting sensitive data
(PII, credentials, etc.) from log messages before returning them to AI agents.

Architecture:
    - RedactionEngine: Core engine that orchestrates redaction using profiles
    - ComplianceProfile: Abstract base class for compliance-specific rules
    - profiles/: Directory containing specific compliance implementations

Example:
    from redaction import RedactionEngine

    engine = RedactionEngine()
    safe_text, was_redacted = engine.redact("User email: john@example.com")
    # safe_text: "User email: {{EMAIL}}"
    # was_redacted: True
"""

from .engine import RedactionEngine
from .base_profile import ComplianceProfile

__all__ = ["RedactionEngine", "ComplianceProfile"]
