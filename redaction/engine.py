"""
RedactionEngine - Core engine for sanitizing sensitive data.

This engine orchestrates:
1. Scrubadub's built-in PII detection (emails, phone numbers, etc.)
2. Custom compliance profile patterns (credit cards, SSN, API keys, etc.)
3. Tracking of whether any redaction occurred

Thread-safe and designed for high-throughput log processing.
"""

import logging
from typing import Optional

import scrubadub

from .base_profile import ComplianceProfile
from .profiles import DEFAULT_PROFILE

logger = logging.getLogger(__name__)


class RedactionEngine:
    """
    Engine for sanitizing sensitive data from text.
    
    Uses a layered approach:
    1. First, apply scrubadub's built-in detectors (emails, phones, etc.)
    2. Then, apply custom patterns from loaded compliance profiles
    
    Example:
        engine = RedactionEngine()
        
        # Basic usage
        safe_text, was_redacted = engine.redact("Email: john@example.com")
        # safe_text: "Email: {{EMAIL}}"
        # was_redacted: True
        
        # With custom profile
        from redaction.profiles.india import IndiaProfile
        engine.load_profile(IndiaProfile())
        safe_text, _ = engine.redact("PAN: ABCDE1234F")
        # safe_text: "PAN: {{PAN_CARD}}"
    
    Thread Safety:
        The engine is thread-safe for the redact() method. However,
        load_profile() should only be called during initialization.
    """
    
    def __init__(self, load_default_profile: bool = True):
        """
        Initialize the RedactionEngine.
        
        Args:
            load_default_profile: If True, loads the US/Global profile by default.
                                  Set to False for a clean slate.
        """
        self._profiles: dict[str, ComplianceProfile] = {}
        self._scrubber = scrubadub.Scrubber()
        
        # Configure scrubadub with standard detectors
        # (email, phone, etc. are enabled by default)
        
        if load_default_profile:
            self.load_profile(DEFAULT_PROFILE)
    
    def load_profile(self, profile: ComplianceProfile) -> None:
        """
        Load a compliance profile into the engine.
        
        Args:
            profile: A ComplianceProfile instance to add.
        
        Note:
            If a profile with the same name already exists, it will be replaced.
        """
        self._profiles[profile.name] = profile
        logger.info(f"Loaded compliance profile: {profile.name}")
        
        # Add any custom scrubadub detectors from the profile
        for detector in profile.get_scrubadub_detectors():
            self._scrubber.add_detector(detector)
    
    def unload_profile(self, profile_name: str) -> bool:
        """
        Remove a compliance profile from the engine.
        
        Args:
            profile_name: The name of the profile to remove.
            
        Returns:
            True if profile was removed, False if not found.
        """
        if profile_name in self._profiles:
            del self._profiles[profile_name]
            logger.info(f"Unloaded compliance profile: {profile_name}")
            return True
        return False
    
    def list_profiles(self) -> list[str]:
        """Return a list of loaded profile names."""
        return list(self._profiles.keys())
    
    def redact(self, text: str) -> tuple[str, bool]:
        """
        Redact sensitive data from the given text.
        
        Args:
            text: The input text to sanitize.
            
        Returns:
            A tuple of (redacted_text, was_redacted):
            - redacted_text: The sanitized text with sensitive data replaced
            - was_redacted: True if any redaction occurred
        
        Example:
            safe, redacted = engine.redact("Call me at 555-123-4567")
            # safe: "Call me at {{PHONE}}"
            # redacted: True
        """
        if not text:
            return text, False
        
        original_text = text
        
        # Step 1: Apply scrubadub's built-in detectors
        # This handles: emails, phone numbers, names, URLs, etc.
        try:
            text = self._scrubber.clean(text)
        except Exception as e:
            logger.warning(f"Scrubadub error (continuing with regex): {e}")
        
        # Step 2: Apply custom patterns from all loaded profiles
        for profile in self._profiles.values():
            for pattern in profile.get_patterns():
                try:
                    text = pattern.pattern.sub(pattern.replacement, text)
                except Exception as e:
                    logger.warning(f"Pattern '{pattern.name}' error: {e}")
        
        # Determine if any redaction occurred
        was_redacted = text != original_text
        
        return text, was_redacted
    
    def redact_batch(self, texts: list[str]) -> tuple[list[str], bool]:
        """
        Redact sensitive data from multiple texts.
        
        Args:
            texts: List of input texts to sanitize.
            
        Returns:
            A tuple of (redacted_texts, any_redacted):
            - redacted_texts: List of sanitized texts
            - any_redacted: True if ANY text had redaction
        """
        results = []
        any_redacted = False
        
        for text in texts:
            redacted_text, was_redacted = self.redact(text)
            results.append(redacted_text)
            if was_redacted:
                any_redacted = True
        
        return results, any_redacted


# Singleton instance for convenience
_default_engine: Optional[RedactionEngine] = None


def get_default_engine() -> RedactionEngine:
    """
    Get the default RedactionEngine instance.
    
    This is a convenience function for simple use cases.
    For more control, instantiate RedactionEngine directly.
    """
    global _default_engine
    if _default_engine is None:
        _default_engine = RedactionEngine()
    return _default_engine
