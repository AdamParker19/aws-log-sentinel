"""
Compliance Profiles Package

This package contains compliance-specific redaction profiles.
Add new profiles here to extend the redaction engine.

Available profiles:
    - us_global: Default US and global patterns (credit cards, SSN, AWS keys, JWT)

To add a new profile:
    1. Create a new file (e.g., compliance_eu.py)
    2. Subclass ComplianceProfile
    3. Implement get_patterns() with your RedactionPatterns
    4. Register in the RedactionEngine or use engine.load_profile()

Example for adding India profile:
    # redaction/profiles/india.py
    from ..base_profile import ComplianceProfile, RedactionPattern
    import re
    
    class IndiaProfile(ComplianceProfile):
        @property
        def name(self) -> str:
            return "india"
        
        def get_patterns(self) -> list[RedactionPattern]:
            return [
                RedactionPattern(
                    name="pan_card",
                    pattern=re.compile(r'[A-Z]{5}[0-9]{4}[A-Z]'),
                    replacement="{{PAN_CARD}}"
                ),
                RedactionPattern(
                    name="aadhaar",
                    pattern=re.compile(r'\\b[2-9]{1}[0-9]{11}\\b'),
                    replacement="{{AADHAAR}}"
                ),
            ]
"""

from .us_global import USGlobalProfile, DEFAULT_PROFILE

__all__ = ["USGlobalProfile", "DEFAULT_PROFILE"]
