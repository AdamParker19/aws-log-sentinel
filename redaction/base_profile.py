"""
Base Compliance Profile - Abstract base class for redaction rules.

Extend this class to create region or industry-specific compliance profiles.
For example:
    - compliance_pci.py for PCI-DSS (credit cards)
    - compliance_hipaa.py for HIPAA (healthcare)
    - compliance_india.py for Indian PII (PAN, Aadhaar)
    - compliance_eu.py for GDPR (IBANs, EU phone formats)

Each profile defines:
    - name: Unique identifier for the profile
    - description: Human-readable description
    - get_patterns(): Returns regex patterns for detection
    - get_scrubadub_detectors(): Optional custom scrubadub detectors
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Pattern
import re


@dataclass
class RedactionPattern:
    """A single redaction pattern definition."""
    name: str  # e.g., "credit_card", "ssn"
    pattern: Pattern[str]  # Compiled regex pattern
    replacement: str  # e.g., "{{CREDIT_CARD}}", "{{SSN}}"
    description: str = ""  # Human-readable description


class ComplianceProfile(ABC):
    """
    Abstract base class for compliance profiles.
    
    Subclass this to add new regional or industry-specific rules
    without modifying the core RedactionEngine.
    
    Example:
        class IndiaProfile(ComplianceProfile):
            @property
            def name(self) -> str:
                return "india"
            
            @property
            def description(self) -> str:
                return "Indian PII patterns (PAN, Aadhaar, etc.)"
            
            def get_patterns(self) -> list[RedactionPattern]:
                return [
                    RedactionPattern(
                        name="pan_card",
                        pattern=re.compile(r'[A-Z]{5}[0-9]{4}[A-Z]'),
                        replacement="{{PAN_CARD}}",
                        description="Indian PAN Card number"
                    ),
                    # Add more patterns...
                ]
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this profile (e.g., 'us_global', 'eu', 'india')."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this profile covers."""
        pass
    
    @abstractmethod
    def get_patterns(self) -> list[RedactionPattern]:
        """
        Return a list of RedactionPattern objects to apply.
        
        These patterns are applied AFTER scrubadub's built-in detectors,
        allowing you to catch domain-specific sensitive data.
        """
        pass
    
    def get_scrubadub_detectors(self) -> list:
        """
        Optional: Return custom scrubadub Detector classes.
        
        Override this to add custom scrubadub detectors for this profile.
        By default, returns an empty list (use scrubadub's built-in detectors).
        """
        return []
    
    def __repr__(self) -> str:
        return f"<ComplianceProfile: {self.name}>"
