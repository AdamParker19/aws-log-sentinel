"""
US/Global Compliance Profile - Default redaction rules.

This profile covers common sensitive data patterns used globally
and those specifically required for US compliance (PCI-DSS, etc.).

Patterns covered:
    - Credit Card Numbers (PCI-DSS compliance)
    - US Social Security Numbers (SSN)
    - AWS Access Key IDs (AKIA...)
    - Bearer Tokens (JWT)
    - Generic API Keys
    - Secret patterns in key=value format
"""

import re
from ..base_profile import ComplianceProfile, RedactionPattern


class USGlobalProfile(ComplianceProfile):
    """
    Default compliance profile for US and globally common patterns.
    
    This profile is always loaded by default and covers:
    - Credit cards (Visa, Mastercard, Amex, Discover)
    - US Social Security Numbers
    - AWS credentials
    - JWT Bearer tokens
    - Common API key patterns
    """
    
    @property
    def name(self) -> str:
        return "us_global"
    
    @property
    def description(self) -> str:
        return "US and global compliance patterns (PCI-DSS, credentials, common PII)"
    
    def get_patterns(self) -> list[RedactionPattern]:
        return [
            # Credit Card Numbers (13-19 digits, various formats)
            # Covers: Visa, Mastercard, Amex, Discover, etc.
            RedactionPattern(
                name="credit_card",
                pattern=re.compile(
                    r'\b(?:'
                    r'4[0-9]{12}(?:[0-9]{3})?|'  # Visa
                    r'5[1-5][0-9]{14}|'  # Mastercard
                    r'3[47][0-9]{13}|'  # Amex
                    r'6(?:011|5[0-9]{2})[0-9]{12}|'  # Discover
                    r'(?:2131|1800|35\d{3})\d{11}'  # JCB
                    r')\b'
                ),
                replacement="{{CREDIT_CARD}}",
                description="Credit card number (PCI-DSS)"
            ),
            
            # Credit cards with separators (spaces, dashes)
            RedactionPattern(
                name="credit_card_formatted",
                pattern=re.compile(
                    r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
                ),
                replacement="{{CREDIT_CARD}}",
                description="Formatted credit card (with spaces/dashes)"
            ),
            
            # US Social Security Number (XXX-XX-XXXX)
            RedactionPattern(
                name="ssn",
                pattern=re.compile(
                    r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
                ),
                replacement="{{SSN}}",
                description="US Social Security Number"
            ),
            
            # SSN without dashes
            RedactionPattern(
                name="ssn_no_dash",
                pattern=re.compile(
                    r'\b(?!000|666|9\d{2})\d{3}(?!00)\d{2}(?!0000)\d{4}\b'
                ),
                replacement="{{SSN}}",
                description="US SSN without dashes"
            ),
            
            # AWS Access Key ID (AKIA...)
            RedactionPattern(
                name="aws_access_key",
                pattern=re.compile(
                    r'\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b'
                ),
                replacement="{{AWS_ACCESS_KEY}}",
                description="AWS Access Key ID"
            ),
            
            # AWS Secret Access Key (40 character base64-ish)
            RedactionPattern(
                name="aws_secret_key",
                pattern=re.compile(
                    r'\b[A-Za-z0-9/+=]{40}\b'
                ),
                replacement="{{AWS_SECRET_KEY}}",
                description="Potential AWS Secret Access Key"
            ),
            
            # Bearer Token (JWT format)
            RedactionPattern(
                name="bearer_token",
                pattern=re.compile(
                    r'Bearer\s+eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
                ),
                replacement="Bearer {{JWT_TOKEN}}",
                description="JWT Bearer token"
            ),
            
            # Generic JWT (not prefixed with Bearer)
            RedactionPattern(
                name="jwt_token",
                pattern=re.compile(
                    r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'
                ),
                replacement="{{JWT_TOKEN}}",
                description="JWT token"
            ),
            
            # Generic API Key patterns (key=value format)
            RedactionPattern(
                name="api_key_value",
                pattern=re.compile(
                    r'(?i)(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-+=/.]{16,})["\']?',
                    re.IGNORECASE
                ),
                replacement=r"\1={{REDACTED_KEY}}",
                description="API key in key=value format"
            ),
            
            # Password patterns
            RedactionPattern(
                name="password",
                pattern=re.compile(
                    r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{4,})["\']?'
                ),
                replacement=r"\1={{REDACTED_PASSWORD}}",
                description="Password in logs"
            ),
            
            # Private key markers
            RedactionPattern(
                name="private_key",
                pattern=re.compile(
                    r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----'
                ),
                replacement="{{PRIVATE_KEY_REDACTED}}",
                description="Private key block"
            ),
            
            # GitHub/GitLab tokens
            RedactionPattern(
                name="github_token",
                pattern=re.compile(
                    r'\b(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36})\b'
                ),
                replacement="{{GITHUB_TOKEN}}",
                description="GitHub personal access token"
            ),
            
            # Slack tokens
            RedactionPattern(
                name="slack_token",
                pattern=re.compile(
                    r'\b(xox[baprs]-[A-Za-z0-9\-]+)\b'
                ),
                replacement="{{SLACK_TOKEN}}",
                description="Slack API token"
            ),
        ]


# Export the default profile
DEFAULT_PROFILE = USGlobalProfile()
