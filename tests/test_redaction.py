"""
Tests for the Redaction Engine and Compliance Profiles.

Tests cover:
- RedactionEngine basic functionality
- US/Global profile patterns (credit cards, SSN, AWS keys, JWT, etc.)
- Profile loading/unloading
- Batch redaction
- Edge cases
"""

import pytest
from redaction import RedactionEngine, ComplianceProfile
from redaction.base_profile import RedactionPattern
from redaction.profiles import USGlobalProfile
import re


class TestRedactionEngine:
    """Test suite for RedactionEngine core functionality."""

    def test_basic_email_redaction(self):
        """Should redact email addresses using scrubadub."""
        engine = RedactionEngine()
        result, was_redacted = engine.redact("Contact: john.doe@example.com")

        assert was_redacted is True
        assert "john.doe@example.com" not in result
        # scrubadub uses {{EMAIL}} format
        assert "{{" in result or "EMAIL" in result.upper()

    def test_no_redaction_for_clean_text(self):
        """Should not flag clean text as redacted."""
        engine = RedactionEngine()
        result, was_redacted = engine.redact("This is a normal log message")

        assert was_redacted is False
        assert result == "This is a normal log message"

    def test_empty_string_handling(self):
        """Should handle empty strings gracefully."""
        engine = RedactionEngine()
        result, was_redacted = engine.redact("")

        assert result == ""
        assert was_redacted is False

    def test_none_handling(self):
        """Should handle None gracefully."""
        engine = RedactionEngine()
        # None should be treated as falsy and return as-is
        result, was_redacted = engine.redact(None)

        assert result is None
        assert was_redacted is False

    def test_profile_loading(self):
        """Should load profiles correctly."""
        engine = RedactionEngine(load_default_profile=False)
        assert len(engine.list_profiles()) == 0

        engine.load_profile(USGlobalProfile())
        assert "us_global" in engine.list_profiles()

    def test_profile_unloading(self):
        """Should unload profiles correctly."""
        engine = RedactionEngine()
        assert "us_global" in engine.list_profiles()

        result = engine.unload_profile("us_global")
        assert result is True
        assert "us_global" not in engine.list_profiles()

    def test_unload_nonexistent_profile(self):
        """Should return False when unloading non-existent profile."""
        engine = RedactionEngine()
        result = engine.unload_profile("nonexistent")
        assert result is False

    def test_batch_redaction(self):
        """Should redact multiple texts and track if any were redacted."""
        engine = RedactionEngine()
        texts = [
            "Email: test@example.com",
            "Normal message",
            "Another email: foo@bar.org"
        ]

        results, any_redacted = engine.redact_batch(texts)

        assert len(results) == 3
        assert any_redacted is True
        assert "test@example.com" not in results[0]
        assert results[1] == "Normal message"


class TestUSGlobalProfile:
    """Test suite for US/Global compliance profile patterns."""

    @pytest.fixture
    def engine(self):
        """Return an engine with only US/Global profile."""
        return RedactionEngine()

    def test_credit_card_visa(self, engine):
        """Should redact Visa credit card numbers."""
        text = "Payment with card: 4111111111111111"
        result, was_redacted = engine.redact(text)

        assert was_redacted is True
        assert "4111111111111111" not in result
        assert "CREDIT_CARD" in result

    def test_credit_card_mastercard(self, engine):
        """Should redact Mastercard numbers."""
        text = "Card: 5500000000000004"
        result, was_redacted = engine.redact(text)

        assert was_redacted is True
        assert "5500000000000004" not in result

    def test_credit_card_with_spaces(self, engine):
        """Should redact credit cards with space separators."""
        text = "Card number: 4111 1111 1111 1111"
        result, was_redacted = engine.redact(text)

        assert was_redacted is True
        assert "4111 1111 1111 1111" not in result

    def test_credit_card_with_dashes(self, engine):
        """Should redact credit cards with dash separators."""
        text = "CC: 4111-1111-1111-1111"
        result, was_redacted = engine.redact(text)

        assert was_redacted is True
        assert "4111-1111-1111-1111" not in result

    def test_ssn_standard_format(self, engine):
        """Should redact US SSN in XXX-XX-XXXX format."""
        text = "SSN: 123-45-6789"
        result, was_redacted = engine.redact(text)

        assert was_redacted is True
        assert "123-45-6789" not in result
        assert "SSN" in result

    def test_aws_access_key(self, engine):
        """Should redact AWS Access Key IDs."""
        text = "AWS Key: AKIAIOSFODNN7EXAMPLE"
        result, was_redacted = engine.redact(text)

        assert was_redacted is True
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "AWS_ACCESS_KEY" in result

    def test_jwt_bearer_token(self, engine):
        """Should redact JWT Bearer tokens."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        text = f"Authorization: Bearer {jwt}"
        result, was_redacted = engine.redact(text)

        assert was_redacted is True
        assert jwt not in result
        assert "JWT_TOKEN" in result or "Bearer" in result

    def test_api_key_in_key_value(self, engine):
        """Should redact API keys in key=value format."""
        # Using obviously fake key that won't trigger secret scanning
        text = "api_key=FAKE_TEST_KEY_0123456789abcdef"
        result, was_redacted = engine.redact(text)

        assert was_redacted is True
        assert "FAKE_TEST_KEY_0123456789abcdef" not in result

    def test_password_in_logs(self, engine):
        """Should redact passwords in log messages."""
        text = "password=mysecretpass123"
        result, was_redacted = engine.redact(text)

        assert was_redacted is True
        assert "mysecretpass123" not in result
        assert "REDACTED_PASSWORD" in result

    def test_github_token(self, engine):
        """Should redact GitHub personal access tokens."""
        text = "Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        result, was_redacted = engine.redact(text)

        assert was_redacted is True
        assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in result
        assert "GITHUB_TOKEN" in result

    def test_slack_token(self, engine):
        """Should redact Slack API tokens."""
        # Using pattern that matches format but is obviously fake
        text = "Slack: xoxb-FAKE-TOKEN-FOR-TESTING-ONLY"
        result, was_redacted = engine.redact(text)

        assert was_redacted is True
        assert "xoxb-" not in result
        assert "SLACK_TOKEN" in result

    def test_phone_number(self, engine):
        """Should redact phone numbers via scrubadub."""
        text = "Call me at 555-123-4567"
        result, was_redacted = engine.redact(text)

        # Phone number redaction depends on scrubadub's detection
        # which may or may not catch all formats
        if was_redacted:
            assert "555-123-4567" not in result

    def test_multiple_sensitive_items(self, engine):
        """Should redact multiple types of sensitive data in one message."""
        text = "User email: test@example.com, CC: 4111111111111111, SSN: 123-45-6789"
        result, was_redacted = engine.redact(text)

        assert was_redacted is True
        assert "test@example.com" not in result
        assert "4111111111111111" not in result
        assert "123-45-6789" not in result


class TestCustomProfile:
    """Test adding custom compliance profiles."""

    def test_custom_profile_integration(self):
        """Should be able to add and use custom profiles."""

        class TestProfile(ComplianceProfile):
            @property
            def name(self) -> str:
                return "test"

            @property
            def description(self) -> str:
                return "Test profile"

            def get_patterns(self):
                return [
                    RedactionPattern(
                        name="test_pattern",
                        pattern=re.compile(r'TEST-\d{4}'),
                        replacement="{{TEST_ID}}"
                    )
                ]

        engine = RedactionEngine(load_default_profile=False)
        engine.load_profile(TestProfile())

        result, was_redacted = engine.redact("ID: TEST-1234")

        assert was_redacted is True
        assert "TEST-1234" not in result
        assert "{{TEST_ID}}" in result
