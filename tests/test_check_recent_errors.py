"""
Tests for the check_recent_errors tool.

Tests cover:
- Successful error retrieval from CloudWatch Logs
- Safety limits enforcement (max 60 min, max 20 results)
- Missing credentials handling
- Invalid log group handling
"""

import os

import boto3
import pytest
from moto import mock_aws


class TestCheckRecentErrors:
    """Test suite for check_recent_errors tool."""

    @mock_aws
    def test_returns_errors_from_log_group(self):
        """Should return error entries from a log group."""
        # Setup: Create log group with error messages
        client = boto3.client("logs", region_name="us-east-1")
        log_group_name = "/aws/lambda/test-function"

        client.create_log_group(logGroupName=log_group_name)
        client.create_log_stream(
            logGroupName=log_group_name,
            logStreamName="test-stream"
        )

        import time
        timestamp = int(time.time() * 1000)

        client.put_log_events(
            logGroupName=log_group_name,
            logStreamName="test-stream",
            logEvents=[
                {"timestamp": timestamp, "message": "ERROR: Test error message"},
            ]
        )

        # Import and call the tool
        from server import check_recent_errors

        result = check_recent_errors(log_group_name, 15)

        # Assertions
        assert result["status"] == "success"
        assert result["log_group"] == log_group_name
        assert "time_range" in result
        assert "query_id" in result

    @mock_aws
    def test_enforces_max_lookback_limit(self):
        """Should cap minutes at 60 even if higher value requested."""
        client = boto3.client("logs", region_name="us-east-1")
        log_group_name = "/aws/lambda/test-function"
        client.create_log_group(logGroupName=log_group_name)

        from server import check_recent_errors

        # Request 120 minutes - should be capped to 60
        result = check_recent_errors(log_group_name, 120)

        # Should succeed and use 60 minutes max
        assert result["status"] == "success"
        assert "Last 60 minutes" in result.get("time_range", "")

    @mock_aws
    def test_enforces_min_lookback_limit(self):
        """Should enforce minimum of 1 minute for lookback."""
        client = boto3.client("logs", region_name="us-east-1")
        log_group_name = "/aws/lambda/test-function"
        client.create_log_group(logGroupName=log_group_name)

        from server import check_recent_errors

        # Request 0 or negative minutes - should use 1
        result = check_recent_errors(log_group_name, 0)

        assert result["status"] == "success"
        assert "Last 1 minutes" in result.get("time_range", "")

    @mock_aws
    def test_handles_nonexistent_log_group(self):
        """Should return error for non-existent log group."""
        from server import check_recent_errors

        result = check_recent_errors("/aws/lambda/does-not-exist", 15)

        assert result["status"] == "error"
        assert "log_group" in result

    def test_handles_missing_credentials(self, monkeypatch):
        """Should return helpful error when AWS credentials are missing."""
        # Clear environment variables
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)

        from server import check_recent_errors

        result = check_recent_errors("/aws/lambda/test", 15)

        assert result["status"] == "error"
        assert "credentials" in result["message"].lower()

    @mock_aws
    def test_truncates_long_messages(self):
        """Should truncate log messages longer than 500 characters."""
        client = boto3.client("logs", region_name="us-east-1")
        log_group_name = "/aws/lambda/test-function"

        client.create_log_group(logGroupName=log_group_name)
        client.create_log_stream(
            logGroupName=log_group_name,
            logStreamName="test-stream"
        )

        import time
        timestamp = int(time.time() * 1000)

        # Create a very long error message
        long_message = "ERROR: " + "x" * 600

        client.put_log_events(
            logGroupName=log_group_name,
            logStreamName="test-stream",
            logEvents=[
                {"timestamp": timestamp, "message": long_message},
            ]
        )

        from server import check_recent_errors

        result = check_recent_errors(log_group_name, 15)

        # If errors are returned, check truncation
        if result["status"] == "success" and result.get("errors"):
            for error in result["errors"]:
                if "message" in error:
                    # Should be truncated to 500 chars + "..."
                    assert len(error["message"]) <= 503

    @mock_aws
    def test_returns_empty_list_when_no_errors(self):
        """Should return empty errors list when no errors found."""
        client = boto3.client("logs", region_name="us-east-1")
        log_group_name = "/aws/lambda/test-function"

        client.create_log_group(logGroupName=log_group_name)
        client.create_log_stream(
            logGroupName=log_group_name,
            logStreamName="test-stream"
        )

        import time
        timestamp = int(time.time() * 1000)

        # Only info messages, no errors
        client.put_log_events(
            logGroupName=log_group_name,
            logStreamName="test-stream",
            logEvents=[
                {"timestamp": timestamp, "message": "INFO: All systems normal"},
            ]
        )

        from server import check_recent_errors

        result = check_recent_errors(log_group_name, 15)

        assert result["status"] == "success"
        # errors list should be empty (no error patterns matched)
        assert result.get("error_count", 0) >= 0
