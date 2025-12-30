"""
Tests for the list_log_groups tool.

Tests cover:
- Listing all log groups
- Filtering by prefix
- Empty results handling
- Missing credentials handling
"""

import boto3
import pytest
from moto import mock_aws


class TestListLogGroups:
    """Test suite for list_log_groups tool."""

    @mock_aws
    def test_lists_all_log_groups(self):
        """Should list all available log groups."""
        client = boto3.client("logs", region_name="us-east-1")

        # Create multiple log groups
        log_groups = [
            "/aws/lambda/function-1",
            "/aws/lambda/function-2",
            "/ecs/service-1",
            "/custom/my-app"
        ]
        for lg in log_groups:
            client.create_log_group(logGroupName=lg)

        from server import list_log_groups

        result = list_log_groups()

        assert result["status"] == "success"
        assert result["count"] == 4
        assert len(result["log_groups"]) == 4
        for lg in log_groups:
            assert lg in result["log_groups"]

    @mock_aws
    def test_filters_by_prefix(self):
        """Should filter log groups by prefix."""
        client = boto3.client("logs", region_name="us-east-1")

        # Create log groups with different prefixes
        client.create_log_group(logGroupName="/aws/lambda/function-1")
        client.create_log_group(logGroupName="/aws/lambda/function-2")
        client.create_log_group(logGroupName="/ecs/service-1")

        from server import list_log_groups

        result = list_log_groups("/aws/lambda")

        assert result["status"] == "success"
        assert result["count"] == 2
        assert "/aws/lambda/function-1" in result["log_groups"]
        assert "/aws/lambda/function-2" in result["log_groups"]
        assert "/ecs/service-1" not in result["log_groups"]
        assert result["prefix_filter"] == "/aws/lambda"

    @mock_aws
    def test_handles_no_matching_prefix(self):
        """Should return empty list when no log groups match prefix."""
        client = boto3.client("logs", region_name="us-east-1")

        client.create_log_group(logGroupName="/aws/lambda/function-1")

        from server import list_log_groups

        result = list_log_groups("/nonexistent")

        assert result["status"] == "success"
        assert result["count"] == 0
        assert result["log_groups"] == []

    @mock_aws
    def test_handles_empty_log_groups(self):
        """Should handle case when no log groups exist."""
        from server import list_log_groups

        result = list_log_groups()

        assert result["status"] == "success"
        assert result["count"] == 0
        assert result["log_groups"] == []

    def test_handles_missing_credentials(self, monkeypatch):
        """Should return helpful error when AWS credentials are missing."""
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)

        from server import list_log_groups

        result = list_log_groups()

        assert result["status"] == "error"
        assert "credentials" in result["message"].lower()

    @mock_aws
    def test_ecs_prefix_filter(self):
        """Should correctly filter ECS log groups."""
        client = boto3.client("logs", region_name="us-east-1")

        client.create_log_group(logGroupName="/ecs/api")
        client.create_log_group(logGroupName="/ecs/worker")
        client.create_log_group(logGroupName="/aws/lambda/handler")

        from server import list_log_groups

        result = list_log_groups("/ecs")

        assert result["status"] == "success"
        assert result["count"] == 2
        assert all(lg.startswith("/ecs") for lg in result["log_groups"])

    @mock_aws
    def test_includes_prefix_in_response(self):
        """Should include the prefix filter used in response."""
        client = boto3.client("logs", region_name="us-east-1")
        client.create_log_group(logGroupName="/aws/lambda/test")

        from server import list_log_groups

        result = list_log_groups("/aws/lambda")

        assert result["prefix_filter"] == "/aws/lambda"

    @mock_aws
    def test_no_prefix_shows_none(self):
        """Should show (none) when no prefix is provided."""
        from server import list_log_groups

        result = list_log_groups()

        assert result["prefix_filter"] == "(none)"
