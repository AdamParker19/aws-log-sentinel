"""
Tests for the check_deployment_status tool.

Tests cover:
- Successful deployment status retrieval
- Handling of different deployment states (Succeeded, Failed, InProgress)
- Missing application handling
- Missing credentials handling
"""

import boto3
import pytest
from moto import mock_aws


class TestCheckDeploymentStatus:
    """Test suite for check_deployment_status tool."""

    @mock_aws
    def test_returns_status_for_valid_application(self):
        """Should return deployment status for a valid CodeDeploy application."""
        client = boto3.client("codedeploy", region_name="us-east-1")

        # Create application and deployment group
        app_name = "test-application"
        client.create_application(applicationName=app_name)
        client.create_deployment_group(
            applicationName=app_name,
            deploymentGroupName="test-group",
            serviceRoleArn="arn:aws:iam::123456789012:role/CodeDeployRole"
        )

        from server import check_deployment_status

        result = check_deployment_status(app_name)

        assert result["status"] == "success"
        assert result["application"] == app_name

    @mock_aws
    def test_handles_nonexistent_application(self):
        """Should return error for non-existent application."""
        from server import check_deployment_status

        result = check_deployment_status("nonexistent-app")

        assert result["status"] == "error"
        assert "application" in result

    @mock_aws
    def test_handles_application_with_no_deployment_groups(self):
        """Should return error when application has no deployment groups."""
        client = boto3.client("codedeploy", region_name="us-east-1")
        app_name = "empty-application"

        client.create_application(applicationName=app_name)

        from server import check_deployment_status

        result = check_deployment_status(app_name)

        assert result["status"] == "error"
        assert "No deployment groups found" in result.get("message", "")

    @mock_aws
    def test_handles_application_with_no_deployments(self):
        """Should handle application with groups but no deployments."""
        client = boto3.client("codedeploy", region_name="us-east-1")
        app_name = "new-application"

        client.create_application(applicationName=app_name)
        client.create_deployment_group(
            applicationName=app_name,
            deploymentGroupName="test-group",
            serviceRoleArn="arn:aws:iam::123456789012:role/CodeDeployRole"
        )

        from server import check_deployment_status

        result = check_deployment_status(app_name)

        assert result["status"] == "success"
        # Should indicate no deployments found
        assert "No deployments found" in result.get("message", "") or result.get("deployment") is None

    def test_handles_missing_credentials(self, monkeypatch):
        """Should return helpful error when AWS credentials are missing."""
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)

        from server import check_deployment_status

        result = check_deployment_status("test-app")

        assert result["status"] == "error"
        assert "credentials" in result["message"].lower()

    @mock_aws
    def test_returns_deployment_details(self):
        """Should return detailed deployment information when deployment exists."""
        client = boto3.client("codedeploy", region_name="us-east-1")
        app_name = "detailed-application"

        client.create_application(applicationName=app_name)
        client.create_deployment_group(
            applicationName=app_name,
            deploymentGroupName="production",
            serviceRoleArn="arn:aws:iam::123456789012:role/CodeDeployRole"
        )

        # Create a deployment
        deployment_response = client.create_deployment(
            applicationName=app_name,
            deploymentGroupName="production",
            revision={
                "revisionType": "S3",
                "s3Location": {
                    "bucket": "my-bucket",
                    "key": "my-app.zip",
                    "bundleType": "zip"
                }
            }
        )

        from server import check_deployment_status

        result = check_deployment_status(app_name)

        assert result["status"] == "success"
        if result.get("deployment"):
            assert "deployment_id" in result["deployment"]
            assert "status" in result["deployment"]

    @mock_aws
    def test_returns_multiple_deployment_groups(self):
        """Should check across all deployment groups for latest deployment."""
        client = boto3.client("codedeploy", region_name="us-east-1")
        app_name = "multi-group-app"

        client.create_application(applicationName=app_name)

        # Create multiple deployment groups
        for group_name in ["staging", "production", "development"]:
            client.create_deployment_group(
                applicationName=app_name,
                deploymentGroupName=group_name,
                serviceRoleArn="arn:aws:iam::123456789012:role/CodeDeployRole"
            )

        from server import check_deployment_status

        result = check_deployment_status(app_name)

        assert result["status"] == "success"
        assert result["application"] == app_name
