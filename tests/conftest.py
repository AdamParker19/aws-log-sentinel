"""
Pytest configuration and shared fixtures for AWS Log Sentinel tests.

Uses moto to mock AWS services (CloudWatch Logs, CodeDeploy) for safe,
isolated testing without real AWS credentials.
"""

import os
import sys

import pytest

# Add parent directory to path for server imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def set_aws_credentials():
    """
    Set mock AWS credentials for moto.
    This runs automatically before each test.
    """
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_REGION"] = "us-east-1"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    yield
    # Cleanup (optional, as each test is isolated)


@pytest.fixture
def cloudwatch_logs_client():
    """Provide a mocked CloudWatch Logs client."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        client = boto3.client("logs", region_name="us-east-1")
        yield client


@pytest.fixture
def codedeploy_client():
    """Provide a mocked CodeDeploy client."""
    import boto3
    from moto import mock_aws

    with mock_aws():
        client = boto3.client("codedeploy", region_name="us-east-1")
        yield client


@pytest.fixture
def sample_log_group(cloudwatch_logs_client):
    """Create a sample log group with some log events."""
    log_group_name = "/aws/lambda/test-function"
    log_stream_name = "test-stream"

    # Create log group and stream
    cloudwatch_logs_client.create_log_group(logGroupName=log_group_name)
    cloudwatch_logs_client.create_log_stream(
        logGroupName=log_group_name,
        logStreamName=log_stream_name
    )

    # Add some log events including errors
    import time
    timestamp = int(time.time() * 1000)

    cloudwatch_logs_client.put_log_events(
        logGroupName=log_group_name,
        logStreamName=log_stream_name,
        logEvents=[
            {"timestamp": timestamp - 5000, "message": "INFO: Starting function"},
            {"timestamp": timestamp - 4000, "message": "ERROR: Database connection failed"},
            {"timestamp": timestamp - 3000, "message": "Exception: NullPointerException at line 42"},
            {"timestamp": timestamp - 2000, "message": "INFO: Retrying connection"},
            {"timestamp": timestamp - 1000, "message": "FATAL: Service unavailable"},
        ]
    )

    return log_group_name
