"""
AWS Log Sentinel - MCP Server for AWS Debugging

A local MCP (Model Context Protocol) server that provides tools to safely query
AWS CloudWatch Logs and CodeDeploy status. Designed for AI agents to debug
AWS environments without incurring high costs.

Tools:
    - check_recent_errors: Query CloudWatch Insights for error patterns
    - check_deployment_status: Check CodeDeploy deployment status

Safety Constraints:
    - Maximum 60 minutes lookback to prevent high AWS costs
    - Results limited to top 20 entries
    - Only filters for Error, Exception, or Critical patterns
"""

import os
import time
from datetime import datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

# Load environment variables from .env file
load_dotenv()

# Initialize MCP server
mcp = FastMCP(
    "aws-log-sentinel",
    instructions="MCP Server for safely debugging AWS CloudWatch Logs and CodeDeploy"
)

# Safety constants
MAX_LOOKBACK_MINUTES = 60
MAX_RESULTS = 20
ERROR_PATTERNS = ["Error", "Exception", "Critical", "FATAL", "error", "exception"]


def get_cloudwatch_client():
    """Create and return a CloudWatch Logs client using environment credentials."""
    return boto3.client(
        "logs",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION", "us-east-1")
    )


def get_codedeploy_client():
    """Create and return a CodeDeploy client using environment credentials."""
    return boto3.client(
        "codedeploy",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION", "us-east-1")
    )


@mcp.tool()
def check_recent_errors(log_group_name: str, minutes: int = 15) -> dict[str, Any]:
    """
    Query AWS CloudWatch Insights for recent error patterns in a log group.

    This tool safely queries CloudWatch Logs using Insights to find log entries
    containing Error, Exception, Critical, or FATAL patterns. Results are limited
    to prevent high AWS costs.

    Args:
        log_group_name: The name of the CloudWatch Log Group to query.
                        Example: "/aws/lambda/my-function" or "/ecs/my-service"
        minutes: How many minutes back to search (1-60). Defaults to 15.
                 Maximum allowed is 60 minutes to prevent high costs.

    Returns:
        A dictionary containing:
        - status: "success" or "error"
        - log_group: The queried log group name
        - time_range: Human-readable time range searched
        - error_count: Number of errors found
        - errors: List of error entries (max 20), each with:
            - timestamp: When the error occurred
            - message: The log message (truncated to 500 chars)
        - query_id: The CloudWatch Insights query ID for reference

    Example usage:
        check_recent_errors("/aws/lambda/payment-processor", 30)
        check_recent_errors("/ecs/api-service", 15)

    Notes:
        - Only returns logs matching: Error, Exception, Critical, FATAL
        - Results sorted by timestamp (newest first)
        - Each message truncated to 500 characters for readability
    """
    # Enforce safety limit
    if minutes < 1:
        minutes = 1
    if minutes > MAX_LOOKBACK_MINUTES:
        minutes = MAX_LOOKBACK_MINUTES

    try:
        client = get_cloudwatch_client()

        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=minutes)

        # CloudWatch Insights query - filter for error patterns
        query = f"""
        fields @timestamp, @message
        | filter @message like /(?i)(error|exception|critical|fatal)/
        | sort @timestamp desc
        | limit {MAX_RESULTS}
        """

        # Start the query
        response = client.start_query(
            logGroupName=log_group_name,
            startTime=int(start_time.timestamp()),
            endTime=int(end_time.timestamp()),
            queryString=query
        )

        query_id = response["queryId"]

        # Poll for query completion (max 30 seconds)
        results = None
        for _ in range(30):
            result_response = client.get_query_results(queryId=query_id)
            status = result_response["status"]

            if status == "Complete":
                results = result_response["results"]
                break
            elif status in ["Failed", "Cancelled"]:
                return {
                    "status": "error",
                    "log_group": log_group_name,
                    "message": f"Query {status.lower()}",
                    "query_id": query_id
                }

            time.sleep(1)

        if results is None:
            return {
                "status": "error",
                "log_group": log_group_name,
                "message": "Query timed out after 30 seconds",
                "query_id": query_id
            }

        # Parse results
        errors = []
        for result in results:
            entry = {}
            for field in result:
                if field["field"] == "@timestamp":
                    entry["timestamp"] = field["value"]
                elif field["field"] == "@message":
                    # Truncate long messages
                    message = field["value"]
                    entry["message"] = message[:500] + "..." if len(message) > 500 else message
            if entry:
                errors.append(entry)

        return {
            "status": "success",
            "log_group": log_group_name,
            "time_range": f"Last {minutes} minutes (from {start_time.isoformat()} to {end_time.isoformat()} UTC)",
            "error_count": len(errors),
            "errors": errors,
            "query_id": query_id
        }

    except NoCredentialsError:
        return {
            "status": "error",
            "log_group": log_group_name,
            "message": "AWS credentials not found. Please set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION environment variables."
        }
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_message = e.response.get("Error", {}).get("Message", str(e))
        return {
            "status": "error",
            "log_group": log_group_name,
            "message": f"AWS Error ({error_code}): {error_message}"
        }
    except Exception as e:
        return {
            "status": "error",
            "log_group": log_group_name,
            "message": f"Unexpected error: {str(e)}"
        }


@mcp.tool()
def check_deployment_status(application_name: str) -> dict[str, Any]:
    """
    Check the status of the most recent AWS CodeDeploy deployment for an application.

    This tool queries AWS CodeDeploy to get information about the latest deployment,
    including whether it Succeeded, Failed, or is In Progress.

    Args:
        application_name: The name of the CodeDeploy application.
                          Example: "my-api-app" or "production-backend"

    Returns:
        A dictionary containing:
        - status: "success" or "error"
        - application: The application name queried
        - deployment: Information about the most recent deployment:
            - deployment_id: The unique deployment ID
            - status: Deployment status (Succeeded, Failed, InProgress, etc.)
            - create_time: When the deployment was created
            - complete_time: When the deployment completed (if finished)
            - deployment_group: The deployment group name
            - revision_location: Where the deployment package came from
            - error_info: Error details if the deployment failed
            - instance_summary: Summary of instance deployment statuses

    Example usage:
        check_deployment_status("my-production-api")
        check_deployment_status("payment-service")

    Notes:
        - Only returns the most recent deployment
        - Includes error details for failed deployments
        - Shows instance-level status summary
    """
    try:
        client = get_codedeploy_client()

        # List deployment groups for the application
        groups_response = client.list_deployment_groups(applicationName=application_name)
        deployment_groups = groups_response.get("deploymentGroups", [])

        if not deployment_groups:
            return {
                "status": "error",
                "application": application_name,
                "message": f"No deployment groups found for application '{application_name}'"
            }

        # Get the most recent deployment across all deployment groups
        latest_deployment = None
        latest_deployment_info = None

        for group_name in deployment_groups:
            deployments_response = client.list_deployments(
                applicationName=application_name,
                deploymentGroupName=group_name,
                includeOnlyStatuses=[
                    "Created", "Queued", "InProgress", "Baking",
                    "Succeeded", "Failed", "Stopped", "Ready"
                ]
            )

            deployment_ids = deployments_response.get("deployments", [])

            if deployment_ids:
                # Get details of the most recent deployment in this group
                deployment_id = deployment_ids[0]
                deployment_info = client.get_deployment(deploymentId=deployment_id)["deploymentInfo"]

                create_time = deployment_info.get("createTime")

                if latest_deployment is None or (create_time and create_time > latest_deployment.get("createTime")):
                    latest_deployment = deployment_info
                    latest_deployment_info = {
                        "deployment_group": group_name,
                        "deployment_id": deployment_id
                    }

        if latest_deployment is None:
            return {
                "status": "success",
                "application": application_name,
                "message": "No deployments found for this application",
                "deployment_groups": deployment_groups
            }

        # Build response with deployment details
        deployment_status = latest_deployment.get("status", "Unknown")

        result = {
            "status": "success",
            "application": application_name,
            "deployment": {
                "deployment_id": latest_deployment_info["deployment_id"],
                "deployment_group": latest_deployment_info["deployment_group"],
                "status": deployment_status,
                "create_time": latest_deployment.get("createTime", "").isoformat() if latest_deployment.get("createTime") else None,
                "complete_time": latest_deployment.get("completeTime", "").isoformat() if latest_deployment.get("completeTime") else None,
            }
        }

        # Add revision location if available
        revision = latest_deployment.get("revision", {})
        if revision:
            rev_type = revision.get("revisionType", "Unknown")
            if rev_type == "S3":
                s3_info = revision.get("s3Location", {})
                result["deployment"]["revision_location"] = f"s3://{s3_info.get('bucket', '')}/{s3_info.get('key', '')}"
            elif rev_type == "GitHub":
                github_info = revision.get("gitHubLocation", {})
                result["deployment"]["revision_location"] = f"github:{github_info.get('repository', '')}@{github_info.get('commitId', '')[:8]}"
            else:
                result["deployment"]["revision_location"] = rev_type

        # Add error information for failed deployments
        error_info = latest_deployment.get("errorInformation")
        if error_info:
            result["deployment"]["error_info"] = {
                "code": error_info.get("code", "Unknown"),
                "message": error_info.get("message", "No error message available")
            }

        # Add instance status summary
        overview = latest_deployment.get("deploymentOverview", {})
        if overview:
            result["deployment"]["instance_summary"] = {
                "pending": overview.get("Pending", 0),
                "in_progress": overview.get("InProgress", 0),
                "succeeded": overview.get("Succeeded", 0),
                "failed": overview.get("Failed", 0),
                "skipped": overview.get("Skipped", 0),
                "ready": overview.get("Ready", 0)
            }

        # Add rollback info if this was a rollback
        if latest_deployment.get("rollbackInfo"):
            rollback = latest_deployment["rollbackInfo"]
            result["deployment"]["rollback_info"] = {
                "rollback_deployment_id": rollback.get("rollbackDeploymentId"),
                "rollback_triggering_deployment_id": rollback.get("rollbackTriggeringDeploymentId"),
                "rollback_message": rollback.get("rollbackMessage")
            }

        return result

    except NoCredentialsError:
        return {
            "status": "error",
            "application": application_name,
            "message": "AWS credentials not found. Please set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION environment variables."
        }
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_message = e.response.get("Error", {}).get("Message", str(e))
        return {
            "status": "error",
            "application": application_name,
            "message": f"AWS Error ({error_code}): {error_message}"
        }
    except Exception as e:
        return {
            "status": "error",
            "application": application_name,
            "message": f"Unexpected error: {str(e)}"
        }


@mcp.tool()
def list_log_groups(prefix: str = "") -> dict[str, Any]:
    """
    List available CloudWatch Log Groups, optionally filtered by prefix.

    This helper tool allows discovery of available log groups before querying
    for errors. Useful when you don't know the exact log group name.

    Args:
        prefix: Optional prefix to filter log groups. Example: "/aws/lambda"
                Leave empty to list all log groups (limited to first 50).

    Returns:
        A dictionary containing:
        - status: "success" or "error"
        - log_groups: List of log group names matching the prefix
        - count: Number of log groups found

    Example usage:
        list_log_groups()  # List all log groups
        list_log_groups("/aws/lambda")  # List only Lambda log groups
        list_log_groups("/ecs")  # List only ECS log groups
    """
    try:
        client = get_cloudwatch_client()

        params = {"limit": 50}
        if prefix:
            params["logGroupNamePrefix"] = prefix

        response = client.describe_log_groups(**params)

        log_groups = [lg["logGroupName"] for lg in response.get("logGroups", [])]

        return {
            "status": "success",
            "log_groups": log_groups,
            "count": len(log_groups),
            "prefix_filter": prefix if prefix else "(none)"
        }

    except NoCredentialsError:
        return {
            "status": "error",
            "message": "AWS credentials not found. Please set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION environment variables."
        }
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_message = e.response.get("Error", {}).get("Message", str(e))
        return {
            "status": "error",
            "message": f"AWS Error ({error_code}): {error_message}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error: {str(e)}"
        }


if __name__ == "__main__":
    # Run the MCP server using stdio transport
    mcp.run()
