# AWS Log Sentinel 🛡️

A local **MCP (Model Context Protocol)** server that enables AI agents to safely debug AWS environments by querying CloudWatch Logs and CodeDeploy status.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-compatible-green.svg)](https://modelcontextprotocol.io/)

## Why?

When debugging production issues, AI assistants often need to answer questions like:
- *"Why is the new deployment failing?"*
- *"Check the logs for 500 errors in the last 30 minutes"*
- *"What's the status of our latest CodeDeploy?"*

This MCP server provides safe, read-only tools to answer these questions without risking high AWS costs or exposing raw logs.

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **CloudWatch Insights** | Query logs for Error, Exception, Critical patterns |
| 🚀 **CodeDeploy Status** | Check deployment status (Succeeded/Failed/InProgress) |
| 🔒 **Safety Limits** | Max 60 min lookback, 20 results - prevents runaway costs |
| 📝 **Filtered Output** | Only error patterns returned, not raw log dumps |

## Tools

### `check_recent_errors(log_group_name, minutes)`

Query CloudWatch Logs for recent errors.

```python
# Find errors in Lambda function logs from last 30 minutes
check_recent_errors("/aws/lambda/payment-processor", 30)

# Returns:
{
    "status": "success",
    "log_group": "/aws/lambda/payment-processor",
    "error_count": 3,
    "errors": [
        {"timestamp": "2024-01-15T10:30:00Z", "message": "ERROR: Database timeout..."},
        ...
    ]
}
```

### `check_deployment_status(application_name)`

Check the most recent CodeDeploy deployment.

```python
check_deployment_status("my-production-api")

# Returns:
{
    "status": "success",
    "deployment": {
        "deployment_id": "d-ABC123",
        "status": "Failed",
        "error_info": {"code": "HEALTH_CHECK_FAILED", "message": "..."}
    }
}
```

### `list_log_groups(prefix)`

Discover available CloudWatch log groups.

```python
list_log_groups("/aws/lambda")  # List Lambda log groups
list_log_groups("/ecs")         # List ECS log groups
```

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/yourusername/aws-log-sentinel.git
cd aws-log-sentinel

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate      # Windows
source .venv/bin/activate   # Linux/macOS

# Install dependencies
pip install -e .
```

### 2. Configure AWS Credentials

```bash
cp .env.example .env
# Edit .env with your AWS credentials
```

```env
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1
```

### 3. IAM Permissions Required

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups",
                "logs:StartQuery",
                "logs:GetQueryResults"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "codedeploy:ListDeploymentGroups",
                "codedeploy:ListDeployments",
                "codedeploy:GetDeployment"
            ],
            "Resource": "*"
        }
    ]
}
```

### 4. Run the Server

```bash
python server.py
```

## MCP Client Configuration

Add to your MCP client (Claude Desktop, etc.):

```json
{
  "mcpServers": {
    "aws-log-sentinel": {
      "command": "python",
      "args": ["C:/path/to/aws-log-sentinel/server.py"],
      "env": {
        "AWS_ACCESS_KEY_ID": "your-key",
        "AWS_SECRET_ACCESS_KEY": "your-secret",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

## Testing

```bash
# Install test dependencies
pip install pytest moto

# Run tests
pytest tests/ -v
```

Tests use [moto](https://github.com/getmoto/moto) to mock AWS services - no real AWS credentials needed.

## Safety Constraints

| Constraint | Value | Purpose |
|------------|-------|---------|
| Max Lookback | 60 minutes | Prevents expensive historical queries |
| Max Results | 20 entries | Limits data transfer and processing |
| Error Filter Only | Regex pattern | No raw log dumps, only errors |
| Read-Only | No writes | Cannot modify AWS resources |

## Project Structure

```
aws-log-sentinel/
├── server.py           # MCP server with tool implementations
├── pyproject.toml      # Dependencies and project config
├── .env.example        # AWS credential template
├── .gitignore          # Git ignore patterns
├── README.md           # This file
└── tests/
    ├── conftest.py                    # Shared pytest fixtures
    ├── test_check_recent_errors.py    # CloudWatch tool tests
    ├── test_check_deployment_status.py # CodeDeploy tool tests
    └── test_list_log_groups.py        # Log group listing tests
```

## License

MIT
