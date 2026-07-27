"""aws-audit-planes-mcp — an MCP server for AWS audit-log health and investigation.

Turns the lessons of the *Field Guide to AWS Audit Logs* series into tools an AI
assistant can call against a live AWS account: verify each plane's logging is on and
correct, run the canonical Athena/Logs-Insights investigations, and check the alarms.

Every AWS call the server makes is read-only (describe/list/get) plus Athena and
CloudWatch Logs Insights query execution. It never mutates configuration or resources.
"""

__version__ = "0.1.0"

DEFAULT_NAME_PREFIX = "atkplane"
