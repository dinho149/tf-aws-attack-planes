"""FastMCP server exposing the audit-log health & investigation tools.

Run over stdio: `aws-audit-planes-mcp` (console script) or `python -m audit_planes_mcp.server`.
Credentials come from the standard boto3 chain (AWS_PROFILE/env/SSO/role).
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from . import DEFAULT_NAME_PREFIX, __version__
from . import alarms as _alarms
from . import config_checks as _checks
from . import investigations as _inv
from .discovery import discover_estate as _discover

mcp = FastMCP("aws-audit-planes")


@mcp.tool()
def discover_estate(name_prefix: str = DEFAULT_NAME_PREFIX, region: str | None = None,
                    use_terraform: bool = False,
                    terraform_dir: str | None = None) -> dict[str, Any]:
    """Resolve the audit-log estate for a region: account id, CloudTrail trails, GuardDuty
    detector, Athena workgroup, Glue database and which tables exist, log bucket, and the
    alert topic name. Call this first — the identifiers it returns feed the other tools.

    Discovery is AWS-native (by name_prefix and atkplane:* tags); set use_terraform=true to
    overlay exact ids from `terraform output` when running inside a repo checkout.
    """
    return _discover(name_prefix=name_prefix, region=region,
                     use_terraform=use_terraform, terraform_dir=terraform_dir)


@mcp.tool()
def check_configuration(planes: list[str] | None = None,
                        name_prefix: str = DEFAULT_NAME_PREFIX,
                        region: str | None = None) -> dict[str, Any]:
    """Audit whether each attack plane's logging is on and correct, per the Field Guide's
    prerequisites and caveats. Returns findings {plane, check_id, status, detail,
    remediation, evidence} plus a summary verdict.

    Checks: multi-region + validated CloudTrail with dual S3/CloudWatch delivery (api);
    S3 data events enabled and not looping on the log bucket (storage); Flow Logs custom
    format with pkt-srcaddr/flow-direction/instance-id (network); Resolver query logging
    (dns); WAF + ALB logging and COUNT-mode warnings (web); GuardDuty on and SNS
    subscriptions confirmed (detectors). Optionally filter `planes` to a subset of
    api|storage|network|dns|web|detectors.
    """
    return _checks.run_checks(name_prefix=name_prefix, region=region, planes=planes)


@mcp.tool()
def check_alarms(name_prefix: str = DEFAULT_NAME_PREFIX, region: str | None = None,
                 state: str | None = None) -> dict[str, Any]:
    """Report the audit-log CloudWatch alarms: state (ALARM/OK/INSUFFICIENT_DATA), reason,
    last update, threshold, and whether each alarm's SNS action reaches a *confirmed*
    endpoint. Flags expected atkplane alarms that are missing and notes the DNS plane's
    deliberate no-alarm/hunter-Lambda design. Filter with `state` to e.g. only ALARM.
    """
    return _alarms.check_alarms(name_prefix=name_prefix, region=region, state=state)


@mcp.tool()
def list_investigations() -> dict[str, Any]:
    """List the canonical investigation checks available to `run_investigation` — each
    check's id, plane, engine (athena/logs_insights), title, and any required filters."""
    return {"count": len(_inv.CATALOG), "checks": _inv.list_catalog()}


@mcp.tool()
def run_investigation(check: str, region: str | None = None,
                      name_prefix: str = DEFAULT_NAME_PREFIX, window_hours: int = 24,
                      filters: dict | None = None, max_rows: int = 200,
                      use_terraform: bool = False,
                      terraform_dir: str | None = None) -> dict[str, Any]:
    """Run one canonical, time-bounded investigation by id (see `list_investigations`),
    e.g. 'network.top-talkers', 'dns.tunnelling', 'storage.reads-by-principal'. Table names
    and the time window are auto-filled from discovery. Some checks need a filter:
    'api.principal-timeline' needs filters={"principal": "..."}; the storage checks need
    filters={"bucket": "..."}. Returns rows plus bytes scanned.
    """
    return _inv.run_investigation(check=check, region=region, name_prefix=name_prefix,
                                  window_hours=window_hours, filters=filters,
                                  max_rows=max_rows, use_terraform=use_terraform,
                                  terraform_dir=terraform_dir)


@mcp.tool()
def list_saved_queries(name_prefix: str = DEFAULT_NAME_PREFIX,
                       region: str | None = None, use_terraform: bool = False,
                       terraform_dir: str | None = None) -> dict[str, Any]:
    """List the saved Athena named queries in the workgroup (the repo's s01..s05 queries),
    each with its id, database, and full SQL. Run one by id with `run_query`."""
    return _inv.list_saved_queries(name_prefix=name_prefix, region=region,
                                   use_terraform=use_terraform, terraform_dir=terraform_dir)


@mcp.tool()
def run_query(sql: str | None = None, named_query_id: str | None = None,
              region: str | None = None, name_prefix: str = DEFAULT_NAME_PREFIX,
              workgroup: str | None = None, database: str | None = None,
              max_rows: int = 200, use_terraform: bool = False,
              terraform_dir: str | None = None) -> dict[str, Any]:
    """Run a read-only Athena query — either a saved query by `named_query_id` or ad-hoc
    `sql` — in the discovered workgroup, and return the rows plus data_scanned_bytes.
    Only SELECT/WITH/SHOW/DESCRIBE statements are permitted; anything else is refused.
    """
    return _inv.run_query(sql=sql, named_query_id=named_query_id, region=region,
                          name_prefix=name_prefix, workgroup=workgroup, database=database,
                          max_rows=max_rows, use_terraform=use_terraform,
                          terraform_dir=terraform_dir)


@mcp.tool()
def describe_plane(plane: str) -> dict[str, Any]:
    """Return concise Field Guide guidance for a plane — the log source, what it answers,
    and the gotcha that ruins investigations. `plane` is one of
    api|network|dns|web|storage (or 'all')."""
    if plane == "all":
        return {"planes": PLANE_GUIDE}
    guide = PLANE_GUIDE.get(plane)
    if not guide:
        return {"error": f"Unknown plane '{plane}'.", "available": list(PLANE_GUIDE)}
    return {"plane": plane, **guide}


PLANE_GUIDE: dict[str, dict[str, str]] = {
    "api": {
        "log_source": "CloudTrail (management events)",
        "answers": "Who called which AWS API, from where, with what user agent?",
        "gotcha": "CloudTrail logs ONLY AWS API activity — it is blind to network, DNS, "
                  "and web-layer traffic. Anchor investigations on userIdentity, "
                  "sourceIPAddress, userAgent.",
    },
    "network": {
        "log_source": "VPC Flow Logs",
        "answers": "Which IP talked to which IP, on what port, how many bytes, accept/reject?",
        "gotcha": "Behind a NAT gateway the source shows as the NAT IP unless you add "
                  "pkt-srcaddr/pkt-dstaddr to a custom format. Flow Logs also exclude "
                  "Amazon-resolver DNS — that's the DNS plane's job.",
    },
    "dns": {
        "log_source": "Route 53 Resolver query logs",
        "answers": "What names are our resources resolving (beacons, DGA, tunnelling)?",
        "gotcha": "A workload pointed at an external resolver (8.8.8.8) or DoH bypasses "
                  "Resolver logging, DNS Firewall, AND GuardDuty DNS findings at once. "
                  "Force outbound DNS through the Amazon resolver.",
    },
    "web": {
        "log_source": "WAF, ALB & CloudFront logs",
        "answers": "What is hitting our public endpoints, and what did WAF do about it?",
        "gotcha": "Behind a CDN the ALB sees the proxy IP — the real client is in "
                  "X-Forwarded-For. And a COUNT-mode WAF rule observes but never blocks.",
    },
    "storage": {
        "log_source": "CloudTrail S3 data events (and S3 server access logs)",
        "answers": "Who read or wrote which object?",
        "gotcha": "Data events are OFF by default and billed per event. Without them you "
                  "cannot prove whether data was read. Scope selectors to sensitive bucket "
                  "ARNs — never the log bucket (recursive loop).",
    },
}


def main() -> None:
    import sys
    if "--version" in sys.argv:
        print(f"aws-audit-planes-mcp {__version__}")
        return
    mcp.run()


if __name__ == "__main__":
    main()
