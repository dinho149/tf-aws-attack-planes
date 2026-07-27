"""Canonical investigation catalog plus the Athena and CloudWatch Logs Insights runners.

The catalog generalizes the repo's saved named queries (s01..s05) into table-name- and
window-parameterized checks, so an assistant can run "network.top-talkers" without
hand-writing SQL. Raw SQL and the exact saved queries are also reachable via
`run_query` / `list_saved_queries`.

Only read queries execute. `run_query` rejects any statement that isn't SELECT/WITH/SHOW/
DESCRIBE. Athena runs inside the discovered workgroup (results land in its configured S3
output); Logs Insights runs against the WAF log group.
"""

from __future__ import annotations

import time
from typing import Any

from .awsclients import for_region, resolve_region
from .discovery import discover_estate

_ALLOWED_STARTS = ("select", "with", "show", "describe", "explain")
_ATHENA_TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED"}


# --------------------------------------------------------------------- catalog schema
# Each entry: engine, plane, title, table key (for athena), and a template.
# Templates use {table} and {window} placeholders; time-bounded via {window}.
CATALOG: dict[str, dict[str, Any]] = {
    "api.enumeration": {
        "engine": "athena", "plane": "api", "table": "cloudtrail",
        "title": "AccessDenied burst by source IP (enumeration)",
        "sql": """
SELECT sourceipaddress, errorcode, count(*) AS calls
FROM {table}
WHERE {window}
  AND errorcode IS NOT NULL
  AND (errorcode = 'AccessDenied' OR errorcode LIKE '%UnauthorizedOperation')
GROUP BY sourceipaddress, errorcode
ORDER BY calls DESC
LIMIT 50""",
    },
    "api.persistence": {
        "engine": "athena", "plane": "api", "table": "cloudtrail",
        "title": "IAM persistence actions (new users/keys/policy attachments)",
        "sql": """
SELECT eventtime, useridentity.username AS actor, eventname, sourceipaddress,
       json_extract_scalar(requestparameters, '$.userName') AS target_user
FROM {table}
WHERE {window}
  AND eventname IN ('CreateUser','CreateAccessKey','AttachUserPolicy',
                    'AttachRolePolicy','PutUserPolicy','UpdateAssumeRolePolicy')
ORDER BY eventtime""",
    },
    "api.principal-timeline": {
        "engine": "athena", "plane": "api", "table": "cloudtrail",
        "title": "Full activity timeline for one principal",
        "needs": ["principal"],
        "sql": """
SELECT eventtime, eventsource, eventname, sourceipaddress, useragent, errorcode
FROM {table}
WHERE {window}
  AND (useridentity.username = '{principal}' OR useridentity.arn = '{principal}')
ORDER BY eventtime""",
    },
    "network.top-talkers": {
        "engine": "athena", "plane": "network", "table": "vpc_flow",
        "title": "Top egress talkers by bytes",
        "sql": """
SELECT pkt_srcaddr AS host, dstaddr AS destination, dstport,
       SUM(bytes) AS total_bytes, SUM(packets) AS total_packets
FROM {table}
WHERE {window}
  AND flow_direction = 'egress'
  AND action = 'ACCEPT'
GROUP BY pkt_srcaddr, dstaddr, dstport
ORDER BY total_bytes DESC
LIMIT 25""",
    },
    "network.reject-probe": {
        "engine": "athena", "plane": "network", "table": "vpc_flow",
        "title": "REJECT fan-out (lateral-movement probing)",
        "sql": """
SELECT srcaddr, dstport, COUNT(*) AS attempts,
       COUNT(DISTINCT dstaddr) AS targets_touched
FROM {table}
WHERE {window}
  AND action = 'REJECT'
GROUP BY srcaddr, dstport
ORDER BY attempts DESC
LIMIT 50""",
    },
    "dns.tunnelling": {
        "engine": "athena", "plane": "dns", "table": "resolver",
        "title": "Long-label TXT/NULL lookups (DNS tunnelling)",
        "sql": """
SELECT query_name,
       length(split_part(query_name, '.', 1)) AS first_label_len,
       COUNT(*) AS lookups
FROM {table}
WHERE {window}
  AND query_type IN ('TXT', 'NULL')
GROUP BY query_name
ORDER BY first_label_len DESC, lookups DESC
LIMIT 20""",
    },
    "dns.dga-beacon": {
        "engine": "athena", "plane": "dns", "table": "resolver",
        "title": "NXDOMAIN storm by parent domain (DGA beacon)",
        "sql": """
SELECT array_join(slice(split(rtrim(query_name, '.'), '.'), -2, 2), '.') AS parent_domain,
       COUNT(*) AS nxdomain_lookups,
       COUNT(DISTINCT query_name) AS distinct_names
FROM {table}
WHERE {window}
  AND rcode = 'NXDOMAIN'
GROUP BY array_join(slice(split(rtrim(query_name, '.'), '.'), -2, 2), '.')
ORDER BY nxdomain_lookups DESC
LIMIT 20""",
    },
    "web.alb-status-by-ip": {
        "engine": "athena", "plane": "web", "table": "alb",
        "title": "ALB status-code shape per client IP",
        "sql": """
SELECT client_ip, elb_status_code, COUNT(*) AS requests
FROM {table}
WHERE {window}
GROUP BY client_ip, elb_status_code
ORDER BY requests DESC
LIMIT 20""",
    },
    "web.waf-blocks-by-ip": {
        "engine": "logs_insights", "plane": "web",
        "title": "WAF blocks by client IP and matched rule",
        "log_group_key": "waf_log_group",
        "query": """fields httpRequest.clientIp, httpRequest.uri, terminatingRuleId, action
| filter action = "BLOCK"
| stats count() as hits by httpRequest.clientIp, terminatingRuleId
| sort hits desc""",
    },
    "storage.reads-by-principal": {
        "engine": "athena", "plane": "storage", "table": "cloudtrail",
        "title": "S3 object reads on a bucket, by principal",
        "needs": ["bucket"],
        "sql": """
SELECT useridentity.arn AS principal, sourceipaddress, eventname,
       COUNT(*) AS object_calls
FROM {table}
WHERE {window}
  AND eventsource = 's3.amazonaws.com'
  AND eventname IN ('GetObject','PutObject','DeleteObject')
  AND requestparameters LIKE '%{bucket}%'
GROUP BY 1, 2, 3
ORDER BY object_calls DESC
LIMIT 100""",
    },
    "storage.objects-read": {
        "engine": "athena", "plane": "storage", "table": "cloudtrail",
        "title": "Exact object keys read (disclosure evidence)",
        "needs": ["bucket"],
        "sql": """
SELECT eventtime, useridentity.arn AS principal, sourceipaddress, eventname,
       json_extract_scalar(requestparameters, '$.key') AS object_key
FROM {table}
WHERE {window}
  AND eventsource = 's3.amazonaws.com'
  AND eventname IN ('GetObject','PutObject','DeleteObject')
  AND requestparameters LIKE '%{bucket}%'
ORDER BY eventtime
LIMIT 1000""",
    },
}

# Which partition column + timestamp expression each table uses for the window predicate.
_WINDOW_SPEC = {
    "cloudtrail": ("date", "from_iso8601_timestamp(eventtime)"),
    "vpc_flow": ("date", "from_unixtime(start)"),
    "resolver": ("date", "from_iso8601_timestamp(query_timestamp)"),
    "alb": ("date", "from_iso8601_timestamp(time)"),
}


def list_catalog() -> list[dict]:
    return [
        {"check": k, "plane": v["plane"], "engine": v["engine"], "title": v["title"],
         "needs": v.get("needs", [])}
        for k, v in CATALOG.items()
    ]


def _window_predicate(table_key: str, hours: int) -> str:
    part_col, ts_expr = _WINDOW_SPEC[table_key]
    # Partition prune to whole days (format yyyy/MM/dd) then refine to the exact hours.
    return (
        f'"{part_col}" >= date_format(current_timestamp - interval \'{hours}\' hour, \'%Y/%m/%d\')'
        f" AND {ts_expr} > current_timestamp - interval '{hours}' hour"
    )


# ------------------------------------------------------------------- Athena execution
def _run_athena(estate: dict, region: str, sql: str, max_rows: int) -> dict:
    workgroup = estate.get("athena_workgroup")
    database = estate.get("glue_database")
    aws = for_region(region)
    athena = aws.client("athena")

    start_kwargs = {"QueryString": sql, "WorkGroup": workgroup}
    if database:
        start_kwargs["QueryExecutionContext"] = {"Database": database}
    # Only set OutputLocation if the workgroup doesn't enforce one; harmless to include.
    if estate.get("athena_results_location"):
        start_kwargs["ResultConfiguration"] = {"OutputLocation": estate["athena_results_location"]}

    try:
        qid = athena.start_query_execution(**start_kwargs)["QueryExecutionId"]
    except Exception as exc:  # noqa: BLE001
        # Retry without an explicit OutputLocation (workgroup may enforce it).
        start_kwargs.pop("ResultConfiguration", None)
        try:
            qid = athena.start_query_execution(**start_kwargs)["QueryExecutionId"]
        except Exception as exc2:  # noqa: BLE001
            return {"ok": False, "error": f"StartQueryExecution failed: {exc2}", "sql": sql}

    state, reason, scanned = _poll_athena(athena, qid)
    if state != "SUCCEEDED":
        return {"ok": False, "query_execution_id": qid, "state": state,
                "error": reason or state, "sql": sql}

    rows, columns = _fetch_athena_rows(athena, qid, max_rows)
    return {
        "ok": True,
        "query_execution_id": qid,
        "state": state,
        "data_scanned_bytes": scanned,
        "columns": columns,
        "row_count": len(rows),
        "rows": rows,
        "sql": sql,
    }


def _poll_athena(athena, qid: str, timeout_s: int = 90):
    deadline = time.monotonic() + timeout_s
    delay = 0.5
    while True:
        ex = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = ex["Status"]["State"]
        if state in _ATHENA_TERMINAL:
            reason = ex["Status"].get("StateChangeReason")
            scanned = ex.get("Statistics", {}).get("DataScannedInBytes")
            return state, reason, scanned
        if time.monotonic() > deadline:
            return "TIMEOUT", f"Query {qid} did not finish within {timeout_s}s", None
        time.sleep(delay)
        delay = min(delay * 1.5, 3.0)


def _fetch_athena_rows(athena, qid: str, max_rows: int):
    resp = athena.get_query_results(QueryExecutionId=qid, MaxResults=min(max_rows + 1, 1000))
    result = resp["ResultSet"]
    columns = [c["Name"] for c in result["ResultSetMetadata"]["ColumnInfo"]]
    data_rows = result["Rows"]
    # First row is the header when the query has results.
    body = data_rows[1:] if data_rows else []
    rows = []
    for r in body[:max_rows]:
        cells = [c.get("VarCharValue") for c in r.get("Data", [])]
        rows.append(dict(zip(columns, cells)))
    return rows, columns


# -------------------------------------------------------------- Logs Insights execution
def _run_logs_insights(estate: dict, region: str, log_group: str, query: str,
                       hours: int, max_rows: int) -> dict:
    aws = for_region(region)
    logs = aws.client("logs")
    end = int(time.time())
    start = end - hours * 3600
    try:
        qid = logs.start_query(logGroupName=log_group, startTime=start, endTime=end,
                               queryString=query, limit=max_rows)["queryId"]
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"logs:StartQuery failed for '{log_group}': {exc}",
                "query": query}

    deadline = time.monotonic() + 90
    while True:
        res = logs.get_query_results(queryId=qid)
        status = res["status"]
        if status in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        if time.monotonic() > deadline:
            status = "Timeout"
            break
        time.sleep(1.0)

    if status != "Complete":
        return {"ok": False, "query_id": qid, "state": status,
                "error": f"Logs Insights query ended: {status}", "query": query}

    rows = [{f["field"]: f["value"] for f in row if f["field"] != "@ptr"}
            for row in res.get("results", [])]
    return {"ok": True, "query_id": qid, "state": status, "row_count": len(rows),
            "rows": rows, "query": query}


# ---------------------------------------------------------------------- public entry
def run_investigation(check: str, region: str | None = None, name_prefix: str = "atkplane",
                      window_hours: int = 24, filters: dict | None = None,
                      use_terraform: bool | None = None,
                      terraform_dir: str | None = None, max_rows: int = 200) -> dict:
    filters = filters or {}
    spec = CATALOG.get(check)
    if not spec:
        return {"ok": False, "error": f"Unknown check '{check}'.",
                "available": list(CATALOG.keys())}

    for need in spec.get("needs", []):
        if not filters.get(need):
            return {"ok": False, "error": f"Check '{check}' requires filters.{need}.",
                    "needs": spec["needs"]}

    region = resolve_region(region)
    estate = discover_estate(name_prefix=name_prefix, region=region,
                             use_terraform=use_terraform, terraform_dir=terraform_dir)
    if not estate.get("ok"):
        return {"ok": False, "error": estate.get("error", "discovery failed")}

    if spec["engine"] == "logs_insights":
        log_group = estate.get(spec["log_group_key"])
        result = _run_logs_insights(estate, region, log_group, spec["query"],
                                    window_hours, max_rows)
        result["check"] = check
        result["title"] = spec["title"]
        return result

    # Athena path — resolve the table name from discovery.
    table = (estate.get("tables_present", {}) or estate.get("tables", {})).get(spec["table"])
    if not table:
        return {"ok": False, "check": check,
                "error": f"Table for '{spec['table']}' not found — the {spec['plane']} plane "
                         "may not be deployed/logging yet.",
                "remediation": f"Enable the {spec['plane']} plane and its Glue table."}

    window = _window_predicate(spec["table"], window_hours)
    sql = spec["sql"].format(table=table, window=window,
                             principal=filters.get("principal", ""),
                             bucket=filters.get("bucket", "")).strip()
    result = _run_athena(estate, region, sql, max_rows)
    result["check"] = check
    result["title"] = spec["title"]
    return result


def run_query(sql: str | None = None, named_query_id: str | None = None,
              region: str | None = None, name_prefix: str = "atkplane",
              workgroup: str | None = None, database: str | None = None,
              max_rows: int = 200, use_terraform: bool | None = None,
              terraform_dir: str | None = None) -> dict:
    region = resolve_region(region)
    estate = discover_estate(name_prefix=name_prefix, region=region,
                             use_terraform=use_terraform, terraform_dir=terraform_dir)
    if not estate.get("ok"):
        return {"ok": False, "error": estate.get("error", "discovery failed")}
    if workgroup:
        estate["athena_workgroup"] = workgroup
    if database:
        estate["glue_database"] = database

    if named_query_id and not sql:
        try:
            nq = for_region(region).client("athena").get_named_query(
                NamedQueryId=named_query_id)["NamedQuery"]
            sql = nq["QueryString"]
            estate["glue_database"] = nq.get("Database", estate.get("glue_database"))
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"GetNamedQuery failed: {exc}"}

    if not sql:
        return {"ok": False, "error": "Provide either sql or named_query_id."}

    if not _is_read_only(sql):
        return {"ok": False, "error": "Refusing to run: only SELECT/WITH/SHOW/DESCRIBE "
                                      "statements are allowed (this server is read-only)."}

    return _run_athena(estate, region, sql.strip(), max_rows)


def _is_read_only(sql: str) -> bool:
    stripped = sql.strip().lstrip("(").lstrip()
    # Drop leading SQL line comments.
    lines = [ln for ln in stripped.splitlines() if not ln.strip().startswith("--")]
    body = "\n".join(lines).strip().lower()
    if not body:
        return False
    if ";" in body.rstrip(";"):
        return False  # reject multi-statement input
    return body.startswith(_ALLOWED_STARTS)


def list_saved_queries(region: str | None = None, name_prefix: str = "atkplane",
                       use_terraform: bool | None = None,
                       terraform_dir: str | None = None) -> dict:
    region = resolve_region(region)
    estate = discover_estate(name_prefix=name_prefix, region=region,
                             use_terraform=use_terraform, terraform_dir=terraform_dir)
    if not estate.get("ok"):
        return {"ok": False, "error": estate.get("error", "discovery failed")}
    workgroup = estate.get("athena_workgroup")
    athena = for_region(region).client("athena")
    try:
        ids = athena.list_named_queries(WorkGroup=workgroup).get("NamedQueryIds", [])
    except Exception:  # noqa: BLE001
        ids = athena.list_named_queries().get("NamedQueryIds", [])
    queries = []
    for i in range(0, len(ids), 50):
        batch = athena.batch_get_named_query(NamedQueryIds=ids[i:i + 50])
        for nq in batch.get("NamedQueries", []):
            if name_prefix and workgroup and nq.get("WorkGroup") not in (workgroup, None):
                continue
            queries.append({"name": nq.get("Name"), "id": nq.get("NamedQueryId"),
                            "database": nq.get("Database"),
                            "description": nq.get("Description"),
                            "sql": nq.get("QueryString")})
    queries.sort(key=lambda q: q.get("name") or "")
    return {"ok": True, "workgroup": workgroup, "count": len(queries), "queries": queries}
