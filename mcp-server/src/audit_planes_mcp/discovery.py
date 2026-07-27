"""Resolve the working context: region, account, and audit-log resource identifiers.

Strategy (per the plan):
  1. Region: explicit arg -> AWS_REGION/AWS_DEFAULT_REGION -> session default.
  2. AWS-native discovery via boto3 — CloudTrail/GuardDuty are account-level; repo
     resources are scoped by `name_prefix` naming and the `atkplane:*` default tags.
  3. Optional `terraform output -json` overlay when run from a checkout (exact ids).

Nothing here mutates AWS. Failures (permissions, absent resources) degrade to `None`
values rather than raising, so a partial estate still yields a useful map.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

from . import DEFAULT_NAME_PREFIX
from .awsclients import Aws, for_region, resolve_region

# Canonical resolved names, keyed off name_prefix (see modules/foundation/main.tf).
# These are the naming-convention fallbacks; AWS discovery and TF outputs refine them.
def convention_names(name_prefix: str, account_id: str | None) -> dict[str, Any]:
    glue_db = f"{name_prefix}_audit".replace("-", "_")
    bucket = f"{name_prefix}-audit-logs-{account_id}" if account_id else None
    return {
        "trail_name": f"{name_prefix}-trail",
        "data_events_trail_name": f"{name_prefix}-s5-data-events",
        "log_bucket": bucket,
        "cloudtrail_log_group": f"/aws/cloudtrail/{name_prefix}",
        "glue_database": glue_db,
        "athena_workgroup": f"{name_prefix}-investigations",
        "athena_results_location": f"s3://{bucket}/athena-results/" if bucket else None,
        "sns_topic_name": f"{name_prefix}-alerts",
        "waf_log_group": f"aws-waf-logs-{name_prefix}-s4",
        "tables": {
            "cloudtrail": "cloudtrail_logs",
            "vpc_flow": "vpc_flow_logs",
            "resolver": "route53_resolver_logs",
            "alb": "alb_access_logs",
        },
    }


def discover_estate(
    name_prefix: str = DEFAULT_NAME_PREFIX,
    region: str | None = None,
    use_terraform: bool | None = None,
    terraform_dir: str | None = None,
) -> dict[str, Any]:
    """Resolve the audit-log estate. Returns the context map other tools consume."""
    region = resolve_region(region)
    aws = for_region(region)

    account_id = None
    caller_arn = None
    try:
        ident = aws.client("sts").get_caller_identity()
        account_id = ident["Account"]
        caller_arn = ident["Arn"]
    except Exception as exc:  # noqa: BLE001 - surface, don't crash
        return {
            "ok": False,
            "error": f"Could not call sts:GetCallerIdentity — are credentials configured? ({exc})",
            "region": region,
            "name_prefix": name_prefix,
        }

    estate: dict[str, Any] = {
        "ok": True,
        "account_id": account_id,
        "caller_arn": caller_arn,
        "region": region,
        "name_prefix": name_prefix,
        "source": "aws-convention",
        **convention_names(name_prefix, account_id),
    }

    _augment_from_aws(aws, region, name_prefix, estate)

    if use_terraform is None:
        use_terraform = terraform_dir is not None
    if use_terraform:
        overlay = _terraform_outputs(terraform_dir)
        if overlay:
            _apply_terraform_overlay(estate, overlay)
            estate["source"] = "aws+terraform"

    return estate


def _augment_from_aws(aws: Aws, region: str | None, name_prefix: str, estate: dict) -> None:
    """Confirm/enrich identifiers from live AWS (best-effort)."""
    # CloudTrail — find the trail(s) and note the shared trail if the prefix matches.
    try:
        trails = aws.client("cloudtrail").describe_trails(includeShadowTrails=False)["trailList"]
        estate["trails"] = [
            {
                "name": t.get("Name"),
                "s3_bucket": t.get("S3BucketName"),
                "multi_region": t.get("IsMultiRegionTrail"),
                "cwl_group_arn": t.get("CloudWatchLogsLogGroupArn"),
                "home_region": t.get("HomeRegion"),
            }
            for t in trails
        ]
        for t in trails:
            if t.get("Name", "").startswith(name_prefix) and t.get("S3BucketName"):
                estate["log_bucket"] = t["S3BucketName"]
                estate["athena_results_location"] = f"s3://{t['S3BucketName']}/athena-results/"
    except Exception as exc:  # noqa: BLE001
        estate.setdefault("warnings", []).append(f"cloudtrail:DescribeTrails failed: {exc}")

    # GuardDuty detector id (account/region singleton).
    try:
        detectors = aws.client("guardduty").list_detectors().get("DetectorIds", [])
        estate["guardduty_detector_id"] = detectors[0] if detectors else None
    except Exception as exc:  # noqa: BLE001
        estate.setdefault("warnings", []).append(f"guardduty:ListDetectors failed: {exc}")

    # Which of the convention tables actually exist in Glue.
    try:
        glue = aws.client("glue")
        present = {}
        for key, table in estate["tables"].items():
            try:
                glue.get_table(DatabaseName=estate["glue_database"], Name=table)
                present[key] = table
            except glue.exceptions.EntityNotFoundException:
                continue
            except Exception:  # noqa: BLE001 - database missing, etc.
                break
        estate["tables_present"] = present
    except Exception as exc:  # noqa: BLE001
        estate.setdefault("warnings", []).append(f"glue:GetTable probing failed: {exc}")


_TF_OUTPUT_MAP = {
    "region": "region",
    "athena_workgroup": "athena_workgroup",
    "glue_database": "glue_database",
    "log_bucket": "log_bucket",
    "cloudtrail_log_group": "cloudtrail_log_group",
    "guardduty_detector_id": "guardduty_detector_id",
    "scenario_05_crown_jewels_bucket": "crown_jewels_bucket",
    "scenario_02_flow_logs_table": ("tables", "vpc_flow"),
    "scenario_03_resolver_query_logs_table": ("tables", "resolver"),
    "scenario_04_alb_access_logs_table": ("tables", "alb"),
}


def _terraform_outputs(terraform_dir: str | None) -> dict[str, Any] | None:
    """Read `terraform output -json` from a checkout. Tolerant of missing state/binary."""
    tf_dir = terraform_dir or _default_tf_dir()
    if not tf_dir or not os.path.isdir(tf_dir):
        return None
    if not shutil.which("terraform"):
        return None
    try:
        proc = subprocess.run(
            ["terraform", f"-chdir={tf_dir}", "output", "-json"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        return json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _default_tf_dir() -> str | None:
    """The repo root is the parent of this package's mcp-server/ directory."""
    here = os.path.dirname(os.path.abspath(__file__))
    # src/audit_planes_mcp -> src -> mcp-server -> repo root
    repo_root = os.path.abspath(os.path.join(here, "..", "..", ".."))
    return repo_root if os.path.isfile(os.path.join(repo_root, "variables.tf")) else None


def _apply_terraform_overlay(estate: dict, overlay: dict) -> None:
    if overlay.get("athena_results_location", {}).get("value"):
        estate["athena_results_location"] = overlay["athena_results_location"]["value"]
    for out_key, dest in _TF_OUTPUT_MAP.items():
        entry = overlay.get(out_key)
        if not entry or entry.get("value") in (None, ""):
            continue
        value = entry["value"]
        if isinstance(dest, tuple):
            estate.setdefault(dest[0], {})[dest[1]] = value
        else:
            estate[dest] = value
    # Derive the results location from the (possibly TF-provided) bucket if still unset.
    if estate.get("log_bucket") and not estate.get("athena_results_location"):
        estate["athena_results_location"] = f"s3://{estate['log_bucket']}/athena-results/"
