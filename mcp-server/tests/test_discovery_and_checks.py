"""Unit tests for pure discovery/config-check helpers (no AWS calls)."""

from audit_planes_mcp import config_checks as checks
from audit_planes_mcp import discovery


def test_convention_names_default_prefix():
    names = discovery.convention_names("atkplane", "123456789012")
    assert names["log_bucket"] == "atkplane-audit-logs-123456789012"
    assert names["cloudtrail_log_group"] == "/aws/cloudtrail/atkplane"
    assert names["glue_database"] == "atkplane_audit"
    assert names["athena_workgroup"] == "atkplane-investigations"
    assert names["athena_results_location"] == "s3://atkplane-audit-logs-123456789012/athena-results/"
    assert names["tables"]["cloudtrail"] == "cloudtrail_logs"


def test_convention_names_hyphenated_prefix_glue_db():
    names = discovery.convention_names("my-team", "111122223333")
    # Glue/Athena identifiers can't contain hyphens.
    assert names["glue_database"] == "my_team_audit"
    assert names["log_bucket"] == "my-team-audit-logs-111122223333"


def test_convention_names_without_account():
    names = discovery.convention_names("atkplane", None)
    assert names["log_bucket"] is None
    assert names["athena_results_location"] is None


def test_terraform_overlay_applies_values():
    estate = dict(discovery.convention_names("atkplane", "123456789012"))
    estate["ok"] = True
    overlay = {
        "athena_workgroup": {"value": "custom-wg"},
        "glue_database": {"value": "custom_db"},
        "scenario_02_flow_logs_table": {"value": "flow_v2"},
        "guardduty_detector_id": {"value": ""},  # empty -> ignored
    }
    discovery._apply_terraform_overlay(estate, overlay)
    assert estate["athena_workgroup"] == "custom-wg"
    assert estate["glue_database"] == "custom_db"
    assert estate["tables"]["vpc_flow"] == "flow_v2"
    assert "guardduty_detector_id" not in estate  # empty value not applied


def test_summary_verdicts():
    fails = [checks._finding("api", "x", checks.FAIL, "d")]
    assert checks._summarize(fails)["verdict"] == "gaps-found"

    warns = [checks._finding("api", "x", checks.WARN, "d")]
    assert checks._summarize(warns)["verdict"] == "warnings"

    passes = [checks._finding("api", "x", checks.PASS, "d")]
    assert checks._summarize(passes)["verdict"] == "healthy"

    counts = checks._summarize(fails + warns + passes)["counts"]
    assert counts[checks.FAIL] == 1 and counts[checks.WARN] == 1 and counts[checks.PASS] == 1
