"""CloudWatch alarm state + whether their SNS actions reach a confirmed endpoint.

Read-only: DescribeAlarms, ListSubscriptionsByTopic. Surfaces the scenario-3 gap (DNS has
no metric-filter alarm — it relies on a scheduled hunter Lambda).
"""

from __future__ import annotations

from typing import Any

from .awsclients import for_region, resolve_region

# Named alarms the foundation/scenarios create (resolved with the default prefix).
KNOWN_ALARMS = {
    "{p}-enumeration-burst": "api (scenario 1) — AccessDenied burst",
    "{p}-iam-persistence": "api (scenario 1) — IAM persistence actions",
    "{p}-egress-exfil": "network (scenario 2) — egress bytes threshold",
    "{p}-waf-blocks": "web (scenario 4) — WAF blocked requests",
    "{p}-crown-jewels-reads": "storage (scenario 5) — S3 GetObject volume",
}


def check_alarms(name_prefix: str = "atkplane", region: str | None = None,
                 state: str | None = None) -> dict[str, Any]:
    region = resolve_region(region)
    aws = for_region(region)
    cw = aws.client("cloudwatch")

    alarms: list[dict] = []
    paginator = cw.get_paginator("describe_alarms")
    for page in paginator.paginate(AlarmNamePrefix=name_prefix, AlarmTypes=["MetricAlarm"]):
        alarms.extend(page.get("MetricAlarms", []))

    confirmed_topics = _confirmed_sns_topics(aws)

    results = []
    for a in alarms:
        if state and a.get("StateValue") != state:
            continue
        actions = a.get("AlarmActions", [])
        wired = [act for act in actions if act in confirmed_topics]
        results.append({
            "name": a.get("AlarmName"),
            "state": a.get("StateValue"),
            "state_reason": a.get("StateReason"),
            "state_updated": _iso(a.get("StateUpdatedTimestamp")),
            "metric": a.get("MetricName"),
            "namespace": a.get("Namespace"),
            "threshold": a.get("Threshold"),
            "comparison": a.get("ComparisonOperator"),
            "actions": actions,
            "notifies_confirmed_endpoint": bool(wired),
        })
    results.sort(key=lambda r: (r["state"] != "ALARM", r["name"] or ""))

    found_names = {a.get("AlarmName") for a in alarms}
    expected = {k.format(p=name_prefix): v for k, v in KNOWN_ALARMS.items()}
    missing = {name: desc for name, desc in expected.items() if name not in found_names}

    notes = []
    if missing:
        notes.append(f"Expected atkplane alarms not found: {sorted(missing)} "
                     "(fine if that scenario isn't deployed).")
    notes.append("DNS plane (scenario 3) has no CloudWatch alarm by design — detection is "
                 f"the scheduled hunter Lambda '{name_prefix}-s3-hunter' (rate 5 min).")

    return {
        "region": region,
        "name_prefix": name_prefix,
        "alarm_count": len(results),
        "in_alarm": [r["name"] for r in results if r["state"] == "ALARM"],
        "alarms": results,
        "missing_expected": missing,
        "notes": notes,
    }


def _confirmed_sns_topics(aws) -> set[str]:
    """Topic ARNs that have at least one confirmed subscription."""
    sns = aws.client("sns")
    confirmed = set()
    try:
        topics = [t["TopicArn"] for t in sns.list_topics().get("Topics", [])]
    except Exception:  # noqa: BLE001
        return confirmed
    for arn in topics:
        try:
            subs = sns.list_subscriptions_by_topic(TopicArn=arn).get("Subscriptions", [])
        except Exception:  # noqa: BLE001
            continue
        if any(s.get("SubscriptionArn") not in ("PendingConfirmation", "Deleted") for s in subs):
            confirmed.add(arn)
    return confirmed


def _iso(dt) -> str | None:
    return dt.isoformat() if dt is not None and hasattr(dt, "isoformat") else None
