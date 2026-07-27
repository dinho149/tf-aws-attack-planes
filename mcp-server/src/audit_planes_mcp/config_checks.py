"""Plane-by-plane configuration audit, derived from the Field Guide's prerequisites and
caveats. Each check returns a finding dict:

    {plane, check_id, status: pass|warn|fail|info, detail, remediation, evidence}

Every AWS call is read-only. Individual checks catch their own errors and downgrade to an
`info` finding so one missing permission doesn't sink the whole audit.
"""

from __future__ import annotations

from typing import Any, Callable

from .awsclients import Aws, for_region, resolve_region

PLANES = ("api", "storage", "network", "dns", "web", "detectors")

PASS, WARN, FAIL, INFO = "pass", "warn", "fail", "info"


def _finding(plane, check_id, status, detail, remediation="", evidence=None) -> dict:
    return {
        "plane": plane,
        "check_id": check_id,
        "status": status,
        "detail": detail,
        "remediation": remediation,
        "evidence": evidence or {},
    }


def run_checks(
    name_prefix: str = "atkplane",
    region: str | None = None,
    planes: list[str] | None = None,
) -> dict[str, Any]:
    region = resolve_region(region)
    aws = for_region(region)
    selected = [p for p in (planes or PLANES) if p in PLANES]

    runners: dict[str, Callable[[Aws, str, str], list[dict]]] = {
        "api": _check_api,
        "storage": _check_storage,
        "network": _check_network,
        "dns": _check_dns,
        "web": _check_web,
        "detectors": _check_detectors,
    }

    findings: list[dict] = []
    for plane in selected:
        try:
            findings.extend(runners[plane](aws, region, name_prefix))
        except Exception as exc:  # noqa: BLE001 - never let one plane crash the audit
            findings.append(
                _finding(plane, f"{plane}.error", INFO, f"Plane check raised: {exc}",
                         "Check IAM permissions for this plane's read APIs.")
            )

    return {
        "region": region,
        "name_prefix": name_prefix,
        "planes": selected,
        "summary": _summarize(findings),
        "findings": findings,
    }


def _summarize(findings: list[dict]) -> dict:
    counts = {PASS: 0, WARN: 0, FAIL: 0, INFO: 0}
    for f in findings:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    verdict = "healthy"
    if counts[FAIL]:
        verdict = "gaps-found"
    elif counts[WARN]:
        verdict = "warnings"
    return {"verdict": verdict, "counts": counts, "total": len(findings)}


# --------------------------------------------------------------------------- API plane
def _check_api(aws: Aws, region: str, name_prefix: str) -> list[dict]:
    ct = aws.client("cloudtrail")
    out: list[dict] = []
    trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

    if not trails:
        return [_finding("api", "api.trail-exists", FAIL,
                         "No CloudTrail trail found in this account/region.",
                         "Create a multi-region trail with log-file validation, delivering to "
                         "both S3 and CloudWatch Logs (see foundation/cloudtrail.tf).")]

    multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
    out.append(_finding(
        "api", "api.multi-region",
        PASS if multi_region else FAIL,
        f"{len(multi_region)} of {len(trails)} trail(s) are multi-region."
        + ("" if multi_region else " A single-region trail misses global-service events "
           "(IAM/STS/CloudFront) and every region an attacker roams to."),
        "" if multi_region else "Set is_multi_region_trail = true (and include_global_service_events).",
        {"trails": [t.get("Name") for t in trails]},
    ))

    for t in trails:
        name = t.get("Name")
        # Logging actually on?
        try:
            status = ct.get_trail_status(Name=t.get("TrailARN", name))
            is_logging = status.get("IsLogging", False)
        except Exception:  # noqa: BLE001
            is_logging = None
        out.append(_finding(
            "api", "api.logging-enabled",
            PASS if is_logging else (FAIL if is_logging is False else INFO),
            f"Trail '{name}': logging {'enabled' if is_logging else 'DISABLED' if is_logging is False else 'unknown'}.",
            "" if is_logging else "Call StartLogging; consider an SCP denying StopLogging outside break-glass.",
            {"trail": name},
        ))
        # Log-file validation (tamper-evidence).
        out.append(_finding(
            "api", "api.log-file-validation",
            PASS if t.get("LogFileValidationEnabled") else FAIL,
            f"Trail '{name}': log-file validation "
            f"{'on' if t.get('LogFileValidationEnabled') else 'OFF'}.",
            "" if t.get("LogFileValidationEnabled") else
            "Enable enable_log_file_validation so digests prove logs weren't altered.",
            {"trail": name},
        ))
        # Dual delivery: S3 AND CloudWatch Logs.
        has_s3 = bool(t.get("S3BucketName"))
        has_cwl = bool(t.get("CloudWatchLogsLogGroupArn"))
        out.append(_finding(
            "api", "api.dual-delivery",
            PASS if (has_s3 and has_cwl) else WARN,
            f"Trail '{name}': S3={'yes' if has_s3 else 'no'}, "
            f"CloudWatch Logs={'yes' if has_cwl else 'no'}.",
            "" if (has_s3 and has_cwl) else
            "Deliver to both — S3 for Athena forensics, CloudWatch Logs for real-time alarms.",
            {"trail": name, "s3": t.get("S3BucketName"), "cwl": t.get("CloudWatchLogsLogGroupArn")},
        ))
    return out


# ------------------------------------------------------------------------ Storage plane
def _check_storage(aws: Aws, region: str, name_prefix: str) -> list[dict]:
    ct = aws.client("cloudtrail")
    out: list[dict] = []
    trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

    s3_selectors: list[dict] = []
    log_bucket_names = {t.get("S3BucketName") for t in trails if t.get("S3BucketName")}
    covers_log_bucket = False

    for t in trails:
        name = t.get("TrailARN", t.get("Name"))
        try:
            sel = ct.get_event_selectors(TrailName=name)
        except Exception:  # noqa: BLE001
            continue
        # Basic event selectors.
        for es in sel.get("EventSelectors", []):
            for dr in es.get("DataResources", []):
                if dr.get("Type") == "AWS::S3::Object":
                    values = dr.get("Values", [])
                    s3_selectors.append({"trail": t.get("Name"), "type": "basic", "values": values})
                    if not values or any(v.rstrip("/").endswith(":::") or v == "arn:aws:s3" for v in values):
                        covers_log_bucket = True  # empty/all-S3 selector => includes log bucket
                    for lb in log_bucket_names:
                        if lb and any(lb in v for v in values):
                            covers_log_bucket = True
        # Advanced event selectors.
        for aes in sel.get("AdvancedEventSelectors", []):
            fields = {fc.get("Field"): fc for fc in aes.get("FieldSelectors", [])}
            rtype = fields.get("resources.type", {})
            if "AWS::S3::Object" in rtype.get("Equals", []):
                arn_field = fields.get("resources.ARN", {})
                arn_values = arn_field.get("StartsWith", []) + arn_field.get("Equals", [])
                s3_selectors.append({"trail": t.get("Name"), "type": "advanced",
                                     "name": aes.get("Name"), "arns": arn_values})
                if not arn_values:
                    covers_log_bucket = True  # unscoped => all buckets, incl. the log bucket
                for lb in log_bucket_names:
                    if lb and any(lb in v for v in arn_values):
                        covers_log_bucket = True

    if not s3_selectors:
        out.append(_finding(
            "storage", "storage.data-events", FAIL,
            "No CloudTrail S3 data-event selectors found. Object-level GetObject/PutObject "
            "is OFF by default — you cannot answer 'was the data actually read?'.",
            "Add an advanced event selector scoped to the sensitive bucket ARN(s) "
            "(foundation authorizes the scenario-05 data-events trail; see modules/scenario-05-s3-exfil/storage.tf).",
        ))
    else:
        out.append(_finding(
            "storage", "storage.data-events", PASS,
            f"{len(s3_selectors)} S3 data-event selector(s) configured.",
            "", {"selectors": s3_selectors},
        ))

    if covers_log_bucket:
        out.append(_finding(
            "storage", "storage.no-log-bucket-recursion", WARN,
            "A data-event selector appears to cover the CloudTrail log bucket (or all "
            "buckets). Logging the log bucket's own writes creates a recursive event loop "
            "and a runaway bill.",
            "Scope selectors to specific sensitive-bucket ARNs; never include the log bucket.",
        ))
    elif s3_selectors:
        out.append(_finding(
            "storage", "storage.no-log-bucket-recursion", PASS,
            "Data-event selectors are scoped and do not appear to include the log bucket.",
        ))
    return out


# ------------------------------------------------------------------------ Network plane
_FLOW_CUSTOM_FIELDS = ("${pkt-srcaddr}", "${pkt-dstaddr}", "${flow-direction}", "${instance-id}")


def _check_network(aws: Aws, region: str, name_prefix: str) -> list[dict]:
    ec2 = aws.client("ec2")
    out: list[dict] = []
    flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
    vpcs = [v["VpcId"] for v in ec2.describe_vpcs().get("Vpcs", [])]

    if not flow_logs:
        out.append(_finding(
            "network", "network.flow-logs", FAIL if vpcs else INFO,
            f"No VPC Flow Logs configured ({len(vpcs)} VPC(s) present).",
            "Enable Flow Logs on your VPCs (see modules/scenario-02-compromised-workload/network.tf).",
        ))
        return out

    vpcs_with_logs = {fl.get("ResourceId") for fl in flow_logs}
    uncovered = [v for v in vpcs if v not in vpcs_with_logs]
    out.append(_finding(
        "network", "network.flow-logs",
        PASS if not uncovered else WARN,
        f"{len(flow_logs)} Flow Log(s) across {len(vpcs_with_logs)} resource(s); "
        f"{len(uncovered)} VPC(s) uncovered.",
        "" if not uncovered else f"Enable Flow Logs on: {', '.join(uncovered)}",
        {"uncovered_vpcs": uncovered},
    ))

    for fl in flow_logs:
        fmt = fl.get("LogFormat", "") or ""
        missing = [f for f in _FLOW_CUSTOM_FIELDS if f not in fmt]
        # Default format (empty LogFormat means AWS default) lacks the custom fields.
        is_default = not fmt
        out.append(_finding(
            "network", "network.custom-format",
            PASS if not missing and not is_default else WARN,
            f"Flow Log {fl.get('FlowLogId')}: "
            + ("uses the default format (missing pkt-srcaddr etc.)." if is_default
               else f"missing custom fields {missing}." if missing else "custom format OK."),
            "" if (not missing and not is_default) else
            "Add pkt-srcaddr/pkt-dstaddr (real source behind NAT), flow-direction, and instance-id.",
            {"flow_log_id": fl.get("FlowLogId"), "destination_type": fl.get("LogDestinationType")},
        ))
    return out


# ---------------------------------------------------------------------------- DNS plane
def _check_dns(aws: Aws, region: str, name_prefix: str) -> list[dict]:
    r53 = aws.client("route53resolver")
    out: list[dict] = []
    configs = r53.list_resolver_query_log_configs().get("ResolverQueryLogConfigs", [])
    assocs = r53.list_resolver_query_log_config_associations().get(
        "ResolverQueryLogConfigAssociations", [])

    if not configs:
        out.append(_finding(
            "dns", "dns.resolver-logging", FAIL,
            "No Route 53 Resolver query-logging configs. DNS is where beacons/tunnelling "
            "show first, and Flow Logs deliberately exclude Amazon-resolver DNS.",
            "Create a resolver query-log config and associate it to your VPC(s) "
            "(see modules/scenario-03-dns-exfil/network.tf).",
        ))
        return out

    active_assocs = [a for a in assocs if a.get("Status") == "ACTIVE"]
    out.append(_finding(
        "dns", "dns.resolver-logging",
        PASS if active_assocs else WARN,
        f"{len(configs)} query-log config(s), {len(active_assocs)} active VPC association(s).",
        "" if active_assocs else "Associate a query-log config to your VPC(s).",
        {"configs": [c.get("Name") for c in configs]},
    ))

    # DNS Firewall (prevent, not just detect) — advisory.
    try:
        fw = aws.client("route53resolver").list_firewall_rule_groups().get("FirewallRuleGroups", [])
        out.append(_finding(
            "dns", "dns.firewall",
            INFO if fw else INFO,
            f"{len(fw)} DNS Firewall rule group(s) present."
            if fw else "No DNS Firewall rule groups (optional prevention layer).",
            "Consider Route 53 Resolver DNS Firewall to block known-bad lookups, and "
            "force outbound DNS through the Amazon resolver (block port 53 / DoH egress) — "
            "otherwise a workload can route around all DNS visibility.",
        ))
    except Exception:  # noqa: BLE001
        pass
    return out


# ---------------------------------------------------------------------------- Web plane
def _check_web(aws: Aws, region: str, name_prefix: str) -> list[dict]:
    out: list[dict] = []
    wafv2 = aws.client("wafv2")
    try:
        acls = wafv2.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
    except Exception as exc:  # noqa: BLE001
        acls = []
        out.append(_finding("web", "web.waf", INFO, f"wafv2:ListWebACLs failed: {exc}",
                            "Grant wafv2:ListWebACLs / GetLoggingConfiguration."))

    if not acls:
        out.append(_finding(
            "web", "web.waf", INFO,
            "No regional WAF Web ACLs found. (Fine if you have no public HTTP endpoints; "
            "otherwise CloudTrail is blind to web-layer attacks.)",
            "Put a WAFv2 Web ACL on public ALBs/CloudFront with managed rule groups + a rate rule.",
        ))
    else:
        try:
            logged = {lc["ResourceArn"] for lc in
                      wafv2.list_logging_configurations(Scope="REGIONAL").get("LoggingConfigurations", [])}
        except Exception:  # noqa: BLE001
            logged = set()
        for acl in acls:
            arn = acl.get("ARN")
            out.append(_finding(
                "web", "web.waf-logging",
                PASS if arn in logged else FAIL,
                f"Web ACL '{acl.get('Name')}': logging "
                f"{'enabled' if arn in logged else 'DISABLED'}.",
                "" if arn in logged else "Enable WAF logging to CloudWatch/S3/Firehose.",
                {"web_acl": acl.get("Name")},
            ))
            # COUNT-mode caveat.
            try:
                full = wafv2.get_web_acl(Name=acl["Name"], Scope="REGIONAL", Id=acl["Id"])["WebACL"]
                count_rules = [r["Name"] for r in full.get("Rules", [])
                               if "Count" in (r.get("Action") or {})
                               or "Count" in (r.get("OverrideAction") or {})]
                if count_rules:
                    out.append(_finding(
                        "web", "web.count-mode", WARN,
                        f"Web ACL '{acl.get('Name')}' has COUNT-mode rule(s): {count_rules}. "
                        "COUNT observes but does not block.",
                        "Switch to Block once tuned, or confirm you intend observation-only.",
                        {"count_rules": count_rules},
                    ))
            except Exception:  # noqa: BLE001
                pass

    # ALB access logs.
    try:
        elbv2 = aws.client("elbv2")
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
        for lb in lbs:
            attrs = {a["Key"]: a["Value"] for a in
                     elbv2.describe_load_balancer_attributes(
                         LoadBalancerArn=lb["LoadBalancerArn"])["Attributes"]}
            enabled = attrs.get("access_logs.s3.enabled") == "true"
            out.append(_finding(
                "web", "web.alb-access-logs",
                PASS if enabled else WARN,
                f"ALB '{lb.get('LoadBalancerName')}': access logs "
                f"{'enabled' if enabled else 'OFF'}.",
                "" if enabled else "Enable access_logs.s3.enabled — the ground truth of what reached the app.",
                {"load_balancer": lb.get("LoadBalancerName")},
            ))
    except Exception as exc:  # noqa: BLE001
        out.append(_finding("web", "web.alb", INFO, f"elbv2 describe failed: {exc}", ""))
    return out


# ---------------------------------------------------------------- Detectors & delivery
def _check_detectors(aws: Aws, region: str, name_prefix: str) -> list[dict]:
    out: list[dict] = []
    # GuardDuty.
    try:
        gd = aws.client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            out.append(_finding(
                "detectors", "detectors.guardduty", WARN,
                "GuardDuty is not enabled in this region.",
                "Enable GuardDuty (CloudTrail/VPC/DNS analysis + S3 Protection). Note: new "
                "Free-Tier accounts may need to complete account setup first.",
            ))
        else:
            det = gd.get_detector(DetectorId=detectors[0])
            out.append(_finding(
                "detectors", "detectors.guardduty", PASS,
                f"GuardDuty enabled (detector {detectors[0]}, "
                f"publish freq {det.get('FindingPublishingFrequency')}).",
                "", {"detector_id": detectors[0]},
            ))
    except Exception as exc:  # noqa: BLE001
        out.append(_finding("detectors", "detectors.guardduty", INFO,
                            f"guardduty check failed: {exc}", ""))

    # SNS subscription confirmation — the silent-failure gotcha.
    try:
        sns = aws.client("sns")
        topics = [t["TopicArn"] for t in sns.list_topics().get("Topics", [])]
        relevant = [t for t in topics if f":{name_prefix}-alerts" in t] or topics
        pending, confirmed = [], []
        for arn in relevant:
            for sub in sns.list_subscriptions_by_topic(TopicArn=arn).get("Subscriptions", []):
                target = confirmed if sub.get("SubscriptionArn") not in ("PendingConfirmation", "Deleted") else pending
                target.append(f"{sub.get('Protocol')}:{sub.get('Endpoint')}")
        if pending:
            out.append(_finding(
                "detectors", "detectors.sns-confirmed", WARN,
                f"Unconfirmed SNS subscription(s): {pending}. Alarms will fire silently — "
                "no email until the confirmation link is clicked.",
                "Confirm the 'AWS Notification - Subscription Confirmation' email.",
                {"pending": pending, "confirmed": confirmed},
            ))
        elif confirmed:
            out.append(_finding(
                "detectors", "detectors.sns-confirmed", PASS,
                f"{len(confirmed)} confirmed SNS subscription(s) on the alert topic.",
                "", {"confirmed": confirmed},
            ))
        else:
            out.append(_finding(
                "detectors", "detectors.sns-confirmed", WARN,
                "Alert topic has no subscriptions — alarms have nowhere to page.",
                "Subscribe an email/endpoint to the alerts topic and confirm it.",
            ))
    except Exception as exc:  # noqa: BLE001
        out.append(_finding("detectors", "detectors.sns-confirmed", INFO,
                            f"sns check failed: {exc}", ""))
    return out
