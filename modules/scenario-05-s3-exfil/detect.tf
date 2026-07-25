locals {
  metric_namespace = "${var.name_prefix}/scenario-05"
}

# ---------------------------------------------------------------------------
# The tripwire. A metric filter over the SHARED CloudTrail log group (where the
# data-event trail delivers alongside the foundation's management events),
# counting GetObject calls against the crown-jewels bucket. The bucket is
# otherwise untouched, so any real read volume is the signal.
#
# The two settings that make an alarm actually fire:
#   - default_value = 0  -> the metric always has data, so the alarm can leave
#                           INSUFFICIENT_DATA and transition to ALARM.
#   - treat_missing_data = notBreaching, Sum over a 5-min period.
#
# NB: when enable_data_events = false there is no data-event trail, so no
# GetObject events reach the log group and this alarm simply never trips - which
# is exactly the "no record" experiment, made visible.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_metric_filter" "crown_jewels_reads" {
  name           = "${var.name_prefix}-s5-crown-jewels-reads"
  log_group_name = var.cloudtrail_log_group_name
  pattern        = "{ ($.eventName = \"GetObject\") && ($.requestParameters.bucketName = \"${local.crown_jewels_bucket}\") }"

  metric_transformation {
    name          = "CrownJewelsGetObjectCount"
    namespace     = local.metric_namespace
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "crown_jewels_reads" {
  alarm_name          = "${var.name_prefix}-crown-jewels-reads"
  alarm_description   = "A burst of GetObject calls against the crown-jewels bucket - someone is reading the whole thing."
  namespace           = local.metric_namespace
  metric_name         = aws_cloudwatch_log_metric_filter.crown_jewels_reads.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.getobject_threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.sns_topic_arn]
  ok_actions          = [var.sns_topic_arn]
}

# ---------------------------------------------------------------------------
# GuardDuty S3-Protection findings -> EventBridge -> SNS (notify). GuardDuty
# reads data-event activity independently and raises findings like
# Exfiltration:S3/AnomalousBehavior. Detect-only here (no responder) - like the
# web plane, the value is telling a human, not auto-remediating.
#
# Gated on enable_guardduty: not on the AWS Free Tier. When off, the metric-
# filter alarm above is the whole detection story.
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  count = var.enable_guardduty ? 1 : 0

  name        = "${var.name_prefix}-s5-guardduty-findings"
  description = "Route GuardDuty S3-Protection findings to the shared alert topic."
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_findings[0].name
  target_id = "notify-sns"
  arn       = var.sns_topic_arn
}
