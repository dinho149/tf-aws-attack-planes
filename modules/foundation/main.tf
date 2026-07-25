data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  log_bucket = "${var.name_prefix}-audit-logs-${local.account_id}"
  trail_name = "${var.name_prefix}-trail"
  # Scenario 5's scoped S3 data-event trail. It delivers into this same bucket
  # (same AWSLogs/.../CloudTrail prefix) so the shared cloudtrail_logs table sees
  # its events, which means the bucket policy below must authorise it too. Named
  # by convention here so the policy can allow it whether or not Scenario 5 is
  # deployed; Scenario 5 constructs its trail with this exact name.
  data_events_trail_name = "${var.name_prefix}-s5-data-events"
  athena_wg              = "${var.name_prefix}-investigations"
  glue_db                = replace("${var.name_prefix}_audit", "-", "_")
  athena_prefix          = "athena-results"
}
