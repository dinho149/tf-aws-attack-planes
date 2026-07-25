output "account_id" {
  value = local.account_id
}

output "region" {
  value = local.region
}

output "log_bucket_id" {
  value = aws_s3_bucket.logs.id
}

output "log_bucket_arn" {
  value = aws_s3_bucket.logs.arn
}

output "cloudtrail_log_group_name" {
  value = aws_cloudwatch_log_group.trail.name
}

output "cloudtrail_log_group_arn" {
  value = aws_cloudwatch_log_group.trail.arn
}

output "glue_database_name" {
  value = aws_glue_catalog_database.audit.name
}

output "cloudtrail_table_name" {
  description = "The shared Glue table over CloudTrail's S3 logs (management + S3 data events)."
  value       = aws_glue_catalog_table.cloudtrail.name
}

output "athena_workgroup_name" {
  value = aws_athena_workgroup.investigations.name
}

output "athena_results_location" {
  value = "s3://${aws_s3_bucket.logs.id}/${local.athena_prefix}/"
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "guardduty_detector_id" {
  # Empty string when GuardDuty is disabled; the attack Lambda treats "" as "skip".
  value = var.enable_guardduty ? aws_guardduty_detector.this[0].id : ""
}
