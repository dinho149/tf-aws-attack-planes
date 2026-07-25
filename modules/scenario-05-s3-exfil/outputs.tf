output "crown_jewels_bucket" {
  description = "The 'crown jewels' bucket the attacker mass-reads - the principal you investigate reads from here."
  value       = aws_s3_bucket.crown_jewels.id
}

output "attack_function_name" {
  description = "Invoke this manually (auto_fire=false) to re-run the exfil read."
  value       = aws_lambda_function.attack.function_name
}

output "data_events_trail" {
  description = "The scoped S3 data-event trail. null when enable_data_events = false (the 'no record' experiment)."
  value       = one(aws_cloudtrail.data_events[*].name)
}

output "alarm_names" {
  description = "The metric-filter alarm that trips on the mass read."
  value = [
    aws_cloudwatch_metric_alarm.crown_jewels_reads.alarm_name,
  ]
}
