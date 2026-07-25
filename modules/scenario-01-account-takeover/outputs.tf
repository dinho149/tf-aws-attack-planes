output "leaked_user_name" {
  description = "The deliberately-leaked IAM user - the principal you investigate."
  value       = aws_iam_user.leaked.name
}

output "attack_function_name" {
  description = "Invoke this manually (auto_fire=false) to re-run the attack."
  value       = aws_lambda_function.attack.function_name
}

output "alarm_names" {
  description = "The metric-filter alarms that trip on the attack."
  value = [
    aws_cloudwatch_metric_alarm.access_denied.alarm_name,
    aws_cloudwatch_metric_alarm.iam_persistence.alarm_name,
  ]
}
