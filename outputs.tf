output "log_bucket" {
  description = "S3 bucket holding CloudTrail logs (and Athena results under athena-results/)."
  value       = module.foundation.log_bucket_id
}

output "cloudtrail_log_group" {
  description = "CloudWatch Logs group the trail delivers to (where the metric-filter alarms watch)."
  value       = module.foundation.cloudtrail_log_group_name
}

output "athena_workgroup" {
  description = "Open this workgroup in the Athena console to run the saved investigation queries."
  value       = module.foundation.athena_workgroup_name
}

output "glue_database" {
  description = "Glue database containing the cloudtrail_logs table."
  value       = module.foundation.glue_database_name
}

output "guardduty_detector_id" {
  description = "Feed this to `aws guardduty create-sample-findings` to exercise the detect->respond pipeline."
  value       = module.foundation.guardduty_detector_id
}

output "leaked_user_name" {
  description = "Scenario 1: the deliberately-leaked IAM user. This is the principal you investigate. null when scenario_01_enabled = false."
  value       = one(module.scenario_01[*].leaked_user_name)
}

output "attack_function_name" {
  description = "Scenario 1 attack Lambda. Invoke it (e.g. via scripts/simulate-attack.sh) to re-run the scenario on demand. null when scenario_01_enabled = false."
  value       = one(module.scenario_01[*].attack_function_name)
}

# --- Scenario 2 (compromised workload / network plane) -----------------------

output "scenario_02_instance_id" {
  description = "Scenario 2: the compromised EC2 instance. null when scenario_02_enabled = false."
  value       = one(module.scenario_02[*].instance_id)
}

output "scenario_02_instance_sg_id" {
  description = "Scenario 2: the instance's baseline security group. simulate-attack.sh restores this before each re-run to undo any isolation."
  value       = one(module.scenario_02[*].instance_security_group_id)
}

output "scenario_02_attack_function_name" {
  description = "Scenario 2 attack Lambda. Invoke it (e.g. via scripts/simulate-attack.sh -s 2) to re-run the scenario on demand."
  value       = one(module.scenario_02[*].attack_function_name)
}

output "scenario_02_flow_logs_table" {
  description = "Scenario 2: Glue table of VPC Flow Logs to query in Athena."
  value       = one(module.scenario_02[*].flow_logs_table)
}

output "scenario_02_alarm_names" {
  description = "Scenario 2: the egress metric-filter alarm that trips on exfiltration."
  value       = one(module.scenario_02[*].alarm_names)
}

# --- Scenario 3 (DNS exfil / DNS plane) --------------------------------------

output "scenario_03_instance_id" {
  description = "Scenario 3: the DNS-noisy EC2 instance. null when scenario_03_enabled = false."
  value       = one(module.scenario_03[*].instance_id)
}

output "scenario_03_attack_function_name" {
  description = "Scenario 3 attack Lambda. Invoke it (e.g. via simulate-attack.sh -s 3) to re-run the scenario on demand."
  value       = one(module.scenario_03[*].attack_function_name)
}

output "scenario_03_hunter_function_name" {
  description = "Scenario 3: the scheduled DNS hunter Lambda. Invoke it by hand to run the beacon/tunnelling hunt immediately."
  value       = one(module.scenario_03[*].hunter_function_name)
}

output "scenario_03_resolver_query_logs_table" {
  description = "Scenario 3: Glue table of Route 53 Resolver query logs to query in Athena."
  value       = one(module.scenario_03[*].resolver_query_logs_table)
}

# --- Scenario 4 (web attack / web plane) -------------------------------------

output "scenario_04_alb_dns_name" {
  description = "Scenario 4: public DNS name of the target ALB. null when scenario_04_enabled = false."
  value       = one(module.scenario_04[*].alb_dns_name)
}

output "scenario_04_attack_function_name" {
  description = "Scenario 4 attack Lambda. Invoke it (e.g. via simulate-attack.sh -s 4) to re-run the scenario on demand."
  value       = one(module.scenario_04[*].attack_function_name)
}

output "scenario_04_waf_web_acl_arn" {
  description = "Scenario 4: ARN of the WAF web ACL associated with the ALB."
  value       = one(module.scenario_04[*].waf_web_acl_arn)
}

output "scenario_04_alb_access_logs_table" {
  description = "Scenario 4: Glue table of ALB access logs to query in Athena."
  value       = one(module.scenario_04[*].alb_access_logs_table)
}

output "scenario_04_alarm_names" {
  description = "Scenario 4: the WAF-blocked-requests metric-filter alarm."
  value       = one(module.scenario_04[*].alarm_names)
}

# --- Scenario 5 (S3 data-events exfil / storage plane) -----------------------

output "scenario_05_crown_jewels_bucket" {
  description = "Scenario 5: the 'crown jewels' bucket the attacker mass-reads. null when scenario_05_enabled = false."
  value       = one(module.scenario_05[*].crown_jewels_bucket)
}

output "scenario_05_attack_function_name" {
  description = "Scenario 5 attack Lambda. Invoke it (e.g. via simulate-attack.sh -s 5) to re-run the scenario on demand."
  value       = one(module.scenario_05[*].attack_function_name)
}

output "scenario_05_data_events_trail" {
  description = "Scenario 5: the scoped S3 data-event trail. null when scenario_05_enabled = false OR enable_data_events = false (the 'no record' experiment)."
  value       = one(module.scenario_05[*].data_events_trail)
}

output "scenario_05_alarm_names" {
  description = "Scenario 5: the crown-jewels-reads metric-filter alarm that trips on the mass read."
  value       = one(module.scenario_05[*].alarm_names)
}

output "region" {
  description = "Region the estate is deployed in (where you invoke the attack Lambda)."
  value       = var.region
}

output "athena_console_url" {
  description = "Deep link to the Athena query editor for this workgroup."
  value       = "https://${var.region}.console.aws.amazon.com/athena/home?region=${var.region}#/query-editor"
}
