variable "region" {
  description = "Home region for the trail. Keep us-east-1 so global-service events (IAM, STS) land here."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix applied to every named resource so the whole demo is easy to find and tear down."
  type        = string
  default     = "atkplane"
}

variable "alert_email" {
  description = "Email address subscribed to the SNS alert topic. Leave empty to skip the subscription (you can still see alarms in the console)."
  type        = string
  default     = ""
}

variable "auto_fire" {
  description = "If true, the attack Lambda is invoked automatically on apply. Set false to stand up the estate and fire the attack yourself later."
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "If true, stand up the GuardDuty detector and wire its findings into the detect/respond pipeline (EventBridge -> SNS + quarantine Lambda). GuardDuty is NOT available on the AWS Free Tier, so this defaults to false. When false, the metric-filter alarms still fire off the attack's own CloudTrail signal; only the GuardDuty-driven auto-quarantine is skipped."
  type        = bool
  default     = false
}

variable "scenario_01_enabled" {
  description = "Deploy Scenario 1 (account takeover / control plane). On by default - it's the reference scenario and cheap (no compute)."
  type        = bool
  default     = false
}

variable "scenario_02_enabled" {
  description = "Deploy Scenario 2 (compromised workload / network plane). Off by default because it stands up a VPC + a t3.micro EC2 instance (small ongoing cost, unlike the Free-Tier-shaped Scenario 1)."
  type        = bool
  default     = false
}

variable "scenario_03_enabled" {
  description = "Deploy Scenario 3 (DNS exfil / DNS plane). Off by default because it stands up a VPC + a t3.micro EC2 instance plus Route 53 Resolver query logging (small ongoing cost, like Scenario 2)."
  type        = bool
  default     = false
}

variable "enable_dns_firewall" {
  description = "Scenario 3 only: also stand up the Route 53 Resolver DNS Firewall 'prevent' control (BLOCK the demo beacon/tunnel domains). Off by default so the demo is detect-only; a blocked lookup is still logged, so the hunter/queries keep working."
  type        = bool
  default     = false
}

variable "scenario_04_enabled" {
  description = "Deploy Scenario 4 (web attack / web plane). Off by default because it stands up a public ALB + a WAF web ACL, which both bill while up - this is the priciest scenario, so tear it down when you're done."
  type        = bool
  default     = false
}

variable "scenario_05_enabled" {
  description = "Deploy Scenario 5 (S3 data-events exfil / storage plane). Off by default because it deliberately turns on a paid feature - CloudTrail S3 data events (see enable_data_events), billed per object read - on a small 'crown jewels' bucket. That paid feature is the entire point of the lesson."
  type        = bool
  default     = false
}

variable "enable_data_events" {
  description = "Scenario 5 only: stand up the scoped CloudTrail S3 data-event trail (the thing that actually records object-level GetObject/PutObject/DeleteObject). On by default - without it the exfil leaves no record, which is the lesson. Set it to false and re-apply to run the blog's 'and now the investigation returns nothing' experiment. Data events are billed per event, so turn it off when you're done."
  type        = bool
  default     = true
}
