variable "name_prefix" {
  description = "Prefix applied to every named resource."
  type        = string
}

variable "auto_fire" {
  description = "Invoke the attack Lambda automatically on apply."
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Wire GuardDuty S3-Protection findings into the detect pipeline (EventBridge -> SNS). When false, the metric-filter alarm still fires off the data events' own signal; only the GuardDuty path is skipped."
  type        = bool
  default     = false
}

variable "enable_data_events" {
  description = "Stand up the scoped CloudTrail S3 data-event trail. ON by default. Set false to run the blog's experiment: the attack still reads every object, but nothing records it, so the investigation returns nothing."
  type        = bool
  default     = true
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "log_bucket_id" {
  type = string
}

variable "cloudtrail_log_group_arn" {
  type = string
}

variable "cloudtrail_log_group_name" {
  type = string
}

variable "glue_database_name" {
  type = string
}

variable "athena_workgroup_name" {
  type = string
}

variable "sns_topic_arn" {
  type = string
}

variable "guardduty_detector_id" {
  type = string
}

# --- demo signal tuning ------------------------------------------------------

variable "seed_object_count" {
  description = "Number of synthetic 'sensitive' objects to seed into the crown-jewels bucket. The attack lists then GetObjects every one of them, so this is also the read volume. Fake data - nothing real."
  type        = number
  default     = 15
}

variable "getobject_threshold" {
  description = "Alarm when this many GetObject calls against the crown-jewels bucket are seen in a 5-min window. Default 10 - the bucket is otherwise untouched, so any real read volume is the signal (a full read of the seeded objects clears this comfortably)."
  type        = number
  default     = 10
}

variable "trail_warmup_duration" {
  description = "How long to wait after the data-event trail is created before the auto_fire attack reads the bucket. A brand-new CloudTrail needs a few minutes before it actually starts capturing events; without this wait the on-apply reads slip through UNRECORDED and the alarm never trips. Paid once, on the apply that stands the trail up - manual re-runs via simulate-attack.sh hit an already-warm trail. Only applies when enable_data_events = true."
  type        = string
  default     = "300s"
}
