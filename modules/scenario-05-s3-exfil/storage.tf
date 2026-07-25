# ---------------------------------------------------------------------------
# The storage plane's target + the ONE control this whole part is about.
#
#   - A "crown jewels" S3 bucket, locked down (Block Public Access, versioning),
#     seeded with a handful of synthetic sensitive-looking objects.
#   - A SECOND, dedicated CloudTrail scoped to S3 *data* events on that one
#     bucket. The foundation trail is management-events only, so without this the
#     GetObject calls that read the bucket are never recorded. THAT is the lesson.
#
# Why a separate trail (not selectors on the foundation trail): adding ANY
# advanced_event_selector to a trail replaces its default management-events
# selector, so bolting data events onto the foundation trail would silently stop
# it recording the management events Scenarios 1-4 rely on. A dedicated trail
# keeps the two concerns - and the paid data-events bill - cleanly separable.
# ---------------------------------------------------------------------------

locals {
  crown_jewels_bucket    = "${var.name_prefix}-crown-jewels-${var.account_id}"
  data_events_trail_name = "${var.name_prefix}-s5-data-events"
}

resource "aws_s3_bucket" "crown_jewels" {
  bucket = local.crown_jewels_bucket
  # Synthetic data + versioning on, so force_destroy so teardown doesn't choke on
  # the seeded objects (and their versions).
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "crown_jewels" {
  bucket = aws_s3_bucket.crown_jewels.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "crown_jewels" {
  bucket = aws_s3_bucket.crown_jewels.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "crown_jewels" {
  bucket = aws_s3_bucket.crown_jewels.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# The "sensitive" objects. Entirely synthetic - fabricated names and fake card
# numbers - so there is nothing real to leak. The attack reads every one of them.
resource "aws_s3_object" "records" {
  count = var.seed_object_count

  bucket       = aws_s3_bucket.crown_jewels.id
  key          = format("customers/customer-%04d.json", count.index + 1)
  content_type = "application/json"
  content = jsonencode({
    id        = format("CUST-%04d", count.index + 1)
    name      = "Synthetic Customer ${count.index + 1}"
    email     = format("customer%04d@example.invalid", count.index + 1)
    card      = format("4111-1111-1111-%04d", count.index + 1)
    ssn       = "000-00-0000"
    note      = "SYNTHETIC TEST RECORD - not real data."
    generated = "terraform"
  })
}

# ---------------------------------------------------------------------------
# The scoped S3 data-event trail. Delivers into the SHARED bucket (same
# AWSLogs/<acct>/CloudTrail prefix, so the shared cloudtrail_logs table sees it)
# AND the shared CloudWatch log group (where detect.tf's metric filter watches).
# The advanced event selector is scoped to the crown-jewels bucket ARN ONLY -
# never the log bucket, which would create a recursive data-event -> log object
# -> data-event billing loop.
#
# Gated on enable_data_events: flip it off to run the "and now it returns
# nothing" experiment, and to stop the per-event bill.
# ---------------------------------------------------------------------------

# Role this trail assumes to write into the shared CloudWatch log group. A trail
# can't share another trail's delivery role, so Scenario 5 brings its own (scoped
# to the shared group's ARN).
data "aws_iam_policy_document" "trail_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trail_to_cwl" {
  count = var.enable_data_events ? 1 : 0

  name               = "${var.name_prefix}-s5-trail-to-cwl"
  assume_role_policy = data.aws_iam_policy_document.trail_assume.json
}

data "aws_iam_policy_document" "trail_to_cwl" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${var.cloudtrail_log_group_arn}:*"]
  }
}

resource "aws_iam_role_policy" "trail_to_cwl" {
  count = var.enable_data_events ? 1 : 0

  name   = "deliver-to-cwl"
  role   = aws_iam_role.trail_to_cwl[0].id
  policy = data.aws_iam_policy_document.trail_to_cwl.json
}

resource "aws_cloudtrail" "data_events" {
  count = var.enable_data_events ? 1 : 0

  name           = local.data_events_trail_name
  s3_bucket_name = var.log_bucket_id

  # The bucket is regional and this trail only cares about one bucket, so a
  # single-region trail in the home region is enough (and cheaper).
  is_multi_region_trail         = false
  include_global_service_events = false
  enable_log_file_validation    = true
  enable_logging                = true

  # The log-group ARN handed to CloudTrail MUST end in ":*" (the log-stream glob).
  cloud_watch_logs_group_arn = "${var.cloudtrail_log_group_arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_cwl[0].arn

  # Data events only, scoped to the crown-jewels bucket. NEVER the log bucket.
  advanced_event_selector {
    name = "S3 object-level access on the crown-jewels bucket"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.crown_jewels.arn}/"]
    }
  }

  # The foundation bucket policy authorises this trail (by name) to write; the
  # module-level depends_on = [module.foundation] guarantees that policy exists
  # first, so CloudTrail doesn't fail with InsufficientS3BucketPolicyException.
}

# A brand-new CloudTrail doesn't start capturing events the instant its create
# call returns - there's a warm-up of a few minutes. Without waiting it out, an
# auto_fire attack on the SAME apply reads the bucket before the trail is live,
# so those reads are never recorded and the alarm never trips (the failure this
# guards against). Give the trail time to warm up before the attack fires. Only
# the on-apply auto-fire path pays this; manual re-runs via simulate-attack.sh
# hit an already-warm trail. Same idea as Scenario 4's time_sleep.alb_ready.
resource "time_sleep" "trail_warmup" {
  count = var.enable_data_events ? 1 : 0

  depends_on      = [aws_cloudtrail.data_events]
  create_duration = var.trail_warmup_duration
}
