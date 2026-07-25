# ---------------------------------------------------------------------------
# The read. No exploit, no malware: the attacker has a foothold and can assume a
# deliberately over-permissive role, and then does exactly what real exfil looks
# like - ListObjectsV2 to enumerate the bucket, then GetObject on every key in a
# tight loop. Each of those reads is an S3 data event stamped with the assumed-
# role principal - the identity you investigate.
# ---------------------------------------------------------------------------

locals {
  exfil_role_name = "${var.name_prefix}-s5-exfil"
  # Constructed (not a resource reference) so the attack role's assume-role policy
  # doesn't depend on aws_iam_role.exfil, whose trust policy in turn references the
  # attack role - that mutual reference would be a dependency cycle. This string is
  # stable and known ahead of apply.
  exfil_role_arn = "arn:aws:iam::${var.account_id}:role/${local.exfil_role_name}"
}

# ---------------------------------------------------------------------------
# The over-permissive role the attacker "has". Read-everything on the crown-
# jewels bucket, assumable by the attack Lambda's execution role. In a real
# breach this is the CI/instance/SSO role whose creds got compromised.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "exfil_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.attack.arn]
    }
  }
}

resource "aws_iam_role" "exfil" {
  name               = local.exfil_role_name
  assume_role_policy = data.aws_iam_policy_document.exfil_assume.json
}

data "aws_iam_policy_document" "exfil_permissions" {
  statement {
    sid       = "ReadTheWholeBucket"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.crown_jewels.arn]
  }
  statement {
    sid       = "ReadEveryObject"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.crown_jewels.arn}/*"]
  }
}

resource "aws_iam_role_policy" "exfil" {
  name   = "read-crown-jewels"
  role   = aws_iam_role.exfil.id
  policy = data.aws_iam_policy_document.exfil_permissions.json
}

# ---------------------------------------------------------------------------
# Attack Lambda. Its own execution role is near-powerless: it can assume the
# exfil role and (optionally) fire a GuardDuty sample finding, nothing more - so
# a stray default-client S3 call would fail loudly instead of being mis-attributed.
# ---------------------------------------------------------------------------
data "archive_file" "attack" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/attack"
  output_path = "${path.module}/build/attack.zip"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "attack" {
  name               = "${var.name_prefix}-s5-attack-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "attack_basic" {
  role       = aws_iam_role.attack.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "attack_role" {
  statement {
    sid       = "AssumeTheExfilRole"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [local.exfil_role_arn]
  }
  statement {
    sid       = "FireDemoFinding"
    effect    = "Allow"
    actions   = ["guardduty:CreateSampleFindings"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "attack_role" {
  name   = "assume-exfil-and-sample-findings"
  role   = aws_iam_role.attack.id
  policy = data.aws_iam_policy_document.attack_role.json
}

resource "aws_lambda_function" "attack" {
  function_name    = "${var.name_prefix}-s5-attack"
  filename         = data.archive_file.attack.output_path
  source_code_hash = data.archive_file.attack.output_base64sha256
  handler          = "handler.handler"
  runtime          = "python3.12"
  role             = aws_iam_role.attack.arn
  timeout          = 300

  environment {
    variables = {
      TARGET_BUCKET  = aws_s3_bucket.crown_jewels.id
      EXFIL_ROLE_ARN = aws_iam_role.exfil.arn
      REGION         = var.region
      DETECTOR_ID    = var.guardduty_detector_id
    }
  }
}

# Belt-and-suspenders against IAM eventual consistency: give the exfil role + its
# trust policy time to propagate before the Lambda tries to assume it. The handler
# ALSO retries the assume-role internally.
resource "time_sleep" "role_propagation" {
  depends_on = [
    aws_iam_role.exfil,
    aws_iam_role_policy.exfil,
    aws_iam_role_policy.attack_role,
  ]
  create_duration = "15s"
}

# Auto-fire on apply. Static input so a plain re-apply never re-fires the side-
# effecting read. depends_on the detection stack AND the data-event trail so the
# tripwire is live and the trail is capturing BEFORE the reads happen.
resource "aws_lambda_invocation" "attack" {
  count = var.auto_fire ? 1 : 0

  function_name = aws_lambda_function.attack.function_name
  input         = jsonencode({ trigger = "terraform-apply" })

  depends_on = [
    time_sleep.role_propagation,
    # Wait out the trail warm-up so the reads are actually captured (when data
    # events are on). aws_cloudtrail.data_events is implied by this, but listed
    # too so the dependency reads clearly.
    time_sleep.trail_warmup,
    aws_cloudtrail.data_events,
    aws_cloudwatch_log_metric_filter.crown_jewels_reads,
    aws_cloudwatch_metric_alarm.crown_jewels_reads,
    aws_cloudwatch_event_rule.guardduty_findings,
  ]
}
