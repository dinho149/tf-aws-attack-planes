# The single S3 bucket every plane's logs land in. CloudTrail writes under
# AWSLogs/<acct>/CloudTrail/... ; Athena writes query results under athena-results/.
# force_destroy so `terraform destroy` doesn't choke on the objects CloudTrail wrote.

resource "aws_s3_bucket" "logs" {
  bucket        = local.log_bucket
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3 (AES256), NOT SSE-KMS: KMS would force a CloudTrail key-policy grant for
# kms:GenerateDataKey* and silently fail delivery if you forget it.
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# CloudTrail needs GetBucketAcl on the bucket and PutObject (bucket-owner-full-control)
# under its log prefix. The aws:SourceArn condition scopes it to this trail only.
data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      # Both the foundation management-events trail AND Scenario 5's scoped S3
      # data-event trail write here. Listing both keeps the SourceArn scoping
      # tight; the second entry is harmless when Scenario 5 isn't deployed.
      values = [
        "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}",
        "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.data_events_trail_name}",
      ]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      # See AWSCloudTrailAclCheck: both the foundation trail and Scenario 5's
      # data-event trail write under AWSLogs/<acct>/*.
      values = [
        "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}",
        "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${local.data_events_trail_name}",
      ]
    }
  }

  # VPC Flow Logs (Scenario 2, network plane) deliver to this same bucket under
  # vpc-flow-logs/AWSLogs/<acct>/vpcflowlogs/... The delivery principal and the
  # write prefix both differ from CloudTrail's, so flow logs need their own
  # statements. Left unconditional: harmless when Scenario 2 isn't deployed (the
  # principal simply never calls), and a bucket can carry only ONE policy.
  statement {
    sid    = "AWSVPCFlowLogsAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${local.region}:${local.account_id}:*"]
    }
  }

  statement {
    sid    = "AWSVPCFlowLogsWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/vpc-flow-logs/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${local.region}:${local.account_id}:*"]
    }
  }

  # Route 53 Resolver query logs (Scenario 3, DNS plane) deliver to this same
  # bucket under route53-resolver/AWSLogs/<acct>/vpcdnsquerylogs/<vpc-id>/... They
  # need their OWN statements: the Flow-Logs AclCheck above pins aws:SourceArn to
  # arn:aws:logs:*, which Resolver's source ARN (arn:aws:route53resolver:*) never
  # matches. And - unlike Flow Logs - AWS's documented Resolver-log policy does
  # NOT require the bucket-owner-full-control ACL, so requiring it here would DENY
  # delivery. Left unconditional beyond SourceAccount: harmless when Scenario 3
  # isn't deployed, and a bucket can carry only ONE policy.
  statement {
    sid    = "AWSResolverQueryLogsAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid    = "AWSResolverQueryLogsWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/route53-resolver/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # ALB access logs (Scenario 4, web plane) deliver to this same bucket under
  # alb-access-logs/AWSLogs/<acct>/elasticloadbalancing/<region>/... ALB access-
  # log delivery is NOT the delivery.logs.amazonaws.com principal the flow/
  # resolver logs use: in regions launched before Aug 2022 (the demo's us-east-1
  # default and the eu-west-1 sandbox both qualify) S3 delivery is performed by
  # the regional ELB service account, so we grant PutObject to that account root
  # (looked up via aws_elb_service_account - no hard-coded account id). Left
  # unconditional beyond the write prefix: harmless when Scenario 4 isn't
  # deployed, and a bucket can carry only ONE policy.
  statement {
    sid    = "AWSALBAccessLogsWrite"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.main.arn]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/alb-access-logs/AWSLogs/${local.account_id}/*"]
  }
}

# The regional ELB service account that writes ALB access logs to S3 (Scenario 4).
data "aws_elb_service_account" "main" {}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}
