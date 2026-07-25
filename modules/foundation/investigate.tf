# ---------------------------------------------------------------------------
# The shared CloudTrail Glue table. A single table over the trail's S3 logs
# (partition projection, so no crawler / MSCK REPAIR) that every CloudTrail-
# reading scenario queries by name (`FROM cloudtrail_logs`). It lives in the
# foundation - not a scenario - because more than one plane reads it: Scenario 1
# queries management events here, and Scenario 5 queries the S3 *data* events its
# scoped trail delivers into the very same AWSLogs/.../CloudTrail prefix. Each
# scenario adds only its own saved queries; the table is shared.
# ---------------------------------------------------------------------------

locals {
  cloudtrail_location = "s3://${aws_s3_bucket.logs.id}/AWSLogs/${local.account_id}/CloudTrail"
  # Regions the multi-region trail may write. Projection enumerates them so no
  # partition load is ever needed.
  projection_regions = join(",", [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "sa-east-1", "ca-central-1",
  ])

  # CloudTrail record schema (see AWS "Querying CloudTrail logs" docs).
  cloudtrail_columns = [
    { name = "eventversion", type = "string" },
    { name = "useridentity", type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>" },
    { name = "eventtime", type = "string" },
    { name = "eventsource", type = "string" },
    { name = "eventname", type = "string" },
    { name = "awsregion", type = "string" },
    { name = "sourceipaddress", type = "string" },
    { name = "useragent", type = "string" },
    { name = "errorcode", type = "string" },
    { name = "errormessage", type = "string" },
    { name = "requestparameters", type = "string" },
    { name = "responseelements", type = "string" },
    { name = "additionaleventdata", type = "string" },
    { name = "requestid", type = "string" },
    { name = "eventid", type = "string" },
    { name = "resources", type = "array<struct<arn:string,accountid:string,type:string>>" },
    { name = "eventtype", type = "string" },
    { name = "apiversion", type = "string" },
    { name = "readonly", type = "string" },
    { name = "recipientaccountid", type = "string" },
    { name = "serviceeventdetails", type = "string" },
    { name = "sharedeventid", type = "string" },
    { name = "vpcendpointid", type = "string" },
    { name = "eventcategory", type = "string" },
  ]
}

resource "aws_glue_catalog_table" "cloudtrail" {
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.audit.name
  table_type    = "EXTERNAL_TABLE"

  partition_keys {
    name = "region"
    type = "string"
  }
  partition_keys {
    name = "date"
    type = "string"
  }

  parameters = {
    "EXTERNAL"                      = "TRUE"
    "projection.enabled"            = "true"
    "projection.region.type"        = "enum"
    "projection.region.values"      = local.projection_regions
    "projection.date.type"          = "date"
    "projection.date.range"         = "2024/01/01,NOW"
    "projection.date.format"        = "yyyy/MM/dd"
    "projection.date.interval"      = "1"
    "projection.date.interval.unit" = "DAYS"
    "storage.location.template"     = "${local.cloudtrail_location}/$${region}/$${date}"
  }

  storage_descriptor {
    location      = local.cloudtrail_location
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
    }

    dynamic "columns" {
      for_each = local.cloudtrail_columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
}
