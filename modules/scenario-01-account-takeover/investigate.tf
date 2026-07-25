# ---------------------------------------------------------------------------
# The investigation layer: the saved queries the blog walks through. Open the
# Athena workgroup and run them to "pull the thread".
#
# The Glue table these query - `cloudtrail_logs` - lives in the shared foundation
# module (modules/foundation/investigate.tf), because more than one plane reads
# it (Scenario 5's S3 data events land in the same trail prefix). These queries
# reference it by name only.
# ---------------------------------------------------------------------------

# --- Saved investigation queries (created, not executed) ---------------------

resource "aws_athena_named_query" "user_timeline" {
  name        = "s01-01-what-is-this-user-doing"
  description = "The whole timeline for the leaked principal - the canonical control-plane query."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- What is this user doing? Read the shape of the output: a burst of Describe*/List*
    -- with errors is enumeration; then the errors stop and the calls narrow.
    SELECT eventtime, eventsource, eventname, sourceipaddress, useragent, errorcode
    FROM cloudtrail_logs
    WHERE useridentity.username = '${local.leaked_user_name}'
    ORDER BY eventtime;
  SQL
}

resource "aws_athena_named_query" "enumeration" {
  name        = "s01-02-enumeration-error-rate"
  description = "Denied calls grouped by source IP - the enumeration burst made legible."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- A high error rate from one source is someone poking at the edges of what a key can do.
    SELECT sourceipaddress, errorcode, count(*) AS calls
    FROM cloudtrail_logs
    WHERE useridentity.username = '${local.leaked_user_name}'
      AND errorcode IS NOT NULL
    GROUP BY sourceipaddress, errorcode
    ORDER BY calls DESC;
  SQL
}

resource "aws_athena_named_query" "persistence" {
  name        = "s01-03-persistence-actions"
  description = "New users, keys, policy attachments and trust edits - the shape of persistence."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- The escalation/persistence moment: what identities did they mint or empower?
    SELECT eventtime, useridentity.username AS actor, eventname, sourceipaddress,
           json_extract_scalar(requestparameters, '$.userName') AS target_user
    FROM cloudtrail_logs
    WHERE eventname IN ('CreateUser','CreateAccessKey','AttachUserPolicy',
                        'PutUserPolicy','UpdateAssumeRolePolicy')
    ORDER BY eventtime;
  SQL
}

resource "aws_athena_named_query" "top_talkers" {
  name        = "s01-04-source-ips-and-agents"
  description = "Where did the principal call from, and with what tooling?"
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- sourceIPAddress + userAgent for the principal: a suspiciously generic SDK
    -- string from an IP you don't operate in is the tell.
    SELECT sourceipaddress, useragent, count(*) AS calls
    FROM cloudtrail_logs
    WHERE useridentity.username = '${local.leaked_user_name}'
    GROUP BY sourceipaddress, useragent
    ORDER BY calls DESC;
  SQL
}
