# ---------------------------------------------------------------------------
# The answer layer. The nice payoff of delivering data events into the shared
# trail prefix: they land in the SAME place as the management events, so the
# existing `cloudtrail_logs` Glue table (now in the foundation) queries them
# too - no new table needed, just new saved queries. And because data events
# carry the same userIdentity as management events, you can pivot straight back
# to the API-plane query from Scenario 1, unchanged.
# ---------------------------------------------------------------------------

resource "aws_athena_named_query" "did_they_read_it" {
  name        = "s05-01-did-they-read-it"
  description = "The board's question: did anyone read the crown-jewels bucket, and who? A principal that normally reads nothing suddenly pulling every object is your exfil, in one row."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- Object-level access against the crown-jewels bucket, by principal. The row
    -- to fear: one principal + one source IP with an object_calls count in the
    -- hundreds/thousands where it should be ~zero.
    SELECT useridentity.arn AS principal,
           sourceipaddress,
           eventname,
           COUNT(*)         AS object_calls
    FROM cloudtrail_logs
    WHERE eventsource = 's3.amazonaws.com'
      AND eventname IN ('GetObject', 'PutObject', 'DeleteObject')
      AND requestparameters LIKE '%${local.crown_jewels_bucket}%'
    GROUP BY 1, 2, 3
    ORDER BY object_calls DESC;
  SQL
}

resource "aws_athena_named_query" "which_objects" {
  name        = "s05-02-which-objects-were-read"
  description = "The one that matters in an incident: not 'a bucket was accessed' but exactly which object keys were read, when, by whom, from where. That's the difference between a hedged disclosure notice and one full of facts."
  database    = var.glue_database_name
  workgroup   = var.athena_workgroup_name
  query       = <<-SQL
    -- Every object read, with the exact key (pulled out of requestParameters),
    -- timestamp, principal and source IP. This is your disclosure-notice evidence.
    SELECT eventtime,
           useridentity.arn                                       AS principal,
           sourceipaddress,
           eventname,
           json_extract_scalar(requestparameters, '$.key')        AS object_key
    FROM cloudtrail_logs
    WHERE eventsource = 's3.amazonaws.com'
      AND eventname IN ('GetObject', 'PutObject', 'DeleteObject')
      AND requestparameters LIKE '%${local.crown_jewels_bucket}%'
    ORDER BY eventtime;
  SQL
}
