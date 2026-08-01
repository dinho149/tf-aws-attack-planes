# aws-audit-planes-mcp

An **MCP server** that turns the lessons of *[A Field Guide to AWS Audit Logs](https://github.com/omardin14/tf-aws-attack-planes)*
into tools an AI assistant (Claude, Codex, …) can call against a live AWS account:

1. **Check configuration** — is each attack plane's logging actually on and correct?
2. **Run common Athena checks** — the canonical investigation per plane.
3. **Check the alarms** — which CloudWatch alarms exist and what state are they in?

It is a **general auditor** (works on any account, scored against the series' lessons) that
is also **atkplane-aware**: when it finds a deployment stood up by this repo it surfaces the
saved `s01…s05` named queries and named alarms directly.

> **Read-only.** Every AWS call is `describe`/`list`/`get` plus Athena / CloudWatch Logs
> Insights query execution. The server never mutates configuration or resources, and
> `run_query` refuses anything that isn't `SELECT`/`WITH`/`SHOW`/`DESCRIBE`.

## The five planes it audits

| Plane | Log source | Key config check | Investigation examples |
|---|---|---|---|
| **api** | CloudTrail | multi-region + log-file validation + dual S3/CloudWatch delivery | `api.enumeration`, `api.persistence`, `api.principal-timeline` |
| **network** | VPC Flow Logs | custom format has `pkt-srcaddr`/`flow-direction`/`instance-id` | `network.top-talkers`, `network.reject-probe` |
| **dns** | Route 53 Resolver query logs | query logging enabled + associated to VPCs | `dns.tunnelling`, `dns.dga-beacon` |
| **web** | WAF / ALB logs | WAF + ALB logging on; COUNT-mode warning | `web.alb-status-by-ip`, `web.waf-blocks-by-ip` |
| **storage** | CloudTrail S3 data events | data events enabled, not looping on the log bucket | `storage.reads-by-principal`, `storage.objects-read` |
| **detectors** | GuardDuty + SNS | GuardDuty on; SNS subscription **confirmed** | — |

## Tools

- `discover_estate` — resolve region, account, trails, GuardDuty, Athena workgroup, Glue
  DB + which tables exist, log bucket, alert topic. **Call this first.**
- `check_configuration` — the plane-by-plane audit; returns findings + a verdict.
- `check_alarms` — alarm states, whether they page a confirmed endpoint, missing/expected.
- `list_investigations` — the catalog of canonical checks.
- `run_investigation` — run one canonical, time-bounded check by id.
- `list_saved_queries` — the repo's saved Athena named queries with full SQL.
- `run_query` — run a saved query by id, or ad-hoc read-only SQL, in the workgroup.
- `describe_plane` — concise Field Guide guidance + the gotcha for a plane.

## What to ask it

You don't call the tools by name — you ask the assistant a question and it picks them. The
questions below are the ones the server is actually built to answer; the tool it lands on is
noted where it helps.

### Start here — posture

- *"Discover my estate and tell me which attack planes are actually logging."*
- *"Audit all five planes and give me the verdict — what are my biggest gaps?"*
- *"Score my account against the Field Guide, but show me only the failures."*
- *"Which planes am I blind on right now?"*

### Is my logging good enough? (`check_configuration`)

| Ask | Lands on |
|---|---|
| *"Is my trail multi-region, and is log-file validation on?"* | `api.multi-region`, `api.log-file-validation` |
| *"Am I delivering CloudTrail to both S3 and CloudWatch Logs?"* | `api.dual-delivery` |
| *"Could I answer 'was the data actually read?' — are S3 data events on?"* | `storage.data-events` |
| *"Is any data-event selector accidentally logging the log bucket?"* | `storage.no-log-bucket-recursion` |
| *"Which VPCs have no flow logs?"* | `network.flow-logs` |
| *"Would I see the real source behind NAT, or am I on the default flow-log format?"* | `network.custom-format` |
| *"Is Resolver query logging on **and** associated to my VPCs?"* | `dns.resolver-logging` |
| *"Are any WAF rules still in COUNT mode — watching but not blocking?"* | `web.count-mode` |
| *"Do my ALBs have access logs enabled?"* | `web.alb-access-logs` |
| *"Is GuardDuty on, and has anyone confirmed the alert subscription?"* | `detectors.*` |

### Will I actually get paged? (`check_alarms`)

- *"Which alarms are in ALARM right now?"*
- *"Do all my alarms reach a confirmed endpoint, or are some firing into the void?"*
- *"Which expected alarms are missing?"*
- *"We had an incident and nobody got paged — work out why."*

### Investigate (`run_investigation`, default window 24h)

- *"Is anyone enumerating? AccessDenied bursts by source IP over the last 6 hours."*
- *"Has anyone created users, access keys, or attached policies today?"*
- *"Build a full timeline for principal `arn:aws:iam::…:user/deploy` over the last 3 days."*
- *"What are my top egress talkers by bytes?"*
- *"Is anything doing REJECT fan-out — lateral-movement probing?"*
- *"Any sign of DNS tunnelling — long-label TXT or NULL lookups?"*
- *"Show me NXDOMAIN storms by parent domain — is something beaconing to a DGA?"*
- *"Which client IPs is WAF blocking, and on which rule?"*
- *"Who read objects from `my-bucket` in the last 48 hours?"*
- *"List the exact object keys read from `my-bucket` — I need it for a disclosure decision."*

The last three principal/bucket questions need a filter (`principal` or `bucket`); the server
will tell you which one is missing rather than guessing.

### Saved queries and ad-hoc SQL

- *"List the repo's saved Athena queries and show me the SQL behind the s03 one."*
- *"Run the saved query for the DNS hunt."*
- *"Run this against the workgroup: `SELECT …`"* — read-only; anything that isn't
  `SELECT`/`WITH`/`SHOW`/`DESCRIBE` is refused.

### Learn the plane

- *"What does the DNS plane answer, and what's the gotcha?"*
- *"Explain the storage plane — why do data events matter if I already have CloudTrail?"*

### Chained — where an assistant earns its keep

- *"Full audit: discover the estate, check every plane, check the alarms, then give me a
  prioritized remediation list with the Terraform changes."*
- *"Something looks off in eu-west-1. Triage it: check the alarms, run the enumeration and
  persistence checks, then tell me whether any data left."*
- *"Compare my account to what this repo deploys and tell me what I'm missing."*

### What it can't answer (yet)

Read-only and Athena-backed, so: it **cannot contain** an attack (no key revocation, session
revoke, or quarantine); it does **not** retrieve GuardDuty *findings*, only whether GuardDuty
is enabled; and because it reads CloudTrail from S3, the **last ~5–15 minutes** aren't visible
yet (`cloudtrail:LookupEvents` would close that). Config checks and alarms are one region per
call, though the CloudTrail Glue table projects across regions, so Athena investigations do
span them.

## Install & run

Requires Python 3.12+ and AWS credentials on the standard boto3 chain
(`AWS_PROFILE` / env / SSO / instance role).

```bash
cd mcp-server
pip install -e .              # or: uv pip install -e .
aws-audit-planes-mcp         # runs the stdio server
```

Try the tools interactively with the MCP inspector:

```bash
pip install -e '.[dev]'
mcp dev src/audit_planes_mcp/server.py
```

## Wire it into a client

Claude Code / Codex `mcp` config (`.mcp.json` or the client's MCP settings):

```json
{
  "mcpServers": {
    "aws-audit-planes": {
      "command": "aws-audit-planes-mcp",
      "env": { "AWS_PROFILE": "sandbox", "AWS_REGION": "eu-west-1" }
    }
  }
}
```

If you prefer not to install it, point `command` at `python` with
`args: ["-m", "audit_planes_mcp.server"]` and set `PYTHONPATH` to `mcp-server/src`.

## Discovery: AWS-native, with a Terraform override

By default the server discovers resources live from AWS — CloudTrail and GuardDuty are
account-level; repo resources are matched by `name_prefix` (default `atkplane`) and the
`atkplane:*` default tags. Pass `use_terraform=true` (and optionally `terraform_dir`) to
overlay exact identifiers from `terraform output` when running inside a checkout, mirroring
`scripts/simulate-attack.sh`.

## IAM

Attach [`policy/audit-planes-readonly.json`](policy/audit-planes-readonly.json) — a
least-privilege read-only policy covering CloudTrail/GuardDuty/EC2/Resolver/WAF/ELB/SNS/
CloudWatch describe calls, Athena + Glue query, Logs Insights, and read/write to the
Athena results prefix only. For the configuration checks alone, the AWS-managed
`SecurityAudit` policy is a quick alternative (but doesn't grant Athena query execution).

## Develop / test

```bash
pip install -e '.[dev]'
pytest
```

The tests cover the read-only SQL guard, the window/predicate builder, the investigation
catalog, and the discovery/overlay helpers — none touch AWS.

## Out of scope (v0.1)

Read-only by design (no remediation tools); single account + region per call; no Security
Hub / Detective / Macie integration yet.
