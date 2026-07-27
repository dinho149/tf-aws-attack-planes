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
