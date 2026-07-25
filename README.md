# tf-aws-attack-planes

Companion Terraform for the blog series **"every attack lives in a different plane."**
Each scenario stands up a small, deliberately-attackable slice of an AWS estate, fires a
simulated attack against it, detects the attack, and gives you the saved queries to
investigate it — so you can run the whole "what is this user doing?" loop yourself.

> [!WARNING]
> This intentionally creates an over-permissive IAM user, leaks its access key, and runs a
> simulated attack (enumeration + privilege escalation + persistence) against **your own
> account**. The attack Lambda also creates a backdoor IAM user out-of-band.
> **Apply this only in a dedicated throwaway sandbox account.** Never in production, never
> in a shared account. A permissions boundary or SCP on the sandbox is a sensible extra guard.

---

## Layout

```
.
├── modules/
│   ├── foundation/                    # shared audit-logging estate, reused by every scenario
│   │   • multi-region CloudTrail (log-file validation, global events)
│   │     delivering to BOTH S3 (forensics/Athena) and CloudWatch Logs (alarms)
│   │   • S3 log bucket · Athena workgroup + Glue database · shared cloudtrail_logs table · GuardDuty · SNS alert topic
│   ├── scenario-01-account-takeover/  # the leaked-key control-plane attack
│   │   ├── attack.tf        # (1) trigger:     leaked user + key + auto-firing attack Lambda
│   │   ├── detect.tf        # (2) detect:      CloudTrail metric-filter alarms + GuardDuty→EventBridge
│   │   ├── respond.tf       # (2) respond:     quarantine Lambda (deny-all) + destroy-time cleanup
│   │   └── investigate.tf   # (3) investigate: saved Athena queries over the shared cloudtrail_logs table
│   ├── scenario-02-compromised-workload/  # the network-plane egress/lateral-movement attack
│   │   ├── network.tf       # (0) target:      VPC + public subnet + IMDSv2 EC2 + VPC Flow Logs (→ S3 + CWL)
│   │   ├── attack.tf        # (1) trigger:     attack Lambda drives the box via SSM (exfil + REJECT probes)
│   │   ├── detect.tf        # (2) detect:      egress-bytes metric-filter alarm + GuardDuty→EventBridge
│   │   ├── respond.tf       # (2) respond:     isolation Lambda (swap to a no-rules SG)
│   │   └── investigate.tf   # (3) investigate: Glue table over Flow Logs + saved Athena queries
│   ├── scenario-03-dns-exfil/             # the DNS-plane beacon/tunnelling attack
│   │   ├── network.tf       # (0) target:      VPC + IMDSv2 EC2 + Route 53 Resolver query logging (→ S3)
│   │   ├── attack.tf        # (1) trigger:     attack Lambda drives the box via SSM (DGA beacon + TXT tunnelling)
│   │   ├── detect.tf        # (2) detect:      scheduled Athena hunter Lambda + GuardDuty→EventBridge
│   │   ├── prevent.tf       # (2) prevent:     optional DNS Firewall rule group (BLOCK the demo domains)
│   │   └── investigate.tf   # (3) investigate: Glue table over Resolver logs + saved Athena queries
│   ├── scenario-04-web-attack/            # the web-plane WAF + ALB attack
│   │   ├── network.tf       # (0) target:      public ALB (fixed-response, no EC2) + WAFv2 web ACL (→ WAF logs to CWL, ALB logs to S3)
│   │   ├── attack.tf        # (1) trigger:     attack Lambda hits the ALB over HTTP (SQLi + burst + 404 scanning)
│   │   ├── detect.tf        # (2) detect:      WAF-blocked-requests metric-filter alarm (WAF blocks in real time)
│   │   └── investigate.tf   # (3) investigate: Glue table over ALB logs + Athena query + saved WAF Logs Insights query
│   └── scenario-05-s3-exfil/              # the storage-plane S3 data-events exfil
│       ├── storage.tf       # (0) target:      crown-jewels S3 bucket (BPA + versioning) + scoped S3 data-event trail (→ shared S3 + CWL)
│       ├── attack.tf        # (1) trigger:     attack Lambda assumes an over-permissive role, lists + GetObjects every key
│       ├── detect.tf        # (2) detect:      crown-jewels GetObject metric-filter alarm + GuardDuty→EventBridge
│       └── investigate.tf   # (3) investigate: saved Athena queries over the shared cloudtrail_logs table (no new table)
└── scripts/
    └── simulate-attack.sh   # fire a scenario's attack Lambda on demand, N times (see "Re-run the attack")
```

Every scenario module follows the same shape: **trigger the attack · detect it · investigate
it** (with an optional **respond**/**prevent** step). Scenario 1 is the reference the later
planes (Network / DNS / Web / Storage) copy. The `cloudtrail_logs` Glue table lives in the
**foundation** because two planes read it — Scenario 1 (management events) and Scenario 5
(S3 data events, delivered into the same trail prefix).

## Scenario 1 — Account Takeover (control plane / CloudTrail)

A long-lived IAM key leaks. Someone orients (`GetCallerIdentity`, `ListUsers`,
`ListAllMyBuckets`), enumerates what the key can do (a burst of `AccessDenied`), then
escalates and plants persistence (a new admin user + access key). The whole story is
CloudTrail events tagged with the same `userIdentity` — which is exactly what makes the
investigation a single query.

## Usage

```bash
terraform init
terraform apply -var 'alert_email=you@example.com'
```

On apply:
1. The foundation + scenario stand up.
2. The attack Lambda fires (signing every call with the **leaked key**, so CloudTrail
   attributes the whole chain to the leaked user), and ends by generating a GuardDuty
   **sample finding** to exercise the response pipeline.
3. The metric-filter alarms trip; the quarantine Lambda attaches `AWSDenyAll` to the user;
   SNS emails you (confirm the subscription first).

> [!NOTE]
> CloudTrail → CloudWatch Logs delivery lags **~1–2 minutes**, so the alarms go to ALARM a
> couple of minutes *after* the attack Lambda runs. That delay is expected, not a bug.

> [!NOTE]
> **Email alerts and the "Deleted" subscription.** AWS requires you to confirm an email
> subscription by clicking the link it sends — Terraform can't do this for you. Two things
> follow from that:
> - After each `apply` you must click the confirmation link. `apply` now waits up to 10
>   minutes for you (see `confirmation_timeout_in_minutes`) and returns as soon as you click.
>   If you miss the window the subscription still works once confirmed, but Terraform state
>   shows `pending_confirmation = true`.
> - Every `terraform destroy` unsubscribes the email. If you're iterating with
>   destroy/re-apply, the SNS console shows the torn-down subscription as a `Deleted` row
>   (a temporary tombstone, keeping its last "Confirmed" status) and the next `apply` creates
>   a fresh one to re-confirm. That churn is expected, not the scenario deleting anything —
>   nothing in the attack/response code touches SNS. Leave `alert_email = ""` while iterating
>   (alarms are still visible in the CloudWatch console) and set it only for a run you keep.

### Investigate

Open the Athena workgroup from the `athena_workgroup` output (or the `athena_console_url`
deep link) and run the saved queries, in order:

| Query | Answers |
|---|---|
| `s01-01-what-is-this-user-doing` | The full timeline for the leaked principal. |
| `s01-02-enumeration-error-rate`  | The `AccessDenied` burst — enumeration made legible. |
| `s01-03-persistence-actions`     | New users / keys / policy attaches — the persistence. |
| `s01-04-source-ips-and-agents`   | Where they called from, and with what tooling. |

### Re-run the attack

Use the helper script to fire the attack Lambda on demand — as many times as you like — so
you can regenerate the signal without re-applying:

```bash
./scripts/simulate-attack.sh              # fire once
./scripts/simulate-attack.sh -n 5 -i 30   # fire 5 times, 30s apart
./scripts/simulate-attack.sh --help       # all options
```

It discovers the function name and region from `terraform output`, so a bare run works from a
checkout with live state. You can also point it anywhere with `--function-name`/`--name-prefix`
and `--region`. Set `-var 'auto_fire=false'` on apply to stand up the estate without firing,
then drive it entirely from the script.

> [!NOTE]
> **Why a plain re-invoke fails, and how the script fixes it.** The respond pipeline quarantines
> the leaked user by attaching `AWSDenyAll` to it — so the *first* run succeeds, but the leaked
> key that signs the attack is then denied everything, and every later run gets `AccessDenied`.
> The script clears that quarantine (detaches `AWSDenyAll` from the leaked user) before each run,
> which is what makes the scenario repeatable; this needs `iam:DetachUserPolicy` on your caller.
> Pass `--no-reset` to leave the quarantine in place and observe the denied state instead.

Under the hood each run is just: clear the quarantine, then
`aws lambda invoke --function-name "$(terraform output -raw attack_function_name)" /dev/null`

### Exercise GuardDuty directly

Requires `enable_guardduty = true` (otherwise `guardduty_detector_id` is empty and there's
no detector to sample against).

```bash
aws guardduty create-sample-findings \
  --detector-id "$(terraform output -raw guardduty_detector_id)" \
  --finding-types UnauthorizedAccess:IAMUser/MaliciousIPCaller
```

## Scenario 2 — Compromised Workload (network plane / VPC Flow Logs)

A workload is handed a static, over-permissive credential. The box is compromised, an attacker
lands on it, and does two things CloudTrail can't see: **exfiltrates data** to the outside, and
**probes east-west** for what else it can reach. Neither is an AWS API call — they only exist as
traffic on the instance's ENI, which is exactly what **VPC Flow Logs** capture.

This scenario is **off by default** (it stands up a VPC + a `t3.micro`, a small ongoing cost).
Turn it on:

```hcl
# terraform.tfvars
scenario_02_enabled = true
auto_fire           = true
enable_guardduty    = false   # the default; true only on a paid sandbox
```

On apply the module stands up a VPC with a public subnet and one EC2 instance carrying an
over-permissive instance role (**IMDSv2 enforced** — the right default, and the point: it raises
the bar for *stealing* the creds but does nothing once an attacker has code execution). VPC Flow
Logs with a custom format deliver to **both** a dedicated CloudWatch group (the alarm) and the
shared S3 bucket (Athena). The attack Lambda then drives the box via `ssm:SendCommand`: it reads
the instance creds from IMDS, POSTs a few MB of **egress** to an external endpoint, and fans out
**REJECT** probes to neighbours. The `atkplane-egress-exfil` alarm trips and SNS emails you.

> [!NOTE]
> VPC Flow Logs are set to `max_aggregation_interval = 60`, but delivery still lags the attack
> by a minute or two — same shape as CloudTrail's delivery lag. The alarm going ALARM a couple
> of minutes *after* the attack is expected, not a bug.

### Investigate — the first cross-plane story

CloudTrail can show the instance role making calls it's never made, but it can't tell you *where
the data went* — egress isn't an API call. For that you need Flow Logs. Open the Athena workgroup
and run the saved queries:

| Query | Answers |
|---|---|
| `s02-01-top-talkers-egress-bytes` | Top talkers to the outside world — a single destination dominating the bytes column is the exfil. |
| `s02-02-reject-lateral-movement-probe` | The lateral-movement probe — refused connections fanned across internal addresses/ports. |
| `s02-03-compromised-instance-egress-timeline` | Egress from the compromised instance over time — line it up with the alarm. |

### Re-run the attack

Same helper script, pointed at scenario 2 with `-s 2`:

```bash
./scripts/simulate-attack.sh -s 2                 # fire once
./scripts/simulate-attack.sh -s 2 -n 5 -i 60      # fire 5 times, 60s apart
```

Recommend `-i 60` or more so each egress spike (aggregation interval + delivery lag) surfaces as
a distinct alarm transition. When GuardDuty is on, the respond pipeline isolates the box by
swapping it into a no-rules SG; the script restores the instance's **baseline security group**
before each run (undo the isolation), exactly as the scenario-1 path clears the `AWSDenyAll`
quarantine. Pass `--no-reset` to leave it isolated and observe the cut-off state. The scenario-2
reset needs `ec2:ModifyInstanceAttribute` + `ec2:DescribeInstances` on your caller.

> [!NOTE]
> **The finding to know by heart:** `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`.
> It fires when credentials issued to an EC2 instance role are used from an IP *outside* AWS. With
> `enable_guardduty = true` the attack emits a sample of it to drive the isolation Lambda; there is
> essentially no legitimate reason for your instance's role to be driving the AWS API from
> someone's laptop.

## Scenario 3 — DNS Exfil (DNS plane / Route 53 Resolver query logs)

An implant wakes up on a box in your VPC and does something quiet before it does anything
loud: it starts resolving names. First a rotating set of pseudo-random domains to find its
command-and-control server (a **DGA `NXDOMAIN` storm**), then long, high-entropy subdomains to
smuggle data out one lookup at a time (**DNS tunnelling**). This is exactly the traffic
**Flow Logs can't help with** — DNS to the Amazon resolver is excluded from Flow Logs, and even
where it isn't, Flow Logs only see *"something talked on port 53,"* never the **name**. The
name is the whole investigation, and **Route 53 Resolver query logs** capture it.

This scenario is **off by default** (it stands up a VPC + a `t3.micro`, like Scenario 2).
Turn it on:

```hcl
# terraform.tfvars
scenario_03_enabled = true
auto_fire           = true
enable_guardduty    = false   # the default; true only on a paid sandbox
```

On apply the module stands up a VPC with a public subnet and one EC2 instance (**IMDSv2
enforced**), enables **Route 53 Resolver query logging** on the VPC delivering to the shared S3
log bucket, and drives the box via `ssm:SendCommand` to beacon and tunnel over DNS.

> [!NOTE]
> **The one design quirk of this plane.** Unlike Flow Logs, which fan out to both CloudWatch
> (alarms) and S3 (Athena), **a VPC can have only one Resolver query-logging destination.** This
> demo sends query logs to **S3**, so there's no CloudWatch stream to hang a metric-filter alarm
> on. Instead the always-on detector is a **scheduled hunter Lambda**: an EventBridge rule runs
> it every 5 minutes, it queries the last window of Resolver logs in Athena for the
> tunnelling/beacon signature, and publishes to SNS on a hit. That's the departure from
> Scenarios 1 & 2 — DNS abuse is a *pattern over a window*, which a raw metric filter reads
> poorly. (Prefer real-time CloudWatch alarms? Point the config at CloudWatch Logs instead and
> query with Logs Insights — a genuine trade, not a free lunch.)

### Investigate — "what is this box asking for?"

Open the Athena workgroup and run the saved queries:

| Query | Answers |
|---|---|
| `s03-01-dns-tunnelling` | Long, high-entropy first labels on `TXT`/`NULL` pointed at one domain — data leaving, one query at a time. |
| `s03-02-dga-beacon-nxdomain` | The DGA beacon — one parent domain with an outsized share of `NXDOMAIN` responses. |
| `s03-03-instance-dns-timeline` | Every lookup from the compromised box over time — line it up with the hunter's alert. |

### Re-run the attack

Same helper script, pointed at scenario 3 with `-s 3`:

```bash
./scripts/simulate-attack.sh -s 3                 # fire once
./scripts/simulate-attack.sh -s 3 -n 5 -i 60      # fire 5 times, 60s apart
```

There's no automated responder for this plane, so (unlike Scenarios 1 & 2) there's nothing to
reset between runs. After firing, the scheduled hunter catches the pattern on its next pass.

### Detect vs prevent — the DNS Firewall toggle

Setting `enable_dns_firewall = true` also stands up a **Route 53 Resolver DNS Firewall** rule
group that **BLOCKs** the demo beacon/tunnel domains — the *prevent* half of the same
detect-versus-prevent split as CloudTrail log-file validation in Part 2. A blocked lookup is
**still logged** (with `firewall_rule_action = BLOCK`), so the hunter and the `s03-*` queries
keep working either way; the difference is the query is now refused at the resolver instead of
merely observed.

> [!NOTE]
> **The caveat that quietly defeats all of this.** The query logs, the hunter, the GuardDuty
> findings, and DNS Firewall all depend on DNS going through the **Amazon-provided resolver**. A
> workload pointed at an external resolver (`8.8.8.8`) or using DNS-over-HTTPS bypasses every one
> of them in a single move. The control that makes this plane trustworthy is a boring one: force
> outbound DNS through the Route 53 resolver, and block egress on port 53 and DoH endpoints, so
> nothing can route around your visibility.

> [!NOTE]
> **The findings to know:** `Backdoor:EC2/C&CActivity.B!DNS`, `Trojan:EC2/DGADomainRequest.C`,
> and `Trojan:EC2/DNSDataExfiltration`. GuardDuty analyses DNS through the Amazon resolver
> itself, so with `enable_guardduty = true` the attack emits a sample of each to drive the
> EventBridge → SNS path.

## Scenario 4 — Web Attack (web plane / WAF + ALB access logs)

Every earlier scenario started with a credential or a foothold — the attacker was already
inside. This one is different: no credentials, no box, no access. Just your public URL and
bad vibes. A request to `/login` isn't an AWS API call, so **CloudTrail is blind to all of
it** — this is application traffic. The logs that see it are **WAF** (what an IP *tried*:
every evaluated request, the matched rule, ALLOW/BLOCK/COUNT) and **ALB access logs** (what
actually *reached* the app: the status-code ground truth).

This scenario is **off by default** and is the **priciest** in the series — it stands up a
public ALB **and** a WAF web ACL, both of which bill while they're up. Turn it on:

```hcl
# terraform.tfvars
scenario_04_enabled = true
auto_fire           = true
```

On apply the module stands up a deliberately-exposed web endpoint — **no compute required**.
A public ALB with a fixed-response listener (the "app") is fronted by a regional **WAFv2**
web ACL carrying the AWS-managed **Common** and **SQLi** rule groups plus a **rate-based
rule**. WAF logs stream to CloudWatch Logs (for the alarm); ALB access logs go to the shared
S3 bucket (for Athena). The attack Lambda then hits the ALB's public URL with the three
signatures — SQLi-shaped query strings (→ SQLi rule → **BLOCK**), a request burst (→ rate
rule), and a spray of 404-path scanning — WAF blocks the malicious requests **in real time**,
the `atkplane-waf-blocks` alarm trips, and SNS emails you.

> [!NOTE]
> **The response is built into the control.** WAF blocks the attack *as it happens*, so —
> unlike the earlier planes — there's no separate quarantine/isolation step to bolt on. The
> alarm's job here isn't to stop anything (WAF already did); it's to **tell a human it
> happened**. And **GuardDuty doesn't feature** in this plane — it doesn't read WAF or ALB
> logs, so `enable_guardduty` has nothing to do here.

> [!NOTE]
> **The attacker IP is the Lambda's.** Because the attack originates from a Lambda, the source
> IP in your logs is the Lambda's egress address, not a spoofed internet IP — fine for seeing
> exactly how the rules and logs behave. Relatedly: behind a proxy (CloudFront/any CDN) an ALB
> logs the *proxy's* IP as the source; the real client is in the `X-Forwarded-For` header (in
> the ALB log). Know that before you spend an hour chasing your own CDN edge node.

### Investigate — two logs, two questions

This is the plane where you reach for two tools that answer genuinely different questions.

**"What did this IP *try*?"** lives in the WAF logs, in CloudWatch — a saved **Logs Insights**
query (`atkplane/s04-waf-blocks-by-ip`), because that's where WAF writes. It groups blocked
requests by client IP and the rule that caught them: SQLi group = an injection attempt dying
at the edge; rate rule = someone who tried to flood you and got throttled.

**"What actually *reached* the app?"** lives in the ALB logs, in S3 — an Athena query, because
that's the status-code ground truth. Open the Athena workgroup and run:

| Query | Answers |
|---|---|
| `s04-01-alb-status-by-ip` | The response-code shape per IP — a wall of one status from one IP is the intent. 403 = WAF held the line; 404 = recon got through; 200 = it's working (and that's the problem). |
| `s04-02-alb-scanned-paths` | The paths that were probed but not blocked — a wall of 404s across many URLs is reconnaissance, and now you know exactly which paths to go harden. |

### Re-run the attack

Same helper script, pointed at scenario 4 with `-s 4`:

```bash
./scripts/simulate-attack.sh -s 4                 # fire once
./scripts/simulate-attack.sh -s 4 -n 5 -i 60      # fire 5 times, 60s apart
```

WAF blocks in real time, so (like Scenario 3) there's no responder and nothing to reset
between runs. The WAF-blocks alarm trips within ~1 min; ALB access logs take ~5 min to land
in S3 before the Athena queries have data.

> [!NOTE]
> **This is the one to tear down promptly.** The ALB and the WAF web ACL both bill while
> they're up, so don't leave it running overnight for the sake of a screenshot —
> `scenario_04_enabled = false` and re-apply, or `terraform destroy`.

## Scenario 5 — S3 Data-Events Exfil (storage plane)

This is the question your board, your regulator, and your biggest customer ask: **did the
data actually leave?** An attacker with a foothold assumes an over-permissive role and does
the most mundane, devastating thing there is — `ListObjectsV2` to enumerate a sensitive
bucket, then `GetObject` on every key. No exploit, no malware.

The catch, and the whole lesson of this part: **CloudTrail does not log object-level access
out of the box.** The foundation trail is multi-region, validated, dual-delivery — and it has
no event selectors, so it captures **management events only**. It will faithfully record that
someone changed a bucket policy (`PutBucketPolicy`), but the `GetObject` calls that read every
file inside are **data events — off by default, and billed per event**. Turn them on for the
buckets worth stealing from, scoped with advanced event selectors, and **never** for your log
bucket (a data-event trail writing to its own log bucket is a recursive billing loop).

This scenario is **off by default** because it deliberately turns on that paid feature (data
events on one small bucket). Turn it on:

```hcl
# terraform.tfvars
scenario_05_enabled = true
auto_fire           = true
enable_data_events  = true    # the scoped data-event trail — the point of the lesson
enable_guardduty    = false   # the default; true only on a paid sandbox
```

On apply the module stands up a **"crown jewels" bucket** — Block Public Access on, versioning
enabled, seeded with a handful of **synthetic** sensitive-looking objects (fake customer
records, nothing real) — plus a **second, dedicated CloudTrail scoped to S3 data events on
that one bucket**. It delivers into the shared S3 bucket (same `AWSLogs/.../CloudTrail` prefix)
and the shared CloudWatch group, so the data events land right alongside the management events
from Part 2. The attack Lambda then assumes the over-permissive role and reads every object; a
metric-filter alarm counting `GetObject` against the crown-jewels bucket trips a minute or two
later, and SNS emails you. (With `enable_guardduty = true`, GuardDuty S3 Protection adds an
`Exfiltration:S3/AnomalousBehavior` finding via the same EventBridge→SNS path.)

> [!NOTE]
> **Why a separate trail, not selectors on the foundation trail.** Adding any
> `advanced_event_selector` to a trail *replaces* its default management-events selector — so
> bolting data events onto the foundation trail would silently stop it recording the management
> events Scenarios 1–4 depend on. A dedicated trail keeps the two concerns (and the per-event
> bill) cleanly separable.

> [!NOTE]
> **First apply waits for the trail to warm up.** A brand-new CloudTrail takes a few minutes
> before it actually starts capturing events. If the attack fired the instant the trail was
> created, the reads would slip through *unrecorded* and the alarm would never trip. So the
> on-apply auto-fire waits out a `trail_warmup_duration` (default `300s`) after the trail is
> created — you'll see `apply` pause on `time_sleep.trail_warmup`. This is paid **once**, on
> the apply that stands the trail up; manual re-runs via `simulate-attack.sh` hit an
> already-warm trail and skip the wait.

### Investigate — "did they actually read it?"

The nice payoff: data events land in the same prefix as the management events, so the existing
`cloudtrail_logs` Glue table queries them — **no new table needed, just new saved queries.**
And because data events carry the same `userIdentity` as management events, you can pivot
straight back to the API-plane query from Part 2, unchanged.

| Query | Answers |
|---|---|
| `s05-01-did-they-read-it` | Object-level access against the crown-jewels bucket, grouped by principal + source IP. A principal that normally reads nothing suddenly pulling every object is your exfil, in one row. |
| `s05-02-which-objects-were-read` | The actual object keys read, with timestamps, principal and IP. The one that matters in an incident: not "a bucket was accessed" but "these specific files were read, at these times, by this principal." |

### The experiment that makes the point

Do this before you tear it down — it's the whole lesson in one command. Set
`enable_data_events = false` and re-apply (that removes the scoped trail, leaving exactly the
setup the previous four scenarios ran on), then re-fire and re-run `s05-01`:

```bash
./scripts/simulate-attack.sh -s 5
```

It returns **nothing**. Not an error — nothing. The bucket was read, every object left, and
your beautifully configured audit trail has no record of it. That's what "off by default"
costs you.

### Re-run the attack

```bash
./scripts/simulate-attack.sh -s 5                 # fire once
./scripts/simulate-attack.sh -s 5 -n 5 -i 60      # fire 5 times, 60s apart
```

Detect-only (GuardDuty S3 Protection / the metric-filter alarm), so — like Scenarios 3 and 4 —
there's no responder and nothing to reset between runs.

> [!NOTE]
> **Turn the data-event trail off when you're done.** It's the one component here that bills
> per event. `enable_data_events = false` (or `scenario_05_enabled = false`) and re-apply, or
> `terraform destroy`. The crown-jewels bucket has `force_destroy` set, so teardown doesn't
> choke on the seeded objects — and it's synthetic data anyway.

## Teardown

```bash
terraform destroy
```

> [!NOTE]
> **Scenarios 2 and 3 tear down a VPC**, and VPCs are fussy to delete while anything is still
> attached. Terraform orders it correctly (Flow Logs / the Resolver query-log association, the
> ENI, and the instance go before the VPC), but if a destroy ever hangs on the VPC, a lingering
> ENI or an in-flight Resolver query-log association is the usual culprit. Neither attack creates
> out-of-band AWS resources (only network/DNS traffic + an IMDS read), so — unlike scenario 1 —
> there is no cleanup Lambda to run for them.

A **destroy-time provisioner** invokes a cleanup Lambda that deletes the backdoor IAM
user(s) the attack created out-of-band (Terraform can't track them). This step shells out
to the **AWS CLI** — make sure it's installed and authenticated on the machine running
`destroy`. If you ever destroy without the CLI available, run the cleanup Lambda manually
first, or delete any `atkplane-persist-*` IAM users by hand.

## Cost

Small but non-zero while running: GuardDuty, CloudTrail management events, S3 storage, a few
Lambda invocations, CloudWatch alarms. Destroy when you're done. `force_destroy` is set on
the log bucket so teardown doesn't choke on the objects CloudTrail wrote.

## Variables

| Variable | Default | Purpose |
|---|---|---|
| `region` | `us-east-1` | Home region. Keep `us-east-1` so global IAM/STS events land here. |
| `name_prefix` | `atkplane` | Prefix on every resource — makes the demo easy to find and tear down. |
| `alert_email` | `""` | Subscribe an email to the SNS alert topic. You must confirm it via the emailed link (see the email-alerts note under Usage). |
| `auto_fire` | `true` | Fire the attack on apply. Set `false` to fire it manually later. |
| `enable_guardduty` | `false` | Stand up the GuardDuty detector + its EventBridge→SNS/quarantine wiring. Off by default because **GuardDuty is not on the AWS Free Tier**. See the note below. |
| `scenario_01_enabled` | `true` | Deploy Scenario 1 (account takeover / control plane). Cheap — no compute — so on by default. |
| `scenario_02_enabled` | `false` | Deploy Scenario 2 (compromised workload / network plane). Off by default because it stands up a VPC + a `t3.micro` EC2 instance (small ongoing cost). |
| `scenario_03_enabled` | `false` | Deploy Scenario 3 (DNS exfil / DNS plane). Off by default because it stands up a VPC + a `t3.micro` EC2 instance + Route 53 Resolver query logging (small ongoing cost). |
| `enable_dns_firewall` | `false` | Scenario 3 only: also stand up the Route 53 Resolver DNS Firewall "prevent" control (BLOCK the demo beacon/tunnel domains). Off by default so the demo is detect-only. |
| `scenario_04_enabled` | `false` | Deploy Scenario 4 (web attack / web plane). Off by default because it stands up a public ALB + a WAF web ACL — the **priciest** scenario, so tear it down when done. |
| `scenario_05_enabled` | `false` | Deploy Scenario 5 (S3 data-events exfil / storage plane). Off by default because it deliberately turns on a **paid feature** — CloudTrail S3 data events (see `enable_data_events`) on a small "crown jewels" bucket — which is the whole point of the lesson. |
| `enable_data_events` | `true` | Scenario 5 only: stand up the scoped CloudTrail S3 data-event trail (the thing that actually records object-level access). Set `false` and re-apply for the "and now the investigation returns nothing" experiment. Data events bill per event — turn it off when done. |

> [!NOTE]
> **GuardDuty and the Free Tier.** GuardDuty is a paid service, so `enable_guardduty`
> defaults to `false` and the demo runs Free-Tier-friendly out of the box. With it off you
> still get the whole **trigger → detect → investigate** loop: the CloudTrail metric-filter
> alarms fire off the attack's own signal, and all the Athena queries work. What you lose is
> the GuardDuty-driven **auto-quarantine** — the detector, its EventBridge rule, and the
> sample-finding step are skipped. The quarantine Lambda is still created, so you can invoke
> it by hand to demo the response step. Set `enable_guardduty = true` on a sandbox account
> where you're happy to pay for GuardDuty to exercise the full detect→respond pipeline.
