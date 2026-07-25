#!/usr/bin/env bash
#
# simulate-attack.sh - fire a scenario's attack Lambda on demand, N times.
#
# Re-generates the trigger -> detect -> investigate signal without re-applying,
# for whichever scenario you point it at (-s/--scenario). Each run fires the
# attack Lambda, trips that scenario's alarm(s), and (when enable_guardduty=true)
# emits a GuardDuty sample finding.
#
#   Scenario 1 (account takeover / control plane):
#     Signs a leaked-key attack chain -> CloudTrail metric-filter alarms.
#     The respond pipeline quarantines the leaked user by attaching AWSDenyAll to
#     it; since the attack is signed with that user's key, once quarantined every
#     later run gets AccessDenied. So before each run this script clears the
#     quarantine (detaches AWSDenyAll from the leaked user) - that's what makes
#     the scenario repeatable.
#
#   Scenario 2 (compromised workload / network plane):
#     Drives an on-box script via SSM -> egress + REJECT probes in VPC Flow Logs.
#     The respond pipeline isolates the box by swapping it into a no-rules SG. So
#     before each run this script restores the instance's baseline security group
#     (undo the isolation) so egress can flow and SSM can reach the box again.
#
#   Scenario 3 (DNS exfil / DNS plane):
#     Drives an on-box script via SSM -> DGA NXDOMAIN beacon + long-label TXT
#     tunnelling in Route 53 Resolver query logs. There is no automated responder
#     for this plane, so there is nothing to reset before a run.
#
#   Scenario 4 (web attack / web plane):
#     Makes outbound HTTP to the public ALB -> SQLi payloads, a request burst, and
#     404-path scanning across the WAF + ALB logs. WAF blocks the attack in real
#     time (the response is built into the control), so there is no responder and
#     nothing to reset before a run.
#
#   Scenario 5 (S3 data-events exfil / storage plane):
#     Assumes an over-permissive role and mass-reads the crown-jewels bucket
#     (ListObjectsV2 + GetObject on every key) -> S3 data events in the scoped
#     data-event trail. Detect-only (GuardDuty S3 Protection / a metric-filter
#     alarm), so there is no responder and nothing to reset before a run.
#
# Pass --no-reset to skip the reset and observe the quarantined/isolated state.
#
# By default it discovers the function name and region from `terraform output`,
# so from a checkout with live state you can just run:
#
#   ./scripts/simulate-attack.sh            # scenario 1, fire once
#   ./scripts/simulate-attack.sh -s 2 -n 5 -i 60   # scenario 2, 5 times, 60s apart
#
# Usage:
#   ./scripts/simulate-attack.sh [options]
#
# Options:
#   -s, --scenario N           Scenario to fire: 1, 2, 3, 4, or 5 (default: 1)
#   -f, --function-name NAME   Attack Lambda to invoke (default: from terraform output)
#   -p, --name-prefix PREFIX   Derive the name (matches var.name_prefix)
#   -r, --region REGION        AWS region (default: terraform output region, else $AWS_REGION)
#   -u, --leaked-user NAME     (s1) Leaked user to un-quarantine (default: terraform output)
#       --instance-id ID       (s2) Instance to un-isolate (default: terraform output)
#       --baseline-sg SG       (s2) Baseline security group to restore (default: terraform output)
#   -n, --count N              Fire N times (default: 1)
#   -i, --interval SECONDS     Wait SECONDS between runs (default: 0)
#       --no-reset             Don't clear the quarantine/isolation before running
#   -h, --help                 Show this help
#
# Requires: aws CLI (authenticated). Reset needs iam:DetachUserPolicy (s1) or
# ec2:ModifyInstanceAttribute + ec2:DescribeInstances (s2) unless --no-reset.
# terraform is only needed when you don't pass --function-name/--region explicitly.

set -euo pipefail

# --- locate the terraform root (this script lives in <root>/scripts/) ----------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
TF_DIR="$(dirname -- "$SCRIPT_DIR")"

SCENARIO=1
FUNCTION_NAME=""
NAME_PREFIX=""
REGION=""
LEAKED_USER=""
INSTANCE_ID=""
BASELINE_SG=""
COUNT=1
INTERVAL=0
RESET=1
DENY_ALL_ARN="arn:aws:iam::aws:policy/AWSDenyAll"

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  # Print the leading comment block (minus the shebang) as help text.
  sed -n '3,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'
  exit "${1:-0}"
}

# --- parse args ----------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -s | --scenario)
      SCENARIO="${2:-}"
      shift 2
      ;;
    -f | --function-name)
      FUNCTION_NAME="${2:-}"
      shift 2
      ;;
    -p | --name-prefix)
      NAME_PREFIX="${2:-}"
      shift 2
      ;;
    -r | --region)
      REGION="${2:-}"
      shift 2
      ;;
    -u | --leaked-user)
      LEAKED_USER="${2:-}"
      shift 2
      ;;
    --instance-id)
      INSTANCE_ID="${2:-}"
      shift 2
      ;;
    --baseline-sg)
      BASELINE_SG="${2:-}"
      shift 2
      ;;
    --no-reset)
      RESET=0
      shift
      ;;
    -n | --count)
      COUNT="${2:-}"
      shift 2
      ;;
    -i | --interval)
      INTERVAL="${2:-}"
      shift 2
      ;;
    -h | --help) usage 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[[ "$SCENARIO" == "1" || "$SCENARIO" == "2" || "$SCENARIO" == "3" || "$SCENARIO" == "4" || "$SCENARIO" == "5" ]] || die "--scenario must be 1, 2, 3, 4, or 5"
[[ "$COUNT" =~ ^[0-9]+$ && "$COUNT" -ge 1 ]] || die "--count must be a positive integer"
[[ "$INTERVAL" =~ ^[0-9]+$ ]] || die "--interval must be a non-negative integer"

command -v aws >/dev/null || die "the aws CLI is required but was not found on PATH"

# --- resolve function name + region (fall back to terraform outputs) -----------
tf_output() {
  terraform -chdir="$TF_DIR" output -raw "$1" 2>/dev/null || true
}

# The attack function name per scenario, and how to derive it from a prefix.
if [[ "$SCENARIO" == "1" ]]; then
  FN_OUTPUT="attack_function_name"
  FN_SUFFIX="-attack"
elif [[ "$SCENARIO" == "2" ]]; then
  FN_OUTPUT="scenario_02_attack_function_name"
  FN_SUFFIX="-s2-attack"
elif [[ "$SCENARIO" == "3" ]]; then
  FN_OUTPUT="scenario_03_attack_function_name"
  FN_SUFFIX="-s3-attack"
elif [[ "$SCENARIO" == "4" ]]; then
  FN_OUTPUT="scenario_04_attack_function_name"
  FN_SUFFIX="-s4-attack"
else
  FN_OUTPUT="scenario_05_attack_function_name"
  FN_SUFFIX="-s5-attack"
fi

# An explicit --name-prefix wins over discovery.
[[ -z "$FUNCTION_NAME" && -n "$NAME_PREFIX" ]] && FUNCTION_NAME="${NAME_PREFIX}${FN_SUFFIX}"

# Fall back to terraform outputs when we still need something and terraform is around.
if [[ -z "$FUNCTION_NAME" || -z "$REGION" ]] && ! command -v terraform >/dev/null; then
  die "terraform not found; pass --function-name (or --name-prefix) and --region explicitly"
fi

if [[ -z "$FUNCTION_NAME" ]]; then
  FUNCTION_NAME="$(tf_output "$FN_OUTPUT")"
  # Scenario 1: pre-existing state (applied before attack_function_name existed)
  # still exposes leaked_user_name; derive the attack name from it.
  if [[ -z "$FUNCTION_NAME" && "$SCENARIO" == "1" ]]; then
    leaked="$(tf_output leaked_user_name)"
    [[ -n "$leaked" ]] && FUNCTION_NAME="${leaked/-leaked-ci-user/-attack}"
  fi
fi

[[ -n "$REGION" ]] || REGION="$(tf_output region)"
[[ -n "$REGION" ]] || REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"

[[ -n "$FUNCTION_NAME" ]] ||
  die "could not determine the attack Lambda name. Pass --function-name or --name-prefix, or run from a checkout with live terraform state."
[[ -n "$REGION" ]] ||
  die "could not determine the region. Pass --region, or set AWS_REGION."

# --- scenario 1 reset: clear the AWSDenyAll quarantine -------------------------
if [[ "$SCENARIO" == "1" && "$RESET" -eq 1 && -z "$LEAKED_USER" ]]; then
  LEAKED_USER="$(tf_output leaked_user_name)"
  if [[ -z "$LEAKED_USER" ]]; then
    prefix="${NAME_PREFIX:-${FUNCTION_NAME%-attack}}"
    [[ -n "$prefix" ]] && LEAKED_USER="${prefix}-leaked-ci-user"
  fi
fi

reset_quarantine() {
  [[ "$RESET" -eq 1 ]] || return 0
  if [[ -z "$LEAKED_USER" ]]; then
    echo "warning: could not resolve the leaked user; skipping quarantine reset (pass --leaked-user)" >&2
    return 0
  fi
  local attached
  attached="$(aws iam list-attached-user-policies \
    --user-name "$LEAKED_USER" --region "$REGION" \
    --query "length(AttachedPolicies[?PolicyArn=='${DENY_ALL_ARN}'])" \
    --output text 2>/dev/null || echo "0")"
  if [[ "$attached" == "1" ]]; then
    echo ">> reset: detaching AWSDenyAll from $LEAKED_USER (undo prior quarantine)"
    if aws iam detach-user-policy \
      --user-name "$LEAKED_USER" --policy-arn "$DENY_ALL_ARN" --region "$REGION"; then
      echo "[+] quarantine cleared"
    else
      echo "warning: failed to detach AWSDenyAll (need iam:DetachUserPolicy?); the run may fail" >&2
    fi
  fi
}

# --- scenario 2 reset: restore the instance's baseline security group ----------
if [[ "$SCENARIO" == "2" && "$RESET" -eq 1 ]]; then
  [[ -n "$INSTANCE_ID" ]] || INSTANCE_ID="$(tf_output scenario_02_instance_id)"
  [[ -n "$BASELINE_SG" ]] || BASELINE_SG="$(tf_output scenario_02_instance_sg_id)"
fi

reset_isolation() {
  [[ "$RESET" -eq 1 ]] || return 0
  if [[ -z "$INSTANCE_ID" || -z "$BASELINE_SG" ]]; then
    echo "warning: could not resolve instance id / baseline SG; skipping isolation reset (pass --instance-id/--baseline-sg)" >&2
    return 0
  fi
  local current
  current="$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" --region "$REGION" \
    --query 'Reservations[0].Instances[0].SecurityGroups[].GroupId' \
    --output text 2>/dev/null || echo "")"
  if [[ "$current" != *"$BASELINE_SG"* ]]; then
    echo ">> reset: restoring $INSTANCE_ID to baseline SG $BASELINE_SG (undo prior isolation)"
    if aws ec2 modify-instance-attribute \
      --instance-id "$INSTANCE_ID" --groups "$BASELINE_SG" --region "$REGION"; then
      echo "[+] isolation cleared"
    else
      echo "warning: failed to restore SG (need ec2:ModifyInstanceAttribute?); the run may fail" >&2
    fi
  fi
}

reset_before_run() {
  if [[ "$SCENARIO" == "1" ]]; then
    reset_quarantine
  elif [[ "$SCENARIO" == "2" ]]; then
    reset_isolation
  fi
  # Scenarios 3, 4 and 5 have no automated responder, so there is nothing to reset.
}

# --- fire ----------------------------------------------------------------------
echo ">> scenario      : $SCENARIO"
echo ">> attack Lambda : $FUNCTION_NAME"
echo ">> region        : $REGION"
if [[ "$SCENARIO" == "3" || "$SCENARIO" == "4" || "$SCENARIO" == "5" ]]; then
  echo ">> reset         : n/a (scenario $SCENARIO has no responder)"
elif [[ "$RESET" -eq 1 ]]; then
  if [[ "$SCENARIO" == "1" ]]; then
    echo ">> reset         : un-quarantine ${LEAKED_USER:+($LEAKED_USER) }before each run"
  else
    echo ">> reset         : un-isolate ${INSTANCE_ID:+($INSTANCE_ID) }before each run"
  fi
else
  echo ">> reset         : disabled (--no-reset)"
fi
echo ">> runs          : $COUNT (interval ${INTERVAL}s)"
echo

RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$RESPONSE_FILE"' EXIT

for ((run = 1; run <= COUNT; run++)); do
  echo "== run $run/$COUNT =="

  reset_before_run

  # --cli-binary-format keeps the raw JSON payload readable on AWS CLI v2.
  status="$(aws lambda invoke \
    --function-name "$FUNCTION_NAME" \
    --region "$REGION" \
    --cli-binary-format raw-in-base64-out \
    --payload "{\"trigger\":\"simulate-attack.sh\",\"run\":$run}" \
    --query 'FunctionError' --output text \
    "$RESPONSE_FILE")"

  echo "-- lambda response --"
  if command -v jq >/dev/null; then
    jq . "$RESPONSE_FILE" 2>/dev/null || cat "$RESPONSE_FILE"
  else
    cat "$RESPONSE_FILE"
  fi
  echo

  if [[ "$status" != "None" && -n "$status" ]]; then
    die "the attack Lambda reported a FunctionError ($status) on run $run - see the payload above"
  fi
  echo "[+] run $run complete"

  if [[ "$run" -lt "$COUNT" && "$INTERVAL" -gt 0 ]]; then
    echo "... sleeping ${INTERVAL}s"
    sleep "$INTERVAL"
  fi
  echo
done

if [[ "$SCENARIO" == "1" ]]; then
  echo "Done. Give CloudTrail ~1-2 min to deliver to CloudWatch Logs, then investigate:"
elif [[ "$SCENARIO" == "2" ]]; then
  echo "Done. Give VPC Flow Logs ~1-2 min to deliver, then investigate:"
elif [[ "$SCENARIO" == "3" ]]; then
  echo "Done. Give Route 53 Resolver query logs a few min to deliver (the scheduled hunter"
  echo "catches the pattern on its next pass), then investigate:"
elif [[ "$SCENARIO" == "4" ]]; then
  echo "Done. The WAF-blocks alarm trips within ~1 min; give ALB access logs ~5 min to"
  echo "deliver to S3, then investigate:"
else
  echo "Done. Give CloudTrail ~1-2 min to deliver the S3 data events to CloudWatch (the"
  echo "crown-jewels-reads alarm trips then), and to S3 before the s05 Athena queries have"
  echo "data. If enable_data_events=false, the reads leave no record - that's the lesson."
fi
ATHENA_URL="$(tf_output athena_console_url)"
if [[ -n "$ATHENA_URL" ]]; then
  echo "  Athena: $ATHENA_URL"
else
  echo "  Athena: terraform -chdir=\"$TF_DIR\" output -raw athena_console_url"
fi
