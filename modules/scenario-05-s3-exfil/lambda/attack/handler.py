"""
Scenario 5 - S3 data-events exfil (the storage plane).

The mundane, devastating attack: an attacker with a foothold assumes an over-
permissive role, lists a sensitive bucket, and reads every object in it. No
exploit, no malware - just ListObjectsV2 and a lot of GetObject.

Each GetObject is an S3 *data* event. The foundation trail is management-events
only, so unless Scenario 5's scoped data-event trail is up (enable_data_events),
none of this leaves a trace. That is the whole point of the plane.

The handler:
  1. Assumes EXFIL_ROLE_ARN via STS (retrying past IAM eventual consistency).
  2. Lists TARGET_BUCKET (paginated) with the assumed-role creds.
  3. GetObjects every key it finds, in a tight loop.
  4. Optionally fires a GuardDuty S3 sample finding (when DETECTOR_ID is set) so
     the S3-Protection detection path is exercised deterministically.
"""

import os
import time

import boto3
from botocore.exceptions import ClientError

TARGET_BUCKET = os.environ["TARGET_BUCKET"]
EXFIL_ROLE_ARN = os.environ["EXFIL_ROLE_ARN"]
REGION = os.environ.get("REGION") or os.environ.get("AWS_REGION")
DETECTOR_ID = os.environ.get("DETECTOR_ID", "")

# The finding type GuardDuty S3 Protection raises for anomalous bulk reads - the
# real-world detection this scenario mirrors.
SAMPLE_FINDING_TYPES = ["Exfiltration:S3/AnomalousBehavior"]


def _assume_exfil_role():
    """Assume the over-permissive role, retrying past IAM propagation lag."""
    sts = boto3.client("sts", region_name=REGION)
    last_err = None
    for attempt in range(6):
        try:
            resp = sts.assume_role(
                RoleArn=EXFIL_ROLE_ARN,
                RoleSessionName="s5-exfil",
            )
            return resp["Credentials"]
        except ClientError as err:
            last_err = err
            # AccessDenied/MalformedPolicy right after create = trust not yet live.
            time.sleep(5)
    raise RuntimeError(f"could not assume {EXFIL_ROLE_ARN}: {last_err}")


def _s3_client(creds):
    return boto3.client(
        "s3",
        region_name=REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _list_all_keys(s3):
    keys = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=TARGET_BUCKET):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
    return keys


def _read_every_object(s3, keys):
    read = 0
    for key in keys:
        try:
            resp = s3.get_object(Bucket=TARGET_BUCKET, Key=key)
            # Drain the body so the GetObject genuinely completes.
            resp["Body"].read()
            read += 1
        except ClientError as err:
            print(f"[warn] GetObject failed for {key}: {err}")
    return read


def _fire_sample_finding():
    if not DETECTOR_ID:
        print("[info] DETECTOR_ID not set - skipping GuardDuty sample finding.")
        return False
    try:
        boto3.client("guardduty", region_name=REGION).create_sample_findings(
            DetectorId=DETECTOR_ID,
            FindingTypes=SAMPLE_FINDING_TYPES,
        )
        print("[info] GuardDuty sample S3 finding requested.")
        return True
    except ClientError as err:
        print(f"[warn] CreateSampleFindings failed: {err}")
        return False


def handler(event, context):
    print(f"[*] exfil against s3://{TARGET_BUCKET} via {EXFIL_ROLE_ARN}")

    creds = _assume_exfil_role()
    s3 = _s3_client(creds)

    keys = _list_all_keys(s3)
    print(f"[*] enumerated {len(keys)} object(s); reading all of them...")
    read = _read_every_object(s3, keys)
    print(f"[*] read {read}/{len(keys)} object(s).")

    finding = _fire_sample_finding()

    return {
        "bucket": TARGET_BUCKET,
        "objects_listed": len(keys),
        "objects_read": read,
        "sample_finding_fired": finding,
    }
