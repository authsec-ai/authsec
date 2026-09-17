"""Scripted Exercise A Lambda fixtures. No model inference or real customer data."""
import base64
import hashlib
import hmac
import json
import os
import time

import boto3
from botocore.exceptions import ClientError


def call_lambda(name, payload):
    response = boto3.client("lambda").invoke(
        FunctionName=name, Payload=json.dumps(payload).encode())
    result = json.loads(response["Payload"].read())
    if response.get("FunctionError"):
        raise RuntimeError(result)
    return result


def handler(event, context):
    mode = os.environ["FIXTURE_MODE"]
    try:
        if mode == "app":
            # Identity comes from a signed, expiring fixture token. A caller's
            # 'user' or 'customer' field is never used as authentication.
            encoded, signature = event.get("token", "").split(".", 1)
            expected = hmac.new(os.environ["LAB_AUTH_KEY"].encode(), encoded.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                return {"status": "denied", "reason": "invalid fixture authentication"}
            claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            if claims.get("exp", 0) < time.time() or claims.get("sub") != "H02":
                return {"status": "denied", "reason": "expired or unknown fixture identity"}
            ticket = str(event.get("ticket_id", ""))
            # Explicit synthetic application ACL, not an AWS-discovered fact.
            allowed = claims.get("customer") == "C-ACME" and ticket == "451"
            print(json.dumps({"fixture": "application_authorization", "subject": "H02", "ticket": ticket, "allowed": allowed}))
            if not allowed:
                return {"status": "denied", "reason": "application customer ACL"}
            return call_lambda(os.environ["ORCHESTRATOR"] + ":prod", {"operation": "getTicket", "ticket_id": ticket})
        if mode == "orchestrator":
            return call_lambda(os.environ["TICKET_TOOL"], event)
        if mode == "refund":
            credentials = boto3.client("sts").assume_role(
                RoleArn=os.environ["REFUND_ROLE"], RoleSessionName="acme-lab-refund")["Credentials"]
            db = boto3.client("dynamodb", aws_access_key_id=credentials["AccessKeyId"],
                              aws_secret_access_key=credentials["SecretAccessKey"],
                              aws_session_token=credentials["SessionToken"])
            response = db.put_item(TableName=os.environ["REFUNDS"], Item={
                "refund_id": {"S": "RF-002"}, "ticket_id": {"S": "451"},
                "amount_minor": {"N": "2500"}, "currency": {"S": "USD"}})
        elif mode == "legacy":
            boto3.client("secretsmanager").get_secret_value(SecretId=os.environ["LEGACY_SECRET"])
            return {"status": "allowed", "fixture": "synthetic secret read; value omitted"}
        elif mode == "ticket":
            operation = event.get("operation", "getTicket")
            if operation == "getTicket":
                response = boto3.client("dynamodb").get_item(TableName=os.environ["TICKETS"],
                    Key={"ticket_id": {"S": str(event.get("ticket_id", "451"))}})
            elif operation == "boundaryProbe":
                response = boto3.client("dynamodb").put_item(TableName=os.environ["TICKETS"],
                    Item={"ticket_id": {"S": "BOUNDARY-PROBE"}})
            elif operation in ("getAttachment", "duplicateProbe", "financeProbe"):
                bucket = os.environ["FINANCE"] if operation == "financeProbe" else os.environ["ATTACHMENTS"]
                key = {"getAttachment": "attachments/451.txt", "duplicateProbe": "sandbox/probe.txt",
                       "financeProbe": "finance/payroll.csv"}[operation]
                response = boto3.client("s3").get_object(Bucket=bucket, Key=key)
                response["Body"].close()
            else:
                return {"status": "unsupported", "operation": operation}
        else:
            return {"status": "unsupported", "mode": mode}
        return {"status": "allowed", "request_id": response["ResponseMetadata"]["RequestId"]}
    except ClientError as error:
        return {"status": "aws_error", "code": error.response["Error"]["Code"],
                "request_id": error.response.get("ResponseMetadata", {}).get("RequestId"),
                "message": error.response["Error"]["Message"]}
    except (ValueError, KeyError):
        return {"status": "denied", "reason": "invalid fixture authentication or input"}
