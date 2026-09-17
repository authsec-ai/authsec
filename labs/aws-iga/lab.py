#!/usr/bin/env python3
"""Exercise A launcher for AWS CloudShell. No credentials are printed/exported."""
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

from templates import generate

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"


def save(name, data):
    OUT.mkdir(exist_ok=True, mode=0o700)
    path = OUT / name
    path.write_text(json.dumps(data, indent=2, default=str) + "\n")
    path.chmod(0o600)
    return path


class Lab:
    def __init__(self, args):
        import boto3
        from botocore.config import Config
        self.args = args
        self.session = boto3.Session(profile_name=args.profile, region_name=args.primary)
        self.config = Config(retries={"mode": "standard", "max_attempts": 8})
        identity = self.client("sts").get_caller_identity()
        if identity["Account"] != args.account_id:
            raise RuntimeError("Account mismatch. No deployment/cleanup performed.")
        if identity["Arn"].endswith(":root"):
            raise RuntimeError("Use an IAM/Identity Center administrator session, not root.")
        if not identity["Arn"].startswith("arn:aws:"):
            raise RuntimeError("This kit targets the commercial AWS partition only.")
        self.lab = args.lab_id
        self.account = identity["Account"]
        self.bucket = f"{self.lab}-{self.account}-deployment"
        self.secret_name = self.lab + "/deployment-credentials"
        self.actor = identity["Arn"]

    def client(self, service, region=None):
        return self.session.client(service, region_name=region or self.args.primary, config=self.config)

    def missing(self, error):
        return getattr(error, "response", {}).get("Error", {}).get("Code") in (
            "ResourceNotFoundException", "NoSuchEntity", "NoSuchBucket", "404")

    def stack(self, region, suffix):
        client = self.client("cloudformation", region)
        try:
            result = client.describe_stacks(StackName=self.lab + "-" + suffix)["Stacks"][0]
        except Exception as error:
            if "does not exist" in str(error):
                return None
            raise
        if not any(t["Key"] == "LabId" and t["Value"] == self.lab for t in result.get("Tags", [])):
            raise RuntimeError("Existing stack lacks matching LabId tag; refusing to use it.")
        return result

    def outputs(self):
        stack = self.stack(self.args.primary, "primary")
        if not stack or stack["StackStatus"] != "CREATE_COMPLETE":
            raise RuntimeError("Primary stack is not CREATE_COMPLETE. Inspect CloudFormation events.")
        return {x["OutputKey"]: x["OutputValue"] for x in stack.get("Outputs", [])}

    def secret(self, create=False):
        client = self.client("secretsmanager")
        try:
            description = client.describe_secret(SecretId=self.secret_name)
            if not any(t["Key"] == "LabId" and t["Value"] == self.lab for t in description.get("Tags", [])):
                raise RuntimeError("Existing deployment secret has no matching LabId tag.")
            return json.loads(client.get_secret_value(SecretId=self.secret_name)["SecretString"])
        except Exception as error:
            if not create or not self.missing(error):
                raise
        data = {"auth_key": secrets.token_hex(32), "keys": {}}
        client.create_secret(Name=self.secret_name, SecretString=json.dumps(data),
            Tags=[{"Key": "LabId", "Value": self.lab}, {"Key": "Purpose", "Value": "deployment-only; not a business fixture"}])
        return data

    def put_secret(self, data):
        self.client("secretsmanager").put_secret_value(SecretId=self.secret_name, SecretString=json.dumps(data))

    def ensure_bucket(self):
        s3 = self.client("s3")
        try:
            s3.head_bucket(Bucket=self.bucket)
        except Exception as error:
            if not self.missing(error):
                raise
            kwargs = {} if self.args.primary == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": self.args.primary}}
            s3.create_bucket(Bucket=self.bucket, **kwargs)
            s3.put_bucket_tagging(Bucket=self.bucket, Tagging={"TagSet": [{"Key": "LabId", "Value": self.lab}]})
        self.check_bucket(self.bucket)
        s3.put_public_access_block(Bucket=self.bucket, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        s3.put_bucket_encryption(Bucket=self.bucket, ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})

    def check_bucket(self, bucket):
        tags = self.client("s3").get_bucket_tagging(Bucket=bucket)["TagSet"]
        if not any(t["Key"] == "LabId" and t["Value"] == self.lab for t in tags):
            raise RuntimeError(f"Refusing to modify bucket without matching LabId: {bucket}")

    def deploy_stack(self, region, suffix, template, parameters=None):
        cfn = self.client("cloudformation", region)
        name = self.lab + "-" + suffix
        existing = self.stack(region, suffix)
        if existing:
            if existing["StackStatus"] == "CREATE_COMPLETE":
                print(name, "already created; resuming remaining setup", flush=True)
                return
            if existing["StackStatus"] != "CREATE_IN_PROGRESS":
                raise RuntimeError(f"{name}: {existing['StackStatus']}; inspect events; use destroy before redeploying")
        else:
            key = suffix + ".json"
            body = json.dumps(template).encode()
            save(key, template)
            self.client("s3").put_object(Bucket=self.bucket, Key=key, Body=body)
            url = f"https://{self.bucket}.s3.{self.args.primary}.amazonaws.com/{key}"
            cfn.validate_template(TemplateURL=url)
            cfn.create_stack(StackName=name, TemplateURL=url, Capabilities=["CAPABILITY_NAMED_IAM"],
                Parameters=parameters or [], Tags=[{"Key": "LabId", "Value": self.lab}],
                OnFailure="ROLLBACK")
        print("Waiting for", name, "(EKS can take tens of minutes)", flush=True)
        try:
            cfn.get_waiter("stack_create_complete").wait(StackName=name, WaiterConfig={"Delay": 20, "MaxAttempts": 180})
        except Exception:
            events = cfn.describe_stack_events(StackName=name)["StackEvents"]
            failures = [{k: e.get(k) for k in ("LogicalResourceId", "ResourceStatus", "ResourceStatusReason")} for e in events if "FAILED" in e["ResourceStatus"]]
            save(suffix + "-failures.json", failures)
            print("Creation failed. Details saved in out/" + suffix + "-failures.json", flush=True)
            raise

    def deploy(self):
        print("Account:", self.account, "Regions:", self.args.primary, self.args.secondary,
              "Lab:", self.lab, "Paid EKS, EC2, ECS, KMS and audit resources will be created.", flush=True)
        self.ensure_bucket()
        credentials = self.secret(create=True)
        now = dt.datetime.now(dt.timezone.utc)
        main, shadow = generate(self.lab, self.account, self.args.primary, self.args.secondary,
            "maya@acme.example", (now + dt.timedelta(days=30)).isoformat(), (now - dt.timedelta(hours=36)).isoformat())
        self.deploy_stack(self.args.primary, "primary", main, [{"ParameterKey": "LabAuthKey", "ParameterValue": credentials["auth_key"]}])
        self.seed()
        self.deploy_stack(self.args.secondary, "secondary", shadow)
        self.kubernetes()
        self.manifest()
        print("Infrastructure and seed setup complete. Now run the probes command; this is not a scan result.")

    def seed(self):
        out = self.outputs()
        db = self.client("dynamodb")
        for ticket, customer, subject, status in [("451", "C-ACME", "Delivery delayed", "open"),
                                                  ("452", "C-NORTH", "Duplicate charge", "investigating")]:
            db.put_item(TableName=out["D01"], Item={k: {"S": v} for k, v in {
                "ticket_id": ticket, "customer": customer, "subject": subject, "status": status,
                "attachment": f"attachments/{ticket}.txt"}.items()})
        db.put_item(TableName=out["D02"], Item={"refund_id": {"S": "RF-001"}, "ticket_id": {"S": "451"},
            "amount_minor": {"N": "2500"}, "currency": {"S": "USD"}, "status": {"S": "draft"}})
        objects = [("BKT01", "attachments/451.txt", "Synthetic attachment 451", None),
            ("BKT01", "attachments/452.txt", "Synthetic attachment 452", None),
            ("BKT01", "sandbox/probe.txt", "Duplicate grant probe", None),
            ("BKT02", "reports/daily.csv", "record_id,amount_minor\nR-001,2500\n", "K01"),
            ("BKT02", "reports/restricted.csv", "record_id,classification\nX-001,restricted\n", "K02"),
            ("BKT02", "finance/payroll.csv", "employee_ref,amount_minor\nSYNTH-01,100000\n", "K02")]
        for bucket, key, body, kms in objects:
            kwargs = {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": out[kms]} if kms else {"ServerSideEncryption": "AES256"}
            self.client("s3").put_object(Bucket=out[bucket], Key=key, Body=body.encode(), **kwargs)
        credentials = self.secret()
        iam = self.client("iam")
        # Resume using the private AWS secret. If creation was interrupted
        # before persistence, refuse unknown keys rather than rotate them silently.
        existing = iam.list_access_keys(UserName=out["U01"])["AccessKeyMetadata"]
        known = {v["AccessKeyId"] for v in credentials["keys"].values()}
        if any(k["AccessKeyId"] not in known for k in existing):
            raise RuntimeError("Untracked lab IAM key exists. Inspect it; no key was deleted or disclosed.")
        for label, status in [("C01", "Active"), ("C02", "Inactive")]:
            if label not in credentials["keys"]:
                key = iam.create_access_key(UserName=out["U01"])["AccessKey"]
                credentials["keys"][label] = {k: key[k] for k in ("AccessKeyId", "SecretAccessKey")}
                self.put_secret(credentials)
            iam.update_access_key(UserName=out["U01"], AccessKeyId=credentials["keys"][label]["AccessKeyId"], Status=status)
        functions = self.client("lambda")
        name = self.lab + "-support-orchestrator"
        versions = {v.get("Description"): v["Version"] for page in functions.get_paginator("list_versions_by_function").paginate(FunctionName=name) for v in page["Versions"] if v["Version"] != "$LATEST"}
        for label, description in [("staging", "lab-v1"), ("prod", "lab-v2")]:
            if description not in versions:
                functions.update_function_configuration(FunctionName=name, Description=description)
                functions.get_waiter("function_updated_v2").wait(FunctionName=name)
                versions[description] = functions.publish_version(FunctionName=name, Description=description)["Version"]
            try:
                functions.get_alias(FunctionName=name, Name=label)
            except Exception as error:
                if not self.missing(error):
                    raise
                functions.create_alias(FunctionName=name, Name=label, FunctionVersion=versions[description])

    def kubernetes(self):
        import shutil
        if not shutil.which("kubectl") or not shutil.which("aws"):
            raise RuntimeError("kubectl and AWS CLI are required for the Kubernetes fixture. Resume deploy from CloudShell after installing kubectl.")
        out = self.outputs()
        OUT.mkdir(exist_ok=True, mode=0o700)
        kubeconfig = str(OUT / "kubeconfig")
        args = ["aws"] + (["--profile", self.args.profile] if self.args.profile else [])
        subprocess.run(args + ["eks", "update-kubeconfig", "--region", self.args.primary, "--name", out["EKS"], "--kubeconfig", kubeconfig], check=True, stdout=subprocess.DEVNULL)
        shell = f"""set -eu
creds=$(aws sts assume-role --region {self.args.primary} --role-arn {out['R06']} --role-session-name acme-reconcile --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)
read AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<EOF
$creds
EOF
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
unset creds
echo 'E04 daily report'
aws s3api get-object --region {self.args.primary} --bucket {out['BKT02']} --key reports/daily.csv /tmp/daily.csv
echo 'E05 restricted report; expected AccessDenied'
if aws s3api get-object --region {self.args.primary} --bucket {out['BKT02']} --key reports/restricted.csv /tmp/restricted.csv 2>/tmp/denial; then echo UNEXPECTED_ALLOW; exit 1; fi
cat /tmp/denial
grep -q '(AccessDenied)' /tmp/denial || exit 1
echo 'E08 delete; expected AccessDenied'
if aws s3api delete-object --region {self.args.primary} --bucket {out['BKT02']} --key reports/daily.csv 2>/tmp/denial; then echo UNEXPECTED_ALLOW; exit 1; fi
cat /tmp/denial
grep -q '(AccessDenied)' /tmp/denial || exit 1
echo EKS_PROBES_PASSED
"""
        pod = {"restartPolicy": "Never", "serviceAccountName": "reconcile-sa", "containers": [{"name": "reconcile",
            "image": "public.ecr.aws/aws-cli/aws-cli:latest", "command": ["/bin/sh", "-c", shell]}]}
        resources = {"apiVersion": "v1", "kind": "List", "items": [
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "operations", "labels": {"lab": self.lab}}},
            {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "reconcile-sa", "namespace": "operations"}},
            {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": "reconcile", "namespace": "operations", "labels": {"lab": self.lab}},
             "spec": {"schedule": "0 2 * * *", "concurrencyPolicy": "Forbid", "successfulJobsHistoryLimit": 1, "failedJobsHistoryLimit": 2,
                      "jobTemplate": {"spec": {"backoffLimit": 0, "activeDeadlineSeconds": 300, "template": {"spec": pod}}}}}]}
        path = save("kubernetes.json", resources)
        subprocess.run(["kubectl", "--kubeconfig", kubeconfig, "apply", "-f", str(path)], check=True)

    def manifest(self):
        out = self.outputs()
        iam = self.client("iam")
        roles = {}
        for n in range(1, 13):
            label = f"R{n:02}"
            role = iam.get_role(RoleName=out[label].split("/")[-1])["Role"]
            roles[label] = {k: role.get(k) for k in ("Arn", "RoleId", "RoleName", "CreateDate", "Tags")}
        keys = iam.list_access_keys(UserName=out["U01"])["AccessKeyMetadata"]
        secondary = self.stack(self.args.secondary, "secondary")
        manifest = {"basis": "operator deployment manifest; NOT AuthSec discovery evidence", "account": self.account,
            "lab_id": self.lab, "regions": [self.args.primary, self.args.secondary], "created_by": self.actor,
            "captured_at": dt.datetime.now(dt.timezone.utc), "outputs": out, "roles": roles,
            "keys_metadata": keys, "secondary_outputs": secondary.get("Outputs", []) if secondary else [],
            "expected_seeded_counts": {"roles": 12, "iam_users": 1, "iam_keys": 2, "lambda_functions": 5,
                "ecs_task_definitions": 1, "eks_cronjobs": 1, "shadow_instances": 1, "business_data_resources": 8},
            "additional_infrastructure": ["EKS cluster/node roles", "EKS worker instances", "deployment credential secret", "audit and deployment buckets", "CloudTrail", "networking", "service-linked roles"],
            "not_automated_in_authsec": ["business-agent registration", "Priya/Maya ownership attestations", "review history", "GP01-GP05 governance policies"],
            "deferred": ["AgentCore/model inference (B)", "cross-account (C)", "Organizations/Identity Center (D)"]}
        path = save("manifest.json", manifest)
        print("Shareable deployment manifest:", path, "(no secret values)")

    def probes(self):
        out = self.outputs()
        private = self.secret()
        claims = {"sub": "H02", "customer": "C-ACME", "exp": int(time.time()) + 900}
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        signature = hmac.new(private["auth_key"].encode(), payload.encode(), hashlib.sha256).hexdigest()
        token = payload + "." + signature
        requests = [("E01", "support-app", {"token": token, "ticket_id": "451"}, "allowed"),
            ("E02", "support-app", {"token": token, "ticket_id": "452"}, "denied"),
            ("E03", "refund-tools", {}, "allowed"),
            ("E06", "ticket-tools", {"operation": "financeProbe"}, "aws_error"),
            ("E07", "ticket-tools", {"operation": "boundaryProbe"}, "aws_error"),
            ("DuplicateBaseline", "ticket-tools", {"operation": "duplicateProbe"}, "allowed")]
        results = []
        for label, function, event, expected in requests:
            response = self.client("lambda").invoke(FunctionName=self.lab + "-" + function, Payload=json.dumps(event).encode())
            body = json.loads(response["Payload"].read())
            passed = not response.get("FunctionError") and body.get("status") == expected
            if expected == "aws_error":
                passed = passed and body.get("code") in ("AccessDenied", "AccessDeniedException")
            row = {"fixture": label, "expected": expected, "passed": passed, "response": body,
                "invocation_request_id": response["ResponseMetadata"]["RequestId"], "observed_at": dt.datetime.now(dt.timezone.utc)}
            results.append(row)
            print(label, "PASS" if passed else "FAIL", flush=True)
        save("probe-results.json", results)
        # A one-shot job supplies real Pod Identity / STS / S3 evidence.
        kubeconfig = str(OUT / "kubeconfig")
        eks_passed = False
        if Path(kubeconfig).exists():
            name = "reconcile-probe-" + str(int(time.time()))
            base = ["kubectl", "--kubeconfig", kubeconfig, "-n", "operations"]
            subprocess.run(base + ["create", "job", name, "--from=cronjob/reconcile"], check=True)
            wait = subprocess.run(base + ["wait", "--for=condition=complete", "job/" + name, "--timeout=360s"], check=False)
            logs = subprocess.run(base + ["logs", "job/" + name, "--all-containers=true"], capture_output=True, text=True)
            (OUT / "eks-probe.log").write_text(logs.stdout + logs.stderr)
            eks_passed = wait.returncode == 0 and logs.returncode == 0 and "EKS_PROBES_PASSED" in logs.stdout
            print("EKS job:", "PASS" if eks_passed else "FAILED or timed out; inspect out/eks-probe.log")
        else:
            print("EKS probes not run: resume deploy to configure Kubernetes first.")
        if not all(x["passed"] for x in results) or not eks_passed:
            raise RuntimeError("One or more Lambda/EKS probes failed or were not run. Inspect out/probe-results.json and out/eks-probe.log; no inferred pass.")

    def empty_bucket(self, bucket):
        self.check_bucket(bucket)
        s3 = self.client("s3")
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
            if objects:
                result = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
                if result.get("Errors"):
                    raise RuntimeError("Could not empty lab bucket: " + bucket)

    def destroy(self):
        # Only tagged, exact-name lab stacks/buckets/user/secret are touched.
        primary = self.stack(self.args.primary, "primary")
        if primary:
            out = {x["OutputKey"]: x["OutputValue"] for x in primary.get("Outputs", [])}
            # Prevent new CloudTrail objects appearing while the bucket empties.
            try:
                self.client("cloudtrail").stop_logging(Name=self.lab + "-trail")
            except Exception as error:
                if not self.missing(error) and "TrailNotFound" not in str(error):
                    raise
            user = self.lab + "-legacy-export-bot"
            iam = self.client("iam")
            try:
                tags = iam.list_user_tags(UserName=user)["Tags"]
                if not any(t["Key"] == "LabId" and t["Value"] == self.lab for t in tags):
                    raise RuntimeError("Lab user ownership tag mismatch")
                for key in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
                    iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
            except Exception as error:
                if not self.missing(error):
                    raise
            for suffix in ("attachments", "finance", "audit"):
                bucket = f"{self.lab}-{self.account}-{suffix}"
                try:
                    self.empty_bucket(bucket)
                except Exception as error:
                    if not self.missing(error):
                        raise
        for region, suffix in [(self.args.secondary, "secondary"), (self.args.primary, "primary")]:
            stack = self.stack(region, suffix)
            if not stack:
                continue
            print("Deleting", stack["StackName"], flush=True)
            cfn = self.client("cloudformation", region)
            cfn.delete_stack(StackName=stack["StackId"])
            cfn.get_waiter("stack_delete_complete").wait(StackName=stack["StackId"], WaiterConfig={"Delay": 20, "MaxAttempts": 180})
        try:
            self.secret()  # validates ownership before deleting the private store
            self.client("secretsmanager").delete_secret(SecretId=self.secret_name, ForceDeleteWithoutRecovery=True)
        except Exception as error:
            if not self.missing(error):
                raise
        try:
            self.empty_bucket(self.bucket)
            self.client("s3").delete_bucket(Bucket=self.bucket)
        except Exception as error:
            if not self.missing(error):
                raise
        print("Lab stacks removed. KMS keys enter their 7-day deletion window. Keep manifests/probe logs for comparison.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["deploy", "seed", "manifest", "probes", "destroy"])
    parser.add_argument("--account-id", required=True, help="Exact 12-digit SANDBOX account ID; checked against STS")
    parser.add_argument("--lab-id", default="acme-iga-01")
    parser.add_argument("--primary", default="us-east-1")
    parser.add_argument("--secondary", default="us-west-2")
    parser.add_argument("--profile", help="Optional local AWS CLI profile; omit in CloudShell")
    args = parser.parse_args()
    if not re.fullmatch(r"\d{12}", args.account_id) or not re.fullmatch(r"[a-z][a-z0-9-]{2,19}", args.lab_id):
        parser.error("Use a 12-digit account ID and a 3-20 character lowercase lab ID")
    if args.primary == args.secondary:
        parser.error("Exercise A needs two different regions")
    try:
        getattr(Lab(args), args.command)()
    except Exception as error:
        # Never print SDK request parameters or the private credential payload.
        print("STOP:", str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
