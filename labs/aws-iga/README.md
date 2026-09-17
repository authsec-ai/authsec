# AWS IGA lab — Exercise A

Creates a synthetic, single-account estate in `us-east-1` and `us-west-2` for
the [AWS lab brief](../../../.claude/specs/AuthSec-AWS-Discovery-Lab-Team-Brief.md).
This is a deployment kit, not proof that AuthSec discovers its contents correctly.
Local Python compilation and CloudFormation linting have passed. Deployment and
runtime probes have **not** been verified in a real AWS account yet.

## Starting with only an AWS account

1. Use a dedicated sandbox account. Sign in as an IAM/Identity Center administrator;
   the launcher refuses the root identity. AWS documents administrator setup at
   https://docs.aws.amazon.com/accounts/latest/reference/getting-started-step4.html.
   You do not need to create access keys for the launcher.
2. Open AWS CloudShell in `us-east-1`. It provides an authenticated AWS CLI session:
   https://docs.aws.amazon.com/cloudshell/latest/userguide/welcome.html.
3. Upload `aws-iga-lab.zip` through **Actions → Upload file**, then run:

```bash
unzip aws-iga-lab.zip
cd aws-iga-lab
python3 lab.py deploy --account-id YOUR_12_DIGIT_SANDBOX_ACCOUNT_ID
python3 lab.py probes --account-id YOUR_12_DIGIT_SANDBOX_ACCOUNT_ID
```

Replace the account placeholder with the sandbox account you intended to use.
The launcher checks it against STS before changing anything. CloudShell must have
Python, boto3, AWS CLI and kubectl. Account policies/quotas can still prevent
creation even for an administrator. EKS creation can take tens of minutes.

**This creates paid resources**, including an EKS cluster and node, a Fargate task,
an EC2 instance, public IPv4 addresses, KMS keys, Secrets Manager secrets and
CloudTrail data events. There is no automatic expiry or spending cap. `ExpiresAt`
is synthetic governance evidence, not a teardown schedule. Review the generated
templates and run `destroy` when finished. EKS pricing: https://aws.amazon.com/eks/pricing/.

## What it creates

| Fixture | Seeded baseline |
|---|---|
| Identity | R01–R12, U01, active C01 and inactive C02 |
| Compute | Five Lambda functions; one ECS task definition and service; an EKS CronJob and Pod Identity association; one secondary-region EC2 instance |
| Relationships | Shared tool role, role-assumption chains, task/execution roles and instance profile |
| Data | Two S3 buckets, two DynamoDB tables, two KMS keys and two synthetic secrets |
| Access cases | Duplicate grants, permission boundary, principal-tag condition, resource-policy denies, KMS restriction |
| Activity | Scripted Lambda/ECS/EKS requests; CloudTrail management and selected data events; deliberate absence of D02 data-event coverage |

EKS infrastructure roles, worker instances, audit/deployment buckets and the private
deployment secret are additional infrastructure. Use `out/manifest.json` to
separate them from the business fixtures. Names have a lab prefix to reduce
collisions. Role IDs come from AWS after creation, not from invented identifiers.
The R05→R06 trust and identity policies permit `sts:TagSession` for Pod Identity's
transitive tags, following https://docs.aws.amazon.com/eks/latest/userguide/pod-id-abac.html.

The functions are scripted application/tool fixtures. They do not invoke a model
or create a native Bedrock agent. H02 is a signed synthetic application identity;
AWS IAM also authenticates the Lambda invocation. Priya/Maya ownership, confirmed
business-agent classification, certification history and GP01–GP05 remain explicit
AuthSec-side work. Extensions B–D (native AI, cross-account, organization/workforce)
are not part of this single-account kit.

## Read the results

* `out/manifest.json`: shareable expected inventory and AWS IDs; no secret values.
* `out/probe-results.json`: E01/E02/E03/E06/E07 and duplicate-grant baseline,
  including actual AWS error codes and request IDs.
* `out/eks-probe.log`: E04/E05/E08. A timeout, missing job or wrong error code fails
  the command; a generic error is not treated as an expected deny.
* E09 runs in EC2 user data. Its success is not asserted by `probes`; verify the
  instance boot logs or matching CloudTrail evidence separately.

The two lab access-key secrets and fixture signing key stay in a tagged AWS
Secrets Manager deployment secret. They are not included in the shareable
manifest. The signing key also exists in the lab application's Lambda environment.
Do not use real customer credentials or data in this estate.

## Connect AuthSec and validate Phase 1

Use the intended AuthSec development workspace's AWS integration onboarding flow
to obtain its discovery-role template, exact principal and generated external ID.
Do not substitute this kit's administrator credentials or reuse another workspace's
external ID. The existing reader template source is
`internal/awsdiscovery/authsec-aws-discovery-role.yaml` in the backend repository.

Create that reader role in this sandbox and register its ARN in AuthSec. Select
**both regions**, verify and scan. Compare the API results and displayed coverage
against the manifest. EKS association evidence does not prove that AuthSec has
inventoried the actual CronJob. Policy-referenced resources are not full resource
inventory. Service-last-accessed rows are not CloudTrail request evidence.

An initial successful scan is only the baseline. Follow the brief's mutation and
failure-injection exercises separately: unchanged rescan, P03 detachment while P04
persists, deletion of the legacy Lambda, removal of the Team tag, role recreation,
denied scope, and worker interruption/recovery. Record before/after IDs, generations,
coverage and relationships. Do not run these destructive lab experiments against
an unrelated person's integration or a shared customer account. This kit does not
automatically perform those mutations or claim the Phase 1 gates have passed.

## Resume and remove

Re-running `deploy` resumes completed stacks and idempotent seed operations. It
does not update an existing stack's template. A rolled-back or failed stack must
be inspected before cleanup/redeployment; failure events are written to `out/`.
Always reuse the same account, lab ID and regions. Keep the local directory between
commands so probes can use its isolated kubeconfig.

```bash
python3 lab.py manifest --account-id YOUR_12_DIGIT_SANDBOX_ACCOUNT_ID
python3 lab.py destroy --account-id YOUR_12_DIGIT_SANDBOX_ACCOUNT_ID
```

Destroy removes matching, tagged lab stacks, empties their data buckets and removes
the lab user's keys. It refuses resources with mismatched ownership tags. The
secondary stack is removed before its primary role. KMS keys enter a seven-day
deletion window. Check CloudFormation for failed deletions and the AWS billing
console afterwards; asynchronous log delivery can require cleanup to be retried.
An independently created AuthSec reader role/integration is not removed by this
command. Disconnect and remove it separately when no longer needed.

## Local review without AWS access

```bash
python3 templates.py out
python3 -m py_compile lab.py templates.py runtime.py
cfn-lint out/primary.json out/secondary.json
```

The template generator uses account `123456789012` for offline inspection only.
`deploy` regenerates templates for the verified account. Schema validation cannot
prove IAM propagation, quotas, container compatibility or live access outcomes.
