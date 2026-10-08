# Runbook: Stage A manual self-test of the AWS enforcement stack

**Spec:** `.claude/specs/SPEC-iga-phase3-policy.md` §3.6 (enforcement stack,
permissions, self-test), §13.1 Stage A exit ("enforcement template written; its
§3.6 self-test run by hand in the lab account, including the
`DeleteRolePermissionsBoundary` condition-key check"), §14.1 step 0, §14.4.

**Template:** `internal/awsdiscovery/authsec-aws-enforcement-role.yaml`,
`TemplateVersion` `2026-10-07` (`awsdiscovery.EnforcementTemplateVersion`).

**Who:** one operator, by hand, in the **dedicated lab account only**. Never a
customer account. Nothing here uses AuthSec's backend: the operator plays
AuthSec's principal, so the result proves what AWS does with the template,
independently of AuthSec's code.

**Output:** a self-test transcript appended to `.claude/specs/P3-EVIDENCE.md`
(§14.4): date, operator, lab account id, template sha256, and for every step
the command, the AWS request id, and the result. J3 (direct enforcement) must
not ship until this passes (§14.1 step 0).

---

## 0. Why this is done by hand

AuthSec's tests simulate the template's policy (`internal/awsenforce/enforcetest`);
a simulation cannot prove two AWS behaviours the design depends on:

1. **`iam:PermissionsBoundary` on `DeleteRolePermissionsBoundary`.** The
   `DetachOnlyAuthSecBoundaries` statement allows the detach only when the
   boundary **currently attached** is an `/authsec/` policy. The request itself
   names no boundary, so the key must come from the role's current state. If AWS
   does not supply it, `ArnLike` on a missing key is false and **every** detach
   is denied (undo and "remove AuthSec control" could never work); if AWS
   supplies it differently, a customer's own boundary could be removed. Steps 6
   and 8 below settle this.
2. **The attach condition actually restricts** (`refuses_foreign_boundary`):
   `PutRolePermissionsBoundary` with a non-`/authsec/` policy must be refused.

---

## 1. Prerequisites

| Item | Value used below |
|---|---|
| Lab account | `$LAB` (12 digits) |
| Admin profile (deploys the stack, creates fixtures, inspects) | `lab-admin` |
| Operator principal that will assume the enforcement role (plays AuthSec) | `$OPERATOR_ARN`, e.g. `arn:aws:iam::$LAB:role/LabOperator`; it needs `sts:AssumeRole` on `arn:aws:iam::$LAB:role/AuthSecEnforcement-*` |
| Region | `us-east-1` |
| AWS CLI | v2, `jq` |
| ExternalId (lab only; any 32+ char value) | `$EXT`, e.g. `enf$(openssl rand -hex 16).lab` |
| Name suffix | `lab01` |

```bash
export LAB=123456789012 AWS_REGION=us-east-1 SUFFIX=lab01
export OPERATOR_ARN=arn:aws:iam::$LAB:role/LabOperator
export EXT="enf$(openssl rand -hex 16).stagea"
export TPL=internal/awsdiscovery/authsec-aws-enforcement-role.yaml
sha256sum "$TPL"            # record in the transcript
```

Policy documents used by the probes:

```bash
cat > /tmp/deny-all-v1.json <<'EOF'
{"Version":"2012-10-17","Statement":[{"Sid":"AuthSecSelfTestV1","Effect":"Deny","Action":"*","Resource":"*"}]}
EOF
sed 's/V1/V2/' /tmp/deny-all-v1.json > /tmp/deny-all-v2.json
```

## 2. Deploy the stack and the fixtures (as `lab-admin`)

Deploy by hand (no `CallbackTopicArn`, so no custom resource is created):

```bash
aws cloudformation deploy --profile lab-admin \
  --template-file "$TPL" --stack-name AuthSec-Enforcement-$SUFFIX \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides AuthSecPrincipalArn=$OPERATOR_ARN ExternalId=$EXT NameSuffix=$SUFFIX
aws cloudformation describe-stacks --profile lab-admin --stack-name AuthSec-Enforcement-$SUFFIX \
  --query 'Stacks[0].Outputs' --output table
```

**Expect:** `CREATE_COMPLETE`; outputs `RoleArn`
(`.../role/AuthSecEnforcement-lab01`), `SelfTestRoleArn`
(`.../role/AuthSecEnforcementSelfTest-lab01`), `TemplateVersion 2026-10-07`.

Fixtures for the negative probes (all inert: trust only the account, no
permissions):

```bash
TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'$LAB':root"},"Action":"sts:AssumeRole"}]}'
aws iam create-role --profile lab-admin --role-name LabEnfTaggedProtected --assume-role-policy-document "$TRUST" \
  --tags Key=authsec:protected,Value=true
aws iam create-role --profile lab-admin --role-name payments-reader --assume-role-policy-document "$TRUST" \
  --tags Key=ManagedBy,Value=AuthSec                 # A11: customer name, AuthSec tag
aws iam create-role --profile lab-admin --role-name AuthSecLookalike --assume-role-policy-document "$TRUST"
                                                      # AuthSec-like NAME, no tag: must NOT be protected
aws iam create-policy --profile lab-admin --policy-name LabCustomerBoundary \
  --policy-document file:///tmp/deny-all-v1.json      # a customer boundary, path /
export CUSTOMER_BOUNDARY=arn:aws:iam::$LAB:policy/LabCustomerBoundary
aws iam get-role --profile lab-admin --role-name AWSServiceRoleForSupport \
  --query Role.Arn                                   # a service-linked role (exists in every account)
```

## 3. Become the enforcement role (the `assume` capability)

```bash
CREDS=$(aws sts assume-role --role-arn arn:aws:iam::$LAB:role/AuthSecEnforcement-$SUFFIX \
  --role-session-name authsec-enforce-selftest-stagea01 --external-id "$EXT" --duration-seconds 900)
aws configure set aws_access_key_id     "$(jq -r .Credentials.AccessKeyId <<<"$CREDS")"     --profile enf
aws configure set aws_secret_access_key "$(jq -r .Credentials.SecretAccessKey <<<"$CREDS")" --profile enf
aws configure set aws_session_token     "$(jq -r .Credentials.SessionToken <<<"$CREDS")"    --profile enf
aws sts get-caller-identity --profile enf
```

**Expect:** `Account` = `$LAB`, `Arn` ends `assumed-role/AuthSecEnforcement-lab01/authsec-enforce-selftest-stagea01`.
**Negative:** the same `assume-role` with `--external-id wrong-wrong-wrong-wrong-wrong-wrong` → `AccessDenied`.

## 4. The §3.6 probes, in order (as `enf`)

Record each command's request id (`--debug 2>&1 | grep -i x-amzn-requestid`,
or from CloudTrail afterwards).

| # | Capability | Command (`--profile enf`) | Expected |
|---|---|---|---|
| 4.1 | `create_policy` | `aws iam create-policy --path /authsec/ --policy-name AuthSecSelfTest-stagea01 --policy-document file:///tmp/deny-all-v1.json --tags Key=authsec:managed-by,Value=authsec Key=authsec:selftest,Value=stagea01` | **ok**; `Arn` = `arn:aws:iam::$LAB:policy/authsec/AuthSecSelfTest-stagea01` |
| 4.2 | `version_management` (1/2) | `aws iam create-policy-version --policy-arn $P --policy-document file:///tmp/deny-all-v2.json --set-as-default` | **ok**; `VersionId v2`, default |
| 4.3 | `version_management` (2/2) | `aws iam delete-policy-version --policy-arn $P --version-id v1` | **ok** |
| 4.4 | `attach_boundary` | `aws iam put-role-permissions-boundary --role-name AuthSecEnforcementSelfTest-$SUFFIX --permissions-boundary $P` | **ok**; `aws iam get-role --profile lab-admin --role-name AuthSecEnforcementSelfTest-$SUFFIX --query Role.PermissionsBoundary` shows `$P` |
| 4.5 | `refuses_foreign_boundary` | `aws iam put-role-permissions-boundary --role-name AuthSecEnforcementSelfTest-$SUFFIX --permissions-boundary arn:aws:iam::aws:policy/ReadOnlyAccess` | **AccessDenied** ("no identity-based policy allows"). The boundary is still `$P` (check with `lab-admin`). **If this succeeds the template is defective: stop, record, revise the template before J3.** |
| 4.6 | `detach_boundary` | `aws iam delete-role-permissions-boundary --role-name AuthSecEnforcementSelfTest-$SUFFIX` | **ok**; `get-role` shows no `PermissionsBoundary`. This is the **positive** half of the condition-key check: the detach of an `/authsec/` boundary is allowed only if AWS supplied `iam:PermissionsBoundary` = `$P` |
| 4.7 | `delete_policy` | `aws iam delete-policy --policy-arn $P` | **ok** (`v1` was deleted in 4.3, and the policy is no longer attached) |

(`export P=arn:aws:iam::$LAB:policy/authsec/AuthSecSelfTest-stagea01` after 4.1.)

## 5. The `DeleteRolePermissionsBoundary` condition-key check (the Stage A question)

4.6 shows the key is **supplied** when the attached boundary is an AuthSec one.
This step shows it **restricts**: with a customer boundary attached, the detach
must be refused.

```bash
# as lab-admin: give the self-test role a CUSTOMER boundary (not under /authsec/)
aws iam put-role-permissions-boundary --profile lab-admin \
  --role-name AuthSecEnforcementSelfTest-$SUFFIX --permissions-boundary $CUSTOMER_BOUNDARY
# as enf: try to remove it
aws iam delete-role-permissions-boundary --profile enf --role-name AuthSecEnforcementSelfTest-$SUFFIX
# as lab-admin: confirm it is still there, then clean up
aws iam get-role --profile lab-admin --role-name AuthSecEnforcementSelfTest-$SUFFIX --query Role.PermissionsBoundary
aws iam delete-role-permissions-boundary --profile lab-admin --role-name AuthSecEnforcementSelfTest-$SUFFIX
```

**Expect:** the `enf` call fails with **`AccessDenied`** and the customer
boundary is still attached.

**Read the result:**

| 4.6 | 5 | Meaning | Action |
|---|---|---|---|
| ok | AccessDenied | AWS supplies `iam:PermissionsBoundary` for `DeleteRolePermissionsBoundary` from the attached boundary, and the condition restricts | **Pass.** Record. |
| AccessDenied | AccessDenied | The key is not supplied (or not as expected): every detach is denied | **Fail.** J3 must not ship; undo/remove-control cannot work. Revise `DetachOnlyAuthSecBoundaries` (e.g. tag-based detach on roles AuthSec tagged) and repeat this runbook |
| ok | ok | The condition does not restrict: a customer boundary can be removed | **Fail.** Revise the template before J3 |

CloudTrail (as `lab-admin`, a few minutes later) shows each call with
`userIdentity.sessionContext.sessionIssuer.userName = AuthSecEnforcement-lab01`,
the session name `authsec-enforce-selftest-stagea01`, and for the denied calls
`errorCode = AccessDenied`:

```bash
aws cloudtrail lookup-events --profile lab-admin \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteRolePermissionsBoundary \
  --max-results 10 --query 'Events[].CloudTrailEvent' --output text | jq '{eventTime, errorCode, requestID, userIdentity: .userIdentity.arn}'
```

The IAM policy simulator is **not** a substitute: it evaluates whatever context
it is given and does not show what AWS supplies at request time.

## 6. Forced attempts AWS must refuse (A11 and §3.5; as `enf`)

Re-create a test policy first (`aws iam create-policy --path /authsec/ --policy-name AuthSecSelfTest-stagea02 --policy-document file:///tmp/deny-all-v1.json`; `export P2=...`).

| Attempt | Command (`--profile enf`) | Expected |
|---|---|---|
| Service-linked role (path `/aws-service-role/`) | `aws iam put-role-permissions-boundary --role-name AWSServiceRoleForSupport --permissions-boundary $P2` | AccessDenied, **explicit deny** (`ProtectServiceRoles`) |
| `ManagedBy=AuthSec` role with a customer name | `... --role-name payments-reader --permissions-boundary $P2` | AccessDenied, explicit deny (`ProtectAuthSecRoles`) |
| AuthSec's own enforcement role | `... --role-name AuthSecEnforcement-$SUFFIX --permissions-boundary $P2` | AccessDenied, explicit deny |
| `authsec:protected=true` role | `... --role-name LabEnfTaggedProtected --permissions-boundary $P2` | AccessDenied, explicit deny (`ProtectTaggedRoles`) |
| AuthSec-like NAME, no tag | `... --role-name AuthSecLookalike --permissions-boundary $P2` | **ok** (protection is never by name); then `delete-role-permissions-boundary --role-name AuthSecLookalike` → ok |
| Customer policy write | `aws iam create-policy-version --policy-arn $CUSTOMER_BOUNDARY --policy-document file:///tmp/deny-all-v2.json` | AccessDenied |
| Policy outside `/authsec/` | `aws iam create-policy --policy-name NotAuthSec --policy-document file:///tmp/deny-all-v1.json` | AccessDenied |
| Any read | `aws iam get-role --role-name AuthSecLookalike` | AccessDenied (the role reads nothing) |
| Role chaining | `aws sts assume-role --role-arn $OPERATOR_ARN --role-session-name x` | AccessDenied |

Then `aws iam delete-policy --profile enf --policy-arn $P2` → ok.

## 7. Optional: the same self-test through AuthSec

On a lab AuthSec deployment with `IGA_POLICY=on` and the lab account connected:
`POST /authsec/discovery/aws/connectors/:id/enforcement/sessions` (deploy with
the returned `stack_parameters`, or open `quick_create_url`), then either let
the callback bind it or `POST .../enforcement` with both role ARNs, then
`GET .../enforcement`. **Expect** `state: verified` and every capability `ok`,
including `refuses_foreign_boundary` (§14.1 step 0). Removing
`iam:DeleteRolePermissionsBoundary` from the stack and `POST .../verify` must
give `state: partial` with `detach_boundary: denied` (A22).

## 8. Expected outcome, per capability

| Capability | Probe | Expected status |
|---|---|---|
| `assume` | §3 | ok |
| `create_policy` | 4.1 | ok |
| `version_management` | 4.2 + 4.3 | ok |
| `attach_boundary` | 4.4 | ok |
| `refuses_foreign_boundary` | 4.5 | ok (= AWS returned AccessDenied) |
| `detach_boundary` | 4.6 | ok |
| `delete_policy` | 4.7 | ok |
| condition key on detach | §5 | AccessDenied with a customer boundary attached |

## 9. Clean up (as `lab-admin`)

```bash
aws iam delete-role-permissions-boundary --role-name AuthSecEnforcementSelfTest-$SUFFIX 2>/dev/null
for r in LabEnfTaggedProtected payments-reader AuthSecLookalike; do aws iam delete-role --profile lab-admin --role-name $r; done
aws iam delete-policy --profile lab-admin --policy-arn $CUSTOMER_BOUNDARY
aws iam list-policies --profile lab-admin --scope Local --path-prefix /authsec/ --query 'Policies[].Arn'   # expect []
aws cloudformation delete-stack --profile lab-admin --stack-name AuthSec-Enforcement-$SUFFIX
aws configure set aws_session_token "" --profile enf
```

## 10. Transcript template (append to `.claude/specs/P3-EVIDENCE.md`)

```
## Stage A — enforcement self-test (manual), <date>
operator: <name>          lab account: <id>          region: us-east-1
template: internal/awsdiscovery/authsec-aws-enforcement-role.yaml  version 2026-10-07  sha256 <...>
backend commit: <sha>
| step | command (abridged) | request id | result | expected | pass |
| 3   | sts assume-role (ExternalId)        | ... | ok           | ok           | y |
| 4.1 | iam create-policy /authsec/         | ... | ok           | ok           | y |
...
| 5   | delete-role-permissions-boundary (customer boundary) | ... | AccessDenied | AccessDenied | y |
| 6.x | forced attempts                     | ... | ...          | ...          | y |
CloudTrail event ids: ...
verdict: PASS / FAIL (and the template revision if FAIL)
```
