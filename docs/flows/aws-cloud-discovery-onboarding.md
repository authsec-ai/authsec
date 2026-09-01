# AWS cloud discovery — onboarding and the IAM identity foundation

How AuthSec connects to a customer's AWS account, what that connection is
allowed to do, what it reads, and what is stored.

This is ticket [1] of AWS discovery, in two halves:

1. **Onboarding** — establish the agentless read-only connection and write the
   `cloud_connector` row everything else resolves against.
2. **The identity foundation** — discover IAM roles, users and access keys into
   `cloud_identity` and `cloud_secret`, and retrieve the policy documents that
   ticket [2] parses.

**Nothing here asserts that anything is an AI agent.** `cloud_identity` is the
candidate pool — no cloud has a list-agents API. Classification is a later
ticket and writes `discovered_agents`, which points at these rows.

Related: `docs/connectors-design-review.md` for why discovery does not sit on
the connector broker.

---

## The flow

```
  console                    AuthSec                     customer AWS account
     │                          │                                  │
     │  GET  /discovery/aws/onboarding                             │
     ├─────────────────────────▶│                                  │
     │  ExternalId + template   │                                  │
     │◀─────────────────────────┤                                  │
     │                          │                                  │
     │        customer deploys the CloudFormation stack ──────────▶│
     │                          │              creates ONE IAM role│
     │◀───────────────────────────────────── RoleArn output ───────┤
     │                          │                                  │
     │  POST /discovery/aws/connectors {role_arn, external_id, regions}
     ├─────────────────────────▶│                                  │
     │                          │  sts:AssumeRole + GetCallerIdentity
     │                          ├─────────────────────────────────▶│
     │                          │◀──── account id, assumed-role ARN┤
     │                          │                                  │
     │      201 cloud_connector │  ExternalId → secrets store      │
     │◀─────────────────────────┤  row        → cloud_connector    │
```

Three properties fall out of this shape and are worth stating:

- **No customer key exists.** The customer creates a role, not a user. AuthSec
  holds no long-lived credential for their account, so there is nothing in an
  AuthSec backup that grants access to it.
- **The account id comes from AWS, never from the request.** It is the
  connector's identity (`scope_id`), and a caller-supplied one could disagree
  with the role it actually points at.
- **Nothing is written until the connection is proven.** A role that cannot be
  assumed leaves no row and no stored secret. A connector that never worked and
  one that has stopped working look identical in a console, and only the second
  is an incident.

---

## What the customer runs

One CloudFormation stack, from
`internal/awsdiscovery/authsec-aws-discovery-role.yaml`. It creates a single
IAM role and nothing else. The template is embedded in the binary rather than
hosted, so the template a customer runs is exactly the one their AuthSec build
expects, and an air-gapped deployment needs no outbound fetch to onboard.

Two parameters, both copied from the console:

| Parameter | What it is |
|---|---|
| `AuthSecPrincipalArn` | The AuthSec IAM principal permitted to assume the role. Deployment configuration (`AUTHSEC_AWS_DISCOVERY_PRINCIPAL_ARN`), the same for every customer. |
| `ExternalId` | Per-connection, AuthSec-generated. Secret. `NoEcho` in the template. |

### Why the ExternalId matters

It is the AWS answer to the confused-deputy problem. AuthSec assumes roles in
many customer accounts; without the condition, any customer who learned another
customer's role ARN could ask AuthSec to assume it.

AuthSec's ExternalIds are `<nonce>.<hmac>`, where the HMAC covers the workspace
the id was issued to. That closes a second hole the plain-random version leaves
open: role ARNs and ExternalIds travel through consoles, tickets and
screenshots, and without the binding, a workspace that learned another
customer's pair could submit it and onboard someone else's AWS account into
their own inventory. An id issued to workspace A fails verification under
workspace B. No server-side state is needed.

---

## Permissions

### Baseline

`arn:${AWS::Partition}:iam::aws:policy/SecurityAudit` — the AWS-managed
read-only policy for exactly this kind of tool. It grants metadata reads across
the account and does not grant reading secret values, SSM parameter values or
decryption keys.

### Additional reads, and the operation each is for

Granted as an inline policy on top of the baseline. Every action is a `List`,
`Describe`, `Get` or `Generate` on metadata.

| Action | Required for | Ticket |
|---|---|---|
| `sts:GetCallerIdentity` | Proving the connection during onboarding and re-verification | [1] |
| `iam:GetAccountAuthorizationDetails` | Every role, user, group, instance profile and attached/inline policy document in one paginated call | [1], [2] |
| `iam:GenerateCredentialReport`, `iam:GetCredentialReport` | All users and their access keys, with creation and last-used dates, in one call | [1] |
| `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails` | Per-service last-used per principal, without paying for CloudTrail volume | [5], [6] |
| `bedrock:ListAgents`, `bedrock:GetAgent` | Bedrock Agents; the execution role and foundation model come from the detail call | [3] |
| `bedrock-agentcore:ListAgentRuntimes`, `GetAgentRuntime` | AgentCore runtimes and the identity each runs as | [3] |
| `bedrock-agentcore:ListWorkloadIdentities` | AgentCore workload identities, written as `cloud_identity` rows | [3] |
| `bedrock-agentcore:ListOauth2CredentialProviders`, `ListApiKeyCredentialProviders` | AgentCore credential providers, written as `cloud_secret` rows. **List only** — there is deliberately no `Get`, because that is where a value would be | [3] |
| `bedrock-agentcore:ListGateways`, `ListGatewayTargets` | What an AgentCore agent can reach | [3] |
| `eks:ListClusters`, `eks:DescribeCluster` | The cluster OIDC issuer, which is what tells two clusters apart in a multi-cluster estate | [5] |
| `eks:ListPodIdentityAssociations`, `DescribePodIdentityAssociation` | Which IAM role a Kubernetes service account may assume. Pods and workloads are **not** read here — the Kubernetes connector already discovers those | [5] |
| `cloudtrail:LookupEvents`, `DescribeTrails`, `GetTrailStatus` | Per-identity API history for liveness and classification | [5] |

The `Generate*` IAM calls are named like writes but produce read-only reports:
they create no resource and change no state. A customer's security reviewer
will ask; that is the answer.

**Every action above is a real IAM action.** `cfn-lint`'s `W3037` check
validates service prefixes and action names against AWS's own IAM spec, and the
template passes with zero findings — including `bedrock-agentcore:`, which was
the prefix most in doubt. Verified with a control: injecting `notaservice:` and
`eks:ListClustersTypo` makes the same check fail, so the pass is meaningful and
not the rule silently skipping.

```
cfn-lint internal/awsdiscovery/authsec-aws-discovery-role.yaml \
         --include-checks W3037 I --include-experimental
```

What is still open is **redundancy, not validity**. Several entries are marked
`possibly_redundant_with_baseline` in `internal/awsdiscovery/permissions.go` and
surfaced through the API, because `SecurityAudit` may already cover them.
Settling that needs the live policy document read from an account. An
over-grant a customer can see and question is better than one hidden in a
template.

### Hard denies

An explicit `Deny` beats any `Allow`. The baseline does not grant any of these
today; the denies are what keeps that true if AWS widens `SecurityAudit` or a
later AuthSec release adds a permission carelessly. This is the shared schema's
**no secret values** rule enforced by IAM rather than by our promise to behave.

| Denied | Why |
|---|---|
| `secretsmanager:GetSecretValue`, `BatchGetSecretValue`, `ssm:GetParameter*` | AuthSec records that a secret exists, its age and its last use. It never reads one. |
| `kms:Decrypt`, `Encrypt`, `GenerateDataKey*`, `ReEncrypt*` | Nothing discovery reads is encrypted at the application layer. |
| `sts:AssumeRole`, `AssumeRoleWithWebIdentity`, `AssumeRoleWithSAML` | The discovery session is a leaf. It may be assumed *by* AuthSec — the trust policy, which this does not affect — but may never assume anything further and pivot deeper into the account. |

### One thing IAM cannot enforce

`lambda:ListFunctions` returns environment variable **values**, not just names.
The plan commits to using names for classification and discarding values at the
point of parsing. There is no IAM action that grants the names without the
values, so this one is a code obligation, enforced in the Lambda parser in
ticket [4] and not by the role. Worth carrying into that ticket's review.

---

## What AuthSec stores

| Thing | Where | Notes |
|---|---|---|
| ExternalId | Secrets store, `kv/data/secret/workspaces/<ws>/cloud-discovery/aws/<account>` | The only secret. Keyed by account, so re-onboarding overwrites rather than orphaning. |
| `auth_ref` | `cloud_connector.auth_ref` | The path above. A handle, never material. `json:"-"` — never serialised, because an API response is the wrong place to publish where a workspace's credentials live. |
| Role ARN, regions, partition, caller ARN | `cloud_connector.attrs` | Not secret. In the row so a scan does not pay a secrets-store read to learn which role to assume. |
| Account id | `cloud_connector.scope_id` | From `GetCallerIdentity`. |

AuthSec's **own** AWS credentials come from the ambient environment — an
instance role, IRSA, or environment variables in development. There is no
per-workspace AWS credential to configure.

---

## API

All under `/authsec/discovery/aws`, authenticated, workspace-scoped.

| Method | Path | Permission | |
|---|---|---|---|
| `GET` | `/onboarding` | `discovery:read` | Mints an ExternalId; returns the template, the principal, and the permission list. |
| `POST` | `/connectors` | `discovery:admin` | `{role_arn, external_id, regions[], display_name}`. 201 new, 200 reconnected. |
| `GET` | `/connectors` | `discovery:read` | List. |
| `GET` | `/connectors/:id` | `discovery:read` | One. |
| `POST` | `/connectors/:id/verify` | `discovery:admin` | Re-prove; records the verdict on the row. |
| `DELETE` | `/connectors/:id` | `discovery:admin` | Removes the row and purges the ExternalId. The customer's stack is theirs to delete. |
| `POST` | `/connectors/:id/scan` | `discovery:admin` | Starts the IAM identity scan. 202; poll the connector. |
| `GET` | `/identities` | `discovery:read` | Discovered identities. Candidates, not agents. |
| `GET` | `/secrets` | `discovery:read` | Access keys, oldest first. Metadata only. |

`GET /onboarding` is `discovery:read` even though it mints an ExternalId: the
id is worthless until a role that trusts it exists, and gating it on admin
would stop a reader from seeing the permissions AuthSec is asking for — exactly
what a reviewer needs.

**The console must hold the ExternalId it displayed and post that same value
back.** Each call to `/onboarding` mints a different one; re-fetching mid-flow
will not match the stack the customer just deployed.

### Errors say whose problem it is

`mapAWSOnboardingError` distinguishes three faults, because collapsing them
sends every case to the same unhelpful place:

- `fault: customer_account` (400) — AWS refused the assume. Wrong ExternalId,
  or a trust policy naming a different principal. Not an AuthSec outage.
- `fault: aws` (429) — throttled after the SDK's own retries.
- `fault: authsec` (500) — the backend has no AWS identity of its own. Nothing
  the customer can fix, and it must not be shown to them as their mistake.

---

## Re-scan and failure behaviour

- **Re-onboarding an account updates its row.** `UNIQUE(workspace_id, provider,
  scope_id)` is the conflict target. A second row would split one account's
  inventory and bill every scan against it twice. The upsert deliberately does
  not touch `scan_generation` or `coverage` — resetting them would make every
  existing row look stale and turn a re-onboard into a silent inventory wipe.
- **A failed verification never deletes anything.** Status becomes `error` with
  the reason; `verified_at` is left alone so the console can still show when the
  connection last genuinely worked. "We cannot look right now" is not "it is
  gone".
- **Retries.** The SDK's standard retryer with 8 attempts, above the default of
  3: IAM and CloudTrail throttle readily on a large account, and a scan that
  gives up on the first `ThrottlingException` reports a partial estate as if it
  were the whole one.

---

## The identity scan

`POST /authsec/discovery/aws/connectors/:id/scan` reads the IAM foundation. It
returns 202 and runs in the background: a full IAM read on a large account is
thousands of calls under a retrying client, and running that inside an HTTP
request is the mistake migration `007` documents fixing for the GitHub channel.

The durable record is the connector's own `coverage` blob, written as the scan
proceeds — so polling is just a `GET` of the connector, and the report survives
a page refresh.

### What it writes

| Surface | Reads | Becomes |
|---|---|---|
| Roles | `ListRoles`, then `GetRole` per role | `cloud_identity` (`kind=iam_role`) |
| Users | `ListUsers` | `cloud_identity` (`kind=iam_user`) |
| Access keys | `ListAccessKeys`, `GetAccessKeyLastUsed` per key | `cloud_secret` (`kind=access_key`) |
| Policies | attached + inline, per identity | **not persisted** — handed to ticket [2] |

`GetRole` is a second call per role and is not avoidable with these operations:
`ListRoles` returns neither `RoleLastUsed` nor tags, and both matter — the first
is liveness without paying for CloudTrail, the second is the only ownership hint
available at this stage. `iam:GetAccountAuthorizationDetails` would collapse
most of this into one paginated call and the template already grants it;
comparing the two on a real account is an open item, and the resulting rows are
identical either way.

### Rules the scan holds itself to

- **Null means unknown, never "never used".** A role AWS has never reported
  using, and a key that has never been used, both leave `last_used_at` NULL. A
  zero timestamp would read as "used at the epoch" and manufacture a finding out
  of a gap in our own coverage.
- **`created_at` is the provider's date.** For a secret, age *is* the finding.
  The Go models map `ProviderCreatedAt` to that column explicitly, because a
  field named `CreatedAt` would be auto-populated by GORM with the insert time
  and silently turn "this key is five years old" into "this key is new".
- **Console sign-in is not usage.** A user's `PasswordLastUsed` is deliberately
  not written to `last_used_at`; a human opening the console says nothing about
  whether a workload's credential is live.
- **Unreached is not missing.** Reconciliation runs only when *every* surface
  reported `reached`. A denied `ListRoles` and an account with no roles are
  indistinguishable from the database, so a scan that could not look never
  concludes anything is gone.
- **One surface failing does not abort the scan.** Each is recorded in coverage
  and the next is attempted — "IAM was denied but access keys were readable" is
  a more useful report than a single error.
- **Pagination runs to completion**, bounded by a page ceiling so a marker
  echoed back unchanged becomes a reported error rather than an infinite loop.
- **Managed policy documents are cached per policy ARN.** Ten roles sharing
  `ReadOnlyAccess` fetch it once.

### Reading the coverage report

```json
{ "generation": 3, "status": "partial",
  "surfaces": {
    "iam_roles":       {"state": "reached",   "count": 412},
    "iam_users":       {"state": "reached",   "count": 18},
    "iam_access_keys": {"state": "reached",   "count": 23},
    "iam_policies":    {"state": "throttled", "count": 380, "error": "..."} },
  "counters": {"identities_new": 12, "identities_removed": 0} }
```

`status: partial` means the inventory is **not** an all-clear. A `count` on a
non-reached surface is a floor — how many we read before being stopped — not a
total.

## How this is tested

| What | Where | Needs |
|---|---|---|
| Schema: fresh install, upgrade, idempotent re-run, fresh/upgraded parity across all three cloud tables | `migrations/master/010_*.sql`, `011_*.sql` on Postgres 16 | Docker |
| Constraints and the re-onboard upsert | same | Docker |
| Onboarding service, DB writes, secret handling, error paths | `tests/integration/cloud_aws_onboarding_test.go` | `IGA_TEST_DSN` |
| IAM scan: identities, keys, policies, pagination, reconciliation gate, coverage | `tests/integration/cloud_aws_iam_scan_test.go` | `IGA_TEST_DSN` |
| Real AWS SDK: SigV4, assume-role, XML parsing, error classification | `internal/awsdiscovery/onboarding_wire_test.go` | nothing |
| Template validity and IAM action names | `cfn-lint`, see above | nothing |

The IAM scan tests run against a fake `IAMAPI` that paginates the way IAM does
and URL-encodes policy documents the way IAM does, and can be told to deny or
throttle a named operation. A compile-time assertion binds the fake to the real
interface, so a new AWS call cannot be added without the fake growing it —
which is what stops a new call going untested.

The wire tests run the real `LiveVerifier`, the real `aws-sdk-go-v2` client and
the real `stscreds` provider against a local server speaking the STS wire
protocol, using the SDK's own `AWS_ENDPOINT_URL_STS` override — so no
production code exists purely to make it testable. They prove the parts that
are ours to get wrong: that `AssumeRole` carries the ExternalId and session
name, that `GetCallerIdentity` is signed with the **assumed** credentials
rather than AuthSec's own (signing it with the base credentials would record
the wrong account on every onboarding), and that an `AccessDenied` becomes
`ErrNotAssumable` without being retried.

## Still open

Everything below needs a live AWS account.

1. **SDK feasibility against real AWS.** The wire tests prove our use of the
   SDK is correct and the fake proves our use of the IAM operations is correct;
   neither proves AWS accepts the call or returns exactly the fields assumed.
   One scan of a real account closes this.
2. **Redundancy against `SecurityAudit`.** Read the live policy document and
   delete whatever the baseline already grants. Validity is settled; only the
   trim is left.
3. **A real CloudFormation deploy.** `cfn-lint` validates structure, intrinsics
   and every IAM action. It does not prove the stack creates cleanly in an
   account.
4. **Bulk versus per-identity IAM.** Compare `GetAccountAuthorizationDetails`
   against the per-role calls on a real account and keep whichever is faster.
   The rows are identical either way, so this is a change to
   `IAMReader.ListRoles` alone.
5. **CloudTrail cost.** Not this ticket, but the template already grants
   `GenerateServiceLastAccessedDetails`, which supplies most of
   `last_exercised_at` without CloudTrail volume. Measure both before
   committing to a window.

## Deliberately deferred, with reasons

- **`cloud_secret.identity_id` is NOT NULL.** Correct for access keys, which
  always belong to a user. AgentCore credential providers (ticket [3]) are
  account-scoped and will need it nullable — left tight because loosening a
  constraint later is an expand-only change while tightening one is not.
- **Reconciliation deletes rather than tombstones.** The shared schema has no
  "gone" column on `cloud_identity`, so ageing out means removing the row. It is
  gated hard on complete coverage. If the schema owner would rather keep
  tombstones, that is a shared-schema change, not an AWS one.
- **`lambda:ListFunctions` returns environment variable values.** No IAM action
  grants the names without the values, so "metadata only" is a code obligation
  in the Lambda parser at ticket [4], not something the role can enforce.
  Carried forward deliberately.

One design point needs the shared-schema owner, recorded in
`migrations/master/010_cloud_discovery_connector.sql`: this table adds `attrs`,
`verified_at` and `last_error` to the ten columns the cross-cloud note lists.
`attrs` is where AWS keeps the role ARN and the region selection, neither of
which the shared columns have anywhere for.
