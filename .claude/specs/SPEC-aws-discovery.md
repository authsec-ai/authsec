# SPEC: AWS Agent Discovery

> **Status:** AWS domain reference — what the provider's objects and documents
> mean. Delivery sequencing, schema and acceptance live in
> [SPEC-iga-roadmap.md](SPEC-iga-roadmap.md); the phase in flight is
> [SPEC-iga-phase1-collect.md](SPEC-iga-phase1-collect.md).
>
> Use the roadmap's coverage manifest to determine which APIs are actually
> collected; the wider AWS examples here do not promise implemented collection.
>
> **Product:** [Agentic IGA](SPEC-agentic-access-management.md).
> **Lab:** [AWS discovery lab](AuthSec-AWS-Discovery-Lab-Team-Brief.md).

*Parts 0–2 teach AWS and the scan. Parts 3–7 follow one Lambda function from an API
response to a row a reviewer acts on.*

---

# Part 0 — The AWS vocabulary you need

## An account is a box

An **AWS account** is a container holding everything a customer runs. It has a
12-digit number like `123456789012`.

Everything inside gets an address called an **ARN** (Amazon Resource Name):

```
arn:aws:s3:::acme-invoices
arn:aws:iam::123456789012:role/refund-role
arn:aws:lambda:us-east-1:123456789012:function:refund-processor
        ↑        ↑            ↑              ↑
     service   region      account        the thing
```

ARNs are the natural join key — when a Lambda says "I use role X", it says it as an
ARN.

> **ARNs are not unique forever.** Stability and reuse vary by service, and S3 is
> the direct counterexample: a deleted bucket name can later be claimed by a different AWS
> account, so the same ARN can refer to someone else's resource. Use a
> **service-specific recognition strategy**, not a blanket rule. For IAM the right
> key is the permanent unique id (`AROA…` for roles, `AIDA…` for users) with the ARN
> stored alongside as the join attribute.

Some services are **global** (IAM); most are **regional** (Lambda, EC2). Five regions
means scanning five times.

## IAM is the login system, for software as well as people

**IAM** = Identity and Access Management. Two kinds of identity:

**An IAM user** is a traditional account, and can hold an **access key** — a
permanent username/password pair for programs:

```
AKIAIOSFODNN7EXAMPLE                        ← key ID
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY    ← secret
```

These never expire. Leaked in a git commit, they work until a human notices.

**An IAM role** has no password. A costume on a hook: anything permitted can
**assume** it and receive temporary keys that die in an hour. Nothing permanent to
steal.

> Almost every AI agent in AWS acts through a role. "What can this agent reach?" is
> really "what can its role do?"

## A policy says what is allowed

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": ["arn:aws:s3:::acme-invoices/*"] },
    { "Effect": "Allow",
      "Action": "bedrock:InvokeModel",
      "Resource": "*" }
  ]
}
```

Three things that shape the schema:

- **A statement is the unit** — several actions and several resources at once.
- **`"Resource": "*"` names nothing specific.** Very different from naming a bucket.
- **Policies attach two ways.** A **managed** policy is named and reusable across
  many identities; an **inline** policy is written onto one identity. Different API
  calls fetch each.

There are also two inverse forms that matter enormously and are easy to miss:

```json
{ "Effect": "Allow", "Action": "s3:GetObject",
  "NotResource": "arn:aws:s3:::payroll/*" }
```

means *GetObject everywhere **except** payroll* — an exception, not an absence. And:

```json
{ "Effect": "Deny", "NotAction": "iam:*", "Resource": "*",
  "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}} }
```

means *deny everything except IAM, when MFA is absent*. Both are load-bearing: a parser that drops them inverts the statement's meaning.

## Every role has a second document: who may wear it

Separate from "what may this role do", each role has a **trust policy** —
"who may assume this role".

For a Lambda:

```json
{ "Statement": [{ "Effect": "Allow",
    "Principal": { "Service": "lambda.amazonaws.com" },
    "Action": "sts:AssumeRole" }] }
```

For a Kubernetes pod:

```json
{ "Statement": [{ "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/ABC123" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": { "StringEquals": {
      "oidc.eks.us-east-1.amazonaws.com/id/ABC123:sub":
        "system:serviceaccount:payments:refund-sa" }}}] }
```

*A pod in namespace `payments` under service account `refund-sa`, in cluster
`ABC123`, may wear this costume.* Remember that string — Part 5 turns it into the
most valuable join in the system.

Trust policies also carry conditions that **narrow** them —
`aws:PrincipalOrgID`, `aws:SourceArn`, `sts:ExternalId`, `aws:SourceAccount`. Reading
the principal without its conditions can turn an organisation-constrained trust into
an apparently world-open one.

## Where software runs

| Service | What it is |
|---|---|
| **Lambda** | Upload a function; AWS runs it on demand. |
| **ECS** | AWS runs your containers. |
| **EC2** | A plain virtual machine. |
| **EKS** | Managed Kubernetes. |
| **Bedrock** | AWS's AI service. **Bedrock Agents** are agents AWS hosts and labels. |

Each one assumes a role when it runs, and each states which role in its own config.

## Why finding an agent is hard

There is no `ListMyAIAgents`. Bedrock Agents are labelled; nothing else is. An agent
written in Python with LangChain and deployed as a Lambda is, to AWS, just a Lambda.

So discovery is: find identities, find workloads, resolve which identity each
workload uses, read what each identity may do, then **guess** which are agents and
say how sure we are. The first four are facts. The fifth is judgement.

---

# Part 1 — Connecting to a customer's AWS account

## Why not just take an access key

A permanent credential to their whole account means one breach of ours is a breach of
every customer, and they cannot revoke it without regenerating and re-telling us.

Instead the customer creates a role we may assume.

## The confused deputy, and the ExternalId

Customer A learns customer B's role ARN — not secret; it turns up in tickets and
screenshots. A pastes B's ARN into their own AuthSec settings. We assume it. We just
read B's account for A.

That is the **confused deputy**: we had the authority and were tricked into using it
for the wrong person. The fix is an **ExternalId** the customer bakes into their trust
policy and we present on every assume:

```json
"Condition": { "StringEquals": { "sts:ExternalId": "7f3a9c2e-…" } }
```

> **The ExternalId is not a secret.** AWS documents it as visible to anyone who can
> view the role. It is an **unguessable, workspace-bound, anti-confused-deputy
> nonce**, and the system must remain secure if it leaks.
>
> Derive it cryptographically from the workspace rather than storing an arbitrary
> random string. Keep it in the secrets store to reduce casual exposure — but do not
> call it a credential.

## The flow

1. Admin clicks **Connect AWS account**.
2. We derive the ExternalId and store the handle; the DB row holds a path, never a
   value — the existing pattern at `services/connector_service.go:117`.
3. We render a **CloudFormation template** with our account and their ExternalId.
4. They run it; it creates the role with read-only permissions.
5. They paste back the role ARN.
6. **Permission probe before any scan.** Assume the role, try one harmless call per
   family. Whatever fails is recorded as a coverage gap *now*, so we never later show
   an empty result that actually means "not allowed to look".

> **Connection probes come in two sets, not one.** Hard-failing on every probe
> would stop a customer who deliberately withholds CloudTrail or AgentCore
> permissions from connecting at all, and it contradicts recording gaps as coverage.
>
> | Set | Probe | On failure |
> |---|---|---|
> | **`required_to_connect`** | `sts:AssumeRole`, `sts:GetCallerIdentity`, `iam:ListRoles` | Reject the connection. Without these there is no discovery. |
> | **`optional_capability`** | Bedrock, AgentCore, EKS, CloudTrail, Access Advisor | Connect as **degraded**; that family's coverage is `not_configured` with the denial as its reason. |
>
> The connection lands `active` or `degraded`, never silently partial.

Permissions: AWS's managed **`SecurityAudit`** is the read-only baseline. Add
`bedrock:List*/Get*`, `bedrock-agentcore:List*`, `eks:ListPodIdentityAssociations`.
All reads. **The discovery role can never write** — changing anything needs a separate
role and separate consent (Part 7).

The branch adds something worth keeping: **hard Denies** on
`secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt`, `sts:AssumeRole*`
in the discovery session. Even if AWS widens `SecurityAudit` under us, those classes
stay unreachable. Because `SecurityAudit` is AWS-owned and can change without our
deploy, also record the observed policy version so drift is visible.

Per scan: `sts:AssumeRole(RoleArn, ExternalId, DurationSeconds=3600)` returns
temporary keys held in memory. **No AWS credential is ever written to disk.**

---

# Part 2 — Scanning

Order is forced by dependencies — everything resolves against identities.

**1. Identities.** `iam:ListRoles` (returns each trust policy inline),
`iam:ListUsers`.

**2. Access keys.** `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`.

**3. Policies, per identity.** Four calls each: `ListAttachedRolePolicies` →
`GetPolicy` + `GetPolicyVersion`; `ListRolePolicies` → `GetRolePolicy`.

> **Also required, and currently missing:** `ListGroupsForUser` plus the group's
> managed and inline policies. IAM users inherit from groups, so
> `machine-user → admins → AdministratorAccess` looks like a user with no permissions
> if you read only what is attached directly. This matters most for access-key
> identities, which is exactly where legacy group permissions live.

> **Strategy decision, not an open question.** `iam:GetAccountAuthorizationDetails`
> returns users, groups, roles and policies **with their relationships** in one
> paginated snapshot. On an account with 10,000 roles the per-identity traversal
> above is tens of thousands of requests; the snapshot is a few hundred. Pick one
> explicitly:
>
> - **A — snapshot primary:** `GetAccountAuthorizationDetails`, plus targeted calls
>   for what it omits. Fewer requests, one large response, coarser failure
>   granularity.
> - **B — traversal primary:** the calls above. Finer checkpointing and per-identity
>   failure isolation, far more requests.
>
> They have different throttling and resumability profiles, so this belongs in the
> scanner architecture rather than being discovered at scale.
>
> **Decided: A.** `GetAccountAuthorizationDetails` is the primary IAM inventory path;
> the per-identity calls are enrichment (`GetAccessKeyLastUsed`, instance profiles,
> workloads, activity) and the fallback when the snapshot call is denied. Its policy
> documents arrive URL-encoded and must be decoded before canonicalisation, or the
> same policy fingerprints differently depending on which API found it.

**4. Workloads.** `lambda:ListFunctions` (carries `Role`),
`ecs:DescribeTaskDefinition`, `ec2:DescribeInstances` → `iam:GetInstanceProfile`.

> **Two traps.** ECS returns *two* roles: `taskRoleArn` is what the application acts
> as — the agent. `executionRoleArn` is ECS pulling images and writing logs.
>
> EC2 names an **instance profile**, a wrapper holding exactly one role.
> `GetInstanceProfile` resolves it. EC2 is the only workload with this hop.

**5. AWS's own agents.** `bedrock:ListAgents` then `GetAgent` per agent (the list
omits the role). `bedrock-agentcore:ListAgentRuntimes` → `GetAgentRuntime`.

**6. The Kubernetes bridge.** `eks:DescribeCluster` for the OIDC issuer;
`eks:ListPodIdentityAssociations` → describe. We are **not** discovering Kubernetes
workloads — the Kubernetes agent already does.

**7. Activity.**

> **What the activity sources actually report.**
>
> **Access Advisor** supports `SERVICE_LEVEL` *and* `ACTION_LEVEL`. More importantly
> it records **attempts**, including denied ones — so the honest column name is
> `last_attempted_at`, not `last_used_at`, unless the source proves success. And a
> service-level result must never be fanned out onto every action: "S3 used
> yesterday" does not mean `s3:DeleteBucket` was used.
>
> **CloudTrail `LookupEvents`** returns 90 days of **management** events and **no
> data events** — and data events are off by default. So `s3:GetObject`, the exact
> case of interest, is invisible unless the customer has configured a trail for it.
> "Unused for 90 days" from that surface actually means "no qualifying management
> activity was visible through this particular surface."
>
> These are two separate capabilities with two separate coverage states, not one
> opt-in upgrade.

`GenerateServiceLastAccessedDetails` is **asynchronous** — it returns a JobId you
poll. It cannot sit inline in a simple loop.

> And the JobId is **bound to the session that created it**, not to us. Our scan
> assumes a role for one hour. If the scan is throttled, the worker crashes, and a
> checkpoint resumes under a *new* STS session, the old JobId may no longer be
> retrievable. So an Access Advisor job is its own stateful sub-operation —
> `job_id`, `principal`, `generated_at`, `session_expiry`, `state` — and an expired
> session means **regenerate**, not resume. A checkpoint token is not portable
> across sessions.

Every list call paginates to the end; throttling retries with backoff; progress is
checkpointed.

> **On resuming:** do not think of it as "resume at role 813". AWS list APIs are not
> database snapshots — between attempts roles are added, deleted, renamed, and
> pagination markers expire. A continuation token is fine for a short retry; after
> invalidation, restart the partition and rely on idempotent writes. Never treat an
> ordinal as a position.

---

# Part 3 — Storage: one Lambda, traced through every table

## What AWS returned

```json
{ "FunctionName": "refund-processor",
  "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:refund-processor",
  "Role": "arn:aws:iam::123456789012:role/refund-role",
  "Runtime": "python3.12",
  "Environment": { "Variables": {
      "LANGCHAIN_TRACING_V2": "true",
      "OPENAI_API_KEY": "sk-…" }},
  "LastModified": "2026-08-14T09:22:31.000+0000" }
```

> **On that env var.** Be precise about what we can claim: **AWS sends us the
> value.** The honest statement is "AWS returns it, we discard it immediately and
> never persist or log it" — not "we never hold it". Those are different security
> statements, and only one of them is true.
>
> This also constrains hashing. `raw_hash` must be computed **after** redaction:
> `response → strip sensitive fields → canonical form → hash`. Hashing the raw
> response first retains a deterministic derivative of material we refused to store.

> **Read the SQL in Parts 3 and 4 as three different writers.**
> The AWS collector writes **evidence** and the **authoritative cloud model**; it
> never writes governance rows.
>
> | Rows | Written by | Reads |
> |---|---|---|
> | `iga_source_objects`, `iga_observations` | collector | AWS |
> | `cloud_identity`, `cloud_permission`, `cloud_resource_selector`, … | collector | AWS |
> | `iga_classification_candidates`, `iga_correlations` | classification / correlation stage | `cloud_*` + observations |
> | `iga_identity_accounts`, `iga_entitlements`, `iga_access_edges` | **projection**, one-way, rebuildable | `cloud_*` |
>
> An implementation whose collector `INSERT`s into both `cloud_*` and `iga_*` is a
> dual write, and the first time they disagree nobody can say which is true. If the
> projection breaks, rebuild it from `cloud_*`. Do not rescan AWS.

## Layer 1 — the source object

```sql
INSERT INTO iga_source_objects (
    workspace_id, integration_id, object_type, recognition_key, native_id,
    locator, normalized_payload, raw_hash, source_version,
    source_subject_key, scan_generation, lifecycle)
VALUES (
  :ws, :aws_integration, 'aws_lambda_function',
  'aws:lambda:us-east-1:123456789012:refund-processor',
  'arn:aws:lambda:us-east-1:123456789012:function:refund-processor',
  '{"region":"us-east-1","account":"123456789012"}',
  '{"function_name":"refund-processor",
    "role_arn":"arn:aws:iam::123456789012:role/refund-role",
    "runtime":"python3.12",
    "env_var_names":["LANGCHAIN_TRACING_V2","OPENAI_API_KEY"]}',
  'sha256:9f2c…', '2026-08-14T09:22:31Z',
  'aws:123456789012', 47, 'active');
```

Three columns doing real work:

- **`recognition_key`** — how we know this is the same Lambda tomorrow. Built only
  from things that never change in normal operation.
- **`normalized_payload`** — environment variable **names**, never values.
- **`source_subject_key`** — the column comment says it: *"Deletion of provider
  payload is scoped by (workspace, integration, source_subject_key)."* This is what
  makes erasure possible later.

For the role, the recognition key uses AWS's permanent unique id:

```sql
('aws_iam_role', 'aws:role:AROAJ4XKPQR2N3EXAMPLE',
 'arn:aws:iam::123456789012:role/refund-role', …)
```

## Layer 2 — observations

`mode` is not a generic strength label; it is the kind of signal, and the enum in the
schema is ordered by descending semantic strength:

| AWS signal | `mode` |
|---|---|
| It is a Bedrock Agent | `platform_declared` |
| Lambda config states its `Role` | `deployment_declared` |
| A policy statement grants something | `identity_grant` |
| LangChain in the image or env var names | `framework_dependency` |
| An MCP config file is mounted | `tool_configuration` |
| An access key or secret reference exists | `secret_reference` |
| Access Advisor / CloudTrail says it was attempted | `audit_event` |

```sql
INSERT INTO iga_observations (
    workspace_id, source_object_id, scan_run_id, mode,
    fact_payload, evidence_ref, observed_at,
    normalizer_version, rule_id, rule_version, dedupe_key)
VALUES
(:ws, :lambda_obj, :scan, 'deployment_declared',
 '{"predicate":"runs_as","object":"aws:role:AROAJ4XKPQR2N3EXAMPLE"}',
 'lambda:ListFunctions', '2026-08-14T09:22:31Z',
 'aws.v1', 'aws.lambda.role.v1', '1',
 'aws:lambda:refund-processor:runs_as:AROAJ4XK…'),

(:ws, :lambda_obj, :scan, 'framework_dependency',
 '{"predicate":"environment_variable_present","name":"LANGCHAIN_TRACING_V2"}',
 'lambda:ListFunctions#Environment', '2026-08-14T09:22:31Z',
 'aws.lambda.env.v1', '', '',      -- a NORMALIZER, not a rule
 'aws:lambda:refund-processor:env:LANGCHAIN_TRACING_V2');
```

> **Never bake a rule's conclusion into the evidence.** Storing
> `{"predicate":"agent_framework","value":"langchain"}` with
> `rule_id = aws.env.framework.v1` breaks the one property this layer exists for.
>
> If the stored fact already says "langchain", then re-running a fixed rule over
> stored observations cannot reach a different answer — the old rule's judgement is
> the input. You would have to go back to AWS, which is the thing the layer was
> supposed to make unnecessary.
>
> So the split is: a **normalizer** writes what AWS said
> (`environment_variable_present: LANGCHAIN_TRACING_V2`) and carries
> `normalizer_version` with an empty `rule_id`. A **classification rule** reads those
> facts and writes a *candidate*, carrying `rule_id` and `rule_version`. Rule v2 then
> re-reads the same untouched facts.
>
> This is the same principle applied to policy statements — preserve the
> provider's words, derive separately. It simply was not applied to agent
> classification.

Why this layer exists:

- **`dedupe_key` is UNIQUE**, so a replayed webhook or re-run segment cannot
  double-count.
- **`rule_id` + `rule_version` on every row.** When `aws.env.framework.v1` turns out
  to also match a logging library, you fix the rule and **re-run detection over
  stored observations**. No rescan. That is the entire justification for this layer.
- **`evidence_ref`** answers "why do you believe this?" with the exact API call.

> **A tension to resolve.** `UNIQUE (workspace_id, dedupe_key)` is global, but the
> keys above are stable across scans — so scan 48 asserting the same fact **collides
> rather than appending**. You cannot have both global stable dedupe and one
> observation per scan with that key. Either key on
> `(workspace_id, scan_run_id, dedupe_key)`, or split into a `fact` /
> `fact_sighting` pair. The second is better: it keeps full temporal evidence without
> duplicating the JSON every day.

## Layer 2b — the candidate

```sql
INSERT INTO iga_classification_candidates (
    workspace_id, source_object_id, proposed_object_kind,
    proposal_signature, rule_id, rule_version, evidence_mode, state)
VALUES (:ws, :lambda_obj, 'agent_instance',
        'aws:lambda:refund-processor:agent', 'aws.env.framework.v1', '2',
        'framework_dependency', 'pending');
-- The rule id lives HERE, on the judgement, not on the fact it read.
```

A Bedrock Agent skips to `confirmed` because `platform_declared` is AWS labelling its
own object. A LangChain Lambda cannot.

## Layer 3 — canonical

```sql
INSERT INTO iga_identity_accounts (
    workspace_id, estate_scope_id, display_name, account_kind,
    identity_backing, lifecycle, rollup_state)
VALUES (:ws, :account_scope, 'refund-role', 'aws_iam_role',
        'workload_identity', 'active', 'confirmed')
RETURNING id;
```

> **A role belongs to the account scope, not a region.** IAM is
> **account-global** — one `refund-role` can back a Lambda in `us-east-1`, another in
> `eu-west-1`, and an ECS task in `ap-south-1`. Scoping it regionally makes the
> consumer count wrong, which makes `identity_backing` wrong, which makes a revoke
> decision wrong. The role belongs to the **account** scope; only workloads belong to
> regions.

> **A workload is not yet an agent instance.** `iga_agent_instances.agent_id` is
> `NOT NULL`, so there is nowhere to put an unclassified Lambda — and a suspected LangChain Lambda is not yet an agent,
> so it should not need an `agent_instance` row at all. The fix is a neutral
> **workload** level. A Lambda becomes discoverable, listable and
> attributable without anyone deciding whether it is an AI agent.

```sql
INSERT INTO iga_correlations (
    workspace_id, source_object_id, canonical_kind, canonical_id,
    join_key, strength, state)
VALUES (:ws, :lambda_obj, 'identity_account', :identity,
        'arn:aws:iam::123456789012:role/refund-role',
        'strong', 'accepted');
```

`iga_correlations` carries a constraint worth reading:

```sql
CONSTRAINT iga_correlations_weak_chk CHECK (
    state <> 'accepted' OR strength = 'strong' OR decided_by IS NOT NULL)
```

A weak join cannot be accepted without a human. Enforced, not trusted.

### How `identity_backing` is computed

| What we see | `identity_backing` | Revoking affects |
|---|---|---|
| Only this Lambda uses the role | `agent_native` | This agent only |
| Twelve Lambdas share it | `generic_service_principal` | All twelve |
| An EKS trust policy points at it | `workload_identity` | Every pod assuming it |
| A human's role used via delegation | `user_impersonation` | That person's access |
| Coverage incomplete | `unknown` | Undetermined — say so |

> **"Only this Lambda uses it ⇒ `agent_native`" carries a hidden premise:** *we have exhaustively found every consumer.* We have not. The role could
> also be used by CodeBuild, SageMaker, Step Functions, Glue, Batch, EventBridge,
> App Runner, a Lambda in an unselected region, another account via `AssumeRole`, or
> a service AWS ships next quarter.
>
> `agent_native` may only be asserted when workload coverage, regional coverage and
> trust-policy coverage are all complete. Otherwise record
> `observed_consumers = 1, exclusivity = unknown`. The product can say **"1 known
> consumer"** without saying **"this role belongs only to this agent."** Large
> difference.

## Never delete on absence

`lifecycle` is `active | tombstoned | redacted`. Real deletion needs a scan that
**completed**; a scope that had objects and now returns zero is a **failed read** with
tombstoning withheld.

> On the mass-deletion threshold: a hardcoded 20% should not decide what is *true*.
> Use a two-phase `missing_pending → tombstoned` requiring an authoritative full scan
> for truth, and keep the percentage as an operational **alert**. A customer
> legitimately deleting 700 obsolete roles must be able to converge.

---

# Part 4 — The graph, in rows

*The `iga_*` rows in this part are the projection described at the top of Part 3.
The collector's own write for the same fact is one `cloud_permission` row plus one
`cloud_resource_selector` row.*

```json
{ "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": ["arn:aws:s3:::acme-invoices/*"] }
```

> **A policy naming an ARN is not evidence that the thing exists**, and a selector
> carries no region — so a resource row written straight from a statement invents
> two facts at once.
>
> It proves a policy contains a reference. It does not prove the bucket exists, is
> owned by this account, still is, or is reachable. The ARN could name a deleted
> bucket, a typo, another account's resource, or one created next year. S3 makes this
> sharp — a deleted bucket name is claimable by a different AWS account.
>
> And **`arn:aws:s3:::acme-invoices/*` carries no region** (look at the empty
> segments). We never called `GetBucketLocation` or listed a single bucket, so
> putting it in `us-east-1` invents a fact.
>
> The selector is the evidence. A resource row is a separate, later observation:

```sql
-- The SELECTOR is what the policy proved. No resource is asserted.
INSERT INTO iga_entitlements (workspace_id, resource_id, native_grant_kind,
                              native_rights, normalized_rights, native_scope, remediable)
VALUES (:ws, NULL, 'aws_iam_policy_statement',   -- selector preserved; no resource asserted
        '{"effect":"Allow","actions":["s3:GetObject","s3:PutObject"],
          "resources":["arn:aws:s3:::acme-invoices/*"],
          "policy_arn":"arn:aws:iam::123456789012:policy/refund-access",
          "statement_sid":"AllowInvoiceRead"}',
        '["read","write"]', 'arn:aws:s3:::acme-invoices/*', true);
-- resource_id stays NULL until independent resource discovery observes the bucket
-- and can say which account owns it and which region it lives in.

INSERT INTO iga_access_edges (workspace_id, subject_kind, subject_id,
                              entitlement_id, resource_id, direction, path_kind,
                              calculation_state, effective_conclusion,
                              native_scope, observed_at)
VALUES (:ws, 'identity_account', :identity, :entitlement, NULL,   -- not :bucket
        'outbound', 'direct', 'partial', 'unknown',
        'arn:aws:s3:::acme-invoices/*', now());
```

> **`resource_id` stays NULL here** — binding a `:bucket` value two lines after
> saying so is exactly the copy-paste that ships the wrong implementation. Both `iga_entitlements.resource_id` and
> `iga_access_edges.resource_id` are nullable in `004`, so nothing else changes. The
> later link is a separate row, and a selector may resolve to **zero, one or many**
> resources — `arn:aws:s3:::customers-*` matches every observed bucket with that
> prefix — so the link is a table, not a column.

> **There is no `DetachStatement` API**, so a statement is not what you can
> actually remove. AWS offers:
>
> ```
> DetachRolePolicy(role, policy_arn)   → detaches the WHOLE managed policy
> DeleteRolePolicy(role, policy_name)  → deletes the WHOLE inline policy
> CreatePolicyVersion(policy_arn, doc) → edits it for ALL consumers
> ```
>
> So a managed policy attached to 50 roles gives a reviewer two options and both have
> blast radius. The statement is the **analysis** unit; the **attachment** is the
> remediation unit. A `remediable boolean` is too weak to carry that distinction.

**Why `partial` / `unknown` is the honest answer.** We read the role's own policy. We
did not read Service Control Policies, permission boundaries, session policies, the
resource's own policy, or Conditions. So the UI says **"grant path"**, not "has
access".

> **Only an *applicable* Deny wins** — "Deny always wins" is not a safe shortcut, and AWS
> evaluates principal, action, resource and request context before applicability. A
> Deny gated on `"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}` does not mean "S3
> denied" — it means "denied when that condition matches."
>
> And since the current parser discards `Condition` entirely, we cannot even
> establish applicability. So: an **unconditional, matching** Deny may be concluded.
> A conditional Deny stays `conditional`/`unknown`.

This is enforced in the DDL:

```sql
CONSTRAINT iga_access_edges_honesty_chk CHECK (
    effective_conclusion = 'unknown' OR calculation_state = 'complete')
```

**The wildcard case writes no resource row** — `"Resource": "*"` records breadth in
`native_scope` with `resource_id = NULL`. Expanding it per bucket would be
fabrication.

> But the **selector must still be preserved**. Two prefixes in one statement —
> `customers-a/*` and `customers-b/*` — are different facts. Wildcards should not
> manufacture resources; they should not erase each other either.

---

# Part 5 — Whose identity, and the join worth building for

## "What identity does this workload use?"

Every workload states its own role: Lambda `Role`, ECS `taskRoleArn`, EC2
profile→role, Bedrock `agentResourceRoleArn`, Pod Identity `roleArn`.

> **This is the *configured* identity, not a fact about what ran.** Running code can call `AssumeRole` for something else, receive credentials
> by another mechanism, or act through delegation — and ECS `RunTask` can **override**
> `taskRoleArn` at launch, so the task definition can disagree with what a running
> task holds.
>
> Model three distinct things: `configured_identity`, `runtime_observed_identity`,
> `delegated_identity`. Claiming live workloads eventually means reading clusters,
> services and task overrides, not just task definitions.

## "Is it an agent?" — judgement that stops at `pending`

Platform-labelled → confirmed. Framework in image or env → suspected. Behaves
autonomously → suspected. *Allowed* to call a model → supporting only, because
permission to do a thing is not evidence of doing it.

## The payoff

**Kubernetes discovery already knows** (running today, in
`discovery-agent/internal/sighting`):

```go
IdentityAnchor: fmt.Sprintf("system:serviceaccount:%s:%s", namespace, serviceAccount)
// → "system:serviceaccount:payments:refund-sa"
```

**AWS discovery knows** the role, that its trust policy names that exact string, and
what the role can reach. Neither side can answer *"what can this Kubernetes agent
reach in AWS?"* alone.

> **The subject matches byte for byte; the issuer does not.** The same issuer
> appears in at least three shapes:
>
> ```
> https://oidc.eks.us-east-1.amazonaws.com/id/ABC123      cluster metadata
> arn:aws:iam::123456789012:oidc-provider/oidc.eks…/ABC123  the IAM provider
> oidc.eks.us-east-1.amazonaws.com/id/ABC123:sub          the condition key prefix
> ```
>
> So: **the normalised subject matches byte for byte; the issuer is canonicalised to
> one host/provider identifier first.** Minor wording, and the difference between a
> join that works and one that silently never matches.

### IRSA and Pod Identity are two different mechanisms

Not one mechanism with two spellings:

| | IRSA | EKS Pod Identity |
|---|---|---|
| Path | pod → SA → OIDC token → IAM OIDC provider → `AssumeRoleWithWebIdentity` | pod → SA → Pod Identity Agent → association → `AssumeRoleForPodIdentity` |
| Trust names | `system:serviceaccount:ns:sa` via OIDC condition | `pods.eks.amazonaws.com` |
| Mapping lives in | the IAM trust policy | the **EKS association**, not IAM |
| Has an issuer | yes | **no** |

Pod Identity roles do **not** carry the service-account subject in their trust policy,
so the IRSA subject extractor finds nothing — correctly. Both must resolve to the same
Kubernetes workload without forcing Pod Identity through an OIDC shape.

### A Pod Identity association is not just a role pointer

The association carries three things that change what the pod can actually do, and
reading only `roleArn` overstates its access:

| Field | What it does |
|---|---|
| `policy` | A **session policy**. Effective permissions are the **intersection** of the role's policies and this one. |
| `targetRoleArn` | A second assumption. EKS assumes the association role, then uses those credentials to assume the target role — possibly **cross-account**. |
| `externalId` | Goes in the *target* role's trust condition; the same confused-deputy defence we use for our own onboarding. |
| `disableSessionTags` | Suppresses the session tags EKS appends, which some roles condition on. |

So the real shape is not `service account → role`, and there are **two** shapes, not
one:

```
WITHOUT targetRoleArn                    WITH targetRoleArn

refund-sa                                refund-sa
   │ eks_pod_identity                       │ eks_pod_identity
   ▼                                        ▼
association role grants                  association role  (its own grants intact)
   ∩ association policy                     │ sts:AssumeRole
   ▼                                        ▼
pod session ceiling                      target role grants
                                            ∩ association policy
                                            ▼
                                         target-role session ceiling
```

> **The association policy does not always restrict the association role.** When
> both `targetRoleArn` and `policy` are set, **the policy restricts the target role's
> session, not the association role's**. Applying the intersection at the wrong hop
> under-reports the association role and over-reports the target. So the edge carries
> a derived, never hand-set field:
>
> ```
> policy_applies_to = CASE WHEN target_role_arn IS NULL THEN 'association_role'
>                          ELSE 'target_role' END
> ```

**The failure this prevents.** A role granting `s3:*` and `dynamodb:*`, with an
association session policy of only `s3:GetObject`, would be reported as *"this agent
has DynamoDB write"* — when the pod's session structurally cannot exercise it. That
is exactly the semantic corruption this architecture exists to avoid, arriving
through the newest AWS mechanism.

So the assume edge must retain `association_arn`, `cluster`, `namespace`,
`service_account`, `role_arn`, `target_role_arn`, `session_policy`,
`policy_applies_to`, `external_id` and `disable_session_tags` — and the session
policy must reduce the reported ceiling **at the hop it applies to**, or the edge must
say the ceiling is `unknown`.

### Why this needs its own table

A trust-policy subject is often something we hold no record of —
`lambda.amazonaws.com`, a GitHub Actions identity, an unconnected cluster. It cannot
be a required foreign key, and `iga_access_edges.subject_id` is `NOT NULL`.

```sql
CREATE TABLE iga_assume_edges (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id        uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    identity_account_id uuid NOT NULL,
    mechanism           text NOT NULL,   -- irsa | eks_pod_identity | sts_assume_role | …
    subject_kind        text NOT NULL,
    subject_raw         text NOT NULL,
    oidc_issuer         text NOT NULL DEFAULT '',
    resolved_subject_id uuid,            -- NULL until the other side is found
    evidence_mode       text NOT NULL,
    first_seen_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz NOT NULL DEFAULT now()
);
```

**Unresolved is a normal, honest state** — not an error, and never something to guess.

---

# Part 6 — API design

The AWS source implements the interface that already exists —
`services/iga_provider.go:33` — with `iga_github_provider.go` as the working
reference. AWS maps `ListScopes` → account + regions; `ListNativeAgents` → Bedrock;
`ListIdentities` → roles, users, keys; `ListGrants` → policy statements.

The merged code shipped these under the existing discovery group with
`discovery:admin` / `discovery:read`, not under `/authsec/iga`. We adopt the shipped
paths (integration plan, D3). Shipped rows are marked ✔; the rest are additive.

| Method | Path | Does |
|---|---|---|
| ✔ `GET` | `/authsec/discovery/aws/onboarding` | Mints the ExternalId, returns the CloudFormation template |
| ✔ `POST` | `/authsec/discovery/aws/connectors` | Assumes the role, probes `GetCallerIdentity`, writes `cloud_connector`. **Change:** reject only on `required_to_connect`; an optional-family denial connects as `degraded` with that coverage `not_configured` |
| ✔ `POST` | `/authsec/discovery/aws/connectors/:id/verify` | Re-runs the probe |
| ✔ `POST` | `/authsec/discovery/aws/connectors/:id/scan` | `202`; today a fire-and-forget goroutine. **Change:** creates a `cloud_scan_run` row and returns its id; `409` if one is running |
| `GET` | `/authsec/discovery/aws/scan-runs/:run_id` | Run state, per-surface coverage, Access Advisor job state |
| `GET` | `/authsec/discovery/aws/connectors/:id/coverage` | Per-scope coverage with reason and last success — never one percentage |
| ✔ `GET` | `/authsec/discovery/aws/{identities,secrets,assume-edges,permissions,resources}` | Read views over `cloud_*` |
| `GET` | `/api/iga/v1/agents/:agent_id/access-paths` | Already exists for GitHub; lights up for AWS once the projection (plan, W2) writes `iga_access_edges` |
| `GET` | `/api/iga/v1/agents/:agent_id/evidence` | Canonical → correlation → observation → source object |

The last two make the product defensible: every number on screen traces to the API
call that produced it.

---

# Part 7 — Policy, and what "enforce" means

## 1. Evaluating

A rule over the graph. Four outcomes per subject: `present` (raise the finding),
`absent` (checked, genuinely fine), `unknown` (could not check), `not_applicable`.

**`unknown` must never render as clean.** "No finding" and "checked and safe" are
different statements, and conflating them tells the customer their estate is safer
than it is.

## 2. Remediating at the source

| Decision | Call |
|---|---|
| Remove a managed policy | `iam:DetachRolePolicy` |
| Remove an inline policy | `iam:DeleteRolePolicy` |
| Disable an access key | `iam:UpdateAccessKey(Status=Inactive)` — reversible |

**A separate write role.** Discovery stays read-only forever.

**Blast radius first**, from `identity_backing` *and* the attachment's
`consumer_count`.

**Verification is a read, not a response:**

```
proposed → approved → dispatched → source_acknowledged → verified
                                                       ↘ failed | drifted | canceled
```

`verified` is reachable only from the **next scan** finding the policy gone.

## 3. Runtime blocking — deliberately not this

Different product, different failure modes, named separately so it cannot creep in.

---

---

# What happens to this document

Parts 0–7 above are the **AWS domain reference**: what an IAM role, trust policy,
instance profile, condition key or policy selector means, and how those meanings
constrain any collector that reads them. That is the part nothing else documents,
and it stays.

The former Parts 8–9 — a build plan and a schema review with their own P0/P1/P2
numbering — are superseded. Delivery sequencing, the physical schema, coverage
states and acceptance gates now live in
[SPEC-iga-roadmap.md](SPEC-iga-roadmap.md), with the phase in flight in
[SPEC-iga-phase1-collect.md](SPEC-iga-phase1-collect.md).

Read this document for what AWS means. Read the roadmap for what we are building.
