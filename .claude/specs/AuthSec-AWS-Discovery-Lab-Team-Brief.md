# AuthSec AWS discovery lab — team brief

**Status:** single-account baseline; no Bedrock dependency. Proposed sandbox exercise, not verified scan results. **Updated:** 15 September 2026.

> Lab work is lettered **Exercise A–D** so it does not collide with the delivery
> phases in [SPEC-iga-roadmap.md](SPEC-iga-roadmap.md). An exercise validates
> collection against real AWS objects; it is not a delivery gate.

## Delivery scope and current blockers

| Exercise | Build / test | Entry criteria | What this does not prove |
|---|---|---|---|
| **A** — start now | One AWS account; real Lambda/ECS/EKS/EC2 identities, S3/DynamoDB/KMS, local STS role chains, policy conditions, duplicate grants, ownership and scan failure cases. Scripted tool calls replace model inference. | An authorized lab account and the necessary service quotas/network access. No Organization, Identity Center or Bedrock setup required. | Native AI-agent discovery, LLM behavior, cross-account authorization or SCP inheritance. |
| **B** — AgentCore extension | AgentCore Runtime deployment, version/endpoint, Gateway target for ticket-tools and one model-driven tool call. | Supported region, AgentCore permissions/quotas, and access to the chosen model. Check control-plane and runtime gates separately. | No new Agents Classic dependency; Organization coverage remains separate. |
| **C** — multiple-account extension | Cross-account discovery/trust/resource permissions; duplicate names across accounts. | Two separately authorized accounts are enough for cross-account IAM; they do not need to share an Organization. | SCPs, OU inheritance and organization-wide assignments. |
| **D** — Organization extension | Workloads/CustomerData/Security member scopes, OU/SCP inheritance and Identity Center account assignments. | Separate setup task: Organization with all features, suitable member accounts, SCP enablement and Identity Center organization instance. Existing management account can be additional. | These tests are deferred, not passed by Exercise A. |

The team currently has standalone accounts only. All detailed fixtures below describe **Exercise A** unless explicitly marked as an extension. Use one of those accounts first. No new accounts or Organization setup are on the baseline critical path.

**Simulation boundary:** business-agent records are operator-registered lab simulations (`execution_mode=scripted_fixture`). Their AWS roles, resources and API calls are real when deployed. Do not call a script a provider-discovered AI agent, and do not report scripted outputs as successful Bedrock/model tests.

## 1. Objective and customer scenario

Build a deliberately challenging AWS estate, scan it with AuthSec and measure whether we recover useful, evidence-backed identities, access relationships and governance findings. Do not simplify the estate around current backend capabilities: missing coverage and incorrect conclusions are the results we want to uncover.

Acme uses agents to investigate support tickets, prepare refunds and reconcile orders. Priya sponsors customer operations, Aditya is a support employee, and Maya owns the infrastructure. The estate includes shared roles, same-account role chains, conditional permissions, an undocumented workload and a retired agent.

This document contains the scenario, seed values, expected product displays and experiment sequence. The extensions are independent: another account can be added before Bedrock recovers; no phase waits on an unrelated dependency. IDs such as A01 and R02 are local fixture references. All customer records, credential values, dates and activity examples are synthetic. The hidden test manifest is ground truth for comparison, not evidence AuthSec may silently claim to have discovered.

**First viable outcome:** an evidenced support-agent → tool → role → resource path, the shared-role risk, an explained denied path, an ownership gap and an honest coverage report. Automated remediation is a later experiment.

## 2. Deployment inputs and boundaries

Use one dedicated sandbox account, synthetic data and lab-scoped permissions. Set a spend budget, provision compute only for the experiment and tear it down afterwards. Keep production infrastructure and credentials outside the lab. No Organization or Identity Center setup is required for this baseline.

| Scope label | Actual AWS account | Purpose |
|---|---|---|
| W — Workloads | `<LAB_ACCOUNT_ID>` | Workload resources |
| D — Customer Data | Same `<LAB_ACCOUNT_ID>` | Synthetic tables, buckets and KMS keys |
| S — Security/Audit | Same `<LAB_ACCOUNT_ID>` | Dedicated lab audit destination and discovery permissions |

**W/D/S are logical labels, not separate accounts, isolation boundaries or three integrations.** Use `EstateArea=Workloads/Data/Audit` tags. Every ARN uses the same resolved account ID. Use one ordinary multi-region CloudTrail trail with a lab audit bucket; no organization trail. Count audit infrastructure separately from the eight business data resources.

- Workspace: `ws-acme-lab` / **Acme Customer Operations Lab**; replace with actual AuthSec workspace UUID.
- Lab tag: `LabId=acme-iga-01`. Primary region: `us-east-1`; secondary: `us-west-2`.
- Resolve `<LAB_ACCOUNT_ID>` once and the bucket suffix `labunique` before deployment.
- Capture actual Lambda versions/aliases, roles, KMS keys, EC2 instances, ECS tasks, EKS associations and key IDs. AgentCore and Identity Center IDs are deferred; Classic IDs apply only to an eligible existing-account fixture. Capture role ARN **and RoleId** to detect replacement under the same name.
- Role ARN: `arn:aws:iam::<account>:role/<name>`; Lambda ARN: `arn:aws:lambda:<region>:<account>:function:<name>`; table ARN: `arn:aws:dynamodb:<region>:<account>:table/<name>`.
- Resolve image URIs, networking, job image and supporting deployment/logging permissions when writing IaC. Configure every simulated agent with `MODEL_MODE=stub`; it performs deterministic tool selection without making model calls. This is a populated design, not an executable Terraform or IAM bundle.
- Sample evaluation clock: **2026-09-15 12:00 UTC**, with activity coverage from **08:00–12:00 UTC**. Replace sample times with real evidence timestamps during the live run.
- Tag supported resources with `AgentId`, `Owner`, `Environment`, `ExpiresAt`. Preserve deliberate omissions. Tags assert ownership/expiry; they do not prove ownership or enforce expiration.

## 3. People, agents and workloads

| ID | Person / email | Business responsibility | Human record source | AuthSec membership |
|---|---|---|---|---|
| H01 | Priya Shah / priya@acme.example | Sponsor | Explicit lab registration | Reviewer |
| H02 | Aditya Rao / aditya@acme.example | Support employee | Application test identity | None |
| H03 | Maya Chen / maya@acme.example | Technical owner | Explicit lab registration | Lab administrator |

No Identity Center users, groups or account assignments are expected from AWS in Exercise A. Do not create IAM users to masquerade as discovered employees. Register Maya and Priya explicitly in AuthSec. For the lab application, authenticate Aditya with the application's test identity mechanism; never trust a caller-supplied name as authentication. Obtain separate sponsorship and technical-owner attestations for A01–A03; leave A05 unowned.

Human-to-ticket authorization is an application test with separately supplied evidence. Workforce federation, account access assignments and direct Bedrock-invocation bypass tests are deferred.

| Agent | Purpose / runtime | Instances | Evidence and tags | Business expiry |
| --- | --- | --- | --- | --- |
| A01 Customer Support Assistant | Read authorized customer tickets and attachments; Lambda orchestrator simulation | I01; I02 | Explicit lab registration + Lambda reference; Owner=priya@acme.example | 2026-12-31T23:59:59Z |
| A02 Refund Assistant | Prepare synthetic refunds through refund-tools; Scripted ECS agent fixture | I03 | Operator registration plus workload reference; tags alone are a claim; Owner=maya@acme.example | 2026-12-31T23:59:59Z |
| A03 Order Reconciliation Assistant | Read daily reports; no writes; Scripted EKS agent fixture | I04 | Operator registration plus Kubernetes workload reference; Owner=maya@acme.example | 2026-12-31T23:59:59Z |
| A04 Shadow Export Assistant | Reads synthetic attachments from an undocumented deployment; Scripted EC2 workload fixture | I05 | Ground truth only; initial AWS scan must show an unclassified workload; Owner missing | Unassigned / unknown |
| A05 Legacy Summary Assistant | Legacy attachment summarizer; Scripted Lambda agent fixture | I06 | Operator registration retained from baseline; Owner missing | 2026-09-14T00:00:00Z |

For A01–A03, Priya is the confirmed sponsor and Maya is the confirmed technical owner. A04 is an agent only in the hidden ground truth until evidence establishes its purpose. A05 is registered at baseline, then its Lambda is deleted during the mutation pass.

| Instance | Agent | Deployment | Scope | IAM binding |
| --- | --- | --- | --- | --- |
| I01 | A01 | Lambda support-orchestrator alias prod, version 2 / lab-production-simulation | W / primary | R01 / tool L01 |
| I02 | A01 | Lambda support-orchestrator alias staging, version 1 / lab-staging | W / primary | R01 / tool L01 |
| I03 | A02 | ECS service refund-agent, task definition refund-agent:1 | W / primary | R03 / execution R04 / tool L02 |
| I04 | A03 | EKS acme-lab / namespace operations / CronJob reconcile / service account reconcile-sa / schedule 0 2 * * * | W / primary | R05 → R06 |
| I05 | A04 | EC2 Name=support-app; instance profile ShadowExportProfile | W / secondary | R08 |
| I06 | A05 | Lambda legacy-summary | W / primary | R09 |

| Component | Deployment | Role | Operations / owner tag |
| --- | --- | --- | --- |
| L01 ticket-tools | Lambda / W / primary | R02 | getTicket; getAttachment; Owner=maya@acme.example |
| L02 refund-tools | Lambda / W / primary | R02 | prepareRefund; Owner=maya@acme.example |
| L03 support-app | Lambda frontend behind authenticated API / W / primary | R12 | authenticate human; check customer membership before requesting ticket; invoke support-orchestrator alias prod; Owner=maya@acme.example |

L03 runs behind an authenticated API. The lab application authenticates Aditya and checks customer membership before requesting a ticket. EC2 `support-app` is intentionally unrelated to the Lambda of the same name. Start the ECS service with one replica; repeated EKS job executions are not new business agents.

## 4. IAM identities and exact permission cases

| ID / IAM role | Logical area (same account) | Trust | Permission references / grants |
| --- | --- | --- | --- |
| R01 / SupportOrchestratorRole | W | lambda.amazonaws.com | lambda:InvokeFunction on L01; write own lab logs |
| R02 / SharedToolRole | W | lambda.amazonaws.com | P01; P02; P03; P04; P05 / boundary B01 |
| R03 / RefundTaskRole | W | ecs-tasks.amazonaws.com | lambda:InvokeFunction on L02; no model call |
| R04 / RefundExecutionRole | W | ecs-tasks.amazonaws.com | Pull lab image from ECR; Write task logs |
| R05 / ReconcilePodRole | W | pods.eks.amazonaws.com; AssumeRole and TagSession; restrict association/session conditions to acme-lab and operations/reconcile-sa | sts:AssumeRole on R06 |
| R06 / ReportsReaderRole | D | R05 only | P06; P07; P08 / tag Team=operations |
| R07 / RefundWriterRole | D | R02 only | dynamodb:PutItem on D02 |
| R08 / ShadowExportRole | W | ec2.amazonaws.com | s3:GetObject on BKT01/attachments/* |
| R09 / LegacySummaryRole | W | lambda.amazonaws.com | s3:GetObject on BKT01/attachments/*; secretsmanager:GetSecretValue on S02; no model call |
| R10 / LabWorkloadReadRole | W | R12 only | s3:ListBucket on BKT01 |
| R11 / LabDataReadRole | D | R12 only | dynamodb:DescribeTable on D02 |
| R12 / SupportAppRole | W | lambda.amazonaws.com | lambda:InvokeFunction on I01 qualified Lambda alias; sts:AssumeRole on R10 and R11 |

R05 is associated with EKS `acme-lab`, namespace `operations`, service account `reconcile-sa`. R02 is shared by L01 and L02. R10 and R11 have distinct names because IAM role names must be unique within this account. Cross-account identical-name testing is deferred. Runtime/logging permissions are resolved and recorded by IaC; no unstated permission should be treated as granted by the scanner.

| ID | Policy type | Subject / attachment | Rule | Condition / context |
| --- | --- | --- | --- | --- |
| P01 | managed | R02 | Allow dynamodb:GetItem; dynamodb:Query; dynamodb:PutItem on D01 |  |
| P02 | inline | R02 | Allow sts:AssumeRole on R07 |  |
| P03 | managed | R02 | Allow s3:GetObject on BKT01/attachments/*; BKT01/sandbox/probe.txt |  |
| P04 | inline | R02 | Allow s3:GetObject on BKT01/sandbox/probe.txt |  |
| P05 | inline | R02 | Allow s3:GetObject on BKT02/finance/* |  |
| P06 | managed | R06 | Allow s3:GetObject on BKT02/reports/* | {"StringEquals": {"aws:PrincipalTag/Team": "operations"}} |
| P07 | inline | R06 | Allow kms:Decrypt on K01 |  |
| P08 | inline | R06 | Allow s3:DeleteObject on BKT02/reports/* |  |
| B01 | permissions_boundary | R02 | Allow * on *; explicit Deny dynamodb:PutItem, UpdateItem, DeleteItem on D01 |  |
| RP01 | bucket_policy | R02 | Deny s3:GetObject on BKT02/finance/* |  |
| RP03 | bucket_policy | R06 on BKT02 | Deny s3:DeleteObject on BKT02/* | A real resource-policy deny; this does not test SCP semantics. |
| P09 | inline IAM policy | R01 | Allow lambda:InvokeFunction on L01 | Resolve the exact ticket-tools function ARN; no Bedrock service principal involved. |

Do not create an SCP or an organization condition for this standalone-account run. Restrict trust to the specified principals, and provision only the lab administrator access needed for setup. R07 trusts R02 and permits PutItem on D02; R06 trusts R05. A source role's permissions boundary does not become the assumed target role's boundary. Actual target permissions and controls still require evaluation.

**Legacy identity U01:** IAM user `legacy-export-bot` in W, allowed only `s3:GetObject` on `BKT01/sandbox/probe.txt`. Create two real keys in the lab, retain their secret material only in the deployment secret store, and deactivate C02. Never put real secret values into this document or AuthSec discovery.

| Credential | AWS principal | Status | Sample creation time | Observed use |
| --- | --- | --- | --- | --- |
| C01 | legacy-export-bot | Active | 2026-09-15T08:00:00Z | None in sample window; not proof of never used |
| C02 | legacy-export-bot | Inactive | 2026-09-15T08:00:00Z | None in sample window; not proof of never used |

Both keys have sample age four hours. Real AWS creation timestamps cannot be backdated; long-age testing needs elapsed time or separately labelled offline fixtures. IAM roles use temporary credentials and do not own these IAM-user access keys.

## 5. Resources and synthetic customer data

| ID | Resource / name | Scope | Encryption / authorization | Telemetry |
| --- | --- | --- | --- | --- |
| BKT01 | S3 bucket / acme-iga-attachments-labunique | W / primary | SSE-S3 | Enabled |
| BKT02 | S3 bucket / acme-iga-finance-labunique | D / primary | SSE-KMS; per-object key below | Enabled |
| D01 | DynamoDB table / acme-tickets | W / primary | ticket_id (String) | Enabled |
| D02 | DynamoDB table / acme-refunds | D / primary | refund_id (String) | Disabled intentionally |
| K01 | Customer-managed KMS key / alias/acme-reports | D / primary | Enable account IAM delegation; R06 policy allows decrypt | Management evidence where available |
| K02 | Customer-managed KMS key / alias/acme-restricted | D / primary | Lab administrator only; no R06 decrypt permission | Management evidence where available |
| S01 | Secrets Manager secret / acme/refund-sandbox | W / primary | Metadata only | Not used for usage claims |
| S02 | Secrets Manager secret / acme/legacy-summary | W / primary | Metadata only | Not used for usage claims |

S01 synthetic value=`NOT_A_REAL_TOKEN_REFUND_01`; S02=`NOT_A_REAL_TOKEN_LEGACY_01`. These are dummy setup strings. AuthSec displays secret metadata and consumers, never secret values. S01 intentionally has no seeded consuming workload. R09 references S02.

| Ticket ID | Customer | Subject | Status | Attachment |
| --- | --- | --- | --- | --- |
| 451 | C-ACME | Delivery delayed | open | attachments/451.txt |
| 452 | C-NORTH | Duplicate charge | investigating | attachments/452.txt |

Application membership: **Aditya (H02) → C-ACME only**. Seed refund `RF-001` for ticket `451`, amount `2500` minor units, currency `USD`, status `draft`. DynamoDB partition keys are string `ticket_id` for D01 and string `refund_id` for D02.

| Bucket / key | Synthetic content | Encryption |
| --- | --- | --- |
| BKT01/attachments/451.txt | Synthetic parcel status: delayed two days | SSE-S3 |
| BKT01/attachments/452.txt | Synthetic Northwind billing case; no real personal data | SSE-S3 |
| BKT01/sandbox/probe.txt | Duplicate permission test | SSE-S3 |
| BKT02/reports/daily.csv | order_id,total_minor<br>O-001,2500<br> | K01 |
| BKT02/reports/restricted.csv | record_id,classification<br>X-001,restricted<br> | K02 |
| BKT02/finance/payroll.csv | employee_ref,amount_minor<br>SYNTH-01,100000<br> | K02 |

Customer rows and object bodies populate the application, not AuthSec inventory. Object-to-KMS-key mappings require separate metadata evidence; bucket default encryption alone is insufficient. Log the selected S3, DynamoDB and Lambda data events before generating activity; deliberately omit D02 data events. Store audit logs in S with separately configured collection access.

## 6. Request scenarios and sample activity

```text
Aditya → support app → scripted support-orchestrator Lambda → ticket-tools Lambda
                                                           ↓ execution role
                                                DynamoDB ticket 452

Refund agent on ECS → refund-tools Lambda → SAME execution role as ticket-tools
                                              ↓ AssumeRole
                                  Same account, Data area: RefundWriterRole → refunds table

Scheduled EKS agent → service account → Pod Identity role → AssumeRole
                                      Same account, Data area: ReportsReaderRole
                                                  ↓
                                         S3 reports + KMS decrypt
```

The support application must enforce ticket-level human authorization. Seed ticket 452 as belonging to another customer and retain an application-level allow/deny log. AWS identity/configuration scans alone cannot establish whether Aditya is entitled to that ticket. Likewise, the manifest identifies custom agents; a Lambda, EC2 instance or role name alone does not prove an AI agent exists. All registered agents in this baseline are explicitly labelled as simulations.

The following are expected probe results, not executed events. Use a lab-controlled probe within the relevant workload/role context; retain AWS request IDs and actual results. Do not expand trust to arbitrary principals just to make a test easy.

| ID / sample UTC time | Caller | Request | Expected result | Evidence to retain |
| --- | --- | --- | --- | --- |
| E01 / 2026-09-15T10:00:00Z | H02 via L03 | ticket 451 | Application allow; L01 uses R02 for D01 GetItem | Application authorization log; DynamoDB data event |
| E02 / 2026-09-15T10:02:00Z | H02 via L03 | ticket 452 | Application denies before orchestrator invocation | Application authorization log only |
| E03 / 2026-09-15T10:04:00Z | I03 via L02 / R02 then R07 | PutItem RF-002 in D02 | AWS allows; refund data-event selector deliberately absent | STS management event; Tool execution log |
| E04 / 2026-09-15T10:06:00Z | I04 / R05 then R06 | GetObject BKT02/reports/daily.csv | AWS allows with Team=operations and K01 decrypt | STS management event; S3 data event; Probe result |
| E05 / 2026-09-15T10:07:00Z | R06 | GetObject BKT02/reports/restricted.csv | AWS denies; K02 decrypt not authorized | Probe result; Available S3/KMS events; do not assume they disclose exact denial cause |
| E06 / 2026-09-15T10:08:00Z | R02 | GetObject BKT02/finance/payroll.csv | AWS denies; RP01 explicit deny (also lacks K02 access) | Probe result; Policy evidence |
| E07 / 2026-09-15T10:09:00Z | R02 | PutItem in D01 | AWS denies due to B01 boundary | Probe result; Policy evidence |
| E08 / 2026-09-15T10:10:00Z | R06 | DeleteObject BKT02/reports/daily.csv | AWS denies due to RP03 | Probe result; bucket-policy evidence |
| E09 / 2026-09-15T10:12:00Z | I05 / R08 | GetObject BKT01/attachments/451.txt | AWS allows; identity use does not prove workload is an agent | S3 data event |
| E10 / 2026-09-16T10:15:00Z | R02 after P03 attachment removed | GetObject BKT01/sandbox/probe.txt | AWS still allows through P04 | IAM detach event; S3 data event; Probe result |

E10 is a mutation on the following day. Baseline counts and findings refer to the earlier snapshot. For an independent credential-use experiment, exercise C01 once and rescan; keep the unused baseline as a separate snapshot.

## 7. Governance policies to configure

| ID / name | Template | Parameters | Mode |
| --- | --- | --- | --- |
| GP01 / Every registered agent has accountable owners | owner_required | {"required_roles": ["sponsor", "technical_owner"]} | finding_only |
| GP02 / Review active keys older than 90 days | credential_age | {"max_age_days": 90, "status": "Active"} | finding_only |
| GP03 / Quarterly access review | review_overdue | {"max_days_since_review": 90} | finding_only |
| GP04 / Investigate access unobserved for 30 days | unused_access_review | {"window_days": 30, "require_sufficient_telemetry": true} | review_only |
| GP05 / Review expired agents | agent_expiry | {"expiry_source": "confirmed business expires_at"} | finding_only |

These are AuthSec governance rules, separate from AWS permission documents. GP03 is scoped to R02 → R07 `sts:AssumeRole`; seed synthetic review RV01, approved by Priya at `2026-06-01T12:00:00Z`. This is AuthSec history, not discoverable AWS evidence. All five policies initially create findings/reviews only; none disables AWS access automatically.

## 8. Expected AuthSec screens and results

### 8.1 Overview and integrations

For the **complete configuration scan plus explicit operator registrations**, show:

| Card | Expected display |
|---|---|
| AWS integration | Acme AWS Lab; **1 account**; 2 selected regions; W/D/S are tags only |
| Configuration coverage | Complete for the enumerated lab families **only if every required collection succeeded** |
| Activity coverage | Partial — refunds-table data events disabled; only 4 hours observed |
| Governed agents | **4 operator-registered simulations; 0 native Bedrock agents** |
| Unclassified workloads | **1**: EC2 `support-app` in us-west-2; AI purpose unverified |
| Agent instances | **5** associated with those 4 agents; the EC2 workload is separate until confirmed |
| Seeded IAM identities | **13**: 12 roles + 1 IAM user; display generated infrastructure and integration identities separately |
| Discovered humans | **0 AWS-discovered workforce users/assignments**. Three people exist as explicit application/AuthSec fixtures, not cloud-discovered identities |
| Credential metadata | 2 IAM keys: 1 active, 1 inactive; 2 secret metadata objects; no secret values |
| Governed data resources | **8**: 2 buckets, 2 tables, 2 KMS keys, 2 secrets; separate category from workload assets |

These are **seeded fixture counts**, not predictions of total AWS inventory. A Kubernetes CronJob is one workload with potentially many job/pod executions. Do not count each execution as a new business agent. Do not double-count IAM globals once per region.

If only AWS inventory is connected, initially show **0 confirmed native agents**. Display workloads and identity bindings; A01/A02/A03/A05 require explicit simulation registrations before appearing as governed agent fixtures. The hidden lab manifest must not silently become discovery evidence. Bedrock, Organizations and Identity Center coverage is “deferred/not configured,” not “successfully scanned with zero results.”

### 8.2 Agents page

| Display name | Evidence | Runtime/identity | Ownership after attestation | User-visible concern |
|---|---|---|---|---|
| Customer Support Assistant | Operator-registered simulation | Lambda prod v2 + staging v1; R01; tool L01 uses R02 | Sponsor Priya; technical owner Maya | Its tool shares a role capable of assuming RefundWriterRole |
| Refund Assistant | Operator-registered | ECS refund-agent:1; R03 task role; R04 execution role; L02 uses R02 | Priya / Maya | Shared tool identity; refund writes have incomplete telemetry |
| Order Reconciliation Assistant | Operator-registered | EKS operations/reconcile-sa; R05 → R06 | Priya / Maya | Conditional report reads; restricted-key dependency; delete blocked by bucket policy |
| Legacy Summary Assistant | Operator-registered | Lambda legacy-summary; R09 | Unassigned / unassigned | Business expiry passed; still deployed at baseline |
| EC2 support-app | Unclassified workload, **not confirmed agent** | us-west-2; ShadowExportProfile → R08 | Unknown | Attachment access observed; purpose and accountable owner need confirmation |

An `Owner=Priya` tag on the orchestrator and `Owner=Maya` on the tool is **ambiguous ownership evidence**, not automatically a violation. Explicit sponsor/technical-owner assignments resolve it without discarding either observation.

### 8.3 Support-agent detail and graph

Show this path, with source evidence on each relationship:

```text
Aditya → application authorization → support-app (R12)
                                      ↓ invokes Lambda alias
Customer Support Assistant [registered simulation]
  ├─ Lambda prod alias → version 2
  ├─ Lambda staging alias → version 1
  └─ support-orchestrator (R01) → ticket-tools Lambda → SharedToolRole (R02)
                                                        ├─ reads acme-tickets
                                                        ├─ reads attachments/*
                                                        ├─ assumes RefundWriterRole → writes acme-refunds
                                                        └─ finance/payroll.csv read: explicitly denied

Refund Assistant [registered simulation] → refund-tools Lambda → same R02
```

The business-agent-to-workload and call-relationship edges require explicit registration, runtime logs or deployment metadata. IAM invocation permission alone is a potential capability, not proof of an observed invocation. Lambda alias/version/configuration and execution-role bindings are native configuration evidence.

Label the same-account refund path **“Configured role capability; not proof the support tool exposes a refund operation.”** The Lambda code exposes `getTicket` and `getAttachment`; IAM may authorize more than the code currently implements. Do not invent a refund tool on the support agent.

Show `Lambda execution role`, `ECS task role` and `ECS execution role` as different relationship types. Add AgentCore runtime/gateway roles and configured identity references in the AgentCore extension; a Classic service role belongs only to an eligible legacy fixture. A role is an AWS identity account, not a human owner or automatically a business agent.

### 8.4 Access page

Display configured permission, constraints and observed outcome separately. “Allowed” below is the expected probe outcome once prerequisites are satisfied; before a real probe, label it **expected/unverified**.

| Caller | Action / target | Policy evidence | Expected outcome |
|---|---|---|---|
| R02 SharedToolRole | GetItem / acme-tickets | P01; B01 does not deny read | Allowed |
| R02 | PutItem / acme-tickets | P01 allows; B01 denies | Denied by boundary |
| R02 → R07 | AssumeRole then PutItem / acme-refunds | P02 + R07 trust + R07 permission | Allowed; R02 boundary is not inherited as R07's boundary |
| R02 | GetObject / finance/payroll.csv | P05 allows; RP01 denies; K02 also unavailable | Denied; report all known blockers |
| R06 ReportsReaderRole | GetObject / reports/daily.csv | P06 requires Team=operations; P07 permits K01 decrypt | Allowed for matching tag context |
| R06 | GetObject / reports/restricted.csv | S3 grant exists; K02 authorization missing | Denied; see encryption-evidence limitation below |
| R06 | DeleteObject / reports/daily.csv | P08 allows; RP03 denies | Denied by bucket resource policy |
| R02 | GetObject / sandbox/probe.txt | P03 and P04 independently allow | Allowed; still allowed after detaching P03 |
| R08 ShadowExportRole | GetObject / attachments/451.txt | R08 grant | Allowed; does not establish agent purpose |
| H02 Aditya | View ticket 452 | Not representable by cloud identity inventory alone | Application denies if L03 authorization is used; cloud inventory does not prove ticket authorization |

**Encryption evidence:** bucket default encryption does not establish every object's key. To explain the restricted.csv result, provide an operator-exported object-encryption metadata record or an explicitly authorized metadata probe identifying K02. With only bucket-level inventory, display “object encryption dependency unresolved”; never infer K02 from the hidden fixture.

**Human evidence:** ticket bodies, customer IDs and amounts are application seed data, not default AuthSec inventory. Show ticket 452 denial only if the application authorization log is integrated. An AWS role session alone does not identify Aditya's customer membership. No workforce permission-set assignment is seeded in this phase; direct human invocation of Bedrock is deferred. Application logs must be integrated separately to show this human-level decision.

### 8.5 Policies, findings and reviews

Configure **five governance policies**, using the five templates in Section 7. For the sample, scope GP03 to the R02 → R07 assumption grant; seed its last approved review as `2026-06-01T12:00:00Z`. That review is **106 days** old at the sample clock. A01–A03 ownership is explicitly attested; A05 is not. GP04 sees only four hours of telemetry.

| Policy | Sample display |
|---|---|
| GP01 owner_required | A01–A03 pass after attestations. A05 fails: sponsor and technical owner missing. EC2 remains outside registered-agent scope. |
| GP02 credential_age | C01 active, age 4 hours: passes 90-day limit. C02 inactive: not applicable. No invented old-key finding. |
| GP03 review_overdue | R02 → R07 review 106 days old: fails 90-day limit. Historical review is an AuthSec fixture, not AWS evidence. |
| GP04 unused_access_review | Unknown: insufficient 30-day observation window; D02 also lacks data-event coverage. No automatic revocation. |
| GP05 agent_expiry | A05 expired 36 hours ago: fails. A01–A03 not expired. Expiry alone has not disabled AWS access. |

Expected finding rows at baseline:

| ID | Finding | Basis | Suggested next action |
|---|---|---|---|
| F01 | Legacy agent lacks accountable owners | GP01; A05 ownership records | Assign sponsor and technical owner |
| F02 | Legacy agent business expiry passed | GP05; confirmed A05 expires_at | Review continued need or approve retirement |
| F03 | SharedToolRole access to RefundWriterRole overdue for review | GP03; stored review record | Assign Priya to recertify this specific grant |

Keep other discoveries visible without pretending the five templates detect everything:

- **Access-risk insight:** R02 shared by two tools and grants same-account refund capability. Ask Maya to assess role separation; severity requires business context.
- **Coverage issue:** refund-table usage unknown because data-event logging is absent.
- **Discovery queue:** classify EC2 support-app and establish ownership.
- **Architecture-review item:** verify the application checks Aditya’s customer membership before calling the orchestrator. Do not present this as an AWS-discovered entitlement or a proven bypass.

Do not report blocked finance access as successful exposure, an inactive key as active, or unused-in-four-hours access as unnecessary. Source changes remain “proposed,” not “remediated,” until authorized execution and verification occur.

### 8.6 Evidence and failure displays

Every graph edge, access result and finding should show source account/region, native ID, collection time, scan ID, evidence reference and freshness. Distinguish `configuration`, `observed use`, `operator assertion`, `AuthSec review` and `derived result`.

Example **illustrative normalized record**, not a raw AWS response:

```json
{
  "fixture_only": true,
  "subject": "R02",
  "action": "dynamodb:PutItem",
  "resource": "D01",
  "configured_grant": "allow",
  "known_restriction": "explicit_deny",
  "restriction_type": "permissions_boundary",
  "evidence_refs": ["P01", "B01"],
  "expected_probe_outcome": "deny",
  "observed_outcome": null,
  "verification_status": "not_run"
}
```

For `SCAN-LIMITED`, show: **Partial scan — secondary region excluded; GetRolePolicy denied for SharedToolRole.** Keep previous policies/edges with “stale, not revalidated.” Do not turn the missing data into zero permissions, a resolved finding or a deleted role. A successful API response with an empty list and a failed API call are different evidence.

### 8.7 Changes after mutations

| Change | AuthSec should display |
|---|---|
| Repeat unchanged scan | Same entity identities; refreshed observations; no duplicate findings |
| Detach P03 from R02 | P03 attachment removed; P04 remains; probe.txt access persists; attachment-prefix permission from P03 is removed |
| Remove legacy-summary Lambda | Instance no longer present after complete reconciliation; A05 history retained; R09 and S02 still exist. Describe them as lacking known consumers, not proven globally unused. |
| Confirm Priya/Maya ownership | Raw owner tags preserved; ownership ambiguity resolved through explicit roles |
| Remove Team=operations from R06 | P06 condition no longer satisfied for newly tested context; rescan and probe before claiming outcome |
| Recreate LabWorkloadReadRole | Same name/ARN but different RoleId; replacement recorded; LabDataReadRole unaffected |
| Disable data source or interrupt scan | Coverage degrades; evidence retained with freshness; no fabricated deletion |

**Lab acceptance:** compare seeded objects, relationships, constraints and evidence-backed conclusions independently. A correct “unknown” passes an insufficient-evidence case. A polished graph with unsupported edges fails.

## 9. Collection scope and execution sequence

| Evidence family | AWS entry points / expected data |
|---|---|
| Identities and permissions | IAM users, roles, trust documents, attached and inline policies, policy versions, boundaries, credential metadata. Organizations/SCPs and Identity Center collection deferred. |
| Workload bindings | Lambda versions, aliases, configuration and relevant invocation policies; ECS task definitions/tasks; EC2 instance profiles; EKS Pod Identity associations. Kubernetes workloads/service accounts require separately authorized Kubernetes API access. |
| Resources and dependencies | S3 bucket policies, encryption and tags; DynamoDB metadata/resource policies where configured; KMS policies; Secrets Manager metadata/resource policies. Do not collect secret values or customer records. |
| Observed use | Configured CloudTrail trails/selectors and available events, plus IAM last-used metadata. Application logs are separate evidence, not something a cloud inventory API supplies. |

Record counts **per account, region and object type**, pages fetched, failures, collection timestamps and retained policy documents. Compare discovered objects and relationships against the manifest; exclude AWS-generated infrastructure roles from the seeded-object denominator. Preserve unrecognized policy constructs as unresolved evidence.

### Experiment sequence

1. **Baseline:** deploy and record ground truth; scan all scopes. Repeat unchanged: IDs/counts should stay stable with no duplicates.
2. **Activity:** invoke every supported request path with synthetic inputs; capture caller/session identity, request IDs, timestamps and success/denial. Enable data events before calls; account for delivery delay. Compare observed usage with configured permissions.
3. **Mutation:** remove one duplicate grant, change one owner tag, retire the Lambda, replace a role under the same name, and rerun the scanner. Check change history, stale relationships and source identity replacement.
4. **Failure:** interrupt and resume a scan; remove an API permission/region scope; force pagination using a small page size where supported. Verify partial results, retry behavior and preservation of previously observed objects.

**First viable outcome:** one evidence-backed support-agent → tool → role → resource path, the shared-role exposure, one explained denied path, one ownership gap and an honest coverage report. Every conclusion links to source evidence. Unknowns are acceptable; confident wrong answers are failures. This experiment diagnoses discovery and interpretation before attempting automated remediation.

Record two scan profiles:

- **SCAN-BASE:** one `<LAB_ACCOUNT_ID>` including W/D/S-tagged resources; both selected regions; configuration complete only for explicitly enumerated API families. Four-hour usage window and D02 event omission mean activity coverage remains partial. Registrations and ownership attestations are separate inputs.
- **SCAN-LIMITED:** same account, primary region only; `iam:GetRolePolicy` denied for R02. Retain secondary-region evidence as out-of-scope/stale and inline-policy evidence as unreadable; do not label access revoked.

For every run, export a short scorecard: seeded objects found/expected by type, relationships recovered/expected, evidence available/missing, correctly explained allow/deny probes, correctly preserved unknowns, and backend errors. Exclude AWS-generated infrastructure identities from the seeded-object denominator while keeping them visible in inventory. Track data volume, pages, API failures and scan duration. This separates collection failures from normalization, graph and policy-evaluation failures.

Build in order: establish the single account scope and ground-truth IDs → deploy identities/data/workloads → collect a baseline → run activity probes → compare AuthSec screens → perform mutations/failure injection. Capture findings before changing the backend so the lab remains an independent benchmark.

## 10. Bedrock lifecycle, quotas and readiness

**Verified 15 September 2026:** AWS closed **Agents Classic** to new customers on July 30, 2026; core Bedrock remains supported. Accounts without qualifying prior use cannot create Classic agents, and AWS provides no exception process. This is a lifecycle restriction, not an outage to wait out. Existing eligible Classic workloads can remain a separate compatibility fixture. [AWS lifecycle notice](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-classic-maintenance-mode.html)

**Decision:** use AgentCore for new agent deployments. Do not schedule new Classic agent creation as a future recovery task. No failure message or account eligibility has been checked for this lab, so the documented lifecycle rule does not by itself diagnose every Bedrock error.

The earlier public-health check showed no open Bedrock incident in the selected US regions, but service health says nothing about Classic onboarding eligibility or this account's model access. [AWS Health](https://health.aws.amazon.com/health/status)

**Quotas are a separate gate.** Inspect the actual applied quota for the selected model, endpoint and region. AWS documents that account quotas can vary with regional factors, payment history and other considerations. It does not establish that all new accounts receive zero quota or guarantee that buying other AWS services unlocks it. If an applicable quota is zero or insufficient, use the supported quota-increase/support process; approval timing and outcome remain unknown. [AWS quota guidance](https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html)

| Gate / observed failure | Action and completion evidence |
|---|---|
| Classic creation rejected with maintenance-mode message | Change the new deployment target to AgentCore. No planned Classic reopening date to wait for. |
| AgentCore configuration readiness | Verify regional support, IAM and applicable quotas; deploy/list/get the selected runtime, endpoint, gateway and target. A successful listing does not prove model invocation. |
| Model access denied / insufficient quota | Check exact model ID, endpoint, applied quota and required entitlement. Submit the appropriate request; a different model is an option only after confirming its access and suitability. |
| Model invocation readiness | Make one minimal real inference request with a small output limit; save timestamp, request ID and result. AgentCore availability does not bypass the selected model's quota. |
| End-to-end readiness | Invoke the AgentCore-hosted support agent, observe the gateway tool call and ticket-tools Lambda's downstream read. Confirm identity attribution and application authorization. |
| 500 / 503 or throttling | Distinguish capacity errors from account quotas; use bounded retry and regional/account Health evidence. Escalate persistent failures with the exact request details. |

Keep Exercise A's scripted AWS probes running independently. AgentCore configuration testing may also proceed without proving inference; any deterministic execution must stay labelled as a simulation. Classic list/get evidence from an eligible existing deployment is optional compatibility coverage, not the new-account path. For all unresolved failures capture account/profile, region, model/API, exact error, timestamp and request ID. [Bedrock error reference](https://docs.aws.amazon.com/bedrock/latest/userguide/troubleshooting-api-error-codes.html)

## 11. Extension fixtures

### AgentCore extension — independent of Organization setup

Proposed code-defined deployment, using the existing support scenario:

| New fixture | Configuration to create | Evidence AuthSec should display |
|---|---|---|
| AC01 `acme-support-runtime` | Support agent code on AgentCore Runtime; real supported model when available | Native runtime identifier, version/endpoint, execution role, scope and collection time |
| AC02 `acme-support-gateway` | Authenticated Gateway with a Lambda tool target referencing L01 `ticket-tools` | Gateway/target identifiers, Lambda reference and configured authorization/credential mechanism |
| R13 `SupportAgentCoreRuntimeRole` | Permissions required for the chosen runtime, model and gateway access; scope to lab resources | A distinct AWS execution identity with source permission documents |
| R14 `SupportGatewayRole` | Gateway service execution role with the required permission to invoke L01 | Gateway-to-Lambda invocation capability; keep distinct from L01 execution role R02 |
| A01 association | Explicitly link AC01 to the existing support business-agent record | Deployment provenance and correlation decision; do not invent a second business agent or silently replace simulation history |

Expected configured/observed path, with evidence type on each edge:

```text
Authenticated support app → AgentCore support runtime (R13)
                          → AgentCore Gateway / ticket-tools target (R14)
                          → ticket-tools Lambda (R02) → acme-tickets
```

Runtime invocation and gateway authorization must both be configured for the chosen mode. Do not assume the gateway automatically enforces Aditya's ticket/customer ACL. The application-level check remains an explicit requirement. A runtime can host an agent or a tool, so a discovered runtime alone does not prove the business-agent classification. Resolve the runtime-to-gateway relationship through configuration, registration or execution evidence, not a naming guess.

AgentCore Runtime hosts code-defined agents/tools and supports versioned endpoints. Gateway can expose Lambda functions as MCP tools. These are separate provider objects from Classic agents, aliases and action groups; the scanner must collect the AgentCore surface explicitly. [Runtime documentation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agents-tools-runtime.html), [Gateway documentation](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway.html)

If added alongside Exercise A, the proposed custom-role count increases from 12 to 14. The registered business-agent count stays four when AC01 is explicitly correlated with A01. Add the native deployment, gateway and target to their own inventories; derive instance totals from the actual endpoint/version mapping. A real model-driven probe is required before removing the simulation-only label for that deployment. AgentCore's other optional services are outside this fixture.

### Cross-account extension — can use existing standalone accounts

Once two accounts are available with authorized setup access, place R06/R07 and customer data in the second account; keep callers in the first. Configure both trust and caller permissions plus resource/key policies where required. Test missing target-account visibility and identical IAM role names across accounts. **An AWS Organization is not required for ordinary cross-account IAM access.** This exercise adds a real account boundary that Exercise A cannot simulate.

### Organization and Identity Center extension — separate infrastructure task

Set up/enable an Organization with all features and the member-account topology, then configure OU/SCP policies and an Identity Center organization instance. Add Support/Platform groups and the three intended assignments: Support → Workloads agent-invoke permission set; Platform → Workloads metadata-read; Platform → CustomerData metadata-read. Priya/Aditya are Support members; Maya is Platform. This adds real workforce account access, not AuthSec membership.

Restore an OU-attached deny of `s3:DeleteObject` for the data bucket, retain the necessary allow baseline and test inherited SCP restrictions **in a member account**. Remove the overlapping RP03 deny for that isolated probe so the result demonstrates SCP enforcement. SCPs do not constrain the management account. Test organization discovery, account gaps and direct human agent-runtime invocation versus application authorization. [AWS SCP semantics](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)

**Exercise A cannot be reported as passing native AgentCore or Classic discovery, cross-account permission evaluation, SCP inheritance or Identity Center discovery.** Its value is real identity/resource collection, same-account access analysis and honest evidence handling.

## 12. AWS references

- [Agents Classic maintenance mode and eligibility](https://docs.aws.amazon.com/bedrock/latest/userguide/agents-classic-maintenance-mode.html)
- [AgentCore overview](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html)
- [Bedrock account quotas](https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html)
- [ECS role distinctions](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security-iam-roles.html)
- [EKS Pod Identity cross-account roles](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-assign-target-role.html)
- [AWS permission evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [Cross-account KMS authorization](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-modifying-external-accounts.html)
- [CloudTrail concepts and data-event coverage](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html)
