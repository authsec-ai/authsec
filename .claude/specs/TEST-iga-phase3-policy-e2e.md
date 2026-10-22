# Phase 3 Policy — end-to-end test plan

Target: backend `authsec-staging` at `4fda6b5` (Ritam's P3 R1a + review fixes + the follow-up fixes), console `Authsec-ui` at `66585a9` with the Policy screens (`/iga/policy/...`). Both are deployed to production; the Policy gate was switched on there on 2026-10-12. A junior-friendly run sheet that follows this plan step by step is [`RUNBOOK-iga-phase3-policy-junior-test.md`](RUNBOOK-iga-phase3-policy-junior-test.md); this document is the case catalogue behind it.
Design reference: [`SPEC-iga-phase3-policy.md`](SPEC-iga-phase3-policy.md). Each case names the spec scenario it exercises where one exists.

**This plan is a checklist for a person to run. Nothing in it has been run yet.** The UI was rendered only against recorded backend responses; the backend's own tests ran only against fake AWS, GitHub and Slack. The purpose of this plan is the first run against real ones.

## 0. Rules for the run

- **Where this runs.** The owner (Aditya Agarwal) decided on 2026-10-12 to test on the production stack, in the workspace and AWS account named in the run sheet, accepting that the deployment-wide Policy gate is on for every workspace. Use only that workspace and that account. Never touch another customer's data. Environment A below is still the safer choice for the destructive cases (S9, S12.3) and for anything the owner has not approved.
- Use an AWS account you can break. The enforcement role writes IAM permission boundaries; undo works, but a mistake on a shared account is still a mistake.
- Never paste tokens, ExternalIds, Slack tokens or GitHub keys into this document, a ticket or chat. Evidence screenshots must hide them.
- Record each result as **PASS / FAIL / BLOCKED** with the evidence named in the case. A case that could not be run is BLOCKED, not PASS.

## 1. Environment

**A. Isolated stack (recommended).** A scratch PostgreSQL, the backend and the console running outside the customer cluster.

| Item | Setting |
|---|---|
| Database | New PostgreSQL 15+. Load `migrations/master/001_bootstrap.sql` (it carries everything through `059`). Never point at the deployed database. |
| Backend | `cp .env.example .env`, then set the database, `IGA_CURSOR_SECRET`, Vault (needed for the enforcement ExternalId, the GitHub App key and Slack tokens). Do **not** set `AUTHSEC_DISABLE_POLICY_WORKER`, `AUTHSEC_DISABLE_AWS_SCAN_WORKER` or `AUTHSEC_DISABLE_AWS_CFN_CALLBACK_WORKER`. `go run ./cmd/` listens on `7468`. |
| Reachability | AWS CloudFormation calls back to the backend, so the backend needs a public HTTPS URL for the enforcement and discovery stacks (a tunnel is fine). The same URL is the OAuth redirect for GitHub and Slack. |
| Console | `Authsec-ui` pointed at that backend (`VITE_API_URL`, `VITE_OAUTH_BASE_URL`). |
| Check | `GET /api/iga/v1/capabilities` shows a `policy` block with `state: "on"`. `enforcement` and `iac` are `true` only when the process has Vault, the AWS deployment environment and the GitHub App; a `false` carries its reason. |

**B. Customer cluster.** Blocked until a cutover decision exists. If one does, the release follows `SPEC-deployment-k3s.md`: schema rehearsal on a production schema copy, `pg_dump` backup, backend first, console second, verify the running commit.

## 2. Accounts and data

### 2.1 People (separation of duties needs three different humans)

| Persona | Needs | Used for |
|---|---|---|
| **Admin** | Workspace admin role (holds `governance:read/author/approve/enforce` through migration `055`) and `iga:admin` | Setup, settings, owners, everything |
| **Author** | `governance:read` + `governance:author` only | Creates policies. Must **not** be able to approve their own version |
| **Approver** | `governance:read` + `governance:approve` (+ `governance:enforce` for rollout) | Approves, accepts gates. A different person from the author |
| **Owner** | A verified human workspace member, assigned as owner of the test role | Owner review responses |
| **Viewer** | `governance:read` only | Confirms controls are hidden, not just failing |

Create these as real members (invite flow), not by inserting rows. Four browser profiles make the run easier.

### 2.2 AWS

- A non-production account with CloudFormation access.
- **A role AuthSec can recommend shrinking.** It needs grants to services it has not used for at least the evidence window. The default window is 90 days; set Setup › Settings › Default evidence window to **30** (the minimum) and use a role older than that. A newly created role will show "too early to say" instead of a finding; this is by design, so do not create the role the same day and expect a finding.
- Suggested shape: an IAM role used by one Lambda function that only writes to S3 and logs, with managed policies for S3, SQS, DynamoDB and EC2 attached. Expect S3 and CloudWatch Logs to be kept and SQS, DynamoDB and EC2 to be offered for removal.
- A **second role shared by two workloads** (two Lambdas) to exercise the shared-role paths, and a **role that no workload uses**.
- Write down: account id, role names, role ARNs. Put no credentials in this file.

### 2.3 The AWS discovery stack must be current

Resource-policy collection runs only when the account's discovery stack reports template version **2026-10-07 or later** (`ResourcePolicyTemplateVersion`, `internal/awsdiscovery/onboarding.go`). On an older stack every resource-policy form is recorded as *not collected: discovery template update needed*, no call is made, and AuthSec cannot trust the evidence enough to propose a change (`evidence_untrusted`). An account connected before that template, or connected by hand-entered role ARN (which records no stack version), needs its stack **updated in AWS** and a **new scan**. Do this first, then confirm the Connections page shows the scan finished and no *update needed* note. The graph's last publication must be after the update; an older publication has no resource-policy evidence.

### 2.4 Optional integrations

- **GitHub:** a GitHub App installed on a test repository with an infrastructure-as-code file that defines the test role (CloudFormation or Terraform). Needed for the pull-request delivery cases (§9).
- **Slack:** a Slack app and workspace you control. Needed for §6.5.

## 3. Test cases

Format: **Precondition → Steps → Expected → Evidence**. Console paths are under `/iga/policy`.

### S0 — Gate and navigation

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S0.1 | Start the backend. Open `/iga/policy` and `/iga/logs`. | Policy renders (no Preview tag on Policy or Logs). Before the schema verifies, Policy says it is not available here, with the reason; nothing errors. | Screenshot; `GET /api/iga/v1/capabilities` shows `policy.state`. |
| S0.3 | Open the retired routes `/iga/policies`, `/iga/upcoming`, `/iga/policy-warnings`, `/iga/enforcement`. | Each redirects to the matching new page. | URL after redirect. |
| S0.4 | As **Viewer**, open every Policy page. | Pages load. Buttons that need author, approve or enforce are absent or disabled with words; nothing is a bare 403. | Screenshot per page. |

### S1 — Setup

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S1.1 | Setup › Settings: change evidence window to 30, observation to 1 day, canary window to 1 hour, owner review 3 days. Save. | Saved; reload shows the same values. Out-of-range values (e.g. 5 days window) are refused inline. | Screenshot; `GET /api/iga/v1/policy/settings`. |
| S1.2 | Settings: switch mode to `enforce` with **no** reason. | Refused until a reason is given. With a reason it saves. Then switch back to `findings_only` for later cases that need it. | Screenshot. |
| S1.3 | Setup › Enforcement: pick the AWS account, **Enable enforcement**. | A link opens the AWS CloudFormation console with the stack prefilled. The page shows "waiting". | Screenshot of the AWS stack screen (hide ExternalId). |
| S1.4 | Create the stack in AWS. Click **Check now**. | The binding moves waiting → verifying → verified. The page lists the stack, enforcement role, self-test role and last verified time. | Screenshot; `cloud_enforcement_binding` row. |
| S1.5 | **Re-run self-test**. | Verifying, then verified again. | Screenshot. |
| S1.6 | Connections › the AWS account shows the Enforcement line. | Line reads the same state as Setup. | Screenshot. |
| S1.7 | Setup › IaC sources: map the repository and directory to the account. | The source is listed with its GitHub permission state. Deleting a source that already opened a pull request is refused. | Screenshot. |
| S1.8 | Setup › Notifications: add a webhook (https only) and toggle owner email. | Saved. An `http://` webhook is refused. | Screenshot. |
| S1.9 | Setup › Finding rules: add "Require a review date" for production workloads and, separately, one limited to Lambda functions (the Runtime list offers the kinds discovery really writes); add "Unused window" 60 days; turn one off; delete one. | The list updates; a window outside 30–400 is refused; a rule changes nothing until the next scan. | Screenshot; `iga_gov_finding_rule` rows; events in Logs. |
| S1.10 | Setup › Owner rules: add rule for tag key `owner`, applies to Roles and workloads, accountable. Tag a test role in AWS `owner=<a member's email>`, rescan. | The role shows that member as accountable owner ("From a tag rule"). A tag whose value is not a member's email, or matches two members, assigns no one and the role still reads "no owner". Deleting the rule removes the owners it assigned and leaves manual owners. | Screenshot; `iga_gov_owner_rule` and owner rows. |

### S2 — Scan and findings

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S2.1 | Connections: scan the AWS account and wait for completion. Open Overview. | Readiness shows counts from the server, each role counted once. A failed read is a banner with Retry, never zeros. | Screenshot; scan run row. |
| S2.2 | Findings: open the test role's finding. | Drawer states the claim in words: services unused, services used, kept, grant age, who uses the role, owners, trust of evidence. | Screenshot. |
| S2.3 | Compare with AWS. | The "used" and "unused" lists match what the role really did, within the evidence window. | A short note per service. |
| S2.4 | Findings for the role with **no owner**. | The drawer says a change cannot go to owner review until someone is assigned; **Assign owner** (Admin) works. | Screenshot. |
| S2.5 | As Author, **Except this finding…** with a date 10 days out and a reason. | Status shows Excepted with the date and reason; it stays out of new proposals. **Clear the exception** returns it to open. A date past a year, a blank reason, or a finding already under review is refused with the server's words. | Screenshot; event `finding.excepted` / `finding.exception_cleared` in Logs. |
| S2.6 | Remove a service's use in AWS (or add a rule) and rescan. | The finding changes at the next evaluation, not before. | Before and after screenshots. |

### S3 — Draft a policy

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S3.1 | From the finding choose **Generate tighter policy**. | The four-step flow opens; exactly **one** draft is created (check Policies). | `GET /api/iga/v1/policy/policies`; one row. |
| S3.2 | Step 1: keep one extra service. | A new version is saved; the removed list shrinks. | Version number increments. |
| S3.3 | Step 2 (Impact): read who runs as the role and who will be asked. | Workloads and owners match S2. Resource-policy routes are listed. | Screenshot. |
| S3.4 | Step 3: set observation 1 day, canary window 1 hour, pick the canary role, choose a delivery. | Deliveries that cannot run are disabled **with the reason** and the Setup page that fixes it. | Screenshot. |
| S3.5 | Step 4: review the summary and submit for review as **Author**. | Draft becomes "in owner review". Intent hash is shown. | Screenshot. |
| S3.6 | Refresh the browser mid-flow; reopen the link. | The same draft resumes; no second draft. | Policies list. |
| S3.7 | Open a link whose finding is already controlled by another policy. | Refused: "Another policy already controls this role". | Screenshot. |

### S4 — Owner review

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S4.1 | As **Owner**, open the review from the email/notification or `/iga/policy/reviews`. | The page states what would change for what the owner owns. | Screenshot. |
| S4.2 | Owner confirms the grant age and each resource-policy route, then responds. | The response is recorded. Silence is never treated as consent. | `iga_gov_owner_response` row. |
| S4.3 | A second owner objects or keeps a service. | A new version is created with that service retained; the earlier approval (if any) no longer applies. | Version list. |
| S4.4 | As Author, **Remind owners**. As Approver, **Record an exception** with a reason. | Reminder reaches only owners who have not responded. The version author cannot record the exception. | Event entries. |
| S4.5 | Let a review pass its deadline. | It shows overdue on the Overview and Reviews pages. | Screenshot. |

### S5 — Approval and separation of duties

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S5.1 | As **Author**, try to approve your own version. | Refused with "You cannot approve your own change". | Screenshot. |
| S5.2 | As **Approver**, open `/iga/policy/approvals`; open the version. | Plan, impact and evidence are visible. Evidence gaps and unanalysed items each need an individual acceptance with a reason. | Screenshot. |
| S5.3 | Approve with an item unaccepted. | Refused (`evidence_gaps_not_accepted` or `residuals_not_accepted`). | Screenshot. |
| S5.4 | Accept every item and approve. | Version is approved; the request body carries the plan hashes the server computed. | Network log shows `POST …/approve`. |
| S5.5 | Let an approval run past its validity (set approval validity to 1 day and wait, or shorten in the database of the scratch stack). | Rollout start is refused as expired; it needs a new approval. | Screenshot. |
| S5.6 | Change the version after approval (edit and save). | The earlier approval is revoked; a new approval is required. | Version and approval rows. |

### S6 — Rollout and canary

Run with **enforcement mode `enforce`** and a **verified binding** and delivery **direct**.

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S6.1 | Policy › Rollout › **Start the rollout** with delivery direct but enforcement off. | Refused: `enforcement_not_enabled`. Turn it on, retry. | Screenshot. |
| S6.2 | Start with the binding not verified (revoke it first). | Refused: `binding_not_verified`. | Screenshot. |
| S6.3 | Start the canary. | Observation period is shown first with its end date and "fresh report needed". After it, the canary role is deployed. | Rollout tab. |
| S6.4 | Watch the deployment. | States move `queued → applying → applied_unverified → verified`. The canary role has the AuthSec boundary attached in AWS. | `aws iam get-role --role-name <role>`, deployment row. |
| S6.5 | Check the five canary gates: artifact verified, no unexpected failures, required operations, no problem reports, window elapsed. | Each shows passed, failed, awaiting evidence or not available. | Screenshot. |
| S6.6 | A gate that is "not available": as the **version author** try to accept it; then as another Approver. | Author refused; the other approver can accept with a reason. | Screenshot. |
| S6.7 | **Pause** the rollout while another target is queued. | The queued deployment does not apply while paused. **Resume** continues. | Deployment states over time. |
| S6.8 | **Expand** to the remaining roles before the canary is healthy. | Refused or requires accepting the gate; it does not skip the health check. | Screenshot. |
| S6.9 | **Regression for A59:** after the canary is verified, run a new scan, then expand. | Expand still works and the approval is **not** revoked. | Approval row `revoked_at` is null; version stays approved. |

### S7 — Deliveries

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S7.1 | **Export:** choose export, deliver. Open the deployment; download the artifacts. | States reach `awaiting_apply`. Files are the plan's documents. After you apply them in AWS and rescan, state becomes `verified`. An unapplied export is reported overdue after the apply window. | Downloaded files; deployment state. |
| S7.2 | **Pull request:** choose iac_pr for the mapped role. | State `awaiting_merge`; a PR appears on GitHub changing the mapped file. The description does not claim "No permission is removed". | Link to the PR; screenshot. |
| S7.3 | Merge the PR. | State becomes `awaiting_apply`, then after you apply and rescan `verified`. | Deployment state. |
| S7.4 | Change the base branch after the PR opens, rerun. | The PR is updated to the approved change, or closed as superseded; no duplicate PRs. | GitHub. |
| S7.5 | Map **no** IaC source and choose iac_pr. | Refused with `iac_source_missing`, **not** silently turned into an export. | Screenshot. |
| S7.6 | A role defined in a form AuthSec cannot edit mechanically. | The Setup page lists it as Export-only, and the choice is made before any PR opens. | Screenshot. |

### S8 — Verification, drift, undo, removal

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S8.1 | Open a verified deployment. | Four dimensions are shown: artifact, graph, application health, restriction. | Screenshot. |
| S8.2 | **Validation:** run it with the role's own session. | Denied for removed services, allowed for kept ones. | Result rows. |
| S8.3 | **Health report:** submit a problem report on the canary. | The `no_problem_reports` gate fails and expand is blocked. | Screenshot. |
| S8.4 | **Drift:** in AWS, detach the boundary or edit the role outside AuthSec; rescan. | Deployment shows `drifted`; the policy shows the change; AuthSec does not silently overwrite. | Screenshot. |
| S8.5 | **Undo** a deployment. | Undo plan is read first; after confirming, state ends `undone` and the role is back as before. Blocked while a later deployment exists. | AWS role; state. |
| S8.6 | **Remove AuthSec control** (policy menu). | Controls to remove are listed; after confirmation the control is `removed`; the policy can then be archived. Archive is refused while the boundary is still on a role. | Screenshot; AWS. |
| S8.7 | **Emergency removal** with a reason. | Works for an approver without a fresh approval, and is recorded as emergency. | Event entry. |

### S9 — Failure handling (needs deliberate faults)

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S9.1 | Revoke the enforcement binding **while** a run is queued. | The next AWS write is refused; the deployment fails or blocks with the reason, not applies. | Deployment state; AWS unchanged. |
| S9.2 | Remove the enforcement role's permission mid-run (or block it with an SCP). | An attempt records the answer; the deployment does not claim success. | Attempts list. |
| S9.3 | If an outcome becomes unknown, the role stays locked, the console says so. **Resolve** it (re-read AWS or choose applied/not applied with a reason). | Role unlocks; the choice is recorded. | Event entry. |
| S9.4 | Kill the backend mid-deployment and restart. | AuthSec's two-minute sweep re-queues a deployment that has no job; the role is **not** locked forever. If it still shows `applying` and nothing moves, the deployment page offers **Queue it again…** (needs `governance:enforce`); it is refused with "still being worked on" while a job runs. A step that may already have reached AWS is checked, never sent twice. | Deployment state after restart; AWS call log shows no duplicate write. |
| S9.5 | Change the plan after approval, then try to deploy. | `plan_changed` or `impact_changed`; needs re-approval. | Screenshot. |
| S9.6 | Revoke the approver's `governance:approve` after approval, then start a **split**/removal deployment. | Refused; no stale approval deploys. | Screenshot. |

### S10 — Notifications and Slack

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S10.1 | Link Slack for Approver. | One link per member per Slack team. A link token forwarded by the Author and opened by the Approver is refused. | Screenshot. |
| S10.2 | Approve and reject from the Slack message. | Result matches the console; Slack replies within three seconds; replaying the same click does nothing. | Slack + approval row. |
| S10.3 | Disconnect Slack and reconnect to another team. | The old token stops working. If AuthSec cannot destroy the stored token, disconnect answers 502 `slack_token_not_destroyed`, the integration stays revoked, the status shows the destroy as pending, and disconnecting again retries it. | Slack; status view. |
| S10.4 | As a linked member who is **not** the deployment's owner and lacks `governance:author`, click a deployment or canary health-report button in Slack. | Refused; no `slack.action_received` event is written and the click is not consumed (a later authorized click still works). | Slack reply; Logs. |

### S11 — Logs, audit and secrets

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S11.1 | Open Logs after a run. | Policy events appear by kind (finding, deployment attempt, owner review, approval, rollout, drift, undo). Filters and export work. | Screenshot. |
| S11.2 | Search events and the export for an email address, the webhook URL, the ExternalId, a Slack token. | None appear. | `select payload from iga_gov_event where payload::text ~ '@|hooks|xoxb|ExternalId'` returns no rows. |
| S11.3 | Network log for any page. | No credential value appears in a URL query. | HAR. |

### S12 — Legacy and regression

| ID | Steps | Expected | Evidence |
|---|---|---|---|
| S12.1 | With a legacy agent policy present, open `/iga/policy/legacy`. | Listed read-only. **Pause** and **Remove** need `governance:enforce`; a workspace admin has it; a user with only `governance:admin` does not. | Screenshot. |
| S12.1b | A legacy agent that was reclaimed after a missed lease reports success late, once with the same `?pod=` it leased with and once without. | Only the matching holder's report is recorded; the other gets 409 and the instruction stays queued. (Agents that do not send `?pod=` do not get late successes recorded.) | HTTP status; instruction row. |
| S12.2 | GitHub connection, Kubernetes pages, OAuth/OIDC login, MCP, governance (old) pages. | Behave as before. | Short note per area. |
| S12.3 | Delete a **scratch** workspace that has events, acceptances and attempts. | Delete succeeds. (Scratch only. Never a real workspace.) | Workspace gone; no orphan `iga_gov_*` rows. |

## 4. Database checks (scratch only)

```sql
-- Where is each policy?
select p.id, p.name, p.lifecycle, v.version_no, v.status as version_status
from iga_gov_policy p join iga_gov_policy_version v on v.policy_id = p.id
order by p.created_at desc, v.version_no desc;

-- Deployments and their states
select id, kind, delivery, state, created_at from iga_gov_deployment order by created_at desc;

-- A role locked by an in-flight or unresolved deployment
select id, state from iga_gov_deployment
where state in ('applying','outcome_unknown','outcome_unresolved');

-- Approval still valid after a rescan (S6.9)
select id, decision, revoked_at, revoked_reason, expires_at from iga_gov_approval order by decided_at desc;

-- Event log without sensitive values (S11.2)
select count(*) from iga_gov_event where payload::text ~* '@|xoxb|external_?id|https://hooks';
```

## 5. Exit criteria

The plan passes when:
- every S0–S8 case is PASS, with S6.9 and S5.1 never FAIL;
- S9 and S10 cases are PASS or each BLOCKED with a named reason;
- S11.2 returns no sensitive rows;
- S12 shows no regression in GitHub, Kubernetes, OAuth/OIDC, MCP or governance.

Any FAIL in S5, S6.9, S9.1, S9.6, S10.1 or S11.2 blocks enabling Policy for a customer.

## 6. Clean-up

Revoke the enforcement binding (Setup › Enforcement › Revoke) and delete the CloudFormation stacks in AWS; remove the test roles and Lambdas; uninstall the GitHub App and Slack app from the test accounts; drop the scratch database.

## 7. Known limits of this plan

- It does not cover load or concurrency.
- GitHub Enterprise Server is not testable: the host allowlist (`AUTHSEC_GITHUB_ENTERPRISE_HOSTS`) exists, but the workspace GitHub App credentials and installation check are github.com-only.
- Real-account behaviour of the evidence window for a role younger than the window is described from the product's behaviour in recorded payloads, not from a live run; confirm it in S2.2.
- The backend fixes Ritam merged for the earlier review are verified separately (see the verification report); this plan tests them only through the cases named S5.1, S6.9, S9.1, S9.4, S9.6, S10.1, S11.2 and S12.3.
