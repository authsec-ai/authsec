# AWS onboarding: Quick Create with automatic callback (rev 4, final and authoritative)

## Goal
Replace today's manual AWS IGA onboarding with Quick Create and an automatic callback. Today's steps are: download the YAML, upload it to CloudFormation, type in `AuthSecPrincipalArn` and `ExternalId`, wait, copy the `RoleArn` output, paste it back, and pick regions. After the change, the user picks their AWS Region(s), clicks **Launch in AWS**, ticks the IAM acknowledgement box, and clicks **Create stack**. AuthSec then finds out by itself and shows the status of each region.

What stays the same:
- `Onboard()` is reused unchanged, including its verification, the Vault write and the upsert.
- Scan, reconciliation, `LiveVerifier`, `ConfigForConnector`, `CreateConnector`, `VerifyConnector` and `RevokeConnector` are unchanged.
- `DiscoveryScanWorker`, GCP code and migrations are unchanged.
- The manual flow still works.

Out of scope: Organizations, StackSets, onboarding several accounts at once, an endpoint for editing regions, GovCloud and China.

This is Sumaya's AWS track. She should be briefed before coding starts and review the work before it merges.

The plan has three parts, kept apart on purpose:
- **Part A** lists facts checked against AWS documentation, each with its source.
- **Part B** lists the design decisions built on those facts.
- **Part C** lists what is still assumed and has to be proven in the spike before anything merges.

---

## PART A: VERIFIED FACTS

| # | Fact | Source | Consequence |
|---|---|---|---|
| F1 | The Quick Create URL is `https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/create/review?templateURL=…&stackName=…&param_{Name}=…`. Users can overwrite every value in the console | Quick-create links doc | The builder uses this exact format. Names that come back in the callback are never trusted |
| F2 | Quick Create **ignores `NoEcho` parameters** passed in the URL | Quick-create links doc | `ExternalId` (currently `NoEcho: true`, template L46) must lose `NoEcho`. There can be no NoEcho token |
| F3 | `templateURL` must be an S3 URL, in one of these forms: `https://s3.{region}.amazonaws.com/{bucket}/{key}`, `https://{bucket}.s3.{region}.amazonaws.com/{key}`, or the legacy `s3-{region}` form | Quick-create links doc | The template is hosted in S3 and must be publicly readable, because customers aren't known in advance. The docs don't say whether the bucket can be in a different region from the stack; a third-party answer suggests it may have to match → **S1** |
| F4 | A custom resource's `ServiceToken` (an SNS topic or Lambda function) **must be in the same region as the stack**. It can be in another account. A topic in another region fails with `InvalidParameter` | CustomResource reference; APN blog; Mozilla issue #5 | AuthSec needs one topic per region it supports as a deployment region |
| F5 | `ServiceTimeout` can be 1–3600 seconds. The default is 3600 | CustomResource reference | Set it to 600, so a missing response fails the stack in 10 minutes |
| F6 | A request carries `RequestType`, `RequestId`, `StackId` (an ARN containing the region and account), `ResponseURL` (a presigned S3 URL), `ResourceType`, `LogicalResourceId` and `ResourceProperties`. Update and Delete requests also carry `PhysicalResourceId`. `(StackId, RequestId)` uniquely identifies a request | Request/response reference | These fields are the idempotency key and the context checks |
| F7 | The response is at most 4096 bytes. `StackId`, `RequestId` and `LogicalResourceId` must be copied verbatim. `PhysicalResourceId` must be non-empty and **identical in every response for the resource**; changing it on Update makes CloudFormation treat the Update as a replacement and send a Delete. With no response, CloudFormation waits until the timeout, then fails | Request/response reference | `PhysicalResourceId` is fixed at `authsec-{sessionID}` |
| F8 | A stack Delete succeeds only if the provider answers the Delete request with SUCCESS | SNS-backed custom resources doc | AuthSec must always answer Delete with SUCCESS |
| F9 | The response bucket host looks like `cloudformation-custom-resource-response-uswest2.s3-us-west-2.amazonaws.com`, with the region written **without dashes** in the bucket name | AWS Lambda/CloudFormation example; search result showing `…-useast1.s3-us-east-1…` | The host allowlist is built from real captured examples (**S3**) |
| F10 | SNS can deliver to SQS in another region. When one side is an **opt-in region**, the queue policy needs a region-specific principal: `sns.{topic-region}.amazonaws.com` for an opt-in topic delivering to a default region. The subscription is created in the topic's region | SNS cross-region delivery doc | Use one central queue. Opt-in deployment regions need extra policy work, so phase 1 excludes them |
| F11 | STS regional endpoints in opt-in regions work only if the region is **enabled**, and a call is checked against the account whose credentials make it. SDK v2 uses regional STS endpoints | IAM STS regions doc | See F12 |
| F12 | *(From the code.)* A scan builds each region's config through `ConfigForConnector(region)`, which leads to `LiveVerifier.Config` with `WithRegion(r)` and then AssumeRole at `sts.{r}` **using AuthSec's own base credentials** (`onboarding.go` L178–209, `cloud_aws_onboarding.go` L363–392) | Code | **Scanning an opt-in region needs that region enabled in AuthSec's account as well as the customer's.** This is how the existing scan behaves, and it is not being changed |
| F13 | AWS positions the external ID as a guard against the confused-deputy problem, not as a secret, and it can be read in the role's trust policy | IAM docs; template L88–95 | Dropping `NoEcho` exposes nothing new that matters |
| F14 | A known production pattern (Mozilla `cloudformation-cross-account-outputs`) uses a topic policy of `Principal: {AWS: "*"}`, `SNS:Publish` and **no condition**, with one topic per region. AWS's APN blog suggests allowlisting customer accounts instead, but that needs the account ID before launch, which is exactly what this design avoids asking for | Mozilla template; APN blog | The topic is effectively open. Narrowing it is tested in the spike (**S2**), and trust never depends on it |
| F15 | *(From the code.)* `Verify` already runs AssumeRole with the ExternalId, then `GetCallerIdentity`. `Onboard` checks that the identity's account matches the ARN's account (L242), writes Vault only after AWS succeeds, and upserts by `(workspace, account)`. `maxRegionsPerConnector = 32`. `awsOnboardingTimeout = 45s` | Code | Reuse all of this unchanged |

---

## PART B: DESIGN DECISIONS

### B1. Region model
- **Deployment region:** where the one stack is created. It must be a *supported deployment region*: a default-enabled commercial region with an AuthSec topic.
- **Scan regions:** the connector's `regions`. The role is global, so scan regions need no callback infrastructure.
- **One active connector per account per workspace** (the existing upsert). Each launch creates one stack and one role. **Older stacks and roles from earlier launches can remain** in the customer's account.

**Opt-in regions, stated explicitly:**

| Region kind | As the deployment region | As a scan region |
|---|---|---|
| Default-enabled commercial | Supported if the region is in the topics map | Supported |
| Opt-in commercial (af-south-1, ap-east-1, me-south-1, il-central-1, …) | **Not in phase 1** (F10: region-specific queue principal, and a topic in an opt-in region AuthSec would have to enable) | Supported **only if the region is listed in `AUTHSEC_AWS_OPTIN_SCAN_REGIONS`**, the opt-in regions AuthSec's own account has enabled (F12). Regions not on that list are shown but disabled in the picker, labelled "Not yet supported by AuthSec". For a listed region, the customer's account must also have it enabled; if it doesn't, the regional probe reports "Not reachable — enable this Region in your AWS account" |
| GovCloud / China | Not supported | Not supported. The automatic flow isn't offered; the wizard offers the manual flow, with a warning that it needs an AuthSec principal in that partition |

The deployment region comes first in `regions`. `Onboard` probes `regions[0]`, and the deployment region is the one most certain to work.

### B2. Correlation
- There is **no separate token.** The `ExternalId` is minted fresh for each session with the existing `MintExternalID`, and is HMAC-bound to the workspace.
- It correlates the callback: the worker looks up `aws:onb:ext:{sha256(ExternalId)}` to get the session ID, then runs `VerifyExternalIDBinding`.
- A separate token would add no secrecy. It would travel in the same URL and sit in the same stack parameters (F2).

### B3. Callback transport
- **One SNS topic per supported deployment region**, in AuthSec's callback account, with a policy that allows only `sns:Publish` (policy choice in **S2**).
- **Every topic delivers to one central SQS queue** in AuthSec's home region, with a DLQ. This is cross-region SNS→SQS (F10).
- The queue policy uses `Principal: {Service: sns.amazonaws.com}` and allows only when `aws:SourceArn` is one of the topic ARNs.
- **Raw message delivery stays off**, so `TopicArn` arrives in the envelope.
- **Separate topics and queues per AuthSec environment** (staging and prod), with names that include the environment.
- **No public webhook**, so there is no SNS signature or subscription-confirmation code to write.

### B4. Order of callback processing
1. Validate the message and the session (B6 steps 1–5).
2. **`Onboard()`**, inside a bounded retry for IAM propagation: about 90 seconds in total, with backoff, modelled on `onboardWithVerificationRetry`.
3. **PUT SUCCESS or FAILED** to `ResponseURL`. The PUT is retried up to 3 times within the attempt.
4. **Regional probes run after the PUT**, so the customer's stack isn't held up. Each one calls `verifier.Verify(Region: r)`, which is exactly the path a scan takes (F12). "Connected" therefore means a scan will work there. Probes run in parallel, at most 8 at once, with a 20-second timeout each.
5. Write the session status and each region's status to Redis.

### B5. Re-onboarding: resolved technically; old stack cleanup is customer-managed
- **Each session has its own names.** A per-session `suffix` (8 random base32 characters) gives the stack name `AuthSec-Discovery-{suffix}` and `param_RoleName=AuthSecCloudDiscovery-{suffix}`. No stack fails because a role name is already taken.
- **Reconnecting an account that is already connected** makes `Onboard` upsert, so the connector moves to the new role and ExternalId. The old role still trusts AuthSec, but with an ExternalId AuthSec no longer holds, so AuthSec can't use it. The UI shows a replaced-role notice built from `previous_role_arn`, which comes from a read-only `GetByScope` before `Onboard`.
- **Cleanup belongs to the customer.** The notice suggests `AuthSec-Discovery-{old suffix}` as the old stack's name, or says "the stack you created" if the old role name had no suffix or was edited. AuthSec never deletes anything in the customer's account.
- **"Launch again" always starts a new session.** A stack that rolled back keeps its name (`ROLLBACK_COMPLETE`), so reusing the name would fail.
- **Changing only the regions** needs no relaunch. That endpoint isn't part of this plan: it is **Phase 2 task T2.1** (`GET /aws/connectors/:id/regions`, `PATCH /aws/connectors/:id`, in `.claude/specs/SPEC-iga-phase2-graph.md` §5.3). Once T2.1 ships, the Connected screen links to it.

### B6. The trusted sequence
Each step rejects cheaply, before any call to AWS.
1. **Envelope.** `IsOurTopic(TopicArn)`, a well-formed event, `LogicalResourceId == "AuthSecRegistration"`, and `ResourceType == "Custom::AuthSecRegistration"`.
2. **ResponseURL.** Scheme `https`. No userinfo. Port empty or 443. The **host must exactly equal one of the hosts in the fixture-derived allowlist for `region(StackId)`** (see B7). The path must be non-empty, and the query must hold a presigned signature (`X-Amz-Signature`, or `Signature` + `Expires`, whichever S3 confirms). If validation fails, the URL is **never contacted** and the message goes to the DLQ with an alarm; it is not silently dropped.
3. **Session.** Look up `sha256(ExternalId)`, confirm the session is live, and run `VerifyExternalIDBinding(session.ws, ExternalId)`. If this fails, PUT FAILED: "Onboarding link expired or unknown — start again in AuthSec". CloudFormation then rolls back and deletes the role, which cleans up by itself.
4. **Session-held values only.** The workspace, the regions and the ExternalId all come from the session.
5. **Stack context.**
   - `region(TopicArn) == region(StackId) == session.deployment_region`.
   - `account(StackId) == account(RoleArn)`.
   - The partition is `aws`.
   - Names are *not* enforced (F1).
6. **AssumeRole with the ExternalId**, through `Onboard()` and then `Verify`.
7. **GetCallerIdentity**, inside `Verify`.
8. **Confirm the account.** The existing L242 check covers identity against the ARN; a new check covers identity against `account(StackId)`.
9. **Complete.** Vault write and upsert (existing), consume the session, PUT SUCCESS.

**Consumption and idempotency**
- A per-session Redis lock (`SET NX`, 5 minutes) keeps two workers from handling the same session at once.
- A repeat of the same `(StackId, RequestId)` gets the stored result PUT again, with no second `Onboard`.
- For a session already consumed:
  - the same account and role → SUCCESS, with no `Onboard`;
  - a different account or role → FAILED: "This AuthSec launch link was already used".
- A callback that arrives after a manual paste in the same session hits the existing idempotent upsert and gets SUCCESS.

**Delete** (including the Delete CloudFormation sends during rollback): always SUCCESS, even for an unknown or expired session. It never changes anything, because a forged Delete must not be able to cause harm.

**Update:** SUCCESS with the same `PhysicalResourceId`, and nothing changes.

**Limiting forged messages:** at most 5 attempts per session, plus the cheap rejections above, plus a DLQ alarm.

**Remaining exposure** (accepted and documented):
- Anyone who learns a live session's ExternalId within its 1-hour TTL, before it is used, could attach **their own** account to the victim's workspace. That pollutes the victim's data; it gives no access to the victim's account.
- Mitigations: the session is used once only, the Connected screen shows the account ID, the values travel in the URL fragment (after `#`, so they're never sent in a Referer header), and the existing revoke route can remove the connection.

### B7. ResponseURL host allowlist, tied to captured fixtures
- `CFNResponseHosts(region)` returns only host forms **seen in real, captured, sanitised ResponseURLs**, stored as test fixtures under `internal/awsdiscovery/testdata/cfn_response_urls/`.
- The one form known before the spike is `cloudformation-custom-resource-response-{regionNoDashes}.s3-{region}.amazonaws.com` (F9).
- The spike captures real ResponseURLs in **us-east-1** (the legacy region, which may use `.s3.amazonaws.com`) and **ap-south-1**. It checks each form in CI.
- A form that no fixture shows stays out of the allowlist. A new region is supported only once a captured fixture shows its form, or it matches a form already confirmed.
- If a real callback arrives with a host not on the list, the message goes to the DLQ and raises an alarm. Someone reviews it and adds the new form along with its fixture. There is no pattern-based fallback.

### B8. Template (`internal/awsdiscovery/authsec-aws-discovery-role.yaml`)
- **`ExternalId`: remove `NoEcho`** (F2, F13). Its length and pattern constraints stay. Change the parameter group label to "Filled in by AuthSec — do not change".
- **Add `CallbackTopicArn`**, default `""`, with the pattern `^$|^arn:aws:sns:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]{1,256}$`.
- **Add the condition `HasCallback`.**
- **Add the resource `AuthSecRegistration`**, type `Custom::AuthSecRegistration`, only when `HasCallback` is true:
  - `DependsOn: AuthSecDiscoveryRole`
  - `ServiceToken: !Ref CallbackTopicArn`
  - `ServiceTimeout: 600`
  - Properties: `RoleArn: !GetAtt AuthSecDiscoveryRole.Arn`, `ExternalId`, `AccountId: !Ref AWS::AccountId`, `TemplateVersion`
- **Unchanged:** the role, the trust policy, the `RoleName` parameter (default `AuthSecCloudDiscovery`) and the `RoleArn` output. The manual flow is unaffected.
- **Bump `TemplateVersion`** and publish the template, byte-for-byte, to a versioned, immutable, publicly readable S3 key.

### B9. UX
1. The wizard reads `GET /aws/onboarding`, which now includes the `automatic` block: `enabled`, `supported_deployment_regions`, `default_deployment_region` and `optin_scan_regions`. If `enabled` is false, it shows the manual flow.
2. **AWS Region(s):** a multi-select that starts empty. Help text: "Which AWS Regions should AuthSec scan? This is the AWS Region of your resources, not your location."
   - It lists the curated `AWS_REGIONS` (L73) plus the opt-in regions from the server, marked "(opt-in)".
   - Opt-in regions AuthSec doesn't support appear disabled.
   - The existing note about scan cost stays.
3. **Validation**, in the browser and again on the server: at least one region, a single partition, and every opt-in region must be allowed. If GovCloud or China is selected, the wizard offers the manual flow before any launch.
4. **Review:**
   - the regions;
   - the permissions summary;
   - "Stack will be created in **{deployment region}** (change)";
   - "Sign in to the AWS account you want to connect first. Don't switch Regions in the console."
5. **Launch in AWS:** the wizard POSTs a new session and opens **one** tab.
6. **In AWS:** the user ticks "I acknowledge that AWS CloudFormation might create IAM resources **with custom names**" (required because `RoleName` is set) and clicks **Create stack**.
7. **Waiting:** "Waiting for your stack in {region}…", polling every 3 seconds. The page offers four actions: reopen the link, open the CloudFormation console, "Paste Role ARN instead" (the existing `POST /connectors`, using the session's ExternalId), and "Start over" (a new session).
8. **Result:**
   - the account ID;
   - a table of each region's status: ✓ Connected (stack region) / ✓ Connected / ⚠ Not reachable, with a reason;
   - the replaced-role notice, when the account was already connected (B5).
9. **Timeout (about 15 minutes):** a troubleshooting list:
   - the stack failed or rolled back;
   - the user is signed in to the wrong account;
   - the user switched region or edited `CallbackTopicArn`;
   - the deploying principal lacks `sns:Publish` (**S5**).

   The page also offers Paste ARN and Start over.

### B10. Callback infrastructure is permanent (found in the 2026-09-24 review)
- **Once any customer stack uses a topic, AuthSec must keep that topic and the worker running for as long as the stack exists.** If the topic is gone, CloudFormation can't publish a Delete to it. If the worker is down, nobody answers the Delete. Either way the customer's stack delete waits `ServiceTimeout`, then fails with `DELETE_FAILED`, and they have to retry with "retain resources".
- **Topic ARNs never change.** Topics are never renamed or recreated. A `ServiceToken` can't be updated in place (CustomResource reference: "Update requires: Replacement"). A new ARN would cause a Create followed by a Delete on every customer's next stack update.
- The runbook in `docs/flows/aws-cloud-discovery-onboarding.md` states both rules. Retiring a region's topic needs a documented migration first.

### B11. Coordination with the Phase 2 spec (commits `82e8a8a` and `d9741e7`; not built yet)

**Shared files.** Phase 2 tasks edit the same files as this plan:
- **T2.1** edits `services/cloud_aws_onboarding.go` and `controllers/platform/cloud_aws_controller.go`.
- **T2.4** edits `authsec-aws-discovery-role.yaml` and `permissions.go`, and bumps the template version.
- **T7.9** edits `AWSOnboardingWizard.tsx`.

This plan only *adds* functions to the service and the controller, so the risk of conflicts there is low. The template and the wizard need an agreed order.

**One template version bump each, in order.** Whichever change merges second rebases onto the first and bumps `TemplateVersion` again. The template tests in both changes must pass on the combined YAML.

**Stack updates are safe.** The spec's coverage view tells customers on an older template to "Update the CloudFormation stack":
- An automatic-flow stack updated to a new template changes the `TemplateVersion` property. CloudFormation then sends **Update** to AuthSec, and B6 answers SUCCESS with no change.
- A manual-flow stack updated to a new template keeps `CallbackTopicArn` at `""`, so `HasCallback` is false and no custom resource is added.
- `RoleName` keeps its previous value in both cases, so the role isn't replaced.

**Open follow-up for Sumaya and Aditya (not in this plan).** The Update message could set the connector's recorded `TemplateVersion`, so the "Update the stack" hint clears after the customer updates. Update messages can be forged, so this would need the ExternalId to match the value in Vault and a successful `Verify` first. It stays out of scope until the owners decide.

**Feedback for the Phase 2 spec.** T2.1 validates `PATCH` regions against `ec2:DescribeRegions`, which covers the **customer's** enabled regions. F12 shows that a scan of an opt-in region also needs the region enabled in **AuthSec's** account. T2.1 should check `AUTHSEC_AWS_OPTIN_SCAN_REGIONS` too; otherwise a region can be selected that will always fail.

**Optional reuse.** When T2.1's `DescribeRegions` helper exists, `CompleteFromStack` can use it to label an opt-in region "not enabled in your account" with certainty, instead of inferring that from a failed probe. The plan doesn't depend on it.

---

## ERROR HANDLING

### EH1. Principles
1. **Every failure has four answers:** how AuthSec *notices* it, what AuthSec *does*, what the *user sees*, and how to *recover*. A failure without all four is a bug in this plan.
2. **Classify before reacting:**
   - **Customer-side permanent:** wrong ExternalId, trust mismatch, the account in the ARN doesn't match the account the role resolves to, the session was already used. AuthSec answers FAILED quickly, and CloudFormation rolls the stack back, which deletes the role.
   - **AuthSec-side temporary:** Redis, Vault, the database, AuthSec's own AWS credentials, STS throttling, a worker restart. AuthSec **retries until the stack's deadline**, then answers FAILED with an "AuthSec side, try again" reason and alerts on-call. The customer should not lose a stack because of AuthSec.
   - **Malformed or forged:** the message goes to the DLQ, the ResponseURL is never contacted, and on-call is alerted.
3. **Deadline:** `deadline = SNS envelope Timestamp + 540s`, which is 60 seconds of margin before `ServiceTimeout: 600`. Every retry loop stops at the deadline, and AuthSec still sends a final FAILED before the stack times out.
4. **Stable error codes** of the form `aws_onb_*`. Each code appears in the session status, the CloudFormation `Reason` string, the logs and the UI copy. UI text reuses the existing `awsErrorCopy.ts`, the file the wizard already imports.
5. **`Reason` strings must be readable by the customer.** They appear in the customer's stack events. They are under 256 characters, carry the short session ID so support can trace them (`AuthSec ref: 1a2b3c4d`), and **never contain internal details**.
6. **Onboarding never depends on the browser.** Closing the tab doesn't stop onboarding: the callback completes on the server, and the connector appears in the Connections list.

### EH2. Session state model (Redis)

```
pending ──callback accepted──▶ verifying ──Onboard ok──▶ connected ──probes──▶ connected (region_status filled)
   │                              │  └─customer-permanent──▶ failed(code)
   │                              └─AuthSec-transient past deadline──▶ failed(aws_onb_authsec_unavailable)
   └─TTL 1h, no callback──▶ (expired; GET returns 404 → UI "expired")
flags: response_put_failed (SUCCESS/FAILED could not be delivered to CloudFormation)
```

### EH3. Error catalogue

**Stage 0: before launch (AuthSec API)**

| Code | Cause | How AuthSec notices | What AuthSec does | What the user sees and how to recover |
|---|---|---|---|---|
| — | Automatic infrastructure not configured | `Enabled()` is false | The package returns `automatic.enabled=false` | The manual flow, with no error shown |
| `aws_onb_not_configured` | AuthSec principal env missing | Existing `configured:false` | Existing behaviour | Existing message |
| `aws_onb_template_missing` | The template for the current `TemplateVersion` wasn't published to S3 | A **startup check, repeated every 10 minutes**, sends a HEAD request to `TemplateURLFor(region)` | Turns automatic onboarding off for affected regions and alerts on-call | The manual flow |
| `aws_onb_invalid_regions` (422) | Empty list, more than 32 regions, mixed partitions, an opt-in region AuthSec doesn't support, or an unsupported deployment region | Validation | Rejects the request, naming the offending region | An inline error on the region picker |
| `aws_onb_session_store_unavailable` (503) | Redis is down | The session write fails | No tab opens. On-call is alerted | "Automatic setup is temporarily unavailable." The user can try again or use manual setup |
| 403 | The user isn't `discovery:admin` | RBAC | Existing behaviour | The Launch button is hidden, with "Ask an admin to connect" |

**Stage 1: in the AWS console (AuthSec receives nothing)**

The only signal AuthSec gets is a missing callback, so the UI's wait screen names each of these causes.

| Cause | What happens | What the user sees and how to recover |
|---|---|---|
| The browser blocks the pop-up | No tab opens | The tab is opened synchronously from the click handler. If it's still blocked, the wizard shows an **"Open AWS console"** link |
| Not signed in, or signed in to the wrong account | AWS shows its sign-in page, or the stack goes into the wrong account | A pre-launch hint. After connecting, the account ID is shown and the user can revoke |
| The user lacks IAM permissions, or skips the acknowledgement checkbox | The stack fails at the role | Timeout guidance: check the stack's **Events** tab |
| An SCP blocks `iam:CreateRole`, or `sns:Publish` is missing (S5) | The stack fails at the role or at the custom resource | Timeout guidance names both causes |
| The user switched console region | The ServiceToken is in another region, so `InvalidParameter`, then rollback | Timeout guidance: "Don't switch Regions". The user clicks Start over |
| The user cleared `CallbackTopicArn` | The stack succeeds without calling back | Timeout: the user uses "Paste Role ARN instead" |
| The user edited `ExternalId` | The callback arrives with an unknown value → `aws_onb_values_changed` (Stage 3) | The stack event reads "Values filled in by AuthSec were changed". The user clicks Start over |
| The template URL can't be read (S1 or S3 problem) | The AWS console shows an error before Create | Guidance, plus the manual flow |
| A stack with that name already exists | AWS rejects the name | The user clicks Start over, which creates a new session and new names |

**Stage 2: getting the message from SNS through SQS to the worker**

| Cause | How AuthSec notices | What AuthSec does | What the user sees |
|---|---|---|---|
| The topic policy denies CloudFormation's publish (a configuration mistake) | **The daily canary** (EH5) fails. AuthSec can't see it on customer stacks | Page on-call | Stack failure, then timeout guidance |
| SNS→SQS delivery fails (queue policy) | SNS `NumberOfNotificationsFailed` alarm, plus delivery-status logging on the topics | Page on-call | Timeout |
| The worker is down or backed up | SQS `ApproximateAgeOfOldestMessage` over 120 seconds | Page on-call. Messages wait in the queue; any processed before the deadline still succeed | "Waiting…", then timeout if the deadline passes |
| The message isn't valid JSON, isn't a CloudFormation event, or has an unknown `LogicalResourceId` | Parsing fails | The message goes to the DLQ immediately and the DLQ alarm fires | — |
| The same message is delivered twice | The stored result for `(StackId, RequestId)` | The stored result is PUT again. `Onboard` doesn't run twice | — |

**Stage 3: validation (B6)**

In every case below AuthSec PUTs FAILED, and CloudFormation rolls the stack back and deletes the role. The one exception is the ResponseURL row.

| Code | Cause | `Reason` in the stack event |
|---|---|---|
| — (DLQ) | ResponseURL fails validation | *(nothing is sent; the URL is never contacted)* |
| `aws_onb_values_changed` | The ExternalId matches no session and has a valid shape | "Values filled in by AuthSec were changed. Start again in AuthSec." |
| `aws_onb_expired` | The session's TTL has passed | "This AuthSec launch link expired. Start again in AuthSec." |
| `aws_onb_wrong_workspace` | `VerifyExternalIDBinding` fails | "This launch link is not valid. Start again in AuthSec." |
| `aws_onb_region_mismatch` | The topic's region, the stack's region and the session's region don't all match | "Stack was created in a different Region than AuthSec expected." |
| `aws_onb_account_mismatch` | The account in the StackId differs from the account in the RoleArn | "Role and stack are in different accounts." |
| `aws_onb_link_used` | The session has already been used by another account or role | "This AuthSec launch link was already used." |
| `aws_onb_too_many_attempts` | More than 5 attempts on the session | "Too many attempts for this link." |

**Stage 4: `Onboard()`, mapped from existing error types**

| Error from `Onboard` / `Verify` | Class | What AuthSec does |
|---|---|---|
| AssumeRole `AccessDenied` or trust failure, still failing after the ~90-second IAM propagation retry | Customer, permanent | FAILED with `aws_onb_assume_denied`: "AuthSec could not assume the role (trust policy or ExternalId)." |
| The account in the ARN differs from the account the role resolves to (existing check at L242) | Customer, permanent | FAILED with `aws_onb_account_mismatch` |
| `ErrAWSProbeTimeout`, STS throttling | Transient | Retry with backoff until the deadline, then FAILED with `aws_onb_authsec_unavailable` |
| `ErrNoBaseCredentials` (AuthSec's own AWS identity is broken) | AuthSec, transient | Page on-call. Retry until the deadline, then FAILED with `aws_onb_authsec_unavailable`: "AuthSec could not complete setup. Try again later. AuthSec ref: …" |
| Vault write fails | AuthSec, transient | `Onboard` writes no connector row (existing ordering). Retry until the deadline |
| Database upsert fails | AuthSec, transient | `Onboard` rolls back a newly written secret (existing behaviour). Retry until the deadline |
| Redis lock or session write fails | AuthSec, transient | The message returns to the queue after the visibility timeout. It is processed again before the deadline |

**Stage 5: the response PUT to CloudFormation**

| Cause | What AuthSec does | What the user sees |
|---|---|---|
| 5xx or network error | 3 retries with backoff, then the message goes back to the queue and the stored result is PUT again on redelivery, until the deadline | — |
| 403 (the presigned URL has expired or the signature doesn't match) | Unrecoverable. Log it (host and path only, **never the signed query**), set `response_put_failed` and alert | If `Onboard` already succeeded: "Connected — but AWS may roll your stack back. If it does, Start over." The stack then times out and rolls back, which deletes the role. The connector's existing Verify then shows it broken, and the coverage UI surfaces it |

**Stage 6: regional probes**

A probe failure never fails the session.

| Probe result | Region status |
|---|---|
| OK | `connected` |
| `AccessDenied` (for example an SCP that denies the region) | `not_reachable: blocked` — "An SCP or permissions boundary blocks this Region" |
| Region not enabled in the customer's account | `not_reachable: region_disabled` — "Enable this Region in your AWS account" |
| Timeout (20 seconds) | `not_reachable: timeout` — "Could not check; the next scan will retry" |
| An opt-in region AuthSec doesn't support reaches the probe | Should never happen, because the server-side allowlist blocks it. It's logged as a **bug** |

**Stage 7: the UI while it waits**

| Cause | What the UI does |
|---|---|
| A poll returns a network error or 5xx | Back off (3s → 6s → 12s, capped) and keep polling. After 3 failures in a row, show "Connection to AuthSec lost — retrying" |
| A poll returns 404 (the session expired or the workspace changed) | "This setup session has ended. Check **Connections**; if the account isn't there, Start over" |
| The user refreshes or comes back later | The session ID is kept in the URL query (`?onb=<id>`), so polling resumes |
| No callback after 15 minutes | Timeout guidance (Stage 1 causes), plus "Paste Role ARN instead" and "Start over" |
| `failed(code)` | Copy from `awsErrorCopy.ts` for that code, plus Start over |

**Stage 8: later in the connector's life**

| Event | What happens |
|---|---|
| The customer deletes the stack | Delete gets SUCCESS. The role is gone, and later Verify and scans fail with the existing errors that coverage already surfaces |
| The customer updates the stack | Update gets SUCCESS, and nothing changes (B11) |
| The Delete CloudFormation sends during a rollback | SUCCESS |
| The worker is down while a customer deletes their stack | The delete fails with `DELETE_FAILED` after 600 seconds. The runbook says to retry the delete once the worker is back (B10) |
| A topic is retired | Not allowed without the migration in B10 |

### EH4. Logging rules
- **Every log line carries** `session_id`, `stack_id`, `request_id`, `account_id`, `deployment_region`, `stage`, `code` and `attempt`.
- **Never logged:**
  - the **ResponseURL query string**. It is a presigned write credential, so only the host and path are logged;
  - base credentials;
  - Vault contents.
- **The ExternalId is logged as `sha256[:8]` only.** It isn't secret, but keeping it out of logs is cheap.
- **Every decision point writes one line**, covering both the ones that accept and the ones that reject, so support can reconstruct any onboarding from its `AuthSec ref`.

### EH5. Monitoring and alerts

**Metrics**
- Sessions started, connected and failed, broken down by `code`.
- Time from callback to connected.
- PUT outcomes.
- Probe outcomes by region.
- DLQ depth.
- Age of the oldest message in the queue.

**Alerts that page on-call**
- DLQ depth greater than 0.
- Oldest message older than 120 seconds.
- More than 5% of PUTs failing.
- Any `NumberOfNotificationsFailed` on a topic.
- `aws_onb_authsec_unavailable` appears at all.
- The template HEAD check fails.
- The canary fails.

**The canary.** Once a day, for each supported deployment region, a lab account runs a scheduled Quick Create-equivalent `create_stack` with a callback, then a `delete_stack`, using the `labs/aws-iga/lab.py` helpers. The alert fires if either doesn't complete within 10 minutes. It is the only way to catch Stage 2 problems, which customers can't report and AuthSec can't otherwise see.

### EH6. Error-path tests
- **Unit tests:**
  - every `aws_onb_*` code is produced by a fixture and appears in its `Reason` and UI copy;
  - transient versus permanent classification for each error type in Stage 4;
  - retry loops stop at the deadline, and a final FAILED is still sent;
  - PUT: retry on 5xx, and a 403 sets `response_put_failed`;
  - logs never contain a signed query string, which a test asserts on captured log output.
- **Integration tests:**
  - Vault failure → no row, then success on redelivery;
  - database failure → the secret is rolled back;
  - Redis down at session start → 503.
- **UI tests:** poll back-off, 404 handling, resuming via `?onb=`, and copy for each failure code.
- **E2E additions:**
  - kill the worker for 2 minutes during a launch → it still connects before the deadline;
  - kill it for longer than 9 minutes → the stack gets FAILED with `aws_onb_authsec_unavailable`, or times out, and the UI explains why;
  - edit the ExternalId in the console → `aws_onb_values_changed` appears in the stack events.

---

## FILES

### Backend (`authsec/`)

**`internal/awsdiscovery/authsec-aws-discovery-role.yaml`:** as in B8.

**`internal/awsdiscovery/onboarding.go`**
- Bump `TemplateVersion`.
- Add `QuickCreateURL(region, templateURL, stackName, params)`. It uses the F1 format, encodes every value, allows the `aws` partition only, and **returns an error if a parameter it's given is `NoEcho` in the embedded template**.
- Add `PartitionForRegion`.
- Add `CFNResponseHosts` (B7).
- Add `IsOptInRegion`, a static list checked against F10/F11.

**New `internal/awsdiscovery/testdata/cfn_response_urls/*.json`:** the captured, sanitised fixtures from the spike.

**New `internal/awsdiscovery/callback_config.go`**
- `LoadCallbackConfig()` reads:
  - `AUTHSEC_AWS_CFN_CALLBACK_TOPICS`, a JSON map of `{region: topicArn}`. Each key must match its ARN's region and be a default-enabled `aws` region.
  - `AUTHSEC_AWS_OPTIN_SCAN_REGIONS`.
  - `AUTHSEC_AWS_TEMPLATE_BASE_URL`, with optional per-region overrides in case **S1** fails.
  - `AUTHSEC_AWS_CFN_CALLBACK_QUEUE_URL`.
- It also provides `SupportedDeploymentRegions`, `TopicFor`, `IsOurTopic`, `TemplateURLFor(region)` and `Enabled()`.

**`services/cloud_aws_onboarding.go`** (additions only)
- `StartOnboardingSession` (validation B1, names B5, Redis keys `aws:onb:session:{id}` and `aws:onb:ext:{hash}`, TTL 1 hour; pattern from `gcp_oauth_provision_service.go` L139).
- `GetOnboardingSession`, scoped to the workspace.
- `CompleteFromStack`, implementing B4 and B6.
- An extended `normalizeRegions`-style check for opt-in scan regions, as a *new* helper. `normalizeRegions` itself is unchanged.

**New `services/cloud_aws_cfn_callback.go`:** unwraps the envelope, parses the event, validates the ResponseURL, dispatches, and sends the response PUT. The PUT has an empty `Content-Type`, a body of at most 4096 bytes, the IDs copied verbatim, the fixed `PhysicalResourceId`, no redirect following, and a 10-second timeout.

**New SQS worker:** runs next to the existing workers (`DiscoveryScanWorker` is untouched). It's gated by `Enabled()`. It long-polls with a 5-minute visibility timeout and deletes a message only once it is handled. Messages go to the DLQ after 5 receives.

**`controllers/platform/cloud_aws_controller.go`:** adds the `automatic` block to `GetOnboardingPackage`, plus new `StartOnboardingSession` and `GetOnboardingSession` handlers.

**`routes/routes.go`**, after L1672:
- `POST /aws/onboarding/sessions`, requiring `discovery:admin`.
- `GET /aws/onboarding/sessions/:id`, requiring `discovery:read`.

**Infrastructure and docs:** a template publishing step; topics, queue, DLQ, policies and alarms for each environment; a runbook in `docs/flows/aws-cloud-discovery-onboarding.md`.

### Frontend (`Authsec-ui/`)
- `src/app/api/cloudDiscoveryApi.ts`: types, `useStartAwsOnboardingSession`, and `useAwsOnboardingSession(id)`.
- `src/features/discovery/cloud/aws/AWSOnboardingWizard.tsx`: B9. The manual flow moves under "Deploy manually".

### Files that do NOT change
- Scan and reconciliation, including `cloud_aws_workload_scan.go`.
- `LiveVerifier`, `ConfigForConnector`, `ParseRoleARN`, `ValidateRegion`, `normalizeRegions`, and the body of `Onboard()`.
- `CreateConnector`, `VerifyConnector` and `RevokeConnector`.
- `models/cloud_discovery.go`.
- `DiscoveryScanWorker`.
- All GCP code.
- All migrations.

### Migration
**None.** Sessions, region status and idempotency records live in Redis with a TTL.

---

## PART C: ASSUMPTIONS AND SPIKE ITEMS
The spike **must finish, with its findings written into this plan, before any implementation PR merges.** Code can be built alongside it. It runs in a sandbox, using the `labs/aws-iga/lab.py` helpers and the real console.

| # | Unverified assumption | How the spike proves it | If it fails |
|---|---|---|---|
| S1 | Quick Create accepts a `templateURL` whose bucket is in a **different region** from the stack (F3 docs say nothing; one answer suggests the regions must match) | Launch from ap-south-1 using a template in a home-region bucket | Replicate the template to one bucket per region, using the `TemplateURLFor(region)` override that's already designed in |
| S2 | Which SNS topic policy works. The candidates, in order: **C** `Principal *` + `aws:CalledVia` includes `cloudformation.amazonaws.com`; **B** `Principal *` + `ArnLike aws:SourceArn arn:aws:cloudformation:{r}:*:stack/*`; **A** the CloudFormation service principal + SourceArn; **D** `Principal {AWS:*}` with no condition, as Mozilla uses (F14) | Each candidate must let a real custom-resource Create through **and** block a direct `aws sns publish` from an unrelated account | Ship D. Trust doesn't depend on the choice (B6), and D is a known production pattern |
| S3 | The real host forms of ResponseURL for us-east-1 and ap-south-1 | Capture real events and save them, sanitised, as fixtures (B7) | Nothing to fall back to: the allowlist is whatever the capture shows |
| S4 | The signature parameters in the presigned URL (`X-Amz-Signature` or `Signature`), and a PUT with an **empty Content-Type** succeeds | Use the captured URLs | Adjust the query check and the headers to match what's observed |
| S5 | Which principal publishes to SNS for the custom resource: the caller's credentials or a service principal. If it's the caller's, **the deploying user or the stack's service role needs `sns:Publish` on AuthSec's topic** | Deploy as a restricted IAM user with no `sns:*` | Add it to the troubleshooting text and the prerequisites |
| S6 | SNS→SQS delivery from us-east-1 and ap-south-1 topics into the central queue, using `sns.amazonaws.com` + `aws:SourceArn` | Publish from each topic | Adjust the queue policy |
| S7 | A FAILED response rolls the stack back, deletes the role, and sends a Delete to the custom resource; that Delete completes once answered with SUCCESS | Send a callback with an unknown ExternalId | Adjust the Delete handling |
| S8 | Once `ExternalId` loses `NoEcho`, every parameter is pre-filled on the Create stack review page | Visual check | — |
| S9 | Regional probes behave as F12 predicts: an opt-in scan region enabled in both accounts shows Connected, and one disabled in the customer's account shows Not reachable | Enable one opt-in region (for example af-south-1) in AuthSec's sandbox account and test both cases | Adjust the probe's wording and classification |
| S10 | *(Code, not AWS.)* `Onboard`'s upsert on a *revoked* connector brings it back to a usable state | An integration test | Raise it with Sumaya before changing anything |

Open questions for people rather than the spike:
- **Q2 (product):** whether AuthSec will have a principal in GovCloud or China.
- **Q5:** where AuthSec's infrastructure-as-code lives.
- **Q6:** which AWS account hosts the callback infrastructure, and whether the backend identity has SQS permissions.

---

## EDGE CASES

| Case | Behaviour |
|---|---|
| User switches the console region before creating the stack | The ServiceToken is in another region (F4), so the stack fails and rolls back. The UI timeout explains why and offers Start over |
| User edits `RoleName` or `StackName` | The callback still completes, because names aren't enforced. The connector stores the edited role ARN |
| User clears `CallbackTopicArn` | The stack creates the role with no callback. The UI times out and offers Paste Role ARN |
| User clicks Create more than an hour after launching | The session has expired, so AuthSec answers FAILED. The stack rolls back and the role is deleted. The user clicks Start over |
| Launched twice from one session | The stack or role name is already taken, so the second stack fails harmlessly |
| Signed in to the wrong account | The connection succeeds for that account. The Connected screen shows its account ID, and the user can revoke |
| SUCCESS PUT keeps failing, so the stack times out and rolls back after `Onboard` wrote the connector | The role is deleted, and the connector's existing Verify shows it as broken. The PUT is retried 3 times and the SQS redelivery re-PUTs the stored result, so this needs a response URL that fails for 10 minutes. Accepted, and logged |
| Redis restarts mid-session | The session is lost, so AuthSec answers FAILED and the stack rolls back. The user clicks Start over |
| Two workers pick up the same message | The per-session lock and the stored result per request prevent a second `Onboard` |
| A forged message (valid topic, unknown ExternalId) | FAILED is sent to an allowlisted AWS host, or the message goes to the DLQ. No AWS call is made on AuthSec's side |
| Opt-in scan region not enabled by the customer | Scan scope is kept. The probe shows Not reachable with the reason |
| Opt-in region AuthSec's account hasn't enabled | It can't be selected: it appears disabled in the picker |

---

## TESTS

### Unit tests

**Template**
- Parses both with and without `HasCallback`.
- `ServiceTimeout` is 600.
- **No parameter that `QuickCreateURL` sets is `NoEcho`.**
- `ExternalId` keeps its constraints.

**`QuickCreateURL`**
- Produces the F1 format and encodes values.
- The region appears in both the host and the query.
- Rejects gov/cn regions and `NoEcho` keys.

**`CFNResponseHosts` and ResponseURL validation**
- Every captured fixture passes.
- Every one of these fails:
  - `http`;
  - a dashed bucket name;
  - a region that doesn't match the StackId;
  - a look-alike suffix (`…amazonaws.com.evil.com`);
  - userinfo;
  - a port other than 443;
  - no signature;
  - a host form not seen in any fixture.

**`LoadCallbackConfig`**
- Rejects a key that doesn't match its ARN's region.
- Rejects an opt-in region used as a key.
- Rejects any partition other than `aws`.

**`StartOnboardingSession`**
- Rejects mixed partitions.
- Rejects an unsupported deployment region.
- Rejects an opt-in scan region that isn't on the allowed list.
- Rejects an empty list and a list longer than 32.
- The suffix is shared by the stack and role names, and the role name is 64 characters or fewer.
- The deployment region comes first.

**Callback (the whole of B6)**
- Every rejection path.
- Idempotency on `(StackId, RequestId)`.
- The consumption rules.
- The per-session lock.
- Delete (known, unknown and expired sessions) always gets SUCCESS.
- Update gets SUCCESS.
- The IAM propagation retry succeeds on the third attempt.
- The PUT happens before the probes.
- `previous_role_arn` is recorded.

**Regional probes**
- A mix of results still leaves the session `connected`.
- The concurrency cap and the per-probe timeout hold.

### Integration test
Extend `tests/integration/cloud_aws_onboarding_test.go` with a fake verifier to cover:
- session → callback → connector row;
- a re-onboard that replaces the role;
- a revoked connector being re-onboarded (S10).

### UI tests
- Launch stays disabled until at least one region is picked.
- An opt-in region AuthSec doesn't support appears disabled.
- Picking GovCloud or China switches to the manual flow.
- Polling leads to the per-region table.
- The replaced-role notice appears.
- On timeout, Paste Role ARN and Start over appear.

### End-to-end (sandbox)
1. Three regions, with the stack in ap-south-1, reach Connected with no pasting.
2. **Scan region differs from deployment region, including an opt-in one:** stack in ap-south-1, scanning `[ap-south-1, us-east-1, af-south-1]`.
   - The connector stores the regions with the deployment region first.
   - af-south-1 shows Connected when both accounts have it enabled, and Not reachable when the customer hasn't.
3. **The user changes the pre-filled RoleName and StackName:** the connection completes, and a later re-onboard shows the "stack you created" wording.
4. Re-onboarding the same account shows the replaced-role notice.
5. Picking GovCloud offers the manual flow.
6. An unknown ExternalId gets FAILED, the stack rolls back, and the role is deleted.
7. A forged ResponseURL is never contacted.
8. Deleting the stack completes promptly and leaves the connector alone.
9. Switching the console region makes the stack fail, and the UI explains why.
10. With the environment variables unset, the old manual flow still works.

---

## IMPLEMENTATION ORDER
1. **Spike** S1–S9. Write the findings back into Part C, and commit the captured fixtures under `testdata/`.
2. **Infrastructure:** topics in us-east-1 and ap-south-1 using the policy chosen in S2, the central queue and DLQ, the queue policy and alarms, the template publishing step, and one opt-in region enabled in AuthSec's sandbox account. Also the EH5 metrics, the alerts, the daily canary and the template HEAD check.
3. **Template and `onboarding.go`:** B8, `QuickCreateURL`, `PartitionForRegion`, `CFNResponseHosts` and `IsOptInRegion`, each with tests.
4. **`callback_config.go`**, with tests.
5. **Session service**, with tests.
6. **Callback handler and `CompleteFromStack`:** B4 through B6, with unit and integration tests.
7. **SQS worker.**
8. **Controller and routes.**
9. **UI**, with tests.
10. **End-to-end run** of all 10 scenarios.
11. **Sumaya reviews, then merge.**

---

## 2026-09-24 REVALIDATION AGAINST NEW BACKEND COMMITS
- **`c30263f` (Akash, the scan write-path fixes):**
  - It touches only the scan and repository files: `cloud_aws_iam_scan.go`, `cloud_aws_scan_worker.go`, `cloud_aws_workload_scan.go`, `cloud_*_repository.go` and `cloud_gcp_scan_identities.go`.
  - The plan changes none of these, and none of them is on the onboarding path this plan uses.
  - **No conflict.** It also implements Phase 2's T1.5 (`run.Generation`) ahead of the spec.
- **The files this plan builds on are unchanged since the plan was written.** Their last change was `24c9f0d` on 2026-09-18, earlier than the plan. That covers `cloud_aws_onboarding.go`, `internal/awsdiscovery/*`, `cloud_aws_controller.go` and `routes.go`. Two facts are still true: `TemplateVersion` is still `2026-09-18`, and `ExternalId` is still `NoEcho: true` at L46.
- **`82e8a8a` and `d9741e7` (Aditya, the Phase 2 spec):** documentation only, nothing built yet. They led to B5 (the region-edit link), B10 (permanent infrastructure) and B11 (coordination).
- **Verdict:** the plan still holds, with the additions above. Nothing in Parts A to C was invalidated.

---

## CHANGES FROM REV 3
- **ResponseURL allowlist:** built only from captured fixtures. A host that isn't on the list goes to the DLQ with an alarm. The three guessed forms are gone (B7).
- **Opt-in regions:**
  - Scan region and deployment region are now told apart explicitly (B1).
  - A new finding from the code (F12): scanning an opt-in region needs **AuthSec's own account** to have that region enabled, so there's a new `AUTHSEC_AWS_OPTIN_SCAN_REGIONS` list, and regions not on it appear disabled in the picker.
  - Deployment in opt-in regions is excluded, backed by F10's rule on region-specific principals.
- **Q3 renamed** to "Resolved technically; old stack cleanup is customer-managed" (B5).
- **Callback order:** the PUT now happens **before** the regional probes, so the stack isn't held up. A per-session Redis lock was added.
- **Topic policy:** the candidates were reordered (`aws:CalledVia` first) and D is the backed fallback (F14). New spike item S5: the deploying principal may need `sns:Publish`.
- **Acknowledgement wording:** it's the "IAM resources with custom names" checkbox, because `RoleName` is set.
- **New edge cases:** the user switches console region, the session expires before Create, Redis restarts, the SUCCESS PUT fails, and "Launch again" needs a new session.
- **Parts A, B and C** now keep verified facts, design decisions and spike items apart, with a source for every fact.

---

## IMPLEMENTATION NOTES (backend, branch `aws-quick-create-onboarding`)

Built: template + adapter (`9ec0549`), service (`5d02404`), SQS worker (`2e06436`),
endpoints (`8424864`). Frontend not started. Deviations from the plan above, each
deliberate:

- **SQS visibility and session lock are 15 minutes, not 5.** One message can take
  the 540s callback deadline plus the regional probes; 5 minutes would let it
  reappear to a second replica while the first still holds it.
- **`aws_onb_values_changed` and `aws_onb_expired` are one code, `aws_onb_unknown_link`.**
  An ExternalId that matches no session cannot be told apart from one whose session
  expired, so the stack-event reason says both.
- **`aws_onb_invalid_request`** added, for a RoleArn in the callback that does not parse.
- **Region-probe `region_disabled`** is inferred from `InvalidClientTokenId` on an
  opt-in region, pending spike S9; otherwise such a failure reads `blocked`.
- **ResponseURL allow-list starts with one host form**, `…-{region no dashes}.s3-{region}.amazonaws.com`,
  whose only fixture is AWS's documented us-west-2 example (marked `"captured": false`).
  Spike S3 must replace it with captured URLs before merge.
- **Onboard's own account cross-check** is recognised by its error text
  ("refusing to onboard"), because Onboard's body is deliberately unchanged.
- The SNS topic policy, the infrastructure, the daily canary and the metrics are not
  code in this repo; see the runbook in `docs/flows/aws-cloud-discovery-onboarding.md`.

### Review fixes (commit `9a125f5` and the controller commit after it)

The note above about a 15-minute visibility and lock is superseded:

- **Visibility is 2 minutes, extended every minute while a message is handled; the lock is 3 minutes with a keep-alive and an owner token.** A crashed worker frees its message and lock within minutes, inside the stack's ServiceTimeout.
- **DLQ after maxReceiveCount 25 (recommended).** The worker reads the real value and answers FAILED on the last delivery.
- **No batch barrier:** up to 16 callbacks per replica run independently.
- **Answer reserve:** no Onboard attempt runs within 40s of the deadline.
- **Fail fast:** AuthSec-side errors that do not heal fail after 60s; throttling and timeouts still retry to the last safe moment.
- **Lock contention never answers**, and **a failed save after a successful Onboard still answers SUCCESS**.
- **Quick Create connections are audited.** `GET /sessions/:id` returns the launch link and ExternalId only to the session's creator.

### Deferred: region checks off the worker slot

Proposed after the final review: run the per-Region probes in a background pool
instead of on the callback worker's slot. They already run AFTER SUCCESS is sent
to CloudFormation, so the stack never waits for them; they only hold a worker
slot for a few more seconds (about 5–10s per callback in total instead of 1–3s).

Not built for now. Capacity is already sufficient: about 100–150 callbacks per
minute per replica at the default 16 slots, so 2–3 replicas clear even a
simultaneous 1000-customer burst in minutes, inside the 540s callback deadline.
`AUTHSEC_AWS_CFN_CALLBACK_CONCURRENCY` and replicas scale it further without
code. The async version would add a second session writer, a second pool and
background work a deploy can lose.

Build it when the queue's ApproximateAgeOfOldestMessage alarm (over 60s) fires in
production. Keep `Onboard()` before SUCCESS in any version: it both proves the
role and persists the connector, and answering SUCCESS before persisting would
leave a completed stack with no connector and nothing to roll back.
