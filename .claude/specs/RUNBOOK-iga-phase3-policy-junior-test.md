# Policy testing run sheet (for the tester)

You are going to test AuthSec's new **Policy** feature end to end on the real console and one real AWS account. Follow this sheet in order. For every step: do it, compare with **Expected**, tick **Pass** or **Fail**, and save the **Evidence**. Do not skip steps and do not improvise. If something is unclear, stop and ask the lead. The detailed case catalogue behind this sheet is [`TEST-iga-phase3-policy-e2e.md`](TEST-iga-phase3-policy-e2e.md) (case numbers like S5.1 below refer to it).

## 0. What you are testing, in one paragraph

AuthSec scans an AWS account, finds IAM roles that have permission for AWS services they never use, and proposes a **policy** that removes those services. People review it, one approver (not the author) approves it, and it is rolled out. In this test AuthSec **writes nothing to AWS**: you use **Export** delivery, which gives the lead a set of commands to apply by hand. AuthSec then checks the result on the next scan.

## 1. Facts about this test (ask the lead if any differs)

| Item | Value |
|---|---|
| Console | https://app.authsec.ai (commit `66585a9`) |
| Workspace | The one the lead names. Check its name in the console header before you start. |
| AWS account | `429418377036` (region `us-east-1` is scanned) |
| Policy feature | On (switched on 2026-10-12) |
| Enforcement mode | `findings_only` and it **stays that way** |
| Slack | Not configured. A "Slack is not configured" message is expected. |
| Test role | Named by the lead. **Only this role may be changed.** |

## 2. Safety rules. Read all of them. Breaking one means stop and tell the lead.

1. **Export delivery only.** Never choose Direct or Pull request.
2. **Never press** *Enable enforcement*, *Revoke*, *Re-run self-test*, or switch the mode to **Enforce**. Those are lead-only.
3. **Only the named test role.** Before you press *Generate tighter policy*, read the role name in the drawer aloud to the lead.
4. **You never apply the export in AWS.** The lead does it, or watches you do it, on the test role only.
5. **Different people, different logins.** The author and the approver must be two humans. Never approve a version you created. Never lend your login.
6. **No secrets anywhere.** Never put a token, an ExternalId, a Slack or GitHub key, or a password in a screenshot, bug report or chat. Black them out first. Never use any token someone pasted in a chat.
7. **Only the workspace and AWS account in section 1.** If you ever see another company's data, **stop immediately** and tell the lead.
8. **Delete nothing you did not create.** Do not archive or remove anyone else's policy.

**Stop and call the lead at once if:** a role other than the test role changes in AWS; a page shows another workspace's data; any mutating button gives an "internal" or unexplained error; a deployment shows *Outcome unknown* or *Needs your decision*; the console shows Policy as unavailable after you reloaded.

## 3. Before you start (tick all)

- [ ] Two or three people are available: **Author**, **Approver** (a different human), **Owner** (a workspace member who owns the test role). The lead has given each the right permissions (read, author / approve / enforce).
- [ ] You use Chrome with DevTools available (press F12). Use a private window per person, so logins do not mix.
- [ ] You have a folder for evidence, with sub-folders `step-01`, `step-02` and so on.
- [ ] The lead has confirmed the **discovery stack in AWS is updated** to template `2026-10-07` and a **new scan has finished**. If not, do step 2 with the lead before going on.
- [ ] You have a copy of the results log (section 6).

## 4. The run

### Step 1: The feature is on
Log in as the **Author**.
1. Open **Policy** in the left menu. Reload with Cmd+Shift+R.
2. Open DevTools → Network, reload, find the request `capabilities`, open its Response.

**Expected:** the left menu shows Policy and Logs **without** a "Preview" tag. The Policy page has a bar with **Overview, Findings, Policies, Approvals, Deployments, Setup**. In the capabilities response, `policy.state` is `on`. `slack` is `false` with a reason about Slack not being configured.
**Evidence:** screenshot of the page; screenshot of the response (nothing secret is in it).
**Fail if:** you see the old preview page, "Policy is not available on this server", or a "Could not check" banner that stays after Retry.

### Step 2: The AWS connection is current (lead does the AWS part)
1. Open **Connections** and the AWS account `429418377036`.
2. The lead confirms the discovery stack was updated, selects the regions that hold the test resources, and starts a scan. Wait until the scan shows **finished**.

**Expected:** a finished scan dated today, coverage with no unexpected gap notes, and no "update needed" note for the discovery template.
**Evidence:** screenshot of the account page showing the scan time.

### Step 3: Setup pages
Open **Policy → Setup**. Visit each section and write down what you see. Change nothing yet except where told.
1. **Enforcement:** the account card is shown. **Do not press anything.** Expected: it shows it is not enabled.
2. **IaC sources:** it says no repository is mapped. Expected and fine.
3. **Notifications:** it says Slack is not configured. Expected and fine.
4. **Owner rules:** empty list. Press **Add a rule…** → tag key `owner`, applies to *Roles and workloads*, *Accountable owner* → **Add rule**. Expected: the rule appears as On. (Run S1.10 later when the test role has an owner tag.)
5. **Finding rules:** press **Add a rule…**. Choose *Unused window*, enter `20`. Expected: refused (between 30 and 400). Enter `60` and add it. Expected: it appears. Then press the switch to turn it Off and back On. Then **Delete** it.
6. **Settings:** set *Default evidence window* to `30`, *Observation period* to `1`, *Owner review deadline* to `3`, *Canary window* to `1`. Save. Reload and check the values stayed. Try *Default evidence window* `5`: expected refused.

**Evidence:** one screenshot per section.

### Step 4: Findings appear
1. Open **Policy → Findings**. If the list is empty, the first evaluation has not run: tell the lead and wait for the scan to publish (it can take several minutes).
2. Find the test role. Open its row; the **drawer** opens.

**Expected:** the drawer says in words which services the role never used, which it used, grant age, who uses the role, who owns it, and how much AuthSec trusts the evidence. Compare the *used* and *unused* services with what the lead sees in the AWS console for that role (service last accessed). They should match.
**Evidence:** screenshot of the whole drawer; the lead's note on any mismatch.
**Also check (S2.5):** press **Except this finding…**, pick a date 10 days ahead, give a reason, save. Expected: status shows *Excepted until…*. Press **Clear the exception**: back to open. Try a blank reason: refused. Try a date more than a year away: refused.

### Step 5: Owner
In the drawer, if it says there is no owner, press **Assign owner** and choose the **Owner** person as *Accountable*. Expected: the drawer lists them as owner.
**Evidence:** screenshot.

### Step 6: Draft a policy (Author)
1. In the drawer press **Generate tighter policy**. Say the role name aloud to the lead first.
2. The new-policy page opens. It works through four steps. Do not close the tab.
   - **Step 1, recommendation:** you see the services to remove and the ones kept. Press **Keep a service** for one more service and give a reason. Expected: it moves to the kept list.
   - **Step 2, impact:** read who runs as the role, the owners who will be asked, and any resource-policy routes.
   - **Step 3, rollout and delivery:** *Observe first* `1` day, *Canary window* `1` hour, **Delivery: Export**. Pick nothing else.
   - **Step 4, review:** read the plan summary. Submit it for review.

**Expected:** exactly **one** draft exists (open **Policies** and count it). The policy shows as *in review* after you submit. Reload in the middle of the flow once: you come back to the same draft, not a second one.
**Evidence:** a screenshot of each of the four steps; the Policies list.
**Fail if:** two drafts appear, a service you kept still shows as removed, or the page shows a raw error.

### Step 7: Owner review (Owner)
Log in as the **Owner**. Open the review from the link in the notification the Owner received. If there is none, go to `https://app.authsec.ai/iga/policy/reviews` (the Approvals tab only shows for people who can approve) and open the review.
1. Read what would change for what you own.
2. Confirm the grant age and each resource-policy route if asked, then respond (confirm).

**Expected:** your response is saved. If you instead **object** or keep a service, a **new version** is created and an earlier approval no longer applies.
**Evidence:** screenshots before and after responding.

### Step 8: Approval (Approver, not the Author)
1. As the **Author**, open the version and try to approve it. **Expected: refused**, "You cannot approve your own change". Screenshot (S5.1).
2. Log in as the **Approver**. Open **Policy → Approvals**, open the version. Read the plan, the owners and the evidence.
3. If any item asks to be accepted (an evidence gap, or an unanalysed item such as other regions), try **Approve…** first with one item **not** accepted. **Expected: refused.** Then accept each item with a reason, and approve.

**Expected:** the version shows *Approved*.
**Evidence:** screenshots of the refusal, the accept boxes, and the approved state.

### Step 9: Roll out (Approver or someone with enforce permission)
Open the policy → **Rollout** tab. Press **Start the canary**.
**Expected:** an observation period is shown first with its end date (1 day). Nothing happens in AWS. After the observation period, a deployment is created for the canary role with delivery **Export** and state *Awaiting apply*.
**Come back the next day** for this step. Note the exact time.
**Evidence:** screenshot of the Rollout tab and of the deployment.

### Step 10: Download the export (the lead applies it)
Open the deployment (Policy → Deployments). In the **Export** panel you see the boundary document and the AWS CLI commands.
1. Press **Download** and save the file as `export-<role>-<date>.json`. Copy nothing into chat.
2. **Give the file to the lead.** The lead applies the commands to the test role in AWS and tells you when done. **You do not run them.**

**Expected:** the panel shows the documents and the commands for the test role only. It says nothing is written to AWS by AuthSec.
**Evidence:** screenshot of the Export panel (before download).

### Step 11: Verify after apply
1. The lead starts a **new scan** and waits for it to finish.
2. In the deployment, press refresh and watch the state. **Expected:** it moves from *Awaiting apply* to *Applied, verifying* and then to *Verified*. It can take more than one scan: write down each state and the time.
3. The lead checks in AWS that the removed services are now **denied** for the role and that a **kept** service still works. The lead's result goes in the log.
4. Open **Policy → Logs** (or the policy's *Events* tab) and look for the deployment events.

**Expected:** states change in the order above; logs show who did what and when.
**Evidence:** screenshots of each state; the lead's AWS check; a screenshot of the log.

### Step 12: Undo
Open the deployment and press **Undo…** (needs the enforce permission). Read what it says, give a reason, confirm. The lead applies the undo commands the same way. After a scan, the deployment ends **Undone** and the role is as before.
**Evidence:** screenshots; the lead's AWS check.

### Step 13: Permissions and safety checks (S0.4, S5, S12)
1. Log in as a person with **read only**. Open every Policy page. **Expected:** pages load; buttons that change things are missing or explain why.
2. As the **Author**, edit and save the policy while it is *approved*. **Expected:** a new version is created and the old approval does not apply to it (S5.6).
3. Open the legacy page (**Policy → Legacy**, if shown in the menu or at `/iga/policy/legacy`). **Expected:** it lists old policies; Pause and Remove need the enforce permission.
4. Check **Logs** for an email address or a URL in any event. **Expected:** none.

### Step 14: Wrap up
- [ ] Every step has Pass or Fail.
- [ ] All evidence is in your folder, with secrets blacked out.
- [ ] Every Fail has a bug report (section 7).
- [ ] The lead confirms the test role is back to its original state.
Send the folder and the results log to the lead.

## 5. Things that are normal (do not report as bugs)

- Slack is shown as not configured.
- The enforcement card says enforcement is off.
- The first evaluation can take a few minutes after a scan.
- The first deployment state can lag a scan by one cycle.
- Changing a setting does not change existing findings until the next scan.

## 6. Results log (copy this table)

| Step | Pass / Fail | Time | Who | Evidence file | Notes |
|---|---|---|---|---|---|
| 1 Feature on | | | | | |
| 2 Connection | | | | | |
| 3 Setup pages | | | | | |
| 4 Findings and exception | | | | | |
| 5 Owner | | | | | |
| 6 Draft | | | | | |
| 7 Owner review | | | | | |
| 8 Approval | | | | | |
| 9 Rollout | | | | | |
| 10 Export | | | | | |
| 11 Verify | | | | | |
| 12 Undo | | | | | |
| 13 Permissions | | | | | |

## 7. Bug report template (one per problem)

```
Title: one line, what is wrong
Step: number from this sheet
Severity: Blocker (stops the test) / Major (wrong result) / Minor (wording, layout)
Who and role: Author / Approver / Owner / Read-only
Page address (path only, no tokens):
What I did (numbered):
What I expected:
What happened:
Screenshots: file names (secrets hidden)
Request that failed (from DevTools → Network): method, path, status, the "error.code" in the response
Time (with timezone):
```

## 8. Phase 2: lead only

After this run passes, the lead may run the cases that write to AWS or need other systems: direct enforcement (S6, S9), pull-request delivery (S7), Slack (S10). They need the enforcement stack in AWS, a GitHub App and a Slack app, and are **not** part of this run.
