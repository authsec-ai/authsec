# Access policies — AWS and Azure

Status (2026-10-23): **AWS and Azure built and in production**, backend and
console. Azure was verified end to end in production on 2026-10-22: a block on
a storage account removed the managed identity's Storage Blob Data Reader
assignment (and nothing else) and End restored it, checked in Azure IAM; the
admin then ran the console flow. §6 lists what is not verified and the known
limits. Code is the evidence for what is built; where this file and the code
differ, §2 says how the build differs from the plan.

An admin blocks or allows identities on one resource for a window. The admin
owns everything (decision 2026-10-13): no owner, approver or review step. The
resource and the identities are chosen from what Discovery found; there is no
separate resources screen.

## 1. One rule, two clouds

| | AWS | Azure |
|---|---|---|
| Resource | an S3 bucket, or a folder (`prefix/`) of it | one ARM resource (storage account, key vault, …) |
| Who | IAM roles | service principals, managed identities, agent identities |
| Block | AuthSec attaches its own IAM policy with a Deny to each role; the window is written into the policy, so AWS honours it if AuthSec is down | Azure has no customer deny. AuthSec records, then deletes, each of the identity's own role assignments on the resource (or below it) whose role grants the access, and puts them back at the end, on Pause and on End |
| Allow | an IAM policy with an Allow and the window | a built-in role assignment (Storage Blob Data Reader for read on storage, Storage Blob Data Contributor for write/delete, Reader / Contributor otherwise), deleted at the end by AuthSec's job — Azure assignments have no expiry |
| Can't do | — | access from a broader scope (resource group, subscription) or through a group: a block on one resource cannot remove it. The preview refuses (`azure_inherited_access`); group access is a warning (`azure_groups_not_checked`) |
| Write access AuthSec needs | the AWS access stack (template v2) in the account | Role Based Access Control Administrator (or User Access Administrator / Owner) for AuthSec's Entra app on the subscription |
| Access levels | Read, Write, Delete; Block also All | the same |

Same routes (`/api/iga/v1/policy/access-policies`), statuses, lifecycle and
history for both. The provider is the resource's.

## 2. Screens and flow

Policy is a list, a detail and one form. Everything else is reached from the
graph or Discovery.

### 2.1 Create policy (`/iga/policy/new`) — built

Built as below, with these differences: the form is opened filled from
`?resource_id=`, `?identity_account_id=`, `?effect=` and, for an Azure object,
`?provider=azure` (the Azure object is read off the shared graph); Azure's
*Identities* list shows the identities holding a role on the resource for both
Block and Allow (badge *Holds a role here*; search results *No role here*),
because holding a role is not holding the access chosen, and the preview says
what changes; a holder whose grant here is not a role assignment (Key Vault
access policy, app permission) cannot be chosen.

Left column, top to bottom:

1. **Cloud** — `AWS | Azure` (radio). Preset from the resource when the form is
   opened from Discovery or the graph (`?resource_id=`); hidden while editing.
   Switching clears the resource and the identities.
2. **Resource**
   - AWS: *Bucket* — search S3 buckets Discovery found, plus an optional folder.
   - Azure: *Resource* — search Azure resources Discovery found
     (`/api/iga/v1/inventory/resources?provider=azure`), ARM resources only
     (not application permissions or delegated scopes). Each row: name, type in
     words ("Storage account"), subscription · resource group. No folder.
3. **Who**
   - AWS: *Roles*, as built.
   - Azure: *Identities* — the identities holding a role assignment on the
     resource now (the shared graph walked in reverse from it, §3), each with
     its role names ("Storage Blob Data Reader"); kinds AuthSec cannot target
     (users, groups) are listed greyed with the reason; search finds any other
     service principal, managed identity or agent identity
     (`inventory/identities?provider=azure`). The same Block/Allow logic as AWS:
     Block lists who reaches it, Allow who does not.
4. **Rule** — Block / Allow for a time; what to block or allow; for how long.
   Identical for both. Allow must end within 30 days.
5. **Name and reason** — identical.

Right column, the summary (identical frame for both):

- the sentence ("Block reading on agentigateststore01 for
  authsec-agent-iga-project-test-01 until 23 Oct 09:00.");
- readiness: "AuthSec can change IAM in this account" / "AuthSec can change
  role assignments in subscription Authnull", or the setup step that is
  missing, with the way to fix it;
- who is affected (workloads running as the identity);
- blockers (red) and warnings (amber), from the server's preview;
- *View the change* — AWS: the IAM policy document per role; Azure: per
  identity, the role assignments AuthSec will remove (role, scope) or the one
  it will create.

Footer: the reason Apply is disabled, Cancel, **Apply block** (red) / **Apply
allow** (primary blue, white text).

### 2.2 Policies (`/iga/policy`) — built

Each row carries the cloud's glyph; the **Cloud** filter (`?cloud=`) appears
once policies of both clouds exist.
The resource column reads the bucket (and folder) for AWS, the resource name
for Azure.

### 2.3 Policy detail (`/iga/policy/:id`) — built

Tabs Overview · In AWS / In Azure · History: sentence, status, window progress, lifecycle (Edit, Pause, Resume,
End now, Delete), versions, history. Provider wording:

| | AWS | Azure |
|---|---|---|
| per-identity state | In AWS / Removing / Removed | Access removed / Restoring / Restored (block); Assigned / Removing / Removed (allow) |
| the change | IAM policy document | assignments removed (role, scope) or created |
| status hints | "…into AWS…" | "…in Azure…" |

The status `ending` (§4.4) reads **Ending** and offers no Edit, Pause or End
until every deployment has left the cloud. The Azure resource links to its
page; Azure identities are listed by name (their page is keyed by the Entra
object id, which the policy does not carry).

### 2.4 Graph — built

An Azure object opens the same graph as an AWS one, read from the shared
`/api/iga/v1/graph` (§3): identity → role assignment → resource or scope, plus
memberships, who can become whom and the workloads that run as an identity.
Summary folds the assignment into one identity → resource line labelled with
the role ("Storage Blob Data Reader", "+N" for more); Detailed draws the
assignment card (role, its kind, what it allows, a condition if any); Paths
lists them. A resource opens in reverse (who holds roles on it).

The selection card offers **New access policy**, as on AWS:

| Selected | The card |
|---|---|
| service principal, managed identity, agent identity | a policy for it; the policies in force naming it |
| ARM resource | a policy on it; the policies in force on it; the identities drawn holding a role on it, each a shortcut filling both |
| a summary line from such an identity to a resource | a policy for that identity on that resource |
| workload | points at the identity it runs as |
| user, group, app registration, scope, app permission | one line saying why no policy can be set there |

Block marks come from AuthSec's own record of block policies in force (no
rescan needed): an identity card reads *Blocked* / *Partly blocked* while any
block policy names it, whatever its resource; a resource card and the summary
line into it only while a policy is on that resource. *Partly* means some
access levels, not all. Once a rescan has run after an Azure block, the
removed assignment is no longer drawn (it is gone); the cards keep the mark.

## 3. The shared graph read for Azure

Decision D-114 (`P2-DECISIONS.md`): the traversal routes read Azure rows the
way they read Kubernetes ones. The middle node is the role assignment (one per
`iga_access_edges` row), not the shared role definition, so no false path is
drawn; subscriptions, resource groups and the directory are leaf scope nodes.
The policy form's identity list is that walk, reversed from the resource.

## 4. Backend changes this needs (built 2026-10-22)

1. D-114 in `internal/igaread` (`traverse_azure.go`, the slot accepting
   `azure`, meta, node and edge decoration).
2. The policy view states the provider: `resource {provider, name, kind}`
   (bucket and ARN stay for AWS; on Azure `arn` is the ARM resource id and
   `account_id` the subscription) and `roles[].kind` (on Azure `arn` is
   empty). Deployments add `target_ref`: the AWS policy ARN, or the ARM scope
   (`aws_policy_arn` is empty for Azure). The list takes
   `?provider=aws|azure`.
3. Readiness covers Azure: `azure_subscriptions [{subscription_id, name,
   connector_id, ready, reason}]` per connected subscription, `ready` when
   AuthSec's app holds role-assignment write and delete there (the check the
   preview runs, cached for a minute). `reason` is `azure_unavailable`,
   `azure_write_access_missing`, or `access_policies_unavailable: <why>`
   without migration 144.
4. Status reasons name the provider: "removing from AWS", "removing from
   Azure" (allow), "restoring access in Azure" (block). A new status
   `ending` holds from End (or the end time) until every deployment has left
   the cloud; only then `ended` with `ended_at`. Delete accepts `ending` and
   refuses with `policy_removing` until it is done. Pause keeps `paused` with
   the same reason.
5. Migration 144 is checked on its own (`VerifyAzureAccessSchema`), not in
   `VerifyAccessPolicySchema`: without it, Azure preview and create return 503
   `access_policies_unavailable` with the reason, and AWS policies (list,
   detail, create, End) work as before.

## 5. Demo (Azure)

Before: run **Scan now** on the Azure connection, so the graph shows the role
assignments as they are; open the storage account's **Access control (IAM)**
and **Activity log** in the Azure portal.

1. Connections: the Azure tenant and subscription are connected; AuthSec's app
   has Role Based Access Control Administrator on the subscription.
2. Discovery → the storage account → Access Graph: workload → runs as →
   managed identity → *Storage Blob Data Reader* → storage account.
3. Select the line (or the identity, or the storage account) → **New access
   policy**: the form opens filled. Block, Read, 1 hour, a reason. The summary
   says AuthSec can change role assignments in the subscription and *View the
   role assignment changes* lists what it will remove. **Apply block**.
4. Policy detail: Applying → Active (about 20 seconds); *In Azure* reads Access
   removed; History: Created, Applied, In place on identity (verified). The graph cards
   read Blocked / Partly blocked.
5. Azure portal, refreshed: the identity's Storage Blob Data Reader is gone and
   its other roles are untouched; Activity log: *Delete role assignment* by
   Authsec Azure Onboarding.
6. **End now** with a reason: Ending → Ended; *In Azure* reads Restored;
   History: Access restored. The portal shows the assignment back and *Create
   role assignment* in the Activity log.

## 6. Verified, and known limits

Verified in production (2026-10-22): the block, End and restore above, by API
and in Azure IAM and the Activity log; the console flow, by the admin. Not
verified: an agent's data-plane read failing while blocked (only the role
assignments were checked), and Allow end to end on Azure.

Known limits, by design or not yet built:

- A block removes role assignments on the resource or below it. Access from a
  resource group, subscription or management group is refused in the preview
  (`azure_inherited_access`); access through an Entra group is not examined
  (`azure_groups_not_checked`); deny assignments and ABAC conditions are not
  evaluated.
- Azure assignments have no expiry: an Allow, and the restore after a block,
  happen when AuthSec's job runs.
- The Azure object pages still read three Azure-only endpoints: the
  neighbourhood (a resource's ARM id, a workload's name and the identity it
  runs as), *What it can reach* (blast radius) and the Discovery summary strip.
  The graph tab and the policy screens use the shared reads.
- On the shared graph (D-114) a scope node is a leaf, `/evidence` does not
  serve Azure claims, and the AKS federation join is not walked.
