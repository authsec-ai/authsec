# Existing agent-policy code: disposition

**Status:** assessment, 7 October 2026. Source inspection of `authsec`
(local `authsec-staging` at `05e8291`; the cached `origin/authsec-staging` is
19 commits ahead and is noted where it differs), `Authsec-ui`
(`authsec-staging`), `iga-agent` (local `main` at `327f92b`; cached
`origin/main` at `c3ca538`), `discovery-agent` and `sdk-authsec`. Nothing was
fetched, switched or changed. No database or cluster was queried.

**Decision this plan implements:** Phase 3 is an independent policy product
([requirements §1](SPEC-iga-phase3-policy-requirements.md)). The existing
Kubernetes agent-lifecycle policy stack is not extended. Each part below is
assigned one disposition:

- **Retain** as shared infrastructure, through a named contract;
- **Reimplement** behind a new Phase 3 contract;
- **Isolate** temporarily for compatibility, with a visible and manageable
  state for any existing controls;
- **Migrate** customer data or configuration;
- **Retire** after a named gate.

## 1. What exists, traced

### 1.1 Running behavior

| Part | Evidence | What it does today |
|---|---|---|
| `PolicyReconcileWorker` | `cmd/main.go:494`, gated only by `config.DB != nil` (`:455`) | Every 5 minutes, for each workspace with an enabled policy, calls `Reconcile(ws, false)` live (`services/governance_policy_worker.go:186`) |
| `PolicyWarningWorker` | `cmd/main.go:506` | Every 5 minutes schedules and delivers pre-deadline email and HMAC-signed webhook warnings (`policy_warning_service.go:200,336`) |
| `ExpiryWorker` | `cmd/main.go:456` | Lapses grants each minute; it is how a policy's `revoke` takes effect, but it serves the AuthSec runtime generally |
| `LeaseReaper` | `cmd/main.go:475` | Reclaims expired `provisioning_instructions` leases |
| Reconcile, cluster arm | `agent_policy_service.go:1265`, `discovery_service.go:922`, `actuation_service.go:441` | Quarantine enqueues a `quarantine` instruction (plus `evict_pods` if the connector flag is set) |
| Reconcile, destruction | `agent_policy_service.go:1144,1214-1219` | `evict` expiry enqueues `evict_pods` / `delete_workload` only if connector flags are set; nothing in this workspace sets them (below), so it fails with "reports neither eviction nor workload deletion enabled" |
| Reconcile, entitlement arm | `agent_policy_enforce.go:81,132-150` | Rewrites `role_bindings.role_id` to a ceiling role and shortens `entitlement_provenance.expires_at` — **this changes AuthSec's own runtime authorization** |
| Audit | `agent_policy_service.go:926` | Every outcome in `agent_policy_actions` |

### 1.2 Transport to clusters

| Part | Evidence | Status |
|---|---|---|
| Lease / report | `GET /authsec/provisioning/instructions`, `POST …/:id/result` (`routes/routes.go:1821-1822`), actuation bearer token resolved to the connector (`actuation_service.go:141`) | Present; token-authenticated |
| Stale report | `Report` (`actuation_service.go:291-340`) checks only `discovery_source_id`, never `leased_by` or lease expiry | Defect: a reclaimed worker's late report is accepted |
| iga-agent executor (local `main`) | `iga-agent/internal/actuate/actuate.go:48-50,276-279` | Handles `quarantine`, `unquarantine`, `verify_uptake` only; other kinds fail as "agent may be out of date" |
| iga-agent executor (cached `origin/main`) | `actuate.go:345-367` on `origin/main` | Adds evict, delete and force-delete behind `ENFORCEMENT_*` flags; not verified as deployed |
| Enforcement plan | `GET /provisioning/enforcement-plan` (`routes.go:1832`) is the only writer of the connector flags `enforcement_evict/delete/force_evict` (`enforcement_plan_service.go:345-351`) | **No poller** in any agent checkout here; the flags stay false |
| `verify_uptake` producer | Only tests create it (`tests/ownership/actuation_test.go:240,420`) | No production producer |

### 1.3 Data

| Table | Created | Note |
|---|---|---|
| `agent_policies`, `agent_policy_confirmations`, `agent_policy_actions` | `001_bootstrap.sql:5577,5685,5724`; mirrored in `026` | Customer intent and audit of the legacy feature |
| `agent_policy_warnings`, `governance_notification_settings` | `001:5909,5878`; `026` | Warnings and channel settings |
| `enforcement_plans` | `001:5803`; `026` | Plans a cluster reports against |
| `provisioning_instructions` | `001:5171`; `026` widens checks only | Instruction queue |
| `discovered_agents` quarantine columns, `discovery_sources.actuation_token_hash` | `001`, `002`, `023` and **hand-run deltas only** (`migrations/deltas/governance_*.sql`, "NOT a committed migration") | Existing databases have them only if the deltas were applied; unverified for production |

### 1.4 Consumers

| Consumer | Status |
|---|---|
| Console | **None.** The governance screens, `governanceApi.ts`, the claim dialog and the enforcement card were deleted (Authsec-ui `8e92359`, 5 October). Old routes render the retirement state (`App.tsx:839-930`). A leftover `NotificationSettings` tag remains (`baseApi.ts:195`) |
| SDKs | None (`sdk-authsec` has no reference) |
| `discovery-agent` | None |
| `iga-agent` | Lease and report only |
| Routes with no remaining caller | `/authsec/governance/agent-policies*`, `/policies/upcoming`, `/policy-warnings*`, `/notification-settings`, `/agents/:id/force-evict`, `/connectors/:id/enforcement-plans`, `/connectors/:id/actuation`, `/instructions` (`routes.go:1883-1954`); `/provisioning/enforcement-plan` |

**Consequence:** the reconciler can quarantine agents and rewrite AuthSec role
bindings every five minutes for workspaces whose administrators no longer have
any screen that shows or controls those policies.

## 2. Dispositions

| Part | Disposition | Contract, gate and rollback |
|---|---|---|
| Workspace membership, RBAC permissions, `AuthMiddleware` | **Retain** | Phase 3 adds its own permissions; no change to existing ones |
| Vault credential storage | **Retain** | Phase 3 stores enforcement and Slack credentials under its own paths |
| `audit_events` / `auditAdminMutation` | **Retain** | Every Phase 3 mutating route writes it in addition to the policy event log |
| Email and webhook delivery code (`policy_warning_senders.go`) | **Reimplement** behind a notification contract | Phase 3 extracts the transport (email send, HMAC-signed webhook) into a shared sender with its own retry table; the legacy warning lifecycle is not reused |
| `ExpiryWorker`, `role_bindings`, `entitlement_provenance` | **Retain** as AuthSec runtime authorization | Not policy infrastructure; Phase 3 never writes them |
| `agent_policies` model and service, reconcile worker | **Isolate**, then **retire** | Gate G1–G4 below |
| Entitlement arm (`agent_policy_enforce.go`) | **Isolate**, then **retire** | It mutates AuthSec runtime authorization from a governance policy, which requirements §1 forbids for the new product. Decide per gate G2 |
| Cluster quarantine (NetworkPolicy) via actuation | **Isolate** | Containment is not part of R1a or R1k; retained only for workspaces that use it until G2 decides migrate or retire |
| Destruction (evict / delete / force-delete) | **Retire** | Unreachable here (no flag producer, local agent cannot execute); confirm with G1 data and deployed-agent checks |
| `enforcement_plans`, `GET /provisioning/enforcement-plan` | **Retire** | No poller found; confirm with 30 days of API logs (G1) |
| `verify_uptake` handling | **Retire** with the arm, or reimplement if quarantine is migrated | No production producer |
| `PolicyWarningWorker`, `agent_policy_warnings` | **Isolate**, then **retire** with the reconciler | Warnings only concern legacy destructive deadlines |
| `governance_notification_settings` | **Migrate** channel addresses into Phase 3 notification settings where a workspace has them | Copy, do not move; the legacy row stays until retirement |
| `agent_policy_actions`, `agent_policy_confirmations` | **Migrate** to an archive and to Logs | Read-only export into the Logs event stream with `source = legacy_agent_policy`; rows retained for the audit retention period |
| Legacy governance routes | **Isolate** (no caller), then **retire** | Replaced by a read-and-manage compatibility endpoint (§3) |
| Stale-report defect in `actuation_service.go` | Repair now, independently | It affects quarantine today; not a Phase 3 dependency |
| Hand-run delta columns | **Migrate** into a numbered expand migration if G1 shows they exist in production; otherwise retire with the feature | Numbered migrations are the only supported schema path |

## 3. Coexistence until retirement

1. **Visibility and control.** A compatibility read, `GET
   /api/iga/v1/legacy/agent-policies`, lists each workspace's legacy policies
   with their last reconcile outcome and pending destructive deadlines. Policy
   shows them in a read-only **Legacy agent policies** section with two
   operations proxied to the legacy manager and audited: **Pause** (set the
   policy disabled) and **Remove**. No create or edit. This is the only legacy
   surface; the retired screens stay retired.
2. **Worker control.** A new environment gate `IGA_LEGACY_AGENT_POLICY`
   (`on` by default until G1, so behavior does not change silently) stops both
   legacy workers when `off`. Turning it off is a recorded release decision
   per environment.
3. **No shared ownership.** The legacy stack owns NetworkPolicies it created
   for quarantine and AuthSec `role_bindings`. Phase 3 owns AWS permissions
   boundaries (R1a) and, later, Kubernetes RBAC bindings (R1k). These sets do
   not overlap in R1a. **R1k may not act on a cluster while the legacy
   reconciler can act on it**: the R1k deployment job refuses a cluster whose
   workspace has an enabled legacy policy, with the reason shown, until G4.
4. **Fencing.** Retiring the reconciler is done by stopping its workers
   (gate) and then setting every legacy policy disabled in one audited
   operation; leased instructions finish or expire under `LeaseReaper`.
   Nothing deletes customer records.

## 4. Gates

| Gate | Question | How it is settled |
|---|---|---|
| G1 | Is the legacy feature used in production? | Operator runs read-only counts on the read replica (below); checks the deployed image revision; counts 30 days of requests to `/provisioning/enforcement-plan` and `/provisioning/instructions` |
| G2 | For each workspace with legacy policies: migrate (to a later Phase 3 containment or Kubernetes capability) or retire? | Customer-facing decision recorded per workspace, after the compatibility view (§3.1) has shipped |
| G3 | Are legacy actions archived? | Export of `agent_policy_actions` and confirmations into Logs completed and checked |
| G4 | Retirement | G1–G3 done; workers off in every environment for one release; then routes, workers and code removed in one change, with the tables retained read-only for the audit period and dropped only by a later contract migration |

```sql
-- G1, read-only, on the read replica
SELECT 'agent_policies' t, count(*) n, count(DISTINCT workspace_id) ws FROM agent_policies
UNION ALL SELECT 'enabled agent_policies', count(*), count(DISTINCT workspace_id) FROM agent_policies WHERE enabled
UNION ALL SELECT 'agent_policy_actions (30d, live)', count(*), count(DISTINCT workspace_id)
  FROM agent_policy_actions WHERE acted_at > now() - interval '30 days' AND NOT dry_run
UNION ALL SELECT 'agent_policy_warnings', count(*), count(DISTINCT workspace_id) FROM agent_policy_warnings
UNION ALL SELECT 'provisioning_instructions (30d)', count(*), count(DISTINCT workspace_id)
  FROM provisioning_instructions WHERE created_at > now() - interval '30 days'
UNION ALL SELECT 'governance_notification_settings', count(*), count(DISTINCT workspace_id) FROM governance_notification_settings;
```

Rollback for each step: turning `IGA_LEGACY_AGENT_POLICY` back on restores
the previous behavior; the compatibility view is read-mostly; archives are
copies.

## 5. Order of work

1. Repair the stale-report defect, and add the missing `auditAdminMutation`
   calls to `ForceEvictAgent` and `UpdateNotificationSettings`
   (`governance_controller.go:831,922`) (independent).
2. Ship the gate (default `on`) and the compatibility view; Phase 3 R1a can
   proceed in parallel because it owns no artifact the legacy stack touches.
3. Run G1. If every count is zero, propose retirement directly (G4) after one
   release with the gate off.
4. Otherwise G2 per workspace, G3, then G4.
5. R1k does not start its deployment job on a cluster until §3.3 holds.

## 6. Not verified

| Unknown | How to settle |
|---|---|
| Production row counts | G1 query on the read replica |
| Deployed image and whether it is ahead of local `authsec-staging` | Compare the running image with repository revisions |
| Deployed iga-agent version (local `main` lacks evict/delete; `origin/main` has them) | Read the agent version from cluster registrations |
| Whether hand-run deltas exist in production | `information_schema` check on the replica |
