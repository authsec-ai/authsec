# SPEC: AWS scheduled scans (automatic rediscovery)

> Status: implemented 2026-10-16; builds, unit tests and the real-Postgres suite
> (`tests/awsschedule`) pass. Ships dark (gate off). Items under "Unverified" are
> not proven and must be before the default is turned on.
> Built differently from the first draft below: the API offers daily (1440) and
> weekly (10080) only (the table still accepts 360..10080); a slot skipped because
> a scan was already running is retried after 1 hour, not a whole interval later.

## Summary

Today an AWS connector is scanned only when a person clicks **Scan now**
(`POST /discovery/aws/connectors/:id/scan`, which enqueues a `cloud_scan_run`
with trigger `"manual"`). This feature lets a connected account rescan itself on
a schedule, so the inventory, change feed and governance findings stay current
without anyone remembering to click. The scheduler is a loop inside the AuthSec
backend that enqueues the same scan a person would. It adds no new AWS access:
same read-only role, same hard denies, nothing installed in the customer's
account, no agent.

The cadence is chosen per connector: off, daily (recommended), weekly.
Manual scan stays unchanged.

## Scope

**In scope:**
- A per-connector schedule (enabled, interval) stored in a new table.
- A scheduler loop in the backend that enqueues `trigger = "scheduled"` runs.
- Safe multi-replica operation, per-connector jitter, minimum interval 6h.
- Auto-pause after repeated failures, with a visible reason; resume by the admin.
- API to read/update the schedule; console controls and "last / next scan" display.
- Audit of schedule changes (user) and of scheduled scans (system actor).
- Env gate, default OFF, so it ships dark.

**Out of scope (deferred):**
- Event-driven refresh (EventBridge/CloudTrail forwarding). It needs a customer-side
  resource, a new template version and customer stack updates (see B11 of
  SPEC-aws-quick-create-onboarding.md). Separate spec.
- GCP and GitHub scheduling. They use their own pipelines (`DiscoveryScanRun` for
  GitHub). The table is provider-neutral so they can adopt it later.
- A platform-wide default schedule for new connectors. Decide after the soak (see Rollout).
- Email/Slack notification of a paused schedule (log line + console banner only in v1).
- Hourly or finer cadence. Weekly is the slowest option offered.
- Organizations / multi-account fan-out.

## Affected repos

| Repo | What changes | Why / why not |
|---|---|---|
| `authsec` | New table `cloud_scan_schedule`, scheduler service + loop, 2 endpoints, env gate | Core of the feature |
| `Authsec-ui` | Auto-scan section in the connection detail; 2 RTK Query endpoints on the discovery slice | Admins need to set and see it |
| `sdk-authsec` | none | Admin-console configuration of a connector; no agent, workload or MCP server calls it |
| `authsec-doc` | Update the AWS discovery/onboarding page: scheduled scans, what customers see in CloudTrail, how to turn off | Operators and customers need to know AuthSec will call their account daily |
| Production K3s | New env var `AUTHSEC_AWS_SCHEDULED_SCANS` (default off). No new workload: runs in the existing backend | Topology unchanged; verify the env in deployment checks |

## Backend spec (authsec)

### How it fits what exists (code)

- `CloudScanRunRepository.Enqueue(workspace, connector, trigger)` already takes a
  trigger string and relies on a partial unique index on `(connector_id) WHERE
  status IN ('queued','running')`; a second live run returns `ErrScanAlreadyLive`.
  The scheduler calls it with `"scheduled"` and treats `ErrScanAlreadyLive` as "skip".
- `AWSScanWorker` claims runs with a lease + fence token. A scan that returns an
  error is marked `failed` at once and is NOT retried (verified in `RunOnce`);
  `scanMaxAttempts = 3` only caps reclaims of runs whose worker crashed. So a
  failed scheduled scan stays failed until the next scheduled slot. Unchanged.
- A failed scan does not touch `cloud_connector.status` or `last_error` (only
  `VerifyConnector` does). Failures are visible only in run history, so the
  console must surface them itself (see Frontend).
- Re-onboarding an account upserts the same `cloud_connector` row and writes
  `status` back to active, so a revoked connector that is re-connected becomes
  schedulable again. See "Revoke and re-onboard".
- In pipeline mode (`IGA_GRAPH_PROJECTION` on) a workspace barrier lets only one
  connector per workspace collect/project at a time; a refused run goes to the back
  of the queue. So several scheduled accounts in one workspace run one at a time.
  The scheduler does not need to know; jitter keeps it from piling up.
- Background workers are started in `cmd/main.go` behind env switches
  (`AUTHSEC_DISABLE_AWS_SCAN_WORKER`, Vault required). The scheduler starts in the
  same block, only if the scan worker starts and the new gate is on.
- The tenant ratchet applies: a cross-workspace statement needs a `TENANT-EXEMPT`
  reason (as the scan claim has); per-workspace writes go through
  `tenancy.InWorkspace`.

### Schema changes

Why a new table rather than columns on `cloud_connector`: that table is a shared
contract with the Azure and GCP connectors (see `models/cloud_discovery.go`), and
`attrs` is the AWS onboarding blob that the region PATCH rewrites. A separate
table avoids both.

```sql
-- 139_cloud_scan_schedule.sql  (next free master number; highest today is 138)
CREATE TABLE IF NOT EXISTS public.cloud_scan_schedule (
    connector_id         uuid PRIMARY KEY,
    workspace_id         uuid NOT NULL,
    enabled              boolean NOT NULL DEFAULT false,
    interval_minutes     integer NOT NULL DEFAULT 1440
                         CHECK (interval_minutes BETWEEN 360 AND 10080),
    next_due_at          timestamptz,
    last_enqueued_at     timestamptz,
    streak_since         timestamptz,   -- scheduled runs older than this do not count toward pausing
    paused_reason        text NOT NULL DEFAULT '',   -- '' = not paused
    updated_by           text NOT NULL DEFAULT '',
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    -- composite, workspace-qualified like every cloud_* table (migration 027):
    FOREIGN KEY (workspace_id, connector_id)
        REFERENCES public.cloud_connector (workspace_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS cloud_scan_schedule_due_idx
    ON public.cloud_scan_schedule (next_due_at) WHERE enabled AND paused_reason = '';
-- Required for every workspace table; guarded form as in 137_access_policies.sql
DO $$
BEGIN
    IF to_regprocedure('public.tenancy_enable_rls(regclass)') IS NOT NULL THEN
        PERFORM public.tenancy_enable_rls('public.cloud_scan_schedule');
    END IF;
END $$;
```
There is no failure counter column: the failure streak is derived from the last
runs (see algorithm), so it cannot drift from the run history.

Also update `001_bootstrap.sql` to the same final state, then run
`scripts/schema-parity.sh`. No row means "never scheduled" (same as `enabled=false`).

### Scheduler algorithm (`services/cloud_aws_scan_scheduler.go`)

Tick every 60s (injectable clock, like `AWSScanWorker.WithClock`). Each tick:

1. **Claim due schedules atomically** (one statement, cross-workspace, `TENANT-EXEMPT`):
   select up to 20 rows where `enabled`, `paused_reason = ''`, `next_due_at <= now`,
   connector `provider='aws'` and `status <> 'revoked'`, `ORDER BY next_due_at`,
   `FOR UPDATE SKIP LOCKED`; in the same statement set `next_due_at = now + 5 min`
   (a short lease), and return the row's previous `next_due_at` (step 2b anchors on it). Two replicas can never claim the same row; a crash between claim
   and enqueue costs 5 minutes, not a whole interval.
2. For each claimed row (the claim returns its workspace, connector, interval):
   a. **Decide whether to pause.** Read the connector's last 3 runs with
      `trigger = 'scheduled'` (newest first). If there are 3 and all are
      `failed` or `abandoned`, set `paused_reason` (short code + last error),
      log `[aws-sched] ALERT paused`, and stop. If there are none, continue
      (`ErrCloudScanRunNotFound` is not an error here).
   b. **Advance first, then enqueue** (at most once per slot): in one scoped
      transaction set `last_enqueued_at = now` and
      `next_due_at = anchor + interval + jitter`, where `anchor` is the slot's
      previous `next_due_at` when it is less than one interval old, else `now`
      (so the schedule does not drift later by the scan duration, and does not
      replay a backlog after an outage).
   c. `Enqueue(ws, connector, "scheduled")`. `ErrScanAlreadyLive` means a scan is already
      running: no new scan, and the slot is retried in 1 hour (`schedLiveRetry`) so
      a busy moment does not cost a whole interval (a week, on weekly).
      Any other error: set `next_due_at = now + 5 min` and log, so it retries soon.
3. **Jitter** is deterministic per connector: a hash of `connector_id` mapped into
   `0 .. min(interval/10, 30 min)`. Connectors spread out and each keeps a stable slot.
4. After an outage every overdue schedule is due on the first tick. The claim takes
   20 per tick, and the workspace barrier runs one connector per workspace at a time,
   so this is bounded; it should still be exercised in the load test.

Why 3 and not more: a failed scan is not retried, so at daily cadence 3 failures
is 3 days of stale data; at weekly it is 3 weeks. The console therefore shows
"last scheduled scan failed" immediately (see Frontend), not only when paused.
A connector whose `status` is `error` (its last verify failed) is still scanned,
because the scan is the thing that will prove or disprove it.

**Revoke and re-onboard.** `RevokeConnector` also sets the schedule
`enabled = false` (same request, audited). Re-onboarding therefore never silently
resumes an old schedule; the admin turns it on again. The scheduler additionally
skips any connector whose status is `revoked`.

**Tenant layer (check-tenant-exempt.sh).** The main baseline is 0, so every
unscoped statement in the new files needs a `TENANT-EXEMPT: <reason>` comment or
must go through the scoped layer. Plan: the cross-workspace claim carries a
`TENANT-EXEMPT` reason (same wording style as the scan claim in
`cloud_scan_run_repository.go`); the per-connector schedule writes run in
`tenancy.InWorkspace`; `Enqueue` keeps its own handle, exactly as
`ScanIAM` calls it today (it is not part of that transaction). The repository and
service files are listed in `tenant-rls-files.txt`; the one cross-workspace
statement (`ClaimDue`) carries its `TENANT-EXEMPT` reason.

### Gate

`AUTHSEC_AWS_SCHEDULED_SCANS` (default off; same style as the `IGA_*` gates). Off:
the loop never starts, the schedule endpoints still read and write (so settings can
be prepared) but the response says `scheduler_active: false` and the UI shows
"Scheduling is not active on this deployment". The scheduler also refuses to run
when the scan worker is disabled.

### New endpoints

```
GET /authsec/discovery/aws/connectors/:id/schedule
Auth: discovery:read
Response 200: { data: { enabled, interval_minutes, next_due_at, last_enqueued_at,
                        paused_reason, scheduler_active },
                meta: { as_of } }     // no row => enabled:false defaults, 200
Errors: 400 (bad id), 401, 403, 404 (not this workspace's connector), 500

PUT /authsec/discovery/aws/connectors/:id/schedule
Auth: discovery:admin
Request body: { enabled: bool, interval_minutes: int }   // 1440 or 10080, unknown fields rejected
Response 200: same shape as GET
Errors: 400, 401, 403, 404, 409 (connector revoked), 422 (interval out of range)
Audit: auditAdminMutation "update_scan_schedule" with before/after
```

Routes sit beside the other `/aws/connectors/:id/...` routes in `routes/routes.go`.
`PATCH /aws/connectors/:id` is left alone (it requires `regions` and rejects unknown
fields).

### Trigger and audit

- Scheduled runs carry `trigger = "scheduled"` (the column already exists).
- Scheduler audit entries use a system actor (`system:scheduler`), following the
  `auditConnected` pattern in `cloud_aws_quickcreate.go`, so they are distinguishable
  from a person's scan.
- Log lines are prefixed `[aws-sched]` with `connector=<id> ref=...`, like `[aws-onb]`.

### Token flow changes

None.

## Frontend spec (Authsec-ui)

### Modified page(s)

- AWS connection detail (`features/iga/connections/ConnectionParts.tsx` header and
  detail area; the **Scan now** button is already there). Add an **Auto-scan** block:
  toggle, interval select (Daily (recommended) / Weekly),
  "Last scan" (from the latest run, with a **Scheduled** or **Manual** label),
  "Next scan" (from `next_due_at`).
- Failed state, shown at once: when the latest run is `failed`, say "Last scan
  failed" with its `last_error`, because a failed scan does not change the
  connector's status. (The Scans tab already shows the trigger, so scheduled runs
  appear there as "scheduled" with no change.)
- Paused state: banner "Auto-scan paused after 3 failed scheduled scans: <reason>",
  with a **Resume** action that PUTs `enabled: true`.
- AWS only. The connection detail is shared by AWS, GCP, Kubernetes and GitHub
  (`OverviewTab.tsx` branches on `c.provider`); render the block only for
  `c.provider === "aws"`. Scan now keeps its shared behaviour.
- Stale warning when the last published scan is older than 2x the interval.
- If `scheduler_active` is false, show the controls disabled with the note above.
- Short customer-facing line: "AuthSec reads your account on this schedule using the
  read-only role. You will see its sessions in your CloudTrail."
- RTK Query: `getAwsConnectorSchedule` and `updateAwsConnectorSchedule` via
  `injectEndpoints` in `app/api/cloudDiscoveryApi.ts` (same slice as
  `scanAwsConnector`). The exact component for the AWS detail view should be
  confirmed when implementing.

## SDK impact

None. This is an admin-console setting on a connector. No agent, workload or MCP
server has a reason to configure it programmatically.

## Acceptance criteria

- [ ] With the gate off, no scheduler goroutine starts and no `scheduled` run is ever created.
- [ ] With the gate on, a connector with `enabled=true` and `next_due_at` in the past gets exactly one `cloud_scan_run` with `trigger='scheduled'` per tick, and `next_due_at` moves forward by interval + jitter.
- [ ] Two scheduler instances against one database enqueue one run per due connector (test with two schedulers and a fake clock).
- [ ] A due connector that already has a queued or running scan is skipped without error, and its next due time still advances.
- [ ] A revoked connector is never scheduled; PUT on a revoked connector returns 409.
- [ ] After 3 consecutive failed scheduled runs the schedule is paused with a reason and enqueues nothing until resumed; a manual run in between does not count toward or reset the streak.
- [ ] Revoking a connector disables its schedule; re-onboarding the same account does not resume it.
- [ ] A due connector with no earlier runs is scheduled without error.
- [ ] `next_due_at` does not drift: after N slots it equals the first slot + N x interval + jitter, within one tick.
- [ ] After a simulated 2-day outage, overdue schedules fire at most 20 per tick and each connector fires once, not once per missed slot.
- [ ] `interval_minutes` below 360 or above 10080 returns 422; unknown body fields return 400.
- [ ] Another workspace's connector id returns 404 on both endpoints; `rls_test.go` passes for the new table.
- [ ] `scripts/schema-parity.sh` passes; `scripts/check-tenant-exempt.sh` passes with the main baseline still 0.
- [ ] Manual **Scan now** behaves exactly as before.
- [ ] `go build ./...` and `npx tsc --noEmit` exit 0.

## Implementation plan

1. Migration `139_cloud_scan_schedule.sql` + `001_bootstrap.sql`; run schema parity and the RLS test.
2. Model + repository (`CloudScanScheduleRepository`: get, upsert, claim-due, advance, pause, disable-on-revoke).
3. Scheduler service with injectable clock; unit tests (fake clock, two schedulers, already-live, pause, jitter spread).
4. Gate + startup in `cmd/main.go`; env var added to the K3s config.
5. Controller handlers + routes + audit; handler tests.
6. UI: RTK endpoints, Auto-scan block, paused/stale states.
7. Docs page update.
8. Build, deploy dark to staging, migration-ledger check, smoke test.

## Rollout

1. Ship with the gate off.
2. Turn it on for one internal workspace at daily; watch a week.
3. Allow customers to toggle it. Only after that, decide as a product call whether
   new connectors default to daily.

Watch during the soak: scan duration vs interval, `throttled`/`partial` coverage,
projection job lag, queue age, runs ending `failed`, and how many connectors pause.

## Unverified (prove before default-on)

- Migration number 139: it was the next free number in `migrations/master` today,
  but other branches (for example `authsec-staging`) also add migrations. Re-check
  the number when the work starts.
- Full-scan duration on a large real account against the 1-hour assumed-role session.
- Behaviour with many connectors due at once (load test with fake connectors).
- AWS API throttling at daily cadence for large accounts.
- Whether a customer's CloudTrail volume from daily scans is acceptable to them.
- Industry cadence norms (daily for CSPM and identity governance) are from memory,
  not researched; web search was unavailable.

## Related docs

- `AWS-AUTO-ONBOARDING.md`, `SPEC-aws-quick-create-onboarding.md`
- `SPEC-iga-phase1-collect.md` (SCAN_SCHEDULE model), `SPEC-iga-phase2-graph.md` (scan worker, barrier, "scheduled scans" deferral)

## Addendum: choosing a time of day (migration 140)

An administrator can choose WHEN a schedule runs, not only how often.

- **Fields** (all optional on `PUT .../schedule`, returned by `GET`):
  `time_of_day` ("HH:MM", quarter hours), `timezone` (IANA name, default UTC),
  `day_of_week` (0 = Sunday to 6, weekly only). Omitted fields keep their value.
- **No time chosen = the original behaviour**: one interval after the schedule
  was turned on. Existing schedules are unchanged by migration 140.
- **With a time**: the next scan is the next occurrence of that wall-clock time
  in the chosen zone. The per-connector jitter is added AFTER it, so a scan
  starts between the chosen time and 30 minutes later; the UI says so.
- **Turning on, resuming or changing the interval** recomputes the next scan.
  **Changing only the time** recomputes it too but does not reset the failure
  streak.
- **Weekly with a time requires `day_of_week`** (422 `invalid_parameter`).
- **Daylight saving** is handled in `internal/scanslot`: a local day always has
  exactly one slot. A time that does not exist on the day clocks go forward
  runs at the end of the gap; a time that occurs twice runs once. Tested in
  `internal/scanslot/slots_test.go` across eight zones and three years.
- **After an outage** a missed slot runs once, then the next future slot, as before.
- **Validation errors** are `422 invalid_parameter` naming `time_of_day`,
  `timezone` or `day_of_week`.
