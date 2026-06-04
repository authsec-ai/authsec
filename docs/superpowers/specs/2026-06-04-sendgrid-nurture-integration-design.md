# SendGrid Nurture Integration — Design Spec

**Date:** 2026-06-04
**Branch:** authsec-prod
**Source doc:** BACKEND-INTEGRATION.md (email pack handoff)

---

## Overview

Extend the authsec backend to enroll and manage contacts in SendGrid Marketing Campaigns as users move through the product lifecycle. Four work areas: login-triggered enrollment, dormant user re-engagement, PQL field update, and plan-upgrade list exit.

---

## Architecture

A new `SendGridService` struct (`services/sendgrid_service.go`) owns all SendGrid HTTP calls, mirroring the existing `HubSpotService` pattern. It is constructed once at startup (in `routes/routes.go` alongside the other controllers) and injected into the controllers that need it.

No external SDK — raw `http.Client` calls matching the pattern already used for HubSpot.

---

## Components

### `services/sendgrid_service.go` (new)

```
SendGridService
  apiKey     string
  httpClient *http.Client   // Timeout: 30s

Methods:
  UpsertContact(email, firstName, listID string, customFields map[string]string) (jobID string, err error)
    PUT /v3/marketing/contacts
    Omits list_ids when listID == "" (field-only update for returning/PQL users)
    Returns the job_id from the 202 response body for logging

  RemoveFromLists(email string, listIDs []string) error
    POST /v3/marketing/contacts/search  →  resolve email → contact_id
    DELETE /v3/marketing/lists/{id}/contacts?contact_ids={contact_id}  for each list
```

Both methods log errors and return them; callers decide whether to fail the request or continue (SendGrid is non-blocking for most flows).

---

### `config/config.go`

Add to `AppConfig` struct and `GetConfig()`:

| Field | Env var | Value (from live SendGrid account) |
|---|---|---|
| `SendGridAPIKey` | `SENDGRID_API_KEY` | `SG.EsEbX83j…` |
| `SendGridListNewSignups` | `SENDGRID_LIST_NEW_SIGNUPS` | `6341c397-1de5-43d2-b957-8c258cce12dc` |
| `SendGridListTrialUsers` | `SENDGRID_LIST_TRIAL_USERS` | `d205a4f4-aa63-43a3-b9e6-ab91d760de3f` |
| `SendGridListLeads` | `SENDGRID_LIST_LEADS` | `1d672677-7c3f-48be-8bd7-1597eb488827` |
| `SendGridListDormant` | `SENDGRID_LIST_DORMANT` | `24a16f32-9361-4714-9e68-309dfb789d1e` |
| `SGFieldSegment` | `SG_FIELD_SEGMENT` | `e1_T` |
| `SGFieldTenantID` | `SG_FIELD_TENANT_ID` | `e2_T` |
| `SGFieldFirstLoginAt` | `SG_FIELD_FIRST_LOGIN_AT` | `e3_D` |
| `SGFieldLastLoginAt` | `SG_FIELD_LAST_LOGIN_AT` | `e4_D` |
| `SGFieldIsPQL` | `SG_FIELD_IS_PQL` | `e5_T` |
| `SGFieldPlanType` | `SG_FIELD_PLAN_TYPE` | `w6_T` |

Note: `plan_type` field is `w6_T` (not `e6_T`) — confirmed from live SendGrid field definitions.

---

### Flow 1 — Login notification (`NotifyOwnerNewRegistration`)

**File:** `controllers/enduser/enduser_controller.go`

Extend the input struct:

```go
var input struct {
    UserName     string `json:"user_name,omitempty"`
    TenantDomain string `json:"tenant_domain,omitempty"`
    FirstLogin   bool   `json:"first_login"`
    Segment      string `json:"segment,omitempty"`
}
```

After the existing owner email send, branch on `first_login`:

**first_login = true:**
```
UpsertContact(email, firstName, LIST_NEW_SIGNUPS, {
    SG_FIELD_SEGMENT:        "new-signup",
    SG_FIELD_TENANT_ID:      tenantID,
    SG_FIELD_FIRST_LOGIN_AT: today (YYYY-MM-DD),
    SG_FIELD_PLAN_TYPE:      "trial",
    SG_FIELD_IS_PQL:         "false",
})
Log: sendgrid_job_id, list="seg-new-signups", contact=email
```

**first_login = false:**
```
1. Check DB: is dormant_enrolled = true for this email?
   YES → UpsertContact(email, firstName, LIST_TRIAL_USERS, {
              SG_FIELD_LAST_LOGIN_AT: today,
              SG_FIELD_SEGMENT:       "trial",
          })
          RemoveFromLists(email, [LIST_DORMANT])
          ResetDormantEnrolled(email)  -- sets dormant_enrolled=false, dormant_enrolled_at=NULL
   NO  → UpsertContact(email, firstName, "", {SG_FIELD_LAST_LOGIN_AT: today})
Log: sendgrid_job_id, list=<assigned or "none">, contact=email
```

SendGrid failures are logged but do **not** cause a 500 — the owner email has already been sent and the response returns 200 regardless.

`first_name` is extracted from the JWT claim `given_name` or `name`; falls back to empty string if absent.

---

### Flow 2 — Dormant user cron job

**New DB columns (migration):**
```sql
ALTER TABLE users
  ADD COLUMN dormant_enrolled    BOOLEAN   NOT NULL DEFAULT false,
  ADD COLUMN dormant_enrolled_at TIMESTAMP;
```

Migration file: `migrations/master/<next_number>_add_dormant_columns.sql`

**New DB methods (`database/enduser_repository.go`):**
- `GetDormantUsers(cutoff, cooloffDate time.Time) ([]DormantUserRow, error)`
  Returns `email`, `first_name`, `tenant_id` for:
  ```sql
  WHERE last_login < $1
    AND active = true
    AND (dormant_enrolled = false
         OR (dormant_enrolled = true AND dormant_enrolled_at < $2))
  ```
- `MarkDormantEnrolled(email string) error` — sets `dormant_enrolled=true`, `dormant_enrolled_at=now()`
- `ResetDormantEnrolled(email string) error` — sets `dormant_enrolled=false`, `dormant_enrolled_at=NULL`

**Cron job (`cmd/main.go`):**
Uses `github.com/robfig/cron/v3`. Schedule: `"0 2 * * *"` (02:00 UTC).

```
cutoff     = now - 30 days
cooloffDate = now - 90 days

for each user in GetDormantUsers(cutoff, cooloffDate):
    RemoveFromLists(email, [LIST_NEW_SIGNUPS, LIST_TRIAL_USERS, LIST_LEADS])
    UpsertContact(email, firstName, LIST_DORMANT, {SG_FIELD_SEGMENT: "dormant"})
    MarkDormantEnrolled(email)
    log each step; continue on per-user errors
```

Cron is started after DB and config are initialized; uses a `context.Context` tied to server shutdown for graceful stop.

---

### Flow 3 — PQL hook

**File:** `controllers/platform/hubspot_controller.go`

`SyncContact` already notifies HubSpot. After the existing HubSpot call succeeds, add:

```
sendgrid.UpsertContact(email, "", "", {SG_FIELD_IS_PQL: "true"})
```

No `list_id` — the nurture sequence continues. This is fire-and-forget (log error, don't fail the response).

If the existing `SyncContactRequest` body doesn't include `first_name`, extract it from the JWT context the same way as Flow 1, or accept it as an optional field.

---

### Flow 4 — Plan upgrade exit

**New endpoint:** `POST /uflow/auth/notify/plan-upgrade`

Protected by: `AuthMiddleware()` + `ValidateTenantFromToken()`

Request body:
```json
{ "new_plan": "pro" }
```

Handler (`controllers/enduser/enduser_controller.go`, new method `NotifyPlanUpgrade`):
```
1. UpsertContact(email, "", "", {SG_FIELD_PLAN_TYPE: newPlan})
2. RemoveFromLists(email, [LIST_NEW_SIGNUPS, LIST_TRIAL_USERS, LIST_LEADS, LIST_DORMANT])
3. Return 200 { "message": "plan upgrade recorded", "new_plan": newPlan }
```

Route registered in `routes/routes.go` alongside the existing `notify` group.

---

## Data Flow Summary

```
Login (first)     → UpsertContact → seg-new-signups  (enroll, 5 fields)
Login (returning) → UpsertContact → no list          (last_login_at only)
Login (dormant)   → UpsertContact → seg-trial-users  (re-enroll)
                  + RemoveFromLists → seg-dormant
                  + DB reset

Cron (02:00 UTC)  → GetDormantUsers
                  → RemoveFromLists → [new-signups, trial, leads]
                  → UpsertContact  → seg-dormant
                  → MarkDormantEnrolled

PQL event         → UpsertContact → no list (is_pql="true" only)
                  + HubSpot lifecycle update (existing)

Plan upgrade      → UpsertContact → no list (plan_type update)
                  → RemoveFromLists → all 4 lists
```

---

## Error Handling

- **SendGrid 202**: async job accepted. Log `job_id`. Contacts appear within ~5 min.
- **SendGrid non-202**: log the status and body; treat as non-fatal for login flows.
- **RemoveFromLists contact-not-found**: log and skip silently (contact may never have been enrolled).
- **Cron per-user error**: log the email + error and continue to next user. Don't abort the batch.
- **DB errors in dormant query**: log + skip the entire cron run; alert via existing logging infra.

---

## Dependencies

| Dependency | Purpose |
|---|---|
| `github.com/robfig/cron/v3` | In-process cron scheduler for dormant job |

No SendGrid SDK — matches the project's existing pattern of raw HTTP calls (see `hubspot_service.go`).

---

## File Change Index

| File | Change type |
|---|---|
| `services/sendgrid_service.go` | New |
| `config/config.go` | Extend — 11 new env vars |
| `.env.example` | Extend — add SendGrid stubs with real IDs |
| `controllers/enduser/enduser_controller.go` | Extend `NotifyOwnerNewRegistration`; add `NotifyPlanUpgrade` |
| `controllers/platform/hubspot_controller.go` | Extend `SyncContact` to fire SendGrid PQL update |
| `database/enduser_repository.go` | Add `GetDormantUsers`, `MarkDormantEnrolled`, `ResetDormantEnrolled` |
| `migrations/master/<n>_add_dormant_columns.sql` | New |
| `routes/routes.go` | Register `POST /auth/notify/plan-upgrade` |
| `cmd/main.go` | Start cron goroutine |
| `go.mod` / `go.sum` | Add `robfig/cron/v3` |
