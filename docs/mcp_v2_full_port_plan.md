# Full kitchen-sink port plan — every endpoint the dev UI calls

This is the plan for porting all 29 missing endpoints from the dev
`/authsec/applications/:id/*` surface onto the prod-mcp-v2 backport so
the deployed admin UI at `ritam.dev.authsec.dev/applications/:id/*` can
drive a tenant-scoped Application end-to-end against the prod backend.

**Total estimate:** 2-3 working days of focused engineering. ~3000 lines
of Go, ~8 new tenant-DB tables, ~50 new tests in the existing test
harness if we add coverage.

**Not starting until you sign off on this plan.**

---

## Inventory: what's missing vs what's on the backport today

### Already on backport (do not re-port)

```
GET    /authsec/applications
POST   /authsec/applications
GET    /authsec/applications/:id
DELETE /authsec/applications/:id
GET    /authsec/applications/:id/clients
POST   /authsec/applications/:id/rotate-introspection-secret
POST   /authsec/applications/:id/validate
POST   /authsec/applications/:id/test
POST   /authsec/applications/:id/launch
GET    /authsec/applications/:id/access-policy
PUT    /authsec/applications/:id/access-policy
GET    /authsec/applications/:id/access            (alias of access-policy)
GET    /authsec/applications/:id/identity-providers
POST   /authsec/applications/:id/identity-providers
DELETE /authsec/applications/:id/identity-providers/:idp_id
GET    /authsec/applications/:id/sdk-policy        (SDK, Basic auth)
PUT    /authsec/applications/:id/sdk-manifest      (SDK, Basic auth)
GET    /authsec/resource-servers/:id/sdk-policy    (same handler, dev URL)
PUT    /authsec/resource-servers/:id/sdk-manifest  (same handler, dev URL)
GET    /authsec/oauth/v2/*  (full v2 OAuth surface)
GET    /authsec/identity-providers (and CRUD)
```

### Missing — to port

29 endpoints across 8 groups. Bundled into phases by dependency.

| Phase | What | New tables | Endpoints | Hours |
|---|---|---|---|---|
| 1 | Reads from existing data | none | 5 GET endpoints | 2 |
| 2 | Activation state machine | none (uses existing `resource_servers` columns) | 3 POST endpoints | 2 |
| 3 | Connection admin (prereg + revoke) | none (extends existing tables) | 2 endpoints | 2 |
| 4 | Drift events | `application_drift_events`, `application_drift_event_dismissals` | 2 endpoints + emit retrofits | 3 |
| 5 | Scope CRUD | `oauth_scopes` (per-application) | 5 endpoints | 3 |
| 6 | Tool→scope mapping | extends `mcp_tools` | 2 endpoints | 1 |
| 7 | Consent grants | none (table 024 already exists) | 2 endpoints | 1 |
| 8 | RBAC bindings + roles + users | `application_roles`, `application_role_scope_grants`, `application_role_bindings` | 12 endpoints | 8 |
| 9 | Governance views | none (read-only joins across existing tables) | 7 endpoints | 6 |

**Cumulative:** Phase 1-7 = 14 hours (~2 days). Phase 8-9 = +14 hours (~2 more days). Total: 28 hours, ~3-4 working days realistically.

---

## Phase 1 — Easy reads (2 hours)

Data already exists on the backport; just need handlers + JSON shaping.

| Endpoint | Source data | Handler |
|---|---|---|
| `GET /authsec/applications/:id/tools` | `mcp_tools` table (already on backport) | New: `ListTools` on `applications_v2_controller.go`. JWT-protected. Return same shape as `sdk-policy` but admin-flavored (no `policy_complete`, just rows). |
| `GET /authsec/applications/:id/scopes` | `resource_servers.scopes_supported` array | Trivial: read the column, return as array of `{name}` objects |
| `GET /authsec/applications/:id/scope-matrix` | `mcp_tools` joined with `scopes_supported` | Compose from the two above |
| `GET /authsec/applications/:id/sdk-manifest-status` | `resource_servers.last_successful_generation` + `resource_servers.scan_generation` + count of `mcp_tools` rows | Trivial read |
| `GET /authsec/applications/:id/setup` | Compose: state, has-secret-rotated, has-policy, has-clients, has-tools | Trivial join, returns checklist |
| `GET /authsec/applications/:id/activation-preview` | Same source as setup + "would-pass-validate" check | Reuse onboarding service, narrower view |

**No schema changes.** All routes JWT-auth-protected.

---

## Phase 2 — Activation state machine (2 hours)

| Endpoint | Behavior |
|---|---|
| `POST /authsec/applications/:id/activate` | Validate readiness (state must be `needs_setup` AND at least 1 client registered AND access-policy enabled OR explicit override flag). Flip `state='ready'`, set `setup_completed_at=now()`, `setup_completed_by=user_id`. Returns updated RS row. |
| `POST /authsec/applications/:id/rescan` | Increment `scan_generation`, set `scan_in_progress=true`, kick off a no-op "scan" (just clears in-progress). Backport doesn't actually scan; this exists so the UI can show "rescan triggered" feedback. |

These need a **`ActivateApplication`** service method that does the readiness check. Dev's version is in `onboarding_service.go` ~800 lines; lean version is ~100 lines.

---

## Phase 3 — Connection (OAuth client) admin (2 hours)

The backport has `GET /applications/:id/clients` (read). Adds the write side.

| Endpoint | Behavior |
|---|---|
| `POST /authsec/applications/:id/connections` | Admin pre-registers an OAuth client (the "prereg" registration mode). Body: client_name, redirect_uris, grant_types, etc. Mints the Hydra client + writes `mcp_oauth_clients` (master) + `resource_server_client_registrations` (tenant) with `registration_type='prereg'`. Returns the client_id + a one-time client_secret (since these aren't public DCR). |
| `DELETE /authsec/applications/:id/connections/:client_id` | Revoke. Mark `resource_server_client_registrations.status='revoked'`, set `revoked_at=now()`. Mark `mcp_oauth_clients.sync_status='pending_delete'`. Reconciler does the Hydra delete. |

Reuses the same Hydra service the backport already has. ~150 lines.

---

## Phase 4 — Drift events (3 hours)

| What | Details |
|---|---|
| Schema | New tenant table `application_drift_events(id, application_id, tenant_id, event_type, event_payload, occurred_at, occurred_by)`. CHECK constraint on event_type: `('scope_deleted','tool_unmapped','default_role_disabled','secret_rotated')`. New tenant table `application_drift_event_dismissals(event_id, admin_user_id, dismissed_at)`. |
| Service | `DriftService` with `EmitEvent(applicationID, eventType, payload, occurredBy)`, `ListUndismissed(applicationID, adminUserID, setupCompletedAfter)`, `Dismiss(eventID, adminUserID)`. |
| Retrofit emit sites | Every admin mutation that *destroys* something post-activation must emit: `RotateIntrospectionSecret` (emit `secret_rotated`), `UpdateAccessPolicy` (emit `default_role_disabled` when toggling off), `Scope deletion` (Phase 5), `Tool unmapped via PUT /tool-scope-map` (Phase 6). |
| Endpoints | `GET /:id/drift-events`, `POST /:id/drift-events/:event_id/dismiss` |

This is the most cross-cutting phase. Drift events touch ~5 existing handlers.

---

## Phase 5 — Scope CRUD (3 hours)

The backport stores scopes as a flat array `resource_servers.scopes_supported`. The UI expects a real table you can CRUD.

| What | Details |
|---|---|
| Schema | New tenant table `oauth_scopes(id, application_id, tenant_id, scope_string, display_name, description, risk_level, created_at, updated_at)`. Unique on `(application_id, scope_string)`. |
| Migration | Backfill: existing rows on `resource_servers.scopes_supported` get one `oauth_scopes` row each on first read; or one-shot SQL backfill. **Recommend the one-shot SQL** so backfill is explicit. Keep `scopes_supported` column populated by trigger or backend logic on every scope CRUD for back-compat with `sdk-policy` consumers. |
| Endpoints | `GET /:id/scopes` (list), `POST /:id/scopes` (create), `PUT /:id/scopes/:scope_id` (update display name/description), `DELETE /:id/scopes/:scope_id` (delete, emits drift event if app is ready) |

This is a real schema change. Carefully sequenced: deploy the migration, run the one-shot backfill, then deploy the code that reads/writes the new table.

---

## Phase 6 — Tool→scope mapping (1 hour)

Extends `mcp_tools` from Phase-6 / commit `86d237c`.

| Endpoint | Behavior |
|---|---|
| `PUT /authsec/applications/:id/tool-scope-map` | Body: `{tool_id, required_scopes: [...]}`. Updates `mcp_tools.required_scopes` for that tool. If app is ready, emits `tool_unmapped` drift event when required_scopes goes from non-empty to empty. |
| `POST /authsec/applications/:id/tools/:tool_id/public` | Flip `mcp_tools.is_public=true`. Same drift-event semantics. |

---

## Phase 7 — Consent grants (1 hour)

`oauth_consent_grants` table (migration 024) already exists. Just need handlers.

| Endpoint | Behavior |
|---|---|
| `GET /authsec/oauth/consent-grants` | List the calling user's consent grants. Filter by `?application_id=`. |
| `DELETE /authsec/oauth/consent-grants/:id` | Mark `revoked=true`, `revoked_at=now()`. Also call Hydra `/admin/oauth2/auth/sessions/consent` to invalidate the upstream consent. |

Per the existing dev URL pattern, these mount under `/authsec/oauth/` not `/authsec/applications/:id/`. UI filters by application_id query param.

---

## Phase 8 — RBAC: roles + bindings + users (8 hours)

This is the trap from before. Honest cost.

| What | Details |
|---|---|
| Schema | Three new tenant tables: `application_roles(id, application_id, tenant_id, name, description, created_at)`, `application_role_scope_grants(role_id, scope_id)`, `application_role_bindings(id, application_id, role_id, user_id, granted_at, granted_by)`. Plus needing to integrate with prod's existing `users` table. |
| Service | Full role-binding logic: resolve effective access (user → bindings → role → scope_grants → scopes), enforce that all granted scopes are in the application's supported set, prevent orphan bindings on application delete (CASCADE). |
| Endpoints (12) | `GET /:id/roles`, `POST /:id/roles`, `PUT /:id/roles/:role_id/scope-grants`, `GET /:id/bindings`, `POST /:id/bindings`, `DELETE /:id/bindings/:binding_id`, `GET /:id/eligible-users`, `GET /:id/access/users`, `GET /:id/users/:user_id/effective-access`, plus three sub-views the UI references (`access-assignments`, `access-change-previews`, `access-simulations`) |
| Wires into | The access policy's `default_role_id` (Phase 4 of original backport). The `/authorize` flow's scope filtering (deeper than current PHASE3-SCOPE). The dev branch's `scope_resolver.go` (~500 lines on dev) — most ports here. |

**This is where the multi-day estimate concentrates.** ~1500 lines of Go, careful schema design.

---

## Phase 9 — Governance views (6 hours)

Read-only joins across the tables Phase 8 builds.

| Endpoint | Notes |
|---|---|
| `GET /:id/effective-access` | A user's resolved scopes for this application |
| `GET /:id/end-user-access-summary` | Per-user scope/role summary, paged |
| `GET /:id/evidence-exports` | CSV export of access grants — auditable |
| `GET /:id/tool-exposure` | Which tools are reachable by which users |
| `GET /:id/posture-summary` | Compliance posture: # users, # roles, # public tools, # binding-less users |
| `GET /:id/access-assignments` | Read-only view of all bindings, filterable |
| `GET /:id/access-change-previews` | Dry-run a binding mutation, show diff before commit |
| `GET /:id/access-simulations` | Simulate "if user X had role Y, what scopes would they get" |

These are mostly view-models composed from Phase 8 data. No new tables, but the queries are non-trivial.

---

## Execution plan — proposed session schedule

| Session | Phases | Hours | Output |
|---|---|---|---|
| 1 (today) | Plan + curl runbook for existing endpoints | 1.5 | Plan committed, runbook committed, you can test current backport |
| 2 | Phase 1-3 (reads + activation + connections) | 6 | Backport handles 7 endpoints, Setup tab + parts of Tools/Scopes start working |
| 3 | Phase 4 + 7 (drift events + consent grants) | 4 | Drift banner works in UI, Consent Grants tab works |
| 4 | Phase 5 + 6 (scope CRUD + tool-scope map) | 4 | Scopes tab fully functional, Tools tab editable |
| 5 | Phase 8 part 1 (roles + scope grants) | 4 | Bottom half of Access tab partially works |
| 6 | Phase 8 part 2 (bindings + users) | 4 | Access tab fully functional |
| 7 | Phase 9 (governance views) | 6 | Access governance subviews work |

Each session ends with `go build ./...` clean + a commit on `authsec-prod-mcp-v2`. You review between sessions and can stop after any phase if it's "enough."

---

## Risks I want flagged before we start

1. **Schema migration ordering.** Phase 5 (scope CRUD) introduces a new `oauth_scopes` table while still keeping `resource_servers.scopes_supported` in sync. There's a 5-minute window during deploy where new rows might not have the array yet — the SDK's `/sdk-policy` falls back to deny-all if the array is empty, which means MCP clients get 403s. Mitigation: deploy with a feature flag, run the backfill, then flip the flag on.

2. **Phase 4 (drift events) retrofitting.** Adding emit calls to existing handlers (`rotate-introspection-secret`, `update-access-policy`) means modifying code I already committed. Future code reviewers may not realize those emit calls are part of an evolving system. Mitigation: clear comments on each emit site referencing this plan.

3. **Phase 8 RBAC integration with the existing dev RBAC tables.** Prod already has `roles`, `permissions`, `role_bindings` at the workspace level. The Application-scoped RBAC in Phase 8 either reuses those (complex) or duplicates with `application_` prefix (clean but parallel state). I recommend the duplicate route — less coupling, easier to test, the prod RBAC already has tenant_id semantics that don't translate cleanly to "scoped to a single Application within a tenant."

4. **Phase 9 governance views call into Hydra audit logs** that the backport doesn't have visibility into for compliance reporting. We'd return "audit data unavailable" rather than empty arrays, so the UI shows the gap honestly rather than misleading. Alternative: add a logs-fetch shim to Hydra's admin audit endpoint. ~1 hour additional if you want real data.

---

## Approval

If you're good with this plan, say "approved" and we go to session 2 next time. If you want to change scope (drop phases, reorder, change estimates), tell me. If you want me to start any phase **today** despite the multi-day estimate, name which one.

This session ends with:
- This plan committed
- A curl runbook covering every endpoint that's already on the backport
