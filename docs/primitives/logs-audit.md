# Logs & Audit

> Read this before adding new log types, modifying audit helpers, or touching the
> Logs UI API endpoints.
> Files: `services/logs_service.go`, `controllers/platform/{logs_controller,audit_helper}.go`.

## Log streams

AuthSec writes to three distinct streams, served from two tables:

| Stream | Source table | What goes in it |
|---|---|---|
| **Auth logs** | `audit_events` (where `resource='authentication'`) | Login attempts, token issuances, OIDC callback events |
| **Audit logs** | `audit_events` (where `resource<>'authentication'`) | Admin mutations: create/update/delete workspace config, roles, scopes, clients, bindings |
| **M2M logs** | `auth_issuance_audit` | Machine-to-machine token issuances (client_credentials, native M2M grants) |

SPIRE audit events are **separate** — stored in `spire_audit_logs` and served by
`SpireController`, not `LogsController`.

## `services/logs_service.go` — `LogsService`

Read-only layer over the two log tables. Constructed via `NewLogsService(db)`.

| Method | Description |
|---|---|
| `AuthLogs(wsID, status, action, page, limit)` | Auth events for a workspace. `status` = `"success"` / `"failure"` (blank = all). Filters on `resource='authentication'`. |
| `AuditLogs(wsID, action, resource, page, limit)` | Admin audit events (non-auth). Optional `action` + `resource` exact-match filters. |
| `M2MLogs(wsID, clientID, page, limit)` | M2M issuance records. Optional `clientID` filter. |

Limits: default 50, max 200 per page (`defaultLogLimit` / `maxLogLimit`). `clampPage`
normalises out-of-range values.

## `controllers/platform/audit_helper.go` — `auditAdminMutation`

```go
auditAdminMutation(c *gin.Context, workspaceID, action, resource, resourceID string, statusCode int, oldValues, newValues interface{})
```

Called by every admin mutation handler (create/update/delete on workspace resources) to
write an `audit_events` row via `config.AuditLogger.LogAdminAction`. Uses
`middlewares.ResolveUserID(c)` for the actor. Call this immediately before (or as part
of) returning the HTTP response — pass the actual status code that will be returned.

Silently returns if `config.AuditLogger == nil` (test environments / early boot).

## Writing a new audit event

1. At the mutation site, call `auditAdminMutation(c, wsID, "action_name", "resource_type", resourceID, statusCode, oldValues, newValues)`.
2. `action` and `resource` are free-form strings; keep them consistent with existing
   conventions (e.g. `"create"` / `"update"` / `"delete"`, `"role"` / `"scope"` / `"client"`).
3. `oldValues` / `newValues` are any JSON-serializable value; pass `nil` for creates
   (no old) and deletes (no new).

## When you're building

- **New log type?** Decide: is it an admin mutation (→ `auditAdminMutation` + `audit_events`)
  or a token issuance (→ `auth_issuance_audit` + existing M2M logging in the grant handler)?
  Don't create a third table without a strong reason.
- **Filtering?** Add query params to `LogsController` + a corresponding filter param to
  the `LogsService` method. Don't add filtering logic in the controller itself.
- **SPIRE audit?** That's in `SpireController` — separate DB table (`spire_audit_logs`),
  separate endpoint, not served by `LogsService`.
- **Pagination** is zero-indexed pages with `page` (1-based) and `limit`. Always clamp
  with `clampPage` before passing to GORM.

## Related

`controllers/platform/logs_controller.go` (HTTP endpoints for all three streams),
`primitives/schema.md` (`audit_events` + `auth_issuance_audit` table definition).
