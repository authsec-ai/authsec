# AuthSec coding practices

> Conventions for Go/Gin code in this repo. Read before adding a new endpoint,
> service, or model.

## Layering

```
controller (HTTP, Gin)
    └─ service (business logic, DB)
        └─ model (GORM struct, no SQL)
        └─ internal/tokens, internal/policy, etc. (primitives)
```

- **Controllers** read HTTP, call services, write HTTP. No SQL, no JWT manipulation.
- **Services** contain all business logic. No `*gin.Context`, no HTTP status codes.
- **Models** are pure structs with GORM tags + `TableName()`. No methods with DB calls.
- **`internal/`** packages are primitives reused across the codebase — keep them
  narrow and dependency-free.

## Adding a new endpoint

1. **Service method** in `services/<area>_service.go` — takes plain Go types, returns
   a value + error.
2. **Controller method** on the appropriate `*Controller` struct — reads params, calls
   service, writes response.
3. **Route** in `router.go` — group by concern, apply the right middleware.
4. **Schema** — if a new table is needed, edit `migrations/master/001_bootstrap.sql`
   inline, add a `models/*.go` struct.
5. **Audit** — call `auditAdminMutation(c, wsID, action, resource, resourceID, statusCode, old, new)`
   on every create/update/delete.

## Error handling

```go
// Service layer — wrap with context:
if err := s.db.WithContext(ctx).Where("id = ?", id).First(&row).Error; err != nil {
    if errors.Is(err, gorm.ErrRecordNotFound) {
        return nil, fmt.Errorf("not_found: resource %s", id)
    }
    return nil, fmt.Errorf("lookup %s: %w", id, err)
}

// Controller layer — map to HTTP:
if err != nil {
    c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
    return
}
```

- Never swallow errors. Never log-and-continue on meaningful failures.
- Use `errors.Is(err, gorm.ErrRecordNotFound)` to distinguish 404 from 500.
- Return the HTTP error from the controller, not from deep inside a service.

## Token issuance

- All native token minting goes through `NativeIssuer.Issue` or `IssueIDJAG`.
  Never call `NativeKeyManager.Sign` directly.
- All Hydra-backed token operations go through `OAuthASService.ProxyFormToHydraPublicCapture`
  or `hydraAdminXxx` functions wrapped with `CircuitDoHydra`.
- `inTx` hooks in `NativeIssuer.Issue` are for operations that must be atomic with
  minting (replay guards). Don't add post-issuance writes as `inTx` — only pre-commit guards.

## Workspace scoping

Every query that touches workspace data must filter by `workspace_id`:
```go
s.db.WithContext(ctx).Where("workspace_id = ? AND id = ?", wsID, id).First(&row)
```
If a controller receives `workspace_id` from the URL path, validate that the resource
belongs to it. Never trust a `workspace_id` embedded inside a request body without
cross-checking the URL param.

## RBAC enforcement

- **Fail-closed**: call `ScopeResolver.ResolveGrantableScopes`; if the result is empty,
  deny with `insufficient_scope`.
- **Hydra downtime = deny**: if admin introspect fails, revoke the issued tokens and
  return 403. Operators must monitor revocation failure logs.
- **Strict-subset on refresh**: use `services.ScopesLost(issuedRS, currentRS)` — partial
  scope loss is a hard denial, not a narrowing.

## Naming

Use market-standard terms (see `AGENTS.md` terminology table):
- `workspace_id` not `tenant_id`
- `service_account` not `workload` for M2M identities
- `resource_server` not `mcp_server` at the auth layer
- `scope` not `permission` at the OAuth layer

## Go conventions

- `gofmt -w` before every commit.
- Return `(value, error)` — never return an error value as the first return.
- Package-level vars only for singletons (keyset, DB) with a `sync.Once` guard.
- Avoid `init()` — prefer explicit initialization in `cmd/main.go`.
- Use `context.Context` as the first param of any function doing DB or HTTP work.
- Test file: `_test.go` suffix, `package services` (same package, not `services_test`)
  for white-box tests.

## Surgical fixes

Before touching a bug, trace the call path in full. Don't patch the first symptom —
find the root cause and fix it at the right layer. A correct fix is small; if a fix is
large, reconsider whether the right layer is being changed.
