# AuthSec — Multi-Tenant Removal Progress

This file tracks the refactoring of authsec from a multi-tenant system to a
single-tenant system. All multi-tenant logic moves to the `mt-plugin` microservice.

## Summary of Changes

authsec becomes a strict single-tenant service:
- Always uses master DB (`config.DB`) for all operations
- One admin allowed; second admin blocked with HTTP 409 unless mt-plugin is available
- `MTPluginClient` is the only connection point to mt-plugin (gRPC)
- No tenant DB creation, no dynamic DB switching, no tenant resolution middleware

## Phase 1 — Delete Multi-Tenant Files
- [x] `services/tenant_db_service.go` → DELETED (moved to mt-plugin)
- [x] `database/tenant_db_service.go` → REPLACED with stub (returns errors)
- [x] `internal/migration/template_builder.go` → DELETED (moved to mt-plugin)
- [x] `middlewares/tenant_resolution.go` → DELETED
- [x] `middlewares/tenant_validation.go` → DELETED
- [x] `middlewares/tenant_context_middleware.go` → DELETED

## Phase 2 — Add MTPluginClient
- [x] `internal/mtplugin/proto/` — generated gRPC stubs
- [x] `internal/mtplugin/client.go` — gRPC client + 15s heartbeat
- [x] `config/config.go` — add `MtPluginAddr` field (MT_PLUGIN_GRPC_ADDR env)

## Phase 3 — Strip Multi-Tenant from Existing Files
- [x] `middlewares/tenant.go` — removed TenantDBManager, GetConnectionDynamically, databaseExists
- [x] `config/database.go` — removed GetTenantDatabase, GetTenantGORMDB
- [x] `cmd/main.go` — removed SetupTenantTemplate goroutine; added MTPluginClient init
- [x] `controllers/admin/admin_auth_controller.go` — removed tenant DB creation; added 409 guard
- [x] `controllers/admin/tenant_controller.go` — removed tenant DB calls, delegates to plugin
- [x] `controllers/admin/migration_controller.go` — removed CreateTenantDB and tenant migration
- [x] `routes/routes.go` — removed tenant middleware

## Phase 4 — Replace GetConnectionDynamically in All Controllers
Replace every `GetConnectionDynamically()` call with `config.DB` (master DB):
- [x] `controllers/admin/api_scopes_controller.go`
- [x] `controllers/admin/scope_controller.go`
- [x] `controllers/admin/admin_user_controller.go`
- [x] All other callers resolved (grep confirms zero remaining)

## Phase 5 — Verify
- [x] `go build ./...` passes
- [x] `go vet ./...` passes
- [x] `go test -short ./...` passes (only pre-existing DB connectivity failure in ad_controller_test)
- [ ] Single-tenant mode: first admin → OK; second admin → 409
- [ ] With mt-plugin: second admin → OK (plugin creates tenant DB)

## ENV Changes
New variable:
```
MT_PLUGIN_GRPC_ADDR=localhost:7469   # empty = single-tenant, no plugin
```
