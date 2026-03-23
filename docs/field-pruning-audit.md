# Field Pruning Audit

## `project_id`

### Status

`project_id` is not a clean product concept, but it is still a live dependency. It cannot be deleted safely in one cut today.

### Real dependencies still in code

- SCIM routes and controllers use `/scim/v2/:client_id/:project_id/...` as part of the active path contract.
- Sync config flows store and validate `project_id`.
- Client creation and secret storage still thread `project_id` through client records and Vault helper calls.
- Admin bootstrap, OIDC registration, and invite flows create default projects and assign `project_id` into users and clients.
- Token generation and middleware still propagate `project_id`, even when it is defaulted.

### Baggage / weak usage

- Many token paths set `project_id = tenant_id` only to satisfy downstream expectations.
- Several auth flows pass `project_id` through claims without using it as a real authorization boundary.
- RBAC no longer needs `projects:*` for current route enforcement.

### Safe immediate position

- Keep `project_id` in the live runtime for now.
- Do not add new features that depend on it.
- Treat it as a staged removal target, not an active design primitive.

### Staged removal plan

1. Remove `project_id` from secret namespacing and derive secrets from `tenant_id` plus `client_id`.
2. Redesign SCIM paths to stop requiring `project_id` in the URL.
3. Remove default-project creation from admin bootstrap and OIDC registration.
4. Remove `project_id` from tokens and middleware context after downstream auth-manager dependencies are gone.
5. Only then remove `projects` table usage and `project_id` columns from users, clients, pending registrations, and sync configs.

## `playground`

### Status

Removed from the active runtime surface.

### Removed

- Playground routes
- Playground OAuth routes
- Playground dev-server routes
- Playground controllers, services, and models
- README and smoke-test references

### Remaining

- None in active runtime code
- Only unrelated third-party `go-playground/*` module names remain in `go.mod` and `go.sum`
