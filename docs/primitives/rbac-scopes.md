# RBAC & Scopes

> Read this before adding a new scope, role, permission, binding, or touching the
> scope resolution pipeline.
> Files: `services/{scope_resolver,scope_mapper,scope_registry_service,scope_preset_catalog,
> rbac_service,permission_service}.go`.

## The chain

```
Role → role_permissions → Permission → oauth_scope_permissions → OAuthScope
                                                ↓
                             ScopeResolver walks this chain to get subject_effective_scopes
```

At token time, `ScopeResolver.ResolveGrantableScopes` computes:

```
granted = requested_scopes ∩ RS.scopes_supported ∩ subject_effective_scopes
```

where `subject_effective_scopes` = the union of all OAuth scopes reachable from
the subject's active `role_bindings` in the target workspace × RS pair.

## Tables (all in `001_bootstrap.sql`)

| Table | Purpose |
|---|---|
| `roles` | Named role per workspace + RS (name, description, workspace_id, resource_server_id) |
| `permissions` | Named permission (name, resource, action, workspace_id) |
| `role_permissions` | M2M: role → permission |
| `oauth_scopes` | The actual OAuth scope string (`scope_value`) registered against an RS |
| `oauth_scope_permissions` | M2M: permission → oauth_scope (the mapping that makes a permission grant a scope) |
| `role_bindings` | Subject (user / group / service_account) bound to a role for a workspace + RS |

## `services/scope_resolver.go` — `ScopeResolver`

Key methods:

| Method | What it does |
|---|---|
| `ResolveGrantableScopes(ctx, wsID, subjectID, rsID, requested, rs, client)` | 3-way intersection; returns `[]string` grantable |
| `ResolveWithReport(...)` | Same but returns `*ScopeResolutionReport` (full diagnostics: requested / RS_supported / user_effective / grantable + per-scope block reasons) |
| `HasEffectiveScopes(ctx, wsID, userID, rsID)` | Quick check — any RBAC-derived scopes? |
| `PrincipalHasEffectiveScopes(ctx, subjectType, wsID, subjectID, rsID)` | Same but dispatches by subjectType (`"user"` or `"service_account"`) |

**Fail-closed rules:**
- RS must declare `scopes_supported` (`resource_servers.scopes_supported JSONB`). If empty, no RS scopes are granted.
- Subject must have active `role_bindings` → permissions → scope mappings. If none, no scopes.
- OIDC core scopes (`openid`, `profile`, `email`, `offline_access`) bypass RS and RBAC but **only when `clientIsOIDC(client)` is true** (client registered with `"openid"` in its `scope` field). An empty scope string is NOT OIDC-capable — this prevents M2M/agent clients from silently getting identity scopes.

## `BlockReason` diagnostic values

```go
BlockNotInRSSupported = "not_in_rs_supported"   // scope not in RS.scopes_supported
BlockNoRBACBinding    = "no_rbac_binding"        // subject has no binding granting this scope
BlockOIDCNotAllowed   = "oidc_not_allowed"       // OIDC scope requested by non-OIDC client
```

These appear in `ScopeDiagnostic.Reason` in the `ResolveWithReport` response — useful
for the scope-matrix / simulate endpoints.

## `services/rbac_service.go` — `RBACService`

CRUD for roles and permissions. Key operations:
- `CreateRoleComposite(role, permissionIDs)` — creates role + links permissions in one transaction.
- `GetRole(roleID)` — preloads permissions.
- `DeleteRole(roleID)`, `DeletePermission(permID)`.

## `services/scope_registry_service.go`

Manages `oauth_scopes` (the scope registry for a workspace + RS). CRUD over `oauth_scopes`
table; `scope_preset_catalog.go` provides preset scope bundles (standard sets for common RS types).

## `services/scope_mapper.go`

Links permissions → scopes (`oauth_scope_permissions`). `MapPermissionToScope`,
`UnmapPermissionFromScope`, `GetScopesForPermission`.

## Approve-with-role (atomic binding)

When an access request is approved, the binding is created atomically with the approval:
`role_assignment_requests` row transitions to `approved`, and a `role_bindings` row is
inserted in the same transaction (`services/xaa_service.go`, `ApproveWithRole`).
This ensures the subject immediately has effective scopes after approval — no window
where approval succeeded but the binding wasn't yet there.

## When you're building

- **New scope for an RS?** Insert into `oauth_scopes` (via registry API or bootstrap seed).
  Then map a permission to it via `scope_mapper`. Then bind a role to that permission.
- **Debugging "no scopes granted"?** Call `ResolveWithReport` — the `ScopeDiagnostic`
  list shows exactly which gate blocked each scope.
- **New subject type?** Add a dispatch branch in `ScopeResolver.PrincipalHasEffectiveScopes`
  and a `resolveXxxEffectiveScopes` private method.
- **Never** grant scopes outside the resolver — no special-case "always grant X" logic
  in grant handlers. Everything goes through the 3-way intersection.

## Related

`primitives/identity-principals.md` (who the subject is), `flows/m2m.md` (SA scope
resolution in the M2M grant), `flows/xaa-idjag.md` (user scope resolution in the
jwt-bearer grant), `primitives/oauth-as.md` (where `ScopeResolver` is called).
