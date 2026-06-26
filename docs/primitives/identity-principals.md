# Identity Principals

> Read this before working with the `sub` / `SubjectType` of a token, adding a new
> identity kind, or touching the scope-resolution entry point.
> Files: `internal/tokens/principal.go`, `services/{service_account,rbac,permission}_service.go`.

## The four principal kinds

| Kind | `SubjectType` | Auth method | `sub` claim value | Workspace relationship |
|---|---|---|---|---|
| **User** | `"user"` | OIDC login (`authorization_code`) | local user UUID | member via `workspace_memberships` |
| **Service Account** | `"service_account"` | `client_secret_basic` or `private_key_jwt` | service account UUID | owned by the RS's workspace |
| **Agent** | `"user"` | XAA (token-exchange → jwt-bearer) | the delegated user's UUID | the user's home workspace |
| **Workload** | (SPIFFE) | SPIFFE JWT-SVID at `/oauth/token` | `spiffe://` URI | a SPIRE trust domain |

**Agent tokens carry `sub = user UUID`** — the agent acts *on behalf of a user*. The
actor (the agent client) is in the `act` claim: `{client_id, spiffe_id?}`. This lets
downstream RS apply user-level RBAC while knowing the delegating party.

## `internal/tokens/principal.go`

```go
type Principal struct {
    SubjectType string    // "user" | "service_account"
    SubjectID   uuid.UUID
    WorkspaceID uuid.UUID
}

type Actor struct {
    ClientID string
    SpiffeID *string // set when the agent client is a SPIFFE workload
}
```

`Principal` is resolved **before any issuance** — the grant handler authenticates the
client, looks up the subject, fills a `Principal`, then calls `NativeIssuer.Issue`. The
`Actor` is also resolved in the grant handler (XAA/CIBA only) and packed into
`NativeClaims.ActorClientID` / `ActorSpiffeID`.

## Scope resolution entry point

`services/scope_resolver.go` — `ScopeResolver.ResolveGrantableScopes(ctx, workspaceID,
subjectID, resourceServerID, requestedScopes, rs, client)`:

```
granted = requested_scopes ∩ RS.scopes_supported ∩ subject_effective_scopes
```

- **Fail-closed**: empty RS scopes_supported → nothing granted; no RBAC bindings → nothing granted.
- OIDC core scopes (`openid`, `profile`, `email`, `offline_access`, `address`, `phone`)
  bypass both RS and RBAC checks — **only for OIDC-capable clients** (client.Scope contains
  `"openid"`; see `clientIsOIDC`).
- `PrincipalHasEffectiveScopes` — used by governance surfaces to show honest "approved but
  no usable scopes yet" state when a connection exists but no role binding is in place.

The resolver dispatches by subject type:
- `"user"` → `resolveUserEffectiveScopes` (walk role_bindings → roles → permissions → oauth_scope_permissions → oauth_scopes)
- `"service_account"` → `resolveServiceAccountEffectiveScopes`

## User identity lifecycle

Users are created in `users` table. Workspace membership is in `workspace_memberships`.
OIDC identity federation links are in `oidc_user_identities` (linked by `oidc_providers`).

A user's identity within a workspace:
1. Signs in via OIDC provider (creates `oidc_user_identities` row).
2. Gets assigned to a role (creates `role_bindings` row linking user + role + workspace + RS).
3. Role → permissions → scope mappings resolve at token time.

## Service Account identity lifecycle

1. Created via `POST /workspaces/:wsid/service-accounts`.
2. Promoted to a confidential client via `POST /admin/service-accounts/:sa_id/credentials`
   (mints `oauth_client_secrets` or `oauth_client_jwks` row + a Hydra client registration).
3. M2M grant: authenticates with `client_secret_basic` or `private_key_jwt` at
   `/oauth/token` (grant_type=client_credentials).
4. Scope resolution uses `resolveServiceAccountEffectiveScopes`.

See `services/service_account_service.go` for CRUD.

## When you're building

- **New principal type?** Add a `SubjectType` constant in `principal.go`, wire the
  scope resolver dispatch in `scope_resolver.go`, extend `NativeClaims` if new claims
  are needed, add to the grant handler.
- **Token `sub` claim** must always be a UUID string (`uuid.UUID.String()`). Never put
  an email or username in `sub` for native tokens.
- **`act` claim** is set only in XAA / CIBA grant handlers. M2M tokens carry no `act`.
- **Workspace scoping**: always resolve `workspaceID` before issuance — the `NativeClaims`
  struct requires it and it appears in the `native_tokens` row for audit.

## Related

`primitives/rbac-scopes.md` (how roles → effective scopes work), `flows/m2m.md`
(service account issuance), `flows/xaa-idjag.md` (agent delegation), `primitives/spire.md`
(workload identity).
