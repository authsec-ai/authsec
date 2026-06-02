# Standards-compliant MCP OAuth flow (v2) — prod backport

The `/authsec/oauth/v2/*` surface backports the dev branch's MCP OAuth server
flow onto authsec-prod. It is **independent** of the legacy
`/clientms/tenants/:tenantId/clients/*` flow and the
`/sdkmgr/playground/oauth/*` playground; both legacy surfaces continue to
work untouched.

## Scope of the backport

- Phase 1: SQL migrations (2 master, 6 tenant) and the matching Go models.
- Phase 2: DCR endpoint + tenant-scoped Application registry.
- Phase 3: Authorize/Token/Introspect/Revoke/JWKS/Userinfo/Logout proxying
  to Hydra; `mcp_oauth_clients ↔ Hydra` reconciler.
- Phase 4: Tenant-scoped IDP registry + per-Application IDP policy gate.
- Phase 5: RFC 8414 + OIDC well-knowns, canonical-issuer middleware, this doc.

## Tables

| Table | DB | Purpose |
| --- | --- | --- |
| `mcp_oauth_clients` | master | Global OAuth client registry, Hydra sync state |
| `resource_server_tenant_index` | master | `resource_uri → tenant_id` lookup |
| `resource_servers` | tenant | The Application row (mcp_server / ai_agent / clawbot / api_service) |
| `resource_server_client_registrations` | tenant | Application ↔ client join |
| `identity_providers` | tenant | Tenant's IDP registry |
| `application_identity_provider_policies` | tenant | Per-Application IDP whitelist |
| `auth_request_context` | tenant | PKCE/state across authorize→token |
| `oauth_consent_grants` | tenant | Durable consent records |

`mcp_oauth_clients` is **global by design** — OAuth clients are protocol
artifacts. Workspace/tenant scoping happens at the Application row that the
client targets via `resource_server_client_registrations`.

## Endpoints

```
POST /authsec/oauth/v2/register          — RFC 7591 DCR (anonymous)
GET  /authsec/oauth/v2/authorize         — auth code flow start, redirects to Hydra
POST /authsec/oauth/v2/token             — proxied to Hydra /oauth2/token
POST /authsec/oauth/v2/introspect        — proxied to Hydra admin introspect
GET  /authsec/oauth/v2/jwks              — proxied to Hydra /.well-known/jwks.json
POST /authsec/oauth/v2/revoke            — proxied to Hydra /oauth2/revoke
GET  /authsec/oauth/v2/userinfo          — introspect-and-filter
POST /authsec/oauth/v2/userinfo          — same
GET  /authsec/oauth/v2/logout            — RP-initiated logout
GET  /authsec/oauth/v2/.well-known/oauth-authorization-server
GET  /authsec/oauth/v2/.well-known/openid-configuration

# Tenant admin surface (requires JWT with tenant_id):
POST   /authsec/applications
GET    /authsec/applications
GET    /authsec/applications/:id
DELETE /authsec/applications/:id
GET    /authsec/applications/:id/identity-providers
POST   /authsec/applications/:id/identity-providers
DELETE /authsec/applications/:id/identity-providers/:idp_id
POST   /authsec/identity-providers
GET    /authsec/identity-providers
GET    /authsec/identity-providers/:id
PUT    /authsec/identity-providers/:id/status
DELETE /authsec/identity-providers/:id
```

## DCR walk-through

```
curl -X POST https://hydra-public.authsec.ai/authsec/oauth/v2/register \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "Acme MCP Client",
    "redirect_uris": ["https://acme.example.com/cb"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "resource": "https://api.acme.tenant.authsec.ai/mcp",
    "scope": "openid offline_access mcp.read"
  }'
```

AuthSec:
1. Resolves `resource` against `resource_server_tenant_index` → `(tenant_id, resource_server_id)`.
2. Loads the `resource_servers` row from the tenant DB; rejects if `registration_modes` excludes `dcr`.
3. Creates a Hydra client with a freshly-minted `hydra_client_id`.
4. Inserts an `mcp_oauth_clients` row (master DB).
5. Inserts a `resource_server_client_registrations` row (tenant DB).
6. Returns the public `client_id` (NOT `hydra_client_id`).

## Application↔IDP policy gate

By default any of the tenant's IDPs may authenticate users for any of the
tenant's Applications. The moment an Application has at least one
`application_identity_provider_policies` row, it switches into whitelist
mode — only IDPs explicitly enabled are accepted.

The gate runs in `/authorize` when the client sends `?idp_id=<uuid>`:
- Application has no policy rows → allowed.
- Application has policy rows, IDP enabled → allowed.
- Application has policy rows, IDP not enabled → **403 access_denied**.

## Hydra reconciler

A background goroutine started from `cmd/main.go` polls
`mcp_oauth_clients WHERE sync_status IN ('sync_error', 'pending_delete')`
every 5 minutes (configurable). It retries create/delete operations against
Hydra and flips the row back to `sync_status='active'` on success.

Disable during initial rollout:
```
AUTHSEC_DISABLE_HYDRA_RECONCILER_V2=true
```

## Things explicitly NOT done in this backport

These are TODOs marked `PHASE3-SCOPE` / `PHASE5-NOTE` in the code:

- **Deep RBAC enforcement on /token and /introspect.** The dev branch resolves
  the user's grantable scopes against `application_role_bindings` and filters
  Hydra's introspection response. We proxy the standard dance only; deeper
  filtering is a follow-up.
- **`application_type` column on legacy prod tables.** AI-agent and Clawbot
  subtypes are modeled in `resource_servers` but not surfaced through any
  legacy controller.
- **Per-tenant `oidc_providers`.** The underlying OIDC provider config rows
  are still global. Each tenant's `identity_providers.config_ref` may point at
  a shared row.

## `auth_request_context` lifecycle (done)

`/authorize` writes a row to `auth_request_context` (tenant DB) with the
captured `redirect_uri`, `scope`, `resource`, `code_challenge`, `nonce`,
and `state`, then forwards to Hydra with `state` rewritten as
`<context_id>~<rp_state>`.

`/token` (authorization_code grant only) recovers the `context_id` two
ways:

1. **Preferred:** parses it out of the `state` form param the RP forwarded.
2. **Fallback:** looks up the most-recent unconsumed row for
   `(tenant_id, client_id, redirect_uri)` when the RP dropped state.

Either way the row is **atomically consumed** (single UPDATE with
`consumed=false` predicate, safe under concurrent replays) and validated:
`client_id`, `redirect_uri`, `resource` must match the captured values;
`scope` must be a subset of what was authorized. Validation failure
aborts before the request reaches Hydra (fail closed).

Tenant resolution on `/token` requires the `resource` form param (RFC 8707)
so the handler can route to the right tenant DB. RPs that omit it are
rejected with `invalid_request`.

## Wipe-and-rebootstrap

Schema changes are forward-only, per CLAUDE.md. To verify the migrations:

1. Wipe the master DB and one tenant DB.
2. Restart the pod; `internal/migration/runner.go` will pick up the new
   `migrations/master/107..108` and `migrations/tenant/019..024` files.
3. Confirm the 8 new tables exist.
4. Curl through the DCR flow above.
