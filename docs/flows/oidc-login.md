# Flow: OIDC Login (authorization_code + PKCE)

> A user logs into the AuthSec console (or an MCP client) via browser.
> Hydra runs the interactive protocol; AuthSec wraps it with policy + context binding.
> Read `primitives/oauth-as.md` and `primitives/hydra.md` first.

## The path

```
1. Browser → GET /oauth/authorize?...
2. AuthSec → stores AuthRequestContext → redirects browser to Hydra /oauth2/auth?authsec_ctx=...
3. Hydra login + consent → browser returns to AuthSec redirect_uri?code=...
4. Client → POST /oauth/token (authorization_code)
5. AuthSec → proxies to Hydra → validates context + RBAC → returns tokens
```

## Step 1: Authorization request (`GET /oauth/authorize`)

Required params:
- `client_id` — the registered MCP OAuth client
- `response_type=code` (only value accepted)
- `response_mode=query` (only value accepted; form_post/fragment rejected)
- `code_challenge` (43–128 chars), `code_challenge_method=S256` (PKCE required)
- `state` — client-supplied CSRF token
- `resource` — target RS URI (or inferred if client maps to exactly one RS)
- `scope` — requested scopes (e.g. `openid profile email tool:invoke`)
- Optional: `nonce`, `prompt`, `max_age` (OIDC Core 1.0 §3.1.2.1)

**PAR is disabled.** `request_uri` in the authorize request returns `invalid_request_uri`.

Key checks:
- `validateOAuthPolicy(clientID, resource, redirectURI, scopes)` — client exists + RS
  registered for client + redirect URI whitelisted.
- `EnsureHydraClientHasRSScopes(oauthClient, rs)` — JIT scope-widening for DCR clients
  whose Hydra registration has empty scope (prevents Hydra from rejecting the authorize
  request; RBAC still gates what's actually granted).

AuthSec stores `auth_request_contexts` row (server-generated `context_id`, NOT the
client `state`), then redirects to Hydra with `authsec_ctx=contextID` appended.

## Step 2–3: Hydra login + consent

Hydra handles the browser redirect, calls the AuthSec login/consent handler
(`controllers/platform/hmgr_controller.go`) to render login UI and collect consent.
AuthSec records OIDC params (`nonce`, `prompt`, `max_age`) from the stored context.
Hydra redirects back to `redirect_uri?code=...&state=...`.

## Step 4–5: Token exchange (`POST /oauth/token`)

Handler: `tokenAuthCodeGrant`.

1. Rewrite `client_id → hydra_client_id`, proxy to Hydra `/oauth2/token`.
2. Parse Hydra 200 response — capture `access_token` + `refresh_token`.
3. **Introspect access token** via Hydra admin → extract `context_id` from session claims.
4. **Lookup `auth_request_contexts`** by `context_id` — must be `consent_completed=true`,
   `consumed=false`. If not found → revoke both tokens + 403.
5. **Validate RS registration** — client must have `status='approved'` for the RS.
6. **RBAC enforcement (strict-subset, fail-closed)**:
   - `IntrospectViaHydraAdmin(accessToken)` → get canonical issued `scope` + `sub`.
   - `ScopeResolver.ResolveGrantableScopes(...)` — current RBAC-grantable scopes.
   - If any RS-specific scope in the issued token is no longer grantable → revoke + `insufficient_scope`.
   - Hydra downtime = fail closed (cannot verify permissions → deny).
7. **Consume `auth_request_contexts`** atomically before returning.
8. Strip `refresh_token` if client `SupportsRefreshToken=false`.
9. Forward Hydra response to client.

## Token types returned

- **`access_token`** — Hydra-minted JWT (`FamilyHydra`, not a native token). Validated
  via Hydra introspect (not native path).
- **`refresh_token`** — Hydra-minted, returned only if client registered with `offline_access`.
- **`id_token`** — Hydra-minted OIDC ID token (when `openid` scope granted).

## Refresh token flow (`POST /oauth/token`, `grant_type=refresh_token`)

Handler: `tokenRefreshGrant`.

Same fail-closed RBAC enforcement pattern:
1. Validate `resource` (cannot widen audience on refresh).
2. Proxy to Hydra (rewrite client_id).
3. Admin-introspect new access token → get issued scope + sub.
4. `ScopeResolver.ResolveGrantableScopes` — strict-subset check.
5. Scope loss → revoke new token set + `insufficient_scope`.

## When you're building

- **Adding new scopes to the authorize flow?** `EnsureHydraClientHasRSScopes` widens
  the Hydra client's registered scopes JIT; RBAC still gates them at exchange.
- **Debugging `context_id not found`?** Check `auth_request_contexts` — 10-min TTL,
  `consumed` flag. Ensure `authsec_ctx` is flowing through Hydra's session claims.
- **Adding OIDC params?** `auth_request_contexts` stores `nonce`, `prompt`, `max_age`;
  consumed by `hmgr_controller.go` during login.
- **Never** bypass `ConsumeAuthRequestContext` — it's the single concurrency guard.

## Related

`primitives/oauth-as.md` (full AS endpoint list), `primitives/hydra.md` (Hydra split),
`primitives/rbac-scopes.md` (scope resolution), `flows/xaa-idjag.md` (next step if the
user wants an agent to call another RS).
