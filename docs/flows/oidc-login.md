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
   (with XAA_NATIVE_SEALER on, the access token is AuthSec-native)
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

1. Rewrite `client_id → hydra_client_id`, proxy to Hydra `/oauth2/token`. With the
   native sealer on, `resource` and `audience` are not forwarded: Hydra is never asked
   about an audience (consent grants it none either, `hmgr_controller.go`).
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
9. With the native sealer on, replace Hydra's access token with a native one
   (`mintBrowserAccessToken`, family `auth_code`) and set `token_type`, `expires_in`
   (1 hour) and `scope`. If minting fails, the Hydra set is revoked and the client gets
   500. With the sealer off, forward Hydra's response as is.

## Token types returned

- **`access_token`** — with `XAA_NATIVE_SEALER` on (production), an AuthSec-native
  JWT (RFC 9068, `typ: at+jwt`, `native:` kid): `iss` = AuthSec's issuer, `sub` = the
  user, `aud` = the RFC 8707 resource bound in the `AuthRequestContext`, `client_id`,
  the issued `scope`, `tf=auth_code`, no `act` (the user authorised the client directly).
  It has a `native_tokens` row, so resource servers introspect it on the native path and
  the SDKs' issuer check passes. With the sealer off, Hydra's own token (`FamilyHydra`),
  which a resource server cannot use (wrong issuer, no resource audience).
- **`refresh_token`** — Hydra-minted, returned only if client registered with `offline_access`.
  The native access token's row links to it by SHA-256 (`source_grant_jti`,
  `source_grant_iss='urn:authsec:hydra-refresh-token'`; never in the JWT).
- **`id_token`** — Hydra-minted OIDC ID token (when `openid` scope granted).

## Refresh token flow (`POST /oauth/token`, `grant_type=refresh_token`)

Handler: `tokenRefreshGrant`.

Same fail-closed RBAC enforcement pattern:
1. Validate `resource` (cannot widen audience on refresh).
2. Proxy to Hydra (rewrite client_id; with the sealer on, without `resource`/`audience`).
3. Admin-introspect new access token → get issued scope + sub.
4. `ScopeResolver.ResolveGrantableScopes` — strict-subset check.
5. Scope loss → revoke new token set + `insufficient_scope`.
6. With the sealer on: the refreshed grant's `ext.resource_server_id` must equal the
   resource's (else `invalid_target`); a new native token is minted, linked to the new
   refresh token, and the native token linked to the presented (rotated) one is revoked.

**Revocation (RFC 7009 §2.1).** `POST /oauth/revoke` with a refresh token also revokes
the native access token linked to it (`RevokeAuthCodeTokensForRefresh`).

**Userinfo (OIDC Core §5.3).** `/oauth/userinfo` accepts the native access token when
its scope includes `openid`; claims come from the user record (`EnrichUserinfoClaims`).

**Sessions consented before this change** carry the audience Hydra stored at consent
and fail to refresh at Hydra ("not whitelisted"). The user signs in again once.

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
