# ORY Hydra — what it owns vs what's native

> Read this before touching anything that touches Hydra client registration, the
> Hydra admin API, the reconciler, or the authorization_code / refresh_token flows.
> Files: `services/{hydra_service,hydra_reconciler}.go`, `internal/hydra/`.

## The split

AuthSec is **not** a Hydra wrapper — it's a dual-path AS:

| Token family | Minted by | Hydra involved? | Validated by |
|---|---|---|---|
| `authorization_code` access token | Hydra | Yes — Hydra runs the protocol | Hydra introspect |
| `refresh_token` | Hydra | Yes | Hydra introspect |
| `FamilyNative` (M2M / XAA / CIBA) | `NativeIssuer` | **No** | Native path (local RS256 verify + `revoked_tokens`) |

The classifier (`internal/tokens/classifier.go`, `Classify(token, nativeKIDs)`) decides
the path at introspect/revoke time. A `native:`-kid token **never** touches Hydra. If the
signature is bad on the native path it's rejected — never retried on Hydra.

## Hydra owns

- **Interactive `authorization_code` + PKCE** — the browser redirect + consent loop.
- **`refresh_token`** issuance and rotation.
- **`id_token`** (OIDC) minting.
- **Hydra client storage** — `mcp_oauth_clients.hydra_client_id` is the Hydra-side client
  identity. AuthSec's `mcp_oauth_clients` is the authoritative row; Hydra is the protocol
  runtime.

## AuthSec owns (Hydra not involved)

- `client_credentials` → `tokenClientCredentialsGrant` → `NativeIssuer.Issue`.
- `urn:ietf:params:oauth:grant-type:token-exchange` → XAA step 1 → `IssueIDJAG`.
- `urn:ietf:params:oauth:grant-type:jwt-bearer` → XAA step 2 → `NativeIssuer.Issue`.
- CIBA token poll → `NativeIssuer.Issue`.
- SPIFFE JWT-SVID exchange → native token.

## `services/hydra_service.go`

Low-level Hydra admin API calls, all wrapped with `CircuitDoHydra` (circuit breaker
in `services/circuit_breaker.go`):

| Function | Hydra admin endpoint |
|---|---|
| `hydraAdminGetClient(clientID)` | `GET /admin/clients/:id` |
| `hydraAdminCreateClient(c)` | `POST /admin/clients` |
| `hydraAdminUpdateClient(clientID, c)` | `PUT /admin/clients/:id` |
| `hydraAdminDeleteClient(clientID)` | `DELETE /admin/clients/:id` |

`hydraClient` mirrors the Hydra JSON schema (client_id, client_secret, grant_types,
redirect_uris, response_types, token_endpoint_auth_method, scope, audience, metadata).

## `services/hydra_reconciler.go` — convergence loop

`HydraReconciler.Run(ctx)` polls on a configurable interval (default 5 min) and:

| `sync_status` | Action |
|---|---|
| `sync_error` | Hydra create/update failed. Check if client exists in Hydra; if absent, create; if present, flip to `active`. |
| `pending_delete` | AuthSec wants the row gone but Hydra delete failed. Retry delete; on success soft-delete the AuthSec row. |

Background goroutines started alongside the reconcile loop:
- `runStaleDCRCleanup` — marks DCR clients with no recent token as `pending_delete` (daily, default 30-day threshold from `DCR_STALE_DAYS` env).
- `runPendingApprovalExpiry` — expires pending access requests.
- `runAccessRequestExpiryAndReminder` — reminder + expiry for role assignment requests.
- `runPRMOverrideReverify` — re-checks policy override entries.

## Authorization code bridge

`tokenAuthCodeGrant` proxies to Hydra's public `/oauth2/token`. AuthSec:
1. Rewrites `client_id` → `hydra_client_id` before the proxy.
2. Captures Hydra's response.
3. Introspects the returned access token to extract `context_id` from session claims.
4. Validates + consumes the stored `AuthRequestContext`.
5. Forwards the full Hydra response to the client.

Failure modes: if `AuthRequestContext` is not found / already consumed, AuthSec revokes
both tokens synchronously (`RevokeFullTokenSet`) and returns 403 — **Hydra downtime must
not become a bypass**.

## When you're building

- **Registering a new client?** Go through `OAuthASController.Register` (RFC 7591).
  Don't call `hydraAdminCreateClient` directly — the controller handles both the
  AuthSec row and the Hydra sync.
- **Debugging a sync_error?** Check `mcp_oauth_clients.sync_status`; the reconciler
  will retry. If Hydra is up and the error persists, inspect the Hydra admin API
  directly.
- **Adding a Hydra admin operation?** Wrap it with `CircuitDoHydra` — bare `http.Do`
  calls skip the circuit breaker.
- **Never** route a `native:`-kid token to Hydra introspect. The classifier enforces
  this, but don't work around it.

## Related

`primitives/token-engine.md` (classifier + NativeIssuer), `primitives/oauth-as.md`
(the `/oauth/token` dispatch), `flows/oidc-login.md` (full auth code flow).
