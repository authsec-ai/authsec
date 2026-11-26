# OAuth Authorization Server

> Read this before touching any `/oauth/*` or `/.well-known/*` endpoint, adding a new
> grant type, modifying client registration/management, or touching introspect/revoke.
> Package: `controllers/platform` (`OAuthASController`) + `services` (`OAuthASService`).

## One-sentence summary

`OAuthASController` is the single AS surface: it enforces policy, proxies Hydra for
interactive flows, and dispatches native grants — **all token issuance goes through
`/oauth/token`**, nothing bypasses it.

## Endpoints

| Endpoint | Handler | Notes |
|---|---|---|
| `GET /.well-known/oauth-authorization-server` | `ASMetadata` | RFC 8414 AS metadata. Canonical issuer enforced by `CanonicalIssuerOnly()`. |
| `GET /.well-known/openid-configuration` | `OIDCDiscovery` | Returns the same superset document (OIDC Discovery is a strict superset of RFC 8414). |
| `GET /oauth/authorize` | `Authorize` | Auth code start. PKCE S256 required. Stores `AuthRequestContext`, redirects browser to Hydra `/oauth2/auth` with `authsec_ctx` correlation key. PAR disabled (explicit error on `request_uri`). |
| `POST /oauth/token` | `Token` | All grants dispatched here (see Grant table). |
| `POST /oauth/introspect` | `Introspect` | Classify → native path or Hydra proxy. |
| `POST /oauth/revoke` | `Revoke` | Classify → native or Hydra. A Hydra refresh token also revokes the native access token linked to it (RFC 7009 §2.1). |
| `GET /oauth/userinfo` | `Userinfo` | OIDC userinfo. A native access token is verified locally (never sent to Hydra) and must carry a user subject and `openid`; M2M tokens get 401. |
| `GET /oauth/jwks` | `JWKS` | Union: native RS256 (`NativeKeys().PublicJWKS()`) + Hydra keys + SPIFFE key. |
| `POST /oauth/register` | `Register` | RFC 7591 Dynamic Client Registration. |
| `GET/PUT/DELETE /oauth/register/:id` | `GetRegistration` / `UpdateRegistration` / `DeleteRegistration` | RFC 7592 client management. |
| `POST /oauth/bc-authorize` | `BCAuthorize` | CIBA backchannel authorize (requires `XAA_CIBA=true`). |
| `POST /oauth/par` | — | PAR **disabled** — explicit `invalid_request_uri` error. |

## Grant dispatch (`POST /oauth/token`)

```
grant_type                                      → handler
──────────────────────────────────────────────────────────────
authorization_code                              → tokenAuthCodeGrant     (Hydra proxy + context binding; native access token)
refresh_token                                   → tokenRefreshGrant      (Hydra proxy; client must have offline_access; native access token)
client_credentials                              → tokenClientCredentialsGrant  (native M2M — no Hydra)
urn:ietf:params:oauth:grant-type:jwt-bearer     → tokenJWTBearerGrant    (XAA step 2: jwt-bearer → native access token)
urn:ietf:params:oauth:grant-type:token-exchange → tokenExchangeGrant     (XAA step 1: subject_token → ID-JAG)
urn:openid:params:grant-type:ciba               → tokenCIBAGrant         (CIBA token poll)
```

- `authorization_code` and `refresh_token` → **Hydra proxy**. AuthSec captures the
  response and validates `AuthRequestContext` binding. With `XAA_NATIVE_SEALER` on it
  replaces Hydra's access token with a native one (family `auth_code`; id_token and
  refresh token stay Hydra's); with it off it forwards Hydra's response.
- `client_credentials`, `jwt-bearer`, `token-exchange`, `ciba` → **native path**
  (`NativeIssuer.Issue`); Hydra is not contacted.

## Authorization code flow (Hydra-backed)

```
Browser → GET /oauth/authorize
  └─ validateOAuthPolicy (client + RS lookup, redirect URI, PKCE)
  └─ EnsureHydraClientHasRSScopes (JIT scope widening for DCR clients)
  └─ StoreAuthRequestContext (server-side context_id, NOT client state)
  └─ Redirect → Hydra /oauth2/auth?authsec_ctx=contextID

POST /oauth/token (authorization_code)
  └─ Proxy to Hydra (rewrite client_id → hydra_client_id)
  └─ Introspect access token → extract context_id from session claims
  └─ LookupAuthContext (must be consent_completed=true, consumed=false)
  └─ ValidateRS registration
  └─ ConsumeAuthContext
  └─ Sealer on: mint native access token (aud = bound resource), linked to Hydra's
     refresh token; sealer off: forward Hydra response
```

`revokeIssuedTokens` is called synchronously before any hard-denial response —
a 403 is always returned even if Hydra revocation fails.

## Policy engine (`evalPDP`)

`OAuthASController` wires an optional PDP (`internal/policy.SimplePDP`), controlled
by `POLICY_ENGINE_MODE` env:
- `""` / unset → PDP disabled, gates-only.
- `"shadow"` → PDP consulted, audit row written, but decision never blocks.
- `"enforce"` → `EffectDeny` from PDP blocks the token and returns 403.

PDP audit is recorded via `policy.RecordAudit` with `gate_effect=permit` (thin gates
passed) + `pdp_effect` from the decision.

## Client resolution

- `client_id` is read from POST body, then `Basic` auth header (`ExtractClientIDFromBasicAuth`).
- `private_key_jwt` callers may omit `client_id` from the body; `AuthenticateClient` inside
  the M2M handler extracts it from the assertion.
- Lookup: `service.GetOAuthClient(clientID)` → `mcp_oauth_clients` row.
- `nil` oauthClient is only allowed for `client_credentials`, `jwt-bearer`,
  `token-exchange`, `ciba` grants (they authenticate themselves).

## Canonical issuer enforcement

`CanonicalIssuerOnly()` middleware redirects any request arriving on a non-canonical host
(e.g. the SPA host) to the configured `OAuthBaseURL` host. This keeps a single issuer while
allowing the SPA to live on a different domain.

## When you're building

- **New grant type?** Add a `case` in `Token()` dispatch and implement a handler method
  on `OAuthASController`. Native issuance → `NativeIssuer.Issue`. Hydra-backed → proxy
  pattern from `tokenAuthCodeGrant`.
- **New discovery field?** Edit `OAuthASService.ASMetadata` — it builds the metadata map.
  The same function backs both RFC 8414 and OIDC Discovery endpoints.
- **New DCR field?** `Register` + `GetRegistration` / `UpdateRegistration` / `DeleteRegistration`
  in the controller; `mcp_oauth_clients` schema in `001_bootstrap.sql`.
- **Never** add a second `/token` entry point. All grants, all clients, one handler.

## Related

`primitives/token-engine.md` (NativeIssuer + classify), `primitives/hydra.md`
(what Hydra owns), `flows/m2m.md`, `flows/xaa-idjag.md`, `flows/oidc-login.md`.
