# Flow: M2M (client_credentials)

> Machine-to-machine. A Service Account calls `/oauth/token` with its credentials
> and gets a native access token scoped to a Resource Server.
> Read `primitives/token-engine.md` and `primitives/identity-principals.md` first.

## The path

```
POST /oauth/token
  grant_type=client_credentials
  client_id=<sa_client_id>   (or Basic auth header)
  client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer   (private_key_jwt)
  client_assertion=<signed JWT>
  resource=<resource_server_uri>
  scope=<requested scopes>
```

**Nothing touches Hydra.** The entire grant runs natively inside AuthSec.

## Step-by-step (`tokenClientCredentialsGrant`)

`controllers/platform/oauth_as_controller.go` → `tokenClientCredentialsGrant`

1. **Authenticate client** — `services.AuthenticateClient(ctx, db, r, tokenEndpoint)`:
   - `private_key_jwt` (`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`):
     extract `client_id` from assertion, look up `oauth_client_jwks`, verify RS256/ES256 sig,
     check `aud=tokenEndpoint`, `exp`, replay via `client_assertion_replay_cache`.
   - `client_secret_basic`: Basic auth header → `oauth_client_secrets` row → bcrypt compare.
   - SPIFFE JWT-SVID assertion (`urn:authsec:params:oauth:client-assertion-type:spiffe-svid`):
     verify SVID against SPIRE JWKS, map `sub` (SPIFFE ID) → `service_accounts.spiffe_id`
     → client.

2. **Resolve RS** — look up `resource_servers` by `resource_uri` (`resource` param);
   must be in the same workspace as the service account.

3. **Resolve service account** — look up `service_accounts` by `client_id`;
   must belong to the RS's workspace.

4. **Resolve scopes** — `ScopeResolver.ResolveGrantableScopes`:
   `requested ∩ RS.scopes_supported ∩ SA_effective_scopes`. Fail-closed; empty result → `insufficient_scope`.

5. **PDP (optional)** — `evalPDP` in shadow or enforce mode.

6. **Mint** — `NativeIssuer.Issue(ctx, NativeClaims{Family:"m2m", ...})`:
   - `sub` = service_account.id, `SubjectType="service_account"`
   - `aud` = RS.resource_uri
   - `tf` = `"m2m"` (token family claim)
   - No `act` claim (no delegation)
   - Inserted into `native_tokens` atomically.

7. **Response**: standard OAuth2 JSON (`access_token`, `token_type`, `expires_in`, `scope`).
   No `refresh_token` (native tokens are non-refreshable).

## Token claims

```json
{
  "iss": "<OAuthBaseURL>",
  "sub": "<service_account_uuid>",
  "aud": ["<resource_server_uri>"],
  "scope": "tool:invoke list:resources",
  "client_id": "<sa_client_id>",
  "jti": "<uuid>",
  "iat": 1234567890,
  "exp": 1234567890,
  "tf": "m2m"
}
```

## Preconditions for success

1. Service account exists in `service_accounts` with `workspace_id` matching the RS's workspace.
2. Client has `client_credentials` in its registered `grant_types`.
3. Client has at least one auth method in `oauth_client_secrets` (or `oauth_client_jwks`).
4. RS has `scopes_supported` populated.
5. SA has a `role_bindings` row → role → permission → scope mapping.

## Validation / introspect

Later, when the RS receives the access token: `POST /oauth/introspect`.
Classifier sees `kid` starts with `native:` → `FamilyNative` → local verify (RS256, `NativeKeyManager.PublicJWKS()`) → check `revoked_tokens` → return active introspect response.

## When you're building

- **New auth method for M2M?** Add to `authenticateClient` in `services/client_auth.go` + a
  new `allowed_token_endpoint_auth_methods` value.
- **New token claim for M2M?** Add to `NativeClaims` struct + `NativeIssuer.Issue`.
- **New workspace-specific SA constraint?** Add the check in `tokenClientCredentialsGrant`
  before `Issue`. Don't add it in the issuer — policy logic belongs in the grant handler.

## Related

`primitives/token-engine.md`, `primitives/rbac-scopes.md`, `primitives/identity-principals.md`.
