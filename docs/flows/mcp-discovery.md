# Flow: MCP Discovery & Dynamic Client Registration

> How an MCP client (e.g. Claude Desktop, an SDK) discovers AuthSec, registers itself,
> and gets authorized for a resource server.
> Read `primitives/oauth-as.md` first.

## Discovery

An MCP client fetches the AS metadata to find endpoints + capabilities:

```
GET /.well-known/oauth-authorization-server
GET /.well-known/openid-configuration      (OIDC superset — same document)
```

Response built by `OAuthASService.ASMetadata(baseURL)` (`services/oauth_as_service.go`).
Key fields:
- `issuer`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`
- `introspection_endpoint`, `revocation_endpoint`, `jwks_uri`
- `grant_types_supported` — includes `client_credentials` when `XAA_M2M=true`
- `code_challenge_methods_supported: ["S256"]`
- `client_auth_supported: ["client_secret_basic", "private_key_jwt"]` (M2M capable clients)

## Dynamic Client Registration (RFC 7591)

```
POST /oauth/register
Content-Type: application/json

{
  "client_name": "My MCP Agent",
  "redirect_uris": ["http://localhost:3000/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "scope": "openid profile tool:invoke",
  "token_endpoint_auth_method": "none"
}
```

Handler: `OAuthASController.Register`.

Processing:
1. Validate fields (redirect URIs, grant types, response types).
2. Generate `client_id` (UUID), `client_secret` if confidential.
3. Insert `mcp_oauth_clients` row.
4. Sync to Hydra via `hydraAdminCreateClient` → set `sync_status='active'` on success,
   `'sync_error'` on failure (reconciler retries).
5. Return RFC 7591 client information response with `registration_access_token` (for
   RFC 7592 management).

`token_endpoint_auth_method`:
- `"none"` — public client (PKCE only; cannot use M2M grants).
- `"client_secret_basic"` — secret stored hashed in `oauth_client_secrets`.
- `"private_key_jwt"` — public keys stored in `oauth_client_jwks`.

## RFC 7592 Client Management

```
GET    /oauth/register/:client_id        — GetRegistration
PUT    /oauth/register/:client_id        — UpdateRegistration
DELETE /oauth/register/:client_id        — DeleteRegistration
```

All require the `registration_access_token` returned at registration. Deletes set
`sync_status='pending_delete'`; the reconciler handles the Hydra-side delete.

## Resource Server SDK Policy

```
GET /resource-servers/:id/sdk-policy
```

Returns machine-readable policy for the SDK to configure itself:
- Which grant types apply to this RS.
- Required scopes.
- Discovery endpoints.

## Client → RS binding (first contact)

After registration, a client's first authorize request for a given RS triggers
the first-contact gate (`resource_server_client_registrations` insert with
`status='access_pending'`). Admin approval upgrades it to `approved`.

For DCR clients, `EnsureHydraClientHasRSScopes` JIT-widens the Hydra-side scope
registration so Hydra doesn't reject the authorize request for unknown scopes.

## Stale client cleanup

`HydraReconciler.runStaleDCRCleanup` marks DCR clients with no token in
`DCR_STALE_DAYS` days (default 30) as `pending_delete`. The reconciler then
deletes them from Hydra on the next tick.

## When you're building

- **New registration field?** Add to `mcp_oauth_clients` schema + `Register`/`GetRegistration`/
  `UpdateRegistration` handlers. Mirror in `hydraClient` struct if Hydra needs it.
- **New discovery field?** Edit `OAuthASService.ASMetadata`.
- **Conditional grant types** (like `client_credentials` for M2M): gated by `config.AppConfig.XAAm2m`
  flag in `m2mGrantTypes()`.

## Related

`primitives/oauth-as.md` (endpoint list + grant dispatch), `primitives/hydra.md`
(Hydra sync + reconciler), `flows/oidc-login.md` (what happens after registration).
