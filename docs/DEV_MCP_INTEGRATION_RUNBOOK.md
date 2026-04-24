# Dev MCP Integration Runbook

Use this runbook when validating an MCP server against the dev AuthSec environment.

## Canonical dev contract

- App host: `https://dev.authsec.dev`
- API and OAuth issuer host: `https://dev.api.authsec.dev`
- Root discovery and OAuth endpoints:
  - `https://dev.api.authsec.dev/.well-known/oauth-authorization-server`
  - `https://dev.api.authsec.dev/.well-known/openid-configuration`
  - `https://dev.api.authsec.dev/oauth/*`
- Resource server admin API:
  - `https://dev.api.authsec.dev/authsec/resource-servers`

Do not use:

- `stage.*` hosts for dev validation
- `/authmgr/*` routes
- OAuth discovery or introspection from `https://dev.authsec.dev`

## MCP validation flow

1. Register the resource server in AuthSec.
2. Save the returned values:
   - `id`
   - `issuer_url`
   - `jwks_uri`
   - `introspection_endpoint`
   - `introspection_secret`
3. Configure the SDK with those returned values, not hand-typed alternatives.
4. Start the MCP server and fetch:
   - `/.well-known/oauth-protected-resource`
   - the resource-path-derived metadata alias if the resource has a path component
5. Call the MCP endpoint without a token and verify the bearer challenge includes `resource_metadata=`.
6. Validate the OAuth issuer contract:
   - discovery returns JSON
   - JWKS returns JSON
   - POST `/oauth/introspect` returns JSON
   - `/authmgr/*` does not resolve
7. Complete a real OAuth flow and verify the SDK accepts the returned token.
https://20-106-226-245.sslip.io/mcp

use this mcp sever

## Browser validation flow

1. Start at `https://dev.authsec.dev/admin/login`.
2. Sign in with Google.
3. Verify the callback path reaches `/authsec/uflow/oidc/callback`.
4. Verify the UI preserves `code` and `state`.
5. Verify the flow advances into the admin callback scene and then WebAuthn.

## Smoke commands

Run from the `authsec` repo:

```bash
./scripts/check_dev_oauth_contract.sh
./scripts/check_public_docs_contract.sh
```
