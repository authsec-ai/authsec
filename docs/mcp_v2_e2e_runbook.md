# End-to-end runbook — prod-mcp-v2 + authsec-mcp-demo

A real working demo. Run the commands in order. Each step's expected output
is shown. **Replace the placeholder UUIDs / secrets / tokens with the
values you get back at each step.**

## Prerequisites

- A login on `prod.api.authsec.ai` that mints a JWT with `tenant_id` in
  the claims. Anything past Phase 3 of the backend migration plan does this.
- `psql` access to the master DB and the tenant DB whose `tenant_id`
  matches your login.
- The `authsec-mcp-demo` repo cloned locally, on the `vanilla-mcp`
  branch.
- `cloudflared` and the demo's tunnel config in `~/.cloudflared/`, OR
  another way to expose the demo on a public HTTPS URL.

Set up two env vars in your shell:

```bash
export AUTHSEC=https://prod.api.authsec.ai
export JWT=eyJ...   # admin JWT with tenant_id
```

---

## Phase 0 — Run the schema migrations

This only needs to happen once per environment. The 9 master + tenant
tables for the v2 surface plus the lean `mcp_tools` from the SDK port.

**On the master DB:**

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- Run the contents of:
--   migrations/master/107_create_mcp_oauth_clients.sql
--   migrations/master/108_create_resource_server_tenant_index.sql
```

**On YOUR tenant DB** (whose UUID matches your JWT's tenant_id):

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- Run the contents of:
--   migrations/tenant/019_create_resource_servers.sql
--   migrations/tenant/020_create_resource_server_client_registrations.sql
--   migrations/tenant/021_create_identity_providers.sql
--   migrations/tenant/022_create_application_identity_provider_policies.sql
--   migrations/tenant/023_create_auth_request_context.sql
--   migrations/tenant/024_create_oauth_consent_grants.sql
--   migrations/tenant/025_create_application_access_policies.sql
--   migrations/tenant/026_create_mcp_tools.sql
```

Verify:

```bash
psql ... -c "\d resource_servers"
psql ... -c "\d mcp_tools"
```

Each `\d` should print the column list.

---

## Phase 1 — Create an Application

```bash
curl -X POST "$AUTHSEC/authsec/applications" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MCP Demo",
    "application_type": "mcp_server",
    "public_base_url": "https://mcp-dev.mcpauthz.com",
    "protected_base_path": "/mcp",
    "resource_uri": "https://mcp-dev.mcpauthz.com/mcp",
    "scopes_supported": ["mcp_demo.read", "mcp_demo.write", "mcp_demo.compute"]
  }'
```

Expected response (201):

```json
{
  "id": "<APPLICATION_UUID>",
  "tenant_id": "<your tenant_id>",
  "application_type": "mcp_server",
  "name": "MCP Demo",
  "resource_uri": "https://mcp-dev.mcpauthz.com/mcp",
  ...
  "state": "pending_scan"
}
```

**Capture `id` as `$APP`:**

```bash
export APP=<APPLICATION_UUID>
```

---

## Phase 2 — Move state to `ready`

The backport doesn't run an auto-scan flow. To exercise the full dance
the Application has to be in `state='ready'`. For now, flip it via SQL:

```sql
UPDATE resource_servers SET state='ready', status='ready',
  setup_completed_at = now()
 WHERE id = '<APPLICATION_UUID>' AND tenant_id = '<your tenant_id>';
```

Verify:

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/validate" \
  -H "Authorization: Bearer $JWT"
```

`state` check should now be `pass`. The `reachability` check will still
report whatever Cloudflare returns — that's about your demo deployment,
not about AuthSec.

---

## Phase 3 — Rotate the introspection secret

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/rotate-introspection-secret" \
  -H "Authorization: Bearer $JWT"
```

Expected response:

```json
{ "introspection_secret": "<43-char base64url string>" }
```

**Capture it as `$RSSECRET`:**

```bash
export RSSECRET=<the secret>
```

The MCP demo server will use `($APP : $RSSECRET)` as Basic auth credentials
when calling `/sdk-policy`, `/sdk-manifest`, and `/oauth/v2/introspect`.

---

## Phase 4 — Optional: enable the default access policy

If you want first-time end-user logins to auto-bind to a default role,
set a policy. Skip this step if you don't have RBAC roles set up yet —
the demo flow works without it.

```bash
curl -X PUT "$AUTHSEC/authsec/applications/$APP/access-policy" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "default_role_id": "<role-uuid-if-you-have-one>"}'
```

---

## Phase 5 — Discover the OAuth server

Anyone can hit this — it's public. Verifies the v2 surface is reachable.

```bash
curl "$AUTHSEC/authsec/oauth/v2/.well-known/oauth-authorization-server"
```

Expected (excerpt):

```json
{
  "issuer": "https://prod.api.authsec.ai",
  "authorization_endpoint": "https://prod.api.authsec.ai/authsec/oauth/v2/authorize",
  "token_endpoint": "https://prod.api.authsec.ai/authsec/oauth/v2/token",
  "registration_endpoint": "https://prod.api.authsec.ai/authsec/oauth/v2/register",
  "introspection_endpoint": "https://prod.api.authsec.ai/authsec/oauth/v2/introspect",
  ...
}
```

---

## Phase 6 — Start the demo MCP server

In the `authsec-mcp-demo` repo:

```bash
cp .env.prod-mcp-v2 .env
# Edit .env: set
#   AUTHSEC_RESOURCE_SERVER_ID=$APP
#   AUTHSEC_INTROSPECTION_CLIENT_ID=$APP   (same value)
#   AUTHSEC_INTROSPECTION_CLIENT_SECRET=$RSSECRET
npm install
npm run share          # starts MCP server + cloudflared tunnel
```

You should see in the logs:

- `MCP server listening on :8091`
- `[authsec] runtime initialized`
- `[authsec] manifest published: 9 tools` (this is the SDK calling
  `PUT /authsec/resource-servers/$APP/sdk-manifest`)
- `[authsec] scope matrix fetched: 9 tools` (the boot fetch from
  `/sdk-policy`)
- `cloudflared` showing the tunnel URL → `https://mcp-dev.mcpauthz.com`

Verify the manifest landed:

```bash
psql ... -c "SELECT name, is_public, required_scopes FROM mcp_tools WHERE resource_server_id = '$APP';"
```

Should show 9 rows.

Verify sdk-policy responds (with the Basic auth the SDK uses):

```bash
curl "$AUTHSEC/authsec/applications/$APP/sdk-policy" \
  -u "$APP:$RSSECRET"
```

Expected:

```json
{
  "state": "ready",
  "policy_complete": true,
  "generation": 1,
  "scopes_supported": ["mcp_demo.read","mcp_demo.write","mcp_demo.compute"],
  "tool_policy": [
    {"name":"add_numbers","is_public":false,"required_scopes":["mcp_demo.compute"]},
    {"name":"current_time","is_public":true,"required_scopes":[]},
    ...
  ]
}
```

---

## Phase 7 — Dynamic Client Registration (DCR)

Now we act as an MCP client wanting to use the demo server. Anonymous —
no JWT needed.

```bash
curl -X POST "$AUTHSEC/authsec/oauth/v2/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "MCP CLI Test Client",
    "redirect_uris": ["http://localhost:9999/cb"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "resource": "https://mcp-dev.mcpauthz.com/mcp",
    "scope": "openid offline_access mcp_demo.read mcp_demo.compute"
  }'
```

Expected (201):

```json
{
  "client_id": "<NEW_CLIENT_UUID>",
  "client_name": "MCP CLI Test Client",
  "redirect_uris": ["http://localhost:9999/cb"],
  "grant_types": ["authorization_code","refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "openid offline_access mcp_demo.read mcp_demo.compute",
  "client_id_issued_at": <unix_ts>,
  "registration_type": "dcr"
}
```

**Capture `client_id` as `$CLIENT`:**

```bash
export CLIENT=<client_id>
```

Verify the client was bound to the Application:

```bash
curl "$AUTHSEC/authsec/applications/$APP/clients" \
  -H "Authorization: Bearer $JWT"
```

Should show one row with `client_id=$CLIENT`, `registration_type=dcr`,
`status=approved`.

---

## Phase 8 — Authorize → callback → token

Open in a browser (the user has to authenticate via the IDP):

```
https://prod.api.authsec.ai/authsec/oauth/v2/authorize?
  client_id=$CLIENT
  &redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcb
  &response_type=code
  &scope=openid+offline_access+mcp_demo.read+mcp_demo.compute
  &state=test-1
  &resource=https%3A%2F%2Fmcp-dev.mcpauthz.com%2Fmcp
  &code_challenge=<base64url(sha256("verifier-string"))>
  &code_challenge_method=S256
```

You'll be redirected through the IDP, then back to
`http://localhost:9999/cb?code=...&state=...`. Spin up a netcat listener
to catch it:

```bash
nc -l 9999
# in another shell, complete the browser flow.
# nc will print: GET /cb?code=AUTH_CODE&state=...
```

**Capture `code` as `$CODE` (decoded, in case it's URL-encoded):**

```bash
export CODE=<auth_code>
```

Exchange for tokens:

```bash
curl -X POST "$AUTHSEC/authsec/oauth/v2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=$CLIENT" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=http://localhost:9999/cb" \
  --data-urlencode "code_verifier=verifier-string" \
  --data-urlencode "resource=https://mcp-dev.mcpauthz.com/mcp"
```

Expected (200):

```json
{
  "access_token": "<JWT_ACCESS_TOKEN>",
  "expires_in": 3600,
  "id_token": "<ID_TOKEN>",
  "refresh_token": "<REFRESH>",
  "scope": "openid offline_access mcp_demo.read mcp_demo.compute",
  "token_type": "bearer"
}
```

**Capture:**

```bash
export ACCESS=<access_token>
export REFRESH=<refresh_token>
```

---

## Phase 9 — Introspect from the demo server's perspective

This is what the demo server does when an MCP client makes a tool call:

```bash
curl -X POST "$AUTHSEC/authsec/oauth/v2/introspect" \
  -u "$APP:$RSSECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$ACCESS"
```

Expected:

```json
{
  "active": true,
  "client_id": "<CLIENT>",
  "exp": <unix_ts>,
  "iat": <unix_ts>,
  "iss": "https://prod.api.authsec.ai",
  "scope": "openid offline_access mcp_demo.read mcp_demo.compute",
  "sub": "<user_uuid>",
  "token_type": "Bearer",
  "aud": ["https://mcp-dev.mcpauthz.com/mcp"]
}
```

If `active=false`, the token was revoked or expired. Re-do Phase 8.

---

## Phase 10 — Call an MCP tool through the demo server

Now use the real token against the demo server's MCP endpoint. The demo
server's SDK middleware validates the bearer, checks the tool against
the scope matrix, and runs the tool handler.

A scope-protected tool (`add_numbers` requires `mcp_demo.compute`):

```bash
curl -X POST "https://mcp-dev.mcpauthz.com/mcp" \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "add_numbers",
      "arguments": {"a": 2, "b": 3}
    }
  }'
```

Expected:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{"type": "text", "text": "5"}],
    "isError": false
  }
}
```

A public tool (`current_time` is `is_public=true`) — also works:

```bash
curl -X POST "https://mcp-dev.mcpauthz.com/mcp" \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": { "name": "current_time", "arguments": {} }
  }'
```

A tool you DON'T have scope for (`todo_add` requires `mcp_demo.write`,
which you didn't request) — should fail with `403 insufficient_scope`:

```bash
curl -X POST "https://mcp-dev.mcpauthz.com/mcp" \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": { "name": "todo_add", "arguments": {"text": "buy milk"} }
  }'
```

Expected `403` with body indicating the missing scope.

---

## Phase 11 — Refresh

```bash
curl -X POST "$AUTHSEC/authsec/oauth/v2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "client_id=$CLIENT" \
  --data-urlencode "refresh_token=$REFRESH" \
  --data-urlencode "resource=https://mcp-dev.mcpauthz.com/mcp"
```

Expected: fresh access token. Same shape as Phase 8 minus `id_token`.

---

## Phase 12 — Revoke

```bash
curl -X POST "$AUTHSEC/authsec/oauth/v2/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$ACCESS"
```

Expected: `200` with `{ "status": "revoked" }`. Re-introspect to confirm
`active=false`.

---

## Troubleshooting

| Symptom | Diagnosis |
| --- | --- |
| Phase 1 returns 401 | JWT doesn't have `tenant_id`. Re-login. |
| Phase 1 returns 409 | resource_uri already in use. Pick a different one or delete the existing Application. |
| Phase 2 validate shows `reachability: fail (HEAD returned 530)` | Cloudflare can't reach the demo server. Make sure `npm run share` is running and the tunnel is up. The OAuth dance still works — only the validate endpoint cares. |
| Phase 3 returns 404 | The Application UUID is wrong. Re-check `$APP`. |
| Phase 6 logs `manifest publish: HTTP 401` | `AUTHSEC_INTROSPECTION_CLIENT_ID` or `AUTHSEC_INTROSPECTION_CLIENT_SECRET` is wrong. The id MUST equal the Application's UUID. |
| Phase 6 logs `scope matrix fetch: HTTP 401` | Same as above — Basic auth mismatch. |
| Phase 8 `/token` returns `invalid_request: resource parameter required` | You forgot `--data-urlencode "resource=..."`. Backport enforces RFC 8707. |
| Phase 8 `/token` returns `invalid_grant: redirect_uri mismatch` | The redirect_uri on /token must EXACTLY match the one used on /authorize. |
| Phase 10 returns `401 invalid_token` | Token expired (3600s), revoked, or introspect found nothing. Run Phase 9 to see what introspect actually reports. |
| Phase 10 returns `403 insufficient_scope` | Token's scope doesn't include the required scope for that tool. Check Phase 8's response — the scope you actually got may be less than what you requested if Hydra/consent narrowed it. |
| Phase 11 returns `invalid_grant: refresh failed` | The auth code grant didn't include `offline_access` scope — no refresh token issued in Phase 8. Re-do Phase 8 with `offline_access` in the scope. |
