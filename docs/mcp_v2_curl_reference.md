# Curl reference — every endpoint on the prod-mcp-v2 backport

Complete reference for manual testing. Every endpoint the backport
currently hosts, with a runnable curl. Use this against `prod.api.authsec.ai`.

Setup env once per shell:

```bash
export AUTHSEC=https://prod.api.authsec.ai
export JWT='<your admin JWT with tenant_id claim>'
```

Then for any Application-scoped commands:

```bash
export APP='<application uuid>'         # from POST /applications
export RSSECRET='<introspection secret>' # from POST /rotate-introspection-secret
```

---

## Section 1 — OAuth v2 surface (public, no auth)

### Discovery

```bash
# RFC 8414
curl "$AUTHSEC/authsec/oauth/v2/.well-known/oauth-authorization-server"

# OIDC discovery (superset)
curl "$AUTHSEC/authsec/oauth/v2/.well-known/openid-configuration"

# JWKS — public keys for verifying issued JWTs
curl "$AUTHSEC/authsec/oauth/v2/jwks"
```

### Dynamic Client Registration (RFC 7591)

```bash
curl -X POST "$AUTHSEC/authsec/oauth/v2/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My MCP CLI Client",
    "redirect_uris": ["http://localhost:9999/cb"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "resource": "https://mcp-dev.mcpauthz.com/mcp",
    "scope": "openid offline_access mcp_demo.read mcp_demo.compute"
  }'
```

Response 201:
```json
{
  "client_id": "<uuid>",
  "client_name": "My MCP CLI Client",
  "redirect_uris": ["http://localhost:9999/cb"],
  "grant_types": ["authorization_code","refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "openid offline_access mcp_demo.read mcp_demo.compute",
  "client_id_issued_at": 1717336200,
  "registration_type": "dcr"
}
```

Capture: `export CLIENT=<client_id>`.

### Authorize (browser flow — see runbook for the full dance)

```
https://prod.api.authsec.ai/authsec/oauth/v2/authorize?
  client_id=$CLIENT
  &redirect_uri=http%3A%2F%2Flocalhost%3A9999%2Fcb
  &response_type=code
  &scope=openid+offline_access+mcp_demo.read+mcp_demo.compute
  &state=test-1
  &resource=https%3A%2F%2Fmcp-dev.mcpauthz.com%2Fmcp
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

Verifier for the example challenge above: `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`.

### Token (authorization code grant)

```bash
curl -X POST "$AUTHSEC/authsec/oauth/v2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=$CLIENT" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=http://localhost:9999/cb" \
  --data-urlencode "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" \
  --data-urlencode "resource=https://mcp-dev.mcpauthz.com/mcp"
```

### Token (refresh grant)

```bash
curl -X POST "$AUTHSEC/authsec/oauth/v2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "client_id=$CLIENT" \
  --data-urlencode "refresh_token=$REFRESH" \
  --data-urlencode "resource=https://mcp-dev.mcpauthz.com/mcp"
```

### Introspect (resource-server perspective)

```bash
curl -X POST "$AUTHSEC/authsec/oauth/v2/introspect" \
  -u "$APP:$RSSECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$ACCESS"
```

Active token returns full claims; revoked/expired returns `{"active": false}`.

### Userinfo

```bash
curl "$AUTHSEC/authsec/oauth/v2/userinfo" \
  -H "Authorization: Bearer $ACCESS"
```

### Revoke

```bash
curl -X POST "$AUTHSEC/authsec/oauth/v2/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$ACCESS"
```

### Logout (RP-initiated)

```bash
curl "$AUTHSEC/authsec/oauth/v2/logout?post_logout_redirect_uri=https://example.com/done"
```

---

## Section 2 — Applications admin (JWT, requires tenant_id claim)

### List applications

```bash
curl "$AUTHSEC/authsec/applications" \
  -H "Authorization: Bearer $JWT"
```

### Get one

```bash
curl "$AUTHSEC/authsec/applications/$APP" \
  -H "Authorization: Bearer $JWT"
```

### Create

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

### Delete (soft)

```bash
curl -X DELETE "$AUTHSEC/authsec/applications/$APP" \
  -H "Authorization: Bearer $JWT"
```

### List clients registered against this application

```bash
curl "$AUTHSEC/authsec/applications/$APP/clients" \
  -H "Authorization: Bearer $JWT"
```

### Rotate introspection secret

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/rotate-introspection-secret" \
  -H "Authorization: Bearer $JWT"
```

Capture: `export RSSECRET=<introspection_secret from response>`.

### Validate (4 checks: state, clients, access-policy, reachability)

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/validate" \
  -H "Authorization: Bearer $JWT"
```

### Test login (state snapshot)

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/test" \
  -H "Authorization: Bearer $JWT"
```

### Launch (requires state=ready)

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/launch" \
  -H "Authorization: Bearer $JWT"
```

### Get access policy

```bash
# Either of these works (the second is the UI's "Access" tab alias)
curl "$AUTHSEC/authsec/applications/$APP/access-policy" \
  -H "Authorization: Bearer $JWT"

curl "$AUTHSEC/authsec/applications/$APP/access" \
  -H "Authorization: Bearer $JWT"
```

### Update access policy

```bash
# Enable + set a default role
curl -X PUT "$AUTHSEC/authsec/applications/$APP/access-policy" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "default_role_id": "<some-role-uuid>"}'

# Disable
curl -X PUT "$AUTHSEC/authsec/applications/$APP/access-policy" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false, "default_role_id": ""}'
```

---

## Section 3 — Identity providers (JWT)

### List

```bash
curl "$AUTHSEC/authsec/identity-providers" \
  -H "Authorization: Bearer $JWT"
```

### Create (OIDC — points at an existing oidc_providers row)

```bash
curl -X POST "$AUTHSEC/authsec/identity-providers" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_type": "oidc",
    "display_name": "Corporate Google",
    "config": {
      "provider_name": "google",
      "config_ref": "<uuid-of-existing-oidc_providers-row>"
    }
  }'
```

### Get one

```bash
curl "$AUTHSEC/authsec/identity-providers/<idp_id>" \
  -H "Authorization: Bearer $JWT"
```

### Toggle status

```bash
curl -X PUT "$AUTHSEC/authsec/identity-providers/<idp_id>/status" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"status": "disabled"}'
```

### Delete

```bash
curl -X DELETE "$AUTHSEC/authsec/identity-providers/<idp_id>" \
  -H "Authorization: Bearer $JWT"
```

### Pin an IDP to an Application (per-Application whitelist)

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/identity-providers" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"identity_provider_id": "<idp_id>", "enabled": true}'
```

### List Application IDP pins

```bash
curl "$AUTHSEC/authsec/applications/$APP/identity-providers" \
  -H "Authorization: Bearer $JWT"
```

### Unpin

```bash
curl -X DELETE "$AUTHSEC/authsec/applications/$APP/identity-providers/<idp_id>" \
  -H "Authorization: Bearer $JWT"
```

---

## Section 4 — SDK-facing endpoints (Basic auth, not JWT)

Authentication: HTTP Basic with `<application_id>:<introspection_secret>`.
These are what the @authsec/sdk runtime calls at startup.

### Get the SDK policy (scope matrix)

```bash
curl "$AUTHSEC/authsec/applications/$APP/sdk-policy" \
  -u "$APP:$RSSECRET"

# Or via the dev-style alias (also works on the backport):
curl "$AUTHSEC/authsec/resource-servers/$APP/sdk-policy" \
  -u "$APP:$RSSECRET"
```

Returns `policy_complete`, `state`, `scopes_supported`, `tool_policy`.

### Publish the SDK manifest

```bash
curl -X PUT "$AUTHSEC/authsec/applications/$APP/sdk-manifest" \
  -u "$APP:$RSSECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "generation": 2,
    "tools": [
      {
        "name": "echo",
        "title": "Echo",
        "description": "Echoes the input",
        "is_public": true,
        "required_scopes": []
      },
      {
        "name": "add_numbers",
        "title": "Add Numbers",
        "description": "Adds two integers",
        "is_public": false,
        "required_scopes": ["mcp_demo.compute"]
      },
      {
        "name": "todo_add",
        "title": "Add Todo",
        "description": "Adds a todo item",
        "is_public": false,
        "required_scopes": ["mcp_demo.write"]
      }
    ]
  }'

# Also accessible via the dev-style alias:
curl -X PUT "$AUTHSEC/authsec/resource-servers/$APP/sdk-manifest" \
  -u "$APP:$RSSECRET" \
  -H "Content-Type: application/json" \
  -d '{ "tools": [...] }'
```

Returns `accepted`, `removed`, `generation`, `published_at`.

---

## Section 5 — Hitting a real MCP server

Once your MCP demo server is running and your Application is created
+ rotated + (optionally) flipped to state=ready, you can drive the full
authorize → token → tool-call dance.

See `docs/mcp_v2_e2e_runbook.md` Phases 7-12 for the browser-driven
authorize, then phase 10 for the tool-call examples.

Minimal tool call once you have `$ACCESS`:

```bash
curl -X POST "https://mcp-dev.mcpauthz.com/mcp" \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": { "name": "add_numbers", "arguments": {"a": 2, "b": 3} }
  }'
```

---

## Section 6 — Quick state-flip SQL (until activation endpoint exists)

The backport doesn't have `POST /applications/:id/activate` yet (Phase 2
of the full port plan). For now, flip state via SQL on your tenant DB:

```sql
UPDATE resource_servers
SET state='ready', status='ready', setup_completed_at = now()
WHERE id = '<APP>' AND tenant_id = '<your-tenant-id>';
```

This makes `/launch` succeed and `/sdk-policy` return
`policy_complete: true` (assuming you have at least one tool published).

---

## Endpoints NOT on the backport yet

If you hit any of these you'll get 404. See `mcp_v2_full_port_plan.md`
for what's coming when:

```
GET    /authsec/applications/:id/tools                     [Phase 1]
GET    /authsec/applications/:id/scopes                    [Phase 1]
GET    /authsec/applications/:id/scope-matrix              [Phase 1]
GET    /authsec/applications/:id/setup                     [Phase 1]
GET    /authsec/applications/:id/activation-preview        [Phase 1]
GET    /authsec/applications/:id/sdk-manifest-status       [Phase 1]
POST   /authsec/applications/:id/activate                  [Phase 2]
POST   /authsec/applications/:id/rescan                    [Phase 2]
POST   /authsec/applications/:id/connections               [Phase 3]
DELETE /authsec/applications/:id/connections/:client_id    [Phase 3]
GET    /authsec/applications/:id/drift-events              [Phase 4]
POST   /authsec/applications/:id/drift-events/:eid/dismiss [Phase 4]
POST   /authsec/applications/:id/scopes                    [Phase 5]
PUT    /authsec/applications/:id/scopes/:scope_id          [Phase 5]
DELETE /authsec/applications/:id/scopes/:scope_id          [Phase 5]
PUT    /authsec/applications/:id/tool-scope-map            [Phase 6]
POST   /authsec/applications/:id/tools/:tool_id/public     [Phase 6]
GET    /authsec/oauth/consent-grants                       [Phase 7]
DELETE /authsec/oauth/consent-grants/:id                   [Phase 7]
GET    /authsec/applications/:id/roles                     [Phase 8]
POST   /authsec/applications/:id/roles                     [Phase 8]
PUT    /authsec/applications/:id/roles/:role_id/scope-grants [Phase 8]
GET    /authsec/applications/:id/bindings                  [Phase 8]
POST   /authsec/applications/:id/bindings                  [Phase 8]
DELETE /authsec/applications/:id/bindings/:binding_id      [Phase 8]
GET    /authsec/applications/:id/eligible-users            [Phase 8]
GET    /authsec/applications/:id/access/users              [Phase 8]
GET    /authsec/applications/:id/users/:user_id/effective-access [Phase 8]
GET    /authsec/applications/:id/access-assignments        [Phase 9]
GET    /authsec/applications/:id/access-change-previews    [Phase 9]
GET    /authsec/applications/:id/access-simulations        [Phase 9]
GET    /authsec/applications/:id/effective-access          [Phase 9]
GET    /authsec/applications/:id/end-user-access-summary   [Phase 9]
GET    /authsec/applications/:id/evidence-exports          [Phase 9]
GET    /authsec/applications/:id/posture-summary           [Phase 9]
GET    /authsec/applications/:id/tool-exposure             [Phase 9]
```
