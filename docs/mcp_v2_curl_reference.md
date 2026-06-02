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

### List tools (admin view)

```bash
curl "$AUTHSEC/authsec/applications/$APP/tools" \
  -H "Authorization: Bearer $JWT"
```

Returns the `mcp_tools` rows — same data the SDK reads via `/sdk-policy`,
but JWT-authenticated for admin UI use.

### List scopes (admin view)

```bash
curl "$AUTHSEC/authsec/applications/$APP/scopes" \
  -H "Authorization: Bearer $JWT"
```

Returns `[{scope, source}, ...]` from `resource_servers.scopes_supported`.

### Scope matrix (tools × scopes)

```bash
curl "$AUTHSEC/authsec/applications/$APP/scope-matrix" \
  -H "Authorization: Bearer $JWT"
```

Returns `{scopes_supported, tools: [{tool_name, tool_id, is_public, required_scopes}, ...]}`.

### Setup checklist

```bash
curl "$AUTHSEC/authsec/applications/$APP/setup" \
  -H "Authorization: Bearer $JWT"
```

Returns the 5-item readiness checklist used by the Setup UI tab AND by
`/activate`'s gate. `ready_to_activate` is true when introspection secret +
tools + scopes + clients are all present.

### SDK manifest status

```bash
curl "$AUTHSEC/authsec/applications/$APP/sdk-manifest-status" \
  -H "Authorization: Bearer $JWT"
```

Returns `{scan_generation, last_successful_generation, tool_count, last_published_at}`.

### Activation preview (setup + validate combined)

```bash
curl "$AUTHSEC/authsec/applications/$APP/activation-preview" \
  -H "Authorization: Bearer $JWT"
```

One-shot read that returns both the setup checklist AND the live validate
result. The Setup UI tab uses this to render the full preview without two
round trips.

### Activate (flip state to ready)

```bash
# Normal activation — only succeeds when the setup checklist is fully done.
curl -X POST "$AUTHSEC/authsec/applications/$APP/activate" \
  -H "Authorization: Bearer $JWT"

# Force activation (bypass the checklist — admin override).
curl -X POST "$AUTHSEC/authsec/applications/$APP/activate" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"force": true}'
```

Returns the updated `resource_servers` row with `state="ready"`.

400 with a hint message if the checklist isn't satisfied.
409 if the application is already activated.

### Rescan (bump scan_generation)

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/rescan" \
  -H "Authorization: Bearer $JWT"
```

Returns `{scan_generation, started_at, status: "queued"}`. The backport
doesn't actually run an outbound scan; this forces connected SDKs to
refetch `/sdk-policy` on their next TTL.

### Pre-register a connection (admin OAuth client)

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/connections" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Admin-Provisioned Client",
    "redirect_uris": ["http://localhost:9999/cb"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic",
    "scope": "openid offline_access mcp_demo.read mcp_demo.compute"
  }'
```

Returns 201 with `{client_id, client_secret, ...}`. **The client_secret is
shown exactly once — capture it now.** The client_id can be reused for
authorize/token; the secret is needed only for token-endpoint auth.

### Revoke a connection

```bash
# Optional: ?reason=... is recorded in revoked_reason for audit
curl -X DELETE "$AUTHSEC/authsec/applications/$APP/connections/$CLIENT?reason=admin-rotated" \
  -H "Authorization: Bearer $JWT"
```

Marks the join row revoked and queues the master `mcp_oauth_clients` row
for deletion. The Hydra reconciler does the actual Hydra-side delete on its
next tick (default 5 min, configurable). Also emits a `connection_revoked`
drift event if the Application is in state=ready.

### List drift events

```bash
# All drift events since activation (includes dismissed-by-me flag)
curl "$AUTHSEC/authsec/applications/$APP/drift-events" \
  -H "Authorization: Bearer $JWT"

# Only events the calling admin hasn't dismissed (used for banner)
curl "$AUTHSEC/authsec/applications/$APP/drift-events?undismissed=true" \
  -H "Authorization: Bearer $JWT"
```

Returns `[{id, application_id, event_type, event_payload, occurred_at, occurred_by, dismissed_by_me}, ...]`.
Event types: `secret_rotated`, `default_role_disabled`, `connection_revoked`
(more in future phases: `tool_unmapped`, `scope_deleted`).

Only emitted when the Application is in `state=ready` — pre-activation
mutations are setup, not drift.

### Dismiss a drift event

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/drift-events/<EVENT_ID>/dismiss" \
  -H "Authorization: Bearer $JWT"
```

Idempotent — already-dismissed returns `200 {"status":"dismissed"}`.
Dismissal is per-admin; another admin can still see the event in their
banner.

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

## Section 4b — Consent grants (JWT, mounted under /authsec/oauth)

### List the caller's own consent grants

```bash
curl "$AUTHSEC/authsec/oauth/consent-grants" \
  -H "Authorization: Bearer $JWT"
```

Filters to the caller's `user_id` (decoded from the JWT). Excludes revoked
grants by default.

### List ALL grants in the tenant (admin scope)

```bash
curl "$AUTHSEC/authsec/oauth/consent-grants?all=true&include_revoked=true" \
  -H "Authorization: Bearer $JWT"
```

`all=true` skips the user_id filter. `include_revoked=true` includes
already-revoked grants (audit view).

### Filter grants by Application

```bash
curl "$AUTHSEC/authsec/oauth/consent-grants?application_id=$APP" \
  -H "Authorization: Bearer $JWT"
```

Combine with `?all=true` for admin-scope per-Application listing.

### Revoke a consent grant (self-service)

```bash
curl -X DELETE "$AUTHSEC/authsec/oauth/consent-grants/<GRANT_ID>" \
  -H "Authorization: Bearer $JWT"
```

The caller can only revoke their own grants. Cross-user attempts return
`404 consent grant not found` (existence is hidden).

### Revoke a consent grant (admin scope)

```bash
curl -X DELETE "$AUTHSEC/authsec/oauth/consent-grants/<GRANT_ID>?admin=true" \
  -H "Authorization: Bearer $JWT"
```

`admin=true` skips the user-ownership check. Side-effect: also calls
Hydra's `/admin/oauth2/auth/sessions/consent?subject=...&client=...` to
invalidate the upstream consent session, so refresh-token issuance fails
immediately rather than waiting for token expiry. Idempotent — revoking
an already-revoked grant returns `200`.

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
for what's coming when. Phases 1+2+3+4+7 (14 endpoints) have shipped —
those are documented in Sections 2 and 4b above.

```
POST   /authsec/applications/:id/scopes                    [Phase 5]
PUT    /authsec/applications/:id/scopes/:scope_id          [Phase 5]
DELETE /authsec/applications/:id/scopes/:scope_id          [Phase 5]
PUT    /authsec/applications/:id/tool-scope-map            [Phase 6]
POST   /authsec/applications/:id/tools/:tool_id/public     [Phase 6]
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
