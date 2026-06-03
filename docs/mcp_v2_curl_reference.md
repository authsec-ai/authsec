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

**Authentication:** HTTP Basic with `<application_id>:<introspection_secret>`
is **required** (RFC 7662 §2.1). Calls without it return 401. The
username MUST match the Application this token is being validated against.

**RBAC scope filtering:** the `scope` field in the response is **not**
what Hydra issued the token with — it's the intersection of the token's
claimed scope AND the user's current effective scopes on this Application.

This means an admin can revoke a binding and the change takes effect on
the very next introspection call, even if the token has 50 minutes of
life left. Specifically:

- The user's `sub` is resolved through `application_role_bindings` →
  `application_roles` → `application_role_scope_grants` → `oauth_scopes`.
- The intersection of (claimed scope) and (effective scope) becomes the
  response `scope`.
- A new field `ext_authsec_scope_filtered: true` is added when the
  filter applied (helps SDK debug logs explain narrowed scopes).

Special cases:
- `sub` doesn't parse as a UUID (service tokens, SPIRE workloads) →
  filter is **skipped**; Hydra's scope claim passes through unchanged.
- `sub` is a UUID but the user doesn't exist in this tenant → scope
  filtered to **empty** (fail-closed; user can't be confirmed).
- Resolver error → scope filtered to **empty** (fail-closed).
- `active=false` → response unchanged (no point filtering an invalid
  token).

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

### Login challenge page-data (Session 1 of login port)

Public, no auth — the `login_challenge` itself is the authentication
context (Hydra signs it). Called by whoever serves the login UI to
fetch the workspace + IDP list to render.

```bash
# Hydra sends the user's browser to your login page with ?login_challenge=...
# That page's backend calls:
curl "$AUTHSEC/authsec/oauth/v2/login/page-data?login_challenge=<challenge-from-hydra>"
```

Response shape:
```json
{
  "success": true,
  "login_challenge": "<challenge>",
  "context_id": "<authsec_ctx UUID>",
  "tenant_id": "<tenant UUID>",
  "application_id": "<app UUID>",
  "application_name": "MCP Demo",
  "resource_uri": "https://mcp-dev.mcpauthz.com/mcp",
  "requested_scope": ["openid","offline_access","mcp_demo.read","..."],
  "skip": false,
  "identity_providers": [
    {
      "identity_provider_id": "<idp UUID>",
      "provider_type": "oidc",
      "display_name": "Corporate Google"
    }
  ],
  "submit": {
    "custom": "https://.../authsec/oauth/v2/login/complete-local",
    "oidc":   "https://.../authsec/oauth/v2/login/oidc/initiate",
    "saml":   "https://.../authsec/oauth/v2/login/saml/initiate",
    "reject": "https://.../authsec/oauth/v2/login/reject"
  }
}
```

`skip: true` means Hydra has an existing session for this client; the UI
should POST to /login/complete-local with the included subject rather than
prompt for credentials again (auto-accept).

`identity_providers` is filtered by the Application's IDP whitelist policy
when one exists; default-allow when no policy rows exist for the Application.

`submit.*` URLs land in Sessions 2-5 of the port. Session 1 only wires
this read endpoint.

### Custom-login completion (Session 2 of login port)

Once the user enters email+password on the login page, the UI POSTs here.
The backend looks up the user, verifies password, calls Hydra accept-login,
and returns the redirect_to URL the browser should follow next (usually
the consent endpoint).

```bash
curl -s -X POST "$AUTHSEC/authsec/oauth/v2/login/complete-local" \
  -H "Content-Type: application/json" \
  -d '{
    "login_challenge": "<challenge-from-page-data>",
    "email": "chandanak7777@gmail.com",
    "password": "<password>",
    "remember": false
  }'
```

Response on success:
```json
{ "success": true, "redirect_to": "https://oauth.example.com/oauth2/auth?..." }
```

Response on bad credentials (401):
```json
{ "success": false, "error": "invalid credentials" }
```

Provider filter: only `provider IN ('custom','ad_sync','entra_id','scim')`
users can log in via this endpoint. OIDC-federated users (`provider='oidc'`)
must use the OIDC initiate path — coming in Session 4.

`remember: true` asks Hydra to skip authentication on subsequent /authorize
calls for this (client, user) pair for 8 hours. UI surfaces this as
"Keep me signed in."

Side effect: writes user_id + auth_time onto the auth_request_context
row identified by login_challenge. Those are read by the consent step
to populate access token claims.

### Reject login (Session 2)

User clicked Cancel on the login page.

```bash
curl -s -X POST "$AUTHSEC/authsec/oauth/v2/login/reject" \
  -H "Content-Type: application/json" \
  -d '{
    "login_challenge": "<challenge>",
    "reason": "User clicked cancel"
  }'
```

Response:
```json
{ "success": true, "redirect_to": "<client redirect_uri>?error=access_denied&..." }
```

Tells Hydra to abort the dance. Hydra returns a redirect_to that ends at
the client's redirect_uri with error=access_denied, so the calling
application can show "login cancelled."

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

Returns rows from the `oauth_scopes` table:
```json
[
  {
    "id": "<uuid>",
    "tenant_id": "<tenant uuid>",
    "application_id": "<app uuid>",
    "scope_string": "mcp_demo.read",
    "display_name": "Read access",
    "description": "Read-only operations",
    "risk_level": "low",
    "source": "admin",
    "created_at": "...",
    "updated_at": "..."
  }
]
```

`source` is one of `admin`, `application_create` (backfilled from
`scopes_supported`), or `sdk_discovered` (reserved).

### Create a scope

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/scopes" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "scope_string": "mcp_demo.admin",
    "display_name": "Admin operations",
    "description": "Privileged admin tools",
    "risk_level": "high"
  }'
```

`risk_level` must be one of `low`, `medium`, `high`, `critical`. Returns
201 with the new row. 409 if `scope_string` already exists for the app.

Also adds the scope to `resource_servers.scopes_supported` in lockstep so
the SDK's `/sdk-policy` reader sees it.

### Update a scope (metadata only)

```bash
curl -X PUT "$AUTHSEC/authsec/applications/$APP/scopes/<SCOPE_ID>" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "Read-only access",
    "description": "Updated description",
    "risk_level": "medium"
  }'
```

`scope_string` is **immutable** after create — Hydra and SDK clients hold
scope strings as opaque identifiers. Renaming would break in-flight tokens.
Display name / description / risk level only.

### Delete a scope

```bash
curl -X DELETE "$AUTHSEC/authsec/applications/$APP/scopes/<SCOPE_ID>" \
  -H "Authorization: Bearer $JWT"
```

Returns `{scope_string, affected_tools: [...]}`. Side effects:
- Strips the scope from `resource_servers.scopes_supported`.
- Strips the scope from every `mcp_tools.required_scopes` array that had it.
- Emits `scope_deleted` drift event (if state=ready).
- Emits one `tool_unmapped` drift event per affected tool (if state=ready).

Note: this is destructive — tokens with the deleted scope continue to
exist until they expire, but introspection still returns the (now-stale)
scope claim. SDK-side enforcement falls back to deny-all for tools that
required the deleted scope and no longer have any non-deleted required
scopes left.

### Scope matrix (tools × scopes)

```bash
curl "$AUTHSEC/authsec/applications/$APP/scope-matrix" \
  -H "Authorization: Bearer $JWT"
```

Returns `{scopes_supported, tools: [{tool_name, tool_id, is_public, required_scopes}, ...]}`.

### Update a tool's required scopes

```bash
curl -X PUT "$AUTHSEC/authsec/applications/$APP/tool-scope-map" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_id": "<MCP_TOOL_UUID>",
    "required_scopes": ["mcp_demo.compute", "mcp_demo.write"]
  }'
```

Validates that every requested scope is registered for the Application.
400 if any scope isn't in the Application's `scopes_supported`.

Returns `{tool, prior_required_scopes, prior_is_public, protection_weakened}`.
`protection_weakened=true` when the change made the tool more permissive
(had scopes but now has none and isn't public). Emits `tool_unmapped`
drift event when weakened (if state=ready).

### Mark a tool public / private

```bash
# Make a tool public (no scope check)
curl -X POST "$AUTHSEC/authsec/applications/$APP/tools/<TOOL_ID>/public" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"is_public": true}'

# Un-mark a tool public
curl -X POST "$AUTHSEC/authsec/applications/$APP/tools/<TOOL_ID>/public" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"is_public": false}'
```

Same `ToolChangeResult` shape as `/tool-scope-map`. Emits `tool_unmapped`
drift event when flipping `false -> true` (public is a weakening of the
protection).

### List roles (Application-scoped)

```bash
curl "$AUTHSEC/authsec/applications/$APP/roles" \
  -H "Authorization: Bearer $JWT"
```

Returns every role for the Application, each hydrated with its scope
grants:

```json
[
  {
    "id": "<role uuid>",
    "tenant_id": "<tenant uuid>",
    "application_id": "<app uuid>",
    "name": "viewer",
    "description": "Read-only access",
    "is_system": false,
    "created_at": "...",
    "updated_at": "...",
    "granted_scopes": [
      {
        "scope_id": "<scope uuid>",
        "scope_string": "mcp_demo.read",
        "display_name": "Read access",
        "risk_level": "low"
      }
    ]
  }
]
```

### Create a role

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/roles" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "viewer",
    "description": "Read-only access to MCP tools",
    "scope_ids": ["<scope_id_1>", "<scope_id_2>"]
  }'
```

`scope_ids` is optional — pass `[]` or omit to create the role without
scope grants. Every passed `scope_id` must be registered for THIS
Application (cross-application scope grants are rejected with 400).

Returns 201 with the hydrated role view. 409 if a role with the same
name already exists for the Application.

### Update a role's scope grants (replace semantics)

```bash
# Replace with a new set
curl -X PUT "$AUTHSEC/authsec/applications/$APP/roles/<ROLE_ID>/scope-grants" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "scope_ids": ["<scope_id_1>", "<scope_id_2>", "<scope_id_3>"]
  }'

# Strip all grants
curl -X PUT "$AUTHSEC/authsec/applications/$APP/roles/<ROLE_ID>/scope-grants" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"scope_ids": []}'
```

Replace semantics — anything in the role's current grants that isn't in
the request gets removed; anything new gets added. Idempotent: passing
the exact current set is a no-op (with an updated_at bump). All
validations are transactional — either every scope_id is accepted and
the diff applies, or nothing changes.

Returns 200 with the hydrated role view.

### List bindings on an Application

```bash
curl "$AUTHSEC/authsec/applications/$APP/bindings" \
  -H "Authorization: Bearer $JWT"
```

Returns every user ↔ role binding for the Application, hydrated with
user email/name and role name:

```json
[
  {
    "id": "<binding uuid>",
    "tenant_id": "<tenant uuid>",
    "application_id": "<app uuid>",
    "role_id": "<role uuid>",
    "user_id": "<user uuid>",
    "granted_at": "...",
    "granted_by": "<admin user uuid>",
    "user_email": "alice@example.com",
    "user_name": "Alice",
    "role_name": "viewer"
  }
]
```

### Create a binding (bind a user to a role)

```bash
curl -X POST "$AUTHSEC/authsec/applications/$APP/bindings" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "<user_uuid_from_users_table>",
    "role_id": "<role_uuid>"
  }'
```

Returns 201 with the hydrated binding view. 409 if the user is already
bound to that role on this Application. 400 if the role doesn't belong
to this Application OR the user isn't in this tenant.

`granted_by` is captured automatically from the calling admin's JWT.

### Delete a binding (revoke a user's role)

```bash
curl -X DELETE "$AUTHSEC/authsec/applications/$APP/bindings/<BINDING_ID>" \
  -H "Authorization: Bearer $JWT"
```

Returns 200 with `{"status": "deleted"}`. 404 if the binding doesn't
exist or doesn't belong to this Application.

### List eligible users (not yet bound)

```bash
# All eligible users (paginated, default 100)
curl "$AUTHSEC/authsec/applications/$APP/eligible-users" \
  -H "Authorization: Bearer $JWT"

# Search by email or name prefix, raise the limit
curl "$AUTHSEC/authsec/applications/$APP/eligible-users?search=alice&limit=20" \
  -H "Authorization: Bearer $JWT"
```

Returns users in the tenant who have NO existing binding on this
Application. Useful for the admin UI's "grant access" picker.

Query params:
- `?search=<prefix>` — case-insensitive LIKE on email + name
- `?limit=<1..500>` — default 100, max 500

### List users with current access

```bash
curl "$AUTHSEC/authsec/applications/$APP/access/users" \
  -H "Authorization: Bearer $JWT"
```

Returns every user with at least one binding on this Application, with
aggregated role names + the union of effective scope strings:

```json
[
  {
    "user_id": "<uuid>",
    "email": "alice@example.com",
    "name": "Alice",
    "active": true,
    "role_names": ["viewer", "tool_runner"],
    "scope_strings": ["mcp_demo.read", "mcp_demo.compute"]
  }
]
```

### Get a single user's effective access

```bash
curl "$AUTHSEC/authsec/applications/$APP/users/<USER_ID>/effective-access" \
  -H "Authorization: Bearer $JWT"
```

Resolves the full per-role + aggregated-scope view for one user:

```json
{
  "user_id": "<uuid>",
  "email": "alice@example.com",
  "name": "Alice",
  "active": true,
  "roles": [
    {
      "role_id": "<uuid>",
      "role_name": "viewer",
      "granted_at": "...",
      "scope_strings": ["mcp_demo.read"]
    },
    {
      "role_id": "<uuid>",
      "role_name": "tool_runner",
      "granted_at": "...",
      "scope_strings": ["mcp_demo.compute"]
    }
  ],
  "effective_scopes": ["mcp_demo.compute", "mcp_demo.read"]
}
```

`effective_scopes` is the deduplicated union of every role's
`scope_strings` — this is the "what can this user do?" set, computed
fresh on every read (no caching).

Returns 404 if the user doesn't exist in the tenant. Returns 200 with
empty `roles` + `effective_scopes` if the user exists but has no
bindings.

---

## Section 2b — Governance views (read-only)

Phase 9 of the port plan. All read-only, all JWT-authenticated, all
compose existing tables (bindings, roles, scope grants, scopes, tools,
users). No new schema.

### List all access assignments (audit-grade)

```bash
# All assignments
curl "$AUTHSEC/authsec/applications/$APP/access-assignments" \
  -H "Authorization: Bearer $JWT"

# Filter by user / role / time window
curl "$AUTHSEC/authsec/applications/$APP/access-assignments?user_id=<USER_UUID>&role_id=<ROLE_UUID>&granted_after=2026-01-01T00:00:00Z" \
  -H "Authorization: Bearer $JWT"
```

Returns one row per binding, hydrated with user email/name, role name,
and the role's scope_strings. Suited for compliance audit.

### Preview an access change (dry-run)

```bash
curl "$AUTHSEC/authsec/applications/$APP/access-change-previews?user_id=<USER_UUID>&add_role_ids=<ROLE1>,<ROLE2>&remove_role_ids=<ROLE3>" \
  -H "Authorization: Bearer $JWT"
```

Pure read — no DB writes. Returns:

```json
{
  "user_id": "<uuid>",
  "user_email": "alice@example.com",
  "prior_roles": ["viewer"],
  "next_roles": ["viewer", "tool_runner"],
  "prior_scopes": ["mcp_demo.read"],
  "next_scopes": ["mcp_demo.read", "mcp_demo.compute"],
  "added_scopes": ["mcp_demo.compute"],
  "removed_scopes": []
}
```

Empty CSV params are fine. Use this to show admins "are you sure?" diffs
before committing a binding mutation.

### Simulate access (if user X had role set Y)

```bash
curl "$AUTHSEC/authsec/applications/$APP/access-simulations?user_id=<USER_UUID>&role_ids=<ROLE1>,<ROLE2>" \
  -H "Authorization: Bearer $JWT"
```

Replaces the user's current roles with the simulated set and reports:
- `simulated_roles` — the named role set
- `simulated_scopes` — union of scope strings the user would have
- `tools_reachable` — tool names the user could call
- `tools_not_reachable` — tool names they could not

Useful for "what would my proposed role really let this user do?"

### Application-wide effective access

```bash
curl "$AUTHSEC/authsec/applications/$APP/effective-access" \
  -H "Authorization: Bearer $JWT"
```

One row per bound user with their resolved scope union. Faster than
calling `/users/:user_id/effective-access` per user (single query).

### End-user access summary (paged)

```bash
curl "$AUTHSEC/authsec/applications/$APP/end-user-access-summary?page=1&limit=50" \
  -H "Authorization: Bearer $JWT"
```

Paged version of the Application-wide effective access view. Same shape
per-user, plus `total / page / limit` for the page envelope.

### Evidence export (CSV-friendly)

```bash
curl "$AUTHSEC/authsec/applications/$APP/evidence-exports" \
  -H "Authorization: Bearer $JWT"
```

Returns one row per `(user, role, scope)` triple — denormalized,
spreadsheet-ready. Sorted stably by user email → role name → scope
string for diff-friendly exports.

### Posture summary (compliance snapshot)

```bash
curl "$AUTHSEC/authsec/applications/$APP/posture-summary" \
  -H "Authorization: Bearer $JWT"
```

Returns:

```json
{
  "application_state": "ready",
  "total_roles": 3,
  "total_scopes": 5,
  "total_tools": 12,
  "public_tools": 3,
  "unmapped_tools": 1,
  "total_users_bound": 24,
  "users_with_no_bindings": 156,
  "total_bindings": 42,
  "orphan_roles": 1,
  "undismissed_drift_events": 2
}
```

Orphan roles = roles with no scope grants AND no bindings (dead weight).
Unmapped tools = `is_public=false AND required_scopes=[]` (deny-all).

### Tool exposure (which tools are reachable by which users)

```bash
curl "$AUTHSEC/authsec/applications/$APP/tool-exposure" \
  -H "Authorization: Bearer $JWT"
```

One row per tool, listing the emails of users who can reach it. Public
tools are reachable by every active user. Non-public tools are reachable
by users whose effective scopes intersect the tool's `required_scopes`.

Cost is O(tools × users). Fine for typical Application sizes.

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

**All 9 phases of `mcp_v2_full_port_plan.md` have shipped.** Every
endpoint the deployed dev UI fires at `/authsec/applications/:id/*` is
now backed by the prod-mcp-v2 backport. See Sections 2, 2b, and 4b for
runnable curl for every endpoint.

If you find an endpoint the UI calls that doesn't have an entry here,
that's a regression — file a bug; the inventory is intentionally
exhaustive as of the port-plan's completion.
