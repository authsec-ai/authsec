# Outbound OAuth Apps — Design Spec

**Date:** 2026-06-10  
**Status:** Approved  
**Scope:** Backend implementation + Frontend handoff plan  

---

## Background

AuthSec's `external_services` feature already handles workspace-level static credentials (API keys, bearer tokens) backed by HashiCorp Vault. The gap — present in every competitor (Descope Outbound Apps, WorkOS Pipes, Auth0 Token Vault, Scalekit Agent Auth) — is **per-user OAuth token management**: a user connects their own Google/GitHub/Slack account, and agents can retrieve a fresh access token on that user's behalf without ever handling OAuth themselves.

This spec adds the OAuth connect flow and per-user token vault on top of the existing system. The static credentials path is unchanged.

---

## Approach

**Approach B — Explicit OAuth columns on `services` + new `service_user_tokens` table.**

- Add 4 columns to the existing `services` table
- Add one new table `service_user_tokens`
- New routes on the existing `/authsec/exsvc` prefix
- `auth_type` field is the discriminator: `api_key` / `bearer_token` / `basic_auth` use existing path; `oauth2_code` activates the new OAuth path
- DB wipe required (standard forward-only rule — edit bootstrap SQL, wipe, restart)

---

## Schema Changes (`migrations/master/001_bootstrap.sql`)

### A) Four new columns on `CREATE TABLE public.services`

```sql
oauth_provider        text,                        -- 'google' | 'github' | 'slack' | 'microsoft' | 'linear' | 'notion' | 'custom'
oauth_authorize_url   text,                        -- auto-filled from template; required when oauth_provider='custom'
oauth_token_url       text,                        -- auto-filled from template; required when oauth_provider='custom'
oauth_default_scopes  text[] DEFAULT '{}'::text[], -- pre-filled from template; admin can override
```

`auth_type` gains a new valid value: `oauth2_code`.  
`auth_config` (existing JSON blob) is used for provider-specific extras, e.g. `ms_tenant_id` for Microsoft.

### B) New table `service_user_tokens`

```sql
CREATE TABLE public.service_user_tokens (
    id            uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    service_id    uuid NOT NULL REFERENCES public.services(id) ON DELETE CASCADE,
    user_id       uuid NOT NULL,
    workspace_id  uuid NOT NULL,
    vault_path    text NOT NULL,
    scopes        text[] DEFAULT '{}'::text[],
    expires_at    timestamptz,
    refresh_error text,
    connected_at  timestamptz DEFAULT now(),
    updated_at    timestamptz DEFAULT now(),
    CONSTRAINT uq_service_user UNIQUE (service_id, user_id)
);

CREATE INDEX idx_service_user_tokens_service_id ON public.service_user_tokens (service_id);
CREATE INDEX idx_service_user_tokens_user_id    ON public.service_user_tokens (user_id);
CREATE INDEX idx_service_user_tokens_workspace  ON public.service_user_tokens (workspace_id);
```

### Vault path conventions

| What | Path |
|---|---|
| Workspace OAuth app credentials (client_secret) | `kv/data/secret/workspaces/{workspace_id}/services/{service_id}` |
| Per-user access + refresh tokens | `kv/data/secret/workspaces/{workspace_id}/users/{user_id}/services/{service_id}` |

---

## Provider Template Registry

A static Go map in `services/oauth_providers.go` — no DB table. Looked up at runtime when `oauth_provider` is a known key.

| Key | Authorize URL | Token URL | Default Scopes |
|---|---|---|---|
| `google` | `https://accounts.google.com/o/oauth2/v2/auth` | `https://oauth2.googleapis.com/token` | `openid email profile` |
| `github` | `https://github.com/login/oauth/authorize` | `https://github.com/login/oauth/access_token` | `read:user user:email` |
| `slack` | `https://slack.com/oauth/v2/authorize` | `https://slack.com/api/oauth.v2.access` | `users:read` |
| `microsoft` | `https://login.microsoftonline.com/{ms_tenant_id}/oauth2/v2.0/authorize` | `https://login.microsoftonline.com/{ms_tenant_id}/oauth2/v2.0/token` | `openid email profile` |
| `linear` | `https://linear.app/oauth/authorize` | `https://api.linear.app/oauth/token` | `read` |
| `notion` | `https://api.notion.com/v1/oauth/authorize` | `https://api.notion.com/v1/oauth/token` | — |
| `custom` | admin-supplied (required) | admin-supplied (required) | admin-supplied |

When a prebuilt template is used, `oauth_authorize_url` and `oauth_token_url` are optional on create — the service layer fills them from the registry. For `custom`, both are required.

Microsoft requires `ms_tenant_id` (the Azure AD tenant ID) stored in `auth_config` JSON.

---

## API Endpoints

All routes under `/authsec/exsvc`, protected by `SpiffeAuthMiddleware()` unless noted.

### Existing routes (unchanged)

```
POST   /services              create service config
GET    /services              list services
GET    /services/:id          get service
PUT    /services/:id          update service
DELETE /services/:id          delete service
GET    /services/:id/credentials   get workspace-level static secrets
```

### New routes

```
POST   /services/:id/connect
       Body:   { redirect_after: string }
       Returns: { url: string, callback_url: string }
       Purpose: Initiates the OAuth flow for the currently authenticated user.
                Returns the provider authorize URL to redirect to, plus the
                callback_url the admin must register at the provider.

GET    /oauth/callback/:workspace_id          ← NO auth middleware (provider hits this directly)
       Query: code, state
       Purpose: Receives the authorization code, validates state JWT,
                exchanges code for tokens, writes to Vault, upserts
                service_user_tokens row, redirects to redirect_after.

GET    /services/:id/token
       Query (optional): user_id (SPIFFE agents only)
       Returns: { access_token, expires_at, scopes }
       Purpose: Returns a fresh access token for the calling user.
                Auto-refreshes if token expires within 5 minutes.
                Returns 404 { error: "not_connected", connect_url } if no token exists.

DELETE /services/:id/token
       Purpose: Disconnects the current user — deletes Vault entry and token row.

GET    /services/:id/connections              ← admin/workspace-owner only
       Returns: { connections: [{ user_id, scopes, connected_at, expires_at, refresh_error }] }
       Purpose: Admin visibility into which users have connected this service.
```

---

## Service Layer

### State JWT (CSRF protection for OAuth callback)

Generated on `POST /connect`, verified on `GET /callback/:workspace_id`.

```json
{
  "service_id":    "uuid",
  "user_id":       "uuid",
  "workspace_id":  "uuid",
  "redirect_after": "https://...",
  "nonce":         "random-string",
  "exp":           1234567890        // 5 minutes TTL
}
```

Signed with `JWT_SECRET`. No DB storage needed — signature + expiry is sufficient.

### Connect flow (`POST /services/:id/connect`)

1. Load service — verify `auth_type == "oauth2_code"` and service belongs to caller's workspace
2. Look up provider template → fill `oauth_authorize_url` / `oauth_token_url` if stored values are blank
3. Build state JWT
4. Construct the callback URL: `{base_url}/authsec/exsvc/oauth/callback/{workspace_id}`
5. Build authorize URL with params: `client_id`, `redirect_uri`, `scope`, `state`, `response_type=code`, `access_type=offline` (for Google refresh tokens)
6. Return `{ url: authorizeURL, callback_url: callbackURL }`

### Callback handler (`GET /oauth/callback/:workspace_id`)

1. Parse and verify state JWT — check signature, expiry, `workspace_id` matches path param
2. Load service by `service_id` from state
3. Read `client_id` + `client_secret` from Vault at service's vault path
4. POST to `oauth_token_url`: `code`, `client_id`, `client_secret`, `redirect_uri`, `grant_type=authorization_code`
5. Parse response: `access_token`, `refresh_token`, `expires_in`, `scope`
6. Write to Vault: `kv/data/secret/workspaces/{wid}/users/{uid}/services/{sid}` → `{ access_token, refresh_token, token_type, scope }`
7. Upsert `service_user_tokens` row: `vault_path`, `scopes`, `expires_at = now() + expires_in`, `refresh_error = NULL`
8. `302` redirect to `redirect_after`
9. On any error: redirect to `redirect_after` with `?error=<reason>` query param

### Token retrieval with auto-refresh (`GET /services/:id/token`)

1. Resolve `user_id` from JWT claims; SPIFFE agents may pass `?user_id=` query param (requires `agent_accessible = true` on the service)
2. Load `service_user_tokens` row for `(service_id, user_id)`
3. If row not found → `404 { error: "not_connected", connect_url: "/authsec/exsvc/services/:id/connect" }`
4. If `expires_at > now() + 5min` → read `access_token` from Vault → return
5. If expiring/expired:
   - Read `refresh_token` from Vault
   - POST to `oauth_token_url` with `grant_type=refresh_token`
   - On success: write new tokens to Vault, update `expires_at`, clear `refresh_error` → return new `access_token`
   - On failure: set `refresh_error`, return `401 { error: "token_refresh_failed", connect_url }`

### New files

| File | Purpose |
|---|---|
| `services/oauth_providers.go` | Static provider template registry |
| `services/oauth_connect_service.go` | Connect, callback, token retrieval logic |
| `repository/service_token_repository.go` | CRUD for `service_user_tokens` |
| `controllers/platform/extsvc_oauth_controller.go` | HTTP handlers for the 4 new endpoints |

Existing files modified:
- `migrations/master/001_bootstrap.sql` — schema additions
- `repository/extsvc_repository.go` — add `oauth_provider`, `oauth_authorize_url`, `oauth_token_url`, `oauth_default_scopes` to `ExternalService` struct
- `services/extsvc_service.go` — fill provider template URLs on create
- `routes/routes.go` — register new routes; `/oauth/callback/:workspace_id` outside auth middleware group

---

## Frontend Integration Plan (handoff to FE dev)

### Overview

The UI types in `types.ts` are already well-prepared (`ExternalServiceToken`, `ProviderOption`, `ExternalServiceConfig`, `ExternalServiceStatus` including `needs_consent`/`expired`). The work is connecting existing types to new API endpoints and adding the provider picker UI.

### 1. Update `externalServiceApi.ts`

**Update `ExternalServiceRequest`** (create payload) — add `oauth_provider` and optional URL override fields:
```typescript
oauth_provider?: 'google' | 'github' | 'slack' | 'microsoft' | 'linear' | 'notion' | 'custom'
oauth_authorize_url?: string   // required only when oauth_provider='custom'
oauth_token_url?: string       // required only when oauth_provider='custom'
oauth_default_scopes?: string[]
```

**Update `RawExternalService`** — add new fields:
```typescript
oauth_provider?: 'google' | 'github' | 'slack' | 'microsoft' | 'linear' | 'notion' | 'custom'
oauth_authorize_url?: string
oauth_token_url?: string
oauth_default_scopes?: string[]
```

**Add new RTK Query endpoints:**
```typescript
// POST /exsvc/services/:id/connect
connectOAuthService(arg: { id: string; redirect_after: string })
→ returns { url: string; callback_url: string }
// Usage: window.location.href = result.url

// GET /exsvc/services/:id/token
getServiceToken(id: string)
→ returns { access_token: string; expires_at: string; scopes: string[] }

// DELETE /exsvc/services/:id/token
disconnectService(id: string)
→ 204 No Content

// GET /exsvc/services/:id/connections
getServiceConnections(id: string)
→ returns { connections: Array<{ user_id, scopes, connected_at, expires_at, refresh_error }> }
```

### 2. `AddExternalServicePage.tsx` — provider picker + callback URL display

**When `auth_type = "oauth2_code"` is selected**, show a provider picker step before the credentials form:

```
Provider grid (tiles with logo + name):
[ Google ]  [ GitHub ]  [ Slack ]  [ Microsoft ]
[ Linear ]  [ Notion ]  [ Custom → ]
```

- Selecting a **prebuilt provider**: auto-fills `oauth_provider`. Show only `client_id`, `client_secret`, and `scopes` (pre-filled with defaults, editable). Hide authorize/token URLs — backend fills these from templates.
- Selecting **Custom**: show `client_id`, `client_secret`, `oauth_authorize_url` (required), `oauth_token_url` (required), `oauth_default_scopes`.

**After service creation succeeds**, prominently display the callback URL using the existing copy-button pattern (`copiedSteps` state):
```
Register this callback URL in your provider's OAuth app settings:
https://auth.yourdomain.com/authsec/exsvc/oauth/callback/{workspace_id}
[ Copy ]
```
The `callback_url` is always returned by the backend in the `POST /connect` response. Use that value — do not construct it client-side.

### 3. `ExternalServicesPage.tsx` — per-user connection status column

Add a **Connect / Connected / Reconnect** action column to the services table:

| Service `auth_type` | User token status | Show |
|---|---|---|
| `oauth2_code` | No token row | **"Connect"** button |
| `oauth2_code` | Token valid | **"Connected ✓"** + Disconnect option |
| `oauth2_code` | Token expired / `refresh_error` set | **"Reconnect"** button |
| Other auth types | — | Nothing (existing behaviour) |

On **Connect / Reconnect**: call `connectOAuthService({ id, redirect_after: window.location.href })` → `window.location.href = result.url`.

On **Disconnect**: call `disconnectService(id)` → invalidate `ExternalService` list tag.

Update `mapRawToExternalService` status logic: for `auth_type === "oauth2_code"`, status defaults to `needs_consent` from the list endpoint; a separate `getServiceToken` call per row updates it to `connected` or `expired`. Use RTK Query's `skip` option to only fetch token status for OAuth services. Note: this is one API call per OAuth service row — acceptable for typical list sizes (tens of services, not thousands). If lists grow large, the backend should add a bulk token-status endpoint in a future iteration.

### 4. No new SPA page needed for callback

The backend handles the OAuth callback server-side (it needs `client_secret`). The per-workspace callback URL `/authsec/exsvc/oauth/callback/{workspace_id}` is registered at the provider, not a SPA route. After storing tokens, the backend redirects to `redirect_after` (the services page). No `OAuthCallbackPage.tsx` required.

### 5. Types already ready in `types.ts` — no changes needed

- `ExternalServiceToken` → use for `getServiceToken` response shape
- `ProviderOption` → use to drive the provider picker grid  
- `ExternalServiceFormData.config.redirectUri` → populate from workspace callback URL
- `ExternalServiceStatus` → `needs_consent`, `expired`, `connected` already defined correctly

---

## Out of Scope (not in this spec)

- M2M / `client_credentials` grant type outbound apps
- Org-level (non-user) shared OAuth tokens
- Audit log per token retrieval (future)
- Prebuilt provider logo assets (FE sourcing)
- Token revocation at the provider on disconnect (best-effort, not guaranteed by all providers)
