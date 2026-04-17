# AuthSec — Technical Architecture (Phases 0–3)

> Audience: senior software architects evaluating or extending AuthSec.
> Scope: everything shipped through Phase 3 — OAuth/OIDC AS, federated identity, unified authorization, remembered consent, MCP positioning.
> Companion docs: `project_authsec_vision.md` (product), `migrations/master/*.sql` (schema of record).

---

## 1. System Overview

**AuthSec** is a multi-tenant third-party OAuth 2.1 / OIDC Authorization Server positioned as "Auth0 for MCP servers." It is a Go monolith that wraps **Ory Hydra v2.2.1** as the token-issuing core, and adds everything Hydra does *not* do: user identity, federation, RBAC-driven scope resolution, consent, DCR policy, resource-server registration, and the MCP-specific glue.

```
┌───────────────────────────────────────────────────────────────────┐
│                         AuthSec monolith (Go)                     │
│                                                                   │
│   ┌──────────────┐   ┌──────────────┐   ┌───────────────────┐    │
│   │ controllers/ │   │  services/   │   │   models/ + GORM  │    │
│   │  platform    │──▶│  (business) │──▶│  (Postgres)       │    │
│   └──────┬───────┘   └──────┬───────┘   └───────────────────┘    │
│          │                  │                                     │
│          │                  │  CircuitDoHydra (circuit breaker)   │
│          │                  ▼                                     │
│          │           ┌──────────────┐                             │
│          │           │  Ory Hydra   │ ── issues access/id/refresh │
│          │           │    2.2.1     │    tokens, manages sessions│
│          │           └──────────────┘                             │
│          │                                                        │
│          ▼                                                        │
│   ┌──────────────┐   ┌──────────────┐                            │
│   │ OIDC / SAML  │   │   SPIFFE /   │                            │
│   │   providers  │   │   Workload   │                            │
│   │ (federation) │   │   identity   │                            │
│   └──────────────┘   └──────────────┘                            │
└───────────────────────────────────────────────────────────────────┘
```

**Design tenets**
1. **Hydra issues tokens. AuthSec owns identity, policy, and binding.** We never reimplement token cryptography.
2. **Fail-closed everywhere.** Every lookup path rejects on miss. No "passthrough" code paths exist.
3. **Deterministic context binding.** Every auth flow has a server-generated UUID (`context_id`) that is bound to Hydra's `request_uri` (RFC 9126) — no heuristic recovery, no custom URL params that a proxy might strip.
4. **Compare-and-set writes** for every race-prone row update (PAR request_uri, login_challenge binding, one-time context consumption).
5. **Scope/permission registry is declarative.** Clients ask for scopes, AuthSec resolves them through the RBAC chain at consent time, Hydra stamps the intersection into the token.

---

## 2. Standards Inventory

| Standard | Purpose | Where in code |
|---|---|---|
| **RFC 6749** OAuth 2.0 | Core authz code grant | `controllers/platform/oauth_as_controller.go` |
| **OAuth 2.1 draft** | PKCE required, public clients, iframe rules | PKCE S256 enforced in Authorize handler |
| **RFC 7636** PKCE | `code_challenge` S256 mandatory | `models/pkce_verifier.go` |
| **RFC 8414** AS Metadata | `/.well-known/oauth-authorization-server` | Discovery handler |
| **OIDC Core 1.0** | id_token, userinfo, nonce, prompt, max_age, amr/acr | `OIDCDiscovery`, `Userinfo` handlers |
| **OIDC Discovery 1.0** | `/.well-known/openid-configuration` | `OIDCDiscovery` |
| **OIDC RP-Initiated Logout 1.0** | `/oauth/logout` + id_token_hint | `EndSession` |
| **RFC 7591** DCR | POST /oauth/register, resource required | DCR controller |
| **RFC 8707** Resource Indicators | `resource=` required at authorize/token/refresh | All grant handlers |
| **RFC 9126** PAR | Deterministic context binding via `request_uri` | `services/hydra_service.go::PushAuthorizationRequest`, public `/oauth/par` endpoint |
| **RFC 7662** Introspection | Token introspection w/ Basic auth | Introspection handler (bcrypt secret) |
| **RFC 7009** Token Revocation | `/oauth/revoke` | Revocation handler |
| **CIMD** Client ID Metadata Docs | HTTPS URL-as-client_id for MCP | CIMD resolver |
| **SAML 2.0** | SP-initiated SSO, assertion decrypt | `services/saml_*` |

Non-goals: CIBA, Device Authorization Grant, JARM, FAPI profiles (not required for AuthSec positioning; some scaffolded in `models/` but not production).

---

## 3. High-Level Component Map

```
controllers/platform/
├── oauth_as_controller.go      # /oauth/{authorize,token,introspect,revoke,register,par,logout,userinfo,jwks,.well-known/*}
├── hmgr_controller.go          # Hydra login/consent bridge (internal)
├── rsmgr_controller.go         # Resource-server + client registration lifecycle
├── scope_controller.go         # Scope/permission registry CRUD
├── consent_controller.go       # Remembered-consent reads (for UI)
├── provider_controller.go      # Unified OIDC/SAML/social provider config
└── dcr_controller.go           # DCR policy enforcement

services/
├── hydra_service.go            # CircuitDoHydra wrapper; all Hydra admin + public calls
├── oauth_as_service.go         # AuthRequestContext CRUD façade
├── authorization_context_service.go  # PAR binding, one-time consumption
├── scope_resolver.go           # Scope → permission → RBAC fail-closed resolver
├── consent_service.go          # UpsertConsent, CheckExistingConsent, 30d TTL
├── provider_service.go         # Federated provider orchestration
├── saml_service.go             # SAML SP, assertion crypto, attribute mapping
├── resource_server_service.go  # RS registration, audience validation
└── client_service.go           # MCP OAuth clients, CIMD resolution

models/ (Postgres via GORM)
├── auth_request_context.go     # Bridge state, one-time
├── mcp_oauth_client.go         # Hydra-backed OAuth client + AuthSec policy
├── resource_server.go          # Audience definitions
├── resource_server_client_registration.go  # RS ↔ client approval matrix
├── oauth_scope.go              # Scope registry (hierarchical)
├── oauth_consent_grant.go      # Remembered consent (30d)
├── pkce_verifier.go            # Server-side PKCE storage
├── oidc.go / saml.go           # Federated provider configs
└── rbac*.go                    # roles/permissions/bindings
```

---

## 4. Core Data Model

All tables use UUID PKs where appropriate and carry `tenant_id` for multi-tenant isolation. Numbers are migration IDs.

### 4.1 Auth bridge — `auth_request_contexts` (108, 109, 112, 113, 115, 116)

Short-lived (10 min TTL) row linking `/oauth/authorize` → Hydra login/consent → `/oauth/token`. One-time consumption.

Key columns:
- `state` (PK) — random per request
- `context_id` (unique) — server-generated UUID, embedded in Hydra session claims, used at token exchange
- `hydra_request_uri` (partial unique index) — RFC 9126 correlation key
- `login_challenge` (unique) — Hydra's challenge, bound at hmgr
- `resource_server_id`, `tenant_id`, `resource_uri` — audience binding
- `nonce`, `prompt`, `max_age`, `auth_time` — OIDC params
- `consent_completed`, `consumed`, `expires_at` — lifecycle flags

**Lifecycle:** see §5.1.

### 4.2 OAuth clients — `mcp_oauth_clients` (106, 117)

AuthSec-side mirror of a Hydra client, plus policy metadata.
- `hydra_client_id` — 1:1 with Hydra
- `client_id_type` — `uuid` | `cimd` | `dcr` | `prereg`
- `scope` — space-delimited default scopes (DCR-requested)
- `post_logout_redirect_uris[]` — OIDC RP-Logout allowlist
- `supports_refresh_token` — per-client gate (Phase 1)
- `tenant_id`, `created_by` — ownership

### 4.3 Resource servers — `resource_servers` (105)

- `resource_uri` — RFC 8707 audience string (validated at authorize AND token)
- `introspection_secret_hash` — bcrypt (migration 111)
- Ownership + metadata

### 4.4 RS ↔ Client approval — `resource_server_client_registrations` (107)

Explicit N:N approval matrix. `status` must be `approved` for the pair to authorize against the resource. Enforced at authorize, token, and refresh.

### 4.5 Scope registry — `oauth_scopes`, `oauth_scope_permissions` (118, 121)

- `oauth_scopes`: `name` (unique per tenant), `parent_scope_id` (hierarchy), `display_name`, `description`, `icon`, `risk_level`, `is_default`
- `oauth_scope_permissions`: N:N to `permissions`
- Hierarchy enables wildcards (`repo:*` implies `repo:read`, `repo:write`) via `expandWildcards` in `services/scope_resolver.go`

Legacy scope tables dropped in migration 121.

### 4.6 Remembered consent — `oauth_consent_grants` (120)

One row per (tenant, subject, client_id, resource_uri, scope). TTL 30 days (`DefaultConsentTTL`). `UpsertConsent` extends TTL on re-grant; `CheckExistingConsent` skips consent prompt when row found & not expired.

### 4.7 Federated providers — `oidc_providers`, `saml_providers` (103 + OIDC model)

Unified `Provider` abstraction: issuer/metadata URL, client creds, attribute mappings, JIT-provision flags, default-role mapping.

### 4.8 PKCE — `pkce_verifiers` (114)

Server-side storage for code_verifier/challenge pairs (S256) with one-time consumption. Separate from the auth context so PKCE can survive hmgr re-renders.

---

## 5. Flows

Conventions below: `AS` = AuthSec, `H` = Hydra, `RS` = resource server, `UA` = user agent, `IdP` = federated provider.

### 5.1 Authorization Code + PAR (deterministic binding)

```
UA ──► AS  GET /oauth/authorize?client_id=C&resource=R&redirect_uri=...&state=...&code_challenge=...&nonce=...
AS: validate client, RS, redirect_uri, PKCE; resolve client↔RS registration
AS: INSERT auth_request_contexts (state, context_id=UUID, tenant, resource, pkce ref, nonce, prompt, max_age, expires_at=now+10m)
AS ──► H   POST /oauth2/par (server-to-server via CircuitDoHydra)  ◄─── RFC 9126
H  ──► AS  201 { request_uri: urn:ietf:params:oauth:request_uri:..., expires_in }
AS: compare-and-set UPDATE auth_request_contexts SET hydra_request_uri=... WHERE state=? AND hydra_request_uri IS NULL
    (on 0 rows affected → 500, do NOT redirect; orphaned PAR expires in Hydra)
AS ──► UA  302 /oauth2/auth?client_id=H&request_uri=urn:...
UA ──► H   follows redirect
H  ──► UA  302 /hmgr/login?login_challenge=X  (AS-hosted login UI)
UA ──► AS  GET /login?login_challenge=X
AS: parse request_uri out of loginRequest.RequestURL (returned by Hydra admin API)
AS: SELECT ... WHERE hydra_request_uri=? AND consumed=false AND expires_at>now()
AS: atomic bind UPDATE SET login_challenge=? WHERE hydra_request_uri=? AND login_challenge IS NULL
    (idempotent on refresh; rejects if bound to different challenge)
AS: render login (local IdP or federation)
... user authenticates (see §5.8/5.9) ...
AS ──► H   PUT /admin/oauth2/auth/requests/login/accept { subject, session: { context_id, amr, acr, auth_time } }
H  ──► UA  302 → hmgr consent endpoint
AS: check remembered consent grant (§5.6); if hit → auto-accept; else render consent
AS ──► H   PUT /admin/oauth2/auth/requests/consent/accept { grant_scope: resolved, session: { ... context_id ... } }
H  ──► UA  302 → client redirect_uri?code=...&state=...
```

### 5.2 Token exchange (authorization_code) — fail-closed

```
Client ──► AS  POST /oauth/token (code, code_verifier, redirect_uri, resource)
AS ──► H   POST /oauth2/token (proxied; Hydra verifies PKCE, issues tokens)
H  ──► AS  200 { access_token, id_token, refresh_token? }
AS ──► H   POST /admin/oauth2/introspect (access_token)
H  ──► AS  { active, sub, session: { context_id, ... } }
AS: SELECT auth_request_contexts WHERE context_id=? AND consent_completed=true AND consumed=false
    (MISS → 400, tokens are effectively burned; we never return them)
AS: atomic consume UPDATE ... SET consumed=true WHERE context_id=? AND consumed=false
    (RowsAffected != 1 → reject)
AS: verify audience (token aud == requested resource == stored resource_uri)
AS: if refresh_token issued: verify client.supports_refresh_token gate
AS ──► Client  { access_token, id_token, refresh_token?, ... }
```

Rationale: even if Hydra happily issued a token, AuthSec refuses to surface it unless the context is valid, once-only, audience-matched, and client-permitted.

### 5.3 Refresh grant

```
Client ──► AS  POST /oauth/token (grant_type=refresh_token, refresh_token, resource, scope?)
AS: validate resource → RS exists, client↔RS registration approved (RFC 8707 at refresh — Phase 1 fix)
AS: ensure requested scope ⊆ original scope
AS ──► H   proxy
H  ──► AS  new access (+ optional rotated refresh)
AS ──► Client
```

### 5.4 Userinfo (OIDC)

```
Client ──► AS  GET/POST /oauth/userinfo (Authorization: Bearer <access_token>)
AS ──► H   introspect
AS: scope-filter claims from session.ext + introspection
     profile → name, given_name, family_name, preferred_username, picture, locale, zoneinfo, updated_at
     email   → email, email_verified (nil-safe via extractClaimBool, default false)
     phone   → phone_number, phone_number_verified
     address → address
     openid  → sub always
     auth_time → from session if present
AS ──► Client  200 application/json
```

### 5.5 RP-Initiated Logout

```
UA ──► AS  GET /oauth/logout?id_token_hint=...&post_logout_redirect_uri=...&state=...
AS: parse id_token_hint (unverified header ok; signed claims read via JWKS)
AS: resolve client, verify post_logout_redirect_uri against client's post_logout_redirect_uris[]
AS ──► H   DELETE /admin/oauth2/auth/sessions/login?subject=...  (revoke Hydra session)
AS ──► UA  302 post_logout_redirect_uri?state=...  (or fallback page)
```

### 5.6 Remembered consent

```
At consent step:
AS: SELECT oauth_consent_grants WHERE tenant=? AND subject=? AND client_id=? AND resource_uri=? AND scope ⊇ requested
    AND expires_at > now()
    HIT  → accept silently, do NOT re-render UI
    MISS → render consent UI → on user accept:
           UpsertConsent(...)  // extends TTL to now+30d
```

### 5.7 DCR (Dynamic Client Registration)

```
Client ──► AS  POST /oauth/register
    { redirect_uris[], resource, scope, token_endpoint_auth_method, grant_types, ... }
AS: policy checks (tenant allows DCR, redirect_uri scheme, resource exists, resource allowed for DCR)
AS ──► H   POST /admin/clients (Hydra creates the client)
AS: INSERT mcp_oauth_clients (hydra_client_id, client_id_type=dcr, scope, resource binding, ...)
AS: INSERT resource_server_client_registrations (status=approved by default policy OR pending)
AS ──► Client  201 { client_id, client_secret?, ..., registration_access_token }
```

### 5.8 CIMD (Client ID Metadata Document)

```
Client presents client_id = https://app.example/.well-known/oauth-client
AS ──► app.example  GET that URL over HTTPS
    → validates metadata, caches
AS: upsert mcp_oauth_clients (client_id_type=cimd) on first use
```

### 5.9 Federated OIDC login

```
AS login page ──► UA chooses provider (or HRD/login_hint routes)
AS ──► IdP  GET /authorize (state = hmac-signed continuation to AS callback)
IdP → UA → AS /oidc/callback?code=...&state=...
AS ──► IdP  POST /token   → id_token, access_token
AS: verify id_token (issuer/JWKS/nonce/aud), extract claims
AS: JIT-provision user if not exists; apply attribute mapping & default role
AS: continue the original Hydra login_challenge with subject=user.id
```

### 5.10 Federated SAML login

SP-initiated: AS generates AuthnRequest → IdP; on POST-back, decrypt assertion, validate signature + conditions, attribute-map, JIT-provision, same Hydra login accept step.

### 5.11 Introspection & Revocation

Standard RFC 7662/7009. Basic auth against `mcp_oauth_clients.introspection_secret_hash` (bcrypt). Hydra is the source of truth for active state.

---

## 6. Authorization Model

```
Client requests:  scope="openid profile mcp:tools:read repo:*"
                                       │
                                       ▼
                   ┌───────────────────────────────┐
                   │ services/scope_resolver.go    │
                   │ expandWildcards() ────────────┼─► expand "repo:*" via parent_scope_id
                   │ map scope → permissions       │     into repo:read, repo:write, …
                   │ intersect with subject RBAC   │
                   │   role_bindings → roles →     │
                   │   role_permissions →          │
                   │   permissions                 │
                   │ OIDC scopes bypass RBAC       │
                   │  (openid/profile/email/...)   │
                   │ FAIL-CLOSED on unknown scope  │
                   └──────────────┬────────────────┘
                                  ▼
                       granted_scopes ⊆ requested
                                  │
                                  ▼
                        Hydra consent accept
```

Rules:
- Unknown scope → reject the whole request (fail-closed).
- Scope known but not in subject RBAC → silently drop that scope (not the whole request), unless it's marked `required`.
- OIDC scopes (`openid profile email phone address offline_access`) are policy-bypassed — they are identity, not authorization.
- Consent UI receives `display_name`, `description`, `icon`, `risk_level` for each scope from the registry for human-readable rendering.

---

## 7. Security Architecture

### 7.1 Deterministic context binding (PAR)

Before PAR, we used a custom `authsec_ctx` URL param — proxies could strip it, and the DB fallback was heuristic (multi-field match) which could mis-bind concurrent flows. Now:
- Each `/oauth/authorize` does a server-to-server POST to Hydra `/oauth2/par`.
- Hydra returns a unique `request_uri`. We store it compare-and-set on the AS row.
- The browser redirect carries only `client_id` + `request_uri` (both standard OAuth params).
- At the AS login page, we parse `request_uri` from Hydra's `loginRequest.request_url` and bind the `login_challenge` atomically.
- Legacy `authsec_ctx` fallback is kept for one release cycle for in-flight pre-PAR flows.

### 7.2 Fail-closed invariants

| Path | Reject unless |
|---|---|
| Authorize | Client ∧ RS registration approved ∧ redirect_uri allowlisted ∧ PKCE present |
| PAR DB update | `hydra_request_uri IS NULL` (compare-and-set); 0 rows → 500 |
| hmgr bind | `request_uri` row exists, not consumed, not expired, either unbound or already bound to same challenge |
| Token exchange | Context found ∧ `consent_completed=true` ∧ `consumed=false` ∧ audience match ∧ refresh gate ok |
| Consume | `UPDATE ... SET consumed=true WHERE consumed=false`, RowsAffected == 1 |
| Refresh | RS exists ∧ client↔RS approved ∧ scope subset |
| Userinfo | Hydra introspection `active=true` |

### 7.3 Circuit breaker

All Hydra calls go through `CircuitDoHydra`. Open circuit → 502 to client, DB rows left for debug. No silent degradation.

### 7.4 Secret storage

- Introspection secrets: bcrypt (migration 111).
- Hydra client secrets: stored by Hydra, not AS.
- Federation provider secrets: envelope-encrypted at rest (KMS-backed).

### 7.5 Defense-in-depth for token audience

We check `aud` three times: at authorize (resource param), at token (introspect → aud), and at refresh (RS re-lookup). Even if Hydra misconfigures an audience, AS will refuse the exchange.

---

## 8. Multi-Tenancy

- Every row carries `tenant_id` (UUID).
- Tenant resolution: from the OAuth client's tenant binding, not from any header (clients don't get to pick their tenant).
- Cross-tenant access is impossible by construction — resource_server + client + user all must share `tenant_id` at every join.
- Admin APIs for tenant management are namespaced under `/admin/tenants/...` and gated by platform-admin RBAC (distinct from end-user RBAC).

---

## 9. Deployment & Operations

- **Runtime**: single Go binary, Postgres, Hydra 2.2.1, optional Redis for rate limiting / session caching.
- **Migrations**: sequential SQL in `migrations/master/NNN_*.sql`, applied by `internal/migration` runner on boot.
- **Health**: `/healthz` checks DB + Hydra circuit state.
- **Observability**: structured logs with `[MCP_AUTH]`, `[CIMD]`, `[DCR]`, etc. tags; every flow logs `context_id` and `request_uri` for trace correlation.
- **Tests**: unit tests per service; `internal/migration` integration tests need a live Postgres.
- **Branching**: active work on `dev`; `main` is production-tracked.
- **Secrets**: loaded from `config.AppConfig` (env + file); no secrets in repo.

---

## 10. Extension Points (Phase 4+)

| Hook | How to extend |
|---|---|
| New federated provider | Implement `Provider` interface in `services/provider/` |
| Custom scope class | Insert into `oauth_scopes`, wire permissions |
| New grant type | Add handler in `oauth_as_controller.go`, reuse `hydra_service.go` wrappers |
| Custom consent UI | Hmgr is a thin renderer — swap template / plug React app |
| Pluggable user store | `models/user.go` is GORM; federation flows already JIT-provision |
| Deferred: login_hint, explicit HRD, explicit account-linking endpoint, consent-UI scope metadata rendering |

---

## Appendix A — End-to-end call trace (happy path)

```
1. Client          → GET  /oauth/authorize                     (AS)
2. AS              → POST /oauth2/par                          (Hydra)        via CircuitDoHydra
3. AS              → 302  /oauth2/auth?client_id&request_uri   (UA)
4. UA              → GET  /oauth2/auth...                      (Hydra)
5. Hydra           → 302  /login?login_challenge=X             (UA → AS)
6. AS              → GET  /admin/oauth2/auth/requests/login    (Hydra admin)
7. AS              → bind by request_uri (compare-and-set)
8. AS renders login, possibly federates to IdP
9. AS              → PUT  /admin/oauth2/auth/requests/login/accept
10. Hydra          → 302 to consent                            (UA → AS)
11. AS             → remembered-consent hit? accept silently : render UI
12. AS             → PUT /admin/oauth2/auth/requests/consent/accept (session.context_id)
13. Hydra          → 302 code=...&state=...                    (UA → Client)
14. Client         → POST /oauth/token                         (AS)
15. AS             → proxy to Hydra /oauth2/token
16. AS             → introspect, find context by context_id, consume, audience-check
17. AS             → 200 { access_token, id_token, refresh_token? }
```

## Appendix B — File:line verification anchors

- PAR push:                    `services/hydra_service.go → PushAuthorizationRequest`
- Compare-and-set PAR update:  `services/authorization_context_service.go → UpdateAuthRequestContextPAR`
- Deterministic bind:          `services/authorization_context_service.go → BindByHydraRequestURI`
- Scope resolution + wildcard: `services/scope_resolver.go → expandWildcards` (l.177+)
- Remembered consent upsert:   `services/consent_service.go → UpsertConsent`
- Token-exchange fail-closed:  `controllers/platform/oauth_as_controller.go → Token handler`
- Userinfo nil-safe claims:    `controllers/platform/oauth_as_controller.go → Userinfo, extractClaimBool`
- RP-Logout allowlist:         `controllers/platform/oauth_as_controller.go → EndSession`
- Refresh-grant resource check:`controllers/platform/oauth_as_controller.go → tokenRefreshGrant`

## Appendix C — Why these decisions

- **Wrap Hydra rather than replace it.** Hydra's cryptography, revocation, consent storage, and JWKS rotation are battle-tested. AuthSec's edge is identity, federation, RBAC, and MCP ergonomics — not token issuance.
- **PAR over custom URL param.** Eliminates proxy-stripping, enables deterministic binding, standards-compliant.
- **Compare-and-set everywhere.** At this layer, races are silent bugs that leak tokens. We refuse to use "last write wins" on anything auth-relevant.
- **One context row, one token exchange.** Replaying a code or reusing a bridge row is a security bug. The `consumed` flag + atomic update guarantees it.
- **Scope registry + RBAC resolution at consent time.** Clients don't know about users' roles. AS intersects requested scopes with subject RBAC at the one moment where we have both — consent accept — and Hydra stamps the result.
- **Remembered consent TTL 30 days.** Matches Auth0/Google defaults, balances UX with revocability.

— End of document. Keep this up to date as Phase 4+ lands.
