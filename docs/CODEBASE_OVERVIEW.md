# AuthSec — Codebase Overview

> A grounded, code-accurate description of what this repository is and what it does.
> For the aspirational/marketing description see [PLATFORM.md](PLATFORM.md). For the
> security findings from the code audit, see the audit notes (not this file).

---

## 1. What it is, in one paragraph

AuthSec is a **single Go binary** (`github.com/authsec-ai/authsec`) that provides
**identity and access management for both human users and AI agents**. It was built by
merging eight previously-separate microservices into one process that listens on a
single port (**7468**) and serves everything under the `/authsec/*` URL prefix. It speaks
a broad set of auth protocols (OAuth 2.0/2.1, OIDC, SCIM 2.0, WebAuthn/FIDO2, TOTP,
SMS/voice OTP, RFC 8628 device code, CIBA, SAML SP, SPIFFE/SVID) and adds AI-agent
features on top (workload identity, scoped delegation tokens, human-in-the-loop action
approval, and Model Context Protocol auth).

It is a **Gin** HTTP application backed by **PostgreSQL**, fronted by **Ory Hydra** as the
OAuth/OIDC protocol engine, with optional **Redis**, **HashiCorp Vault**, and **SPIRE**.

---

## 2. The big picture

```
            Browser / API client / CLI / AI agent / MCP tool
                              │
                              ▼  (reverse proxy / TLS terminates upstream)
            ┌─────────────────────────────────────────────────┐
            │           AuthSec monolith  (:7468)              │
            │           one Gin engine, /authsec/*             │
            │                                                  │
            │  uflow     auth, OIDC, SCIM, TOTP, CIBA, device  │
            │  webauthn  passkey / FIDO2 ceremonies            │
            │  clientms  OAuth client lifecycle                │
            │  hmgr      Hydra login/consent + SAML SP         │
            │  oocmgr    per-tenant OIDC/SAML provider config  │
            │  authmgr   token verify/generate + RBAC checks   │
            │  sdkmgr    MCP auth, playground, voice, devserver │
            │  spire     SPIFFE workload identity + cloud fed   │
            │  exsvc     external-service credential registry  │
            │  oauth/v2  standards-compliant OAuth 2.1 AS      │
            │  migration DB migration / tenant provisioning    │
            └─────────────────────────────────────────────────┘
                │            │            │            │
                ▼            ▼            ▼            ▼
          PostgreSQL     Ory Hydra      Redis        Vault / SPIRE
          (master +     (OAuth/OIDC   (cache,      (secrets, PKI,
           per-tenant     engine)      rate-limit,   workload SVIDs)
           databases)                  optional)     all optional
```

All former services are now **in-process function calls** — no network hops between
modules. They share one Gin engine, the PostgreSQL pool(s), and (when configured) one
Redis connection.

---

## 3. What it actually does (capabilities)

### Authenticate humans
- **Password login** for admins (`/uflow/auth/admin/*`) and end-users (`/uflow/auth/enduser/*`, `/uflow/user/*`), with bcrypt hashing, account lockout, and an optional nonce/timestamp/challenge anti-replay layer.
- **WebAuthn / passkeys** (`/authsec/webauthn/*`) — registration and authentication ceremonies for platform and roaming authenticators, plus "biometric" aliases.
- **TOTP** (`/uflow/auth/totp/*`), **SMS OTP** and **voice OTP** (Twilio), and a **voice-assistant linking** flow.
- **OIDC federation** (`/uflow/oidc/*`) — log in / register via Google, GitHub, Microsoft, or any OIDC provider; link/unlink external identities.
- **SAML SP** (`/authsec/hmgr/saml/*`) — accept assertions from corporate IdPs.
- **Device Authorization Grant** (RFC 8628, `/uflow/auth/device/*`) for CLIs / TVs / agents.
- **CIBA** (`/uflow/auth/ciba/*`) — backchannel push approval.

### Authenticate and govern AI agents
- **Agent registry** and **SPIFFE workload identity** issuance (`/uflow/admin/agents/*`, `/authsec/spire/*`, `/authsec/spiresvc/*`).
- **Scoped delegation tokens**: a human delegates a bounded subset of their permissions to an agent for a limited TTL, governed by **delegation policies** (`/uflow/delegation-policies`).
- **Human-in-the-loop action guard** (`/uflow/agent/actions/*`): an agent submits a sensitive action, it's scored against **risk policies**, and a human approves/denies before the agent proceeds.
- **MCP (Model Context Protocol) auth** (`/authsec/sdkmgr/mcp-auth/*`): adds OAuth + RBAC tool-gating to MCP tools, plus a chat **playground** (Azure OpenAI), a **dev server** for prototyping MCP servers, and connectors to external MCP servers.
- **Cloud federation** (`/authsec/spire/oidc/exchange/{aws,azure,gcp}`): intended to swap a SPIFFE SVID for cloud credentials *(currently stubbed)*.

### Authorize (RBAC)
- A scoped RBAC model: `User → RoleBinding → Role → Permission → Scope → Resource → ResourceMethod`.
- Middleware `Require(resource, action)`, `RequireAll`, `RequireAny`; an `admin` role short-circuits checks.
- A **policy-decision API** (`/authsec/authmgr/check/*`, `/validate/*`) external systems can query.
- A **parallel end-user RBAC** system (`/uflow/user/rbac/*`) separate from admin RBAC.

### Provision and integrate
- **SCIM 2.0** service provider (`/uflow/scim/v2/*`) for IdP-driven user/group provisioning.
- **Active Directory** and **Azure Entra** user sync (AES-encrypted sync configs).
- **HubSpot** contact sync; **Okta** CIBA delivery.
- **OAuth client management** (`/authsec/clientms/*`) and per-tenant **OIDC/SAML provider config** (`/authsec/oocmgr/*`), both backed by Hydra client metadata + Vault.

### Operate
- **Custom SQL migration runner** applied at startup (master migrations + per-tenant migrations + a "golden template" DB cloned for fast tenant creation).
- **Prometheus metrics** (`/authsec/metrics`), structured audit logging (90-day retention), health checks (`/uflow/health`).
- **Background workers**: audit cleanup (daily), metrics refresh (30s), PKI retry (5m), Hydra reconciler.

---

## 4. How a request flows

1. **Global middleware chain** (set in [cmd/main.go](../cmd/main.go)): metrics → CORS → request-ID → auth-logging → security headers → recovery → timeout → in-memory rate limit → gzip.
2. **Routing** ([routes/routes.go](../routes/routes.go)) — one 1,700-line file that registers every endpoint, grouped by former-service prefix. This file is the single source of truth for the API surface.
3. **Authentication** ([middlewares/auth.go](../middlewares/auth.go)) — `AuthMiddleware()` extracts a Bearer JWT, validates it (HMAC, tried against `JWT_SDK_SECRET` / `JWT_DEF_SECRET` / `JWT_SECRET`), checks issuer/expiry, and populates the Gin context with `tenant_id`, `user_id`, `email`, `roles`, `scopes`, `claims`, etc. Some routes use `SpiffeAuthMiddleware()` (accepts a JWT *or* a SPIFFE JWT-SVID).
4. **Authorization** — `Require("resource","action")` / `ValidateTenantFromToken()` run per route group.
5. **Controller** → **service** → **repository** → **database**. Controllers are thin; business logic lives in `services/`; SQL lives in `database/` (raw `database/sql`) and `internal/.../repo` (GORM).

---

## 5. Repository layout

| Path | Role |
|---|---|
| `cmd/main.go` | Entry point; 5-phase boot (config → DB/migrations → webauthn → router → workers → serve). |
| `routes/routes.go` | All HTTP route registration. Start here to find any endpoint. |
| `config/` | Env-driven config, DB init, Vault, WebAuthn setup, schema sync. |
| `middlewares/` | Auth, SPIFFE auth, CORS, security headers, rate limiting, tenant resolution, logging, audit. |
| `controllers/` | HTTP handlers, split by audience: `admin/`, `enduser/`, `platform/`, `sdkmgr/`, `shared/`. |
| `services/` | Business logic; `services/sdkmgr/` for the MCP subsystem. |
| `handlers/` | WebAuthn / TOTP / SMS ceremony handlers (from the former webauthn-service). |
| `database/` | Raw-SQL repositories + the multi-tenant connection manager + tenant DB service. |
| `internal/` | Cleaner-architecture packages: `spire/`, `migration/`, `session/`, `authmgr/`, `hydra/`, `clients/`, `oocmgr/`, `schemaaudit/`. |
| `models/` | Domain models incl. RBAC, auth requests, agent actions. |
| `monitoring/` | Prometheus metrics, audit logger, Redis cache manager. |
| `vault/` | Vault KV client. |
| `migrations/` | SQL files: `master/`, `tenant/`, `permissions/`. |
| `repository/` | GORM RBAC repositories. |

---

## 6. Data model (essentials)

- **Tenancy**: a **master database** holds platform-wide rows (`users`, `tenants`, `clients`, `projects`, `role_bindings`, `tenant_mappings`, `migration_logs`, `audit_logs`). Each tenant additionally gets **its own database** (`tenant_<uuid>`), created by cloning a pre-built template DB. Connections are resolved per-tenant at request time.
- **RBAC**: `roles`, `permissions`, `scopes`, `resources`, `resource_methods`, `user_roles` / `role_bindings`.
- **Auth/MFA**: `webauthn_credentials`, `totp_secrets`, `totp_backup_codes`, `device_codes`, `ciba_auth_requests`, `voice_sessions`, `voice_identity_links`, `device_tokens`.
- **OIDC/OAuth**: `oidc_providers`, `oidc_states`, `oidc_user_identities`, plus OAuth clients stored as **Hydra client metadata**, and `mcp_oauth_clients` / `resource_servers` for the v2 Application registry.
- **AI agent**: `delegation_policies`, `delegation_tokens`, `agent_actions`, `risk_policies`.
- **Conventions**: many time fields are Unix epoch seconds; TOTP seeds and AD/Entra sync configs are AES-encrypted at rest; some tables use `deleted_at` soft deletes; `scopes` / `device_info` / `profile_data` are JSONB.

---

## 7. Key external dependencies

| Dependency | Required? | Used for |
|---|---|---|
| **PostgreSQL** | Yes | All persistent state (master + per-tenant DBs). |
| **Ory Hydra** | Yes (for OAuth/OIDC flows) | OAuth2/OIDC protocol engine; AuthSec implements the login/consent callbacks and stores client config as Hydra metadata. |
| **Redis** | Optional | Cache, rate-limiter state, token revocation set. Falls back to in-memory / DB when absent. |
| **HashiCorp Vault** | Optional | OIDC provider secrets, PKI mounts. Falls back to env vars. |
| **SPIRE** | Optional | SPIFFE workload identity / SVID issuance for agents. |
| **Twilio** | Optional | SMS + voice OTP. |
| **Azure OpenAI** | Optional | MCP playground chat + voice assistant. |

Most secrets and integrations are **fail-soft**: if not configured, the related feature is disabled and the service still starts (the required floor is DB credentials + the JWT secrets).

---

## 8. Configuration (the floor)

Required to boot (see [config/config.go](../config/config.go)):
`DB_USER`, `DB_PASSWORD`, `JWT_SDK_SECRET`, `JWT_DEF_SECRET`, plus the WebAuthn trio
`WEBAUTHN_RP_NAME` / `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN`.

Common knobs: `PORT` (7468), `ENVIRONMENT`, `GIN_MODE`, `CORS_ALLOW_ORIGIN`,
`HYDRA_ADMIN_URL` / `HYDRA_PUBLIC_URL`, `REDIS_URL`, `VAULT_ADDR` / `VAULT_TOKEN`,
`SKIP_MIGRATIONS`, `TOTP_ENCRYPTION_KEY`, `SYNC_CONFIG_ENCRYPTION_KEY`,
`AUTHSEC_OAUTH_BASE_URL` (canonical issuer for the v2 OAuth surface).

---

## 9. Mental model for newcomers

- **It's a monolith pretending to be eight services.** Each `/authsec/<prefix>/*` group maps to a former microservice; the code is organized that way too. When you need to find something, map the URL prefix → the `register*Routes` function in `routes.go`.
- **There are two OAuth stacks.** The **legacy** stack (`oidc_controller`, `oocmgr`, `clientms`, `hmgr`) treats Hydra as a config store and largely takes tenant identifiers from request bodies. The **newer v2 stack** (`/authsec/oauth/v2/*`, `applications_v2`, `login_v2`) is the standards-compliant OAuth 2.1 AS and is where active development lives.
- **Tenancy is database-per-tenant**, resolved dynamically. Almost every data access needs a `tenant_id`, usually taken from the JWT.
- **Hydra owns the OAuth protocol; AuthSec owns the identity decisions.** AuthSec implements Hydra's login/consent/logout callbacks and makes all the "who is this user and what may they do" calls itself.
- **AI-agent identity is a first-class concern**, not a bolt-on: agents get SPIFFE identities, delegated tokens bounded by policy, and an approval workflow for risky actions.

---

*Generated from a full read of the codebase (main → routes → config → middleware →
controllers → services → internal/database/models). This file describes current behavior
as implemented, which in places differs from [PLATFORM.md](PLATFORM.md).*
