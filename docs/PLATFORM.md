# AuthSec Platform — Technical Overview

**Version:** 2.0.0 (monolith)
**Last updated:** May 2026

---

## Table of Contents

1. [What is AuthSec](#1-what-is-authsec)
2. [Architecture](#2-architecture)
3. [Services & Infrastructure](#3-services--infrastructure)
4. [Authentication Methods](#4-authentication-methods)
5. [Authorization & RBAC](#5-authorization--rbac)
6. [AI Agent Features](#6-ai-agent-features)
7. [Enterprise Integrations](#7-enterprise-integrations)
8. [API Surface](#8-api-surface)
9. [Data Model](#9-data-model)
10. [Security Mechanisms](#10-security-mechanisms)
11. [Configuration Reference](#11-configuration-reference)
12. [Background Workers](#12-background-workers)
13. [Improvement Opportunities](#13-improvement-opportunities)
14. [Proposed New Features](#14-proposed-new-features)

---

## 1. What is AuthSec

AuthSec is an open-source, self-hosted **identity and access management platform** designed for organizations that need to authenticate both human users and AI agents under a unified policy model.

It consolidates what was previously a distributed set of eight microservices into a **single Go binary** running on one port (7468). Everything — authentication, RBAC, OIDC federation, WebAuthn, TOTP, CIBA, SCIM provisioning, SPIFFE workload identity, AI agent delegation, and MCP protocol support — ships in one deployable unit.

### Design Goals

- **Single-tenant by default.** One organization, one admin, one PostgreSQL database. No operational complexity of managing per-tenant database clusters.
- **Protocol-complete.** Implements OAuth 2.0, OIDC, SCIM 2.0, FIDO2/WebAuthn, RFC 8628 (Device Code), CIBA, SAML SP, and SPIFFE/SVID — not partial implementations.
- **AI-native.** Built-in support for AI agent authentication, delegation, workload identity, and human-in-the-loop action approval. Not bolted on after the fact.
- **Self-hostable.** Runs entirely on-premise with Docker Compose. No cloud dependencies required.

---

## 2. Architecture

```
Browser / API Client / AI Agent
              │
              ▼
         ┌─────────┐
         │  Nginx  │  :80 / :443  (reverse proxy + TLS termination)
         └────┬────┘
              │
              ├── /                  ──► UI (React frontend :3000)
              ├── /authsec/*         ──► AuthSec backend (:7468)
              ├── /.well-known/*     ──► AuthSec backend (:7468)
              ├── /oauth2/*          ──► Hydra public API (:4444)
              └── /userinfo          ──► Hydra public API (:4444)

  ┌─────────────────────────────────────────────────────────┐
  │                 AuthSec Backend (:7468)                 │
  │                                                         │
  │  /authsec/uflow/*    auth, OIDC, TOTP, WebAuthn, SCIM  │
  │  /authsec/authmgr/*  RBAC, token validation             │
  │  /authsec/clientms/* OAuth client management            │
  │  /authsec/hmgr/*     Hydra login/consent proxy          │
  │  /authsec/oocmgr/*   OIDC provider configuration        │
  │  /authsec/sdkmgr/*   MCP auth, playground, voice        │
  │  /authsec/exsvc/*    external service registry          │
  │  /authsec/spire/*    SPIFFE workload identity           │
  │  /authsec/migration/*  DB migration management          │
  └─────────────────────────────────────────────────────────┘
              │
              ├── PostgreSQL :5432   (primary database)
              ├── Ory Hydra  :4445   (OAuth2/OIDC — admin API)
              ├── Redis      :6379   (session cache, token revocation)
              └── Vault      :8200   (secrets — OIDC provider credentials)
```

### Module Map

| URL Prefix | Module | Former Service |
|---|---|---|
| `/authsec/uflow/*` | User Flow | authsec-uflow |
| `/authsec/authmgr/*` | Auth Manager | authsec-auth-manager |
| `/authsec/clientms/*` | Client Microservice | authsec-clientms |
| `/authsec/hmgr/*` | Hydra Manager | authsec-hydra-manager |
| `/authsec/oocmgr/*` | OIDC Config Manager | authsec-oocmgr |
| `/authsec/sdkmgr/*` | SDK Manager | authsec-sdkmgr |
| `/authsec/exsvc/*` | External Services | authsec-exsvc |
| `/authsec/spire/*` | SPIRE Identity | authsec-spire |
| `/authsec/webauthn/*` | WebAuthn | authsec-webauthn |

All modules share a single Gin HTTP engine, a single PostgreSQL connection pool, and a single Redis connection. Internal calls between modules (e.g., Auth Manager checking tokens, Hydra Manager calling User Flow) are in-process function calls — no network hop, no serialization overhead.

---

## 3. Services & Infrastructure

### Ory Hydra
AuthSec uses Hydra as its OAuth2/OIDC protocol engine. Hydra handles:
- Authorization code + PKCE flow
- Token issuance and refresh
- Client credential management
- OIDC discovery and JWKS publication

AuthSec implements the Hydra login/consent/logout callback interface at `/authsec/hmgr/login`, `/authsec/hmgr/consent`, `/authsec/hmgr/logout`. All user identity decisions are made in AuthSec; Hydra only handles the protocol.

### PostgreSQL
All persistent state lives in one database (`kloudone_db` by default). AuthSec manages its own schema via a custom migration runner — 106 sequential SQL files applied at startup. No ORM migrations; raw SQL only.

### Redis
Used for:
- Token revocation blacklist (checked on every authenticated request)
- Rate limiter state (Redis-backed token bucket, falls back to in-memory)
- WebAuthn challenge sessions

### HashiCorp Vault
Used to store OIDC provider client secrets (Google, GitHub, Microsoft). Vault is optional — if a secret isn't in Vault, AuthSec falls back to the corresponding environment variable (`GOOGLE_CLIENT_SECRET`, etc.).

> In the default on-premise Docker Compose setup, Vault runs in dev mode (in-memory storage). Secrets are lost on container restart. Use environment variables as the primary storage mechanism unless you configure persistent Vault storage.

---

## 4. Authentication Methods

AuthSec supports 12 authentication methods out of the box.

### 4.1 Email + Password

Standard credential-based login with:
- Challenge/response mechanism to prevent replay attacks
- Failed attempt tracking per user in the database
- Account lockout after threshold breaches
- Nonce + timestamp + signature fields on login requests

**Routes:** `POST /authsec/uflow/auth/admin/login`, `POST /authsec/uflow/auth/enduser/login`

---

### 4.2 WebAuthn / Passkeys (FIDO2)

Full WebAuthn Level 2 implementation covering:
- Credential registration with attestation verification
- Authentication with sign count validation
- Backup eligibility and backup state flags (for passkey sync detection)
- Multi-device credential support
- Both platform authenticators (Touch ID, Windows Hello) and roaming authenticators (YubiKey, etc.)

**Routes:**
- Admin: `/authsec/webauthn/admin/beginRegistration`, `/finishRegistration`, `/beginAuthentication`, `/finishAuthentication`
- End-user: `/authsec/webauthn/enduser/*` (same pattern)
- Biometric alias: `/authsec/webauthn/biometric/verifyBegin`, `/verifyFinish`

**Configuration:**
```
WEBAUTHN_RP_NAME=Your App Name
WEBAUTHN_RP_ID=yourdomain.com        # hostname only, no protocol/port
WEBAUTHN_ORIGIN=https://yourdomain.com
WEBAUTHN_TIMEOUT=60000               # ceremony timeout in milliseconds
```

---

### 4.3 TOTP (Time-Based One-Time Password)

RFC 6238 TOTP compatible with Google Authenticator, Authy, and any standards-compliant app.

- AES-256 encryption of TOTP secrets at rest (key: `TOTP_ENCRYPTION_KEY`)
- Backup recovery codes (hashed, single-use)
- Multiple TOTP devices per user with a designated primary
- Registration confirmation requires successful code verification before activation

**Routes:** `/authsec/uflow/auth/totp/*`, `/authsec/webauthn/totp/*`

---

### 4.4 SMS OTP

One-time codes delivered via Twilio SMS.

```
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...
TWILIO_FROM_NUMBER=+15551234567
```

---

### 4.5 Voice OTP + Voice Assistant Integration

OTP delivery via Twilio voice call, plus a persistent linking mechanism for voice assistants.

Users can permanently link their account to a voice identity (Alexa, Google Assistant, Siri, or a custom provider). Once linked, the voice assistant can initiate auth flows and approve pending device codes — hands-free authentication.

**Models:** `VoiceSession`, `VoiceIdentityLink`
**Routes:** `/authsec/uflow/auth/voice/*`

---

### 4.6 OIDC Federation

Login via external identity providers using standard OIDC. Supported providers out of the box:
- Google
- GitHub
- Microsoft / Azure AD
- Any custom OIDC-compliant provider

Identity linking: users can link multiple external identities to a single AuthSec account and unlink them independently.

**Routes:** `/authsec/uflow/oidc/*`
**Models:** `OIDCProvider`, `OIDCState`, `OIDCUserIdentity`

---

### 4.7 OAuth2 / Authorization Code + PKCE

Full OAuth2 authorization code flow with mandatory PKCE enforcement via Hydra. Used for third-party application integration and the MCP playground.

**Routes:** `/oauth2/*` (Hydra, proxied through Nginx), `/authsec/hmgr/login`, `/authsec/hmgr/consent`

---

### 4.8 Device Authorization Grant (RFC 8628)

Authentication flow for input-constrained devices (smart TVs, CLIs, IoT devices, AI agents).

Flow:
1. Device requests a device code (`POST /authsec/uflow/auth/device/code`)
2. Device polls for a token (`POST /authsec/uflow/auth/device/token`)
3. User visits activation URL, logs in, enters user code
4. Device receives token on next poll

**Routes:** `/authsec/uflow/auth/device/*`
**Models:** `DeviceCode` with status: `pending → authorized → consumed` (or `denied` / `expired`)

---

### 4.9 CIBA (Client-Initiated Backchannel Authentication)

Push notification-based authentication without browser redirects. The authentication request originates from a backend service, not the user's browser.

Flow:
1. Service calls `POST /authsec/uflow/auth/ciba/initiate`
2. User receives a push notification to their registered device
3. User approves/denies
4. Service polls `POST /authsec/uflow/auth/ciba/token` for the result

Supports Okta CIBA integration for enterprise customers.

**Routes:** `/authsec/uflow/auth/ciba/*`
**Models:** `CIBAAuthRequest`, `DeviceToken`

---

### 4.10 SAML SP (Service Provider)

SAML 2.0 service provider support for enterprise SSO integration with corporate identity providers.

**Routes:**
- `/authsec/hmgr/saml/initiate/:provider`
- `/authsec/hmgr/saml/acs` (Assertion Consumer Service)
- `/authsec/hmgr/saml/metadata/:tenant_id/:client_id`

---

### 4.11 SPIFFE JWT-SVID

Cryptographic workload identity for AI agents and microservices. Agents authenticate using a JWT-SVID issued by SPIRE rather than a username/password.

The SPIFFE OIDC discovery endpoint (`/.well-known/openid-configuration`) and JWKS endpoint (`/.well-known/jwks.json`) allow any system that can validate JWTs to verify agent identity.

---

### 4.12 Hybrid (WebAuthn + Password)

Combined factor login where both a passkey and a password are required. For high-security scenarios where a single factor is insufficient.

**Route:** `POST /authsec/uflow/auth/admin/login-hybrid`

---

## 5. Authorization & RBAC

### Model

AuthSec implements a scoped RBAC model:

```
User → RoleBinding → Role → Permission → Scope → Resource → ResourceMethod
```

- **Role**: named collection of permissions (e.g., `admin`, `read-only`, `billing-manager`)
- **Permission**: atomic `resource.action` pair (e.g., `users.delete`, `clients.create`)
- **Scope**: logical grouping (e.g., `identity`, `billing`, `agents`)
- **Resource**: protected entity (e.g., `/authsec/uflow/admin/users`)
- **ResourceMethod**: HTTP method + path pattern pair

### Authorization Middleware

Two middleware functions are available for route protection:

```go
RequireAll(needs ...Need)   // all listed permissions must be satisfied
RequireAny(needs ...Need)   // any one permission is sufficient
```

Admin role short-circuits all permission checks — an admin token always passes.

### Policy Decision Endpoint

External systems can query AuthSec's authorization engine:

```
POST /authsec/authmgr/check/permission
POST /authsec/authmgr/check/role
POST /authsec/authmgr/check/oauth-scope
POST /authsec/authmgr/validate/token
POST /authsec/authmgr/validate/scope
POST /authsec/authmgr/validate/resource
```

### End-User RBAC

A parallel RBAC system exists for end-users (not just admins):

- `/authsec/uflow/user/rbac/roles`
- `/authsec/uflow/user/rbac/bindings`
- `/authsec/uflow/user/rbac/permissions`
- `/authsec/uflow/user/rbac/policy/check`

### Groups

Users can be organized into user-defined groups. Groups can be assigned roles, and group membership can be synced from Active Directory or Azure Entra.

---

## 6. AI Agent Features

This is the differentiating area of AuthSec. Identity management for AI agents is treated as a first-class concern, not an afterthought.

### 6.1 Agent Registry

Agents are registered as first-class entities with their own profiles, identity records, and permission sets.

**Routes:**
- `GET /authsec/uflow/admin/agents` — list agents
- `GET /authsec/uflow/admin/agents/:id` — get agent
- `POST /authsec/uflow/admin/agents/:id/provision-identity` — issue SPIFFE identity
- `DELETE /authsec/uflow/admin/agents/:id/revoke-identity` — revoke identity
- `POST /authsec/uflow/admin/agents/:id/delegate-token` — issue scoped delegation token
- `POST /authsec/uflow/admin/agents/:id/revoke-token` — revoke token

---

### 6.2 Delegation Policies

Define which human roles are permitted to delegate trust to which types of agents, with what permission scopes, and up to what token TTL.

A delegation policy answers the question: "Can a user with role X authorize an agent of type Y to perform actions in scope Z for up to T seconds?"

**Model:** `DelegationPolicy`
**Routes:** `/authsec/uflow/delegation-policies*`

---

### 6.3 SPIFFE Workload Identity

Agents receive cryptographic identities in the SPIFFE SVID format — short-lived, automatically rotated, verifiable without a network call.

The identity encodes:
- Trust domain (e.g., `spiffe://authsec.example.com`)
- Workload path (e.g., `/agent/billing-processor`)
- Key material for signing

Cloud federation endpoints allow agents to exchange a SPIFFE SVID for cloud-native credentials:
- `POST /authsec/spire/oidc/exchange/aws` → AWS STS AssumeRoleWithWebIdentity
- `POST /authsec/spire/oidc/exchange/azure` → Azure Managed Identity token
- `POST /authsec/spire/oidc/exchange/gcp` → GCP service account token
- `POST /authsec/spire/oidc/exchange/cloud` → generic cloud token exchange

---

### 6.4 Human-in-the-Loop (Agent Action Guard)

Before an AI agent performs a sensitive action (transfer funds, delete data, send email, call an API), it can be required to obtain explicit human approval.

Flow:
1. Agent calls `POST /authsec/uflow/agent/actions/evaluate` with action details
2. AuthSec evaluates the action against configured risk policies
3. If approval is required, a push notification is sent to a designated human reviewer
4. Human calls `POST /authsec/uflow/agent/actions/respond` to approve or deny
5. Agent polls `GET /authsec/uflow/agent/actions/status` and proceeds only on approval

**Risk Policies:**
- Configurable per action type, agent, scope, and time window
- `POST /authsec/uflow/admin/risk-policies` — CRUD risk policies
- `GET /authsec/uflow/admin/risk-policies/settings` — global settings
- `GET /authsec/uflow/admin/risk-policies/audit` — approval/denial audit log

**Models:** `AgentAction`, `RiskPolicy`

---

### 6.5 MCP (Model Context Protocol) Support

AuthSec implements the MCP auth specification, making it possible to add authentication and authorization to any MCP-compatible AI tool.

**Routes (`/authsec/sdkmgr/mcp-auth/*`):**
- `/start` — initiate MCP auth session
- `/authenticate` — authenticate session
- `/callback` — OAuth callback
- `/status` — session status
- `/logout` — end session
- `/tools/list` — list available (authorized) tools
- `/tools/call` — execute a tool with auth enforcement

**MCP Playground (`/authsec/sdkmgr/playground/*`):**
- Conversation management
- Chat streaming (Azure OpenAI backend)
- MCP server connection management
- Tool execution with live auth checks

---

### 6.6 External Service Registry

A credential vault for external services that agents need to access (databases, APIs, SaaS tools). Services are registered with credentials stored in Vault, and agents retrieve them using their SPIFFE identity.

This enables a pattern where an agent never has a hardcoded secret — it authenticates with its workload identity and receives scoped, audited credentials at runtime.

**Routes:** `/authsec/exsvc/services*`
**Dual auth:** accepts standard JWT or SPIFFE JWT-SVID

---

## 7. Enterprise Integrations

### Active Directory Sync

Bidirectional user sync from on-premise Active Directory. Sync configurations are stored AES-256 encrypted (`SYNC_CONFIG_ENCRYPTION_KEY`).

**Routes:**
- `POST /authsec/uflow/admin/ad/sync` — trigger sync
- `POST /authsec/uflow/admin/ad/test-connection` — verify connectivity
- `GET/POST/PUT/DELETE /authsec/uflow/admin/sync-configs/*` — CRUD sync config

---

### Azure Entra (formerly Azure AD) Sync

Same pattern as AD sync, targeting Azure Entra ID as the source directory.

**Routes:**
- `POST /authsec/uflow/admin/entra/sync`
- `POST /authsec/uflow/admin/entra/test-connection`

---

### SCIM 2.0 Provisioning

AuthSec acts as a SCIM 2.0 service provider. Any identity provider that supports SCIM (Okta, Azure AD, OneLogin, etc.) can provision users and groups into AuthSec automatically.

**Discovery (public):**
- `GET /authsec/scim/v2/ServiceProviderConfig`
- `GET /authsec/scim/v2/Schemas`
- `GET /authsec/scim/v2/ResourceTypes`

**User provisioning:**
- `GET/POST /authsec/scim/v2/Users`
- `GET/PUT/PATCH/DELETE /authsec/scim/v2/Users/:id`

**Group provisioning:**
- `GET/POST /authsec/scim/v2/Groups`
- `GET/PUT/PATCH/DELETE /authsec/scim/v2/Groups/:id`

Admin variants at `/authsec/scim/v2/admin/Users` and `/authsec/scim/v2/admin/Groups`.

---

### HubSpot

Contact sync from AuthSec user records to HubSpot CRM.

**Route:** `POST /authsec/uflow/hubspot/contacts/sync`
**Config:** `HUBSPOT_ACCESS_TOKEN`

---

### Okta CIBA

CIBA push notification delivery via Okta's infrastructure for organizations already using Okta for device management.

**Config:** `OKTA_DOMAIN`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`, `OKTA_ISSUER`, `OKTA_API_TOKEN`

---

### Twilio

SMS OTP and voice call OTP delivery.

**Config:** `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`

---

## 8. API Surface

### Route Prefixes

| Prefix | Purpose | Auth |
|---|---|---|
| `/authsec/uflow/auth/admin/*` | Admin authentication flows | Public (tokens returned here) |
| `/authsec/uflow/auth/enduser/*` | End-user authentication flows | Public |
| `/authsec/uflow/auth/device/*` | Device code grant | Public |
| `/authsec/uflow/auth/totp/*` | TOTP login and management | Mixed |
| `/authsec/uflow/auth/ciba/*` | CIBA flows | Mixed |
| `/authsec/uflow/auth/voice/*` | Voice OTP and assistant linking | Mixed |
| `/authsec/uflow/oidc/*` | OIDC federation | Mixed |
| `/authsec/uflow/admin/*` | Admin management API | JWT required |
| `/authsec/uflow/user/*` | End-user self-service | JWT required |
| `/authsec/uflow/agent/*` | Agent action approval | JWT required |
| `/authsec/uflow/delegation-policies*` | Delegation policy CRUD | JWT required |
| `/authsec/uflow/hubspot/*` | HubSpot sync | JWT required |
| `/authsec/uflow/health/*` | Health checks | Public |
| `/authsec/webauthn/*` | WebAuthn flows | Mixed |
| `/authsec/authmgr/*` | Token validation + RBAC checks | Mixed |
| `/authsec/clientms/*` | Hydra client lifecycle | JWT required |
| `/authsec/hmgr/*` | Hydra login/consent/SAML | Mixed |
| `/authsec/oocmgr/*` | OIDC provider configuration | JWT required |
| `/authsec/sdkmgr/*` | MCP auth, playground, voice | Mixed |
| `/authsec/exsvc/*` | External service registry | JWT or SPIFFE SVID |
| `/authsec/spire/*` | SPIFFE workload identity | Mixed |
| `/authsec/migration/*` | Database migration management | Public (should be restricted in prod) |
| `/authsec/scim/v2/*` | SCIM 2.0 provisioning | Bearer token |
| `/oauth2/*` | Hydra OAuth2 (proxied) | OAuth2 |
| `/.well-known/*` | OIDC discovery + JWKS | Public |
| `/authsec/metrics` | Prometheus metrics | Public (restrict in prod) |

### Key Well-Known Endpoints

| Endpoint | RFC | Purpose |
|---|---|---|
| `/.well-known/openid-configuration` | RFC 8414 | OIDC discovery |
| `/.well-known/jwks.json` | RFC 7517 | Public key set |
| `/authsec/oauth/.well-known/openid-configuration` | RFC 8414 | MCP OAuth discovery |
| `/authsec/oauth/.well-known/oauth-authorization-server` | RFC 8414 | MCP auth server metadata |

---

## 9. Data Model

### Core Tables

| Table | Purpose |
|---|---|
| `users` | Admin user accounts |
| `tenants` | Tenant records |
| `projects` | Project/client groupings |

### RBAC

| Table | Purpose |
|---|---|
| `roles` | Named roles |
| `permissions` | Atomic `resource.action` permissions |
| `scopes` | Authorization scopes |
| `resources` | Protected resources |
| `resource_methods` | HTTP method + path pattern |
| `user_roles` | User → role assignments |

### Authentication & MFA

| Table | Purpose |
|---|---|
| `webauthn_credentials` | FIDO2 credential metadata |
| `totp_secrets` | AES-256 encrypted TOTP seeds |
| `totp_backup_codes` | Hashed single-use recovery codes |
| `device_tokens` | Push notification device registrations |
| `ciba_auth_requests` | In-flight CIBA requests |
| `device_codes` | RFC 8628 device/user code pairs |
| `voice_sessions` | Active voice OTP sessions |
| `voice_identity_links` | Permanent voice assistant links |

### OIDC / OAuth2

| Table | Purpose |
|---|---|
| `oidc_providers` | External IdP configurations |
| `oidc_states` | Short-lived CSRF protection tokens |
| `oidc_user_identities` | Provider identity → AuthSec user mapping |

### AI Agent

| Table | Purpose |
|---|---|
| `delegation_policies` | Trust delegation rules |
| `delegation_tokens` | Issued delegation tokens |
| `agent_actions` | Human-in-the-loop action requests |
| `risk_policies` | Action approval policies |

### Directory & Admin

| Table | Purpose |
|---|---|
| `sync_configs` | AD/Entra sync config (AES-256 encrypted) |
| `admin_invites` | Pending admin invitations |
| `groups` | User-defined groups |
| `group_members` | Group membership |
| `tenant_domains` | Domain associations |
| `audit_logs` | Audit trail (auto-deleted after 90 days) |
| `migration_logs` | Migration execution history |

### Key Design Notes

- **Timestamps**: Most tables use Unix epoch (seconds) for time fields, not SQL `timestamp`.
- **Encryption at rest**: TOTP secrets (AES-256, `TOTP_ENCRYPTION_KEY`), sync configs (AES-256, `SYNC_CONFIG_ENCRYPTION_KEY`).
- **Soft deletes**: `deleted_at` column pattern used on select tables.
- **JSONB fields**: Used for `scopes`, `device_info`, `profile_data`, `allowed_permissions`.
- **106 master migrations**: Sequential SQL files applied at startup by the custom migration runner.

---

## 10. Security Mechanisms

### Token Security

- **Three JWT secret keys** (`JWT_DEF_SECRET`, `JWT_SECRET`, `JWT_SDK_SECRET`) — different keys for different token types (admin, SDK, SPIFFE delegate)
- **Issuer + audience validation** on every authenticated request (`AUTH_EXPECT_ISS`, `AUTH_EXPECT_AUD`)
- **Token blacklist** — revoked tokens written to Redis, checked on every request
- **Short-lived tokens** — OIDC state tokens, device codes, voice sessions all have hard TTLs

### Anti-Replay

- Challenge/response on admin login (nonce + timestamp + signature)
- PKCE enforcement on all OAuth2 flows (`OAUTH2_PKCE_ENFORCED=true`)
- OIDC state tokens are single-use and short-lived

### Rate Limiting

- Admin auth endpoints: **5 requests/minute** (strict)
- End-user auth endpoints: **10 requests/minute** (strict)
- General API: configurable via Mennonv algorithm (in-memory) or Redis-backed token bucket

### Encryption at Rest

| Data | Algorithm | Key |
|---|---|---|
| TOTP secrets | AES-256 | `TOTP_ENCRYPTION_KEY` |
| AD/Entra sync configs | AES-256 | `SYNC_CONFIG_ENCRYPTION_KEY` |
| OIDC provider secrets | Vault kv-v2 | `VAULT_TOKEN` |

### WebAuthn Security

- Attestation verification on registration
- Sign count validation on every authentication (detects credential cloning)
- Backup state flags to detect passkey sync across devices
- Origin binding — credentials are tied to `WEBAUTHN_ORIGIN`

### Network Security

- Postgres, Redis, Hydra admin port (4445) bound to `127.0.0.1` — not exposed to external network
- CORS validated against `CORS_ALLOW_ORIGIN` (supports wildcard patterns)
- Security headers middleware: `X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`

### Audit Logging

- Structured audit trail for all write operations
- Auto-cleanup after 90 days
- Queryable via `/authsec/uflow/admin/risk-policies/audit`

---

## 11. Configuration Reference

### Required

| Variable | Purpose |
|---|---|
| `DB_PASSWORD` | PostgreSQL password |
| `JWT_DEF_SECRET` | Default JWT signing key (32+ chars) |
| `JWT_SECRET` | Primary JWT signing key (32+ chars) |
| `JWT_SDK_SECRET` | SDK JWT signing key (32+ chars) |
| `TOTP_ENCRYPTION_KEY` | AES-256 key for TOTP secrets (64 hex chars) |
| `SYNC_CONFIG_ENCRYPTION_KEY` | AES-256 key for sync configs (32+ chars) |
| `SESSION_SECRET` | Session signing key (32+ chars) |
| `HYDRA_SECRETS_SYSTEM` | Hydra system secret (32+ chars) |
| `HYDRA_SECRETS_COOKIE` | Hydra cookie secret (32+ chars) |
| `WEBAUTHN_RP_ID` | Hostname only, no protocol/port |
| `WEBAUTHN_ORIGIN` | Full origin e.g. `https://yourdomain.com` |

### Deployment

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `7468` | HTTP listen port |
| `ENVIRONMENT` | `development` | `development` / `production` |
| `GIN_MODE` | `debug` | `debug` / `release` |
| `BASE_URL` | `http://localhost` | Public root URL |
| `REACT_APP_URL` | `http://localhost` | Frontend URL |
| `HYDRA_PUBLIC_URL` | `http://localhost:4444` | Hydra public URL (browser-accessible) |
| `CORS_ALLOW_ORIGIN` | `http://localhost` | Allowed CORS origins (comma-separated) |
| `REQUIRE_SERVER_AUTH` | `false` | Enforce inter-service JWT auth |
| `SKIP_MIGRATIONS` | `false` | Skip DB migrations at startup |

### Feature Flags (Optional)

| Variable | Purpose |
|---|---|
| `REDIS_URL` | Enable Redis-backed sessions + rate limiting |
| `VAULT_ADDR` / `VAULT_TOKEN` | Enable Vault for OIDC secret storage |
| `SMTP_HOST/PORT/USER/PASSWORD` | Enable email delivery |
| `TWILIO_*` | Enable SMS + voice OTP |
| `GOOGLE_CLIENT_SECRET` | Enable Google OIDC |
| `GITHUB_CLIENT_SECRET` | Enable GitHub OIDC |
| `MICROSOFT_CLIENT_SECRET` | Enable Microsoft OIDC |
| `OKTA_*` | Enable Okta CIBA |
| `HUBSPOT_ACCESS_TOKEN` | Enable HubSpot sync |
| `AZURE_OPENAI_*` | Enable MCP playground LLM |
| `SPIFFE_*` | Enable SPIFFE OIDC issuer |
| `ICP_SERVICE_URL` | Enable PKI/SPIRE provisioning |

---

## 12. Background Workers

Three goroutines start automatically in `cmd/main.go`:

### Audit Log Cleanup
- **Interval:** every 24 hours
- **Action:** deletes `audit_logs` rows older than 90 days
- **Purpose:** prevent unbounded table growth

### System Metrics Update
- **Interval:** every 30 seconds
- **Action:** updates Prometheus gauge metrics (active users, session count, etc.)
- **Purpose:** real-time observability

### PKI Retry Worker
- **Interval:** every 5 minutes
- **Action:** retries failed SPIFFE/PKI identity provisioning requests
- **Purpose:** recover from transient SPIRE unavailability without losing pending agent identity requests
- Falls back to HTTP ICP client if in-process SPIRE is unavailable

---

## 13. Improvement Opportunities

These are existing features that work but have notable gaps.

### 13.1 SAML Routes Lack Authentication (Security)

Dev-only SAML provider management routes at `/hmgr/dev/saml-providers` require no authentication. A comment in the code marks them for migration to `/hmgr/admin/saml-providers` with auth. Until fixed, these routes are a risk in any deployment where the backend is reachable.

**Fix:** Move to the admin route group with `AuthMiddlewareWithConfig()` applied.

---

### 13.2 JWT Keys Are Static — No Rotation

All three JWT secrets (`JWT_DEF_SECRET`, `JWT_SECRET`, `JWT_SDK_SECRET`) are environment variables with no rotation mechanism. Rotating them requires:
1. Taking a maintenance window
2. Restarting the service
3. Invalidating all active sessions

**Fix:** Add versioned key IDs (`kid` header in JWTs), a `/admin/keys/rotate` endpoint, and a configurable grace period during which both old and new keys are valid. No restart, no forced logout.

---

### 13.3 Rate Limiter Splits State Between Instances

When Redis is unavailable, the rate limiter falls back to in-memory state. In a multi-instance deployment, each instance has independent counters — a client can bypass the limit by round-robining between pods.

**Fix:** Make Redis a hard dependency for rate limiting in production mode, or expose a warning when running in-memory mode with multiple instances detected.

---

### 13.4 Audit Retention Is Hard-Coded

The 90-day retention window for audit logs is a constant in the cleanup worker. There's no way to adjust it without modifying the source code.

**Fix:** Add `AUDIT_LOG_RETENTION_DAYS=90` environment variable, default 90, read by the cleanup worker.

---

### 13.5 Account Lockout Threshold Is Hard-Coded

Failed login attempt tracking exists in the database, but the lockout threshold (number of attempts before lockout) and lockout duration appear to be hard-coded constants.

**Fix:** Make these configurable per environment (`MAX_FAILED_LOGINS=5`, `LOCKOUT_DURATION_MINUTES=15`) or, better, configurable per tenant through the admin UI.

---

### 13.6 Migration Endpoint Is Unauthenticated

`POST /authsec/migration/migrations/master/run` requires no authentication. In production, this allows any network-reachable party to trigger schema migrations.

**Fix:** Guard behind admin JWT authentication, or at minimum restrict to `127.0.0.1` in the Nginx config.

---

### 13.7 PKI Retry Worker Has No Dead Letter

The PKI retry worker retries failed provisioning requests every 5 minutes indefinitely. There's no max retry count, no alerting when something is permanently stuck, and no way to inspect the failed queue without querying the database directly.

**Fix:** Add a retry counter column to the provisioning table, a configurable `MAX_PKI_RETRIES` env var, and a failed-state endpoint at `/authsec/admin/pki/failed` to list and manually re-trigger stuck records.

---

### 13.8 Vault Dev Mode Silently Loses Secrets

Vault runs in dev mode (in-memory). Any OIDC provider secrets stored via the Vault UI are silently lost on container restart, causing OIDC login to break until secrets are re-entered. The env var fallback exists but isn't prominently documented.

**Fix (operational):** Document the fallback more clearly. Prefer env vars for on-premise deployments.
**Fix (architectural):** Default to env var storage for the open-source edition. Make Vault optional with explicit opt-in.

---

## 14. Proposed New Features

These are capabilities not yet present that would meaningfully extend the platform.

---

### 14.1 Passkey-First Login

**What:** Remove the password form from the primary login flow. User enters email, is immediately prompted for a passkey. No password field shown.

**Why:** The FIDO Alliance's 2024 data shows passkey authentication reduces phishing-related account takeovers to near zero. WebAuthn infrastructure is already fully implemented in AuthSec — this is a UX-layer change.

**Implementation sketch:**
- Add `POST /authsec/uflow/auth/admin/passkey-login/begin` (returns WebAuthn options)
- Add `POST /authsec/uflow/auth/admin/passkey-login/finish` (verifies assertion, returns JWT)
- Update UI to show passkey prompt as primary, password as "other options"
- Password login remains available but is de-emphasized

---

### 14.2 Magic Link / Passwordless Email

**What:** `POST /authsec/uflow/auth/magic-link` → email sent with a one-time link → click → receive JWT. No password, no app required.

**Why:** Large segment of users won't set up TOTP or a passkey but still need more security than a password alone. Magic links are phishing-resistant (single-use, short TTL, bound to email).

**Implementation sketch:**
- Generate a cryptographically random token, store hashed in a `magic_link_tokens` table with TTL
- Send via existing SMTP integration
- `GET /authsec/uflow/auth/magic-link/verify?token=...` validates, issues JWT, marks token consumed
- Rate-limit heavily: 3 per hour per email address

---

### 14.3 Admin Audit Dashboard API

**What:** A queryable REST API over the `audit_logs` table with filtering, pagination, and CSV export.

**Why:** Audit logs exist and have auto-retention, but there's no way to query them without direct database access. Enterprise customers and compliance frameworks (SOC 2, ISO 27001) require searchable audit trails.

**Endpoints:**
```
GET /authsec/uflow/admin/audit?user_id=&action=&resource=&from=&to=&page=&limit=
GET /authsec/uflow/admin/audit/export?format=csv&...  (same filters)
GET /authsec/uflow/admin/audit/stats?from=&to=        (aggregated counts)
```

---

### 14.4 Webhook Notifications

**What:** When key events occur in AuthSec, POST a configurable payload to an external URL.

**Why:** Enables integrations (SIEM, Slack, PagerDuty, custom workflows) without requiring polling or direct database access.

**Events to support:**
- `user.registered` — new user created
- `user.mfa_enrolled` — TOTP or passkey added
- `user.login.success` / `user.login.failure`
- `user.locked` — account locked after failed attempts
- `agent.action.approved` / `agent.action.denied`
- `admin.login` — any admin login (useful for alerting)
- `token.revoked`

**Implementation sketch:**
- `webhooks` table: `id, event_type, url, secret, is_active, created_at`
- Admin API: `POST/GET/DELETE /authsec/uflow/admin/webhooks`
- Async delivery via goroutine pool with retry (3 attempts, exponential backoff)
- HMAC-SHA256 signature on payload (`X-AuthSec-Signature` header) for receiver verification

---

### 14.5 Session Management API

**What:** Let users see all their active sessions and remotely terminate individual ones.

**Why:** Standard security feature — if a user sees an active session from an unrecognized device or location, they can revoke it without changing their password. The Redis token blacklist already supports revocation; what's missing is the session inventory layer.

**Endpoints:**
```
GET    /authsec/uflow/user/sessions            — list active sessions
DELETE /authsec/uflow/user/sessions/:id        — revoke one session
DELETE /authsec/uflow/user/sessions            — revoke all except current
```

**Implementation sketch:**
- `sessions` table: `id, user_id, token_jti, device_type, ip_address, user_agent, created_at, last_seen_at`
- On login: write session record
- On request: update `last_seen_at`
- On revocation: add `token_jti` to Redis blacklist, delete session record

---

### 14.6 Adaptive Risk Scoring on Login

**What:** Extend the existing risk policy engine (currently only used for agent actions) to standard human login flows. Step up to MFA when the risk score exceeds a configurable threshold.

**Risk signals:**
- New device (no prior `device_id` seen for this user)
- New geographic location (IP geolocation delta)
- Login at unusual hour (outside user's historical pattern)
- Multiple failed attempts in the session
- Compromised credential detection (HaveIBeenPwned API lookup on login)

**Flow:**
1. User submits password
2. AuthSec computes risk score from signals
3. If score > threshold → require TOTP, passkey, or CIBA push before issuing token
4. If score is critical → block login, trigger alert webhook

---

### 14.7 Email Domain Allow/Block List

**What:** Admin-configurable rules controlling which email domains can register.

**Why:** Common enterprise requirement — an organization wants to ensure only `@acme.com` addresses can register, and block disposable email services.

**Configuration (via admin API):**
```json
{
  "allowlist": ["acme.com", "contractor.acme.com"],
  "blocklist": ["mailinator.com", "guerrillamail.com"]
}
```

If `allowlist` is non-empty, only those domains are accepted. `blocklist` is always applied. Evaluated at registration time, invite time, and OIDC identity linking.

---

### 14.8 JWT Key Rotation Without Downtime

**What:** A `/admin/keys/rotate` endpoint that generates a new signing key, publishes it in the JWKS endpoint with a new `kid`, and continues accepting tokens signed with old keys for a configurable grace period.

**Why:** Currently any key rotation requires a deployment restart and invalidates all active tokens. For production systems, this is a significant operational burden.

**Implementation sketch:**
- `signing_keys` table: `id, kid, algorithm, public_key, private_key_encrypted, status (active/grace/retired), created_at, retired_at`
- `POST /authsec/admin/keys/rotate` — generates new key pair, sets old key to `grace`, new key to `active`
- JWT signing: always use the `active` key
- JWT verification: accept any key with status `active` or `grace`
- Grace period: configurable (`KEY_ROTATION_GRACE_HOURS=24`)
- Background worker: set `grace` keys to `retired` after grace period

---

### 14.9 OpenTelemetry Distributed Tracing

**What:** Emit OTLP traces from AuthSec so that a login flow, token validation, or agent action approval can be traced end-to-end across services.

**Why:** Prometheus metrics show *what* is slow or broken. Traces show *where* and *why*. The existing Gin middleware layer is the right insertion point.

**Implementation:**
- Add `go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin` middleware
- Instrument database calls with `go.opentelemetry.io/contrib/bridges/otelslog`
- Add `OTEL_EXPORTER_OTLP_ENDPOINT` env var (default empty = tracing disabled)
- Span names: `auth.login`, `auth.totp.verify`, `webauthn.authenticate`, `hydra.consent`, etc.

---

### 14.10 `authsec` CLI Admin Tool

**What:** A standalone CLI binary that wraps the AuthSec admin API for common operations.

**Why:** Most admin actions currently require crafting `curl` commands or using the UI. A CLI accelerates operations, scripting, and CI/CD integration.

**Commands:**
```bash
authsec health                          # check service health
authsec users list                      # list admin users
authsec users create --email --role     # create user
authsec sessions list --user-id         # list active sessions
authsec sessions revoke --token-jti     # revoke a token
authsec keys rotate                     # rotate JWT signing key (feature 14.8)
authsec migrations run                  # run pending migrations
authsec audit --from --to --action      # query audit log
authsec webhooks create --event --url   # register webhook
authsec agents list                     # list registered agents
authsec agents provision --id           # provision SPIFFE identity
```

Built with Cobra + Viper, reads `AUTHSEC_BASE_URL` and `AUTHSEC_ADMIN_TOKEN` from env or `~/.authsec/config.yaml`.
