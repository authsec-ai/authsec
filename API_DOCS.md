# AuthSec API Documentation

**Version:** 5.0.0  
**Base URL:** `https://<host>/authsec`  
**Default Port:** `7468`

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Authentication](#authentication)
4. [Rate Limiting](#rate-limiting)
5. [Common Response Formats](#common-response-formats)
6. [Environment Variables](#environment-variables)
7. [Routes Reference](#routes-reference)
   - [OIDC Discovery](#oidc-discovery)
   - [Admin Authentication](#admin-authentication)
   - [End-User Authentication](#end-user-authentication)
   - [Device Authorization (RFC 8628)](#device-authorization-rfc-8628)
   - [Voice Authentication](#voice-authentication)
   - [TOTP Authentication](#totp-authentication)
   - [Tenant TOTP](#tenant-totp)
   - [CIBA Authentication](#ciba-authentication)
   - [Tenant CIBA](#tenant-ciba)
   - [WebAuthn / FIDO2](#webauthn--fido2)
   - [Admin Management](#admin-management)
   - [RBAC (Admin)](#rbac-admin)
   - [RBAC (End-User)](#rbac-end-user)
   - [End-User Self-Service](#end-user-self-service)
   - [OIDC Federation](#oidc-federation)
   - [SCIM 2.0](#scim-20)
   - [Agent Action Guard](#agent-action-guard)
   - [Delegation Policies](#delegation-policies)
   - [AI Agent Management](#ai-agent-management)
   - [Client Management (clientms)](#client-management-clientms)
   - [Hydra Manager (hmgr)](#hydra-manager-hmgr)
   - [OIDC Config Manager (oocmgr)](#oidc-config-manager-oocmgr)
   - [Auth Manager (authmgr)](#auth-manager-authmgr)
   - [SDK Manager (sdkmgr)](#sdk-manager-sdkmgr)
   - [SPIRE Headless (spire)](#spire-headless-spire)
   - [SPIRE Identity Service (spiresvc)](#spire-identity-service-spiresvc)
   - [External Services (exsvc)](#external-services-exsvc)
   - [Migration API](#migration-api)
   - [HubSpot Integration](#hubspot-integration)
   - [Health Checks](#health-checks)
   - [Legacy Routes (uflow)](#legacy-routes-uflow)
   - [Purge Utility](#purge-utility)
   - [Metrics](#metrics)
8. [Data Models](#data-models)
9. [Unregistered Controller Methods (Not Active)](#unregistered-controller-methods-not-active)

---

## Overview

AuthSec is a unified authentication and identity platform delivered as a single Go monolith. It consolidates the following formerly-separate microservices:

| Former Service | Now Served Under |
|---|---|
| user-flow | `/authsec/uflow/*` |
| webauthn-service | `/authsec/webauthn/*` |
| clients-microservice | `/authsec/clientms/*` |
| hydra-service | `/authsec/hmgr/*` |
| oath_oidc_configuration_manager | `/authsec/oocmgr/*` |
| auth-manager | `/authsec/authmgr/*` |
| sdk-manager | `/authsec/sdkmgr/*` |
| spire-headless | `/authsec/spire/*` |
| authsec-spire | `/authsec/spiresvc/*` |
| external-service / mcp-service | `/authsec/exsvc/*` |
| authsec-migration | `/authsec/migration/*` |

A backward-compatibility alias exists at the bare root `/sdkmgr/*` for legacy SDK clients.

### Tenant to Workspace Migration Contract

AuthSec is currently in Phase 5 of the tenant to workspace migration. For
backend JSON, `workspace_id` is canonical. `tenant_id` is a deprecated
compatibility mirror and, when present, has the same value as `workspace_id`
until it is removed in Phase 8.

UI and SDK clients do not need an immediate Phase 5 change, but all clients
must migrate to `workspace_id` before Phase 8. Existing path names are not all
renamed during this phase; the legacy MFA URL families
`/authsec/uflow/auth/workspace/totp/*` and
`/authsec/uflow/auth/workspace/ciba/*` remain valid exceptions.

### Single-Tenant vs Multi-Tenant Mode

authsec operates in **single-tenant mode** by default — one admin, one master database. Multi-tenant support is provided by the **mt-plugin** gRPC microservice. When `MT_PLUGIN_GRPC_ADDR` is configured and mt-plugin is reachable, authsec enables multi-tenant admin registration and delegates tenant database management to mt-plugin.

| Mode | `MT_PLUGIN_GRPC_ADDR` | Second admin registration |
| --- | --- | --- |
| Single-tenant | Not set / unreachable | HTTP 409 Conflict |
| Multi-tenant | Set and reachable | Allowed; mt-plugin creates tenant DB |

---

## Architecture

```
Client → CORS/Rate-limit → Auth Middleware → Controller → config.DB (master)
                                                        ↘ mt-plugin (gRPC, optional)
```

**Key components:**

- **Gin** HTTP framework
- **PostgreSQL** master DB — admin users, tenants, audit log, all operations
- **mt-plugin** (optional) — separate gRPC service for multi-tenant DB management
- **Vault** (optional) — secret storage via `internal/vault`
- **Redis** (optional) — caching
- **SPIRE** — workload identity and JWT-SVIDs
- **Hydra** (Ory) — OAuth2/OIDC federation

---

## Authentication

Most routes require a **JWT Bearer token** issued by the auth-manager.

```
Authorization: Bearer <jwt>
```

Some routes also accept a **SPIFFE JWT-SVID** for service-to-service calls (dual-auth routes under `/exsvc/services`).

**Token claims include:** `sub` (user ID), `workspace_id`, deprecated mirror
`tenant_id`, `roles`, `permissions`, `scope`.

Routes explicitly marked **[Public]** require no authentication.

---

## Rate Limiting

| Context | Limit |
|---|---|
| Admin authentication routes | 5 requests / minute |
| End-user authentication routes | 10 requests / minute |
| All other routes | Global Mennanov rate limiter (configurable) |

---

## Common Response Formats

**Success (2xx)**

```json
{
  "message": "...",
  "data": { }
}
```

**Error (4xx / 5xx)**

```json
{
  "error": "error_code",
  "error_description": "Human-readable description",
  "message": "..."
}
```

All timestamps are **Unix epoch (seconds)** unless noted otherwise.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | HTTP listen port (default `7468`) |
| `DB_HOST` | Yes | PostgreSQL host |
| `DB_PORT` | Yes | PostgreSQL port |
| `DB_USER` | Yes | PostgreSQL user |
| `DB_PASSWORD` | Yes | PostgreSQL password |
| `DB_NAME` | Yes | Master database name |
| `DB_SSLMODE` | No | SSL mode (`disable`, `require`, etc.) |
| `MT_PLUGIN_GRPC_ADDR` | No | mt-plugin gRPC address (e.g. `localhost:7469`); omit for single-tenant mode |
| `WEBAUTHN_RP_NAME` | Yes | Relying party display name |
| `WEBAUTHN_RP_ID` | Yes | Relying party domain (e.g. `example.com`) |
| `WEBAUTHN_ORIGIN` | Yes | Allowed origin (e.g. `https://example.com`) |
| `CORS_ALLOW_ORIGIN` | No | Allowed CORS origins (comma-separated) |
| `REDIS_URL` | No | Redis connection string for optional cache |
| `VAULT_ADDR` | No | HashiCorp Vault address |
| `VAULT_TOKEN` | No | Vault auth token |
| `ICP_SERVICE_URL` | No | Internal PKI provisioning service URL |
| `SKIP_MIGRATIONS` | No | Set `true` to skip auto-migrations on startup |

---

## Routes Reference

### OIDC Discovery

Public OIDC well-known endpoints (RFC 8414).

| Method | Path | Description |
|---|---|---|
| GET | `/authsec/.well-known/openid-configuration` | OIDC provider metadata |
| GET | `/authsec/.well-known/jwks.json` | JSON Web Key Set |

---

### Admin Authentication

**Base:** `/authsec/uflow/auth/admin`  
**Rate limit:** 5 req/min  
**Auth:** [Public]

#### `GET /challenge`

Returns a server challenge for anti-replay protection.

**Response 200**
```json
{
  "challenge": "base64-encoded-challenge",
  "expires_at": 1713000000,
  "created_at": 1712999700
}
```

---

#### `POST /login/precheck`

Check whether an admin email exists and which next step to take.

**Request body**
```json
{
  "email": "admin@example.com",
  "current_domain": "example.com"
}
```

**Response 200**
```json
{
  "exists": true,
  "display_name": "Alice Smith",
  "tenant_domain": "example.com",
  "workspace_id": "uuid",
  "tenant_id": "uuid",
  "next_step": "login",
  "requires_password": true,
  "available_providers": ["google", "github"]
}
```
`workspace_id` is canonical. `tenant_id` is a deprecated mirror retained until Phase 8.
`next_step` values: `"login"` | `"bootstrap"` | `"register"`

---

#### `POST /login/bootstrap`

Create the first admin user and tenant (initial setup only).

**Request body**
```json
{
  "email": "admin@example.com",
  "password": "minimum10chars",
  "confirm_password": "minimum10chars",
  "tenant_domain": "example.com",
  "name": "Alice Smith"
}
```

**Response 200**
```json
{
  "message": "Bootstrap successful",
  "status": "pending_verification",
  "workspace_id": "uuid",
  "tenant_id": "uuid",
  "tenant_domain": "example.com",
  "user_id": "uuid"
}
```
`workspace_id` is canonical. `tenant_id` is a deprecated mirror retained until Phase 8.

---

#### `POST /login`

Authenticate an admin user with email and password.

**Request body**
```json
{
  "email": "admin@example.com",
  "password": "password123",
  "tenant_domain": "example.com",
  "nonce": "unique-nonce",
  "timestamp": 1713000000,
  "challenge": "challenge-from-GET-challenge",
  "signature": "hmac-signature"
}
```

**Response 200**
```json
{
  "token": "jwt-access-token",
  "message": "Login successful"
}
```

---

#### `POST /login-hybrid`

Login with hybrid flow (password + passkey/MFA).

**Request body** — same as `/login`

---

#### `POST /register`

Register a new admin user (requires invite or open registration).

**Request body**
```json
{
  "email": "admin@example.com",
  "password": "password123",
  "tenant_domain": "example.com",
  "name": "Alice Smith"
}
```

---

#### `POST /complete-registration`

Complete admin registration after email verification.

---

#### `POST /forgot-password`

Initiate admin password reset — sends OTP via email.

**Request body**
```json
{ "email": "admin@example.com" }
```

---

#### `POST /forgot-password/verify-otp`

Verify the OTP sent during password reset.

**Request body**
```json
{
  "email": "admin@example.com",
  "otp": "123456"
}
```

---

#### `POST /forgot-password/reset`

Set a new password after OTP verification.

**Request body**
```json
{
  "email": "admin@example.com",
  "otp": "123456",
  "new_password": "newpassword123"
}
```

---

### End-User Authentication

**Base:** `/authsec/uflow/auth/enduser`  
**Rate limit:** 10 req/min  
**Auth:** [Public]

| Method | Path | Description |
|---|---|---|
| GET | `/challenge` | Get anti-replay challenge |
| POST | `/initiate-registration` | Start end-user registration flow |
| POST | `/verify-otp` | Verify OTP and complete registration |
| POST | `/login/precheck` | Pre-check user existence before login |
| POST | `/webauthn-callback` | Complete WebAuthn login callback |
| POST | `/delegate-svid` | Delegate a SPIFFE JWT-SVID |

### Auth Notifications

**Base:** `/authsec/uflow/auth/notify`  
**Auth:** JWT + `ValidateTenantFromToken`

| Method | Path                     | Description                                        |
|--------|--------------------------|----------------------------------------------------|
| POST   | `/new-user-registration` | Notify tenant owner of a new end-user registration |

#### `POST /login/precheck`

**Request body**
```json
{
  "email": "user@example.com",
  "tenant_domain": "example.com"
}
```

---

### End-User Self-Service Login

**Base:** `/authsec/uflow/user`  
**Auth:** [Public] for login/register routes; JWT required for authenticated routes.

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/login` | Public | Email/password login |
| POST | `/login/status` | Public | Poll login status (async flows) |
| POST | `/saml/login` | Public | SAML SSO login |
| POST | `/register/initiate` | Public | Start registration |
| POST | `/register/complete` | Public | Complete registration |
| POST | `/register` | Public | Full registration (single step) |
| POST | `/forgot-password` | Public | Initiate password reset |
| POST | `/forgot-password/verify-otp` | Public | Verify reset OTP |
| POST | `/forgot-password/reset` | Public | Set new password |
| POST | `/oidc/login` | Public | OIDC-initiated login |
| POST | `/clients/register` | JWT | Register OAuth client |
| GET | `/clients` | JWT | List user's clients |
| GET | `/enduser/:tenant_id/:user_id` | JWT | Get end-user profile |
| PUT | `/enduser/:tenant_id/:user_id` | JWT | Update end-user profile |
| PUT | `/enduser/:tenant_id/:user_id/status` | JWT | Enable/disable user |
| POST | `/enduser/delete` | JWT | Delete end-user |
| DELETE | `/enduser/:tenant_id/:user_id` | JWT + `users:delete` | Delete end-user |
| POST | `/admin/change-password` | JWT | Admin changes user password |
| POST | `/admin/reset-password` | JWT | Admin resets user password |

---

### Device Authorization (RFC 8628)

**Base:** `/authsec/uflow/auth/device`

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/code` | Public | Request device and user code |
| POST | `/token` | Public | Poll for access token |
| GET | `/activate/info` | Public | Get activation page data |
| POST | `/verify` | Public | Verify user_code pre-login |
| POST | `/authorize` | JWT | Approve or deny device |
| POST | `/authorize-oidc` | Public | Authorize via OIDC code exchange |
| GET | `/activate` | Public | Activation page (HTML) |

#### `POST /code`

Initiate device authorization. The device displays `verification_uri` and `user_code` to the user.

**Request body**
```json
{
  "client_id": "your-client-id",
  "scope": "openid profile"
}
```

**Response 200**
```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://example.com/activate",
  "verification_uri_complete": "https://example.com/activate?user_code=WDJB-MJHT",
  "expires_in": 1800,
  "interval": 5
}
```

#### `POST /token`

Poll for access token (RFC 8628 §3.4).

**Request body**
```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "client_id": "your-client-id"
}
```

**Response — pending**
```json
{ "error": "authorization_pending", "error_description": "The user has not yet approved the request." }
```

**Response — success**
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "..."
}
```

#### `POST /authorize`

**Auth:** JWT required. Browser submits approval after user logs in.

**Request body**
```json
{
  "user_code": "WDJB-MJHT",
  "approve": true
}
```

---

### Voice Authentication

**Base:** `/authsec/uflow/auth/voice`

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/initiate` | Public | Start voice auth session, get spoken OTP |
| POST | `/verify` | Public | Submit spoken OTP |
| POST | `/token` | Public | Get token using spoken credentials |
| POST | `/link` | JWT | Link voice assistant to user account |
| POST | `/unlink` | JWT | Unlink voice assistant |
| GET | `/links` | JWT | List linked voice assistants |
| GET | `/device-pending` | JWT | Get pending device authorization codes |
| POST | `/device-approve` | JWT | Approve device code via voice |

#### `POST /initiate`

**Request body**
```json
{
  "client_id": "your-client-id",
  "voice_platform": "alexa",
  "voice_user_id": "amzn1.ask.account.xxx",
  "device_info": { "device_type": "Echo Dot" },
  "scopes": ["openid"]
}
```

**Response 200**
```json
{
  "session_token": "...",
  "voice_otp": "8532",
  "expires_in": 300,
  "message": "Please say the code: 8532"
}
```

#### `POST /verify`

**Request body**
```json
{
  "session_token": "...",
  "voice_otp": "8532",
  "voice_confirmation": true
}
```

**Response 200**
```json
{
  "success": true,
  "status": "verified",
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

#### `POST /link`

**Auth:** JWT  
**Request body**
```json
{
  "voice_platform": "alexa",
  "voice_user_id": "amzn1.ask.account.xxx",
  "voice_user_name": "Alice",
  "link_method": "browser_verification"
}
```

---

### TOTP Authentication

**Base:** `/authsec/uflow/auth/totp`

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/login` | Public | Login with TOTP code (no password) |
| POST | `/device-approve` | Public | Approve device code with TOTP |
| POST | `/register` | JWT | Register a new TOTP device |
| POST | `/confirm` | JWT | Confirm TOTP device after QR scan |
| POST | `/verify` | JWT | Verify TOTP code (MFA step) |
| GET | `/devices` | JWT | List registered TOTP devices |
| POST | `/device/delete` | JWT | Delete a TOTP device |
| POST | `/device/primary` | JWT | Set primary TOTP device |
| POST | `/backup/regenerate` | JWT | Regenerate backup codes |

#### `POST /login`

**Request body**
```json
{
  "email": "user@example.com",
  "totp_code": "123456"
}
```

#### `POST /register`

**Auth:** JWT  
**Request body**
```json
{
  "device_name": "My iPhone",
  "device_type": "google_auth"
}
```

**Response 200**
```json
{
  "success": true,
  "secret": "BASE32SECRET",
  "qr_code_url": "otpauth://totp/...",
  "device_id": "uuid",
  "backup_codes": ["code1", "code2", "..."],
  "message": "Scan QR code and confirm with a 6-digit code"
}
```

#### `POST /confirm`

**Request body**
```json
{
  "device_id": "uuid",
  "totp_code": "123456"
}
```

---

### Tenant TOTP

**Base:** `/authsec/uflow/auth/workspace/totp`

Same flow as Admin TOTP but scoped to a specific tenant via `client_id`. All authenticated routes require JWT + `ValidateTenantFromToken`.

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/login` | Public | Tenant user TOTP login |
| POST | `/register` | JWT+Tenant | Register TOTP device |
| POST | `/confirm` | JWT+Tenant | Confirm TOTP setup |
| GET | `/devices` | JWT+Tenant | List TOTP devices |
| POST | `/devices/delete` | JWT+Tenant | Delete TOTP device |
| POST | `/devices/primary` | JWT+Tenant | Set primary TOTP device |

#### `POST /login` — Tenant TOTP

**Request body**
```json
{
  "client_id": "tenant-client-id",
  "email": "user@tenant.com",
  "totp_code": "123456",
  "tenant_domain": "tenant.com"
}
```

---

### CIBA Authentication

Client-Initiated Backchannel Authentication (CIBA). Mobile push notification-based auth.

**Base:** `/authsec/uflow/auth/ciba`

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/initiate` | Public | Start CIBA flow (send push to user's device) |
| POST | `/token` | Public | Poll for access token |
| POST | `/respond` | JWT | User approves/denies via mobile |
| POST | `/register-device` | JWT | Register mobile device for push |
| GET | `/devices` | JWT | List registered push devices |
| DELETE | `/devices/:device_id` | JWT | Remove a push device |

#### `POST /initiate`

**Request body**
```json
{
  "login_hint": "user@example.com",
  "binding_message": "Login to My App",
  "client_id": "optional-client-id",
  "scopes": ["openid", "profile"]
}
```

**Response 200**
```json
{
  "auth_req_id": "1c266114-a1be-4252-8ad1-04986c5b9ac1",
  "expires_in": 120,
  "interval": 5
}
```

#### `POST /token`

**Request body**
```json
{
  "auth_req_id": "1c266114-a1be-4252-8ad1-04986c5b9ac1",
  "client_id": "optional-client-id"
}
```

**Possible errors:** `authorization_pending`, `access_denied`, `expired_token`, `user_not_found`, `no_device_registered`

#### `POST /respond`

**Auth:** JWT (mobile app)  
**Request body**
```json
{
  "auth_req_id": "1c266114-...",
  "approved": true,
  "biometric_verified": true
}
```

#### `POST /register-device`

**Auth:** JWT  
**Request body**
```json
{
  "device_token": "ExponentPushToken[xxx]",
  "platform": "ios",
  "device_name": "Alice's iPhone",
  "device_model": "iPhone 15",
  "app_version": "2.1.0",
  "os_version": "17.4"
}
```

---

### Tenant CIBA

**Base:** `/authsec/uflow/auth/workspace/ciba`

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/initiate` | Public | Start tenant CIBA flow |
| POST | `/token` | Public | Poll for token |
| POST | `/respond` | JWT+Tenant | Approve/deny via mobile |
| POST | `/register-device` | JWT+Tenant | Register push device |
| GET | `/requests` | JWT+Tenant | List CIBA requests |
| GET | `/devices` | JWT+Tenant | List push devices |
| DELETE | `/devices/:device_id` | JWT+Tenant | Delete push device |

#### `POST /initiate` — Tenant CIBA

**Request body**
```json
{
  "client_id": "tenant-client-id",
  "email": "user@tenant.com",
  "tenant_domain": "tenant.com",
  "binding_message": "Approve login",
  "scopes": ["openid"]
}
```

---

### WebAuthn / FIDO2

**Base:** `/authsec/webauthn`  
**Auth:** Handled by session-based WebAuthn challenge flow.

#### Admin WebAuthn — `/authsec/webauthn/admin`

| Method | Path | Description |
|---|---|---|
| POST | `/mfa/status` | Get MFA status for admin user |
| POST | `/mfa/loginStatus` | Get MFA status during login |
| GET | `/mfa/loginStatus` | Get MFA login status (GET) |
| POST | `/beginRegistration` | Begin passkey registration |
| POST | `/finishRegistration` | Complete passkey registration |
| POST | `/beginAuthentication` | Begin passkey authentication |
| POST | `/finishAuthentication` | Complete passkey authentication |

#### End-User WebAuthn — `/authsec/webauthn/enduser`

Same endpoints as admin but scoped to tenant-specific databases.

| Method | Path | Description |
|---|---|---|
| POST | `/mfa/status` | End-user MFA status |
| POST | `/mfa/loginStatus` | MFA login status |
| GET | `/mfa/loginStatus` | MFA login status (GET) |
| POST | `/beginRegistration` | Begin passkey registration |
| POST | `/finishRegistration` | Complete passkey registration |
| POST | `/beginAuthentication` | Begin passkey authentication |
| POST | `/finishAuthentication` | Complete passkey authentication |

#### Legacy Flat WebAuthn — `/authsec/webauthn`

| Method | Path | Description |
|---|---|---|
| POST | `/mfa/status` | MFA status |
| POST | `/mfa/loginStatus` | MFA login status |
| POST | `/beginRegistration` | Begin registration |
| POST | `/beginAuthRegistration` | Begin auth+registration |
| POST | `/finishRegistration` | Finish registration |
| POST | `/beginAuthentication` | Begin authentication |
| POST | `/finishAuthentication` | Finish authentication |
| POST | `/biometric/verifyBegin` | Begin biometric verify |
| POST | `/biometric/verifyFinish` | Finish biometric verify |
| POST | `/biometric/beginSetup` | Begin biometric setup |
| POST | `/biometric/confirmSetup` | Confirm biometric setup |
| POST | `/biometric/beginLoginSetup` | Begin biometric login setup |
| POST | `/biometric/confirmLoginSetup` | Confirm biometric login setup |
| POST | `/biometric/verifyLoginBegin` | Begin biometric login verify |
| POST | `/biometric/verifyLoginFinish` | Finish biometric login verify |
| POST | `/totp/beginLoginSetup` | Begin TOTP login setup (legacy) |
| POST | `/totp/beginSetup` | Begin TOTP setup |
| POST | `/totp/confirmLoginSetup` | Confirm TOTP login setup |
| POST | `/totp/confirmSetup` | Confirm TOTP setup |
| POST | `/totp/verifyLogin` | Verify TOTP during login |
| POST | `/totp/verify` | Verify TOTP |
| POST | `/sms/beginSetup` | Begin SMS setup |
| POST | `/sms/confirmSetup` | Confirm SMS setup |
| POST | `/sms/requestCode` | Request SMS code |
| POST | `/sms/verify` | Verify SMS code |

---

### Admin Management

**Base:** `/authsec/uflow/admin`  
**Auth:** JWT + `admin:access` + `ValidateTenantFromToken`

#### Tenant Management

| Method | Path | Description |
|---|---|---|
| GET | `/tenants` | List all tenants |
| POST | `/tenants` | Create a new tenant |
| PUT | `/tenants/:tenant_id` | Update tenant |
| DELETE | `/tenants/:tenant_id` | Delete tenant (requires `tenants:delete`) |
| GET | `/tenants/:tenant_id/users` | List users in a tenant |

#### Domain Management

**Base:** `/admin/tenants/:tenant_id/domains`

| Method | Path | Description |
|---|---|---|
| POST | `` | Add domain to tenant |
| GET | `` | List tenant domains |
| POST | `/:domain_id/verify` | Verify domain ownership |
| POST | `/:domain_id/set-primary` | Set primary domain |
| GET | `/:domain_id` | Get domain by ID |
| DELETE | `/:domain_id` | Remove domain |

#### Admin User Management

| Method | Path | Description |
|---|---|---|
| GET | `/users/list` | List admin users |
| POST | `/users/list` | List admin users (POST with filters) |
| DELETE | `/users/:user_id` | Delete admin user (requires `users:delete`) |
| DELETE | `/users/delete_all/:user_id` | Delete admin user + all data |
| POST | `/enduser/list` | List end-users by tenant |
| POST | `/users/active` | Toggle admin user active state |
| POST | `/enduser/active` | Toggle end-user active state |

#### Admin Invitations

| Method | Path | Description |
|---|---|---|
| POST | `/invite` | Invite a new admin |
| POST | `/invite/cancel` | Cancel a pending invite |
| POST | `/invite/resend` | Resend invite email |
| GET | `/invite/pending` | List pending invites |

#### Groups

| Method | Path | Description |
|---|---|---|
| POST | `/groups` | Create user-defined group |
| POST | `/groups/map` | Map groups to client |
| POST | `/groups/list` | List tenant groups |
| DELETE | `/groups/map` | Remove groups from client |
| GET | `/groups/:tenant_id` | Get user-defined groups |
| PUT | `/groups/:id` | Update group |
| DELETE | `/groups` | Delete groups |
| POST | `/groups/:tenant_id/users/bulk` | Add users to group |
| DELETE | `/groups/:tenant_id/users/bulk` | Remove users from group |

#### OIDC Provider Management (Admin)

| Method | Path | Description |
|---|---|---|
| GET | `/oidc/providers` | List all OIDC providers |
| PUT | `/oidc/providers/:provider` | Update OIDC provider config |

#### Projects

| Method | Path | Description |
|---|---|---|
| POST | `/projects` | Create project |
| GET | `/projects` | List projects |

#### Active Directory / Entra ID Sync

| Method | Path | Description |
|---|---|---|
| POST | `/ad/sync` | Sync AD users |
| POST | `/ad/test-connection` | Test AD connectivity |
| POST | `/ad/test-network` | Test network to AD |
| POST | `/ad/agent-sync` | Agent-based AD sync |
| POST | `/entra/sync` | Sync Entra ID users |
| POST | `/entra/test-connection` | Test Entra ID connection |
| POST | `/entra/check-permissions` | Check Entra ID permissions |
| POST | `/admin-users/ad/sync` | Sync AD admin users |
| POST | `/admin-users/entra/sync` | Sync Entra ID admin users |

#### Sync Configurations

| Method | Path | Description |
|---|---|---|
| POST | `/sync-configs/create` | Create sync config |
| POST | `/sync-configs/list` | List sync configs |
| POST | `/sync-configs/update` | Update sync config |
| POST | `/sync-configs/delete` | Delete sync config |

#### SCIM Token

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/admin/scim/generate-token` | JWT+Tenant | Generate SCIM bearer token |

---

### RBAC (Admin)

**Base:** `/authsec/uflow/admin`  
**Auth:** JWT + `admin:access` + `ValidateTenantFromToken`

#### Roles

| Method | Path | Description |
|---|---|---|
| POST | `/roles` | Create composite role |
| GET | `/roles` | List roles |
| GET | `/roles/:role_id` | Get role by ID |
| PUT | `/roles/:role_id` | Update role |
| DELETE | `/roles/:role_id` | Delete role |

#### Role Bindings

| Method | Path | Description |
|---|---|---|
| POST | `/bindings` | Assign role to user/resource (scoped) |
| GET | `/bindings` | List role bindings |

#### Permissions

| Method | Path | Description |
|---|---|---|
| POST | `/permissions` | Register atomic permission |
| GET | `/permissions` | List permissions |
| DELETE | `/permissions/:id` | Delete permission by ID |
| DELETE | `/permissions` | Delete permission by body |
| GET | `/permissions/resources` | Show available resources |

#### Scopes

| Method | Path | Description |
|---|---|---|
| GET | `/scopes` | List admin scopes |
| GET | `/scopes/mappings` | Get scope-resource mappings |
| POST | `/scopes` | Add scope |
| PUT | `/scopes/:scope_name` | Edit scope |
| DELETE | `/scopes/:scope_name` | Delete scope |

#### API Scopes

| Method | Path | Description |
|---|---|---|
| POST | `/api_scopes` | Create API scope |
| GET | `/api_scopes` | List API scopes |
| GET | `/api_scopes/:scope_id` | Get API scope |
| PUT | `/api_scopes/:scope_id` | Update API scope |
| DELETE | `/api_scopes/:scope_id` | Delete API scope |

#### Policy Check

| Method | Path | Description |
|---|---|---|
| POST | `/policy/check` | Policy Decision Point check (admin) |

---

### RBAC (End-User)

**Base:** `/authsec/uflow/user`  
**Auth:** JWT + `ValidateTenantFromToken`

| Method | Path | Description |
|---|---|---|
| POST | `/rbac/roles` | Create role |
| GET | `/rbac/roles` | List roles |
| PUT | `/rbac/roles/:role_id` | Update role |
| DELETE | `/rbac/roles/:role_id` | Delete role |
| POST | `/rbac/bindings` | Assign role binding |
| GET | `/rbac/bindings` | List role bindings |
| GET | `/rbac/permissions` | List permissions |
| POST | `/rbac/permissions` | Register permission |
| DELETE | `/rbac/permissions/:id` | Delete permission |
| DELETE | `/rbac/permissions` | Delete permission by body |
| GET | `/rbac/permissions/resources` | Show resources |
| POST | `/rbac/policy/check` | PDP check (end-user) |
| GET | `/permissions` | Get my permissions |
| GET | `/permissions/effective` | Get my effective permissions |
| GET | `/permissions/check` | Check specific permission |
| GET | `/scopes` | List user scopes |
| GET | `/scopes/mappings` | Get scope mappings |
| POST | `/scopes` | Add user scope |
| PUT | `/scopes/:scope_name` | Edit scope |
| DELETE | `/scopes/:scope_name` | Delete scope |
| POST | `/api_scopes` | Create API scope |
| GET | `/api_scopes` | List API scopes |
| GET | `/api_scopes/:scope_id` | Get API scope |
| PUT | `/api_scopes/:scope_id` | Update API scope |
| DELETE | `/api_scopes/:scope_id` | Delete API scope |
| POST | `/groups/users/add` | Add self to groups |
| POST | `/groups/users/remove` | Remove self from groups |
| GET | `/groups/users` | Get my groups |
| GET | `/groups/:tenant_id/:group_id/users` | Get group members |

---

### End-User Self-Service

**Base:** `/authsec/uflow/user` (authenticated section)  
**Auth:** JWT + `ValidateTenantFromToken`

| Method | Path | Description |
|---|---|---|
| POST | `/clients/register` | Register OAuth client |
| GET | `/clients` | Get user's clients |
| POST | `/clients/get` | Get clients (POST filter) |
| GET | `/enduser/list` | List end-users |
| POST | `/enduser/list` | List end-users (POST filter) |
| GET | `/enduser/databases` | Get tenant databases |
| PUT | `/enduser/:tenant_id/:user_id/status` | Update user status |
| POST | `/enduser/active` | Activate/deactivate end-user |
| DELETE | `/enduser/delete_all/:tenant_id/:user_id` | Delete user + all data |

---

### OIDC Federation

**Base:** `/authsec/uflow/oidc`

#### Public OIDC Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/providers` | Public | List available OIDC providers |
| POST | `/initiate` | Public | Initiate OIDC flow |
| POST | `/register/initiate` | Public | Initiate OIDC registration |
| POST | `/login/initiate` | Public | Initiate OIDC login |
| GET | `/callback` | Public | OIDC callback (redirect from IdP) |
| POST | `/exchange-code` | Public | Exchange authorization code for token |
| POST | `/complete-registration` | Public | Complete OIDC registration |
| GET | `/check-tenant` | Public | Check if tenant exists |
| POST | `/auth-url` | Public | Get OIDC authorization URL |

#### Authenticated OIDC Endpoints

**Auth:** JWT + `ValidateTenantFromToken`

| Method | Path | Description |
|---|---|---|
| POST | `/link` | Link OIDC identity to user account |
| GET | `/identities` | List linked OIDC identities |
| DELETE | `/unlink/:provider` | Unlink OIDC provider |

---

### SCIM 2.0

#### Discovery (Public)

**Base:** `/authsec/uflow/scim/v2`

| Method | Path | Description |
|---|---|---|
| GET | `/ServiceProviderConfig` | SCIM service provider config |
| GET | `/Schemas` | SCIM schemas |
| GET | `/ResourceTypes` | Supported resource types |

#### End-User Provisioning

**Base:** `/authsec/uflow/scim/v2/:client_id/:project_id`  
**Auth:** JWT + `ValidateTenantFromToken`

| Method | Path | Description |
|---|---|---|
| GET | `/Users` | List users |
| GET | `/Users/:id` | Get user |
| POST | `/Users` | Create user |
| PUT | `/Users/:id` | Replace user |
| PATCH | `/Users/:id` | Patch user |
| DELETE | `/Users/:id` | Delete user |
| GET | `/Groups` | List groups |
| GET | `/Groups/:id` | Get group |
| POST | `/Groups` | Create group |
| PUT | `/Groups/:id` | Replace group |
| PATCH | `/Groups/:id` | Patch group |
| DELETE | `/Groups/:id` | Delete group |

#### Admin SCIM Provisioning

**Base:** `/authsec/uflow/scim/v2/admin`  
**Auth:** JWT + `admin:access` + `ValidateTenantFromToken`

| Method | Path | Description |
|---|---|---|
| GET | `/Users` | List admin users |
| GET | `/Users/:id` | Get admin user |
| POST | `/Users` | Create admin user |
| PUT | `/Users/:id` | Replace admin user |
| PATCH | `/Users/:id` | Patch admin user |
| DELETE | `/Users/:id` | Delete admin user |

---

### Agent Action Guard

Human-in-the-loop approval system for AI agents.

#### Agent-Facing Endpoints

**Base:** `/authsec/uflow/agent/actions`  
**Auth:** JWT

| Method | Path | Description |
|---|---|---|
| POST | `/evaluate` | Evaluate an action against risk policies |
| GET | `/status` | Poll action approval status |
| POST | `/respond` | Submit approval/denial response |
| GET | `/pending` | Get pending actions awaiting approval |

#### Risk Policy Admin

**Base:** `/authsec/uflow/admin/risk-policies`  
**Auth:** JWT + `admin:access` + `ValidateTenantFromToken`

| Method | Path | Description |
|---|---|---|
| GET | `` | List risk policies |
| POST | `` | Create risk policy |
| PUT | `/:id` | Update risk policy |
| DELETE | `/:id` | Delete risk policy |

#### Agent Guard Settings

**Base:** `/authsec/uflow/admin/agent-guard`  
**Auth:** JWT + `admin:access`

| Method | Path | Description |
|---|---|---|
| GET | `/settings` | Get guard settings |
| PUT | `/settings` | Update guard settings |

#### Agent Audit Log

**Base:** `/authsec/uflow/admin/agent-audit`  
**Auth:** JWT + `admin:access`

| Method | Path | Description |
|---|---|---|
| GET | `` | Get agent action audit log |

---

### Delegation Policies

**Base:** `/authsec/uflow/delegation-policies`  
**Auth:** JWT + `admin:access` + `ValidateTenantFromToken`

| Method | Path | Description |
|---|---|---|
| POST | `` | Create delegation policy |
| GET | `` | List delegation policies |
| GET | `/:id` | Get delegation policy |
| PUT | `/:id` | Update delegation policy |
| DELETE | `/:id` | Delete delegation policy |

#### SDK Delegation Token (Public)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/authsec/uflow/sdk/delegation-token` | Public (client_id) | Get delegation token for SDK |

---

### AI Agent Management

**Base:** `/authsec/uflow/admin/agents`  
**Auth:** JWT + `admin:access` + `ValidateTenantFromToken`

| Method | Path | Description |
|---|---|---|
| GET | `` | List AI agents |
| GET | `/:id` | Get agent details |
| POST | `/:id/provision-identity` | Provision SPIFFE identity for agent |
| DELETE | `/:id/revoke-identity` | Revoke agent identity |
| POST | `/:id/delegate-token` | Issue delegation token for agent |
| POST | `/:id/revoke-token` | Revoke delegation token |

#### Admin Self-Introspection

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/authsec/uflow/admin/me/roles-permissions` | JWT+Admin | Get my roles and permissions |

---

### Client Management (clientms)

**Base:** `/authsec/clientms`  
**Auth:** JWT (all API routes)

#### Health

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | Public | Service health check |

#### Tenant Clients

**Base:** `/clientms/tenants/:tenantId/clients`

| Method | Path | Description |
|---|---|---|
| GET | `/getClients` | List clients for tenant |
| POST | `/getClients` | List clients with filters |
| GET | `/:id` | Get client by ID |
| GET | `/platform-selectors` | Get platform selector keys for UI |
| POST | `/create` | Register a new client |
| PUT | `/:id` | Update client (full replace) |
| PATCH | `/:id` | Edit client (partial update) |
| PATCH | `/:id/soft-delete` | Soft-delete client |
| DELETE | `/:id` | Hard-delete client |
| POST | `/delete-complete` | Delete client + all associated data |
| PATCH | `/:id/activate` | Activate client |
| PATCH | `/:id/deactivate` | Deactivate client |
| POST | `/set-status` | Set client status |

#### Admin Cross-Tenant

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/admin/clients/` | JWT + `clients:admin` | List all clients across tenants |

---

### Hydra Manager (hmgr)

**Base:** `/authsec/hmgr`

#### Public Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/login/page-data` | Public | Get login page data |
| POST | `/auth/initiate/:provider` | Public | Initiate OIDC auth with provider |
| POST | `/auth/callback` | Public | Handle OIDC callback |
| POST | `/auth/exchange-token` | Public | Exchange token |
| POST | `/pkce/store` | Public | Store PKCE verifier |
| POST | `/saml/initiate/:provider` | Public | Initiate SAML auth |
| POST | `/saml/acs` | Public | SAML ACS handler |
| POST | `/saml/acs/:tenant_id/:client_id` | Public | SAML ACS (client-specific) |
| GET | `/saml/metadata/:tenant_id/:client_id` | Public | SAML SP metadata |
| POST | `/saml/test-provider` | Public | Test SAML provider |
| GET | `/login` | Public | Login redirect |
| GET | `/consent` | Public | Consent handler |
| GET | `/health` | Public | Health check |
| GET | `/challenge` | Public | Login challenge |

#### Admin Endpoints

**Base:** `/hmgr/admin`  
**Auth:** JWT + `admin:manage`

| Method | Path | Description |
|---|---|---|
| GET | `/users` | List users |
| POST | `/users` | Create user |
| PUT | `/users/:id` | Update user |
| DELETE | `/users/:id` | Delete user |
| GET | `/tenants` | List tenants |
| POST | `/tenants` | Create tenant |
| PUT | `/tenants/:id` | Update tenant |
| DELETE | `/tenants/:id` | Delete tenant |
| GET | `/saml-providers` | List SAML providers |
| POST | `/saml-providers` | Create SAML provider |
| PUT | `/saml-providers/:id` | Update SAML provider |
| DELETE | `/saml-providers/:id` | Delete SAML provider |
| GET | `/roles` | List roles |
| POST | `/roles` | Create role |
| PUT | `/roles/:id` | Update role |
| DELETE | `/roles/:id` | Delete role |
| GET | `/permissions` | List permissions |
| POST | `/permissions` | Create permission |
| POST | `/users/:id/roles` | Assign role to user |
| DELETE | `/users/:id/roles/:role_id` | Remove role from user |
| GET | `/profile` | Get own profile |
| PUT | `/profile` | Update own profile |

---

### OIDC Config Manager (oocmgr)

**Base:** `/authsec/oocmgr`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | Public | Health check |
| POST | `/configure-complete-oidc` | — | Full OIDC configuration |
| POST | `/tenant/create-base-client` | — | Create base tenant client |
| POST | `/tenant/check-exists` | — | Check if tenant exists |
| POST | `/tenant/list-all` | — | List all tenants |
| POST | `/tenant/delete-complete` | — | Delete tenant + config |
| POST | `/tenant/update-complete` | — | Update tenant config |
| POST | `/tenant/login-page-data` | — | Get login page data |
| POST | `/config/edit` | — | Edit OIDC config |
| POST | `/oidc/add-provider` | — | Add OIDC provider to tenant |
| POST | `/oidc/get-config` | — | Get tenant OIDC config |
| POST | `/oidc/get-provider` | — | Get OIDC provider |
| POST | `/oidc/get-provider-secret` | — | Get provider secret |
| POST | `/oidc/update-provider` | — | Update OIDC provider |
| POST | `/oidc/delete-provider` | — | Delete OIDC provider |
| POST | `/oidc/templates` | — | Get provider templates |
| POST | `/oidc/validate` | — | Validate OIDC config |
| GET | `/oidc/show-auth-providers` | — | Show auth providers |
| POST | `/oidc/show-auth-providers` | — | Show auth providers (POST) |
| POST | `/oidc/raw-hydra-dump` | JWT | Dump raw Hydra data |
| POST | `/oidc/edit-client-auth-provider` | — | Edit client auth provider |
| POST | `/saml/add-provider` | — | Add SAML provider |
| POST | `/saml/list-providers` | — | List SAML providers |
| POST | `/saml/get-provider` | — | Get SAML provider |
| POST | `/saml/update-provider` | — | Update SAML provider |
| POST | `/saml/delete-provider` | — | Delete SAML provider |
| POST | `/saml/templates` | — | Get SAML templates |
| POST | `/hydra-clients/list` | — | List Hydra clients |
| POST | `/hydra-clients/get-by-tenant` | — | Get Hydra clients by tenant |
| POST | `/hydra-clients/sync` | — | Sync Hydra clients |
| POST | `/test/oidc-flow` | Public | Test OIDC flow |
| POST | `/stats/tenant` | — | Get tenant stats |
| POST | `/clients/getClients` | — | Get clients by tenant |

---

### Auth Manager (authmgr)

**Base:** `/authsec/authmgr`

#### Public Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/token/verify` | Verify JWT token |
| POST | `/token/generate` | Generate JWT token |
| POST | `/token/oidc` | Generate OIDC token |

#### `POST /token/generate`

**Request body**
```json
{
  "user_id": "uuid",
  "tenant_id": "uuid",
  "roles": ["admin"],
  "permissions": ["users:read"],
  "scopes": ["openid"]
}
```

**Response 200**
```json
{
  "token": "eyJ...",
  "expires_in": 3600
}
```

#### Admin Endpoints

**Base:** `/authmgr/admin`  
**Auth:** JWT

| Method | Path | Description |
|---|---|---|
| GET | `/profile` | Get user profile from token |
| GET | `/auth-status` | Get authentication status |
| GET | `/validate/token` | Validate token |
| GET | `/validate/scope` | Validate scope |
| GET | `/validate/resource` | Validate resource access |
| POST | `/validate/permissions` | Validate permissions |
| GET | `/check/permission` | Check specific permission |
| GET | `/check/role` | Check if user has role |
| GET | `/check/role-resource` | Check role on resource |
| GET | `/check/permission-scoped` | Check scoped permission |
| GET | `/check/oauth-scope` | Check OAuth scope |
| GET | `/permissions` | List user permissions |
| POST | `/groups` | Create group |
| GET | `/groups` | List groups |
| GET | `/groups/:id` | Get group |
| PUT | `/groups/:id` | Update group |
| DELETE | `/groups/:id` | Delete group |
| POST | `/groups/:id/users` | Add users to group |
| DELETE | `/groups/:id/users` | Remove users from group |
| GET | `/groups/:id/users` | List group users |

---

### SDK Manager (sdkmgr)

**Base:** `/authsec/sdkmgr` (also aliased at `/sdkmgr` for backward compatibility)

#### MCP Auth

**Base:** `/sdkmgr/mcp-auth`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | Public | Health check |
| POST | `/start` | Public | Start MCP auth session |
| POST | `/authenticate` | Public | Authenticate with MCP |
| POST | `/callback` | Public | Auth callback (JSON) |
| GET | `/callback` | Public | Auth callback (HTML) |
| GET | `/status/:session_id` | Public | Get session status |
| GET | `/sessions/status` | Public | Get all sessions status |
| POST | `/logout` | Public | Logout |
| POST | `/tools/list` | Public | List available MCP tools |
| POST | `/tools/call/:tool_name` | Public | Call an MCP tool |
| POST | `/protect-tool` | Public | Protect a tool with auth |
| POST | `/cleanup-sessions` | Public | Cleanup expired sessions |

#### Services

**Base:** `/sdkmgr/services`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | Public | Health check |
| POST | `/credentials` | Public | Get service credentials |
| POST | `/user-details` | Public | Get user details |

#### SPIRE Proxy

**Base:** `/sdkmgr/spire`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | Public | Health check |
| POST | `/workload/initialize` | Public | Initialize workload identity |
| POST | `/workload/renew` | Public | Renew workload certificate |
| POST | `/workload/status` | Public | Get workload status |
| GET | `/validate-agent-connection` | Public | Validate SPIRE agent connection |

#### Dashboard

**Base:** `/sdkmgr/dashboard`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | Public | Health check |
| POST | `/sessions` | Public | Get sessions |
| POST | `/statistics` | JWT | Get statistics |
| POST | `/users` | Public | Get users |
| POST | `/admin-users` | JWT | Get admin users |

#### MCP OAuth

**Base:** `/sdkmgr/playground/oauth`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/check-requirements` | Public | Check OAuth requirements |
| GET | `/authorize` | Public | Authorize OAuth flow |
| GET | `/callback` | Public | OAuth callback |
| POST | `/refresh` | Public | Refresh OAuth token |

#### MCP Playground

**Base:** `/sdkmgr/playground`

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | Public | Health check |
| POST | `/conversations` | Public | Create conversation |
| GET | `/conversations` | Public | List conversations |
| GET | `/conversations/:id` | Public | Get conversation |
| PATCH | `/conversations/:id` | Public | Update conversation |
| DELETE | `/conversations/:id` | Public | Delete conversation |
| GET | `/conversations/:id/messages` | Public | Get conversation messages |
| POST | `/conversations/:id/chat` | Public | Send chat message |
| POST | `/chat/stream` | Public | Stream chat response |
| POST | `/conversations/:id/mcp-servers` | Public | Add MCP server |
| GET | `/conversations/:id/mcp-servers` | Public | List MCP servers |
| POST | `/conversations/:id/mcp-servers/:sid/disconnect` | Public | Disconnect MCP server |
| POST | `/conversations/:id/mcp-servers/:sid/reconnect` | Public | Reconnect MCP server |
| DELETE | `/conversations/:id/mcp-servers/:sid` | Public | Remove MCP server |
| GET | `/conversations/:id/mcp-servers/:sid/tools` | Public | Get MCP server tools |
| GET | `/conversations/:id/tools` | Public | Get all conversation tools |

#### Voice Client

**Base:** `/sdkmgr/voice`

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/interact` | Public | Voice interaction |
| POST | `/poll` | Public | Poll voice response |
| POST | `/tts` | Public | Text-to-speech |

#### Dev Server

**Base:** `/sdkmgr/playground/dev-server`  
**Auth:** JWT

| Method | Path | Description |
|---|---|---|
| POST | `/start` | Start dev server |
| POST | `/stop` | Stop dev server |
| GET | `/status` | Get dev server status |

---

### SPIRE Headless (spire)

**Base:** `/authsec/spire`

#### Discovery (Public)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| GET | `/.well-known/jwks.json` | JWKS endpoint |

#### Workload Registry

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/registry/workloads` | — | Register workload |
| PUT | `/registry/workloads/:id` | — | Update workload |
| DELETE | `/registry/workloads/:id` | — | Delete workload |
| GET | `/registry/workloads` | — | List workloads |

#### OIDC Token Operations

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/oidc/token` | — | Exchange OIDC token |
| POST | `/oidc/introspect` | — | Introspect token |
| POST | `/oidc/revoke` | — | Revoke token |
| POST | `/oidc/exchange/spiffe` | — | Exchange for SPIFFE token |
| POST | `/oidc/issue/jwt-svid` | — | Issue JWT-SVID |
| POST | `/oidc/exchange/cloud` | — | Exchange for cloud token |
| POST | `/oidc/exchange/aws` | — | Exchange for AWS credentials |
| POST | `/oidc/exchange/azure` | — | Exchange for Azure credentials |
| POST | `/oidc/exchange/gcp` | — | Exchange for GCP credentials |

#### Policy Engine

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/policy` | — | Create policy |
| GET | `/policy` | — | List policies |
| GET | `/policy/:id` | — | Get policy |
| PUT | `/policy/:id` | — | Update policy |
| DELETE | `/policy/:id` | — | Delete policy |
| POST | `/policy/evaluate` | — | Evaluate policy |
| POST | `/policy/batch-evaluate` | — | Batch evaluate policies |
| POST | `/policy/test` | — | Test policy |

#### Role Bindings

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/roles/bind` | — | Bind role |
| POST | `/roles/unbind` | — | Unbind role |
| GET | `/roles/bindings` | — | List role bindings |

#### Audit

| Method | Path | Description |
|---|---|---|
| GET | `/audit/logs` | Get audit logs |
| GET | `/audit/logs/export` | Export audit logs |

---

### SPIRE Identity Service (spiresvc)

**Base:** `/authsec/spiresvc`  
Available only when SPIRE is bootstrapped successfully at startup (requires master DB).

#### Public / Bootstrap Endpoints

Rate-limited. No authentication required — the node attests itself during bootstrap.

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/v1/node/attest` | Node attestation (bootstrap rate-limited) |
| POST | `/v1/agent/renew` | Renew agent certificate (bootstrap rate-limited) |
| GET | `/bundle/:tenant` | Get trust bundle for a tenant |
| GET | `/v1/jwt/bundle` | Get JWT signing bundle |
| POST | `/v1/jwt/validate` | Validate a JWT-SVID (sensitive rate-limited) |
| POST | `/v1/jwt/renew` | Renew a JWT-SVID (sensitive rate-limited) |
| POST | `/admin/pki/provision` | Provision PKI for default tenant (sensitive rate-limited) |
| POST | `/admin/pki/provision/:tenant_id` | Provision PKI for specific tenant (sensitive rate-limited) |

#### Agent-Certificate Protected (`/v1`)

Requires a valid agent mTLS certificate.

| Method | Path | Description |
|---|---|---|
| GET | `/v1/entries/by-parent` | List workload entries by parent SPIFFE ID |
| POST | `/v1/workload/attest` | Attest a workload and receive SVID |
| POST | `/v1/workload/revoke` | Revoke a workload SVID |

#### JWT Protected (`/v1`)

**Auth:** JWT (standard auth-manager token)

| Method | Path | Description |
|---|---|---|
| GET | `/v1/agents` | List registered SPIRE agents |
| POST | `/v1/entries` | Create workload entry |
| GET | `/v1/entries` | List workload entries |
| GET | `/v1/entries/:id` | Get workload entry by ID |
| PUT | `/v1/entries/:id` | Update workload entry |
| DELETE | `/v1/entries/:id` | Delete workload entry |
| POST | `/v1/entries/agent` | Create agent-level workload entry |
| POST | `/v1/jwt/issue-delegated` | Issue delegated JWT-SVID on behalf of user |

#### mTLS Protected (`/v1`)

**Auth:** Mutual TLS — service-to-service only.

| Method | Path | Description |
|---|---|---|
| POST | `/v1/attest` | Attest workload identity (mTLS) |
| POST | `/v1/renew` | Renew X.509-SVID certificate |
| POST | `/v1/revoke` | Revoke X.509-SVID |
| POST | `/v1/jwt/issue` | Issue JWT-SVID for attested workload |

---

### External Services (exsvc)

**Base:** `/authsec/exsvc`

Manages service-to-service authentication credentials.

#### Debug (authenticated)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | Public | Health check |
| GET | `/debug/auth` | JWT | Debug auth headers |
| GET | `/debug/test` | JWT | Auth test |
| GET | `/debug/token` | JWT | Inspect token claims |

#### Service Registry

**Base:** `/exsvc/services`  
**Auth:** SPIFFE JWT-SVID or standard JWT (dual-auth)

| Method | Path | Permission | Description |
|---|---|---|---|
| POST | `` | `external-service:create` | Register external service |
| GET | `` | `external-service:read` | List external services |
| GET | `/:id` | `external-service:read` | Get external service |
| PUT | `/:id` | `external-service:update` | Update external service |
| DELETE | `/:id` | `external-service:delete` | Delete external service |
| GET | `/:id/credentials` | `external-service:credentials` | Get service credentials |

---

### Migration API

**Base:** `/authsec/migration`  
**Auth:** JWT

#### Master Migrations

| Method | Path | Description |
|---|---|---|
| POST | `/migrations/master/run` | Run master database migrations |
| GET | `/migrations/master/status` | Get master migration status |

#### Tenant Migrations

| Method | Path | Description |
|---|---|---|
| GET | `/tenants` | List tenants |
| POST | `/tenants/create-db` | Create tenant database |
| POST | `/tenants/create-from-template` | Create tenant from template (fast clone) |
| GET | `/tenants/template-status` | Check template readiness |
| POST | `/tenants/migrate-all` | Run migrations on all tenant DBs |
| POST | `/tenants/:tenant_id/migrations/run` | Run migrations for specific tenant |
| GET | `/tenants/:tenant_id/migrations/status` | Get tenant migration status |

---

### HubSpot Integration

**Base:** `/authsec/uflow/hubspot`  
**Auth:** JWT + `ValidateTenantFromToken`

| Method | Path | Description |
|---|---|---|
| POST | `/contacts/sync` | Sync user as HubSpot contact |

---

### Health Checks

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/authsec/uflow/health` | Public | Comprehensive system health |
| GET | `/authsec/uflow/health/tenant/:tenant_id` | Public | Single tenant DB health |
| GET | `/authsec/uflow/health/tenants` | Public | All tenant DBs health |
| GET | `/authsec/webauthn/health` | Public | WebAuthn service health |
| GET | `/authsec/clientms/health` | Public | Client management health |
| GET | `/authsec/hmgr/health` | Public | Hydra manager health |
| GET | `/authsec/oocmgr/health` | Public | OIDC config manager health |
| GET | `/authsec/authmgr/health` | Public | Auth manager health |
| GET | `/authsec/sdkmgr/mcp-auth/health` | Public | MCP auth health |
| GET | `/authsec/sdkmgr/services/health` | Public | Services health |
| GET | `/authsec/sdkmgr/spire/health` | Public | SPIRE proxy health |
| GET | `/authsec/sdkmgr/dashboard/health` | Public | Dashboard health |
| GET | `/authsec/sdkmgr/playground/health` | Public | Playground health |
| GET | `/authsec/spire/health` | Public | SPIRE headless health |
| GET | `/authsec/exsvc/health` | Public | External services health |

---

### Metrics

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/authsec/metrics` | Public | Prometheus metrics scrape endpoint |

---

### Legacy Routes (uflow)

These legacy routes exist at the top level of `/authsec/uflow` for backward compatibility with older clients. They duplicate functionality available under the structured `/auth/*` paths.

**Base:** `/authsec/uflow`  
**Auth:** [Public]

| Method | Path                        | Description                              |
|--------|-----------------------------|------------------------------------------|
| POST   | `/login`                    | Legacy admin/user login                  |
| POST   | `/login/webauthn-callback`  | Legacy WebAuthn login callback           |
| POST   | `/register/verify`          | Legacy OTP verification + registration   |

---

### Purge Utility

> **Warning:** This endpoint is intentionally unauthenticated. It is a dev/ops utility and **must be removed or gated behind a proper permission before production**.

**Base:** `/authsec/admin/purge`

| Method | Path    | Auth   | Description                                                    |
|--------|---------|--------|----------------------------------------------------------------|
| DELETE | `/user` | Public | Completely purge a user and all associated data by email       |

What is purged (in order):

1. Hydra OAuth clients linked to the tenant
2. Vault PKI secrets engine mount for tenant domain
3. Vault KV secrets under tenant path
4. Tenant database (`DROP DATABASE`)
5. Master DB rows: `tenant_hydra_clients`, `tenant_mappings`, `clients`, `projects`, `role_bindings`, `users`, `tenants`, `pending_registrations`

Request body:
```json
{ "email": "user@example.com" }
```

Response 200:
```json
{
  "email": "user@example.com",
  "steps": ["found user=... tenant=... db=...", "deleted hydra client ...", "..."],
  "errors": [],
  "success": true,
  "purged_at": "2026-04-21T12:00:00Z"
}
```

Response is `206 Partial Content` if some steps failed, `500` if the initial lookup failed.

---

## Data Models

### AdminLoginInput
```json
{
  "email": "string (required, email)",
  "password": "string (required, min 10 chars)",
  "tenant_domain": "string (optional)",
  "nonce": "string (optional)",
  "timestamp": "int64 (unix epoch, optional)",
  "challenge": "string (optional)",
  "signature": "string (optional)"
}
```

### AuthChallenge
```json
{
  "challenge": "string",
  "expires_at": "int64 (unix epoch)",
  "created_at": "int64 (unix epoch)"
}
```

### CIBAInitiateRequest
```json
{
  "login_hint": "string (required, user email)",
  "binding_message": "string (optional)",
  "client_id": "string (optional)",
  "scopes": ["string"]
}
```

### CIBAInitiateResponse
```json
{
  "auth_req_id": "string",
  "expires_in": "int (seconds)",
  "interval": "int (polling interval in seconds)",
  "message": "string (optional)",
  "error": "string (optional)",
  "error_description": "string (optional)"
}
```

### CIBATokenResponse
```json
{
  "access_token": "string",
  "token_type": "Bearer",
  "expires_in": "int",
  "refresh_token": "string",
  "scope": "string",
  "error": "string (if pending/denied)",
  "error_description": "string"
}
```

**CIBA Error Codes:**
| Code | Meaning |
|---|---|
| `authorization_pending` | User has not responded yet |
| `access_denied` | User denied the request |
| `expired_token` | Request expired |
| `user_not_found` | Email not found |
| `no_device_registered` | User has no push-capable device |

### DeviceTokenRegistrationRequest
```json
{
  "device_token": "string (required, Expo Push Token)",
  "platform": "string (required, ios|android)",
  "device_name": "string (optional)",
  "device_model": "string (optional)",
  "app_version": "string (optional)",
  "os_version": "string (optional)"
}
```

### TOTPRegistrationResponse
```json
{
  "success": true,
  "secret": "BASE32ENCODED",
  "qr_code_url": "otpauth://totp/...",
  "device_id": "uuid",
  "backup_codes": ["code1", "code2", "..."],
  "message": "string"
}
```

### VoiceInitiateRequest
```json
{
  "client_id": "string (required)",
  "voice_platform": "alexa|google|siri|custom",
  "voice_user_id": "string (platform-specific)",
  "device_info": {},
  "scopes": ["openid"]
}
```

### VoiceInitiateResponse
```json
{
  "session_token": "string",
  "voice_otp": "string (4-digit spoken code)",
  "expires_in": 300,
  "message": "Please say the code: 8532"
}
```

### DeviceSummary
```json
{
  "id": "uuid",
  "device_name": "string",
  "platform": "ios|android",
  "device_model": "string",
  "app_version": "string",
  "os_version": "string",
  "is_active": true,
  "last_used": "int64 (unix epoch, nullable)",
  "created_at": "int64 (unix epoch)"
}
```

### TenantCIBAInitiateRequest
```json
{
  "client_id": "string (required, maps to tenant)",
  "email": "string (required)",
  "tenant_domain": "string (optional)",
  "binding_message": "string (optional)",
  "scopes": ["openid"]
}
```

### TenantTOTPLoginRequest
```json
{
  "client_id": "string (required)",
  "email": "string (required)",
  "totp_code": "string (required, 6 digits)",
  "tenant_domain": "string"
}
```

---

## Unregistered Controller Methods (Not Active)

The following methods exist in `controllers/platform/token_controller.go` with Swagger annotations but are **not wired into any route** in `routes/routes.go`. They are scaffolding only and produce no live HTTP endpoint.

| Swagger path           | Method           | Handler                                           |
|------------------------|------------------|---------------------------------------------------|
| `POST /auth/refresh`   | `RefreshToken`   | Refresh access token using refresh token          |
| `POST /auth/revoke`    | `RevokeToken`    | Revoke a specific refresh token                   |
| `POST /auth/logout`    | `Logout`         | Revoke all tokens for the authenticated user      |
| `POST /auth/blacklist` | `BlacklistToken` | Immediately blacklist an access token (emergency) |

These will become active if registered in a future `routes.go` change.

---

*Documentation generated for AuthSec v5.0.0 — 2026-04-21*
