# Subsystems map

> One-liner per file so an agent can find the right file without reading 50 of them.

## `controllers/platform/` — HTTP handlers (Gin controllers)

| File | What it handles |
|---|---|
| `oauth_as_controller.go` | ALL `/oauth/*` + `/.well-known/*` endpoints (grants, discovery, introspect, revoke, JWKS, DCR, CIBA bc-authorize) |
| `hmgr_controller.go` | Login UI, Hydra login/consent hooks, session management |
| `authmgr_controller.go` | Admin auth manager (admin login, OTP, session) |
| `oocmgr_controller.go` | Out-of-context (external) OAuth client manager |
| `authorization_controller.go` | Policy-based authorization decisions (`/authz/*`) |
| `resource_server_controller.go` | Applications / Resource Servers CRUD + drift |
| `applications_controller.go` | Application metadata + tool registration |
| `applications_access_controller.go` | Access control for applications (policy gates) |
| `applications_machine_access_controller.go` | M2M-specific access management for applications |
| `applications_requests_controller.go` | Access request lifecycle (pending → approve/deny) |
| `workspace_controller.go` | Workspace CRUD, members, domains |
| `token_controller.go` | Token inspect, revoke, list (`/tokens/*`, `/admin/tokens/*`) |
| `sdk_token_controller.go` | SDK token test + simulate (`/token-test/*`) |
| `logs_controller.go` | Auth / audit / M2M log endpoints |
| `spire_controller.go` | SPIRE workload registry, OIDC, policies |
| `spiffe_delegate_controller.go` | SPIFFE delegation exchange |
| `delegation_policy_controller.go` | A2A delegation policy CRUD |
| `trusted_issuers_controller.go` | Trusted issuer CRUD |
| `workload_identity_providers_controller.go` | Workload identity provider CRUD |
| `a2a_brokering_controller.go` | A2A brokering policy CRUD |
| `oidc_controller.go` | OIDC provider management |
| `scim_controller.go` | SCIM 2.0 user/group provisioning |
| `scope_matrix_controller.go` | Scope matrix / assignment UI endpoints |
| `extsvc_controller.go` | External service integrations |
| `hubspot_controller.go` | HubSpot CRM integration |
| `agent_action_controller.go` | Agent Shield: approve/deny agent actions |
| `audit_helper.go` | `auditAdminMutation` shared helper (not a controller) |
| `delegation_helpers.go` | Shared delegation logic helpers |

## `services/` — Business logic

| File | What it does |
|---|---|
| `oauth_as_service.go` | AS metadata, Hydra proxy, client/RS lookup, auth context store/consume, DCR |
| `client_auth.go` | `AuthenticateClient` — private_key_jwt / client_secret_basic / SPIFFE SVID |
| `xaa_service.go` | `ValidateIDJAG`, subject mapping, `ApproveWithRole` (XAA) |
| `hydra_service.go` | Hydra admin API calls (CRUD on Hydra clients) |
| `hydra_reconciler.go` | Background convergence loop (sync_error / pending_delete); stale DCR cleanup |
| `scope_resolver.go` | `ResolveGrantableScopes` — 3-way intersection (requested ∩ RS ∩ RBAC) |
| `scope_mapper.go` | Permission ↔ OAuth scope mapping (oauth_scope_permissions) |
| `scope_registry_service.go` | OAuth scope CRUD (oauth_scopes table) |
| `scope_preset_catalog.go` | Pre-defined scope bundles for common RS types |
| `rbac_service.go` | Role / permission CRUD |
| `permission_service.go` | Permission lookup + assignment |
| `service_account_service.go` | Service account CRUD |
| `resource_server_service.go` | RS CRUD, RS-by-URI lookup |
| `resource_server_onboarding_service.go` | RS manifest, onboarding, drift check |
| `resource_server_drift_service.go` | Drift event management |
| `authorization_context_service.go` | Auth request context store + PKCE binding |
| `consent_service.go` | OAuth consent grant store/lookup |
| `identity_provider_service.go` | IdP CRUD (OIDC + SAML) |
| `oidc_service.go` | OIDC callback, user identity resolution, JIT provisioning |
| `oidc_state.go` | OIDC state parameter management |
| `logs_service.go` | Auth / audit / M2M log read |
| `token_service.go` | Token list + revoke (controller-facing) |
| `token_utils.go` | `RSSpecificScopes`, `ScopesLost` — scope comparison helpers |
| `anti_replay_service.go` | Client assertion replay cache check |
| `ciba_auth_service.go` | CIBA auth (legacy path) |
| `workspace_ciba_service.go` | Workspace-plane CIBA (native M2M + XAA path) |
| `device_auth_service.go` | OAuth device flow (RFC 8628) |
| `authmanager_token_service.go` | Auth manager token handling |
| `authmgr_service.go` | Auth manager business logic |
| `clients_auth_service.go` | Client-facing auth service |
| `totp_service.go` | TOTP / 2FA |
| `workspace_totp_service.go` | Workspace-plane TOTP (admin login) |
| `webauthn_service.go` | WebAuthn (passkeys) |
| `voice_auth_service.go` | Voice biometric auth |
| `spiffe_key_service.go` | SPIFFE RS256 key pair (singleton, `SPIFFE_RSA_PRIVATE_KEY` env) |
| `push_notification_service.go` | FCM/APNs push for CIBA + step-up |
| `okta_ciba_service.go` | Okta-specific CIBA integration |
| `domain_service.go` | Workspace domain verification |
| `icp_provisioning_service.go` | SCIM / ICP provisioning |
| `risk_engine_service.go` | Risk scoring engine |
| `extsvc_service.go` | External service integration |
| `hubspot_service.go` | HubSpot CRM |
| `pki_retry_worker.go` | Background PKI/cert retry |
| `circuit_breaker.go` | `CircuitDoHydra` — HTTP circuit breaker for Hydra calls |
| `utils.go` | Shared service utilities |
| `agent_action_service.go` | Agent Shield action evaluation |

## `internal/` packages

| Package | What it does |
|---|---|
| `tokens/` | Classifier, NativeKeyManager, NativeIssuer, store, GrantHandler, Principal/Actor |
| `spire/` | SPIRE client, workload API integration |
| `hydra/` | Hydra public-URL client helpers |
| `policy/` | PDP interface + SimplePDP (OPA/embedded) |
| `migration/` | Migration runner + `migration_logs` AutoMigrate |
| `mcp/` | MCP protocol helpers |
| `authz/` | Authorization engine |
| `session/` | Session primitives |
| `vault/` | Vault KVStore interface (for native key loading) |
| `clients/` | OAuth client lookup helpers |
| `sharedmodels/` | Cross-package model types |
| `schemaaudit/` | Schema audit utilities |
| `oocmgr/` | Out-of-context manager |
| `authmgr/` | Auth manager internals |
