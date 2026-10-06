> **Phase 0 working notes (2026-10-06)** — platform/enduser/handlers SQL audit (agent-generated, verbatim). Not individually verified unless marked R/C in ISSUES.md.

# Part D — Tenant-isolation audit: controllers/platform, controllers/enduser, controllers/shared, handlers, middlewares

Read-only audit of commit `e25d76f`, branch `multitenacyV2`. Non-test `.go` files only. I mapped every handler to a route in `routes/routes.go` / `routes/iga_routes.go`.

## Method and caveats

- **What I counted.** I grepped every raw-SQL string, every GORM call (`Where/First/Find/Take/Delete/Save/Update(s)/Model/Raw/Exec/Create/Table/Count`) and every `QueryRow`/`Exec`. That gave about 540 matching lines, which collapse to about 400 distinct statements because one statement can span several lines.
  - Many handlers in scope don't touch SQL directly; they call services or repositories (`services/*`, `repository/*`, `internal/*`), which are outside scope. For those I checked one hop: what workspace the handler passes in, and, for risky callers, the callee's WHERE clause.
- **How I classified.**
  - **SCOPED:** the statement has a workspace predicate, or it runs after a workspace-scoped parent check.
  - **GLOBAL-OK:** the statement is legitimately global, for example a lookup by an opaque token, by `client_id` during OAuth, or against a global table where that is by design.
  - **RISKY:** everything else.
- **What I also flagged.** Some severe findings are authentication or authorization bypasses rather than missing `workspace_id` predicates. I list them anyway because they let an attacker reach another tenant's data or accounts.
- **Middleware facts the analysis relies on:**
  - `AuthMiddleware` puts the JWT `workspace_id` claim into the Gin context.
  - `ValidateWorkspaceFromToken` only compares the URL `:workspace_id` against the token. **It does nothing for workspace IDs that arrive in the body or query string.**
  - `RequireWorkspaceRole(owner,admin)` checks `workspace_memberships`, scoped to the token's workspace.
  - Workspace signup is self-service (`/uflow/oidc/complete-registration`, admin register), so **anyone on the internet can become a workspace admin**. A finding that "any workspace admin" can exploit is therefore cross-tenant.

## 1. Per-domain summary

The counts are approximate distinct statements, not grep lines.

| Domain | Reviewed | SCOPED | GLOBAL-OK | RISKY |
|---|---|---|---|---|
| users / identity (users, otp-driven login/registration, MFA rows on users) | ~140 | ~92 | ~20 | ~28 |
| workspaces / memberships | ~20 | ~12 | ~7 | ~1 |
| agents / service accounts / workloads (incl. spire_*) | ~50 | ~24 | ~8 | ~18 |
| applications / clients / resource servers | ~65 | ~58 | ~4 | ~3 |
| roles / permissions / scopes / bindings | ~80 | ~76 | ~1 | ~3 |
| policies (delegation, brokering, trusted_issuers, WIF providers, spire policies) | ~22 | ~14 | 0 | ~8 |
| grants / consents / delegation tokens | ~8 | ~8 | 0 | 0 |
| tokens / sessions (otp_entries, pending_registrations, pkce, auth_request_contexts, revoked_tokens, access_requests) | ~32 | ~9 | ~15 | ~8 |
| audit (scim_events, spire_audit_logs) | ~4 | ~3 | ~1 | 0 |
| connectors / integrations / SCIM / sync (AD, Entra, extsvc) | ~32 | ~22 | 0 | ~10 |
| IGA / discovery graph | ~14 + 5 ingress service calls | ~9 | 0 | ~5 |
| other (health, ratelimit) | ~3 | 0 | ~3 | 0 |
| **Total** | **~470** | **~327** | **~59** | **~84** |

### Consistency by file

**Well scoped.** These files consistently take the workspace from the token (`extractWorkspaceID`, `shared.RequireWorkspaceID`, `ResolveWorkspaceIDFromToken`, `ctl.workspace(c)`, `tokenWorkspace(c)`). Every `:id` is either loaded with `GetByIDAndTenant(id, ws)` or carries `workspace_id = ?`. Child tables are reached only through a scoped parent.
- `scope_matrix_controller.go`, `applications_*.go`, `resource_server_controller.go`
- `delegation_policy_controller.go`, `authmgr_controller.go` (groups), `governance_controller.go`
- `iga_*`, `connector_controller.go`, `workload_identity_providers_controller.go`, `a2a_brokering_controller.go`
- SCIM user handlers, the CIBA/TOTP authenticated handlers, `GetEndUser`, `UpdateUser`, `UpdateEndUserStatus`, `DeleteEndUser`, `DeleteUserAll`, `ActiveOrDeactiveEndUser`

**Where the problems are.**
- The unauthenticated MFA handlers (`handlers/`).
- Several legacy uflow end-user and admin handlers that take `workspace_id` from the request body.
- The AD and Entra sync controllers.
- Global tables that workspace admins can write: `trusted_issuers`, and `spire_*` (spire_* is behind a feature flag).
- The unauthenticated discovery ingress.

## 2. RISKY items

`file:line` | table | statement | endpoint | why risky / mitigation | severity

### P0 — exploitable cross-tenant access or account takeover

1. `controllers/enduser/enduser_controller.go:247-282` (`GetEndUsers`) | `users` | `Model(User).Where("deleted_at IS NULL")` plus optional filters, then `Count` and `Find`, with **no `workspace_id` predicate at all**. `filter.WorkspaceID` is read from the body or query and the token is only a fallback, but the value is never used in the query. | `GET/POST /authsec/uflow/user/enduser/list` (AuthMiddleware + ValidateWorkspaceFromToken; no role gate) | Any authenticated principal, including an end user of any workspace, can page through the users of every workspace (email, name, provider, groups). The `email` filter makes this a global email search. | **P0**

2. `controllers/enduser/enduser_controller.go:2060-2111` (`AdminChangeUserPassword`) | `users` | `Where("workspace_id = ? AND active = ?", input.WorkspaceID…)` then `Updates(password_hash)`. **The workspace comes from the request body and is never compared with the token.** | `POST /authsec/uflow/user/admin/change-password` (AuthMiddleware + ValidateWorkspaceFromToken; the route has no `:workspace_id`, so validation does nothing; no admin role check) | Any authenticated user of any workspace can set the password of any custom or ad_sync user in any workspace by email or `user_id`. **Full cross-tenant account takeover.** | **P0**

3. `controllers/enduser/enduser_controller.go:2167-2225` (`AdminResetUserPassword`) | `users` | Same pattern; overwrites `password_hash` with a random temporary password. | `POST /authsec/uflow/user/admin/reset-password` | Cross-tenant lockout or denial of service. The temporary password is emailed to the victim and not returned to the caller. Same root cause as #2. | **P0**

4. `controllers/enduser/enduser_auth_controller.go:155-196` (`WebAuthnCallback`) | `users` | `tenantDB.Where("LOWER(email) = LOWER(?)", input.Email).First(&user)` with **no workspace predicate**, followed by `Update(last_login) WHERE id`. A JWT is then minted with `workspace_id = input.WorkspaceID`. | `POST /authsec/uflow/auth/enduser/webauthn-callback` (**unauthenticated**) | The handler trusts a client-sent `"mfa_verified": true`, takes the workspace from the body, and picks the first user with that email from any workspace. It returns a **one-year access token** for that user, stamped with the attacker-chosen workspace. Unauthenticated token minting for any email in any workspace. | **P0**

5. `handlers/webauthn_handler.go:415-806` (`BeginRegistration` → `FinishRegistration`) | `users`, `credentials`, `mfa_methods` | Begin looks the user up by `(email, workspace_id)` from the body. Finish loads the user at **:599 by `Where("email = ?")` only**, because `resolveDBWithError` always reports `isGlobalDB=true`, which makes the scoped branch at :606 dead code. It then `AddCredential`, runs `UPDATE users SET mfa_*` (:739-762), and calls `WebAuthnRegisterInternal`, which **returns access and refresh tokens**. | `POST /authsec/webauthn/beginRegistration` and `/finishRegistration` (**unauthenticated**) | No prior authentication is required to enrol a passkey for an arbitrary `(email, workspace)`, and the finish step returns tokens for the victim. The :599 lookup can also attach the credential to a same-email user in a different workspace. Account takeover. | **P0**

6. `handlers/webauthn_handler.go:1117` and `:1144` (`BeginBiometricSetup`) | `users` | `Where("email = ?")` without workspace (dead-branch bug again). If the email is absent everywhere, it runs **`db.Create(&user)` with `WorkspaceID` taken from the body**. `ConfirmBiometricSetup` (:1278-1454) then enrols a credential and sets the MFA flags. | `POST /authsec/webauthn/biometric/beginSetup` and `/confirmSetup` (unauthenticated) | An unauthenticated attacker can insert users into any workspace and enrol a passkey on them, or on existing users. | **P0**

7. `handlers/enduser_webauthn_handler.go:379-412` (`BeginRegistration`) | `users` | `GetClientByEmailTenantAndClient(body…)`, then `tenantDB.Create(newUser)` with **`workspace_id` and `client_id` from the body**. `FinishRegistration` (:529-701) then enrols the credential and runs `UPDATE users SET mfa_enabled…`. | `POST /authsec/webauthn/enduser/beginRegistration` and `/finishRegistration` (unauthenticated) | Same class as #5 and #6: unauthenticated user creation in any workspace and passkey enrolment on any existing user. | **P0**

8. `handlers/totp_handler.go:46-455` (`BeginTOTPSetup`, `BeginSetup`, `ConfirmTOTPSetup`, `ConfirmSetup`); `handlers/sms_handler.go:297-523` (`BeginSMSSetup`, `ConfirmSMSSetup`) | `users`, `mfa_methods` | The lookups are scoped by `(email, workspace_id)`, but both values come from the body. `Save(&client)` and `UPDATE users SET mfa_*` follow. | `POST /authsec/webauthn/totp/*` and `/sms/*` (unauthenticated) | Tenant predicate present, but **no authentication**: anyone can read a fresh TOTP secret for any user and enable it. That defeats MFA, and replaces or overrides a victim's MFA method. | **P0** (security; not a missing predicate)

9. `controllers/shared/ad_controller.go:92, 138, 476-545, 577, 627-678` (`SyncADUsers`, `AgentSyncUsers`, `syncUserToDatabase`, `syncAgentUserToDatabase`) | `users`, `sync_configurations` | All queries carry `workspace_id = ?`, but the value is **`input.WorkspaceID` from the request body and is never compared with the token**. The flow loads a stored config, then creates or updates users. | `POST /authsec/uflow/admin/ad/sync` and `/ad/agent-sync` (AuthMiddleware + RequireWorkspaceRole + ValidateWorkspaceFromToken; the latter does nothing without a path param) | An admin of workspace A, and anyone can be an admin of some workspace, can:<br>(a) create `ad_sync` users with no password in workspace B, or deactivate and rename B's users (`active` and `name` updates);<br>(b) use B's stored AD credentials (`loadStoredADConfig(configID, B…)`; requires B's config UUID) with `dry_run` to dump B's directory.<br>Chained with #13, (a) gives account takeover in B. | **P0**

10. `controllers/shared/entra_controller.go:141, 188, 623-703, 735` (`SyncEntraIDUsers`) | `users`, `sync_configurations` | Same pattern as #9: `input.WorkspaceID` from the body. | `POST /authsec/uflow/admin/entra/sync` (`/entra/test-connection` and `/check-permissions` take only connection params and were not deeply audited) | Same impact as #9. | **P0**

11. `controllers/platform/trusted_issuers_controller.go:55-63` (List), `:119` (Create), `:185-237` (Revoke) | `trusted_issuers` (**global table**), `native_tokens`, `revoked_tokens` | List returns every issuer. Create inserts a global issuer. Revoke runs `Where("id = ?")`, then `UPDATE trusted_issuers … WHERE id`, then `INSERT INTO revoked_tokens SELECT … FROM native_tokens WHERE source_grant_iss = ?` **across all workspaces**. | `GET/POST /authsec/trusted-issuers`, `DELETE /authsec/trusted-issuers/:id` (any workspace owner/admin) | The table is platform-global trust configuration, yet the endpoints are gated only by workspace admin and there is **no platform-admin check**. Any tenant admin can:<br>(a) read every other tenant's federation config;<br>(b) revoke another tenant's issuer, which mass-revokes that tenant's XAA tokens (DoS);<br>(c) register an attacker-controlled issuer with `jit_provisioning` and a chosen `provider_name` / `workspace_claim_mapping`. `services/xaa_service.go:221` and `MapSubject` then map ID-JAG subjects into the target workspace by `(workspace, provider_name, sub)`, which allows identity collision or JIT users in other tenants. Whether a token can actually be redeemed still depends on RS client-registration approval (uncertain). | **P0**

12. `controllers/platform/discovery_controller.go:217-245` (`assertedWorkspace`), with ingress handlers at :461 `ReportSighting`, :517 `RegisterAgent`, :575 `ReportLifecycleEvent`, :628 `ReportResyncManifest` and :986 `ReportRBACSnapshot` | `discovered_agents`, `discovery_sources`, lifecycle events, k8s RBAC graph (services) | The workspace is taken from the **body of an unauthenticated request**; the only check is that the workspace exists. | `POST /authsec/discovery/{sightings,agent-registration,lifecycle,resync-manifest,rbac-snapshot}` (no auth) | The routes.go comment accepts this risk for sightings only ("noise"). But:<br>(a) `resync-manifest` with `complete=true` and an empty fingerprint list can **mark another tenant's agents as gone**;<br>(b) `lifecycle` mutates agent state;<br>(c) `rbac-snapshot` ingests an attacker-supplied Kubernetes RBAC graph into another workspace (when the projection gate is on);<br>(d) the responses echo existing `agent` and `source` rows on a fingerprint or instance match, a cross-tenant read.<br>All of these need only the target's workspace UUID, which is not a secret. | **P0** (integrity; the read side is uncertain)

13. `controllers/enduser/enduser_controller.go:1666-1747` (`CustomLoginRegister`) | `users` | `Where(workspace_id, email, provider IN…)`, then **`Update("password_hash", …)` on an existing ad_sync/entra_id/scim user with an empty password, with no OTP or email proof**. Otherwise it inserts a user. | `POST /authsec/uflow/user/register` (unauthenticated; workspace from the body via `ResolveWorkspace`) | The tenant predicate is present, but any unauthenticated caller can claim any directory-synced user that has no password yet, in any workspace, and set the password. The verified flow (`register/initiate` + `complete`) exists alongside this unverified shortcut. Combines with #9 and #10. | **P0** (security)

14. `controllers/platform/oocmgr_controller.go:93-139` (`DumpHydraRawData`) | Hydra admin clients (not SQL) | Workspace taken from the **body**; clients are filtered by `metadata.workspace_id` or a `client_id` prefix. | `POST /authsec/oocmgr/oidc/raw-hydra-dump` (AuthMiddleware only) | Any authenticated user can dump another workspace's OAuth client configuration (sanitised, so no secrets: redirect URIs and metadata). | **P0 (leak, lower sensitivity)** — could be argued down to P1

### P1 — gated by a feature flag, needs an ID or a privileged credential, or affects only one tenant's correctness

15. `controllers/platform/spire_controller.go:574, 599, 632-718` (workloads), `:1114-1177` (policies), `:1248-1278` (role bindings), `:1374` (evaluatePolicy), `:840/873/1590/1629/1649` (spire OIDC tokens) | `spire_workloads`, `spire_policies`, `spire_role_bindings`, `spire_oidc_tokens` (**no tenant column**) | Unscoped `Find`, `Where("spiffe_id = ?")` updates and deletes, `First(&policy, c.Param("id"))`, `Save`, `Delete(&SpirePolicy{}, id)`. | `/authsec/spire/registry/*` (AuthMiddleware only); `/authsec/spire/policy/*` and `/authsec/spire/roles/*` (**no auth at all**) | Global control-plane rows. Any caller can create, update or delete policies and role bindings that `evaluatePolicy` applies to everyone, and any authenticated user can list or delete every workload. **Mounted only when `ENABLE_EMBEDDED_SPIRE=true` (default off).** If that flag is on, this is P0. Bug: `UpdateWorkload` and `DeleteWorkload` read `c.Param("spiffe_id")` but the route is `/:id`. | **P1** (P0 if the flag is on)

16. `controllers/platform/spire_controller.go:400-476` (`RegisterAgentWorkload`) | `spire_workloads`, `workload_entries`, `application_spiffe_identities` | `Create`; `Where("spiffe_id = ?").Assign().FirstOrCreate`, an upsert by global SPIFFE ID. | Internal helper (callers outside this scope) | Assign-upsert by a global key can overwrite another workspace's identity row if the SPIFFE ID collides (uncertain; the caller builds the ID). | P1 (uncertain)

17. `controllers/platform/scim_controller.go:771, 838, 1142` (insert member) and `:1114` (`getGroupMembers`) | `user_groups`, `users` | `INSERT INTO user_groups (user_id, group_id, workspace_id)` with **`user_id` from the SCIM payload, never checked to belong to the workspace**. `getGroupMembers` then reads `users WHERE id = ?` **without a workspace predicate**. | `/authsec/uflow/scim/v2/c/:conn/Groups` POST/PUT/PATCH (SCIM bearer token) | A SCIM token holder (admin-equivalent of workspace A) can add a foreign user UUID to A's groups and read back that user's name and email. Requires knowing the UUID. The authmgr `ListGroupUsers` association read (`authmgr_controller.go:1092`) also returns such foreign members. | P1

18. `controllers/platform/oauth_as_controller.go:2853` (`inferAuthorizeResource`) | `resource_servers` | `Where("active = true").Select("resource_uri").Find(&servers)` across **all workspaces**; the URIs are placed in the error description. | `GET /oauth/authorize` (unauthenticated) when a client maps to more than one RS | Leaks every tenant's MCP resource URIs to anyone holding an ambiguous `client_id`. | P1

19. `handlers/sms_handler.go:654-660` (`VerifySMS`) | `users` | After verifying user X's code, runs `Where("workspace_id = ?", req.WorkspaceID).First(&u)`, which returns **an arbitrary user** in that workspace, then `Update("mfa_verified", true)` on it. | `POST /authsec/webauthn/sms/verify` (unauthenticated) | Writes to the wrong row within the tenant. `mfa_verified` gates token issuance in `WebAuthnRegisterInternal`. | P1

20. `controllers/enduser/totp_controller.go:557, 624` (`LoginWithTOTP`, `ApproveDeviceCodeWithTOTP`) | `users`, `device_codes` (via repository) | `GetUserByEmail(req.Email)` is unscoped (the code carries a `TODO P2-11`). The workspace is derived from the first matching row. `FindByUserCode` is global, and nothing checks that the device code's client or workspace matches the user's workspace. | `POST /authsec/uflow/auth/totp/login` and `/totp/device-approve` (unauthenticated) | With duplicate emails across workspaces, the wrong user is chosen (the TOTP check still applies to that user). A device code started for workspace A's client can be approved by a workspace B user, returning a B token to A's device. | P1

21. `services/ciba_auth_service.go:56`, reached from `controllers/enduser/ciba_auth_controller.go:59` | `users`, `ciba_*` | `lookupUserByEmail` is a cross-tenant lookup; the workspace is taken from the first row. | `POST /authsec/uflow/auth/ciba/initiate` (unauthenticated, deprecated) | Ambiguous-email lookup with push notifications to the wrong user. The successor `/auth/workspace/ciba` derives the workspace from `client_id`. | P1

22. `middlewares/auth.go:651-657` (`resolveUserIDFromEmail`) | `users` | When the workspace-scoped lookup fails, it **falls back to `GetUserByEmail` with no workspace**, then sets `user_id` in the context. | Every route behind AuthMiddleware when the JWT lacks `sub`/`user_id` | A token for workspace A with email E, where E is not in A, resolves to E's user ID in another workspace. Signed tokens limit exploitability (legacy and trimmed tokens only). | P1 (defence in depth)

23. `controllers/platform/hmgr_controller.go:1686` (`ProcessSAMLAssertion` fallback) | `auth_request_contexts` | When the challenge lookup fails, it picks the **newest unconsumed context in the workspace**. | `POST /authsec/hmgr/saml/acs*` | Can bind one user's SAML login to another user's in-flight authorisation context (resource, client) in the same tenant. | P1 (intra-tenant)

24. `controllers/platform/extsvc_controller.go:261, 335, 352, 360` → `services/extsvc_service.go:81-160` | `external_services` | `GetByID(id)`, then checks `svc.CreatedBy == clientID`. **Scoped by `client_id` from the token, not by `workspace_id`.** | `/authsec/exsvc/services/:id[/credentials]` (SpiffeAuthMiddleware + Require) | Isolation holds only if `client_id` is unique per workspace. If a client is shared across workspaces (global OAuth clients exist by design), services and vault credentials leak across tenants. | P1 (uncertain)

25. `controllers/platform/oidc_controller.go:1231-1400` (`CompleteRegistration`) | `workspaces`, `users`, `role_bindings`, `workspace_memberships` | Creates a new workspace and an admin user from **body** fields (email, provider, provider_user_id). The `state_token` check is optional (`if input.StateToken != ""`). | `POST /authsec/uflow/oidc/complete-registration` (unauthenticated) | No cross-tenant read, but anyone can create a workspace whose admin identity claims a victim's email or provider ID, without IdP proof. This also feeds #11 and the other "any workspace admin" findings. | P1 (security)

26. `controllers/enduser/enduser_controller.go:1446-1506, 1556-1603, 1655-1656, 1851-1963, 2006-2020` | `otp_entries` (no tenant column), `pending_registrations` | `DELETE/INSERT/SELECT/UPDATE … WHERE email = $1`. Note that `pending_registrations` does have `workspace_id`, but its deletes run by email only. | `/authsec/uflow/user/register/initiate`, `/register/complete`, `/forgot-password*` (unauthenticated) | OTPs are not bound to a workspace or purpose: an OTP issued for workspace A (or for registration) is accepted to reset the password in workspace B, or for another flow. Proof of email ownership limits this. Deletes by email alone let anyone cancel another workspace's pending registration or OTP for that email (DoS). | P1 (cross-workspace OTP reuse) / P2 (DoS)

27. `controllers/platform/scim_controller.go:1228-1300` (`GenerateSCIMToken`) | — (token mint) | Mints a **one-year** end-user JWT with `scim:*` scopes for the caller. | `POST /authsec/uflow/admin/scim/generate-token` (AuthMiddleware + ValidateWorkspaceFromToken; **no `RequireWorkspaceRole`**) | Same workspace, but any end user can turn a short-lived token into a one-year token. | P1 (authz)

28. `/authsec/uflow/user/*` group (routes.go:1094) → `UpdateUser` (:439), `UpdateEndUserStatus` (:343), `DeleteEndUser`, `DeleteUserAll`, `ActiveOrDeactiveEndUser` | `users`, `role_bindings`, … | Scoped to the token's workspace (correct), but the group has **no admin role gate**. Only the DELETE routes carry `Require("users","delete")`; `POST /enduser/delete` and `/enduser/active` do not. | — | Any end user can modify, deactivate or delete other users in their own workspace. Not cross-tenant. | P1 (intra-tenant authz)

### P2 — hygiene and defence in depth

29. `scope_matrix_controller.go:467` | `resource_servers` | `Where("id = ?", *scope.ResourceServerID)` with no workspace, but the scope row was loaded scoped (:439). | P2
30. `scope_matrix_controller.go:1413` → `ResourceServerDriftService.Dismiss(eventID, adminUserID)` | `resource_server_drift_event_dismissals` | The `event_id` is not checked to belong to the path RS. Effect is limited to the caller's own dismissal row. | `POST /authsec/{resource-servers,applications}/:id/drift-events/:event_id/dismiss` | P2
31. `scim_controller.go:505, 578, 852, 931` | `users`, `groups` | Re-read `Where("id = ?")` after a scoped update. | P2
32. `applications_controller.go:491-509` (`ListConnections`) | `access_requests`, `users` | The LATERAL subquery and the users join carry no workspace predicate. The outer `r.workspace_id` is scoped. A subject from another workspace (cross-workspace connections by design) is shown with email and name. | P2 (by design?)
33. `applications_machine_access_controller.go:554, 667` | `mcp_oauth_clients` | `Where("client_id = ?")` global, by design (OAuth clients are global). `resolveSimulateSA` re-checks the SA's workspace; `SimulateXAA` exposes existence and approval state of foreign clients. | P2
34. `applications_machine_access_controller.go:1150` | `application_spiffe_identities` | `Where("spiffe_id = ?")` global uniqueness check that returns the status of another tenant's identity (existence oracle). | P2
35. `oauth_as_controller.go:3351` (`AccessRequestStatus`) | `access_requests` | Unauthenticated `Where("id = ?")`. Capability by UUID; returns status and reason. | P2
36. `controllers/platform/oocmgr_controller.go:69-90` (`SyncHydraClients`) | `mcp_oauth_clients` | Unauthenticated global `Count`. | `POST /authsec/oocmgr/hydra-clients/sync` | P2
37. `controllers/enduser/enduser_controller.go:1373` (`CustomLoginStatus`), `enduser_auth_controller.go:92` (`SAMLLogin`), `handlers/*` `GetMFAStatus*`, `admin_webauthn_handler.go:113/152/234` (`GetClientByEmail`, unscoped) | `users` | User and MFA enumeration for any workspace. The admin variants use an **email-only** lookup, so the "admin" user could be an end user of another workspace. | P2 (P1 for the admin webauthn registration path: `admin_webauthn_handler.go:329-600`, unauthenticated passkey enrolment for the first user with that email — same class as #5)
38. `controllers/platform/sdk_token_controller.go:51` | `delegation_tokens` | Scoped, but any authenticated workspace member can fetch any agent's delegation token via `?client_id=`. | `GET /authsec/uflow/sdk/delegation-token` (AuthMiddleware only) | P2 (intra-tenant)
39. `handlers/webauthn_handler.go:1602, 1683, 1926` | `mfa_methods` | `Where("method_type = ? AND enabled = true").First` then `Update(verified)` — fully unscoped, touches an arbitrary user's row. These are **dead code**: `WebAuthnHandler.VerifyOTP`, `VerifySMS` and `VerifyBackupCode` are unrouted, as are `BeginOTPSetup`, `BeginSMSSetup` and `GenerateBackupCodes`. | Unrouted | P2 (delete them)

## 3. GLOBAL-OK (brief)

- `controllers/shared/workspace_resolver.go:63, 73, 98, 106` — `workspaces` lookup by host, slug or UUID. `ResolveWorkspace` deliberately accepts a body or query workspace for pre-auth login; credentials are then checked inside that workspace. Acceptable, but it enables enumeration.
- `middlewares/scim_connection_auth.go:46` — `scim_connections WHERE id = ?`, then a constant-time token-hash compare. The workspace is taken from the row.
- `middlewares/scim_event_logger.go:62` — insert using the workspace from the connection context.
- `middlewares/workspace_role.go:65-75` — membership check scoped to the token's workspace and user.
- `oauth_as_controller.go:1101` (`application_spiffe_identities` by `spiffe_id`), `:1111` (`service_accounts` by authenticated `sa.ID`), `:2029` (SA by authenticated `client.ID`) — identifiers come from an authenticated client.
- `oauth_as_controller.go:2566` — `role_bindings` by `scope_id = rs.ID` and subject, where the RS comes from introspection credentials.
- `oauth_as_controller.go:1746` and `applications_machine_access_controller.go:698` — brokering policies scoped by the subject's or token's workspace.
- `scope_matrix_controller.go` `SDKPolicy` (:600-690) and `PutSDKManifest` (:750-1020) — Basic auth with RS introspection credentials, and **path `:id` is compared with the authenticated RS**. Child rows are keyed by `rs.ID` and `rs.WorkspaceID`.
- `hmgr_controller.go:40-49` — `pkce_verifiers` by opaque state key.
- `hmgr_controller.go:245-246` — user lookup scoped to the workspace from the Hydra challenge, cross-checked against the token.
- `spire_controller.go:840, 873, 1649` — `spire_oidc_tokens` by `jti`, only after signature validation (behind the flag).
- `connector_broker_controller.go:368, 371, 649` — by `authCtx.Principal.SubjectID` and the resolved connection, from authenticated broker context.
- `trusted_issuers_controller.go:235` — `revoked_tokens` is global by design. The `native_tokens` select is the cross-tenant part covered in #11.
- `enduser_controller.go:1090-1137` (`OIDCLogin`) — workspace from Hydra introspection `ext` (trusted). Scoped lookup.
- `device_auth_controller.go:386-394` — workspace from server-side OIDC state.
- Device-code approval by `user_code` (`voice_auth_controller.go:468`, `device_auth_controller.go:215`) — RFC 8628 global `user_code`, approver from the JWT.
- `extsvc_controller.go:139` and `discovery_controller.go:231` — `workspaces` existence checks.
- `health_controller.go:118, 126` — `SELECT 1` and `information_schema`.
- `iga_classification_controller.go:68` — membership check scoped by workspace and user.

## 4. Notes

### Scoping helpers and markers

- **No automatic workspace filter.** There is no GORM scope or repository that applies `workspace_id` for you. Scoping is manual everywhere.
- **De-facto helpers, used consistently in the modern controllers:**
  - `ResourceServerService.GetByIDAndTenant(id, ws)` — the parent check for every RS-child route.
  - `extractWorkspaceID`, `shared.RequireWorkspaceID`, `shared.ResolveWorkspaceIDFromToken`, `middlewares.GetWorkspaceIDFromToken`, and the per-controller `ctl.workspace(c)` / `tokenWorkspace(c)`. All read the token context.
  - The IGA graph `serve()` wrapper, which documents "workspace ONLY from the token, never a parameter".
- **Where the legacy code goes wrong.** The uflow end-user and admin handlers, the AD and Entra sync controllers, and every MFA handler under `handlers/` instead read `workspace_id` from the body or query.
- **`ValidateWorkspaceFromToken` gives false comfort.** It is applied widely but checks only `:workspace_id` path params. None of the body-workspace handlers above have a path param.
- **No exemption markers.** I found no `TENANT-EXEMPT` (or similar) markers anywhere in scope.
- **Platform-level endpoints are not platform-gated.** Nothing in scope checks a "platform admin" role. Global or platform resources are protected only by workspace-admin (`trusted_issuers`), by any-auth (`oocmgr` dump, `spire/registry`), or by nothing (`spire/policy`, `spire/roles`, `oocmgr/hydra-clients/sync`). `hmgr/admin/*` uses `Require("admin","manage")` but every handler is a stub.

### Test coverage

- Only one cross-tenant test exists in scope: `controllers/enduser/enduser_controller_activation_test.go:317` (`TestActiveOrDeactiveEndUser_CrossWorkspaceDenied`).
- There are no cross-workspace isolation tests for `GetEndUsers`, `AdminChange/ResetUserPassword`, AD/Entra sync, SCIM, trusted issuers, discovery ingress, or the MFA handlers.
- There are 18 `_test.go` files in scope.

### Dead code and dead tables

- **Unrouted methods:** `WebAuthnHandler.VerifyOTP`, `VerifySMS`, `BeginOTPSetup`, `BeginSMSSetup`, `GenerateBackupCodes`, `VerifyBackupCode`, `VerifyBiometricFinish`.
- **Placeholder handlers:** every `HmgrController` admin handler.
- **Dead branches:** `resolveDB` / `resolveDBWithError` always return the global DB with `isGlobalDB=true`, so every "tenant branch" in `handlers/webauthn_handler.go` is unreachable. That is the root cause of the email-only lookups at :599 and :1117.
- **Tables outside migrations:** `spire_*` handlers write to tables outside the master migrations, and per the routes.go comment, `workloads` and `workload_entries` (used by `RegisterAgentWorkload`) are absent from the master bootstrap. This code is quarantined behind `ENABLE_EMBEDDED_SPIRE`.
- **Route-param bug:** `SpireController.UpdateWorkload` and `DeleteWorkload` read `c.Param("spiffe_id")` on a `/:id` route.

### Not audited in depth (out of scope)

These sit behind services or repositories, so they need a follow-up audit:
- `internal/authz.Require` permission resolution.
- The `services/*` for governance, connectors, cloud AWS/GCP, discovery manager, CIBA, TOTP and voice. The handlers do pass the token workspace correctly.
- `GCPOAuthProvisionService.HandleCallback` and the session-ID binding behind the unauthenticated `GET /discovery/gcp/google-oauth/callback`.
- SAML ACS signature validation behind `/hmgr/saml/acs/:workspace_id`.
