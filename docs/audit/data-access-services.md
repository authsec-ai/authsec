> **Phase 0 working notes (2026-10-06)** — services/ SQL audit (agent-generated, verbatim). Not individually verified unless marked R/C in ISSUES.md.

# Part B: tenant-isolation audit of `services/` (non-test .go)

Scope: `/home/sauron/k1/authsec/merger/authsec/services/*.go` (99 non-test files, ~49.5k LOC). This was a read-only review.

Method:
- I extracted statements with a Go-AST walker (`scratchpad/sqlx_b/main.go`). It records every outermost GORM/`database/sql` terminal call (First/Find/Take/Count/Pluck/Scan/Create/Save/Update(s)/Delete/Exec/Raw/Query/QueryRow/FirstOrCreate) together with its whole chain and enclosing function.
  - Output is in `sqlx_b/final.tsv`: 574 statements.
  - About 35% of the 99 files have no direct SQL. They delegate to `repository/` or `database/` packages.
  - For those, I reviewed the ~389 `repo.X(...)` call sites in `sqlx_b/repocalls.txt`. I traced the ones that pass only an id (no workspace) to their controller callers.
- I traced every unscoped id-based statement up to its `routes/` endpoint.

## 1. Per-domain counts (574 direct SQL/GORM statements)

| Domain | # reviewed | # SCOPED | # GLOBAL-OK | # RISKY |
|---|---|---|---|---|
| users/identity | 44 | 37 | 7 | 0 (+2 P0 via repo, see oidc_service) |
| workspaces/memberships | 7 | 0 | 6 | 1 |
| agents/service accounts/workloads | 69 | 47 | 13 | 9 |
| applications/clients/resource servers | 176 | 123 | 44 | 9 |
| roles/permissions/scopes/bindings | 45 | 33 | 0 | 12 |
| policies | 52 | 43 | 7 | 2 |
| grants/consents/delegation | 53 | 48 | 1 | 4 |
| tokens/sessions | 27 | 0 | 26 | 1 |
| audit | 6 | 6 | 0 | 0 |
| connectors/integrations/SCIM/sync | 24 | 16 | 8 | 0 (+extsvc via repo) |
| IGA/discovery graph | 70 | 67 | 3 | 0 |
| other | 1 | 1 | 0 | 0 |
| **Total** | **574** | **421** | **115** | **38** |

How the statements were classified:
- **SCOPED** includes statements whose WHERE has no `workspace_id` but whose parent row was loaded with a workspace filter in the same function or its caller. Typical cases:
  - child tables keyed by `rs.ID`, `scope.ID` or `sa.OAuthClientID` after `GetByIDAndTenant`;
  - `tx.Model(&rs).Updates` on a row that was loaded scoped.
- **Repo-delegated calls:** 389 sites were reviewed. Of the id-only ones, these are RISKY:
  - oidc_service: 2 (P0)
  - discovery ClaimAgent: 1 (P0, the root cause of item 3)
  - extsvc: 4 (P1) plus a controller sibling (P0)
  - domain_service: 4 (P1)
  - connector_oauth: 1 (P2)
  - device_auth: 1 (P2)
- All other repo-delegated calls pass `workspaceID`, or are opaque-token lookups with a post-check: CIBA, agent-action, device_code, voice session, and TOTP device by `device.ID` after a scoped load.

Severity totals across RISKY items in section 2: **P0 = 5, P1 = 9, P2 = 17**.

## 2. RISKY items

file:line | table | statement | caller endpoint | why / mitigation | severity

### P0

1. **client_auth.go:360** | service_accounts | `Where("spiffe_id = ? AND status = 'active'", sub).First(&sa)`, with no workspace filter, in `authenticateSPIFFESVID` | `POST /oauth/token` (routes.go:234, `oauthASController.Token` → `services.AuthenticateClient`, oauth_as_controller.go:973/1143/1835/1898/2002)
   - **Why risky:**
     - The provider is resolved by `issuer` (globally unique, client_auth.go:231), and `providerWS` is captured.
     - On the federated-OIDC path the SA lookup is filtered by `providerWS` (client_auth.go:345-352).
     - On the **spiffe** path it is not. There is also no check that `sa.workload_provider_id == provider.ID`, or that `sa.workspace_id == provider.workspace_id`.
     - The trust-domain check only compares the SVID against the provider's *own* `trust_domain`. Any workspace admin can set that field freely, or omit it, which skips the check entirely (`controllers/platform/workload_identity_providers_controller.go:79-121`, `POST /authsec/workload-identity-providers`).
   - **Attack:**
     1. The admin of workspace A registers a spiffe provider with an attacker-controlled issuer/JWKS, and trust_domain set to the victim's trust domain (or empty).
     2. They mint a JWT-SVID with `sub = spiffe://<victimTD>/...`. SPIFFE IDs are guessable naming conventions.
     3. The lookup resolves workspace B's service account and its linked confidential client (client_auth.go:376).
     4. Tokens are issued as B's workload.
   - **Mitigation present:** none. Also related: the `application_spiffe_identities` lookup/UPDATE by `spiffe_id` at :387/:401 is unscoped. | **P0**

2. **oidc_service.go:400 `GetAllProviders()` / :410 `UpdateProvider(providerName, input)`** → database/oidc_repository.go:102 / :130 | oidc_providers (has workspace_id)
   - **Statements:** `SELECT ... FROM oidc_providers ORDER BY display_name` (no WHERE); `UPDATE oidc_providers SET client_id, client_secret_vault_path, is_active, icon_url, redirect_uri WHERE provider_name = $7` (no workspace).
   - **Endpoints:** `GET /authsec/uflow/admin/oidc/providers` and `PUT /authsec/uflow/admin/oidc/providers/:provider` (routes.go:963-971). The only middleware is `AuthMiddleware + RequireWorkspaceRole("owner","admin") + ValidateWorkspaceFromToken`, so any workspace admin can call them.
   - **Why risky:**
     - Any workspace admin can list every workspace's OIDC provider config (client_id, vault path, redirect URIs).
     - They can also rewrite **every** provider named e.g. `google`: the platform-global row (`workspace_id IS NULL`) and every tenant's row.
     - Changing `client_id`/`redirect_uri`/vault path to attacker values hijacks social login for all tenants (cross-tenant account takeover), or disables it (`is_active=false`).
   - **Mitigation present:** none. These look like platform-admin endpoints mounted on a workspace-admin group. | **P0**

3. **provisioning_service.go:190 / :330 (Provision) and :509 / :579 / :598 / :607 (Deprovision)** | mcp_oauth_clients, resource_server_client_registrations
   - **Statements:**
     - `tx.First(&client, "id = ?", *agent.MatchedClientID)`
     - `UPDATE mcp_oauth_clients SET governance_status='active', owner_user_id=? WHERE id=?`
     - In Deprovision:
       - `First(&client,"id = ?",clientID)`
       - `Where("oauth_client_id = ? AND status <> revoked").Find(&regs)`, followed by an UPDATE to status=revoked per reg
       - `UPDATE mcp_oauth_clients SET governance_status='deprovisioned' WHERE id=?`
   - **Where the client id comes from:** the agent row is loaded scoped, but `agent.matched_client_id` is attacker-supplied. `discoveryManager.ClaimAgent` (discovery_service.go:886-945) passes `in.MatchedClientID` straight from the request body (`controllers/platform/discovery_controller.go:166,871`) to `repo.ClaimAgent` without checking that the client belongs to the workspace. `OwnerUserID` is not validated either.
   - **Endpoints:**
     1. `POST /authsec/discovery/agents/:id/claim` with `matched_client_id = <B's mcp_oauth_clients.id>`
     2. then `POST /authsec/provisioning/agents/:id/provision`, which rewrites B's client `owner_user_id`/`governance_status` and binds an A service account to B's client
     3. or `POST /authsec/provisioning/agents/:id/deprovision`, which revokes **all** of B's client's registrations on B's resource servers and marks the client deprovisioned
   - **Impact:** cross-tenant write / DoS.
   - **Preconditions:** the attacker needs B's internal client UUID, which is not the public client_id. If B's client already has a service account, Provision fails on `uq_sa_client`, but Deprovision does not. | **P0**

4. **oauth_as_service.go:1747 `ApprovePendingRedirects(clientID)`** (via authorization_context_service.go:359 `GetMCPOAuthClientByClientID` global lookup, and :371 `s.db.Save(client)`) | mcp_oauth_clients
   - **Endpoint:** `PUT /authsec/resource-servers/:id/clients/:client_id/approve-redirects` (resource_server_controller.go:466-486).
   - **Why risky:**
     - The controller checks only that `:id` (the RS) belongs to the caller's workspace.
     - The client is looked up by its **public** client_id across all tenants. Nothing checks that the client is registered to that RS or belongs to the workspace.
     - So an admin of A can approve redirect-URI changes that are pending review in workspace B, and the URIs are pushed to Hydra. Combined with control of a DCR client's registration access token (RAT), this bypasses B's redirect review and enables auth-code theft.
   - **Mitigation present:** none. | **P0**

5. **(controller sibling of extsvc_service) controllers/platform/extsvc_controller.go:375** | `services` table, which has **no workspace_id column**
   - **Statement:** `repo.GetByID(serviceID)` for `auth_method == "spiffe-jwt-svid"`, checking only `svc.AgentAccessible`.
   - **Endpoint:** `GET /authsec/exsvc/services/:id/credentials`.
   - **Why risky:** any SPIFFE-authenticated agent in any workspace can read Vault credentials of any agent-accessible external service in any workspace, given the service UUID. | **P0** (cross-ref; the controller is in another part's scope)

### P1

6. **provisioning_service.go:748 (GrantEntitlement)** + **oauth_as_service.go:740/756/817** | mcp_oauth_clients, resource_server_client_registrations, role_bindings
   - **Statement:** `Where("client_id = ?", in.ClientID).First(&client)` is a global lookup by public client_id. `ensureRegistration` (:400-424) then **creates** a pending registration for that client on the caller's RS and approves it.
   - **Endpoint:** `PUT /authsec/applications/:id/connections/:connection_id/approve` (applications_controller.go:660-730). The RS is pre-checked by `GetByIDAndTenant`.
   - **Why risky:**
     - The client is never checked to belong to the workspace or to have asked for access. An admin can link a foreign tenant's client to their own RS.
     - `binding.SubjectID` (user or service account) is not validated as a workspace member, unlike the role, which is checked at :759.
   - **Mitigation:** writes are confined to the caller's RS, so the impact is mostly on the caller's own resource. | **P1**

7. **agent_policy_enforce.go:81 / :93** + **agent_policy_service.go:239** | role_bindings, role_permissions
   - **Statements:** `UPDATE role_bindings SET role_id = ? WHERE id = ?` (ceiling role) and `SELECT permission_id FROM role_permissions WHERE role_id = ?`.
   - **Why risky:** `RoleCeilingID` comes from the policy body (`POST` agent policies, governance_controller.go:1480/1516) and is never checked to be in the workspace. A binding in A can be re-pointed at a role from workspace B.
   - **Mitigation:** the binding rows themselves are workspace-filtered (agent_policy_enforce.go:49), and the subset check limits a foreign role to an empty permission set. | **P1**

8. **oauth_as_service.go:918 (InferSingleResourceURIForClient)** | resource_servers
   - **Statement:** `Where("active = ?", true).Find(&servers)` lists active RS across **all** workspaces for the DCR fallback.
   - **Endpoints:** `/oauth/authorize`, `/oauth/token`, CIMD flows (oauth_as_controller.go:794/1008/1188/2845).
   - **Why risky:** if exactly one DCR-enabled RS exists deployment-wide, any unbound DCR client gets that tenant's resource inferred.
   - **Mitigation:** later registration/approval gates still apply. | **P1**

9. **resource_server_onboarding_service.go:266 (EnsureDefaultAccessBinding)** | users
   - **Statement:** `Where("id = ?", userUUID).First(&user)`, with no workspace filter, before creating a default-role binding in the RS's workspace.
   - **Caller:** hmgr consent handler (hmgr_controller.go:897), where the subject comes from the Hydra consent request.
   - **Why risky:** a user from another workspace who completes Hydra login for this RS gets an auto-binding. Whether that is reachable depends on whether login is tenant-bound. (uncertain) | **P1**

10. **rbac_service.go:39 `DeletePermission(permID)`** | permissions
    - **Statement:** `Delete(... "id = ?")`.
    - **Callers:** permission_controller.go:228/285/349/411. Each first does `Where("id = ? AND workspace_id = ?")`.
    - **Why risky / mitigation:** mitigated by the pre-check; this is a defence-in-depth gap. | **P1**

11. **rbac_service.go:90 / :98 `AssignRoleScoped(binding)`** | role_bindings
    - **Caller:** roles_scoped_bindings_controller.go:936-1063 (uflow admin/user role-binding endpoints).
    - **Why risky:** the role, user and service account are validated to be in the workspace, but `GroupID` (:1036) and `Scope.ID` (an RS id, :984) are not. A binding can reference another tenant's group or RS.
    - **Mitigation:** the PDP filters `rb.workspace_id` and `os.workspace_id` (scope_resolver.go:302-307), but the `user_groups` subquery is not workspace-filtered. | **P1**

12. **domain_service.go:38 / :56 / :64 / :130** (`repo.GetDomainByID`, `VerifyDomain`, `UpdateVerificationStatus`, `DeleteDomain` by id) | workspace_domains
    - **Callers:** domain_controller.go:251/349 (`/admin/tenants/:workspace_id/domains/...`).
    - **Mitigation:** the controller pre-checks `td.WorkspaceID != workspaceID`. It returns **403**, not 404, which is an existence oracle. | **P1**

13. **extsvc_service.go:82 / :94 / :155 / :159** | `services` (no workspace_id)
    - **Why risky:** ownership is enforced only by `svc.CreatedBy == clientID` (the JWT `client_id`), and the table has no tenant column.
    - **Mitigation:** isolation relies on client_id being globally unique. | **P1**

14. **authorization_context_service.go:359 `GetMCPOAuthClientByClientID`**, used by admin paths: RevokeClientRegistration (oauth_as_service.go:1711), DenyClientRegistration (:847), ApproveClientRegistrationInTx (:740)
    - **Why risky:** global client lookup by public id from admin endpoints.
    - **Mitigation:** the follow-up writes are filtered by the pre-checked `resource_server_id`. The exception is the ApprovePendingRedirects path, which is P0 item 4. | **P1**

### P2

15. **resource_server_service.go:122** | resource_servers | global `resource_uri` duplicate check in Create. The error message "a resource server with this URL already exists" leaks existence across tenants. | P2
16. **resource_server_service.go:373 / :376 `Update(id)`** and **:384 / :388 `Delete(id)`** | resource_servers, client registrations | unscoped by id; **no callers (dead code)**. | P2
17. **scope_registry_service.go:283 `Update`, :338 `Delete`, :354 `GetByID`** | oauth_scopes | unscoped by id; no callers (dead). | P2
18. **rbac_service.go:32 `ListPermissions`, :43 `DeleteRole`, :48 `GetRole`, :275 / :290 `CheckPrincipalActive`, :363 `ListEffectiveBindings`** | permissions, roles, workspace_memberships, role_bindings | unscoped; no external callers (dead). Only `CheckPrincipalActiveInWorkspace` is used. | P2
19. **consent_service.go:153 `RevokeConsent(grantID)`** | oauth_consent_grants | unscoped; no callers. `RevokeConsentByUser` (:165) is filtered by user_id. | P2
20. **resource_server_drift_service.go:92 `Dismiss(eventID, adminUserID)`** | resource_server_drift_event_dismissals
    - **Endpoint:** `POST /authsec/resource-servers/:id/drift-events/:event_id/dismiss`.
    - **Why risky:** `event_id` is not bound to the pre-checked RS.
    - **Impact:** limited to the caller's own dismissal rows. | P2
21. **governance_certify_service.go:395 / :418** | native_tokens, discovered_agents | evidence counts by `subject_id` / agent id with no workspace filter. The ids come from scoped provenance rows. | P2
22. **governance_certify_service.go:596** | certification_items | when delegating, `reviewer_user_id = in.DelegateTo` is written even if the user is not in the workspace (the email lookup is scoped, but the id is not validated). | P2
23. **service_account_service.go:160 / :164** | spire_workloads, spire_oidc_tokens (no tenant column) | DELETE/UPDATE by `spiffe_id`, taken from a workspace-scoped SA. SPIFFE ids are globally unique on service_accounts, but the spire_* tables have no tenant guard. | P2
24. **pki_retry_worker.go:82** | workspaces | `UPDATE workspaces ... WHERE workspace_id = $3`, but `workspaces` has `id`, not `workspace_id` (001_bootstrap.sql:1630). The statement always errors: a functional bug, not a leak. | P2
25. **connector_oauth_service.go:76** | connector_connections | `repo.GetUserConnection(connectorID, subject)` pre-read with no workspace filter. The Vault delete only happens if the scoped `RevokeUserConnection` affected rows. | P2
26. **device_auth_service.go:128-158 `AuthorizeDevice(userCode, ...)`** | device_codes | any authenticated user of any workspace can approve any pending user_code (RFC 8628 behaviour). The minted token belongs to the approver's workspace, so this is login-CSRF-style only. | P2
27. **actuation_service.go:549 (enqueueEviction)** | discovery_sources | `First(&src,"id = ?", *agent.DiscoverySourceID)`, where `agent` was loaded scoped. | P2 hygiene
28. **agent_policy_service.go:1006** | users | `authorIsActive`: `users WHERE id=? AND active`, keyed by the policy author id (from a scoped policy). | P2 hygiene

## 3. GLOBAL-OK (brief)

- **authorization_context_service.go:31-371 (all):** OAuth/Hydra bridge state keyed by server-generated `context_id`, `state`, `hydra_request_uri`, `login_challenge`, or by `hydra_client_id`/`client_id` during the flow. Pre-auth by design. (:371 Save is RISKY only via ApprovePendingRedirects, item 4.)
- **client_auth.go:69/106/117/171/421/433/773:** client authentication at the token endpoint, by client_id and JWKS/secret. The replay cache is global.
- **client_auth.go:231:** workload provider by globally unique `issuer`.
- **client_auth.go:345-352:** federated SA lookup filtered by `providerWS`.
- **actuation_service.go:146-396:** in-cluster agent authenticated by actuation token hash. Every later query is keyed by that source (`discovery_source_id`). applyToAgent uses `inst.DiscoveredAgentID` from a server-created row.
- **enforcement_plan_service.go:123/142/360:** keyed by `src.ID` from the agent-authenticated discovery source (governance_controller.go:1094).
- **hydra_reconciler.go:101-403:** background reconciler across all workspaces (stale DCR cleanup, pending-approval expiry, access-request expiry).
- **governance_jml_worker.go:51, governance_sod_worker.go:54, governance_policy_worker.go:211:** enumerate workspaces, then call workspace-scoped managers.
- **policy_warning_service.go:248-426:** delivery worker claiming rows with SKIP LOCKED. emailOf uses a user id from the warning row.
- **resource_server_onboarding_service.go:557-579:** background PRM re-verify job.
- **oauth_as_service.go:158/264/280/357/423/1489/1549/1640/1846/1941:** DCR/CIMD/RFC 7592 client self-management, authenticated by RAT or by the client itself. Token-endpoint SA lookup is by the authenticated client.
- **oauth_as_service.go:2280:** userinfo enrichment, using a user id from the verified token `sub`.
- **oauth_as_service.go:2752:** native token by `jti`, then `nt.WorkspaceID != workspaceID` returns not found (post-check). The insert into global `revoked_tokens` follows.
- **oauth_as_service.go:889 / :996 and resource_server_service.go:328/336:** RS by id or resource_uri from the auth context or the token `aud`. Used by OAuth flow and introspection (`ValidateIntrospectionCredentials`, authenticated by RS secret).
- **connector_oauth_service.go:184/188:** OAuth callback by opaque `state`. **:573-673:** token refresh on a connection row plus advisory locks.
- **workspace_ciba_service.go:85-116:** CIBA client context by client_id and resource_uri, with an approved-registration check.
- **xaa_service.go:145/329:** trusted issuers (global table) and the ID-JAG replay cache.
- **ciba_auth_service.go:152/203, agent_action_service.go:246/327, voice_auth_service.go:121/282, device_auth_service.go:202:** opaque random request ids. Respond paths post-check user and workspace (ciba :157, agent_action :335).
- **icp_provisioning_service.go:64-155, pki_retry_worker.go:42:** platform provisioning. `icp_tenant_migrations` is not in master migrations.
- **github_graph_projection.go:99/348, iga_classification_service.go:220, connector_oauth_service.go:573/585:** advisory locks / `SET LOCAL`, no data access.
- **iga_service.go:1451 `ResolveBinding(appRegistrationID, installationID)`:** GitHub webhook routing (HMAC-verified delivery).

## 4. Notes

**Scoped helpers.**
- There is no GORM scope or scoped-repository abstraction that applies `workspace_id` automatically. Every service passes `workspaceID` by hand into WHERE clauses.
- The de-facto pattern is a scoped parent fetch (`GetByIDAndTenant`, `First(&x,"id = ? AND workspace_id = ?")`) followed by child operations keyed by the parent id.
- This pattern is used consistently in:
  - the IGA, cloud, governance and discovery code: `repositories.*` methods take `workspaceID` first, and `RunFenced` / `conflictOn` upserts are keyed on `(workspace_id, source_key)`;
  - the newer resource-server, scope and IDP code.
- The older pairs keep an unscoped twin next to the scoped method: `Update`/`UpdateByTenant`, `Delete`/`DeleteByTenant`, `GetByID`/`GetByIDAndTenant`, `RevokeConsent`/`RevokeConsentByTenant`. Most unscoped twins are dead code.

**Markers.**
- There are no `// TENANT-EXEMPT` (or similar) markers in `services/`.
- There are informal comments such as `// SECURITY: only link permissions owned by this tenant ... Never remove this filter` (scope_registry_service.go:262/322) and "no tenant ownership check — kept for internal use" (scope_registry_service.go:280).

**Odd but harmless patterns.**
- `(workspace_id = ? OR workspace_id = ?)` with the same parameter twice, left over from a rollout (resource_server_service.go:221/240/312/665…).
- `workspace_id = ? OR (workspace_id IS NULL AND workspace_id = ?)` (:358) is equivalent to `workspace_id = ?`.
- Platform-global rows are intentionally included via `workspace_id IS NULL`: permissions, roles, sod_rules, platform oidc_providers.

**PDP (scope_resolver.go:294-312, 542-560).** Correctly filters `rb.workspace_id`, `ro.workspace_id`, `p.workspace_id` and `os.workspace_id`, plus the RS scope. Note that the `user_groups` subquery (:302) has no workspace filter; it matters only together with item 11.

**Tables without a tenant column touched here:**
- `services` (extsvc, items 5 and 13)
- `spire_workloads`, `spire_oidc_tokens` (item 23)
- `role_permissions`, `oauth_scope_permissions`, `mcp_tool_scope_map`, `resource_server_drift_events` / `_dismissals`, `oauth_client_secrets` / `_jwks`: all accessed via a scoped parent
- `revoked_tokens`, `client_assertion_replay_cache`, `id_jag_replay_cache` (global by design)

**Dead or legacy code.**
- `icp_tenant_migrations` (icp_provisioning_service.go) is not in migrations.
- `pki_retry_worker.go:82` uses a non-existent column.
- Unused methods:
  - RBACService.{ListPermissions, DeleteRole, GetRole, CheckPrincipalActive, ListEffectiveBindings}
  - ResourceServerService.{Update, Delete}
  - ScopeRegistryService.{Update, Delete, GetByID}
  - ConsentService.RevokeConsent
- `TOTPService.LoginWithTOTP` is a stub, and `AgentActionService.resolveTenantFromClientID` is a stub.
- I did not see `agents`, `workloads`, `workload_entries`, `certificates` or `voice_active_sessions` referenced directly in `services/`. Voice and device paths go through `database/` repositories.

**Test coverage (services/*_test.go, 30 files).**
- Explicit cross-workspace assertions exist only in:
  - `cloud_aws_quickcreate_test.go:261` ("cross-workspace read must be not-found")
  - `gcp_oauth_provision_service_test.go:376` (cross-tenant session burn)
- Seven test files reference `workspace_id`.
- None cover the P0 paths: SPIFFE SA resolution, OIDC provider admin, claim/provision with a foreign client, approve-redirects, extsvc SPIFFE credentials.

Artifacts:
- `scratchpad/sqlx_b/final.tsv` (all 574 statements with function and chain text)
- `scratchpad/sqlx_b/repocalls.txt`
- `scratchpad/sqlx_b/tally.py` (classification sets)
