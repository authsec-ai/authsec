# AuthSec — Progress Log

Newest first. Each session records what was done, what was learned, and what's next.

---

## 2026-10-07 (cont. 2) — P2/P3 burn-down, schema parity, ratchet

Branch `fix/p0-containment` (backend) and `feat/ui-voice-perf` (UI); nothing pushed.

### Done
- **AS-065:** SPIFFE SVIDs are verified by kid against the workspace bundle, and the tenancy context is set (`0b0ec03`).
- **AS-076:** PSAT verification is never switched off by `ENVIRONMENT`; skipping it needs an explicit flag (`e65fff6`).
- **AS-078:** admin WebAuthn and MFA status act in the signed-in workspace (`4fb6ccd`, `9291044`; UI `b1faa55`). Before this fix, an admin could get passkey-registration options for another workspace's account with the same email.
- **AS-079:** platform rows are `workspace_id IS NULL`, with a CHECK against new system-workspace rows (055, `456ffd4`).
- **AS-080:** `scripts/schema-parity.sh` shows that a fresh bootstrap and an upgraded DB end with the same schema. 069 adds the two indexes the upgrade path had missed (`456ffd4`).
- **AS-081:** embedded SPIRE is refused at startup in production and staging (`deb5645`).
- **AS-094:** dead config and code deleted, about 930 lines (`04eeb37`).
- **AS-097:** expand step for `entra_tenant_id` (070, `a44fa5a`).
- **AS-060:** the ADR records why four uniques stay global for now, and the steps to finish (`87aec78`).
- **Ratchet:**
  - It now skips RLS-only packages and statements handed to the scoped layer (`538b92d`, `ef6c39a`).
  - SCIM writes moved onto the scoped layer (`24ef0e7`).
  - 445 → 303.
- **IGA FK catalog test** updated for 047 (`2bd9077`).

- **Ratchet 303 → 175.** The admin controllers, the platform and end-user controllers, and the OAuth AS follow-up statements moved onto the scoped layer, plus most repositories. Statements that run before a workspace is known carry specific TENANT-EXEMPT reasons. The parallel agents found and fixed three cross-tenant or broken-flow bugs:
  - AS-099: admin sign-up could take over another workspace's pending domain (`946237b`).
  - AS-100: AD/Entra sync never created memberships (`64ccc89`).
  - AS-101: end-user sign-up deleted other workspaces' pending registrations (`30d546a`).
  Eight unrouted legacy `UserController` handlers were also deleted (`3dabc45`).
- **Interrupted:** two of the three agents hit the spend limit. Their committed work is merged and verified (build, vet, unit, flows, onboarding and flagsoff all pass). Left to do: `services/oauth_as_service.go`, `scope_resolver.go` and `governance_certify_service.go`, and `database/voice_auth_repository.go`, `agent_action_repository.go`, `ciba_auth_repository.go` and `user_repository.go`. A half-finished voice repository change was not taken.

### Verification
- Build, vet and unit tests pass.
- The flows, onboarding, flagsoff and igagraph suites pass.
- Migrations 055, 066–070 were rehearsed on clones of the scratch DB; all are idempotent.
- Schema parity: fresh == upgraded.

### Release notes (deploy)
- **Migrations:**
  - 055: platform rows. The `migrations:*` permissions are removed, and every workspace admin role gains `users:read` and `users:write`.
  - 069: indexes.
  - 070: `entra_tenant_id`, kept in sync with the old column by a trigger.
- **New or changed settings:**
  - `SPIRE_K8S_INSECURE_SKIP_TOKEN_VERIFY` and `SPIRE_DEV_MTLS_BYPASS`: development only.
  - `ICP_SERVICE_URL` is required in production when SPIFFE SVIDs are used.
  - `ENABLE_EMBEDDED_SPIRE` is refused in production and staging.
  - `ADMIN_CROSS_TENANT_ACCESS` is removed; nothing read it.
- **Admin MFA status:** send `workspace_id`. Without it, an email that exists in more than one workspace now gets a 400.

### Needs the owner
- AS-098: `.env` is tracked with dev secrets. Confirm that no environment uses these values, then untrack the file.
- AS-081: fix or remove the embedded SPIRE control plane.
- AS-015: retire legacy `/uflow/auth/ciba` (needs a Python SDK change).
- AS-097: run the contract migration after the next deploy.
- OPS-001: the deploy-on-push process.
- ENV-001: the root-owned Go module cache (needs `sudo`).

---

## 2026-10-07 (cont.) — Data layer, auth P0/P1 remainders, IGA reads

Same branch (`fix/p0-containment`), nothing pushed.

### Done
- **Scoped layer:**
  - Legacy CIBA, device codes, TOTP devices, and the workspace-plane devices, CIBA and TOTP repositories (`b8cf865`, `4a4c2a2`, `5489e6f`, `84b80ac`).
  - The unused `EndUserRepository` was deleted (`143f93d`).
  - IGA graph and Kubernetes graph reads take the workspace from the tenant context and run under RLS (`28c92ca`, `b940571`).
  - Ratchet 464 → 445.
- **Auth and security:**
  - AS-014 (`fa5a39c`)
  - AS-044 and AS-015 (`53e8b81`)
  - AS-018 (`09a8bff`)
  - AS-025 (`21396a2`)
  - AS-038 (`f77562e`)
  - AS-064 (`ea07bb1`)
  - AS-083 (`e7ead9d`)
  - AS-095 (`6a243ce`)
- **Fixes found while merging:**
  - A `//` TENANT-EXEMPT note inside a SQL string broke admin sign-up (`6b5a98a`).
  - The IGA FK catalog test now covers 047's `cloud_*` workspace keys (`2bd9077`).

### Verification
- Build, vet and unit tests pass.
- The flows, onboarding, flagsoff and igagraph suites pass.
- The ratchet is at 445 against a baseline of 446.
- Migrations 066–068 were applied twice to a clone of the scratch DB: they apply cleanly and are idempotent.
- `001_bootstrap.sql` applies to an empty DB and reaches the same end state.

### Release notes (deploy)
- **Migrations:**
  - 066 adds `workspace_ciba_auth_requests.resource_server_id`.
  - 067 adds `discovery_collector_tokens`.
  - 068 adds `otp_entries.workspace_id` and `purpose`.
- **Discovery collectors:** collectors without an actuation token stop reporting. To keep them reporting, do one of these:
  - mint a collector token (`POST /authsec/discovery/collector-tokens`) and set it as `controlPlane.sourceToken`;
  - set `DISCOVERY_ALLOW_UNAUTHENTICATED_INGRESS=true`.
- **CIBA:** workspace CIBA needs HTTP Basic client authentication. `CIBA_ALLOW_UNAUTHENTICATED_CLIENTS=true` is a temporary opt-out.
- **Registration:** `POST /uflow/user/register` now only starts registration. The account is created by `/user/register/complete` with the emailed OTP.
- **OTP codes:** codes issued before the upgrade no longer verify. Users request a new one.
- **Host checks:** Host, Origin and `X-Forwarded-Host` count only for allow-listed hosts. Set `CORS_ALLOW_ORIGIN`, `BASE_URL` and `TRUSTED_PROXIES` correctly.

### Still open
- AS-015: retire legacy `/uflow/auth/ciba` (the Python SDK has no client secret).
- AS-060, 065, 076, 078, 079, 080, 081, 094, 097.
- The ratchet's remaining 445 raw statements.
- UI-033, OPS-001, ENV-001.

---

## 2026-10-07 — Voice tables, row-level security, remaining areas and P2/P3

**Owner asked for:** build the voice-auth tables; switch on RLS; move the remaining areas onto the scoped layer and work through P2/P3. Committed locally on `fix/p0-containment` (backend) and `feat/ui-voice-perf` (UI, stacked on `fix/ui-integrations`); nothing pushed.

### Done
- **Voice auth (AS-047), `208d8e7`:**
  - Migration 053 adds `voice_active_sessions`.
  - The voice flow was unsafe as well as broken, so voice backends must now authenticate as an OAuth client of the workspace, and a session belongs to its client.
  - UI watcher re-mounted (`d773999`).
- **Row-level security (AS-050), `978e8d7`:**
  - Migration 054 enables and forces the `tenancy_isolation` policy on all 163 workspace tables.
  - `internal/tenancy` transactions set `app.workspace_id` and `SET LOCAL ROLE authsec_tenant`, because superusers bypass RLS.
  - A test fails if any workspace table lacks the policy.
- **Multi-tenant sign-up (AS-030), `c9b6b11`:** single-tenant guard removed; a second workspace signs up end to end.
- **Scoped-layer migration:**
  - Admin users, seeding, the workspace registry, end-user lookups and sign-up writes (`f397c7a`, `fd643db`).
  - Ratchet 482 → 464.
- **P1/P2 fixes:** AS-033, 034, 004, 036, 042, 061, 067, 071, 072, 073, 075, 082, 096. See `ISSUES.md`.
- **UI:** route-level code splitting (UI-034).

### Interrupted
- All three parallel agents hit the account spend limit.
- Their committed work was merged and verified after each set (build, vet, unit, all integration suites, upgrade rehearsals 053, 054 and 065, each 0 failed).
- Small uncommitted remainders were finished and verified here: the AS-061 connection-grant check, and the SSRF client.
- One large uncommitted remainder was **discarded**: the database/ device, CIBA, TOTP and OTP repositories moved onto the scoped layer. It conflicted with the newly merged TOTP lockout code and was untested. That migration is still to do.

### Release notes (deploy)
- **Row-level security:** run `scripts/create-tenant-role.sql` if migration 054 logged that it could not create `authsec_tenant`.
- **New settings:**
  - `TRUSTED_PROXIES` (unset means forwarding headers are ignored)
  - `AUTH_LOCKOUT_MAX_FAILURES`, `AUTH_LOCKOUT_WINDOW`, `AUTH_LOCKOUT_DURATION`
  - `METRICS_TOKEN` or `METRICS_ADDR` (otherwise metrics are not exposed)
  - `OUTBOUND_ALLOWED_HOSTS`, `OUTBOUND_ALLOWED_CIDRS`
- **Startup now refuses to run when:**
  - `ENVIRONMENT=production` and the native signing key is ephemeral, unless Vault works or `NATIVE_RSA_PRIVATE_KEY_B64` is set;
  - XAA issuance flags are on without `XAA_NATIVE_SEALER`.
- **Behaviour changes for clients:**
  - Voice assistant backends must use OAuth client credentials.
  - Session tokens are now class-bound: admin tokens work on the console, end-user tokens on self-service, SDK tokens on the SDK surface. Tokens issued before this change keep working until they expire.

### Still open
- AS-014: per-workspace collector credentials.
- AS-015/044: CIBA client authentication.
- AS-018, AS-025, AS-038: remaining parts.
- AS-060: global `resource_uri` and issuer uniques.
- AS-064, 065, 076, 078, 079, 080, 081, 083, 094, 095, 097.
- The ratchet's remaining 464 raw statements.
- UI-033: `Tenant*` naming.
- OPS-001: deploy-on-push process.
- ENV-001: local Go module cache owned by root (needs your `sudo`).

## 2026-10-06 (cont.) — Phases 1–6 run back to back (owner: "complete each phase and commit, do not push")

**Branches (local only, nothing pushed):**
- Backend: `fix/p0-containment`, about 50 commits on top of `authsec-staging`.
- UI: `fix/p0-admin-login-ticket` → `chore/ui-stabilize` → `feat/ui-tenancy` → `fix/ui-integrations`. Each branch is stacked on the previous one; the tip is `fix/ui-integrations`.

### By phase
- **P0 containment (before Phase 1).**
  - Sign-in chain: login tickets.
  - The token's workspace is enforced on path, query and body.
  - User management and SCIM need owner/admin.
  - Global listings are scoped, and password hashes are never serialized.
  - OTPs no longer echoed; the TOTP key and its rotation are fixed; secrets are out of logs.
  - Token exchange requires client authentication.
  - Issuers and SPIFFE providers are scoped to a workspace.
  - SAML signatures are verified; legacy CIBA, registration and OIDC paths are scoped.
  - Discovery, provisioning, redirect approval, extsvc and delegation-token lookups stay in their workspace.
  - OIDC sign-in is a first factor only.
  - Policies enforced by default; session revocation and logout; audit persistence; one reconciler leader across replicas.
- **Phase 1:** `docs/adr/0001-tenancy-model.md`.
- **Phase 2:**
  - Default tests green without local services.
  - `go mod tidy`.
  - `deploy/dev` stack (Postgres, Hydra, Vault) and a `Makefile`.
  - `/authsec/healthz` and `/authsec/readyz`.
  - `internal/tenancy` scoped layer.
  - `TwoTenants` isolation harness.
  - TENANT-EXEMPT ratchet wired into CI.
  - UI type-check and lint at 0 errors.
- **Phase 3:**
  - Migrations 045–048: missing `workspace_id` columns, backfill with orphan report, FKs and NOT NULL added NOT VALID, per-workspace uniques. Plus 050 (session revocation), 051 (audit append-only) and 052 (`users:delete` for admins).
  - Per-request membership re-check.
  - Users and identity domain moved onto the scoped layer.
  - Agent/resource-plane fixes.
  - Isolation tests per endpoint for users, groups, RBAC, password reset, sync/SCIM and the agent plane.
  - Ratchet 487 → 482.
- **Phase 4 (UI):**
  - Workspace from token claims.
  - Full cache reset on identity change, cross-tab and logout, plus server-side logout.
  - Workspace switcher (backed by `GET /authsec/workspaces`).
  - OIDC `state_token`.
  - About 12 broken integrations fixed.
  - Global 401 handler, not-found states, HubSpot token leak closed.
- **Phase 6 (in part):**
  - `tests/integration/flows/e2e_agent_books_flight_test.go`: the two-tenant flight-booking story.
  - Unscoped-SQL sweep: 482 statements remain outside the layer. By area: database 107, igaread 84, controllers/admin 62, services 51, controllers/platform 47, repository 46, other 85. 9 TENANT-EXEMPT markers.

### Verification at the end
- **Backend:** `go build`, `go vet` and `go test ./...` green. Integration flows, onboarding and flags-off green. Ratchet at its baseline.
- **Upgrade rehearsals on the scratch DB:** 043 → 052 applied, 0 failed.
- **UI:** type-check 0 errors, lint 0 errors (572 warnings), 26 files / 165 tests pass, build OK.

### Not done / needs a decision
- **RLS** is not enabled on tables yet. It needs the application/owner DB role split (ADR §4.4) and a deploy change.
- **Caller migration** is finished for users and identity only. The other domains are still scoped by hand, and the ratchet tracks them.
- **Interrupted agents.** Two delegated agents stopped on the account spend limit. Their committed work was merged and verified; the users-domain work-in-progress was finished by hand and verified.
- **Phase 5 leftovers:** open P2/P3 rows in `docs/ISSUES.md`, e.g. AS-047 voice tables, AS-060 global `resource_uri`/issuer squatting, AS-079 platform-row convention, AS-080 bootstrap drift, AS-014 per-workspace collector credentials, AS-015 legacy CIBA client authentication.
- **Release notes required:**
  - TOTP key must be valid hex in production (startup fails otherwise).
  - Collectors with actuation must set `controlPlane.sourceToken`.
  - The Python SDK's legacy CIBA call must send `client_id`.
  - SAML IdPs must sign responses.
  - Run `scripts/tenancy-validate.sql` after the 047 deploy.
  - Test passkey registration on Windows Hello.
- **Housekeeping:**
  - Agent worktrees remain under `.claude/worktrees/`, which git ignores; remove them with `git worktree remove`.
  - Containers still running: `authsec-audit-pg` and the `authsec-dev` compose stack.

## 2026-10-06 (cont.) — P0 containment track, item 1: interactive sign-in chain (AS-001/002/003/029, UI-001)

**Status:** done, pending your review. **Uncommitted** on backend branch `fix/p0-containment` and UI branch `fix/p0-admin-login-ticket`. Nothing is pushed. You approved the two edits the permission classifier had blocked.

### What changed
- **Login tickets.**
  - Migration `043_login_tickets.sql`, with the same end state in `001_bootstrap.sql`, plus a new package `internal/logintickets`.
  - Tickets are opaque, stored as SHA-256 hashes, last 15 minutes, are single use, and carry a realm (`admin` or `enduser`).
- **Issued only after a server-verified first factor:**
  - admin: `/uflow/login`, `/auth/admin/login` (when MFA is required), the OIDC admin login response
  - end user: `/uflow/user/login`, `/uflow/user/oidc/login`, the SAML ACS redirect
  - **Never** issued by the anonymous `/uflow/user/saml/login` (AS-029).
- **`middlewares.RequireLoginSubject`** gates every enrolment and verification route under `/authsec/webauthn/*`: admin, end-user, legacy, biometric, TOTP and SMS.
  - It accepts a ticket or a Bearer session, and body or query `email`, `workspace_id` and `user_id` must match it.
  - A 2xx from a verify route marks the ticket as MFA-verified.
  - `mfa/status` and `mfa/loginStatus` stay open for the Python SDK.
- **Both `webauthn-callback` endpoints** mint only by consuming a verified ticket of their realm, for that ticket's subject.
- **The forged-attestation fallback is deleted** (`handlers/fallback.go`, plus its uses in all three handlers).
- **CORS** allows `X-Login-Ticket`.
- **UI:**
  - `src/auth/loginTicket.ts` provides `withLoginTicket`, applied to `baseApi`, `userAuthApi` and `oidcApi`: it sends the header on MFA and callback URLs, captures `login_ticket` from responses, and clears the ticket after a successful callback.
  - `main.tsx` picks up the ticket from the SAML redirect URL.

### Verification
- **Backend:** 9 new integration tests (`tests/integration/flows/{admin,enduser}_login_ticket_test.go`), all pass.
  - Full flows suite: only the pre-existing `Test_MCP_RegisterDiscoverActivate` failure.
  - `go test ./...`: only the 3 known "no Postgres on :5432" failures.
  - `go build` and `go vet` are clean; gofmt is clean on every changed hunk.
- **Upgrade rehearsal:** the audit's scratch DB (at 042, with data) applied 043 with "1 applied, 0 failed". The Phase-0 live exploit now returns 401.
- **UI:** 5 new vitest tests; full suite 14 files / 123 tests pass; `vite build` OK; tsc error count unchanged (197, pre-existing); no new lint errors.
- **Not tested end to end:** a real browser WebAuthn ceremony, and a SAML IdP round-trip. ⚠️ Check Windows Hello passkey registration manually; the deleted fallback existed for it.

### Next
- Review, then commit (one commit per repo).
- Continue the P0 list: AS-006 (body `workspace_id`), AS-009, AS-019, AS-007/008/023, AS-010/011/012, …

## 2026-10-06 — Phase 0: Discovery and audit (read-only)

**Status:** complete, awaiting approval to start Phase 1 (ADR-0001).

### Done
- Read CLAUDE.md and AGENTS.md. The workspace-level `../AGENTS.md` and `../.claude/DEFINITION-OF-DONE.md` that AGENTS.md references **do not exist** in `merger/`.
- Mapped both repos: stack, entry points, config, DB, migrations, auth, tests, CI. Filled the `<!-- FILL -->` sections of CLAUDE.md.
- Built, vetted, tested and ran the backend against a scratch Postgres 16 container (`authsec-audit-pg`, `127.0.0.1:55432`, throwaway). Built, tested, type-checked, linted and started the frontend dev server.
- Ran a smoke test over HTTP: register → OTP → complete → login for workspace A. To get a second workspace past the single-tenant guard, flipped A's `status` to `inactive` **in the scratch DB only**, registered B, then flipped A back.
- Reproduced three cross-tenant P0s at runtime (AS-001, AS-006, AS-009) and several other issues.
- Traced the multi-tenancy history: DB-per-tenant → extracted to `mt-plugin` (`764a654`) → single-tenant substrate (`69c82a3`) → tenant model removed, workspace replaces tenant (`05e289d`).
- Ran parallel read-only audit agents (schema, request context, data access ×6 parts, tokens and runtime authz, core flows ×4 parts, frontend). Their reports are kept verbatim under `docs/audit/`.
- Wrote `docs/AUDIT.md`, `docs/ISSUES.md` (about 95 rows) and this log.

### Learned
- The tenant is the **workspace**. A shared DB with `workspace_id` is about 82% present at the schema level, but enforcement is manual, inconsistent and absent in the older uflow, WebAuthn, CIBA, OIDC and SAML code.
- The admin UI login currently depends on the AS-001 bypass, so it has to be fixed together with the UI (UI-001).
- Without Vault, every backend restart invalidates all tokens (ephemeral native keys and HS secrets); expect this in local testing.
- Admin-auth endpoints are rate-limited to 5/min per IP across register and login, which matters when scripting tests.

### Housekeeping
- `go.mod` was found modified mid-session (a `go mod tidy`-style reclassification, likely from an audit sub-agent). It was **reverted** to HEAD to keep Phase 0 read-only, and logged as AS-091.
- The pre-existing uncommitted edit to `CLAUDE.md` (the new template) was kept; only its FILL sections were completed.
- The scratch container `authsec-audit-pg` is still present (data: the two test workspaces). Remove with `docker rm -f authsec-audit-pg` when no longer needed.
- Nothing was committed or pushed.

### Next
- Waiting for approval. Proposed next steps:
  1. Decide whether P0 containment (AS-001…AS-028) runs **before** Phase 1/2 as a hotfix track, or inside Phase 3/5.
  2. Phase 1: ADR-0001 tenancy model.
- Open questions for the user:
  - Can a user belong to several workspaces (memberships plus switching), or exactly one?
  - Is a platform super-admin realm needed?
  - Are the legacy uflow, CIBA and oocmgr endpoints still used by any client other than this UI (SDKs, demos)? If not, delete them rather than fix them.
  - Is the TOTP key typo (AS-020) still live in prod, and can we schedule a re-encryption migration?
  - Should `ENV-001` (root-owned Go module cache) be fixed with `sudo chown`?
