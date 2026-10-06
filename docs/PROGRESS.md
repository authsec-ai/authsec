# AuthSec — Progress Log

Newest first. Each session records what was done, what was learned, and what's next.

---

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
