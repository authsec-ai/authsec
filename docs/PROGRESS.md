# AuthSec — Progress Log

Newest first. Each session records what was done, what was learned, and what's next.

---

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
