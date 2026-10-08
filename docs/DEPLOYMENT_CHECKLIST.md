# Deployment checklist: multi-tenancy program (fix/p0-containment + feat/ui-voice-perf)

For the manual deployment that precedes pushing these branches. Work top to
bottom; each step says how to tell it worked. Background: `docs/PROGRESS.md`
(session logs and release notes), `docs/ISSUES.md` (what each change fixes),
`docs/adr/0001-tenancy-model.md`.

## 1. Before you deploy

- [ ] **Back up the production database** (or snapshot it), and note the time.
- [ ] **Rehearse the upgrade on a copy of production.** Restore the backup into
      a throwaway database and start this build against it once:
      the log must end with `[Migration] master done: N applied, 0 failed`.
      Migrations 101–119, 130 (and the SPIRE migrations 120+, if present) apply
      on top of staging's 002–046. `scripts/schema-parity.sh <binary> <copy>`
      then confirms a fresh install and the upgraded copy end with the same
      schema.
- [ ] **Database roles** (row-level security, ADR-0001 §4.4):
  - Migration 111 creates the role `authsec_tenant` (NOLOGIN, NOBYPASSRLS) and
    grants the application user membership. If the application user may not
    create roles, the migration logs a NOTICE: run `scripts/create-tenant-role.sql`
    once as a superuser, then restart.
  - Check: `SELECT rolname FROM pg_roles WHERE rolname = 'authsec_tenant';`
    returns one row, and `SELECT pg_has_role(current_user, 'authsec_tenant', 'member');`
    is `t` for the application user.
  - Optional, later: the `authsec_platform` BYPASSRLS role (ADR §4.4) needs a
    superuser and is not required for this release.
- [ ] **Production must NOT have `ENABLE_EMBEDDED_SPIRE=true`** unless the
      AS-081 work (embedded SPIRE made multi-tenant) is part of this build.
      Without it, startup refuses that flag in production.

## 2. Configuration

Set or confirm (names only; values from your secret store):

| Setting | Why |
|---|---|
| `TOTP_ENCRYPTION_KEY` | Must be valid hex in production, or startup fails. |
| `NATIVE_RSA_PRIVATE_KEY_B64` or a working Vault | With `ENVIRONMENT=production` and an ephemeral signing key, startup fails. |
| `CORS_ALLOW_ORIGIN`, `BASE_URL`, `TRUSTED_PROXIES` | Host, Origin and X-Forwarded-Host count only for allow-listed hosts; forwarding headers only from `TRUSTED_PROXIES`. |
| `AUTH_LOCKOUT_MAX_FAILURES`, `AUTH_LOCKOUT_WINDOW`, `AUTH_LOCKOUT_DURATION` | Account lockout (defaults apply if unset). |
| `METRICS_TOKEN` or `METRICS_ADDR` | Metrics are not exposed otherwise. |
| `OUTBOUND_ALLOWED_HOSTS`, `OUTBOUND_ALLOWED_CIDRS` | Only if a tenant-configured URL must reach a private address (SSRF guard). |
| `ICP_SERVICE_URL` | Required in production when SPIFFE SVIDs are used. |
| `IGA_DISCOVERY_INGEST_AUTH` | `warn` (default) accepts and logs unauthenticated discovery reports; set `enforce` once every collector has an ingest token. |
| `XAA_NATIVE_SEALER` | Required if any XAA issuance flag is on. |

Removed settings (delete if present): `ADMIN_CROSS_TENANT_ACCESS`,
`DISCOVERY_ALLOW_UNAUTHENTICATED_INGRESS`.

Development-only settings that must never be set in production:
`SPIRE_K8S_INSECURE_SKIP_TOKEN_VERIFY`, `SPIRE_DEV_MTLS_BYPASS`,
`CIBA_ALLOW_UNAUTHENTICATED_CLIENTS` (a temporary opt-out for SDKs that cannot
yet send a client secret).

## 3. Deploy

- [ ] Backend from `fix/p0-containment`, UI from `feat/ui-voice-perf`.
- [ ] Watch the backend log for `[Migration] master done: … 0 failed` and no
      `CRITICAL` line.
- [ ] `GET /authsec/healthz` → 200, `GET /authsec/readyz` → 200.

## 4. Verify (smoke)

Use two workspaces (A and B) with an admin each.

- [ ] **Admin sign-in end to end** (password → MFA → console), including a
      **passkey registration on Windows Hello**: the forged-attestation fallback
      was removed, so that path must work through the real ceremony.
- [ ] **Second workspace sign-up** works (the single-tenant guard is gone).
- [ ] **Isolation:** as A, open a URL that names B's workspace id or one of B's
      objects (user, group, application, agent). Every one is **404**.
- [ ] **Workspace switcher** (an operator with memberships in both): switching
      clears the old workspace's data before the new one loads.
- [ ] **End-user registration**: `/user/register` starts and emails an OTP; the
      account exists only after `/user/register/complete`.
- [ ] **OTP codes** issued before the deploy no longer verify (users request a
      new one); expected.
- [ ] **Agent flow:** an agent client gets a token for its own workspace's
      application; the e2e "agent books a flight" scenario
      (`tests/integration/flows/e2e_agent_books_flight_test.go`) describes it.
- [ ] **CIBA** (workspace surface) with HTTP Basic client authentication.
- [ ] **Voice assistant backends** authenticate with OAuth client credentials.
- [ ] **SAML IdPs** must sign responses; check one SAML sign-in.
- [ ] **Discovery collectors** keep reporting (warn mode); mint ingest tokens
      (`POST /authsec/discovery/ingest-tokens`) for each, then plan `enforce`.
- [ ] **Resource servers:** registering a URL another workspace already uses
      now requires a verified domain covering its host (expected 409 otherwise).
- [ ] **Admin MFA status** callers send `workspace_id` (the console does).

## 5. After the deploy

- [ ] Run `psql "$DATABASE_URL" -X -f scripts/tenancy-validate.sql` (read-only).
      It lists rows that violate the NOT VALID workspace constraints from 105
      and the statements to validate them once clean. Resolve rows in
      `tenancy_backfill_orphans`; never assign rows to a guessed workspace.
- [ ] **AS-097:** once no running server writes `sync_configurations.entra_workspace_id`,
      the contract migration (drop the old column and its trigger) can ship.
- [ ] **AS-098:** rotate any secret from the old tracked `.env` that was ever
      used outside local development (the values remain in git history).
- [ ] **OPS-001:** add required reviewers to the GitHub Environment
      `production` in both repositories.
- [ ] Switch `IGA_DISCOVERY_INGEST_AUTH=enforce` when every collector has a token.

## 6. Rolling back

The migrations are forward-only and idempotent; they add columns, tables,
constraints (NOT VALID), indexes, policies and one trigger, and remove the
global unique indexes on `resource_servers.resource_uri` and
`workload_identity_providers.issuer`. The previous build runs against the
migrated schema except where it relied on those two global uniques or on
the removed legacy routes. To roll back the application, redeploy the previous
image; to roll back the schema, restore the backup from step 1.
