# AuthNull / AuthSec — Agent entrypoint

> **Read this first.** Orientation for any engineer or AI coding assistant working in
> `~/Desktop/authnull`. This is the workspace map + the rules + the product's mental
> model. Each repo has its own `AGENTS.md` with specifics (nearest file wins).
> `AGENTS.md` is the cross-tool standard; `CLAUDE.md` in each repo just points here.

## What AuthSec is

An **agent-first identity & authorization layer for AI / MCP**. It fronts ORY Hydra to
speak OAuth 2.1 / OIDC and sits in front of MCP servers ("applications" / resource
servers) so every caller — a human **user**, a **service account** (M2M), an **agent**
(acting on behalf of a user), or a **workload** (k8s pod with a SPIFFE SVID) — gets a
scoped, auditable token.

## Repos in this workspace

| Repo | Role | Stack | Start here |
|------|------|-------|-----------|
| `authsec` | **Core backend** — auth/authz, OAuth AS, RBAC, API. Fronts ORY Hydra. One Postgres DB. | Go / Gin | `authsec/AGENTS.md` |
| `Authsec-ui` | **Production console** (admin UI at app.authsec.ai) | Vite + React + TS + Tailwind v4 + shadcn | `Authsec-ui/AGENTS.md` |
| `sdk-authsec` | Client **SDKs** (go / python / typescript) + examples — ~3-line MCP/agent integration | Go, Python, TS | `sdk-authsec/AGENTS.md` |
| `deploy/single-node` | **DEPRECATED** — old local Docker Compose stack (was mcpauthz.com). Live deploy is now on Hetzner VM via Jenkins CI/CD | Docker Compose | `deploy/single-node/AGENTS.md` |
| `authsec-charts` | Helm charts for **staging / AKS** | Helm | `authsec-charts/AGENTS.md` |
| `authsec-doc` | Public **documentation** site | Docusaurus | `authsec-doc/AGENTS.md` |
| `authsec-agent-shield` | **Separate product** — system-level guard for risky AI tool actions (phone-approve `rm -rf`, `DROP TABLE`) | — | `authsec-agent-shield/AGENTS.md` |
| `UI` | **LEGACY — do not edit.** Production console is `Authsec-ui`. If grep or file search leads you here, find the equivalent file in `Authsec-ui/` instead. `UI/AGENTS.md` explains the redirect. | — | **Stop. Go to `Authsec-ui/`.** |
| `claw-auth` | Legacy / secondary. Don't touch unless told. | — | — |

## Rules that don't change

> **Scope:** everything here is **project-scope** — it applies to anyone (human or
> agent) touching this codebase. An individual's own preferences and tool permissions
> are **personal-scope** and live in that assistant's private memory, not in this file.

**Engineering practice**
- **Keep the codebase clean.** Don't add code that isn't needed — no dead scaffolding, no speculative abstractions, no duplicate helper when one already exists. Reuse before you add; delete what a change makes obsolete.
- **Fix surgically, never band-aid.** Diagnose the root cause with the whole architecture + product behaviour in mind, then make the minimal correct change. Don't patch the first symptom, and don't stack a workaround on a workaround — if a fix needs a structural change, do the structural change.
- **Don't add tests** unless explicitly asked; verify with the repo's `tsc` / `vet` / build + a manual smoke.

**Guardrails**
- **`git push` is the only action that needs explicit per-command approval.** Everything else (kubectl, docker, edits) is pre-authorized.
- **Schema is single-state, forward-only:** edit the `CREATE TABLE` in `authsec/migrations/master/001_bootstrap.sql` in place, then wipe + re-bootstrap. Never add `ALTER TABLE` patch files or `AutoMigrate`.
- **Everything is workspace-scoped** (see *Ownership model*) — new code scopes by `workspace_id`.
- **UI:** every console page renders through `ConsolePage`; primary `<Button>` is white-on-blue; verify with `npx tsc --noEmit` (+ `eslint`), **not** a dev server (authenticated routes need the backend).
- Use **market-standard terms** (User / Service Account / Agent / Workload / Application·Resource Server / Scope / Workspace) — see per-repo files.

## Ownership model

The data model is **workspace-centric**: a Workspace owns everything inside it.

- **User** — belongs to a Workspace through a **WorkspaceMembership**.
- **Workspace** — owns its **Applications**, **Identity Providers**, **Users / Groups**, **Roles / Permissions / Scopes**, **SCIM Connections**, and **Audit Logs**.
- **Application** (`resource_servers`, `workspace_id NOT NULL`) — the protected thing. `application_type` ∈ **MCP Server · AI Agent · Clawbot · API Service**. Has **Tools**, **OAuth Scopes**, an **Access Policy**, **OAuth Client Registrations**, and **may have a SPIFFE Identity**.
- **OAuth Client** (`mcp_oauth_clients`) — belongs to a Workspace (`home_workspace_id`) but is **only a protocol caller**: a `client_id` mapped to a Hydra client. An Application registers one or more. A client whose home is workspace A can still call an Application in workspace B — that's XAA (see Flows).
- **Identity Provider** — belongs to one Workspace; can be enabled for one or more Applications.

## Identity model

| Identity | What it is | Auth | Lives where |
|---|---|---|---|
| **User** | human via browser | OIDC login | a workspace |
| **Service Account** | machine M2M | client secret or private-key JWT | the **RS's** workspace |
| **Agent** | acts *on behalf of a user* across apps | XAA / ID-JAG | the user's home workspace |
| **Workload** | k8s pod, no long-lived secret | SPIFFE SVID | a SPIRE trust domain |

## Flows (the mental model) — implemented in `authsec`

- **M2M** (`grant_type=client_credentials`) — `client_secret_basic` *or* `private_key_jwt` (RFC 7523). Mints a **native** token (NativeSealer JWT, no Hydra round-trip). The machine client must live in the RS's workspace. → `oauth_as_controller.go` (tokenClientCredentialsGrant), `services/client_auth.go`.
- **XAA / ID-JAG** (cross-app, agent on behalf of user) — login (`authorization_code`) → **token-exchange (RFC 8693)** → ID-JAG assertion → **`jwt-bearer` (RFC 7523)** → scoped access token at the target RS. **Boundary = requesting client ≠ target RS** (a registered resource server); **workspace equality is NOT the gate** (the old §19 same-domain rejection was removed). First contact → `access_pending` → approve-with-role (atomic binding). → `oauth_as_controller.go` (tokenJWTBearerGrant), `services/xaa_service.go`.
- **SPIFFE / SVID workloads** — SPIRE issues **X.509-SVID (mTLS)** + **JWT-SVID**; the pod presents its JWT-SVID at `/oauth/token`; SPIRE's OIDC discovery provider federates it (own `jwks.json`). → `internal/spire`, `/authsec/spiresvc/*`, single-node `docker-compose.spire.yml` + `spire/`.
- **Federation** — **trusted issuers** (external IdP assertions accepted for XAA), **workload identity providers** (multi-cluster SPIFFE + OIDC/CI e.g. GitHub Actions OIDC), **A2A brokering policies** (cross-app permit/deny). → `/authsec/{trusted-issuers,workload-identity-providers,brokering-policies}`, `/authsec/oidc/*`.
- **MCP discovery & dynamic registration** — RFC 7591 `/oauth/register` + RFC 7592 management; discovery at `/.well-known/oauth-authorization-server` (RFC 8414) + `/.well-known/openid-configuration`; resource-server metadata + `/resource-servers/:id/sdk-policy`.
- **RBAC & scopes** — roles → scope grants → bindings (user / group / service_account) → `ResolvePrincipalEffectiveScopes`. Approve-with-role is the atomic bind step. → `services/scope_resolver.go`, rolesApi/bindingsApi.
- **Token engine & discovery** — native NativeSealer JWTs (persisted RSA key, env fallback `NATIVE_RSA_PRIVATE_KEY_B64`) **vs** ORY Hydra; **JWKS union** (native + Hydra + SPIFFE) at `/oauth/jwks`; `/oauth/introspect`, `/oauth/revoke`, `DELETE /tokens/:jti`, agent `revoke-identity` / `revoke-token`. → `internal/tokens`.

## Deploy

- **Production = `app.authsec.ai`** — Docker Compose on Hetzner VM (`192.168.122.252` behind hypervisor `49.12.150.218`).
  - **CI/CD:** Push to `authsec-staging` branch → GitHub webhook → **Jenkins** (`jenkins.authsec.ai`) auto-builds Docker image → deploys.
  - **TLS:** Let's Encrypt wildcard cert (`*.authsec.ai` + `*.app.authsec.ai`) on root VM Nginx.
  - **Tenant subdomains:** `<workspace>.app.authsec.ai`.
  - Admin login OTP appears in the **backend logs** (`docker logs authsec-backend`).
  - Env config: `/opt/authsec/.env` on the VM (SSH to edit, then `docker compose up -d` to apply).
- **Staging = Azure AKS** (cluster `authsec`, ns `authsec-staging`); separate Helm-based deploy via `authsec-charts`.
- **Schema changes:** Tiered approach — see `/schema-change`. Minor = direct SQL. Major = delta migration. Destructive = backup + wipe (last resort).
- **Developer access:** SSH via `ssh -J root@49.12.150.218 ubuntu@192.168.122.252`. DB: `docker exec -it authsec-postgres psql -U authsec -d authsec`. Logs: `docker logs authsec-backend -f`.

## Where knowledge lives (keep it correct)

1. **This file + per-repo `AGENTS.md`** = the versioned source of truth every agent sees. When something becomes permanently true, write it here, not in chat.
2. **`authsec-doc`** (Docusaurus) = deep, public, rendered docs (concepts/flows/SDK/reference). *Curation + diagrams are a deferred phase — until then, prefer this file for the canonical mental model.*
3. **AI-assistant memory (`~/.claude/.../memory`)** is private to one user's Claude Code — a fresh agent never sees it. Keep it tiny (user identity, working-style constraints, current deploy/secrets). Never log completed-feature history.
4. **`~/.claude/plans/`** = scratch, in-flight plans only; not authoritative.

## AI/SDLC tooling — skills, hooks, agents

All cross-repo tooling lives in `.claude/` at the workspace root.

### Slash commands (skills) — `.claude/commands/`

| `/command` | What it does |
|---|---|
| `/deploy` | Deploy via Jenkins pipeline (push-to-deploy); emergency manual deploy via SSH |
| `/wipe-rebootstrap` | Backup + wipe DB + re-bootstrap on the VM (DESTRUCTIVE, last resort) |
| `/schema-change` | Tiered schema changes: minor (direct SQL), major (delta migration), destructive (wipe) |
| `/console-page` | Checklist + pattern for adding a new sidebar page |
| `/flow-test` | curl smoke tests for M2M / XAA / SPIFFE / OIDC / CIBA |
| `/ship` | Pre-push checklist: `go build/vet/gofmt` + `tsc --noEmit` |
| `/spec` | Create a feature spec (forces SDK + docs decision before coding) |
| `/docs` | Update deep docs + public docs after a change |

### Subagent reviewers — `.claude/agents/`

Invoke with the **Agent tool** using `subagent_type: "authsec-reviewer"` etc.

| Agent | When to use |
|---|---|
| `authsec-reviewer` | After any Go backend change — checks token engine, schema, workspace scoping, PDP |
| `ui-reviewer` | After any UI change — checks ConsolePage standard, RTK Query, Button contract |
| `flow-verifier` | After implementing or debugging a flow — checks end-to-end correctness + token claims |

### Hooks (guardrails)

| Hook | Repo | What it blocks |
|---|---|---|
| Block `git push` | workspace root | requires manual push; see `.claude/hooks-manual.md` to wire it |
| Block `ALTER TABLE` in Bash | `authsec` | enforces single-state schema rule |
| `gofmt -w` on `*.go` | `authsec` | auto-formats every Go file after Edit/Write |
| Block `npm run dev` / `npx vite` | `Authsec-ui` | auth routes need backend; use `tsc --noEmit` instead |

### Definition of Done

`.claude/DEFINITION-OF-DONE.md` — per-repo gate table (build/vet/tsc/deploy).
