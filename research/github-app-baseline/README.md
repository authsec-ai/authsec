# Task 101 — GitHub App capability baseline: fixtures and evidence

Companion docs: `REGISTRATION.md` (App registration, field by field),
`CAPABILITY_MATRIX.md` (endpoint matrix), `RATE_LIMIT_BUDGET.md` (scan budget),
`OBSERVATIONS.md` (the three recorded answers + bonus findings).

Captured live on 2026-08-24 UTC against org `authsec-sandbox`:

- **Main App** `authsec-discovery-sandbox321` (id `4704782`), installation `156264905`
  (initially "all repositories", re-configured "only select repositories").
- **Probe App** `authsec-capability-probe` (id `4705654`), installation `156281961`,
  **zero permissions** — used for failure modes only.

Capture tool: `tool/` (standalone Go, zero dependencies, mirrors — never imports —
the product's token flow). All credentials are environment-only
(`GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY_PATH`, `GITHUB_APP_INSTALLATION_ID`);
nothing in this directory contains a token, key, or secret. Token-like JSON
fields and `?token=` URL params are scrubbed (`<redacted>`); only whitelisted
headers are stored (`X-RateLimit-*`, `Link`, `ETag`, `Retry-After`,
`X-GitHub-Request-Id`).

## Fixture map: fixture → endpoint → permission → observed limits

| Fixture (fixtures/) | Endpoint | Auth | Permission | Status | Rate-limit observation |
|---|---|---|---|---|---|
| `meta/app.json` | `GET /app` | App JWT | — | 200 | no `X-RateLimit-*` headers |
| `meta/installations.json` | `GET /app/installations` | App JWT | — | 200 | no headers; 1 install only (org allows one per App) |
| `meta/install-156264905.json` | `GET /app/installations/156264905` | App JWT | — | 200 | no headers; `repository_selection: all` → `selected` after re-config |
| `meta/install-156281961.json` | probe install meta | App JWT | — | 200 | no headers; `permissions: {}` |
| `repos/install-156264905-page1.json` | `GET /installation/repositories?per_page=100` | install token | none | 200 | core 5000/h; 1/page; **post-removal state: only `test-repo-1`, `total_count: 1`** |
| `repos/install-156264905-2repos.json` | `GET /installation/repositories?per_page=100` | install token | none | 200 | core 5000/h; **current state: `test-repo-1` + `bigtree`, `total_count: 2`** (API reports `repository_selection: "selected"`) |
| `repos/pagination-per-page1.json` / `.http` | `GET /installation/repositories?per_page=1` | install token | none | 200 | core 5000/h; **real `Link: rel="next"` + `rel="last"` headers captured** — pagination past one page verified |
| `tree/tree-test-repo-1.json` | `GET /repos/…/git/trees/main?recursive=1` | install token | `contents: read` | 200 | core 1; 6 entries, `truncated: false` |
| `tree/tree-bigtree.json` | same on bigtree (66k files) | install token | `contents: read` | 200 | core 1; **40,269 entries, `truncated: true` (~7 MB cap)**; full payload 15.7 MB pretty, excerpt committed |
| `blob/blob-*.json` | `GET /repos/…/git/blobs/{sha}` | install token | `contents: read` | 200 | core 1; base64 content |
| `codeowners/codeowners-{1,2,3}.json` | `GET /repos/…/contents/{.github/CODEOWNERS,CODEOWNERS,docs/CODEOWNERS}` | install token | `contents: read` | 404/200/404 | core 1 each; product's 3-probe order confirmed |
| `org-secrets/org-secrets.json` | `GET /orgs/{org}/actions/secrets` | install token | `organization_secrets: read` | 200 | core 1; **names-only, empty list** |
| `workflows/workflows.json` | `GET /repos/…/actions/workflows` | install token | `actions: read` | 200 | core 1; 1 workflow |
| `sbom/sbom.json` | `GET /repos/…/dependency-graph/sbom` | install token | `contents: read` (assumed) | 404 | **own bucket `dependency_sbom` limit 100/h** |
| `copilot/copilot-seats.json` | `GET /orgs/{org}/copilot/billing/seats` | install token | none granted | 200 | core 1; **200-empty without license/permission** |
| `copilot/copilot-usage.json` | `GET /orgs/{org}/copilot/usage` | install token | `copilot: read` | 404 | licence-gated 404 |
| `copilot/copilot-agents.json` | `GET /repos/…/copilot/agents` | install token | — | 404 | **endpoint does not exist** |
| `keys/deploy-keys.json` | `GET /repos/…/keys` | install token | `contents: read` | 200 | core 1; empty |
| `commits/commits.json` | `GET /repos/…/commits?per_page=10` | install token | `contents: read` | 200 | core 1 |
| `failure-modes/probe-repos.json` | `GET /installation/repositories` (probe) | probe token | none | **200** | **empty array with zero permissions** |
| `failure-modes/probe-{tree,codeowners,workflows,keys,commits,sbom}.json` | repo-level endpoints (probe) | probe token | none | **404** | absent permission on repo-level = 404 |
| `failure-modes/probe-{org-secrets,copilot-seats}.json` | org-level endpoints (probe) | probe token | none | **403** | "Resource not accessible by integration" |
| `failure-modes/exhausted.json` | `GET /repos/…/commits` | probe token | — | **403** | **`Remaining: 0`, `Used: 5000`**; exact exhausted body captured |
| `failure-modes/revoked-in-flight.json` | `GET /installation/repositories` | revoked token | — | **401** | token minted pre-revocation; **401 "Bad credentials" ≤5 s after uninstall** — no grace period |
| `failure-modes/tree-bigtree-ungranted.json` | bigtree tree after de-grant | main token | granted gone | **404** | removal reflected instantly |

## Reproducing

```bash
cd tool && go build -o /tmp/task101-tool .
export GITHUB_APP_ID=<app id> GITHUB_APP_PRIVATE_KEY_PATH=<pem> GITHUB_APP_INSTALLATION_ID=<install id>
/tmp/task101-tool app | installations | install-meta <id> | repos <id> | endpoint <auth> <name> <group> <path> | scan-sim <o> <r> <branch> | burst | exhaust
```

The tool mints installation tokens exactly as the product does (RS256 App JWT,
`iss`=AppID, iat −30s, exp 9m → `POST /app/installations/{id}/access_tokens`);
tokens are in-memory only.

## Out of scope (product code — not modified)

`internal/connectoradapters/`, `services/{connector_oauth_service,connector_broker_service,iga_github_provider,iga_service,discovery_github_scanner}.go`,
`controllers/platform/{connector*,iga,discovery_github}_controller.go`,
`models/connector.go`, `repository/connector_repository.go`, `routes/routes.go`,
`migrations/master/*.sql`. This directory is a self-contained research module
(own `go.mod`) and does not affect `go build ./...` of the main module.