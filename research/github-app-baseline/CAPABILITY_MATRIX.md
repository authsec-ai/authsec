# Task 101 — Capability matrix: endpoint | permission | GA/preview | licence-gated | cost | failure mode

Measured live on `authsec-sandbox`, 2026-08-24 UTC. GA = generally available
(no preview header required; `X-GitHub-Api-Version: 2022-11-28` used throughout).
All fixtures in `fixtures/`; failure modes from the zero-permission probe App.

> Caveat: the GA/preview column rests on the absence of preview headers on the
> endpoints called — no preview-gated or enterprise-tier endpoint was probed.
> Enterprise Copilot management (spec G2/G3) is therefore **untested/unsupported**
> here, not verified.

| Endpoint | Permission (App) | GA/preview | Licence-gated | Rate cost | Failure mode when unavailable |
|---|---|---|---|---|---|
| `GET /app` | none (App JWT) | GA | no | app bucket; **no `X-RateLimit-*` headers returned** | 401 bad JWT (`fixtures/meta/app.json` is 200) |
| `GET /app/installations` | none (App JWT) | GA | no | app bucket; no headers | 401 bad JWT |
| `GET /app/installations/{id}` | none (App JWT) | GA | no | app bucket; no headers | 404 if install gone |
| `POST /app/installations/{id}/access_tokens` | none (App JWT) | GA | no | — | 401 bad JWT; 404 if install gone |
| `GET /installation/repositories` | none (installation token) | GA | no | core, 1/page | **never errors: 200-empty** = no repos granted (`probe-repos`) — the silent-under-report trap |
| `GET /repos/{o}/{r}/git/trees/{ref}?recursive=1` | `contents: read` | GA | no | core, 1; truncates at ~7 MB / ~40k entries | 404 (`probe-tree`) |
| `GET /repos/{o}/{r}/git/blobs/{sha}` | `contents: read` | GA | no | core, 1 | 404 |
| `GET /repos/{o}/{r}/contents/{path}` (CODEOWNERS) | `contents: read` | GA | no | core, 1 per probe (1..3) | **404 for both "absent permission" and "file doesn't exist" — indistinguishable** |
| `GET /repos/{o}/{r}/keys` (deploy keys) | `contents: read` (observed) | GA | no | core, 1 | 404 (`probe-keys`) |
| `GET /repos/{o}/{r}/commits` | `contents: read` (observed) | GA | no | core, 1 | 404 (`probe-commits`) |
| `GET /repos/{o}/{r}/actions/workflows` | `actions: read` | GA | no | core, 1 | 404 (`probe-workflows`) |
| `GET /orgs/{org}/actions/secrets` | `organization_secrets: read` | GA | no | core, 1 | **403 "Resource not accessible by integration"** (`probe-org-secrets`) — names only, never values |
| `GET /orgs/{org}/copilot/billing/seats` | `copilot: read` — **not granted, still 200-empty** | GA | no (200-empty without license or permission) | core, 1 | 403 absent permission (`probe-copilot-seats`) |
| `GET /orgs/{org}/copilot/usage` | `copilot: read` | GA | **yes (404 on this org)** | core, 1 | 404 unlicensed (`copilot-usage`) |
| `GET /repos/{o}/{r}/dependency-graph/sbom` | `contents: read` (assumed; absent perm → 404, unverifiable) | GA | no | **own bucket `dependency_sbom`, 100/h** | 404 (no SBOM enabled OR absent permission — indistinguishable) |
| `GET /repos/{o}/{r}/copilot/agents` | — | **endpoint does not exist** | — | core, 1 | **404 always** (`copilot-agents`) — product assumption falsified |

## Failure-mode taxonomy (the 403 ≠ 404 ≠ empty-array rule)

| Observable | Means | Seen on |
|---|---|---|
| **200 + non-empty** | authorized, data present | all positive fixtures |
| **200 + empty array** | authorized, nothing there — OR no repos granted (probe). Never "clean" by itself | org-secrets (main), copilot-seats (main), probe-repos |
| **403 "Resource not accessible by integration"** | integration lacks the permission; org-level endpoints | org-secrets, copilot-seats (probe) |
| **403 "API rate limit exceeded for installation ID …"** | bucket exhausted; `X-RateLimit-Remaining: 0` | exhausted (probe, after 5000 used) |
| **401 "Bad credentials"** | installation revoked — in-flight token dead, no grace period | revoked-in-flight |
| **404 Not Found** | repo-level absent permission, un-granted repo, or nonexistent resource — GitHub hides which | probe-tree/codeowners/workflows/keys/commits/sbom, tree-bigtree-ungranted |
| **403 + `X-RateLimit-Remaining: 0`** | throttle, retry after `X-RateLimit-Reset` | exhausted |
| **429** | secondary throttle | not observed (see budget §2) |

## Cost summary

- `core`: 5000/h per installation; 1 per origin call (edge-cached repeats ≈ 0).
- `dependency_sbom`: 100/h, separate bucket.
- App-JWT calls: no headers returned; separate undocumented bucket.
- Full 300-repo scan ≈ 1504 core calls, ~9 min (see `RATE_LIMIT_BUDGET.md`).