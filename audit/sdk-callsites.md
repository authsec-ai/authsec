# External Caller Audit — Legacy Endpoint Usage

Snapshot taken before the v4 deprecation windows are opened. Used to gate
removal of `/authsec/resource-servers/*`, `/authsec/clientms/*`, the
`client_id`-scoped SAML/SCIM/AD routes, and `legacy_client_id` from the schema.

The rule per v4 §12: an endpoint can be removed once 30 days of zero traffic
plus zero references in any of these repos. This file is the inventory of
"references" — the metrics dashboard supplies the traffic side.

## Repositories scanned

| Repo | Branch | Tree |
|---|---|---|
| `sdk-authsec` | `sdk-v2` | `packages/{go-sdk,python-sdk,ts-sdk}` |
| `claw-auth` | n/a (deploy-only) | `deploy/` manifests |
| `authsec-agent-shield` | `windows` | `cmd/`, `internal/`, `kernel/`, `shield/` |
| `local-k8s` | n/a | `manifests/`, `Tiltfile`, `images/` |
| `trial-modules` | n/a | `ai-agent/`, `ai-voice-agent/`, `breachbox-mcp/`, `mcp-server/` |
| `Authsec-ui` | `authsec-dev-ui-cutover` | `src/app/api/*.ts` |

## Findings

### `sdk-authsec` — actively uses `/authsec/resource-servers/*`

Three concrete callsites in `packages/go-sdk`:

- `<AUTHSEC_API_ORIGIN>/authsec/resource-servers/%s/sdk-policy`
- `<AUTHSEC_API_ORIGIN>/authsec/resource-servers/%s/sdk-manifest`
- `<AUTHSEC_API_ORIGIN>/authsec/resource-servers/%s/sdk-manifest-status`

Documentation in `packages/python-sdk/CHANGELOG.md` references the same
`sdk-policy` path. The SDK pulls scope policy and manifest data; these
endpoints are read-only and authenticated with Basic auth using the RS's
introspection secret (i.e. distinct auth from the JWT-protected admin API).

**Deprecation impact:** the SDK *must* be migrated before
`/authsec/resource-servers/*` can be removed. The replacement is the same
endpoints under `/authsec/applications/:id/...`, which already exist (the
applications facade reuses these handlers). SDK release needs:

1. Bump path templates to `/authsec/applications/%s/sdk-policy`,
   `/authsec/applications/%s/sdk-manifest`,
   `/authsec/applications/%s/sdk-manifest-status`.
2. Add a fallback to the legacy path for one release so older AuthSec
   deployments stay compatible.
3. Cut a new minor and update `local-k8s` consumers.

### `claw-auth` — clean

No source references found. Only contains `deploy/` manifests that point at
the AuthSec service URL; no specific endpoint paths.

### `authsec-agent-shield` — clean

No references to `/authsec/resource-servers`, `/clientms`, or the legacy
SCIM/SAML paths. The agent shield only consumes SPIFFE-issued tokens — it
doesn't speak to the AuthSec admin API.

### `local-k8s` — clean

No endpoint references in manifests, Tiltfile, or image build configs. The
stack only configures network routing and env vars.

### `trial-modules` — clean

No references to the legacy endpoints. The MCP demo servers register with
AuthSec via OAuth DCR (`/oauth/register`) which is a standards endpoint
unaffected by this rollout.

### `Authsec-ui` — uses `/authsec/resource-servers` via alias slice

The UI's `applicationsApi.ts` is a thin alias over `resourceServersApi.ts`
which posts/gets `/authsec/resource-servers`. The new `/authsec/applications`
facade exists in the backend; the UI cutover (v4 Step 11) needs to switch
the alias from re-exporting `resourceServersApi` to making direct calls
against `/applications`. The route group is already mounted server-side.

Other notable UI calls (all current backend, no migration needed):

- `/authsec/oocmgr/oidc/*` — OIDC provider config CRUD
- `/authsec/oocmgr/saml/*` — SAML provider config CRUD
- `/authsec/spiresvc/v1/{agents,entries,workloads}` — SPIRE proxy
- `/authsec/uflow/admin/*` — admin user/permission/role flows

None of these are slated for removal in this rollout.

## Punch list for deprecation

| Endpoint | Status | Gate |
|---|---|---|
| `/authsec/resource-servers/*` | Used by `sdk-authsec` + `Authsec-ui` | (1) SDK release with `/applications` paths, (2) UI cutover, (3) 30-day quiet window |
| `/authsec/clientms/*` | Not surfaced in any audited repo | Verify via route metrics; if zero traffic, eligible for 30-day window now |
| `/authsec/uflow/scim/v2/:client_id/:project_id` | Not in audited repos; possible external SCIM provisioners (Okta, Entra) configured by operators | Cannot remove without operator-side update; advertise `/scim/v2/c/:scim_connection_id` and provide rotation tooling |
| `/uflow/saml/acs/:tenant_id/:client_id` | Not in audited repos; external IdPs point at this URL | Same as SCIM — operator-side cutover required first |
| `/authsec/uflow/user/rbac/*` (mutation) | Locked to 403 (Step 0.5) | 30-day quiet window from metric start |
| `resource_servers.legacy_client_id` column | Backfilled by migration 118 | 90-day quiet window after zero code references and zero API traffic |
| `delegation_*.client_id` (alongside `application_id`) | Code prefers `application_id` | Hold until SDK + UI both consume `application_id` only |

## Re-audit cadence

Re-run this audit before each removal step. Specifically:

1. Before the **first** removal (`/clientms` is the most likely candidate),
   diff this file against a fresh scan and confirm no new references appeared.
2. After each SDK release, refresh the SDK section.
3. Always pair the code grep with the runtime metrics dashboard from Step 0.5.
