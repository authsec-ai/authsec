# GCP-02 — Cloud schema conformance review

**Status: lands nothing.** No migration, no table, no repository, no
`cloud:*` permission seed. This is a review of AWS's already-landed shared
`cloud_*` migrations (`010`–`013`) against the GCP mapping rows in
"common dicovery schema.md" (28 August 2026), plus one additive test file
(`tests/ownership/cloud_schema_ownership_test.go`) that proves the
conformance claims below in the database itself rather than only in prose.

Reviewed against branch `akash-gcp-onboarding`, migrations
`migrations/master/010_cloud_discovery_connector.sql` through
`013_cloud_permission_and_resource.sql`, `models/cloud_discovery.go`,
`repository/cloud_connector_repository.go`, `migrations/master/001_bootstrap.sql`,
`models/discovery.go`, `migrations/master/002_agent_discovery.sql`.

## Table-by-table conformance

### `cloud_connector`

Common schema mapping row: *"GCP: One row per org / folder / project scope."*

| Common schema column | Landed (migration 010 / `models.CloudConnector`) | Conforms? |
|---|---|---|
| `workspace_id`, `provider`, `scope_kind`, `scope_id`, `parent_scope_id`, `auth_ref`, `status`, `scan_generation` | present, exact names | Yes |
| `scope_kind` enum: `account`, `project`, `folder`, `org`, `subscription` | `cloud_connector_scope_kind_chk CHECK (scope_kind IN ('account','project','folder','org','subscription'))` | Yes — `project`, `folder`, `org` (GCP's three) all present. Live-asserted by the new test file. |
| `provider` enum: `aws`, `gcp`, `azure` | `cloud_connector_provider_chk CHECK (provider IN ('aws','gcp','azure'))` | Yes — `gcp` present. Live-asserted by the new test file. |
| `parent_scope_id` — "Azure tenant · GCP org" | `parent_scope_id text` (nullable, no default) | Yes — GCP-04 writes the org id here when a project or folder is onboarded, NULL at org scope itself. |

**Deviations (recorded by AWS in the migration's own footer, GCP has no
objection to any of them):**
- **`attrs jsonb`** — not in the shared column list. AWS added it for
  `role_arn`/`regions`/`caller_arn`; GCP will use the identical mechanism for
  `GCPConnectorAttrs` (`reader_project_id`, `auth_method`,
  `wif_provider_resource`, `wif_subject`, `pool_id`, `provider_id`,
  `cai_quota_project`, `role_set_status`, `setup_script_version` — GCP-04's
  job to add the struct, not this ticket's). Conforms with the shared note's
  own instruction ("if something is missing, whether it belongs in attrs
  rather than as a new column").
- **`coverage jsonb`, `verified_at`, `last_error`** — not in the shared
  column list, added by AWS as provider-neutral (not AWS-only) fields. GCP
  needs and will use all three unchanged: `coverage` for per-surface
  reached/denied/not_configured/throttled, `verified_at` for the
  `iam.serviceAccounts.get`-on-self connectivity proof GCP-03/04 already
  design around, `last_error` for a WIF `wif_pool_missing`/JSON-key
  `key_invalid` message.
- **`parent_scope_id` stays nullable** — matches the shared note exactly,
  called out because it's against this repo's usual `NOT NULL DEFAULT ''`
  convention. GCP relies on this: a project-scope connector's `parent_scope_id`
  is the org id when known, NULL when the reader can't resolve it (no org
  exists, or `organizations.get` was denied).

### `cloud_identity`

Common schema mapping row: *"GCP: Service account → native_id = SA email."*

| Common schema column | Landed (migration 011) | Conforms? |
|---|---|---|
| `kind`, `native_id`, `name`, `created_at`, `last_used_at`, `enabled`, `attrs` | present, exact names | Yes |
| `connector_id`, `last_seen_generation` (reconciliation, "not repeated" in the shared note but implied for every new table) | present | Yes — live-asserted by the new test file, alongside the five other child tables |
| `native_id` = SA email, cross-connector join key | `native_id text NOT NULL`, `UNIQUE(workspace_id, native_id)` | Yes — GCP-09 will write `kind='service_account'`, `native_id=<SA email>`. No schema change needed. |

`created_at` semantics (provider creation time, not row insert time — see
migration 011's header) apply to GCP identically: a service account's own
creation timestamp, not when AuthSec first saw it.

### `cloud_secret`

Common schema mapping row: *"GCP: SA JSON key (user-managed)."*

| Common schema column | Landed (migration 011) | Conforms? |
|---|---|---|
| `identity_id`, `kind`, `native_id`, `created_at`, `expires_at`, `last_used_at`, `status`, `attrs` | present, exact names | Yes |
| No column for a secret **value** | Confirmed by direct column enumeration — see the new test file, which asserts the exact column set rather than trusting a blacklist of guessed dangerous names | Yes |
| GCP mapping: `native_id` = key id, dates only, age is the finding | `kind` will be `sa_json_key` (GCP-09's job), `native_id` = the GCP key id, `created_at`/`expires_at` unused (GCP SA keys have no expiry — same "NULL is the finding" shape AWS access keys already use) | Yes, no schema change needed |

One nuance carried over from `authsec/docs/gcp/feasibility-validation.md`
(GCP-01): a Google-managed SA key produces **no** `cloud_secret` row at all
(per the plan §4 "Key metadata" capability and the common schema's GCP
mapping, "user-managed" only) — this is a write-time filter in GCP-09, not a
schema constraint, and `cloud_secret` has no column that would need to
distinguish managed-by at the DB level.

### `cloud_assume_edge`

Common schema mapping row: *"GCP: iam.serviceAccountTokenCreator · GKE
Workload Identity."*

| Common schema column | Landed (migration 012) | Conforms? |
|---|---|---|
| `identity_id`, `subject_kind`, `subject`, `issuer`, `mechanism` | present, exact names | Yes |
| `subject_kind`/`mechanism` are **open text, not a closed enum** | `cloud_assume_edge_subject_kind_chk CHECK (subject_kind <> '')`, `cloud_assume_edge_mechanism_chk CHECK (mechanism <> '')` — non-empty only, no enumeration | Yes — migration 012's own header explains why: a closed CHECK would reject GCP's first `mechanism='gcp_impersonation'` row (service-account impersonation is neither `sts_assume_role` nor `oidc_federation`) or an Azure federated-identity row. GCP is free to write `mechanism='gcp_impersonation'` for `iam.serviceAccountTokenCreator` edges and `mechanism='gke_workload_identity'` (or similar — GCP-implementation-tickets.md's own choice) for the GKE join, without a schema change. |
| `issuer` — "Disambiguates two clusters with the same namespace and service account" | `issuer text` nullable, no format constraint | Yes — GKE Workload Identity join (M2) writes the cluster's OIDC issuer host here, matching the shared open question in "common dicovery schema.md" (the Kubernetes connector doesn't currently emit one — a K8s-connector-owner decision, not a GCP schema gap) |
| `k8s_ref` invariant | `cloud_assume_edge_k8s_ref_chk CHECK (subject_kind <> 'k8s_service_account' OR k8s_ref IS NOT NULL)` | Not GCP's concern directly (fixed by the Kubernetes connector's own join contract per the migration's header), but does not block GCP: a GKE Workload Identity edge can legitimately use `subject_kind='k8s_service_account'` and populate `k8s_ref` in the same `system:serviceaccount:<ns>:<sa>` format the Kubernetes connector already writes. |

### `cloud_permission`

Common schema mapping row: *"GCP: IAM binding (role + member) from
searchAllIamPolicies — no parsing. Roles expanded to actions."*

| Common schema column | Landed (migration 013) | Conforms? |
|---|---|---|
| `identity_id`, `resource_id`, `plane`, `effect`, `role_name`, `actions`, `scope_kind`, `derivation`, `sensitivity`, `last_exercised_at` | present, exact names | Yes |
| `role_name` — "Null for AWS" (i.e., meant for GCP/Azure) | `role_name text` nullable, no CHECK forcing null | Yes — GCP-09 writes the full role name here (`roles/storage.objectViewer` or `projects/<p>/roles/<custom>`), unlike AWS which always leaves it NULL. First real consumer of a column AWS defined but never populates. |
| `actions text[]` — role expanded to actions | `cloud_permission_actions_chk CHECK (array_length(actions,1) > 0)` | Yes, but **load-bearing for GCP-10/GCP-11 sequencing**: this CHECK means a binding cannot be written before its role has been expanded into an action list — GCP-10 (role expansion) must run, and must produce at least one action, before GCP-09 (binding discovery) can INSERT the row. This is GCP-D12 in the open-decisions table (§12) — not a new finding here, restated because it is exactly the kind of thing a schema conformance review exists to catch. An unresolvable custom role (deleted after the binding was read, or a transient `iam.roles.get` failure) has nowhere to go without either a placeholder action or dropping the binding — GCP-11's job, not this ticket's, to decide which. |
| `plane` | `cloud_permission_plane_chk CHECK (plane IN ('cloud','api'))`, default `'cloud'` | Yes — every GCP row is `plane='cloud'`; `'api'` is Azure-only (Graph API permissions), never written by GCP. |
| `effect` | `cloud_permission_effect_chk CHECK (effect IN ('allow','deny'))` | **Partial.** The CHECK accepts `'deny'`, but GCP has no capability in this plan that reads a GCP deny policy (a structurally separate object from a different API — see GCP-D5, plan §10). Every GCP row this connector's current tickets write is `effect='allow'`; the schema does not block a future ticket from adding deny support, it simply isn't populated by anything landed or planned in GCP-01..05. |
| `scope_kind` | `cloud_permission_scope_kind_chk CHECK (scope_kind IN ('resource','prefix','account_wide'))`, plus `cloud_permission_scope_resource_chk CHECK ((scope_kind='resource') = (resource_id IS NOT NULL))` | Yes — a GCP binding at a specific resource (e.g. one Secret Manager secret) is `scope_kind='resource'` with `resource_id` set; a project/folder/org-wide binding is `scope_kind='account_wide'` with `resource_id` NULL, matching the wildcard-never-invents-a-row rule the plan (§7) and common schema both state explicitly. |
| **IAM Conditions** — no column | Confirmed absent: `role_name`, `actions`, `effect`, `scope_kind`, `derivation`, `sensitivity` is the complete set of grant-shape columns; nothing holds a condition expression or title | **Gap, correctly left unfixed here.** `authsec/docs/gcp/feasibility-validation.md` (GCP-01, question c) live-confirmed IAM Conditions arrive from `searchAllIamPolicies` as a third top-level key on the binding object (peer of `members`/`role`), and recorded that inventing a column for it is schema-owner territory. Restated here as the schema-conformance finding it also is: this ticket does not add one. |

### `cloud_resource`

Common schema mapping row: *"GCP: Full resource name."*

| Common schema column | Landed (migration 013) | Conforms? |
|---|---|---|
| `kind`, `native_id`, `name`, `sensitivity` | present, exact names | Yes |
| `kind` — "Text, not an enum" | `cloud_resource_kind_chk CHECK (kind <> '')`, no enumeration | Yes — GCP writes a service-typed string (`secretmanager_secret`, `storage_bucket`, `cloudkms_cryptokey`, ...), same shape as AWS's `s3_bucket`/`dynamodb_table` |
| `native_id` — "Provider identifier, verbatim" | `native_id text NOT NULL`, `UNIQUE(workspace_id, native_id)` | Yes — GCP writes the full resource name (`//secretmanager.googleapis.com/projects/.../secrets/...` or the shorter `projects/.../secrets/...` form CAI returns — GCP-09's exact-string decision, not a schema question) |
| Resource rows come from grants only, no independent scan | No DB mechanism creates a `cloud_resource` row except an application INSERT; the schema cannot enforce "a permission named it" on its own | Yes in practice (an application-layer rule, same as AWS), consistent with the shared note's rule "a `cloud_resource` row exists only because a `cloud_permission` named it" |

### `cloud_usage` — not yet landed

Common schema mapping row: *"GCP: Cloud Audit Log entries."* **This table
does not exist in the repository yet** — confirmed by grep across
`migrations/` and `models/`: the only references to `cloud_usage` are
forward-looking comments in migrations 010 and 013 ("cloud_assume_edge and
cloud_usage all carry connector_id...", "Aggregated from cloud_usage by a
later ticket") and `CloudPermission.LastExercisedAt`, which is always NULL
as written today. This is expected: `cloud_usage` is M2 scope (plan §4,
"Audit activity read" / "Usage aggregation") for both AWS and GCP, not a
GCP-02 blocker, and not something this conformance review can check
conformance of yet.

### `discovered_agents` — the reused table

Common schema mapping row: *"GCP: Vertex reasoningEngine (platform-declared)
· Cloud Run / Function / GCE (classified)."* New column: `cloud_identity_id`
(fk null).

**`discovered_agents.cloud_identity_id` does not exist** on this branch.
Confirmed directly in both `migrations/master/001_bootstrap.sql`
(`discovered_agents` DDL, lines ~3498–3570) and
`migrations/master/002_agent_discovery.sql`'s own `CREATE TABLE IF NOT EXISTS
public.discovered_agents` — neither defines it, and `models/discovery.go`'s
`DiscoveredAgent` struct has no corresponding field. This is **not a GCP
blocker**: the column is the join between a classified agent and the cloud
identity it runs as, and per this ticket's own acceptance criteria and
`prompt.md`'s FACT list, adding it is tracked against the AWS track's tickets
5/6/9 (the ones that would populate and consume it), not against GCP-02.
GCP-09 (identity discovery) writes `cloud_identity` rows independently of
whether or when this join column lands; nothing in GCP-01..05 depends on it
existing.

## ADOPTED decision: WIF `auth_ref` convention

Per this file's "GCP-D9 — RESOLVED" section (`prompt.md`) — recorded here as
an **adopted decision, not a pending question**. No schema-owner sign-off is
being sought: this is a value-shape choice inside a column AWS already
defined as free text (`auth_ref text NOT NULL DEFAULT ''`, no CHECK on its
contents beyond `status<>'active' OR auth_ref<>''`), owned by Akash.

A WIF-authenticated `cloud_connector` row's `auth_ref` column holds the
literal string:

```
"wif:" + <full WIF provider resource name>
```

e.g.

```
wif:projects/123456789012/locations/global/workloadIdentityPools/authsec-a1b2c3d4e5f6a7b8/providers/authsec-provider
```

This is **non-secret** — a GCP resource name, not key material — and it
satisfies the landed `cloud_connector_auth_ref_chk` (`status <> 'active' OR
auth_ref <> ''`) exactly as any non-empty string would. It requires no
migration: the column already accepts arbitrary text.

**Contrast with the `json_key` path's `auth_ref`**, which is a Vault KV path:
`kv/data/secret/workspaces/<workspace_id>/cloud-discovery/gcp/<scope_id>`.
The two auth methods are distinguishable **by the `"wif:"` prefix alone** —
a WIF connector's `auth_ref` never starts with `kv/data/secret/...`, and a
json_key connector's `auth_ref` never starts with `wif:`. No new column, no
enum, no CHECK addition: GCP-04's `CreateConnector` and `RevokeConnector`
branch on this prefix to decide whether a Vault round trip is needed at all
(WIF: none — see `prompt.md`'s design and
`authsec/docs/gcp/feasibility-validation.md`'s SDK section for why no secret
ever exists to store for this path).

## STEP 3 — confirmed, not fixed

- **`discovery:read`/`discovery:admin` already gate every AWS cloud route.**
  All twelve `/aws/*` discovery routes in `routes/routes.go` (onboarding,
  connectors CRUD + verify, scan, identities, secrets, assume-edges,
  permissions, resources) are wired through
  `middlewares.Require("discovery", "read")` or
  `middlewares.Require("discovery", "admin")` — none uses a different
  permission resource. GCP-04's future `/gcp/*` routes are expected to mirror
  this exactly (per `prompt.md`'s GCP-04 design), which needs no new
  permission seed.
- **No `cloud:*` permission seed exists anywhere.** Case-insensitive search
  for `'cloud:` / `"cloud:` across every `.go` and `.sql` file in the
  repository returns zero matches. `discovery:*` (seeded globally in
  `migrations/master/002_agent_discovery.sql`, folded into
  `001_bootstrap.sql`) is the only permission resource cloud discovery of any
  provider uses.

## Summary

Every GCP mapping row in "common dicovery schema.md" is representable in the
landed schema with **zero migration, zero new table, zero new column**. The
two structural gaps this review surfaces — IAM Conditions have no column,
and `cloud_usage` doesn't exist yet — are both already-known, already-recorded
items (GCP-01's ledger for the first, plan §4's M2 sequencing for the second),
not new discoveries requiring a decision from this ticket. The one adopted
decision (WIF `auth_ref` prefix convention) needs no schema change and is
recorded above for GCP-03/04 to implement against.
