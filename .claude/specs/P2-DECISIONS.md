# IGA Phase 2 — implementation decisions where the spec is silent or contradicts itself

Spec: `SPEC-iga-phase2-graph.md` @ d9741e7. The handoff says *ask before
inventing* and *raise spec errors before building around them*. M1 was built
without a review round, so every point below is **provisional**: it is the most
conservative reading we could find, it is implemented and tested as written
here, and it is listed so that review can overturn it. Each entry names the spec
lines in tension. Where the spec is clear, the spec wins and nothing is
recorded here.

Conventions: **D-n** is a decision; *Why* is the reason; *Raise* marks a spec
defect that should be fixed in the spec itself.

## Read contract (§5.1–§5.2)

- **D-1 Node `state` and `last_confirmed_at`.** Node tables carry `lifecycle`
  only. `state` = `current` if any non-ended support row is current, else
  `stale` if any is stale, else `ended`. `last_confirmed_at` = max of the
  support rows' `last_confirmed_at`. External principals (no support rows):
  `current` if any non-ended `can_assume` edge from them is current, else
  `stale` if any is stale, else `ended`. *Why:* staleness lives on support
  (§2.10B); the list examples show `state`. *Raise:* §5.3 examples use a field
  no table defines.
- **D-2 ARN.** No ARN column exists. Identities and workloads: the native
  segment of `source_key` (`igaread.NativeOfKey`). Resources: `display_name`
  (the reference text). *Why:* §2.4 forbids formatting keys outside
  `sourcekey.go`; reading the last segment back is not formatting.
- **D-3 Account.** Workload: its connector's account (the estate scope's
  connector), always known. Identity: its ARN. Resource: `provider_attrs.account`
  (never the scanning account). `connected` = a connector for that account exists
  in the workspace and is not `revoked`, computed **at read time** — the
  projector's frozen `account_connected` attr is not used by the read side.
  `label` = the connector's `display_name`, falling back to the account id; an
  unconnected account's label is its id. *Raise:* the projector's
  `ConnectedAccounts` counts revoked connectors.
- **D-4 Detail routes when nothing is published.** `404 not_found` (no object
  can exist before the first publication; §5.1's `not_published` is a list
  state). Lists answer `200`, empty `data`, `graph_state: not_published`.
- **D-5 Route ids.** `/:id` accepts the bare UUID or the typed reference of the
  route's own type. Anything else, including a malformed id or another type's
  reference, is `404` (no hint), per §5.2.
- **D-6 GitHub rows.** Graph routes read only `provider = 'aws'` rows; a GitHub
  identity or resource id is `404`.
- **D-7 `rev` and cursor together.** Both must equal the current revision; either
  one stale is `409 revision_stale`.
- **D-8 `IGA_CURSOR_SECRET` unset.** A random per-process key and a startup
  warning. Cursors then fail `400 cursor_invalid` across restarts or replicas
  (the console restarts the list). Never a forged position. *Raise:* the spec
  names the secret but not its absence.
- **D-9 401/403 envelope.** `AuthMiddleware` and `authz.Require` keep their
  existing bodies (shared by every product); the `§5.2` envelope is applied to
  every status the graph handlers themselves produce. *Raise:* §5.2 lists
  `unauthenticated` / `forbidden` codes the shared middleware does not emit.
- **D-10 Order of checks.** Permission middleware (403) runs before the handler,
  so 403 precedes 503. The handler then applies 503, then 401 (no workspace in
  the token), then parameters (400), then the snapshot.
- **D-11 `/capabilities` features.** A feature is `true` only when its routes
  are implemented **and** `graph_projection` is `on`: with the switch off or
  misconfigured every graph route answers 503, so nothing is usable.
- **D-12 Ended edges on tabs and the graph.** Default `current` and `stale`
  (§5.4). `include_ended=true` adds ended rows to `/graph`, `/graph/expand` and
  the detail tabs, so the canvas can show *"1 current · 1 ended"* (UI5).
  *Raise:* UI5 and §5.4 disagree; the spec defines no parameter.
- **D-13 Sort tiebreakers.** Every sort ends with `id` (§5.2). Name sorts are
  `(lower(display_name), id)`, matching `idx_iga_workload_list`. *Raise:*
  §2.14.6 says name, then account, then id; the index has no account.
- **D-14 Facets.** A facet's counts apply every other active filter. The
  `account` facet always offers `unknown` (count may be 0). A facet whose
  optional count timed out is `null`.
- **D-15 Totals beyond 10 000.** `total_known: false`, `total_at_least: 10000`.

## Resources (§2.14.12, §5.3 Resources)

- **D-16 API `kind`.** `selector` when the stored kind is `selector` (text has
  `*`/`?`); otherwise `external` when the reference states an account that is
  not connected (D-3); otherwise `exact`. A selector in an unconnected account is
  `selector` with `account.connected = false`. `type` carries the typed kind
  (`s3_object`, `s3_bucket` ...), derived from the text at read time for
  selectors too, so an object selector never renders as a bucket. `service` is
  the ARN's service field (`null` for `*`).
- **D-17 `named_by_count`** counts **Allow** statements naming the resource as a
  positive target; `excluded_by_count` counts Allow statements excluding it via
  `NotResource`; Deny statements are neither (they are restrictions, shown on
  `/access` as `deny_statements_naming`).
- **D-18 `/resources/:id/access` via groups.** One row per (holder, grant): the
  grant's holder; for a group-held grant, also one row per current member user
  with `via_group` = the group.
- **D-19 `resource_policy`.** `read: true` when a resource-policy observation
  exists for this exact ARN; otherwise `read: false`, `has_deny: null`.
  *Raise:* "read, none exists" and "not read" are indistinguishable today (no
  observation is written for either).

## Evidence (§5.3 Evidence)

- **D-20 `status.effective_access`** is `"not_evaluated"`, as the frozen §5.3
  example. *Raise:* §2.14.9 calls the same value `unknown`.
- **D-21 Limitations follow the vocabulary table, not the example.** A
  selector-only grant carries `selector_may_match_nothing`, not
  `resource_existence_not_verified`. *Raise:* the §5.3 example lists both.
- **D-22 `permissions_boundary_present` / `deny_statements_present`** are
  computed for the claim's holder (and, for Deny, its groups). A group-held
  grant therefore never carries the member's boundary. *Raise:* E4's "priya's
  group grant" cannot produce it; /evidence has no path context.
- **D-23 `stale_since`.** The `published_at` of the first publication of the
  claim's connector after its `last_confirmed_at`. No column records it.
- **D-24 Facts.** Every linked observation, newest first, each with its
  `observed_in_run` (the observation's latest confirming run) and
  `last_confirmed_at`, filtered to source APIs that bear on the claim type
  (activity and credential-report observations are not facts about a grant).
  Sentences are composed from the claim rows, not from observation contents.
- **D-25 cloud_* reads.** `internal/igaread` reads, read-only and inside the
  snapshot: `cloud_connector` (labels, connected), `cloud_scan_run` (coverage,
  pipeline), `cloud_observation` (evidence, resource policy), `cloud_usage`
  (Access Advisor), `users` (display names). *Raise:* §2.1 says the read APIs
  never read cloud_*; these values have no iga_* home.

## Changes (§5.3 Changes, T5.4)

- **D-26 Run attribution.** One projection pass uses ONE timestamp — the
  publication's `published_at` — for every `valid_from`, `valid_to`,
  `first_seen_at`/`last_seen_at` write and lifecycle `occurred_at` it makes, so
  an event's revision and run are recovered by joining on `published_at`.
  *Why:* today `valid_from` is the database's transaction start and `valid_to`
  is taken after publication, so no join is exact.
- **D-27 Event shape, paging.** Defined in the implementation and documented
  beside the route; `kind=configuration` by default; 50 per page, `limit` 1–200
  accepted; keyset on `(at, event, id)`.
- **D-28 Remaining grants** on an ended grant/assignment: the holder's current
  grants whose statements name the same positive target, at the current
  revision.

## Classification (§5.5)

- **D-29 Request hash.** SHA-256 over canonical JSON of `{workload_id,
  actor_user_id, decision, purpose, reason, expected_version,
  undoes_decision_id}`, strings trimmed, `null` for an absent undo.
- **D-30 Validation.** Missing `operation_id`, `decision`, `reason` or
  `expected_version`: `400 invalid_parameter`. A decision equal to the current
  classification, an `unclassified` decision on a workload that is not
  `classified_agent`, an `undoes_decision_id` that is not this workload's latest
  decision, or a retired workload: `422 invalid_decision`.
- **D-31 Lock wait.** `SET LOCAL lock_timeout = '3s'`; a timeout is
  `504 query_timeout`.
- **D-32 Display names.** `users.name` unless empty or `Not Provided`, else
  `email`, else the user id — resolved in `internal/igaread`, so no iga_* file
  names `users` (isolation check).
- **D-33 History.** `GET …/classification`, newest first by `result_version`,
  not bound to a revision (classification is not part of one), paged 100.

## Traversal (§5.4)

- **D-34 `/graph` depth.** Walks every edge kind to the node/edge budgets;
  `assume_hops` (default 2, 0–4; above 4 is `400`) limits only `can_assume`.
- **D-35 Response shapes.** `/graph/expand` returns `{nodes, edges, frontier,
  truncated, next_cursor}`; `/graph/path` returns `{outcome, paths: [{nodes,
  edges}], more_paths, bound_by}`.
- **D-36 `crosses_account`** when both endpoints have a known account and they
  differ; statements and policies have no account.
- **D-37 `group_key`** = sorted actions (NotActions prefixed `!`), `→`, sorted
  positive target refs, plus a digest of condition and exclusions — statements
  differing in either never share a key.
- **D-38 `none_exists`** only when both frontiers are exhausted (the spec,
  literally).
- **D-39 Roots.** workload, identity, external_principal, statement, resource;
  a policy root is `400`.
- **D-40 Time reserve.** The traverser stops when less than a quarter of the
  budget (and at least 250 ms) remains, so a time-bound graph is always
  `200 truncated: time`, never 504.

## Trust (§4.7, T3.4, T4.7)

- **D-41 Edge source vs key.** The source column follows §4.7's table (a live
  identity in any connected account, else an external principal). The **edge
  key** uses the principal's normalized recognition string, not the endpoint
  type, so when the far account connects (or its identity retires) the edge is
  upgraded **in place** and keeps its history (§2.12). *Raise:* §4.7 (identity
  source) and §3 034 / §2.12 (external principal with derived resolution)
  disagree.
- **D-42 External principal identity.** `aws_account`: issuer `aws`, subject =
  the account id (bare id and `:root` ARN are one node). `aws_principal`: issuer
  `aws`, subject = the ARN (also unresolved unique ids and session ARNs).
  `aws_service`: issuer `aws`, subject = the service principal. `oidc`: issuer =
  provider host, subject = each positive `sub` value, or `*`. `saml`: issuer =
  the SAML provider ARN, subject `*` unless a `SAML:sub` value is given.
  `k8s_service_account` (IRSA and pod identity alike): issuer = the cluster's
  OIDC issuer, else the cluster ARN; subject = `system:serviceaccount:ns:sa`.
  `*` principal: `aws_principal`, subject `*`.
- **D-43 Mechanism on the edge.** `sts:AssumeRole` → `sts_assume_role`;
  `AssumeRoleWithWebIdentity` → `oidc_federation`; `AssumeRoleWithSAML` →
  `saml_federation`; pod identity → `eks_pod_identity`. A statement whose
  actions include no assume action produces no edge.
- **D-44 Deny and NotPrincipal** produce no edges; they set
  `trust_has_deny` / `trust_has_not_principal` on the role.
- **D-45 Unreadable trust.** Any skipped trust statement sets
  `trust_parse_error` (the role's trust edges go stale, never end); a role with
  no trust document and no error is treated as unreadable.
- **D-46 Trust content hash** covers Effect, Principal, NotPrincipal, Action,
  NotAction and Condition.
- **D-47 External principals have no support rows.** Their lifecycle is derived
  at read time (D-1); they are never retired by reconciliation.

## Collection (S3)

- **D-48 Authorization details.** One paginated call per filter (Role, User,
  Group, LocalManagedPolicy), so each surface has its own state. Fields the
  call does not return (role `MaxSessionDuration`, `Description`) are merged
  from the previous row's attrs, never blanked; fields it does return (tags,
  boundary) replace.
- **D-49 Skipped policy statements.** A document with any unusable statement
  gets `document_error = 'parse: N statement(s) unusable'`, so its statements
  go stale rather than end.
- **D-50 AWS-managed boundary policies** are fetched like attached ones.
- **D-51 Scenario 4 / E9(b).** After T3.1 a customer-managed document cannot
  fail to *fetch*; the fixture denies `GetPolicyVersion` on an attached
  **AWS-managed** policy instead. *Raise:* E9(b) and B12 name TicketRead.
- **D-52 Instance profiles** are not persisted (no column is specified).
- **D-53 Detail-call failures** keep the workload under its constructed ARN and
  make the surface `partial`; its execution-role state is left as the previous
  row had it rather than written `none`. *Raise:* 029 has no `unknown` state.
- **D-54 Regions.** `GET …/regions` → `[{name, opt_in_status, enabled,
  selected}]`; a selected region no longer enabled is listed `enabled: false`.
  `PATCH` validates against the enabled list; `422 {"error": {"code":
  "invalid_region", "regions": [...]}}`. A run keeps the regions it was claimed
  with. `ec2:DescribeRegions` is added to the template explicitly in the same
  bump as `bedrock-agentcore:GetGateway`.

## Pipeline and coverage (T2.2, T2.3)

- **D-55 Times.** `queued_at` = the run's `created_at` (T1.3 moves
  `requested_at` on every refused claim); `started_at` is cleared by a refused
  claim.
- **D-56 `last_published_rev`** = the revision that published this connector's
  latest projected run.
- **D-57 Manifest.** `iga_publication.manifest` is cumulative (the previous
  publication's partitions merged with this run's), as 033 says; `/coverage`
  reads the runs it names.
- **D-58 `prevents`.** `denied` → `surface_denied`; `partial` →
  `surface_partial`; `throttled`, `error`, `unknown` → `surface_stale`;
  `organizations: unsupported` → `organizations_not_collected`; `reached` and
  `not_selected` → `null`. *Raise:* no mapping is specified.
- **D-59 A projection job failed below its attempt ceiling** is reported as
  `projecting` with `retrying: true`, `attempts`, `last_error`.
