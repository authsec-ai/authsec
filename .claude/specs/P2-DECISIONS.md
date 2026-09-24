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
- **D-3 Account (revised after audit).** Workload: its connector's account (the
  estate scope's), always known. Identity: its ARN. Resource:
  `provider_attrs.account` (never the scanning account). For a **resource**,
  `connected` is the PROJECTED `provider_attrs.account_connected`, read in the
  revision's snapshot, so it cannot change while the revision stays the same
  (§1.4 l.261, §4.7 l.4288-4292, §2.14.11 l.1766-1770 "a disagreement at the
  same revision is a bug"). Workloads and identities count as connected by
  construction as of the revision. `label` = the connector's `display_name`,
  falling back to the account id — display only. The projector's
  `ConnectedAccounts` (load.go) excludes revoked connectors (D-61). *Raise:* a
  resource's `account_connected` is rewritten only when a pass names it, so after
  a new account publishes, references made only by other connectors' policies
  stay `false` until those connectors are projected again.
- **D-4 Detail routes when nothing is published.** `404 not_found` (no object
  can exist before the first publication; §5.1's `not_published` is a list
  state). Lists answer `200`, empty `data`, `graph_state: not_published`.
- **D-5 Route ids.** `/:id` accepts the bare UUID or the typed reference of the
  route's own type. Anything else, including a malformed id or another type's
  reference, is `404` (no hint), per §5.2.
- **D-6 Readable rows (spec-settled, §2.1 l.322-326).** Graph routes read only
  rows the projector owns: `provider = 'aws'` with at least one support row. A
  GitHub row, or an AWS node with no support row, is `404` with no hint.
  External principals (no provider column, no support rows) are readable
  without that condition; their state comes from their `can_assume` edges (D-1).
- **D-7 (spec-settled, §5.1 l.5574-5575, 5618, 5639).** The requested `rev` and
  the cursor's `rev` are each checked against the current revision in the same
  snapshot; either one stale is `409 revision_stale`.
- **D-8 `IGA_CURSOR_SECRET` unset.** A random per-process key and a startup
  warning. Cursors then fail `400 cursor_invalid` across restarts or replicas
  (the console restarts the list). Never a forged position. *Raise:* the spec
  names the secret but not its absence.
- **D-9 401/403 envelope (revised after audit).** Graph routes return the §5.2
  envelope for 401 and 403 too (§5.2 "Errors, on every route"). The permission
  decision is unchanged: `RegisterIGAGraphReadRoutes` receives a `require` that
  wraps `middlewares.Require` and rewrites only its deny body to
  `{"error":{"code":"forbidden","message":...}}`; a missing or invalid token on
  a graph route answers `{"error":{"code":"unauthenticated",...}}` (a wrapper
  on the graph routes' group). The shared middleware's bodies do not change for
  Phase 1 `/api/iga/v1` routes or any other product.
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
- **D-13 Sorts (revised after audit).** Every sort ends with `id` (§5.2).
  Identities, resources and Used-by: name sorts are `(lower(name), account id,
  id)` with unknown account last (§2.14.6 l.1433, 1442, 1456, 1481). Resources
  `kind` sort (the default) ranks exact < selector < external, then name, then
  account, then id (l.1444) — never alphabetical. Workloads provisionally keep
  §5.3's `(lower(display_name), id)` keyset on `idx_iga_workload_list`.
  Other sort keys: `account` on the account id with unknown last in both
  directions; `classification` by rank provider_native_agent < classified_agent
  < unclassified; identity `kind` iam_role < iam_user < iam_group; `service`
  alphabetical, null last; `last_confirmed` D-1's derived value, nulls last; `-`
  reverses the rank. *Raise:* §2.14.6 (name, then account) vs §5.3 and the
  workload index (no account).
- **D-14 Facets (spec-settled, §5.2 l.5715, §2.14.10 l.1671-1672, §5.1
  l.5600).** Each facet's counts apply every other active filter; the account
  facet always includes `unknown` (0 where the kind never lacks an account); the
  `region` facet always offers `not_stated`; a timed-out facet is `null`. Every
  facet entry carries a label.
- **D-15 Totals (spec-settled, §5.2 l.5719-5723).** Above 10 000: no `total`,
  `total_known: false`, `total_at_least: 10000`; a timed-out count:
  `total_known: false` and no `total_at_least`.
## Resources (§2.14.12, §5.3 Resources)

- **D-16 API `kind` (revised after audit).** `selector` when the stored kind is
  `selector`; otherwise `external` when the reference states an account and the
  revision's projected `account_connected` is false (D-3); otherwise `exact`.
  Fixed per revision, never computed from live connector state. A selector in an
  unconnected account stays `selector` with `account.connected = false`. `type`
  carries the typed kind (`s3_object`, `s3_bucket` ...), derived from the text
  for selectors too; `service` is the ARN's service field (`null` for `*`).
  *Raise:* §2.14.6's wireframe (l.1402-1404) calls a KMS key in a connected
  account "External reference", contradicting §1.4 l.261.
- **D-17 Counts (spec-settled except the Allow rule).** `named_by_count` counts
  positive (`mode = resource`) targets; exclusions are `excluded_by_count`;
  `excluded_by` holds Allow statements naming it in NotResource (§5.3 l.5940,
  5948-5954; §5.4 l.6096). *Decision:* `named_by_count` counts Allow statements
  only. `deny_statements_naming` = Deny statements with a `mode = resource`
  target on this resource; a Deny whose NotResource names it is in neither list.
  Counts are optional queries capped at 1000: `{value, exact: true}` at or under
  the cap, `{value: 1000, exact: false}` above it (rendered 1000+), `{value:
  null, exact: false}` on timeout. `used_by_count` counts distinct workloads over
  executes_as ∪ task_execution_role in state current or stale — the same
  predicate as the Used-by workloads section and the `used_by=workloads` filter.
- **D-18 `/resources/:id/access` via groups (revised after audit).** One row per
  (holder, grant) for the grant's own holder; for a group-held grant, also one
  row per member user whose `member_of` is current or stale, with `via_group` =
  the group and the membership's state beside the grant's; a row is stale if
  either is stale — marked, never dropped.
- **D-19 `resource_policy` (revised after audit).** Count only observations that
  belong to the current revision: subject = this exact ARN, first recorded at or
  before the revision's `published_at`, by a run that published (a publication
  rev at or below the current rev). If one qualifies, `read: true` and
  `has_deny` from the latest such observation; otherwise `read: false`,
  `has_deny: null`. `resource_policy_not_projected` uses the same scoping.
  *Raise:* "read, none exists" and "not read" are indistinguishable today.
## Evidence (§5.3 Evidence)

- **D-20 `status.effective_access`** is `"not_evaluated"`, as the frozen §5.3
  example. *Raise:* §2.14.9 calls the same value `unknown`.
- **D-21 Limitations (spec-settled, §5.3 l.6019-6035).** The table's conditions
  are exact: a selector target carries `selector_may_match_nothing`, an exact
  one `resource_existence_not_verified`, a statement naming both kinds carries
  both. *Raise:* the §5.3 example's `resource_existence_not_verified` on the
  selector-only grant (l.6010) is wrong.
- **D-22 Boundary and Deny (revised after audit).** Computed for the claim's
  holder (and, for Deny, the holder's groups). For a group-held grant,
  `permissions_boundary_present` is ALSO emitted when a current member user of
  the group has a boundary assignment, with the count and the member refs —
  the grant reaches that member only on a path through a restricted node (§2.6
  l.549, §5.4 l.6099-6101); this produces E4's "for priya". *Raise:* the
  vocabulary row (l.6027) says "the holder"; whether a member's own Deny
  statements bear on a group grant is unstated.
- **D-23 `stale_since` (revised after audit).** The `published_at` of the first
  publication of the claim's connector whose `rev` is greater than the rev of
  the publication of the claim's last confirming run (`last_confirmed_by` →
  `iga_publication.scan_run_id`). For a node, use the support row D-1 draws
  `last_confirmed_at` from. Computed from runs and revisions, never by comparing
  timestamps.
- **D-24 Facts (revised after audit).** A fact is one of the claim's junction
  rows with `relation = 'supports'` whose observation was still confirmed as of
  the claim's last confirming run (`last_confirmed_by`); links whose observation
  was last confirmed by an earlier run (an older policy version) are dropped on
  read. Each fact's `observed_in_run` and `last_confirmed_at` are the CLAIM's
  `last_confirmed_by` / `last_confirmed_at` — never the observation's own, which
  collection stamps before publication. Keep only source APIs that bear on the
  claim type (§4.8's table). Sentences are composed from the claim rows.
  *Raise:* the junction has no current-link marker.
- **D-25 cloud_* reads (spec-settled).** `internal/igaread` reads, read-only in
  the snapshot: `cloud_observation` (evidence, raw, resource policy),
  `cloud_scan_run` (coverage, pipeline), `cloud_connector` (labels),
  `cloud_usage` (Access Advisor), `cloud_identity` / `cloud_workload` (/lookup
  only), `users` (display names). Graph-bearing cloud_* reads are keyed to runs
  the current revision was built from (D-57), never an unpublished run;
  `/pipeline` reports live state by design.
## Changes (§5.3 Changes, T5.4)

- **D-26 Run attribution (implemented with T5.4).** One projection pass uses
  ONE timestamp — the publication's `published_at` — for every `valid_from`,
  `valid_to`, `last_confirmed_at`, `first_seen_at`/`last_seen_at` write and
  lifecycle `occurred_at` it makes, so an event's revision and run are
  recovered by joining on `(workspace_id, published_at)`. The projector reads
  its clock once, when the revision is allocated (`Projector.At`, normalised
  by `igagraph.PassTime` to UTC microseconds); Reconcile takes the same value
  from the pass's event log; `valid_from` is always written explicitly, never
  the column default `now()` (the transaction's start). The graph repository
  refuses an edge, support, node, revision, event or publication write
  without it (`ErrNoPassTime`). *Why:* before, `valid_from` was the
  database's transaction start and `valid_to` was taken after publication, so
  no join was exact. *Raise:* nothing in §3 makes the join unique; propose
  `CREATE UNIQUE INDEX uq_iga_publication_published_at ON
  public.iga_publication (workspace_id, published_at)` (D-27a is the read
  side's answer when two publications share a time).
- **D-27 Event shape, paging (defined with T5.4).**
  `GET /{workloads|identities|resources}/:id/changes?kind=&limit=&cursor=&rev=`.
  `kind` is `configuration` (the default: every event but `coverage_changed`)
  or `coverage` (only `coverage_changed`); `limit` 1–200, default 50; any
  other parameter is `400 invalid_parameter`. Newest first, keyset on `(at,
  event, id)`, all descending; the cursor's route is `<type>/<id>/changes`
  (D-62), its filter hash is over the EFFECTIVE kind (an absent kind and
  `kind=configuration` page the same list), its sort `-at`. The §5.2 list
  envelope (D-77) with `meta.kind` and `meta.history_begins` (D-70; null
  when the object has no `first_seen` event) added; `meta.coverage` names
  the object's own partitions' gaps in the runs the current revision was
  built from (D-73), `affects: "changes of this <type>"`. Like every object
  route, the object must be this workspace's graph row (D-6), in any
  lifecycle, and before the first publication there is none: `404` (D-4).
  Each event:
  `{id: "<event>:<uuid>", event, at, rev, run: "cloud_scan_run:<id>", subject,
  claims: [refs, subject first], reason, via?, detail, before?, after?,
  remaining?, paths?, labels: {ref: name}}`. `detail` per event: lifecycle
  `{object}`; relationship `{type, source, target, mechanism?, state}`;
  assignment `{policy, holder, assignment_kind, state}`; grant `{policy,
  statement, holder, assignment, state, actions, not_actions?, targets}`;
  `statement_revised` `{policy, statement}` with before/after `{statement
  (verbatim), policy_version_id, content_hash}` (D-69); `statement_replaced`
  `{policy}` with before/after `{policy_version_id, statements: [{statement,
  content, content_hash}]}` (D-69, D-27c); `coverage_changed`
  `{integration, account_id, surface}` with before `{state, recorded, run,
  coverage}` and after `{state, recorded, error_code, api, error, prevents}`
  (D-58). `detail.state` is the row's state
  at the current revision. The full contract is in
  `internal/igaread/changes.go`, the route's summary beside it in
  `controllers/platform/iga_graph_read_changes.go`.
- **D-27a Attribution on read.** `at` is rendered to the microsecond (it IS
  the pass's `published_at`, D-26). A lifecycle event carries its own `rev`
  and run; a revision its `first_seen_run_id` (the rev is that run's
  publication's); every start and end joins its time to the ONE publication
  with that `published_at`. A time shared by two publications, or by none (a
  row written before D-26), renders `rev` and `run` null — never guessed.
- **D-27b `statement_revised`.** Only a revision whose immediate predecessor
  on the same statement has DIFFERENT content: the first revision is not an
  edit, and the revision a restored statement reopens with unchanged content
  is a restoration (its lifecycle `restored` event says so).
- **D-27c `statement_replaced`.** One event per (policy, run): its subject is
  the policy, its id derived from (policy, run) (`md5(policy || ':' ||
  run)::uuid`, as `coverage_changed`'s is from (run, surface)), so two
  replacements of one policy are two ids. `before` lists every Sid-less
  statement of the policy retired `unsupported` in that run, `after` every
  statement of it first seen or restored in the same run. Listed as they are,
  never paired: with several Sid-less statements edited in one run nothing
  says which replaced which. A Sid-less statement deleted with nothing
  beginning in its policy in that run is its grant's end only, and a Sid-keyed
  statement deleted beside a new one is a deletion and a new statement, never
  a replacement. The grant ends and starts a replacement causes are listed
  beside it, not folded into it (the view may group by run).
  `policy_version_id` (D-69) comes from the policy-version observations (the
  D-66 source; a Sid-less statement has no revision, and `iga_policy` keeps
  only its current version): `after` is the version the replacing run read,
  `before` the version read by the runs that last confirmed the ended
  statements, published before the replacing run. A run is proven to have
  read a version only when that version's observation was first recorded or
  last confirmed by it, from a readable document; a side is `null` when no
  such proof exists (a later re-read moved the confirmation on; a restored
  statement's support row keeps only its later confirmation) or the runs read
  more than one version. An inline policy has no versions: `""` both sides,
  as its revisions store. *Raise:* D-69 cannot be met exactly for Sid-less
  statements from the §3 DDL; propose `ALTER TABLE public.iga_lifecycle_event
  ADD COLUMN policy_version_id text NOT NULL DEFAULT ''` (a statement's
  `first_seen`/`restored`: the version read in that pass) and `ALTER TABLE
  public.iga_entitlements ADD COLUMN last_policy_version_id text NOT NULL
  DEFAULT ''` (the version of its last confirmation, kept on retirement).
- **D-27d Scope limits (D-68 applied).** An identity's revision and
  replacement events are those of statements it held a grant to WHILE that
  grant was valid (`valid_from <= at <= valid_to`); a workload's events via an
  execution identity are those at instants its `executes_as` edge to that
  identity was valid, inclusive at both ends, one row per event. Deny
  statements appear on the resources they name, not on the identity (it holds
  no grant to them). *Raise:* whether an identity should see its own Deny
  statements' revisions.
- **D-27e `coverage_changed` lanes (D-70 applied).** One lane per (supporting
  connector, surface) of the object's support rows' partitions, rebuilt by the
  projector's partition table and accepted only when the rebuilt key is the
  stored `partition_key` (a partition this build cannot rebuild claims no
  transitions). The sequence is that connector's runs with a publication in
  the snapshot, in revision order, from the support row's first pass; an ENDED
  support speaks only up to the run that last confirmed it. An absent entry
  reads as `canEnd` reads it: a required surface absent was not looked at
  (`unknown`); a scanner marker absent means the scanner ran (`reached`).
  Transitions only; the event id is derived from (run, surface).
- **D-27f Resource Changes use current targets.** A statement's targets are
  replaced with its content (`ReplaceTargets`), so a resource's Changes are
  those of the statements that name it NOW (a retired statement keeps its last
  targets). A statement edited to stop naming the resource drops out of that
  resource's Changes, earlier events included. *Raise:* targets have no
  validity period; a historical target table would let the resource keep that
  history.
- **D-27g Grant history and the Allow rule (added in the T5.4 review).** §3
  rule 7 ("every grant query joins its statement with `effect = 'allow'`")
  is applied to HISTORY as the statement stood when the grant started: a
  grant is a Changes event when the statement revision covering its
  `valid_from` is Allow; with no covering revision (a Sid-less statement,
  whose key is its content, so its effect cannot change in place) the
  statement's current effect decides. A covering revision naming no Effect is
  not Allow. The D-28 candidates (what REMAINS) keep the current effect.
  *Why:* a Sid-keyed statement keeps its id when edited, effect included
  (§2.6), so the current effect would erase an Allow grant's start and its end
  the moment the statement became Deny, and the removal would carry no
  `grant_ended` and no `remaining`; a grant row written for a statement that
  was Deny at the time is still never shown. *Raise:* rule 7 assumes a
  statement's effect never changes in place.
- **D-28 Remaining grants (revised after audit; implemented with T5.4).** At
  the current revision, the holder's non-ended grants (`current` and `stale`,
  each with its state and `last_confirmed_at`) whose statements name the same
  positive target. When only stale grants remain, the event says the path
  remains and marks it stale; it says no path remains only when none, current
  or stale, is left. On `grant_ended` the targets are the ended grant's
  statement's positive targets; on `policy_detached` (attached or inline) the
  positive targets of every Allow statement granted through the detached
  assignment, and a grant still reached through that assignment is not
  another path. A boundary detach carries neither field (it grants nothing).
  Rendered as `remaining: [{grant, state, last_confirmed_at, policy,
  statement, targets}]` (current first) and `paths: [{target, remains:
  current|stale|none}]`, one per target of the ended claim. Matching is by
  reference: a selector and an exact ARN are different targets.
## Classification (§5.5)

- **D-29 Request hash.** SHA-256 over canonical JSON of `{workload_id,
  actor_user_id, decision, purpose, reason, expected_version,
  undoes_decision_id}`, strings trimmed, `null` for an absent undo.
- **D-30 Validation (revised after audit).** `400 invalid_parameter`: a missing
  `operation_id`, `decision`, `reason` or `expected_version`; a blank `reason`; a
  `decision` other than `classified_agent` / `unclassified`; an `operation_id`
  that is not a UUID; `reason` over 2000 characters or `purpose` over 500. Then
  §5.5's order: lock (404), operation lookup (replay / 422
  `operation_id_reused`), provider-native (422), version (409 with the current
  decision). Only after those: `422 invalid_decision` for `unclassified` on a
  workload that is not `classified_agent`, an `undoes_decision_id` that is not
  this workload's latest decision, or a retired workload. `classified_agent` on
  an already `classified_agent` workload at the expected version is ALLOWED — the
  spec's deliberate replacement (§2.14.3 l.1109: a new decision row, `previous =
  classified_agent`, version bumped).
- **D-31 Lock wait.** `SET LOCAL lock_timeout = '3s'`; a timeout is
  `504 query_timeout`.
- **D-32 Display names.** `users.name` unless empty or `Not Provided`, else
  `email`, else the user id — resolved in `internal/igaread`, so no iga_* file
  names `users` (isolation check).
- **D-33 History (revised after audit).** `GET …/classification`: newest first by
  `result_version`, 100 per page (`limit` 1–200). It runs under §5.1 like every
  route (a stale `rev` is 409; the cursor carries `rev`). No
  `classification_seq` binding: it neither filters nor sorts on classification,
  and a new decision's version is higher than every existing one.
## Traversal (§5.4)

- **D-34 `/graph` depth.** Walks every edge kind to the node/edge budgets;
  `assume_hops` (default 2, 0–4; above 4 is `400`) limits only `can_assume`.
- **D-35 Response shapes (revised after audit).** `/graph/expand`: `{nodes,
  edges, frontier, truncated, next_cursor}`. `/graph/path`: `{outcome, paths:
  [{nodes, edges, limitations}], more_paths, bound_by}`, shortest first. Every
  node and edge on `/graph`, `/graph/expand` and in paths carries `limitations`
  computed by the SAME function as `/evidence`, limited to codes that need no
  facts (account_not_connected, surface_*, conditions_not_evaluated,
  negated_statement, not_principal_unresolved, caller_permission_not_evaluated,
  deny_statements_present, permissions_boundary_present); each path carries the
  union of its steps; `effective_access_not_evaluated` and
  `organizations_not_collected` are stated once in meta. Every
  `crosses_account` edge carries the far account's coverage limitations.
  `direction` is required on `/graph` and `/graph/expand` (400 if absent).
- **D-36 `crosses_account`** when both endpoints have a known account and they
  differ; statements and policies have no account.
- **D-37 `group_key`** = sorted actions (NotActions prefixed `!`), `→`, sorted
  positive target refs, plus a digest of condition and exclusions — statements
  differing in either never share a key.
- **D-38 `none_exists` (spec-settled, §5.4 l.6143).** Only when both frontiers
  are exhausted before any budget binds; otherwise `not_found_within_budget`
  with `bound_by`. *Raise (optional):* one exhausted frontier already proves no
  path.
- **D-39 Roots (spec-settled, §5.4 l.6071-6072, §5.2).** workload, identity,
  external_principal, statement, resource. A policy or claim ref: `400
  invalid_parameter`. A well-formed ref not in this workspace: `404`.
- **D-40 Time reserve (revised after audit).** The traverser checks the
  remaining deadline before each level and stops before starting one when less
  than a quarter of the budget (at least 250 ms) remains; each level runs in a
  savepoint with a local statement timeout inside the remaining budget, so an
  overrunning level is rolled back and the earlier levels are returned as `200
  truncated: time`. If even the root cannot be read in time: `504
  query_timeout`, nothing partial (§5.1 l.5602).
## Trust (§4.7, T3.4, T4.7)

- **D-41 Trust edge keys (revised after audit — supersedes both earlier
  versions).** can_assume keys follow §4.4/§4.6/§4.7 with no exception: trust
  statement key + source endpoint key + target endpoint key. An identity
  endpoint is `EndpointKey` (its immutable key when it has one); an external
  principal endpoint is `ExternalPrincipalKey(issuer, subject)`. A principal's
  ARN never stands in for an identity endpoint (that is B7's ARN-only defect).
  **No edge is ever re-pointed in place**; `UpsertRelationship` does not touch
  source columns, and `EndEdgesOnSubject` has no can_assume exemption. Choosing
  the source: (1) if a live `iga_external_principal` for (issuer, subject)
  already exists, it stays the source and its edges keep their history; when it
  now exactly matches a live identity in a connected account, the projector
  records a `derived` resolution on that NODE (034 `resolved_identity_account_id`,
  `resolution_basis = derived`, `resolution_rule`) — §2.12's continuity is the
  node's, not the edge's; (2) otherwise an exact role/user ARN of a live
  identity in any connected account becomes that identity as the source, basis
  `declared` (§4.7 l.4411); (3) otherwise an external principal per §4.7's
  table. When an identity source retires or is recreated its edges end
  `subject_retired` / `subject_recreated` and the principal is re-sourced as a
  new edge. *Raise:* §4.7 l.4411 vs 034 l.3012-3016, §2.3 l.397-399, §2.12
  l.841-842.
- **D-42 External principal identity (revised after audit).** `aws_account`:
  issuer `aws`, subject = the account id (bare id and `:root` ARN are one node).
  `*` principal (`"*"` or `{"AWS": "*"}`, one node): `aws_account`, subject `*`,
  account null, label "any AWS principal" (§4.7 l.4414). `aws_principal`: issuer
  `aws`, subject = the ARN (also unresolved unique ids and session ARNs).
  `aws_service`: issuer `aws`, subject = the service principal. `oidc`: EVERY
  Federated OIDC principal, EKS IRSA included (§4.7 l.4416); issuer = the
  provider URL without scheme, keeping host AND path (what oidcIssuerFromARN
  returns after `:oidc-provider/`); subject = each positive `sub` value verbatim,
  or `*`. `saml`: issuer = the SAML provider ARN, subject `*` unless a `SAML:sub`
  value is given. `k8s_service_account`: ONLY EKS pod-identity associations
  (§1.4 l.232, §4.7 l.4393); issuer = the cluster's OIDC issuer without scheme;
  subject `system:serviceaccount:ns:sa`. No cluster-ARN fallback: a cluster with
  no issuer leaves the association unresolved (its key must not change between
  scans). *Raise:* `ExternalPrincipalKey` omits the mechanism, so an IRSA `oidc`
  node and a pod-identity `k8s_service_account` node for the same service
  account would collide on `uq_iga_external_principal_key` — until decided, the
  pod-identity node's subject is prefixed `pod:` to keep them distinct.
- **D-43 Mechanism on the edge.** `sts:AssumeRole` → `sts_assume_role`;
  `AssumeRoleWithWebIdentity` → `oidc_federation`; `AssumeRoleWithSAML` →
  `saml_federation`; pod identity → `eks_pod_identity`. A statement whose
  actions include no assume action produces no edge.
- **D-44 Deny and NotPrincipal (spec-settled, l.231, 4379, 4417, 5893, 6034).**
  No `can_assume` edges; they set `trust_has_deny` / `trust_has_not_principal` in
  the role's provider_attrs; every path into a role with
  `trust_has_not_principal` carries `not_principal_unresolved`. *Raise:* l.371
  says a trust Deny is "shown as a restriction or limitation" but §5.3 has no
  code for it.
- **D-45 Unreadable trust.** Any skipped trust statement sets
  `trust_parse_error` (the role's trust edges go stale, never end); a role with
  no trust document and no error is treated as unreadable.
- **D-46 Trust content hash** covers Effect, Principal, NotPrincipal, Action,
  NotAction and Condition.
- **D-47 External principals have no support rows.** Their lifecycle is derived
  at read time (D-1); they are never retired by reconciliation.

## Collection (S3)

- **D-48 Authorization details (spec-settled, §1.4 l.209-212, §1.3 l.142).** One
  paginated call per filter, each with its own surface state; fields the call
  returns (tags, boundary, trust document, last used, instance profiles)
  replace, fields it does not return are kept. *Raise:* RoleDetail returns
  neither MaxSessionDuration nor Description, which §1.4 lists as captured;
  existing rows keep a frozen value and new roles get none.
- **D-49 Skipped policy statements.** A document with any unusable statement
  gets `document_error = 'parse: N statement(s) unusable'`, so its statements
  go stale rather than end.
- **D-50 AWS-managed boundary policies** are fetched like attached ones.
- **D-51 Scenario 4 / E9(b).** After T3.1 a customer-managed document arrives in
  the LocalManagedPolicy listing, so a `GetPolicyVersion` denial cannot make it
  unreadable. Scenario 4 denies `GetPolicyVersion` on an attached AWS-managed
  policy that is the only one naming its resource. B12 may use either that or a
  customer-managed `parse:` document_error (D-49). *Raise:* E9(b) only (l.6458
  names customer-managed TicketRead).
- **D-52 Instance profiles (revised after audit).** Store the role's
  `InstanceProfileList` (ARNs, names) in its `cloud_identity.attrs` (§1.4
  l.209), replaced on each successful read. Descriptive only: not projected, not
  in `provider_attrs`. EC2's `executes_as` still resolves through
  `iam:GetInstanceProfile`.
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

- **D-55 Times (corrected).** `cloud_scan_run` has no `created_at` (020), and
  T1.3 moves `requested_at` on every refused claim, so the original enqueue
  time is stored nowhere. `queued_at` = `requested_at`, documented as "last
  (re)queued at". A refused claim clears `started_at` (Requeue), so
  `started_at` means "began collecting". *Raise:* §2.14.7's wait metric (p50/p95
  enqueue → claim) needs a column §3 does not have.
- **D-56 `last_published_rev` (revised after audit).** The workspace revision the
  current graph is at (= `current_rev`) for every connector with at least one
  published run; null before its first publication ("First publication
  pending"). This is what the §5.3 example shows (two accounts at 41). The rev
  that published a connector's own run is on the run (`projection.rev`).
- **D-57 Manifest (spec-settled; the code is corrected to match).** The spec
  says `iga_publication.manifest` is cumulative ("every partition's watermark AS
  OF this revision", 033 l.2888-2890) and keyed by a partition key that covers
  scope and connector (l.2840-2841, 4480-4481, 4832-4834). The code's
  `Partition.Key()` omits scope and connector and `manifestOf` records only the
  publishing run's partitions: a code bug, fixed on graph after Wave A (key
  gains scope and connector; manifest merges the previous publication's). No
  partition key has been persisted outside test databases, so the key change
  needs no migration. Readers of "the runs the current revision was built from"
  may read the manifest or `iga_projection_state` (equivalent at the current
  revision).
- **D-58 `prevents` (revised after audit).** `denied` → `surface_denied`;
  `partial` → `surface_partial`; `throttled`, `not_selected` (§2.14.13
  l.1856-1859: "earlier results are kept and marked stale"), `unknown`, `stale`,
  `constrained` → `surface_stale`; `organizations: unsupported` →
  `organizations_not_collected`; any other `unsupported`, `not_configured` and
  `reached` → `null`. *Raise:* no mapping is specified, and l.5792 cites "§5.4's
  limitations vocabulary", which is in §5.3.
- **D-59 A projection job failed below its attempt ceiling** is reported as
  `projecting` with `retrying: true`, `attempts`, `last_error`.

## Added after the gap analysis's completeness critic

- **D-60 Partition keys are frozen once deployed.** `Partition.Key()` is
  persisted on every support, edge, assignment and projection-state row. After
  the D-57 key fix lands (before any deployment), never rename a surface string
  or add a required surface to an existing partition kind without a
  partition_key backfill. A new surface may be collected and reported without
  becoming required.
- **D-61 One definition of "connected".** The projector's `ConnectedAccounts`
  (load.go) uses the same rule as the read side (D-3): a connector exists and is
  not `revoked`.
- **D-62 Cursor routes carry the object.** Per-object paged routes put the
  object id (and the section) in `Cursor.Route` — `workloads/<id>/resources`,
  `identities/<id>/used-by/workloads`, `resources/<id>/access`,
  `<type>/<id>/changes`, `workloads/<id>/classification`,
  `graph/expand/<node>/<edge>/<direction>` — so a cursor for one object cannot
  page another.
- **D-63 Regions on rows.** Identities (IAM) render `region: "global"`; a
  resource or workload with no stated region renders `null` (Region not stated,
  never `global`, §2.14.10).
- **D-64 Credentials.** A key whose status becomes Inactive is updated in place
  on its existing row (found by source key regardless of lifecycle), never
  inserted beside it: 028's partial unique index excludes revoked rows, so an
  insert never conflicts and duplicates accumulate. *Raise:* §2.5 reserves
  `revoked` for absence under four conditions; AWS `Inactive` is a status.
- **D-65 Presence.** `/evidence` accepts an object ref (`workload:<id>` ...)
  meaning that object's presence (all its support rows); `presence:<id>` names
  one support row.
- **D-66 Target evidence.** No junction table exists for
  `iga_entitlement_target` (032/036 define three). A target's facts come from its
  statement's policy-version observation. *Raise:* §4.8 and the T4.9 gate expect
  target evidence.
- **D-67 Policy or statement retired vs not_seen.** Reconciliation ends edge
  partitions `not_seen` before `retireUnsupported` runs (§4.10's own
  `Reconcile`), so a retired policy's assignments end `not_seen`, not
  `policy_retired`. *Statement case (added in the m1/bdb review):* the same
  holds for the grants of a Sid-less statement that was edited (replaced) —
  they end `not_seen`, not the `statement_retired` of §2.7 l.605 and the
  cascade table (l.5241): the grant partition, read in full, closes them in
  the pass before the statement retires. A cascade reason is written only
  when the partition could not end the edge itself (P2-EVIDENCE §6.5). The
  read side (Changes) never relies on `ended_reason` to classify an end; it
  uses lifecycle events and assignment and grant periods (a replacement is
  `statement_replaced`, D-27c). *Raise:* the T5.2 gate wording; §2.7's
  Sid-less row and the cascade table.

## Added after the decisions audit (gaps no entry covered)

- **D-68 Changes scope.** Workload: its own lifecycle; its executes_as and
  task_execution_role starts and ends; the assignment, grant,
  statement_revised and statement_replaced events of identities it executes_as
  (executes_as only), limited to the interval that edge was valid and tagged
  `via: identity:<id>`. Identity: its lifecycle; relationships it is either end
  of; assignments and grants it holds; revisions/replacements of statements it
  holds a grant to. Group events are not copied onto members (the member sees
  its member_of start/end). Resource: its lifecycle; grant and statement events
  of statements naming it positively (never NotResource). No walk through
  can_assume or member_of. *Raise.*
- **D-69 Policy default-version change.** No new event type: statement_revised
  and statement_replaced carry `policy_version_id` before/after; a version
  change that alters no statement produces no event. *Raise:* §2.6 l.560-562.
- **D-70 coverage_changed.** The sequence is each supporting connector's
  published runs, by `published_at`, up to the run the current revision was
  built from; the object's surfaces are its partitions' RequiredSurfaces and
  RequiredScanners; transitions only. `meta.history_begins` = the object's
  first_seen event time; nothing earlier is claimed.
- **D-71 Coverage detail fields.** Per-run coverage gains optional additive
  fields stamped at collection: `error_code` and `api` per surface, and for
  `policy_documents` a bounded `items` list `[{policy, version, error}]` (100
  plus `truncated: true`). Readers use the run the revision was built from; old
  runs return null. Never parse `Error` prose into a code; never read
  `cloud_policy.document_error` live.
- **D-72 /coverage fields.** `count`: the stored count only when `reached`, else
  null. `since`: `published_at` of the earliest run in an unbroken streak of the
  same state for that connector and surface (walk ≤ 50 published runs, else
  null). Nothing published: 200, `data: []`, `graph_state: not_published`. Per
  account: `template {deployed, current, outdated}` from connector attrs vs the
  build's template version, stated as a fact, never as a denial's cause.
- **D-73 meta.coverage.** One server-side table maps each list route to its
  surfaces — workloads: `<svc>:<region>`, `compute:<region>`, `workload_scan`,
  narrowed by account/region filters; identities: `iam_roles`, `iam_users`,
  `iam_groups` (by kind), `permission_scan`; resources: `iam_policies`,
  `policy_documents`, `permission_scan`. Emit every entry not `reached`,
  `not_selected`→stale per D-58, excluding `unsupported`; `organizations` is never
  a banner. `affects` is a fixed per-surface string from the same table. Detail
  responses carry entries for the object's own partitions. A revoked account in
  scope adds `{account_id, surface: "*", state: "revoked"}`.
- **D-74 Stale reason.** A stale row, node or edge carries `stale_reason:
  [{account_id, surface, state, since}]` from the required surfaces of its
  partitions whose revision run did not reach them; a document-protected row
  names `policy_documents`.
- **D-75 List filters.** §5.3 is the contract plus §2.14.10's defined filters:
  `provider` accepts only `aws` (else 400); `integration` on identities and
  resources = objects with a non-ended support row from that connector
  (`cloud_connector:<uuid>` or bare UUID; a foreign id filters to nothing, a
  malformed one is 400); `region` on identities is accepted and never filters
  (IAM is global). Any other unknown parameter is `400 invalid_parameter` naming
  it.
- **D-76 `q`.** Display-name substring, case-insensitive; exact, case-sensitive
  matches on the full ARN/pattern, the provider id (identities: immutable_key;
  workloads: the ARN's resource-id segment) and a 12-digit account id (the
  object's own account; unknown-account objects never match).
- **D-77 Tab envelopes.** Single-collection tabs (workloads/:id/resources,
  resources/:id/access, referenced-by, changes, classification history) use the
  §5.2 list envelope (limit 1–200, default 100; Changes 50). Multi-section tabs
  (workloads/:id/identities, identities/:id/used-by) use the detail envelope;
  each paged section is `{items, next_cursor, total_known, total}` and
  `?section=<name>&cursor=` returns only that section. `/permissions` is unpaged
  with a hard statement cap and `truncated: true` when it binds.
- **D-78 Workload › Resources holders.** The identities reached by the
  workload's executes_as edges (current or stale); task_execution_role excluded
  (§2.2 l.359); no can_assume hops. `restrictions` is holder-level: the number of
  Deny statements the holders hold and whether any holds a boundary (matching is
  not evaluated).
- **D-79 Grouped-edge evidence.** `/evidence` accepts `claim` repeated (1–50),
  read in one snapshot; `data` is an array in request order when more than one
  claim is given; a summary sentence only when every claim is a grant with the
  same holder and group_key; any claim not found makes the whole request 404.
- **D-80 Evidence details.** Add `freshness.valid_to` and
  `freshness.ended_reason` (null unless ended). `status.collection`: `complete`
  when every required surface and scanner of the claim's partition is reached;
  `partial` when any is partial; `stale` otherwise. A `coverage:<run>:<surface>`
  claim must name a run the revision was built from (else 404). `raw` is
  `[{observation, source_api, sanitized_facts}]` aligned with facts. An
  external-principal ref takes its facts from the trusting roles' observations.
- **D-81 /lookup.** Reads the cloud row in the snapshot, builds its key with
  sourcekey.go, matches `source_key` AND `immutable_key` when the row has one,
  and requires a support row from the row's own connector; prefers the active
  object, else the retired one. `{data: {ref, lifecycle}, meta: {rev}}`;
  revision-bound; nothing published / no match / foreign row → 404.
- **D-82 Revision-bound routes.** `/coverage` and `/lookup` echo `meta.rev` and
  honour `rev` with 409. `/pipeline` and `/capabilities` report live state and
  reject a `rev` parameter with 400.
- **D-83 can_classify.** True only when the caller holds `iga:review` (checked
  through the same permission source `authz.Require` uses), passes the
  verified-human rule, and the workload is active and not provider-native;
  otherwise `false` (never absent). On workload detail only. Facets on
  classification do not bind the cursor to the clock; only filter and sort do.
- **D-84 Statement index.** The API's `index` is 1-based (stored
  `statement_index + 1`), converted in one read helper; ordering uses the stored
  value.
- **D-85 provider_attrs on details.** Never the raw jsonb: an allowlist per kind.
  Workload: status, foundation_model, env_var_names, gateway_targets `[{id, name,
  status, type}]` (the projector writes these from cloud_workload attrs; no
  read-side fallback). Identity: path, tags, permissions_boundary_arn,
  trust_has_deny, trust_has_not_principal. Resource: none (the projected
  `account_connected` surfaces only as `account.connected`).
- **D-86 Credentials and activity.** Credentials: every `iga_credentials` row of
  the user, newest first, with AWS `status` (Active/Inactive) and `lifecycle` as
  separate fields. Activity: `{source, state: collected|not_collected,
  tracking_note, services}`; `services: []` only when collected; an identity
  outside the cap sample or an unreached surface is `not_collected`, never "no
  attempts". The 500-identity sample is taken in a deterministic order (by ARN).
- **D-87 External principal rendering.** `resolution` is null when
  `resolution_basis` is ''; else `{state, basis, rule, resolved_to, resolved_by}`.
  Labels: aws_account → account id; `*` → "any AWS principal"; aws_principal →
  ARN; aws_service → service principal; oidc/saml → issuer + subject; k8s →
  ns/sa. `account` is parsed only for aws_account and aws_principal.
- **D-88 Trust actions.** An Allow yields edges when its Action matches an
  assume action under IAM wildcard rules (`sts:*`, `*`, `sts:Assume*`); a
  NotAction statement yields edges when it does not exclude the relevant action,
  and the edge carries `negated_statement`. The mechanism comes from the
  principal type (AWS/Service/`*` → sts_assume_role, Federated OIDC →
  oidc_federation, Federated SAML → saml_federation); one edge per (statement
  key, principal, role).
- **D-89 Revoked connectors.** Their objects and edges stay visible with their
  stored state; `account.connected` is false; claims from them carry
  `account_not_connected`; `/pipeline` lists the connector as revoked. *Raise:*
  whether revocation should stale its support rows.
- **D-90 Regions failure modes.** `GET …/regions` when `ec2:DescribeRegions`
  fails: 200 with the selected regions, `enabled: null`, and `error: {code, api:
  "ec2:DescribeRegions"}` plus `template_outdated`. `PATCH` then answers `422
  regions_unavailable` (never an unvalidated write); only `regions` is accepted
  (other fields 400); an empty list is `422 invalid_region`; duplicates removed,
  stored sorted.
- **D-91 Scan-run history.** The discovery routes' envelope, not
  revision-bound; keyset on `(requested_at DESC, id)`, `limit` 1–100 default 20,
  cursor signed with `IGA_CURSOR_SECRET`. Coverage summary = counts per state
  plus the non-reached surfaces. `projection` is null when no job exists, else
  `{status, rev, attempts, last_error}`. A failed/abandoned run's end time is
  `updated_at`, documented as "last updated".
- **D-92 /pipeline details.** `barrier.since` is never the lease's `updated_at`:
  the held run's `started_at` while collecting, its `published_at` while
  projecting, null when idle. Accounts: every AWS connector with its status,
  ordered by label then id. `latest_run`: the newest non-terminal run, else the
  latest terminal one. `waiting_on` = the barrier's run whenever another run
  holds it. `latest_run.error` carries `last_error` for failed/abandoned runs.
- **D-93 `unsupported` and resource policies.** `unsupported` comes only from a
  static availability list or an endpoint-resolution failure, never from an API
  error code (AccessDenied, OptInRequired, SubscriptionRequired stay `denied`).
  `resource_policies`: all reads succeed → reached; some fail → partial (count =
  failures); all fail → denied; `NoSuchBucketPolicy` is a successful read.

## Added in the M1 Wave C reviews

- **D-94 Deleting a workspace after a projection (schema defect; migrations
  unchanged).** `036` declares `iga_le_publication_fkey` `ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED` (§3 l.3354-3356). PostgreSQL never defers a
  RESTRICT action — only `NO ACTION` honours `DEFERRABLE` — so when `DELETE
  FROM workspaces` cascades to `iga_publication`, the check fires at once, while
  the `iga_lifecycle_event` rows that cite those revisions (which cascade only
  with their subject node) still exist: every workspace that has published
  refuses deletion with 23503. With the switch off (nothing published) the
  delete goes through. *Proposed DDL* (a corrected `036`, or `037`):

  ```sql
  ALTER TABLE public.iga_lifecycle_event
      DROP CONSTRAINT iga_le_publication_fkey,
      ADD CONSTRAINT iga_le_publication_fkey FOREIGN KEY (workspace_id, rev)
          REFERENCES public.iga_publication (workspace_id, rev)
          ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;
  ```

  It keeps the §3 probe (an event whose revision has no publication is still
  rejected at commit, l.6645) and lets the workspace cascade finish before the
  check. Applied in a rolled-back transaction, the delete then leaves no row of
  the workspace in any `iga_*` table (`TestP2BdbWorkspaceDeletionAfterProjection`).
  Until the DDL lands, that test's "under 036 as shipped" subtest is **skipped**
  naming this entry — a skip, not a pass (§7.4) — and it runs unchanged once
  the key is fixed; any other refusal fails it. The `cloud_*` rows are left
  behind in both phases (`cloud_connector` has no foreign key to `workspaces`;
  Phase 1, not changed). A connector **hard** delete after a projection is also
  refused (23503 on an evidence junction's observation key: observations
  cascade from the connector, edges survive it with `connector_id` set null);
  that is the RESTRICT keys keeping every surviving edge's evidence (T4.9), and
  the product only revokes a connector (D-89), so no DDL is proposed for it: the
  test asserts only that no edge survives without its evidence. *Raise:* the
  §3 DDL for `iga_le_publication_fkey`; and whether a workspace delete should
  also reach its `cloud_*` rows.
- **D-95 B9 and B20 pass WITH named exemptions.** §2.9
  (l.656-661) forbids any single-column foreign key to a workspace-scoped
  table, and B9 (l.6523) / B20 (l.6533) say every composite key rejects a
  foreign row and that single-column references to `cloud_identity` are
  caught. The schema at 036 still holds **19** single-column references to
  workspace-scoped tables that no migration from 027 on converted. None of
  these migrations is ours to change: the ones before 027 are Phase 1's,
  and 027-036 are §3's DDL verbatim. So B9 and B20 are recorded as
  passing ONLY for the keys outside this list, and §2.9 as NOT holding for
  these 19, pending a spec ruling on the proposed DDL.
  `tests/igagraph/p2_bfk_fk_test.go` pins the list exactly
  (`bfkLegacySingleColumn`; a new single-column key, or an exemption whose
  key has gone, fails the guard). For each key it proves what the key
  enforces (a missing parent is refused) and that another workspace's parent
  is ADMITTED. That subtest (`known_gap_foreign_workspace_admitted`) reports
  SKIP, so it cannot read as a pass, and it FAILS once the gap closes. The
  guard's `known_gap_open_section_2_9_exemptions` SKIPs with the whole list,
  grouped. The guard's scope is every key on an `iga_*` or `cloud_*` table
  and every key into one. It does not depend on a key's form, and every
  `cloud_*` table must be classified Phase 1 or Phase 2 (review of bfk:
  scoping by form missed the A3 pattern in a new table).
  - *On the Phase 2 `cloud_*` tables B9/B20 cover (5):*
    `cloud_identity_connector_id_fkey` (011) and
    `cloud_observation_{identity,permission,resource,workload}_id_fkey`
    (re-declared single-column by 024).
  - *On the `iga_*` tables (1):* `iga_observations_delivery_fkey` (004).
  - *On Phase 1's `cloud_*` tables (13):* `cloud_{secret,assume_edge,permission,
    resource,workload,usage,scan_checkpoint}_connector_id_fkey`,
    `cloud_{secret,assume_edge,permission,workload,usage}_identity_id_fkey`,
    `cloud_permission_resource_id_fkey`.
  - *B20's "Catches" class still open (6 of the above):*
    `cloud_observation_identity_id_fkey` and the five Phase 1
    `*_identity_id_fkey`.
  - Also bare (no key at all): `cloud_identity.workspace_id`,
    `cloud_connector.workspace_id` and the seven Phase 1 tables'
    `workspace_id` (`bfkNoForeignKey`).

  *Raise*, proposed DDL. Each keeps the key's current ON DELETE action; a SET
  NULL key nulls only its own column:
  - connector references (the 7 Phase 1 ones and cloud_identity's):
    `FOREIGN KEY (workspace_id, connector_id) REFERENCES cloud_connector
    (workspace_id, id) ON DELETE CASCADE` (027's
    `cloud_connector_workspace_id_key`). This also puts every bare
    `workspace_id` above except `cloud_connector`'s own under a key, which
    then must agree with its connector's workspace;
  - identity references: `FOREIGN KEY (workspace_id, connector_id,
    identity_id) REFERENCES cloud_identity (workspace_id, connector_id, id)`
    (035's `cloud_identity_scope_key`). CASCADE for secret, assume_edge,
    permission and usage; `ON DELETE SET NULL (identity_id)` for workload
    and observation;
  - permission/resource/workload subjects: first `UNIQUE (workspace_id,
    connector_id, id)` on `cloud_permission`, `cloud_resource` and
    `cloud_workload`, then the matching integration-qualified key (`SET NULL
    (<column>)` from `cloud_observation`, CASCADE for
    `cloud_permission.resource_id`);
  - `iga_observations.delivery_id`: needs a ruling first.
    `iga_webhook_deliveries.workspace_id` is nullable (a delivery is stored
    before it is bound), so no composite key can name an unbound delivery;
  - `cloud_connector.workspace_id`: `REFERENCES workspaces (id)`, if the
    connector rows of 001/010 permit it.

## Added by the frozen-contract conformance pass (T6.7, M1 Wave C)

Every §5.3 route was called on one rich estate and compared field by field
with §5.2/§5.3 (`tests/integration/p2_contract_*_test.go`). Where one concept
had two shapes, or §5 was silent, the most conservative reading is below and
the implementation now follows it.

- **D-96 One rendering of a publication's time.** `meta.published_at` (every
  response), `/pipeline`'s `current_published_at` and 409 `revision_stale`'s
  `current_published_at` are the SAME instant and render as the same string:
  RFC 3339 UTC to the second, as every §5.1/§5.2 example writes it
  (`igaread.PublicationTime`). Before, `meta.published_at` carried
  microseconds and the other two did not, so a console comparing the pinned
  revision's time with /pipeline's or a 409's saw two values for one
  publication. Changes keeps its event times (`at`, `meta.history_begins`) to
  the microsecond (D-27a): every event carries its `rev`, so nothing joins on
  the string.
- **D-97 `meta.capabilities` on every detail envelope.** §5.2's detail
  envelope shows `capabilities`, and §2.14.14 says the UI depends on
  `meta.capabilities` on detail responses. Every response in the detail
  envelope -- details, multi-section tabs, `/evidence`, `/lookup`,
  `/pipeline`, `/coverage` and the three graph routes -- carries it: the
  actions the response offers this caller, each stated, and `{}` where the
  route offers none. Only workload detail offers one (`can_classify`, D-83).
  The graph routes' meta is the detail envelope's plus `budgets` and
  `limitations` (D-35). Never absent, so the console reads one meta type and
  never infers an action from a missing field.
- **D-98 One shape per concept.** A code, an object or a claim renders the
  same everywhere it appears:
  (a) *Graph limitations* (D-35 made literal): every node's and edge's
  limitations come from `Query.ClaimLimitations` -- the computation `/evidence`
  renders -- restricted to `FactFreeLimitations`, one call per traversal level
  for all its new nodes and edges. An edge's list is exactly `/evidence`'s for
  that claim (same codes, fields and order); a crossing edge adds the far
  account's coverage (§5.4). A node's list is `/evidence`'s for its presence
  plus the limitations of its restrictions (§5.4 "every path through a
  restricted node carries the matching limitation"): an identity's Deny
  statements (its own and its live groups', read by `loadRestrictions`, the
  reader `/evidence` uses, so `restrictions.deny_statements` is the same count)
  and its OWN boundary, a role's NotPrincipal trust (D-44), a statement's
  Condition and negation -- each built by `/evidence`'s per-code constructor
  (`contract_limitations.go`). Before, the graph built its own maps
  (`account_not_connected` with `account_id` where `/evidence` has
  `accounts`; `deny_statements_present` with `refs` where `/evidence` has
  `statements`; `negated_statement` and `permissions_boundary_present` without
  their fields), and edges lacked codes `/evidence` gave the same claim
  (surface gaps of current claims, a target's Condition). A group's member
  boundaries (D-22) are its grants' limitation, never the group node's.
  (b) *sources*: one entry per support row, `{presence, integration, account,
  state, first_seen_at, last_confirmed_at, ended_reason}`, on workload,
  identity and resource detail alike (workload detail had aggregated per
  connector with `account_id`/`label`).
  (c) *A can_assume's trust statement*: `statement: {key, sid, negated}` on
  Workload > Identities `may_assume`, Used by `principals` and `referenced-by`
  alike (`may_assume` had a bare `statement_key`).
  (d) *retired_reason* is always present on detail routes, null while active
  (§5.2 "Every detail route returns retired objects with lifecycle,
  retired_reason and last_confirmed_at"); list rows keep it only on retired
  rows. Identity, resource and external-principal detail omitted it.
  (e) *Graph nodes*: a statement node always states `sid` (`""` for a Sid-less
  statement, as §5.3's grant line shows), and an external-principal node its
  derived `lifecycle` (D-47, the detail's rule), so every node carries
  `lifecycle`.
- **D-99 Resource > Access pages by holder.** §5.3 "paged by holder": `limit`,
  `next_cursor` and `total` count HOLDERS, never (holder, grant) rows, so a
  holder's rows are never split across pages; `data.access` may hold more rows
  than `total`. `excluded_by` and `deny_statements_naming` are capped lists
  with their `_more` flags, never paged (D-77's list envelope with §5.3's named
  fields as the `data` object).
- **D-100 D-9 wired.** The production chain did not implement D-9: the graph
  catalogue was mounted with the shared `AuthMiddleware` and
  `middlewares.Require`, whose denials are `{"error": "<text>"}`,
  `{"error": "insufficient_scope", ...}` or an empty 401. The catalogue is now
  mounted by `MountIGAGraphReadRoutes` on its own `/api/iga/v1` group, behind
  the same middlewares, each wrapped by `GraphEnvelope`: a 401 or 403 is
  rendered `{"error": {"code": "unauthenticated" | "forbidden", "message",
  "required_permissions"?}}` with the middleware's own description as the
  message and its `WWW-Authenticate` header kept; a denial that is already the
  §5.2 envelope (a handler's own 401 or 403) passes verbatim; the decisions are
  untouched, and the Phase 1 routes keep the shared bodies. `/capabilities`
  now also refuses a `rev` or any other parameter with 400, as D-82 says.
  The whole `/api/iga/v1` surface is mounted by `routes.SetupIGARoutes`, which
  `SetupRoutes` calls and which the contract test mounts itself with the
  production `AuthMiddleware()` (configured from the environment) and
  `middlewares.Require`: `SetupRoutes` cannot be built in a test without the
  whole platform, so the test also checks, from the routes package's source,
  that `SetupRoutes` calls `SetupIGARoutes` and that nothing else mounts the
  graph catalogue. Reverting to the shared-group mount now fails a test.
- **D-101 bound_by beyond §5.4's four budgets (recorded, not introduced, by
  the conformance pass).** Two values the traversal already returns are
  outside §5.4's `nodes | edges | assume_hops | time`: `/graph/path`'s
  `bound_by: "paths"` (the path budget bound: `found` with `more_paths: true`,
  §5.4 "more_paths: true if the path budget bound" names no value for it), and
  `resolution_not_followed` on `/graph` `truncated` and `/graph/path`
  `bound_by`: the walk passed an external principal whose resolution is in
  force (§2.12) and, the principal being terminal (§5.4), did not follow it --
  so the answer must not read as complete (§5.4 "never states a completeness it
  did not establish"). Kept as the conservative reading; the contract test
  pins both as the only additions. *Raise:* §5.4's vocabulary should list them,
  or say how the console renders an unknown `bound_by`. *Superseded in part
  by D-105:* `/graph` no longer puts `resolution_not_followed` in `truncated`
  (it is the additive `data.resolution_not_followed`); `/graph/path`'s
  `bound_by` value stands.
- **D-102 Four shapes §5 leaves open (recorded by the conformance pass).**
  (a) `graph_state` is on every detail envelope's meta, as on the list
  envelope's (§5.2's detail example shows `rev`, `published_at` and
  `capabilities` only): one meta type (D-97), `published` wherever an object
  answers (D-4), and `not_published` on `/coverage` and `/pipeline` before the
  first publication (D-72), where `rev` alone (null) would not say why.
  (b) `meta.coverage`: §2.14.14 lists it among the fields "on every list and
  detail response". It is on every list envelope and every object detail and
  tab (D-73). `/graph`, `/graph/expand`, `/graph/path` and `/evidence` state
  each gap instead as a `surface_*` limitation ON the node, edge or claim it
  bears on (§2.14.11 "unread surfaces appear as a coverage note on the
  affected edge"; D-35, D-98a) -- nothing is left unstated, and nothing is
  summarised that the elements do not carry. `/coverage` is the coverage;
  `/pipeline` and `/lookup` answer no question a gap bears on. *Raise:*
  whether the canvas also wants the union in `meta.coverage` for its banner.
  (c) A frontier entry's `expand` is §5.3's call verbatim
  (`/api/iga/v1/graph/expand?node=<ref>&edge=<kind>&direction=<dir>`, the
  ref's colon unescaped), plus `&include_ended=true` when the request asked
  for ended claims (D-12), so an expansion shows what the canvas shows; `more`
  is `{count: n, exact: true}` or `{count: null, exact: false}`, never a count
  it did not establish (§5.4). The contract test pins all three.
  (d) Identity detail `provider_attrs` (D-85 per kind): all five keys on
  every kind -- §5.3 and D-85 list them for identity detail without
  qualifying by kind, and one shape per concept (D-97, D-98) means a key is
  never absent. `path` and `permissions_boundary_arn` are null when not
  recorded, `tags` `{}`. `trust_has_deny` and `trust_has_not_principal` are a
  bool only on a role whose flag the projector wrote; null on a role whose
  flag it did not write, never `false` (a `false` would claim its trust has
  no Deny), and null on a user or group, which has no trust document -- as a
  group's `permissions_boundary_arn` is null. (Revised in review: the flags
  had been left off users and groups, so the object's keys depended on the
  kind.)
- **D-103 The discovery routes' 401 and 403 keep the shared bodies.** §5.3
  keeps connector and scan operations "on the existing
  `/authsec/discovery/aws/*` routes with `discovery:read` /
  `discovery:admin`", §5.2's 403 row names only `iga:read` / `iga:review`,
  and D-9 scopes the §5.2 denial envelope to the graph routes, leaving the
  shared middlewares' bodies unchanged for "any other product". The
  discovery group's `AuthMiddleware` also guards every Phase 1 discovery
  route (sources, Kubernetes sightings, claim/quarantine), so its 401 and
  the `discovery:*` 403 keep `{"error": "<text>"}` /
  `{"error": "insufficient_scope", ...}` on the Phase 2 discovery routes too.
  The errors the three NEW discovery routes' handlers raise (400, 401 for a
  token naming no workspace, 404, 422) are the §5.2 envelope; the extended
  `GET .../scan-runs/:id` keeps its handler's existing bodies. The discovery
  contract test claims only the handlers' envelope. *Raise:* whether §5.2's
  "Errors, on every route" is meant to cover the discovery routes'
  middleware denials; if so, they need their own group wrapped by
  `GraphEnvelope`, as the graph catalogue has.

## Added in the M1 E-gates review

Numbered on merge after the Wave C entries (D-104, D-105).

- **D-104 policy_documents names its first failing call.** When a
  `policy_documents` surface is `partial` because a document's fetch was
  refused, its `api` and `error_code` (D-71, §5.3 "the call that failed") are
  the FIRST document's refused call and AWS's code for it, in the order the
  scan met the documents — as every other partial surface names its first
  failing call (`withFirstFailure`, `services/cloud_aws_collection_coverage.go`).
  Both are taken from the failed call itself (`awsdiscovery.APICallError` →
  `AttachedPolicy.FetchAPI` / `FetchCode` → `PermissionSnapshot.UnreadableAPI`
  / `UnreadableCode`), never parsed from a reason's prose (D-71). Both stay
  null when no document failed on a call (every unreadable one was read and
  did not parse, D-49, or the listing omitted it). Items stay D-71's `{policy,
  version, error}`: a second document refused by another call is named in its
  own item's `error`. *Why:* E9 ("coverage names the call") and §2.14.13 ("so
  coverage names the failed call and the error code") need the call in a
  structured field, and the surface already has one; the S2 test had pinned
  it null for this one surface, unlike every other partial surface. *Raise:*
  whether §5.3's per-surface `api` should name every distinct failed call.
- **D-105 A resolution the walk does not follow is not
  a budget (§5.4, §2.12).** An external principal's resolution in force (034
  `resolution_state = 'active'`) is shown on its node (D-87) and never walked:
  the principal is terminal (§5.4). On `/graph`, `truncated` names only a
  budget that bound — `nodes | edges | assume_hops | time` (§5.4
  "Continuation" l.6129-6130; the §5.3 Graph example has `truncated: null`
  beside a non-empty frontier) — so an unfollowed resolution never sets it.
  The additive `data.resolution_not_followed` says it instead: `true` when the
  walk passed one (a principal it holds whose resolved node it does not hold;
  forward only, also a node it holds that a principal it does not hold
  resolves to, when that principal has `can_assume` edges under the request's
  lifecycle filter); `false` when it passed none; `null` when that was not
  established (the time budget bound first; a check that itself runs out of
  the request's time sets `truncated: time` when no other budget bound, as
  D-40's levels do). It is set
  whether or not a budget bound, and speaks of the nodes the response holds.
  `/graph/path` is unchanged: `not_found_within_budget` with `bound_by:
  "resolution_not_followed"` (or `more_paths` with it on a found list) when
  the search passed such a resolution linking its two sides, since
  `none_exists` would claim more than was searched and §5.4's outcome table
  has no other value. *Merge note:* graph's D-101 (recorded by the
  frozen-contract pass after this branch was cut) lists
  `resolution_not_followed` on `/graph` `truncated`; this entry supersedes that
  half of D-101 (its `/graph/path` `bound_by` half stands). On merge, graph's
  `tests/integration/p2_contract_schemas_test.go` must follow: `contractTruncated`
  loses `"resolution_not_followed"` from its enum, and `contractGraph` (a
  closed shape) gains `contractReq("resolution_not_followed",
  contractNullable(contractBool))`; `p2_graph_trust_test.go` takes this
  branch's assertions. *Raise:* §5.4's outcome table has no value for "a path
  may run through a resolution that was not followed", and its `bound_by`
  names only budgets; and §2.12 ("no path is drawn through [suspended /
  pending_reconfirmation] as current") implies a path MAY be drawn through an
  active resolution, while §5.4 makes every external principal terminal.
  Either add the value to §5.4's vocabulary or decide that the traversal
  follows resolutions in force.
