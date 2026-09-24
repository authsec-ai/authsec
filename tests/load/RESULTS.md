# T6.10 — §5.6 performance targets on a 10 000-workload fixture

| | |
|---|---|
| **Spec** | `SPEC-iga-phase2-graph.md` §5.6 (targets), §5.1–§5.4 (what is measured); decisions in `.claude/specs/P2-DECISIONS.md` |
| **Measured on** | branch `m1/load` @ `09925f7` (the tree measured; this file was added after) |
| **Date** | 2026-09-24, 18:44–18:55 IST |
| **Result** | **77 reads measured, every §5.6 target met** (`TestP2LoadTargets` PASS); fixture integrity, strategy-agreement and harness tests PASS |

## 1. Reproduce

```bash
# A Phase 2 database at 036 that NOTHING ELSE is using: the integration suite
# empties cloud_observation / cloud_scan_run wholesale, which the fixture's
# evidence junctions and publications forbid (and the fixture would break it).
export IGA_LOAD_DSN='postgres://authsec:pw@localhost:55433/iga_w_load?sslmode=disable'
export IGA_LOAD_KEEP=1                      # optional: keep the fixture for the next run
export IGA_LOAD_REPORT=/tmp/t610-report.md  # optional: the tables below
export IGA_LOAD_SQL_DIR=/tmp/t610-sql       # optional: each read's slowest statements, binds inlined, for EXPLAIN
go test -count=1 -timeout 60m -v ./tests/load/
```

Without `IGA_LOAD_DSN` the database tests skip and only the harness's own
tests run. `IGA_LOAD_ONLY=<regexp>` or `IGA_LOAD_ITERATIONS` below 50 make a
*diagnostic* run: misses still fail it, but a clean diagnostic run ends
**skipped**, never passed. The fixture is built on first use (≈2.5 s to
generate, ≈2.5 min to COPY and ANALYZE) and reused only when the database holds
exactly the same rows (the workspace name carries a digest of every row);
without `IGA_LOAD_KEEP=1` it is wiped when the run ends.

## 2. Environment

| | |
|---|---|
| Machine | Laptop, Intel Core i5-11400H (6 cores / 12 threads, 2.7 GHz), 16 GB RAM, Windows 11 |
| PostgreSQL | 16.15 in Docker Desktop (WSL2 VM: 12 vCPU, 7.65 GB), data on the VM's ext4 volume |
| Server settings | defaults: `shared_buffers` 128 MB, `work_mem` 4 MB, `effective_cache_size` 4 GB, `random_page_cost` 4, `jit` on (`jit_above_cost` 100 000), `plan_cache_mode` auto — the reads set the last two per transaction (§4) |
| Client | Go 1.25.0, the service's own gorm/pgx stack, same machine |
| Database | `iga_w_load`, migrations 001–036 (the `iga_tpl` template), 440 MB with the fixture |
| Load | **Shared.** Other agents' integration suites ran against the same PostgreSQL server and the same CPUs during every run of this session (host CPU 30–60% busy at idle-looking moments; PostgreSQL container 27–34%). Nothing was stopped for the measurement. |

## 3. The fixture

Generated in memory (seeded, deterministic) and written **directly** with
COPY, one transaction per workspace, in foreign-key order, every constraint
live (`tests/load/p2_load_copy_test.go`). Projection throughput is not a §5.6
target, so nothing runs the projector; instead the generator makes the
projector's decisions with the projector's own exported helpers — source,
partition, statement, grant and trust keys (`igagraph.*Key`,
`Snapshot.PartitionFor`), statement parsing and content hashes
(`awsdiscovery.ParsePolicyDocument`), trust principals
(`awsdiscovery.ParseTrustDocument`) — and every time it writes is a
publication's `published_at` (D-26), so every Changes event is attributed to
its revision and run. `TestP2LoadFixtureIntegrity` proves the real routes read
it back as generated (totals, the hub role's Used-by, Changes attribution,
evidence facts, declared paths found, duplicate names) before any timing is
trusted.

**Measured workspace** (a second, 2 000-workload workspace shares every table,
so no plan wins by one tenant being alone):

| Object | Count | Shape |
|---|---:|---|
| Accounts | 3 | connected; 50% / 30% / 20% of every per-account count; two regions each |
| Workloads | 10 000 | 9 823 active; Lambda 5 788, ECS 1 992, EC2 1 553, Bedrock agents 392, AgentCore runtimes 180, gateways 95; 40 names repeated across accounts |
| Identities | 3 550 | 3 000 roles, 500 users, 50 groups |
| Policies | 2 000 | 1 450 customer-managed, 150 AWS-managed (one object across accounts), 400 inline |
| Statements | 11 202 | 5.6 per policy; 9 780 Allow, 1 422 Deny, 3 958 Sid-less, 208 retired |
| Statement revisions | 7 722 | Sid-keyed edits across four cycles |
| Resource references | 10 000 | 2 474 selectors; `*` named by 2 827 targets, the most-named exact reference by 599, 8 774 references named once (Zipf) |
| Targets | 21 509 | 21 300 positive, 209 NotResource |
| Assignments | 8 813 | attached 8 215, inline 400, boundary 198; 372 ended |
| Grants | 49 776 | 5.8 per non-boundary assignment; 47 064 current, 2 712 ended |
| Relationships | 16 982 | executes_as 10 336 (234 stale), task_execution_role 1 995, member_of 909, can_assume 3 742 — 140 mutual pairs (cycles), 61 external principals |
| History | 4 cycles × 3 accounts = 12 publications | lifecycle events 37 276 (first_seen 36 752, retired 480, restored 44); workloads that change role, arrive late, retire and come back; partial coverage in the last cycle (one denied, one partial surface) |
| Evidence | 31 816 observations | 143 452 junction links, 38 492 support rows, 317 classification decisions |

Hub objects are measured on their own, because a p95 over typical objects
says nothing about the one object every workload shares: the execution role
547 workloads run as, `ecsTaskExecutionRole` (1 016 task definitions), the
largest group, the `*` selector, the most-named exact reference (the reads
labelled "most-named bucket": the fixture's most-named exact reference is a
KMS key in an unconnected account, 599 targets), the most-granted holder,
`lambda.amazonaws.com`.

## 4. Methodology

- **Through the real routes**: `platform.RegisterIGAGraphReadRoutes` on a gin
  engine over the fixture database (the permission check is a pass-through; it
  calls an external service and is not what §5.6 measures). The time is the
  whole request as the server sees it — routing, handler, every statement of
  the §5.1 snapshot and its 3 s budget, JSON rendering (httptest, no network).
- **Sequential**: one request at a time, one process.
- **Warm**: each read first makes every distinct request of its measured pass
  once, unrecorded.
- **Iterations**: 50 measured per read, rotating over typical objects (50
  workloads, 50 roles, 30 users, 50 resources, 30 external principals), or
  pinned to one hub object.
- **Interleaved round-robin**: iteration *i* of every read runs before
  iteration *i+1* of any. On this shared machine a burst of outside load
  lasting a few seconds would otherwise fall on one read's consecutive
  iterations and decide its p95 alone.
- **p50 / p95 / max** by nearest rank. Then a short traced pass (10 requests,
  not timed) records the statement count, the slowest statement and the time
  spent in optional COUNT work (totals and facets).
- **Only honest answers count**: every measured response must be 200 with the
  graph published, and none may carry a timed-out optional piece (a
  `total_known: false` without `total_at_least`, a `null` facet, a
  `{value: null, exact: false}` count, a traversal `bound_by: time`). Any such
  response fails the read whatever its time.
- **Judged per §5.6 row**: Lists 400 ms; Totals and facets 3 s ("within the
  3 s timeout, counted in the page budget": a facets-on page is judged on BOTH
  its Lists row and this one, its totals and facets counted inside its time);
  Detail tabs 300 ms; Graph 1.5 s at the display defaults (assume_hops 2, 150
  nodes, 300 edges — `/graph`, `/graph/expand`, `/graph/path`); Evidence
  300 ms; Changes 500 ms. A miss fails `TestP2LoadTargets`.

## 5. Results (this run)

### Lists (p95 target 400ms)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /workloads first page | 59.4 | 96.3 | 257.1 | 18 | 29.1 | 29.1 | met |
| GET /workloads deep page (page 50, cursor) | 55.0 | 72.5 | 128.0 | 18 | 29.5 | 29.5 | met |
| GET /workloads q=<team> search | 56.0 | 73.9 | 87.4 | 18 | 16.9 | 23.4 | met |
| GET /workloads account=<account> | 41.4 | 55.5 | 56.4 | 11 | 18.3 | 18.3 | met |
| GET /workloads facets=account,runtime_kind,classification,region | 186.8 | 228.0 | 293.4 | 38 | 152.5 | 37.2 | met |
| GET /workloads q + account + facets | 135.7 | 185.0 | 252.7 | 31 | 88.7 | 21.2 | met |
| GET /identities first page | 55.4 | 72.4 | 79.9 | 16 | 10.8 | 31.3 | met |
| GET /identities deep page (page 30, cursor) | 35.8 | 47.5 | 67.7 | 16 | 9.9 | 14.0 | met |
| GET /identities q=<team> search | 33.4 | 45.7 | 84.7 | 16 | 11.0 | 7.6 | met |
| GET /identities account=<account> | 40.5 | 72.1 | 168.8 | 16 | 11.1 | 19.4 | met |
| GET /identities facets=account,kind | 76.0 | 102.4 | 128.8 | 26 | 25.4 | 33.0 | met |
| GET /identities q + account + facets | 47.2 | 71.2 | 84.3 | 26 | 23.6 | 7.9 | met |
| GET /resources first page | 155.8 | 201.8 | 272.4 | 16 | 41.3 | 132.3 | met |
| GET /resources deep page (page 50, cursor) | 135.6 | 183.4 | 191.1 | 16 | 35.4 | 90.2 | met |
| GET /resources q=<team> search | 60.8 | 92.1 | 126.4 | 16 | 34.5 | 29.0 | met |
| GET /resources account=<account> | 74.8 | 113.8 | 155.4 | 16 | 36.8 | 69.0 | met |
| GET /resources facets=kind,service,account | 264.4 | 335.4 | 378.2 | 31 | 143.3 | 113.7 | met |
| GET /resources q + account + facets | 94.5 | 130.1 | 147.4 | 31 | 56.1 | 18.3 | met |
| GET /workloads classification=agent sort=classification | 42.7 | 64.5 | 73.3 | 12 | 8.8 | 46.3 | met |
| GET /identities used_by=workloads | 74.2 | 104.0 | 129.9 | 16 | 30.3 | 36.6 | met |

### Totals and facets (p95 target 3s)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /workloads facets=account,runtime_kind,classification,region | 186.8 | 228.0 | 293.4 | 38 | 152.5 | 37.2 | met |
| GET /workloads q + account + facets | 135.7 | 185.0 | 252.7 | 31 | 88.7 | 21.2 | met |
| GET /identities facets=account,kind | 76.0 | 102.4 | 128.8 | 26 | 25.4 | 33.0 | met |
| GET /identities q + account + facets | 47.2 | 71.2 | 84.3 | 26 | 23.6 | 7.9 | met |
| GET /resources facets=kind,service,account | 264.4 | 335.4 | 378.2 | 31 | 143.3 | 113.7 | met |
| GET /resources q + account + facets | 94.5 | 130.1 | 147.4 | 31 | 56.1 | 18.3 | met |

### Detail tabs (p95 target 300ms)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /workloads/:id | 15.4 | 25.7 | 34.7 | 10 | 0.0 | 4.6 | met |
| GET /workloads/:id/identities | 48.6 | 68.6 | 76.6 | 40 | 10.9 | 3.2 | met |
| GET /workloads/:id/resources | 39.3 | 52.9 | 81.8 | 20 | 4.9 | 7.7 | met |
| GET /workloads/:id/classification | 11.5 | 15.3 | 22.4 | 10 | 1.1 | 1.9 | met |
| GET /workloads/:id/resources (most-granted role) | 38.1 | 48.5 | 55.4 | 20 | 4.9 | 7.3 | met |
| GET /workloads/:id (most-granted role) | 15.0 | 18.6 | 22.2 | 10 | 0.0 | 2.5 | met |
| GET /identities/:id (roles) | 16.2 | 21.8 | 29.3 | 12 | 2.7 | 3.4 | met |
| GET /identities/:id/used-by (roles) | 26.0 | 35.5 | 75.9 | 19 | 12.4 | 14.6 | met |
| GET /identities/:id/permissions (roles) | 39.0 | 49.1 | 68.3 | 19 | 6.6 | 11.3 | met |
| GET /identities/:id (users) | 17.1 | 21.4 | 24.9 | 13 | 2.2 | 2.7 | met |
| GET /identities/:id/permissions (users) | 46.8 | 62.0 | 80.9 | 20 | 6.4 | 23.8 | met |
| GET /identities/:id (hub role, 547 workloads) | 17.0 | 21.0 | 26.5 | 12 | 2.8 | 2.8 | met |
| GET /identities/:id/used-by (hub role, 547 workloads) | 57.4 | 73.7 | 106.5 | 26 | 11.0 | 12.1 | met |
| GET /identities/:id/used-by (ecsTaskExecutionRole, 1016) | 50.9 | 63.7 | 82.2 | 19 | 15.3 | 19.8 | met |
| GET /identities/:id/used-by (largest group) | 18.5 | 21.9 | 28.3 | 12 | 2.3 | 4.0 | met |
| GET /identities/:id/permissions (most grants) | 38.3 | 49.1 | 64.9 | 19 | 5.4 | 9.2 | met |
| GET /external-principals/:id | 11.3 | 18.4 | 60.1 | 7 | 0.0 | 3.8 | met |
| GET /external-principals/:id/referenced-by | 17.0 | 25.1 | 41.6 | 12 | 2.2 | 4.0 | met |
| GET /external-principals/:id (lambda.amazonaws.com) | 15.2 | 21.4 | 25.9 | 7 | 0.0 | 4.9 | met |
| GET /external-principals/:id/referenced-by (lambda.amazonaws.com) | 34.3 | 47.5 | 48.3 | 12 | 4.9 | 14.4 | met |
| GET /resources/:id | 38.3 | 48.3 | 58.3 | 14 | 2.2 | 22.0 | met |
| GET /resources/:id/access | 27.6 | 37.3 | 43.6 | 16 | 4.4 | 4.9 | met |
| GET /resources/:id ("*") | 48.1 | 57.9 | 66.2 | 14 | 15.7 | 18.8 | met |
| GET /resources/:id/access ("*") | 224.5 | 286.8 | 311.7 | 18 | 110.3 | 108.7 | met |
| GET /resources/:id (most-named bucket) | 42.6 | 57.3 | 70.9 | 14 | 5.1 | 19.2 | met |
| GET /resources/:id/access (most-named bucket) | 128.5 | 158.4 | 191.7 | 18 | 38.8 | 56.2 | met |
| GET /identities/:id/used-by section=workloads page 2 (ecsTaskExecutionRole, 1016) | 38.9 | 50.0 | 57.8 | 12 | 9.8 | 16.6 | met |
| GET /resources/:id/access page 2 ("*") | 219.7 | 248.1 | 289.3 | 18 | 69.7 | 88.7 | met |

### Graph (p95 target 1.5s)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /graph workload forward | 72.7 | 103.1 | 108.9 | 39 | 7.3 | 13.5 | met |
| GET /graph workload forward (most-granted role) | 75.0 | 94.0 | 112.5 | 39 | 4.4 | 7.6 | met |
| GET /graph identity forward (roles) | 59.0 | 169.4 | 464.2 | 32 | 9.4 | 11.6 | met |
| GET /graph identity reverse (hub role) | 113.1 | 143.3 | 165.5 | 37 | 12.0 | 53.9 | met |
| GET /graph resource reverse | 121.5 | 175.8 | 189.6 | 35 | 17.1 | 12.9 | met |
| GET /graph resource reverse (most-named bucket) | 210.2 | 267.3 | 269.0 | 31 | 99.7 | 72.5 | met |
| GET /graph external principal forward (lambda.amazonaws.com) | 193.0 | 244.8 | 373.0 | 22 | 133.5 | 84.4 | met |
| GET /graph/expand executes_as reverse (hub role, 547 workloads) | 20.4 | 28.5 | 33.6 | 13 | 3.8 | 4.1 | met |
| GET /graph/expand target reverse ("*") | 74.4 | 99.0 | 122.6 | 17 | 9.8 | 59.9 | met |
| GET /graph/path workload -> a resource its role reaches | 143.2 | 529.7 | 621.3 | 65 | 56.6 | 14.5 | met |
| GET /graph/path workload -> "*" (most-granted role) | 150.6 | 214.4 | 269.7 | 31 | 4.3 | 72.0 | met |

### Evidence (p95 target 300ms)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /evidence grant | 45.3 | 57.0 | 75.0 | 14 | 0.0 | 20.5 | met |
| GET /evidence assignment | 13.8 | 19.4 | 21.9 | 8 | 0.0 | 5.0 | met |
| GET /evidence relationship (executes_as) | 14.2 | 21.8 | 23.0 | 8 | 0.0 | 4.8 | met |
| GET /evidence relationship (cross-account can_assume) | 14.2 | 18.1 | 23.3 | 8 | 0.0 | 3.6 | met |
| GET /evidence workload presence | 22.7 | 35.7 | 57.9 | 9 | 0.0 | 14.3 | met |
| GET /evidence coverage | 12.1 | 16.2 | 19.6 | 5 | 0.0 | 3.3 | met |
| GET /evidence grouped edge (39 grants) | 58.4 | 69.8 | 86.7 | 15 | 0.0 | 29.2 | met |
| GET /evidence 50 claims (the D-79 maximum, many holders) | 72.5 | 90.9 | 128.4 | 14 | 0.0 | 24.6 | met |

### Changes (p95 target 500ms)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /workloads/:id/changes | 91.4 | 146.3 | 170.8 | 24 | 47.6 | 43.2 | met |
| GET /workloads/:id/changes (role switched) | 94.6 | 147.1 | 194.8 | 29 | 36.7 | 33.8 | met |
| GET /workloads/:id/changes (most-granted role) | 82.0 | 95.8 | 113.0 | 24 | 26.0 | 25.6 | met |
| GET /workloads/:id/changes kind=coverage | 19.4 | 24.2 | 29.0 | 14 | 3.3 | 3.3 | met |
| GET /identities/:id/changes (roles) | 81.9 | 122.8 | 125.9 | 22 | 30.3 | 59.2 | met |
| GET /identities/:id/changes (most grants) | 62.8 | 76.5 | 104.7 | 17 | 26.0 | 24.0 | met |
| GET /identities/:id/changes page 2 (most grants) | 76.9 | 104.0 | 126.5 | 23 | 26.3 | 34.5 | met |
| GET /resources/:id/changes | 125.6 | 160.0 | 210.9 | 21 | 55.2 | 59.2 | met |
| GET /resources/:id/changes ("*") | 304.5 | 370.8 | 490.0 | 28 | 120.7 | 182.5 | met |
| GET /resources/:id/changes (most-named bucket) | 240.6 | 297.7 | 511.0 | 28 | 89.6 | 90.0 | met |

Closest to their targets: `GET /resources/:id/access ("*")` p95 286.8 of
300 ms, `GET /resources facets=kind,service,account` 335.4 of 400 ms,
`GET /resources/:id/changes ("*")` 370.8 of 500 ms. On this shared machine a
run under heavier outside load can move those p95s by 30–100 ms (§7).

## 6. Defects found and fixed

A target missed is a defect (§5.6). Each fix below keeps the answer
byte-for-byte (the existing suites and the tests named pass) and is held to
its speed by this load test (§8).

| Read | Cause (EXPLAIN ANALYZE) | Fix | Before → after |
|---|---|---|---|
| Every read of a hub object, first seen on `/resources/:id/changes ("*")` | pgx prepares and caches statements per connection; after five executions PostgreSQL may switch to a GENERIC plan, costed for a typical object and ruinous for `*` | `Reader.Read` sets `plan_cache_mode = force_custom_plan` for its transaction (`internal/igaread/snapshot.go`) | generic plans: `504 query_timeout` on `/resources/:id/changes` within the first measured read (mutation LM1); custom: 304.5 / 370.8 ms p50 / p95 |
| Any statement costed above `jit_above_cost` (100 000) | JIT compilation before the first row: a holder count over `*` ran 875 ms with JIT, 106 ms without; the resource list's page is already costed at 75 073 on this fixture, so a somewhat larger estate would pay it on every page | the same statement also sets `jit = off` for the transaction (both via `set_config(..., true)`, one round trip) | latent here (no measured statement crosses the threshold); guarded by `TestP2LoadReadPlansWithBindValuesOnlyInsideTheRead` |
| `GET /resources/:id/access ("*")` (and its page 2) | grant-first: all 20 049 grants on the 2 553 statements naming `*`, their 26 145 access rows materialised (spilling to disk at `work_mem` 4 MB), to keep a page of 101 of 3 279 holders | identity-first page for references named by ≥ 1 000 positive targets (`rdetailAccessDensePageSQL`): walk the identities in page order, one `LIMIT 1` probe each, stop at the page. Same rows, same order (tested on the lab and the fixture) | page statement 150 → 38 ms (psql); read 355.7 / 908.2 → 224.5 / 286.8 ms; page 2 277.4 / 354.4 → 219.7 / 248.1 ms (the "before" run was under heavier outside load). Mutation LM2 (strategy off): misses again |
| `GET /resources/:id/access` (all) | the access CTEs carried every statement's document through all rows | CTEs carry ids only; the page joins statement and policy columns for its own rows (earlier Wave C commit) | disk spill removed |
| `GET /resources/:id/changes` (hub references) | per-revision predecessor lookup with no index (`iga_statement_revision` is indexed only on its live row): 2.5 s for the 1 913 revisions under `*`, a 504; correlated `EXISTS` over the event table per retired statement; every branch re-reading the naming set; full sort of 22 000 grant events for a page of 50; a total over one DISTINCT | one window for predecessors; `(policy, run)` pairs computed once; shared MATERIALIZED CTEs; each branch cut to its first limit+1 rows after the cursor before merging (repeatable branches deduplicated first); the total streams unique branches into its LIMIT (earlier Wave C commits; their comments record the revision predecessors at 2.5 s and a 504 before, the `*` total at 415 → 90 ms) | now 304.5 / 370.8 ms (`*`), 240.6 / 297.7 ms (most-named) |
| `GET /evidence` grouped edges | one `cloud_observation` scan per distinct target text (≈ 20 ms each, as recorded in the earlier commit; `subject_native_id` has no index) | `ResourcePoliciesOf`: one statement for every text, decided per text | 50-claim request 90.9 ms p95 |
| `GET /workloads?q=...` with facets | the provider-id arm (two regular expressions per row) evaluated in six statements over the whole estate | a cheap suffix test on the ARN first; the full equality still decides (`listsExact.suffixOf`) | q + account + facets 185.0 ms p95 |

## 7. What only an index would fix, and what the numbers depend on

**Spec question (proposed DDL, not applied to any migration).** Three reads of
a resource's Changes — the grant, revision and replacement branches — have no
index on the column they select by, so every page and every total of every
resource scans `iga_access_edges` (the one entitlement index,
`idx_iga_access_edges_entitlement`, is partial on `state <> 'ended'`, and
Changes must see ended grants), `iga_statement_revision` and
`iga_lifecycle_event`. §5.6 names "lifecycle and validity columns" for Changes;
036 has none by entitlement. Proposed:

```sql
CREATE INDEX idx_iga_access_edges_entitlement_all ON public.iga_access_edges (workspace_id, entitlement_id);
CREATE INDEX idx_iga_le_entitlement ON public.iga_lifecycle_event (workspace_id, entitlement_id) WHERE entitlement_id IS NOT NULL;
CREATE INDEX idx_iga_statement_revision_entitlement ON public.iga_statement_revision (workspace_id, entitlement_id, valid_from, id);
```

Measured in `iga_w_load` (created, ANALYZEd, measured, dropped), psql,
`EXPLAIN (ANALYZE, TIMING OFF)`, median of 9, `jit = off`:

| Statement | Before | After |
|---|---:|---:|
| typical resource's Changes page | 46.2 ms | 3.1 ms |
| typical resource's Changes total | 52.5 ms | 2.2 ms |
| most-named resource's page / total | 207.2 (min 92.1) / 93.1 ms | 97.3 / 93.8 ms |
| `*` page / total | 179.9 / 95.2 ms | 179.9 / 97.2 ms |

Typical references improve fifteen-fold; the hub references are bound by their
volume (22 000 grant events under `*`), and at `random_page_cost` 4 the planner
keeps the sequential scan even with the index. The targets are met without the
indexes; they buy headroom on the reads a user opens most.

**Other conditions of these numbers.**

- The machine is shared (§2). The first run of this session, before the
  identity-first Access page and the interleaving, measured
  `/resources/:id/access ("*")` at p95 908 ms with a p50 of 356 ms, and a
  heavily loaded diagnostic run put the most-named reference's Access at p95
  417 ms with its slowest statement at 42 ms: outside load, not the query.
  Interleaving spreads such bursts; it cannot remove them.
- PostgreSQL runs with its defaults (128 MB shared buffers for a 440 MB
  database). A production-sized `shared_buffers` and an SSD
  `random_page_cost` would change several plans (the proposed indexes would be
  chosen more often).
- The warm pass makes each read's pages resident; §5.6 states steady-state
  targets. Cold first requests were not measured.
- `IGA_CURSOR_SECRET`, authorization and the network are outside the timing.

## 8. Safeguards and their mutation checks

Every safeguard was removed or inverted, the test that must catch it run and
seen to FAIL, and the file restored from an on-disk copy and verified with
sha256.

| Id | Safeguard removed | Test | Caught |
|---|---|---|---|
| S1 | `Reader.Read` applies no snapshot settings | `TestP2LoadReadPlansWithBindValuesOnlyInsideTheRead` | yes |
| S2 | `jit = off` dropped | same | yes |
| S3 | settings session-wide (`set_config(..., false)`) | same | yes |
| LM1 | `plan_cache_mode` no longer forced | `TestP2LoadTargets` (Changes reads) | yes: `504 query_timeout` |
| LM2 | identity-first Access page never chosen | `TestP2LoadTargets` (Access reads) | yes: Detail tabs misses on the `*` reads (page 2 at p95 303.3 ms), under heavy outside load that also pushed the most-named reference's Access, grant-first either way, to 417 ms |
| D1–D6 | identity-first page: direct probe, member probe, member-row overlap, member-probe overlap, cursor `>` → `>=`, ended memberships counted by default | `TestP2LoadAccessStrategiesAgreeOnTheLab` | yes, each |
| L1, L2 | q provider-id: suffix test `right` → `left`; full equality dropped | `TestP2LoadWorkloadQMatchesTheWholeProviderID` | yes, each |
| R1 | batched resource policies not split by subject | `TestP2LoadGroupedEvidenceReadsEachTargetsOwnResourcePolicy` | yes |
| C1–C3 | Changes: workload revisions, holders' and resource's replacements counted as unique | `TestP2LoadChangesTotalCountsEachEventOnce` | yes, each |
| C4 | Changes: repeatable arms not deduplicated before the per-branch cut | `TestP2LoadChangesTotalCountsEachEventOnce` | **no** — the test could not reach it; strengthened with `TestP2LoadChangesPagesKeepEveryRepeatedEvent` (two policies replaced in one pass, three Sid-less statements each): caught, the limit-2 pages skipped an event |
| C5, C6 | Changes: per-branch cursor `<` → `<=`; total without DISTINCT over repeatable branches | `TestP2LoadChangesTotalCountsEachEventOnce` | yes, each |
| C7–C9 | Changes: edited revisions include a first revision (holders; resource); before/after loader takes the wrong predecessor | `TestP2Changes*` + the above | yes, each |
| H1–H7, H2b, I1 | harness: a timed-out total / time-bound traversal / null facet not flagged; a non-200 not a failure; a p95 over target not a miss; nearest rank off by one; facets not counted as COUNT work; reads measured one after another instead of round-robin | `TestP2LoadHonest`, `…MeasureFailsWhatIsNotAnAnswer`, `…VerdictJudgesEveryRow`, `…Rank`, `…IsCount`, `…Interleaves` | yes, each |
