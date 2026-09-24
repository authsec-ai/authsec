# T6.10 — §5.6 performance targets on a 10 000-workload fixture

| | |
|---|---|
| **Spec** | `SPEC-iga-phase2-graph.md` §5.6 (targets), §5.1–§5.4 (what is measured), §7.4 (how a result is recorded); decisions in `.claude/specs/P2-DECISIONS.md` |
| **Measured on** | branch `m1/load` @ `3a80c785c43f5daed85b782e0613f5e557189f5c`, committed, clean tree (`git status --porcelain` empty). This file and the P2-DECISIONS entry were committed after the run, in a commit that changes no Go file (`git diff --stat 3a80c78..` lists only `tests/load/RESULTS.md` and `.claude/specs/P2-DECISIONS.md`) |
| **Date** | 2026-09-24, 22:44–22:52 IST (run 2; run 1, 22:23–22:33 at `555a821`, is in §5.1) |
| **Database** | `iga_w_loadfx` — the load test's own, created from the 036 template `iga_tpl`; never the integration suite's database (§1) |
| **Result** | `go test ./tests/load/`: **12 tests (40 with subtests) — 40 passed, 0 skipped, 0 failed** (`ok  github.com/authsec-ai/authsec/tests/load 458.720s`). **77 reads measured, every §5.6 target met** (`TestP2LoadTargets` PASS, 50 iterations each, no diagnostic narrowing) |

## 1. Reproduce

The exact commands of the recorded run (§7.4: environment variables included):

```bash
# A database of the load test's OWN, made from the 036 template. Never the
# integration package's IGA_TEST_DSN or tests/igagraph's TEST_DATABASE_URL:
# every p2 lab empties cloud_observation / cloud_scan_run wholesale, which the
# fixture's evidence junctions and publications reference, so a fixture left
# in either database breaks that suite's whole TestP2 gate (and the suite
# would break the fixture). loadEnvFor refuses an IGA_LOAD_DSN naming the same
# database as either, however spelled, before anything is written
# (loadDSNRefusal; TestP2LoadRefusesASharedDatabase, TestP2LoadRefusalStopsTheFixture).
docker exec p2pg psql -U authsec -d postgres \
  -c 'DROP DATABASE IF EXISTS iga_w_loadfx WITH (FORCE)' -c 'CREATE DATABASE iga_w_loadfx TEMPLATE iga_tpl'

cd m1-wt/load    # at 3a80c785c43f5daed85b782e0613f5e557189f5c
export IGA_LOAD_DSN='postgres://authsec:pw@localhost:55433/iga_w_loadfx?sslmode=disable'
export IGA_TEST_DSN='postgres://authsec:pw@localhost:55433/iga_w_load?sslmode=disable'      # the other suites' databases, as the
export TEST_DATABASE_URL='postgres://authsec:pw@localhost:55433/igt_w_load?sslmode=disable' # gate sets them: the guard checks both
export GOFLAGS=-p=2
export IGA_LOAD_KEEP=1                           # keep the fixture: only ever in the dedicated database
export IGA_LOAD_REPORT="$SCRATCH/report.md"      # the tables in §5
export IGA_LOAD_SQL_DIR="$SCRATCH/sql"           # each read's slowest statements, binds inlined (§7 measured these)
go test -count=1 -timeout 60m -v ./tests/load/
```

`IGA_LOAD_KEEP=1` was set so the index measurement of §7 could run on the same
rows afterwards; `iga_w_loadfx` was then recreated from `iga_tpl` (empty). Run 2
reused the fixture run 1 had built in it at 22:23 from the same generator
(`fixture: 492743 rows ... written in 0s (0 = reused)`: the workspace name
carries a digest of every generated row, so reuse means identical rows).
Without `IGA_LOAD_KEEP=1` the fixture is wiped when the run ends. Never set it
for a database any other suite uses.

Without `IGA_LOAD_DSN` the database tests skip and only the harness's own tests
run. `IGA_LOAD_ONLY=<regexp>` or `IGA_LOAD_ITERATIONS` below 50 make a
*diagnostic* run: misses still fail it, but a clean diagnostic run ends
**skipped**, never passed. The fixture is built on first use (≈2.5 s to
generate, ≈1.5–2.5 min to COPY and ANALYZE).

## 2. Environment

| | |
|---|---|
| Machine | Laptop, Intel Core i5-11400H (6 cores / 12 threads, 2.7 GHz), 16 GB RAM, Windows 11 |
| PostgreSQL | 16.15 in Docker Desktop (WSL2 VM: 12 vCPU, 7.65 GB), data on the VM's ext4 volume |
| Server settings | defaults: `shared_buffers` 128 MB, `work_mem` 4 MB, `effective_cache_size` 4 GB, `random_page_cost` 4, `jit` on (`jit_above_cost` 100 000), `plan_cache_mode` auto — the reads set the last two per transaction (§6) |
| Client | Go 1.25.0, the service's own gorm/pgx stack, same machine |
| Database | `iga_w_loadfx` (dedicated; migrations 001–036 from the `iga_tpl` template), 309 MB with the fixture |
| Load | **Shared machine.** Before run 2: host CPU 6–20%, no other test binary running, no other database session active on the server; another agent's `go` process appeared as it started. Nothing was sampled during run 2. Run 1 ran while other agents' suites were active on the host, with a 30 s `docker stats` / `pg_stat_activity` sampler of mine running beside it (§5.1). |

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
it back as generated (totals, the hub role's Used-by and its executes_as
expand, Changes attribution, evidence facts, declared paths found, duplicate
names) before any timing is trusted.

**Measured workspace** (a second, 2 000-workload workspace shares every table,
so no plan wins by one tenant being alone; 492 743 rows in all):

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
the most workloads run as (**403**, through executes_as — the reads labelled
"hub role"), account A's `ecsTaskExecutionRole` (1 016 task definitions,
through task_execution_role), the largest group, the `*` selector, the
most-named exact reference (the reads labelled "most-named bucket": the
fixture's most-named exact reference is a KMS key in an unconnected account,
599 targets), the most-granted holder, `lambda.amazonaws.com`.

Until `3a80c78` the "hub role" was account B's `ecsTaskExecutionRole` (547
task definitions): the selection left out only account A's. Its workloads
reach it through task_execution_role alone, so
`/graph/expand executes_as reverse (hub role)` measured an EMPTY page — fast
for the wrong reason. The Graph response sizes (§5) showed it (0 nodes, 0
edges); the selection now leaves out every `ecsTaskExecutionRole`, and
`TestP2LoadFixtureIntegrity` requires the hub's executes_as expand to be a
full page of 100 with a cursor (§8, H8). The earlier measurement of that read
(20.4 / 28.5 ms) measured nothing and is withdrawn.

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
  iteration *i+1* of any. On a shared machine a burst of outside load lasting
  a few seconds would otherwise fall on one read's consecutive iterations and
  decide its p95 alone.
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
  Detail tabs 300 ms; Graph 1.5 s; Evidence 300 ms; Changes 500 ms. A miss
  fails `TestP2LoadTargets`.
- **Graph "for the display defaults" — what ran.** The Graph reads
  (`/graph`, `/graph/expand`, `/graph/path`) are requested as the console
  requests a first drawing: no `assume_hops`, so the server's default of **2**
  (§5.4, D-34). Every request then ran under the server's **hard budgets —
  500 nodes, 2 000 edges** (`meta.budgets` of every response), not under the
  console's display maxima of 150 nodes and 300 edges: those are drawing
  limits (§5.4 *Budgets*: "150 drawn, then a truncation chip"), and the
  server takes no parameter for them, so the harness cannot make the routes
  apply them. The harness records instead how large every Graph response was
  (`loadGraphShape`, the table under §5 Graph): a read whose responses stayed
  within 150 / 300 was measured exactly at the display defaults; for one whose
  responses were larger, the time is an **upper bound** on a display-default
  drawing (the server did more work than the drawing needs).

## 5. Results (run 2, at `3a80c78`)

### Lists (p95 target 400ms)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /workloads first page | 34.3 | 36.0 | 41.6 | 18 | 15.3 | 15.3 | met |
| GET /workloads deep page (page 50, cursor) | 33.6 | 36.1 | 37.6 | 18 | 12.5 | 12.5 | met |
| GET /workloads q=<team> search | 47.9 | 57.2 | 57.9 | 18 | 16.3 | 18.6 | met |
| GET /workloads account=<account> | 32.0 | 34.5 | 39.9 | 11 | 11.5 | 11.5 | met |
| GET /workloads facets=account,runtime_kind,classification,region | 102.8 | 109.5 | 110.9 | 38 | 71.9 | 17.0 | met |
| GET /workloads q + account + facets | 118.4 | 125.1 | 127.7 | 31 | 78.4 | 19.9 | met |
| GET /identities first page | 47.2 | 51.3 | 55.7 | 16 | 9.2 | 29.7 | met |
| GET /identities deep page (page 30, cursor) | 29.0 | 31.7 | 35.8 | 16 | 8.7 | 12.7 | met |
| GET /identities q=<team> search | 26.2 | 28.9 | 30.5 | 16 | 8.4 | 6.5 | met |
| GET /identities account=<account> | 31.3 | 39.4 | 73.2 | 16 | 8.2 | 17.0 | met |
| GET /identities facets=account,kind | 63.0 | 70.0 | 74.3 | 26 | 20.5 | 27.1 | met |
| GET /identities q + account + facets | 37.2 | 40.5 | 52.8 | 26 | 16.0 | 6.7 | met |
| GET /resources first page | 124.8 | 132.4 | 148.3 | 16 | 16.2 | 97.6 | met |
| GET /resources deep page (page 50, cursor) | 89.9 | 96.3 | 111.2 | 16 | 16.9 | 65.9 | met |
| GET /resources q=<team> search | 52.4 | 56.3 | 88.9 | 16 | 21.8 | 22.0 | met |
| GET /resources account=<account> | 56.3 | 81.8 | 87.6 | 16 | 21.0 | 48.8 | met |
| GET /resources facets=kind,service,account | 183.6 | 193.7 | 219.7 | 31 | 76.8 | 98.8 | met |
| GET /resources q + account + facets | 76.9 | 85.4 | 87.9 | 31 | 52.2 | 17.3 | met |
| GET /workloads classification=agent sort=classification | 33.2 | 37.2 | 51.7 | 12 | 4.7 | 21.2 | met |
| GET /identities used_by=workloads | 65.5 | 72.0 | 81.1 | 16 | 23.9 | 35.7 | met |

### Totals and facets (p95 target 3s)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /workloads facets=account,runtime_kind,classification,region | 102.8 | 109.5 | 110.9 | 38 | 71.9 | 17.0 | met |
| GET /workloads q + account + facets | 118.4 | 125.1 | 127.7 | 31 | 78.4 | 19.9 | met |
| GET /identities facets=account,kind | 63.0 | 70.0 | 74.3 | 26 | 20.5 | 27.1 | met |
| GET /identities q + account + facets | 37.2 | 40.5 | 52.8 | 26 | 16.0 | 6.7 | met |
| GET /resources facets=kind,service,account | 183.6 | 193.7 | 219.7 | 31 | 76.8 | 98.8 | met |
| GET /resources q + account + facets | 76.9 | 85.4 | 87.9 | 31 | 52.2 | 17.3 | met |

### Detail tabs (p95 target 300ms)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /workloads/:id | 11.0 | 17.0 | 20.6 | 10 | 0.0 | 2.0 | met |
| GET /workloads/:id/identities | 34.3 | 44.4 | 58.6 | 40 | 6.6 | 2.5 | met |
| GET /workloads/:id/resources | 29.7 | 33.8 | 44.9 | 20 | 3.2 | 5.0 | met |
| GET /workloads/:id/classification | 8.1 | 9.3 | 13.7 | 10 | 1.1 | 1.3 | met |
| GET /workloads/:id/resources (most-granted role) | 29.1 | 33.1 | 48.8 | 20 | 4.1 | 4.7 | met |
| GET /workloads/:id (most-granted role) | 10.7 | 12.6 | 22.0 | 10 | 0.0 | 1.8 | met |
| GET /identities/:id (roles) | 11.3 | 16.4 | 24.1 | 12 | 1.9 | 2.1 | met |
| GET /identities/:id/used-by (roles) | 18.6 | 27.0 | 53.0 | 19 | 13.7 | 23.5 | met |
| GET /identities/:id/permissions (roles) | 27.6 | 37.5 | 40.6 | 19 | 5.1 | 6.4 | met |
| GET /identities/:id (users) | 12.2 | 14.6 | 16.1 | 13 | 1.4 | 1.7 | met |
| GET /identities/:id/permissions (users) | 32.8 | 43.2 | 47.2 | 20 | 4.9 | 8.9 | met |
| GET /identities/:id (hub role, 403 workloads) | 11.8 | 12.7 | 13.8 | 12 | 2.3 | 2.3 | met |
| GET /identities/:id/used-by (hub role, 403 workloads) | 35.3 | 40.8 | 41.8 | 19 | 9.8 | 9.5 | met |
| GET /identities/:id/used-by (ecsTaskExecutionRole, 1016) | 45.9 | 50.1 | 51.8 | 19 | 12.5 | 17.3 | met |
| GET /identities/:id/used-by (largest group) | 13.1 | 14.8 | 16.8 | 12 | 1.7 | 2.9 | met |
| GET /identities/:id/permissions (most grants) | 30.2 | 33.6 | 37.1 | 19 | 4.0 | 6.8 | met |
| GET /external-principals/:id | 8.4 | 9.9 | 15.3 | 7 | 0.0 | 2.3 | met |
| GET /external-principals/:id/referenced-by | 11.8 | 16.3 | 21.2 | 12 | 1.6 | 3.3 | met |
| GET /external-principals/:id (lambda.amazonaws.com) | 11.7 | 13.9 | 16.7 | 7 | 0.0 | 5.0 | met |
| GET /external-principals/:id/referenced-by (lambda.amazonaws.com) | 28.2 | 32.6 | 35.3 | 12 | 4.5 | 12.2 | met |
| GET /resources/:id | 31.9 | 34.3 | 38.6 | 14 | 1.3 | 18.8 | met |
| GET /resources/:id/access | 21.4 | 25.7 | 27.7 | 16 | 4.1 | 4.7 | met |
| GET /resources/:id ("*") | 41.9 | 44.1 | 46.6 | 14 | 13.1 | 17.7 | met |
| GET /resources/:id/access ("*") | 201.6 | 219.8 | 230.4 | 18 | 69.9 | 74.1 | met |
| GET /resources/:id (most-named bucket) | 34.7 | 36.9 | 48.2 | 14 | 4.6 | 18.8 | met |
| GET /resources/:id/access (most-named bucket) | 115.7 | 121.0 | 122.8 | 18 | 32.2 | 43.9 | met |
| GET /identities/:id/used-by section=workloads page 2 (ecsTaskExecutionRole, 1016) | 36.7 | 38.8 | 39.4 | 12 | 10.1 | 19.5 | met |
| GET /resources/:id/access page 2 ("*") | 200.5 | 214.5 | 229.7 | 18 | 71.8 | 81.7 | met |

### Graph (p95 target 1.5s)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /graph workload forward | 51.7 | 73.7 | 77.0 | 39 | 3.9 | 5.4 | met |
| GET /graph workload forward (most-granted role) | 56.6 | 60.9 | 73.1 | 39 | 3.1 | 4.9 | met |
| GET /graph identity forward (roles) | 41.9 | 119.1 | 129.7 | 32 | 6.4 | 4.3 | met |
| GET /graph identity reverse (hub role) | 58.1 | 64.4 | 364.2 | 22 | 2.0 | 16.8 | met |
| GET /graph resource reverse | 84.9 | 119.4 | 159.4 | 35 | 12.0 | 11.2 | met |
| GET /graph resource reverse (most-named bucket) | 182.8 | 219.3 | 228.7 | 31 | 35.0 | 330.8 | met |
| GET /graph external principal forward (lambda.amazonaws.com) | 214.0 | 233.9 | 280.2 | 22 | 89.3 | 76.8 | met |
| GET /graph/expand executes_as reverse (hub role, 403 workloads) | 28.7 | 32.0 | 49.6 | 14 | 1.7 | 14.5 | met |
| GET /graph/expand target reverse ("*") | 51.6 | 56.8 | 59.5 | 17 | 5.7 | 24.2 | met |
| GET /graph/path workload -> a resource its role reaches | 102.6 | 433.7 | 437.7 | 65 | 31.8 | 10.9 | met |
| GET /graph/path workload -> "*" (most-granted role) | 124.8 | 133.1 | 427.5 | 31 | 3.3 | 57.4 | met |

Response sizes (every measured, warm and traced response; display maxima 150 nodes, 300 edges):

| Read | Server budgets (meta.budgets) | Largest response: nodes | edges | Within the display maxima | Truncated (bound_by: responses) |
|---|---|---:|---:|---|---|
| GET /graph workload forward | 500 nodes, 2000 edges | 99 | 115 | yes | none |
| GET /graph workload forward (most-granted role) | 500 nodes, 2000 edges | 105 | 146 | yes | none |
| GET /graph identity forward (roles) | 500 nodes, 2000 edges | 189 | 237 | no | assume_hops: 12 |
| GET /graph identity reverse (hub role) | 500 nodes, 2000 edges | 405 | 404 | no | none |
| GET /graph resource reverse | 500 nodes, 2000 edges | 500 | 499 | no | assume_hops: 38, nodes: 2 |
| GET /graph resource reverse (most-named bucket) | 500 nodes, 2000 edges | 500 | 499 | no | nodes: 53 |
| GET /graph external principal forward (lambda.amazonaws.com) | 500 nodes, 2000 edges | 500 | 499 | no | nodes: 53 |
| GET /graph/expand executes_as reverse (hub role, 403 workloads) | 500 nodes, 2000 edges | 100 | 100 | yes | none |
| GET /graph/expand target reverse ("*") | 500 nodes, 2000 edges | 100 | 100 | yes | none |
| GET /graph/path workload -> a resource its role reaches | 500 nodes, 2000 edges | 4 | 3 | yes | nodes: 2 |
| GET /graph/path workload -> "*" (most-granted role) | 500 nodes, 2000 edges | 0 | 0 | yes | nodes: 53 |

### Evidence (p95 target 300ms)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /evidence grant | 38.1 | 42.8 | 57.7 | 14 | 0.0 | 19.5 | met |
| GET /evidence assignment | 10.5 | 12.7 | 44.1 | 8 | 0.0 | 3.5 | met |
| GET /evidence relationship (executes_as) | 10.7 | 12.4 | 13.4 | 8 | 0.0 | 3.6 | met |
| GET /evidence relationship (cross-account can_assume) | 10.6 | 11.8 | 13.6 | 8 | 0.0 | 3.1 | met |
| GET /evidence workload presence | 19.0 | 24.1 | 25.6 | 9 | 0.0 | 13.0 | met |
| GET /evidence coverage | 7.2 | 10.2 | 12.4 | 5 | 0.0 | 1.9 | met |
| GET /evidence grouped edge (39 grants) | 51.3 | 61.1 | 95.6 | 15 | 0.0 | 22.0 | met |
| GET /evidence 50 claims (the D-79 maximum, many holders) | 64.9 | 74.3 | 78.0 | 14 | 0.0 | 23.2 | met |

### Changes (p95 target 500ms)

| Read | p50 ms | p95 ms | max ms | Statements | COUNT ms (traced) | Slowest statement ms (traced) | Verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| GET /workloads/:id/changes | 73.4 | 117.5 | 134.5 | 24 | 25.2 | 25.9 | met |
| GET /workloads/:id/changes (role switched) | 77.0 | 113.3 | 154.8 | 29 | 26.6 | 25.4 | met |
| GET /workloads/:id/changes (most-granted role) | 70.2 | 80.4 | 131.4 | 24 | 25.4 | 24.5 | met |
| GET /workloads/:id/changes kind=coverage | 14.0 | 15.3 | 20.4 | 14 | 4.2 | 4.2 | met |
| GET /identities/:id/changes (roles) | 67.6 | 103.9 | 107.9 | 22 | 29.6 | 36.8 | met |
| GET /identities/:id/changes (most grants) | 54.6 | 57.4 | 58.6 | 17 | 22.8 | 25.0 | met |
| GET /identities/:id/changes page 2 (most grants) | 66.0 | 70.6 | 74.4 | 23 | 23.9 | 21.9 | met |
| GET /resources/:id/changes | 111.2 | 133.7 | 173.2 | 21 | 51.7 | 50.2 | met |
| GET /resources/:id/changes ("*") | 280.9 | 305.7 | 331.6 | 28 | 109.0 | 152.0 | met |
| GET /resources/:id/changes (most-named bucket) | 218.3 | 231.0 | 258.1 | 28 | 83.6 | 86.9 | met |

**Graph, read against the display defaults.** Five of the eleven Graph reads
stayed within the display maxima in every response and were measured exactly
at the display defaults: both workload-forward graphs (≤ 105 nodes, ≤ 146
edges), both expands (a page of 100) and the path to a resource the
workload's role reaches (≤ 4 nodes; 2 of its responses carried
`bound_by: nodes`). Five returned more than a first drawing shows, so their
time is an upper bound on a display-default request: identity forward (up to
189 nodes; 12 responses stopped by `assume_hops`), the hub role's reverse
graph (405 nodes, nothing bound), and three that reached the **hard** node
budget of 500 (`truncated.bound_by: nodes`) — a typical resource's reverse
graph (2 responses), the most-named reference's and `lambda.amazonaws.com`'s
(every response). Even these stayed far inside 1.5 s (largest p95 of the
five: 233.9 ms). The eleventh, `GET /graph/path workload -> "*"
(most-granted role)`, returned no path: `not_found_within_budget` with
`bound_by: nodes` in every response — the search reached the node budget
before its two sides met, so its time is that of a search run to the hard
budget, and it establishes nothing about a path (honest by §5.4's rules;
noted in §7).

Closest to their targets (run 2): `GET /resources/:id/access ("*")` p95
219.8 of 300 ms (page 2: 214.5), `GET /resources/:id/changes ("*")` 305.7 of
500 ms, `GET /resources facets=kind,service,account` 193.7 of 400 ms.

### 5.1 Run 1 (at `555a821`): four misses under shared load

The first run of this pass, 22:23–22:33 at `555a821` (the same code and the
same reads, except that the hub-role reads still measured account B's
`ecsTaskExecutionRole`, §3), **failed**: 12 tests (40 with subtests) — 39
passed, 0 skipped, **1 failed** (`TestP2LoadTargets`), with four p95 misses:

| Read | Run 1 p50 / p95 / max ms | Run 2 p50 / p95 / max ms | Target |
|---|---|---|---:|
| `GET /resources facets=kind,service,account` | 197.2 / **432.2** / 460.0 | 183.6 / 193.7 / 219.7 | 400 |
| `GET /resources/:id/access ("*")` | 226.9 / **560.2** / 602.1 | 201.6 / 219.8 / 230.4 | 300 |
| `GET /resources/:id/access (most-named bucket)` | 127.2 / **346.0** / 434.6 | 115.7 / 121.0 / 122.8 | 300 |
| `GET /resources/:id/access page 2 ("*")` | 217.1 / **425.1** / 653.0 | 200.5 / 214.5 / 229.7 | 300 |

The code under test is the same in both runs (`555a821..3a80c78` changes only
the harness's hub selection, §3). Run 1's p50s are within 13% of run 2's (and
of the earlier session's passing run: 224.5 ms for the `*` Access), while its
p95s are 2.0–2.7× its p50s where run 2's are 1.05–1.09×, and its traced pass
once saw the most-named reference's grant-first page statement take 346 ms
(44 ms in run 2): the pattern of outside load, not of more work. A
nearest-rank p95 over 50 samples is the 48th, so three disturbed requests
decide it. Run 1 ran with a 30 s `docker stats` / `pg_stat_activity` sampler
of mine beside it — a burst of work in the Docker VM every half minute — while
other agents' suites ran on the host (Windows Defender was its largest CPU
consumer when checked after the run). Run 2 ran without the sampler on a quiet
host. Both runs are recorded because the margin is real: the `*` Access
page's p50 is two thirds of its target, so on a loaded machine its p95
crosses 300 ms (run 1, and the session's first run before the identity-first
page, at 908 ms). On an unloaded server these reads meet their targets with
the margins above; on a shared one they may not.

## 6. Defects found and fixed

A target missed is a defect (§5.6). Each fix below keeps the answer
byte-for-byte (the existing suites and the tests named pass) and is held to
its speed by this load test (§8). All but the last were fixed in earlier
commits of `m1/load` and are measured again here.

| Read | Cause (EXPLAIN ANALYZE) | Fix | Before → after |
|---|---|---|---|
| Every read of a hub object, first seen on `/resources/:id/changes ("*")` | pgx prepares and caches statements per connection; after five executions PostgreSQL may switch to a GENERIC plan, costed for a typical object and ruinous for `*` | `Reader.Read` sets `plan_cache_mode = force_custom_plan` for its transaction (`internal/igaread/snapshot.go`) | generic plans: `504 query_timeout` on `/resources/:id/changes` within the first measured read (mutation LM1); custom: 280.9 / 305.7 ms p50 / p95 (run 2) |
| Any statement costed above `jit_above_cost` (100 000) | JIT compilation before the first row: a holder count over `*` ran 875 ms with JIT, 106 ms without; the resource list's page is already costed at 75 073 on this fixture, so a somewhat larger estate would pay it on every page | the same statement also sets `jit = off` for the transaction (both via `set_config(..., true)`, one round trip) | latent here (no measured statement crosses the threshold); guarded by `TestP2LoadReadPlansWithBindValuesOnlyInsideTheRead` |
| `GET /resources/:id/access ("*")` (and its page 2) | grant-first: all 20 049 grants on the 2 553 statements naming `*`, their 26 145 access rows materialised (spilling to disk at `work_mem` 4 MB), to keep a page of 101 of 3 279 holders | identity-first page for references named by ≥ 1 000 positive targets (`rdetailAccessDensePageSQL`): walk the identities in page order, one `LIMIT 1` probe each, stop at the page. Same rows, same order (tested on the lab and the fixture) | page statement 150 → 38 ms (psql); read 355.7 / 908.2 → 201.6 / 219.8 ms (run 2); page 2 277.4 / 354.4 → 200.5 / 214.5 ms. Mutation LM2 (strategy off): misses again |
| `GET /resources/:id/access` (all) | the access CTEs carried every statement's document through all rows | CTEs carry ids only; the page joins statement and policy columns for its own rows | disk spill removed |
| `GET /resources/:id/changes` (hub references) | per-revision predecessor lookup with no index (`iga_statement_revision` is indexed only on its live row): 2.5 s for the 1 913 revisions under `*`, a 504; correlated `EXISTS` over the event table per retired statement; every branch re-reading the naming set; full sort of 22 000 grant events for a page of 50; a total over one DISTINCT | one window for predecessors; `(policy, run)` pairs computed once; shared MATERIALIZED CTEs; each branch cut to its first limit+1 rows after the cursor before merging (repeatable branches deduplicated first); the total streams unique branches into its LIMIT | 280.9 / 305.7 ms (`*`), 218.3 / 231.0 ms (most-named), run 2 |
| `GET /evidence` grouped edges | one `cloud_observation` scan per distinct target text (≈ 20 ms each; `subject_native_id` has no index) | `ResourcePoliciesOf`: one statement for every text, decided per text | 50-claim request 74.3 ms p95 (run 2) |
| `GET /workloads?q=...` with facets | the provider-id arm (two regular expressions per row) evaluated in six statements over the whole estate | a cheap suffix test on the ARN first; the full equality still decides (`listsExact.suffixOf`) | q + account + facets 125.1 ms p95 (run 2) |
| The harness: `/graph/expand executes_as reverse (hub role)` | the hub role was an `ecsTaskExecutionRole`, which no workload runs as (§3): the read measured an empty page | the hub selection leaves out every `ecsTaskExecutionRole` (`3a80c78`) | 20.4 / 28.5 ms of nothing → 28.7 / 32.0 ms for a page of 100 workloads |

## 7. What only an index would fix, and what the numbers depend on

**Proposed indexes — recorded as P2-DECISIONS "D-load (number on merge)",
*Raise* for Aditya; not applied to any migration** (the §3 DDL stays verbatim
this milestone). A resource's Changes selects its grant, revision and
replacement branches by statement, and 036 has no index on the column any of
them selects by: `idx_iga_access_edges_entitlement` is partial on
`state <> 'ended'` and Changes must see ended grants; `iga_statement_revision`
is indexed only on its live revision; `iga_lifecycle_event` has none by
entitlement. So every page and every total of every resource's Changes scans
`iga_access_edges`, `iga_statement_revision` and `iga_lifecycle_event`.
§5.6 names "lifecycle and validity columns" for Changes. Proposed:

```sql
CREATE INDEX idx_iga_access_edges_entitlement_all ON public.iga_access_edges (workspace_id, entitlement_id);
CREATE INDEX idx_iga_le_entitlement ON public.iga_lifecycle_event (workspace_id, entitlement_id) WHERE entitlement_id IS NOT NULL;
CREATE INDEX idx_iga_statement_revision_entitlement ON public.iga_statement_revision (workspace_id, entitlement_id, valid_from, id);
```

Measured after run 2 on its rows in `iga_w_loadfx` (the statements run 2
traced, binds inlined; the typical reference's page is its total's reference
put into the `*` page statement): psql `EXPLAIN (ANALYZE, TIMING OFF)` with
the reads' settings (`jit = off`, `plan_cache_mode = force_custom_plan`),
median of 9; the indexes created, the three tables ANALYZEd, measured again,
the indexes dropped (verified gone), then the database recreated empty:

| Statement | Without (036) | With the three indexes | Sequential scans left |
|---|---:|---:|---|
| typical resource's Changes page | 49.0 ms | 0.9 ms | none (was all three tables) |
| typical resource's Changes total | 48.2 ms | 0.8 ms | none (was all three tables) |
| most-named resource's page / total | 92.9 / 91.8 ms | 93.4 / 89.1 ms | `iga_access_edges`, `iga_statement_revision` |
| `*` page / total | 154.9 / 96.1 ms | 161.5 / 98.0 ms | `iga_access_edges`, `iga_statement_revision` |

A typical reference's Changes statements become fifty times faster; the hub
references are bound by their volume (22 000 grant events under `*`), and at
`random_page_cost` 4 the planner keeps the sequential scans of edges and
revisions for them even with the indexes (only the lifecycle scan goes). The
targets are met without the indexes; they buy headroom on the reads a user
opens most. (The earlier session's measurement in `iga_w_load` found the same:
46.2 → 3.1 ms and 52.5 → 2.2 ms typical, the hub references unchanged.)

**A traversal observation (for `m1/graph`, not a §5.6 miss).** `GET /graph/path`
from the workload of the most-granted role to `*` answers
`not_found_within_budget` (`bound_by: nodes`) every time: the bidirectional
search reaches the 500-node hard budget before its sides meet. The answer is
honest (§2.14.11 *Budgets*: "a budget stopped it — the answer is unknown"), but a path
search from a heavily granted workload to a hub reference will not complete
within the hard budgets on an estate of this shape.

**Other conditions of these numbers.**

- The machine is shared (§2, §5.1). Interleaving spreads bursts of outside
  load across the reads; it cannot remove them.
- PostgreSQL runs with its defaults (128 MB shared buffers for a 309 MB
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
| D7 | identity-first page: a listed holder's DIRECT rows without the state filter (`g.state IN ?` → `(g.state IN ? OR true)`, `resource_access.go` access_rows) | `TestP2LoadAccessStrategiesAgreeOnTheLab`, now with deployer holding an ended (OpsRead) and a current (DeployWide) grant on `*` | yes: the default-state pages of `*` differ (identity-first lists OpsRead's ended row), stages 2 and 3, limits 1, 2 and 100. The same mutation against the test as it was at `54b48f5` (no holder with both): PASS — nothing caught it before |
| L1, L2 | q provider-id: suffix test `right` → `left`; full equality dropped | `TestP2LoadWorkloadQMatchesTheWholeProviderID` | yes, each |
| R1 | batched resource policies not split by subject | `TestP2LoadGroupedEvidenceReadsEachTargetsOwnResourcePolicy` | yes |
| C1–C3 | Changes: workload revisions, holders' and resource's replacements counted as unique | `TestP2LoadChangesTotalCountsEachEventOnce` | yes, each |
| C4 | Changes: repeatable arms not deduplicated before the per-branch cut | `TestP2LoadChangesPagesKeepEveryRepeatedEvent` | yes: the limit-2 pages skipped an event |
| C5, C6 | Changes: per-branch cursor `<` → `<=`; total without DISTINCT over repeatable branches | `TestP2LoadChangesTotalCountsEachEventOnce` | yes, each |
| C7–C9 | Changes: edited revisions include a first revision (holders; resource); before/after loader takes the wrong predecessor | `TestP2Changes*` + the above | yes, each |
| X1 | holders' statement_replaced correlated by run only (`changesBegunInRunSQL`: `(e.policy_id, le.scan_run_id) IN (SELECT ne.policy_id, n.scan_run_id ...)` → `le.scan_run_id IN (SELECT n.scan_run_id ...)`) | `TestP2LoadChangesReplacementStaysInItsPolicy` | yes: the identity's and the workload's Changes show a SplitOld replacement in the run |
| X2 | resource's statement_replaced window by run only (`PARTITION BY s.policy_id, n.scan_run_id` → `PARTITION BY n.scan_run_id`) | same | yes: the bucket's Changes show it |
| X3 | resource's replacement without the new side (`w.names OR w.begun_naming` → `w.names`) | `TestP2LoadChangesReplacementReachesTheNewTarget` | yes: `move-to/*` has 0 statement_replaced, want 1 |
| G1 | `loadEnvFor` never calls `loadDSNRefusal` | `TestP2LoadRefusalStopsTheFixture` (a child run with `IGA_LOAD_DSN` = `IGA_TEST_DSN`, on an unresolvable host) | yes: the child failed connecting, without the refusal |
| G2 | `loadDSNRefusal` never finds a match (`theirs == mine` → `false && ...`) | `TestP2LoadRefusesASharedDatabase` | yes: 7 of 13 cases |
| GS1 | Graph shape keeps the last response, not the largest | `TestP2LoadGraphShape` | yes |
| GS2, GS3 | `/graph/path` edges / nodes not deduplicated across paths | same | yes, each — GS2 only after the test's second body was given a shared edge (at first the largest-response rule masked it) |
| H8 | the hub role may be an `ecsTaskExecutionRole` (the old selection) | `TestP2LoadFixtureIntegrity` | yes: "hub role's executes_as expand: 0 nodes ... (547 workloads use it)" |
| H1–H7, H2b, I1 | harness: a timed-out total / time-bound traversal / null facet not flagged; a non-200 not a failure; a p95 over target not a miss; nearest rank off by one; facets not counted as COUNT work; reads measured one after another instead of round-robin | `TestP2LoadHonest`, `…MeasureFailsWhatIsNotAnAnswer`, `…VerdictJudgesEveryRow`, `…Rank`, `…IsCount`, `…Interleaves` | yes, each |

## 9. Test counts (§7.4)

| Run | Commit | Command | Tests (with subtests) | Passed | Skipped | Failed |
|---|---|---|---:|---:|---:|---:|
| 2 (recorded) | `3a80c78` | §1, reusing run 1's fixture | 12 (40) | 12 (40) | 0 | 0 |
| 1 | `555a821` | §1, fixture built from `iga_tpl` | 12 (40) | 11 (39) | 0 | 1 (`TestP2LoadTargets`, §5.1) |

The tests: `TestP2LoadTargets` (the 77 reads), `TestP2LoadFixtureIntegrity`,
`TestP2LoadAccessStrategiesAgree` (both Access strategies over every
reference of the fixture), `TestP2LoadRefusesASharedDatabase`,
`TestP2LoadRefusalStopsTheFixture`, and the harness's own
`TestP2LoadHonest`, `…Rank`, `…IsCount`, `…MeasureFailsWhatIsNotAnAnswer`,
`…VerdictJudgesEveryRow`, `…Interleaves`, `…GraphShape`. Without
`IGA_LOAD_DSN` the first three skip — such a run is not a pass for them.
The integration package's T6.10 tests (`TestP2Load*` in `tests/integration`)
run in the §7.3 gate, `go test -p 1 -run 'TestP2' ./tests/integration/`.
