# Testing the Agentic IGA flow

Two ways to exercise it: the automated integration test (fast, deterministic,
no tenant needed) and a manual curl walkthrough against a running server.

Neither touches a real GitHub tenant. The provider is an interface with a
fixture-backed implementation, which is deliberate — the Stage-0 spike is what
produces recorded response fixtures, and until it runs there is nothing
verified to call.

---

## A. Automated integration test

Exercises the whole pipeline against a real Postgres: connect → verify →
enumerate → classify → project → coverage, plus webhook ingress and the worker.

### 1. Create a scratch database

Never run this against a database you care about — the bootstrap is
single-state and assumes an empty database.

```bash
docker exec postgres psql -U authsec -d postgres \
  -c "DROP DATABASE IF EXISTS iga_test;" \
  -c "CREATE DATABASE iga_test;"

docker cp migrations/master/001_bootstrap.sql postgres:/tmp/bootstrap.sql
docker exec postgres psql -U authsec -d iga_test -v ON_ERROR_STOP=1 -q -f /tmp/bootstrap.sql

# expect 24
docker exec postgres psql -U authsec -d iga_test -tAc \
  "SELECT count(*) FROM information_schema.tables WHERE table_name LIKE 'iga_%';"
```

### 2. Run the test

```bash
export IGA_TEST_DSN="host=localhost port=5432 user=authsec password=<pw> dbname=iga_test sslmode=disable"
go test ./tests/integration/ -run TestIGA -v
```

Without `IGA_TEST_DSN` the tests skip, so plain `go test ./...` stays green.

### If the host cannot reach the container

On this machine a native PostgreSQL service owns host port 5432, so Docker's
published port never reaches the container. Symptom: `password authentication
failed` from the host while `docker exec psql` works fine. Cross-compile the
test and run it inside the Docker network instead:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o /tmp/iga_test.bin ./tests/integration/

docker run -d --name igarun --network onprem_authsec-net alpine sleep 1200
docker cp /tmp/iga_test.bin igarun:/iga_test && docker exec igarun chmod +x /iga_test

docker exec -e IGA_TEST_DSN="host=postgres port=5432 user=<u> password=<pw> dbname=iga_test sslmode=disable" \
  igarun /iga_test -test.run TestIGA -test.v

docker rm -f igarun
```

### What the four tests assert

**`TestIGABindingSecurity`** — the two ways an installation could bind to the
wrong tenant.

| Assertion | Why it matters |
|---|---|
| A spoofed installation id is refused | Setup-URL ids are attacker-supplied; the installation account must match the authenticated admin |
| The honest case verifies | The guard is not just blocking everything |
| A second workspace cannot claim the same installation | The unique index that deliberately *excludes* `workspace_id` |
| An unverified re-auth is still allowed | An abandoned authorization must not permanently block a retry |

**`TestIGAScanPipeline`** — the enumeration funnel end to end, over three
deliberately different repositories: one with a provider-declared agent, one
with only a weak workflow signal *and* a truncated tree, one that 403s.

| Assertion | Why it matters |
|---|---|
| Scan is `succeeded` **and** authoritative | An interrupted scan must never prove deletion |
| Exactly **1** auto-confirmed agent | Only `platform_declared` may auto-confirm |
| The workflow signal stays a **pending candidate** | Weak evidence never silently becomes an agent |
| The App installation became an **identity**, not an agent | Lane C is not Lane A |
| The `langchain` dependency proposed **nothing** | A framework dependency is never sufficient |
| No secret value or prompt body persisted | Only the secret *name* is kept, as redacted evidence |
| Truncated tree → `partial`, not a smaller complete count | This is how "0 agents" gets manufactured |
| 403 scope → `partial` with a denied count | Permission loss is not absence |
| Operational issues recorded separately | A scan failure is not an agent-risk finding |
| Rescan **skipped 2** blobs, **fetched 0** | Cheap refresh via the stored blob SHA |
| Agent drills down to supporting observations | Every canonical fact resolves to evidence |

**`TestIGACandidateDecisionConcurrency`**

| Assertion | Why it matters |
|---|---|
| A stale `expected_version` is refused | Lost updates rejected, not last-write-wins |
| The correct version confirms and creates one agent | |
| A human-confirmed but weakly-evidenced agent gets `rollup_state=unknown` | Confirming does not upgrade the underlying evidence |
| A decided candidate cannot be decided twice | |

**`TestIGAWebhookIngress`**

| Assertion | Why it matters |
|---|---|
| Bad signature rejected **and zero jobs queued** | An invalid signature must not touch durable work |
| Valid signature + unknown installation → binding failure | The payload's installation id never authorizes |
| Valid + bound → accepted, exactly 1 job | |
| Redelivery → 1 delivery, 1 job, 1 effect | `X-GitHub-Delivery` is the idempotency key |
| Worker claims and completes it | |
| Empty queue is not an error | |

### Expected output

```
--- PASS: TestIGABindingSecurity
--- PASS: TestIGAScanPipeline
      scan: scopes=3 source_objects=5 observations=5 candidates=3 confirmed=1 fetched=2 skipped=0
      PASS: rescan skipped 2 unchanged blobs, fetched 0
--- PASS: TestIGACandidateDecisionConcurrency
--- PASS: TestIGAWebhookIngress
PASS
```

---

## B. Manual walkthrough

Needs a running server, a bearer token, and a role holding `iga:admin`,
`iga:read` and `iga:review`. The workspace comes from the token — it is never
accepted from a body or query parameter.

```bash
TOKEN="<bearer>"
H=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")
BASE=http://localhost:8080/api/iga/v1
```

### 1. Create an integration

```bash
curl -s "${H[@]}" -X POST $BASE/integrations -d '{
  "provider":"github","provider_host":"github.com",
  "app_registration_id":"app-1",
  "requested_permissions":{"contents":"read","administration":"read"}
}'
```

`status: pending`, `verified_at: null`. Note the `id`.

### 2. Verify the binding

```bash
curl -s "${H[@]}" -X POST $BASE/integrations/$IID/verify -d '{
  "installation_id":"12345","account_native_id":"acme",
  "authenticated_account_id":"acme",
  "granted_permissions":{"contents":"read"}
}'
```

Now try the spoof — the same call with `"authenticated_account_id":"attacker"`
must return **403 `binding_failed`**.

### 3. Scan

```bash
curl -s "${H[@]}" -X POST "$BASE/integrations/$IID/scans?mode=full"
```

Returns a report with separate counts and per-scope coverage.

### 4. Read the results — note they are separate routes

```bash
curl -s "${H[@]}" "$BASE/integrations/$IID/coverage"      # no averaged percentage
curl -s "${H[@]}" "$BASE/agents"                          # confirmed only
curl -s "${H[@]}" "$BASE/classification-candidates"       # candidates only
curl -s "${H[@]}" "$BASE/integrations/$IID/source-health" # operational issues
curl -s "${H[@]}" "$BASE/agents/$AID/evidence"            # drill-down
```

### 5. Decide a candidate

```bash
curl -s "${H[@]}" -X POST $BASE/classification-candidates/$CID/decisions \
  -d '{"decision":"confirmed","reason":"reviewed","expected_version":1}'
```

Repeat with a wrong `expected_version` → **409 `version_conflict`**.

### 6. Webhook

```bash
SECRET="$IGA_GITHUB_WEBHOOK_SECRET"
BODY='{"action":"created"}'
SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"

curl -s -X POST "http://localhost:8080/api/iga/v1/webhooks/github/app-1" \
  -H "X-GitHub-Delivery: d-1" -H "X-GitHub-Event: installation_repositories" \
  -H "X-GitHub-Installation-ID: 12345" -H "X-Hub-Signature-256: $SIG" \
  -H "Content-Type: application/json" -d "$BODY"
```

- Correct signature + known installation → **202**
- Same delivery id again → **202** with `"redelivery": true`, no second job
- Tampered signature → **401**, and `iga_durable_jobs` gains nothing

---

## C. Direct SQL checks

```sql
-- coverage is per scope and class, and is never averaged
SELECT object_class, state, reason_code, inspected_count, denied_count
  FROM iga_coverage_states WHERE workspace_id = :ws;

-- confirmed agents and candidates are separate counts
SELECT 'confirmed_agents' AS k, count(*) FROM iga_agents WHERE workspace_id = :ws
UNION ALL
SELECT 'pending_candidates', count(*) FROM iga_classification_candidates
 WHERE workspace_id = :ws AND state = 'pending';

-- no secret material anywhere in the evidence
SELECT count(*) AS must_be_zero FROM iga_observations
 WHERE workspace_id = :ws AND fact_payload::text ~* '(sk-|BEGIN.*PRIVATE KEY|password)';

-- every agent resolves to evidence
SELECT a.id, count(l.id) AS supporting
  FROM iga_agents a
  LEFT JOIN iga_observation_links l
    ON l.target_kind='agent' AND l.target_id=a.id AND l.workspace_id=a.workspace_id
 WHERE a.workspace_id = :ws GROUP BY a.id;
```

---

## What is NOT covered

- **No live GitHub call anywhere.** The provider is a fixture. Real endpoints,
  per-plan availability, rate-limit behaviour and token minting are Stage-0
  work and cannot be tested without a tenant.
- **The rule catalogue is a two-rule starter set**, not the Stage-4 catalogue.
  Real rules need official schema references, positive/negative/malformed
  fixtures, and measured precision on a labelled corpus before any of them may
  auto-classify.
- **No scale or cadence benchmark.** Scan duration, API-call cost and safe
  refresh interval are explicitly must-not-guess and need a measured tenant run.
- **Tombstoning is not implemented.** The generation columns and the
  authoritative-scan gate exist, but the sweep that marks absent objects does
  not, so nothing is ever tombstoned yet.
