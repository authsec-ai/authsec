# GCP-01–04 Live E2E Test Plan (real Google Cloud, no mocks)

**Purpose:** prove the actually-implemented GCP onboarding contract (GCP-01
through GCP-04) works against a real GCP project, real Vault, and a real
running AuthSec backend — not `go test`, not the `httptest`/fake-server
seams those tests use. This document is a prompt: work through it top to
bottom, run every command, and fill in the report template at the end with
what actually happened (paste real output, never paraphrase a response).

**Scope — read this before starting anything.** GCP-04 is the onboarding
API only: create / verify / read / revoke a `cloud_connector` row. Nothing
past that exists yet. Specifically OUT OF SCOPE for this test plan, because
the code does not exist:
- Any discovery/scan endpoint (`GCP-06`+) — no `cloud_identity`,
  `cloud_secret`, `cloud_permission`, `cloud_resource`, `cloud_assume_edge`
  row is ever written by anything built so far. If you find yourself
  looking for a "scan" button or endpoint, stop — it isn't built.
- GKE Workload Identity, effective-access computation, deny-policy reads.
- The console/UI (GCP-05) — everything below is `curl` against the API
  directly.

If you find any of the above appears to exist, that is itself a finding —
report it, don't test it as if it were in scope.

---

## 0. The one thing most likely to make the WIF half of this fail

The WIF flow is not "fake" or "stubbed" — it is fully implemented — but it
has a real, physical precondition that is easy to miss: **Google's STS
(`sts.googleapis.com`) has to be able to reach your AuthSec server's own
OIDC issuer endpoints over the public internet**, because the WIF provider
setup-reader.sh creates trusts `config.AppConfig.OAuthBaseURL()` as its
issuer, and STS fetches `<issuer>/.well-known/openid-configuration` and
`<issuer>/oauth/jwks` from wherever that URL actually points.

If you run AuthSec locally with the repo's default `.env`
(`BASE_URL=http://localhost:7001`), the WIF live test **will fail**, at the
STS-exchange step, with an error shaped like
`{"error":"invalid_grant","error_description":"Error connecting to the
given credential's issuer."}` — this is the exact failure
`authsec/docs/gcp/feasibility-validation.md` (GCP-01, question e) already
recorded as expected in this situation. It is not a bug in GCP-04; it is
GCP-D9's design depending on a precondition this environment doesn't meet
by default.

**Before starting Workflow B (WIF), do ONE of:**
- **(a) Tunnel your local server publicly** (fastest to set up):
  `ngrok http 7001` (or `cloudflared tunnel --url http://localhost:7001`),
  then set both `BASE_URL` and `OAUTH_ISSUER_URL` in `.env` to the exact
  public HTTPS URL the tunnel gives you (e.g.
  `https://abc123.ngrok-free.app`), and **restart the AuthSec server**.
  Verify it worked: `curl https://<your-tunnel-host>/.well-known/openid-configuration`
  from a machine OTHER than the one running AuthSec (or just confirm the
  tunnel dashboard shows inbound traffic) — you need to see the real JSON
  discovery document, not a connection error.
- **(b) Point at an already-public AuthSec deployment** (dev/staging) if
  you have one, and run this whole plan against that deployment's API
  instead of localhost.
- **(c) Skip Workflow B's actual GCP connection steps** and only run its
  request-shape/validation sub-tests (§4.1, the pre-flight `wif_pool_missing`
  cross-check, which needs no network reachability at all) — mark the rest
  `UNVERIFIED — NO PUBLIC ISSUER` in your report, exactly as GCP-01's own
  ledger did. This is a legitimate, honest outcome — do not fabricate a
  success you didn't actually see.

Do **not** change `BASE_URL`/`OAUTH_ISSUER_URL` again once you start
Workflow B — a mismatch between what the script embedded and what the
server currently serves will make the discovery-document Host check
(`CanonicalIssuerOnly`) 308-redirect, which may or may not be followed
cleanly by Google's fetcher.

---

## 1. Prerequisites

### 1.1 GCP side (you said you already have `gcloud auth login` — confirm scope)

```bash
gcloud auth list                      # confirm the active account
gcloud config get project             # confirm a default project
gcloud organizations list             # note whether you have an org (optional — project-scope test works without one)
```

Decide your **reader project** (call it `$READER_PROJECT`) — where the
`authsec-reader` SA and, for WIF, the pool/provider will live — and your
**scope to connect** (`$SCOPE_KIND` = `project`, and `$SCOPE_ID` = a real
project id you can read; use `$READER_PROJECT` itself for `$SCOPE_ID` if you
don't have a second project, that's a valid, simple test case).

You need IAM admin rights on `$READER_PROJECT` (to create the SA, grant
roles, and — for WIF — create the workload identity pool/provider), and at
least `roles/browser` + `roles/iam.serviceAccountViewer` +
`roles/iam.roleViewer` + `roles/cloudasset.viewer` grantable on `$SCOPE_ID`.

### 1.2 Vault (required for the json_key path only — WIF never touches Vault)

```bash
# Dev-mode Vault is fine for this test.
vault server -dev -dev-root-token-id=root &
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root

# The code writes to paths shaped "kv/data/secret/...", which requires a
# KV v2 engine mounted at path "kv" specifically — dev mode's default mount
# is at "secret/", not "kv/", so this step is NOT optional:
vault secrets enable -path=kv -version=2 kv
vault secrets list   # confirm "kv/" is listed
```

Set in the AuthSec server's `.env` (or environment) before starting it:
```
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=root
```
If you skip this, every `json_key` `CreateConnector` call will fail at
`StoreKey` with a `secrets store not configured` error — that is expected,
not a bug, if Vault genuinely isn't wired; just don't mistake it for a
GCP-side problem.

### 1.3 Optional but recommended: a fixed HMAC key

```
AUTHSEC_CLOUD_DISCOVERY_HMAC_KEY=some-fixed-test-value
```
`internal/gcp.DeriveWIFParams` derives `pool_id`/`provider_id`/`wif_subject`
from this key (falling back to `JWTSecret`, then a dev constant, if unset).
Setting it explicitly just makes the derived values stable and easy to spot
in logs — not required for correctness as long as you don't restart the
server with a *different* value between fetching the onboarding package and
posting `CreateConnector` (if you do, the two calls derive different values
and the cross-check will legitimately reject you with `wif_pool_missing` —
that would be a real, correct rejection, not a bug).

### 1.4 Start the AuthSec server and get an API bearer token

Start the server per its normal run instructions with the env above set.
Then obtain a real, normal session/access token for a user or service
account in some workspace, through whatever your deployment's normal login
flow is (this test plan does not prescribe one — use what you already use
day to day). Confirm the token actually carries `discovery:read` and
`discovery:admin`:

```bash
export AUTHSEC_URL=http://localhost:7001     # or your tunnel URL
export TOKEN="<your real bearer token>"

curl -s $AUTHSEC_URL/authsec/discovery/gcp/connectors \
  -H "Authorization: Bearer $TOKEN" | jq .
```
Expect **200** with `{"data":[],"meta":{"count":0,...}}` (or existing
connectors if you've run this before) — not 401/403. If you get 401/403
here, stop and fix authentication before continuing; nothing below will work
without it.

---

## 2. Workflow A — JSON key, full lifecycle

### 2.1 Fetch the onboarding package

```bash
curl -s "$AUTHSEC_URL/authsec/discovery/gcp/onboarding?reader_project_id=$READER_PROJECT&scope_id=$SCOPE_ID&scope_kind=$SCOPE_KIND" \
  -H "Authorization: Bearer $TOKEN" | jq .
```
**Expect:** HTTP 200, `"configured": true` (always — there is no
`configured:false` branch left in this code), `data.setup_script` containing
a full shell script with BOTH `Option A` (WIF) and `Option B` (json_key)
sections, `data.role_set` = exactly
`["roles/iam.serviceAccountViewer","roles/iam.roleViewer","roles/cloudasset.viewer","roles/browser"]`,
`data.role_set_status` = `"candidate_pending_GCP-01"`, `data.pool_id`
starting with `authsec-`, `data.provider_id` = `"authsec-provider"`.

Save the script and run **only the reader-SA-creation + role-grant section
plus Option B** for this workflow:

```bash
jq -r '.data.setup_script' onboarding.json > setup-reader.sh   # or copy from the curl output above
chmod +x setup-reader.sh
./setup-reader.sh
```
Watch it actually create `authsec-reader@$READER_PROJECT.iam.gserviceaccount.com`
and grant the four roles at `$SCOPE_KIND` scope `$SCOPE_ID` — confirm
independently:
```bash
gcloud iam service-accounts describe authsec-reader@$READER_PROJECT.iam.gserviceaccount.com
gcloud projects get-iam-policy $SCOPE_ID --flatten="bindings[].members" \
  --filter="bindings.members:authsec-reader@$READER_PROJECT.iam.gserviceaccount.com" \
  --format="table(bindings.role)"
```
**Expect:** all four roles listed (or the org/folder equivalent command if
you chose that scope kind).

The script's Option B prints a `gcloud iam service-accounts keys create`
command — run it, producing `reader-key.json`.

### 2.2 CreateConnector (json_key)

```bash
KEY_JSON=$(cat reader-key.json | jq -c .)   # compact, single-line
curl -s -X POST "$AUTHSEC_URL/authsec/discovery/gcp/connectors" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"scope_kind\":\"$SCOPE_KIND\",\"scope_id\":\"$SCOPE_ID\",\"reader_project_id\":\"$READER_PROJECT\",\"display_name\":\"live e2e json_key\",\"auth\":{\"method\":\"json_key\",\"key_json\":$(jq -Rs . < reader-key.json)}}" \
  | tee create_jsonkey.json | jq .
```
**Expect:** HTTP **201** (first time), `data.status = "active"`,
`data.verified_at` non-null, `data.provider = "gcp"`,
`data.scope_kind`/`data.scope_id` matching your input,
`data.parent_scope_id` non-null (the bare org/folder id one level up from
`$SCOPE_ID` — null only if you connected at org scope). The response body
must **not** contain `reader-key.json`'s `private_key` value anywhere —
`grep` it to be sure:
```bash
grep -c "$(jq -r .private_key reader-key.json | head -c 40)" create_jsonkey.json   # expect 0
```
Save the connector id: `CONNECTOR_ID=$(jq -r .data.id create_jsonkey.json)`.

**Now delete the local key file** (`rm reader-key.json`) — the plan and
GCP-03 both promise it's never needed again after this call.

### 2.3 Verify the row and the secret independently (DB + Vault, not the API)

```bash
psql "$DATABASE_URL" -c \
  "SELECT id, provider, scope_kind, scope_id, parent_scope_id, status, auth_ref, scan_generation, coverage, attrs FROM cloud_connector WHERE id = '$CONNECTOR_ID';"
```
**Expect:** `auth_ref` starts with `kv/data/secret/workspaces/` (never
`wif:`); `attrs` (jsonb) contains `"auth_method":"json_key"`,
`"reader_sa_email"` matching the key's `client_email`, and **no**
`private_key`/`key_json` field anywhere in `attrs`; `scan_generation = 0`;
`coverage = {}`.

```bash
vault kv get -mount=kv "data/secret/workspaces/<workspace_id>/cloud-discovery/gcp/$SCOPE_ID"
# or: vault read kv/data/secret/workspaces/<workspace_id>/cloud-discovery/gcp/<scope_id>
```
**Expect:** the secret exists and contains `key_json` = the full key file
content. This is the ONLY place the key value should exist anywhere in
AuthSec's stack — confirm the DB query above truly showed nothing.

### 2.4 VerifyConnector

```bash
curl -s -X POST "$AUTHSEC_URL/authsec/discovery/gcp/connectors/$CONNECTOR_ID/verify" \
  -H "Authorization: Bearer $TOKEN" | jq .
```
**Expect:** HTTP 200, `"success": true`, `data.status = "active"`. Confirm
`verified_at` in the DB moved forward:
```bash
psql "$DATABASE_URL" -c "SELECT verified_at, updated_at FROM cloud_connector WHERE id='$CONNECTOR_ID';"
```

### 2.5 GetConnector / ListConnectors

```bash
curl -s "$AUTHSEC_URL/authsec/discovery/gcp/connectors/$CONNECTOR_ID" -H "Authorization: Bearer $TOKEN" | jq .
curl -s "$AUTHSEC_URL/authsec/discovery/gcp/connectors" -H "Authorization: Bearer $TOKEN" | jq '.data | length'
```
**Expect:** the same row; list length includes this connector, filtered to
`provider="gcp"` only (if you have AWS connectors from earlier tickets in
the same workspace, they must NOT appear here).

### 2.6 Reconnect (idempotent upsert) — before revoking

Simulate a completed scan having advanced state, so the next check is
meaningful:
```bash
psql "$DATABASE_URL" -c \
  "UPDATE cloud_connector SET scan_generation = 5, coverage = '{\"iam_roles\":{\"state\":\"reached\",\"count\":3}}' WHERE id='$CONNECTOR_ID';"
```
Re-run the **exact same** `CreateConnector` call from §2.2 (you'll need a
fresh `reader-key.json` — re-run just the key-creation line from the script,
or reuse your key if you saved it before deleting):
```bash
# repeat the curl from 2.2 with the same scope_id
```
**Expect:** HTTP **200** this time (not 201), `id` in the response
identical to `$CONNECTOR_ID`. Then:
```bash
psql "$DATABASE_URL" -c "SELECT id, scan_generation, coverage FROM cloud_connector WHERE id='$CONNECTOR_ID';"
```
**Expect:** still exactly one row with this id, `scan_generation` **still
5**, `coverage` **still** containing `iam_roles` — the reconnect must not
have reset either.

### 2.7 RevokeConnector

```bash
curl -s -X DELETE "$AUTHSEC_URL/authsec/discovery/gcp/connectors/$CONNECTOR_ID" \
  -H "Authorization: Bearer $TOKEN" | jq .
```
**Expect:** HTTP 200, `"success": true`.
```bash
psql "$DATABASE_URL" -c "SELECT status FROM cloud_connector WHERE id='$CONNECTOR_ID';"   # expect 'revoked', row STILL PRESENT
vault kv get -mount=kv "data/secret/workspaces/<workspace_id>/cloud-discovery/gcp/$SCOPE_ID"  # expect: no value found (purged)
curl -s "$AUTHSEC_URL/authsec/discovery/gcp/connectors/$CONNECTOR_ID" -H "Authorization: Bearer $TOKEN" | jq .status
```
**Expect:** the connector is still readable via GET (row kept for audit —
this is the deliberate AWS divergence), `data.status = "revoked"`.

---

## 3. Workflow B — WIF, full lifecycle (requires §0's public-issuer setup)

### 3.1 Fetch the onboarding package for a DIFFERENT scope_id

Use a different `$SCOPE_ID` from Workflow A (or the same one is fine too,
since AuthRef differs — but a different one keeps the two lifecycles easy
to tell apart in the DB). Re-fetch:
```bash
curl -s "$AUTHSEC_URL/authsec/discovery/gcp/onboarding?reader_project_id=$READER_PROJECT&scope_id=$SCOPE_ID2&scope_kind=$SCOPE_KIND" \
  -H "Authorization: Bearer $TOKEN" | tee onboarding_wif.json | jq .
```
Note `data.pool_id`, `data.provider_id`, `data.wif_subject`,
`data.issuer_url` — **`issuer_url` must be your public tunnel/deployment
URL, not `localhost`.** If it says `localhost`, stop and fix §0 first.

### 3.2 Run the script's Option A section

```bash
jq -r '.data.setup_script' onboarding_wif.json > setup-reader-wif.sh
chmod +x setup-reader-wif.sh
./setup-reader-wif.sh
```
This creates the reader SA (if not already present), grants the four
roles, then Option A creates the workload identity pool + OIDC provider
trusting your issuer, binds impersonation, and prints:
```
Reader SA email:        authsec-reader@...iam.gserviceaccount.com
WIF provider resource:  projects/<NUM>/locations/global/workloadIdentityPools/<pool_id>/providers/authsec-provider
```
Copy both values exactly. Independently confirm the pool/provider exist and
the binding is scoped (not wildcard):
```bash
gcloud iam workload-identity-pools providers describe authsec-provider \
  --location=global --workload-identity-pool=<pool_id> --project=$READER_PROJECT

gcloud iam service-accounts get-iam-policy authsec-reader@$READER_PROJECT.iam.gserviceaccount.com --format=json
```
**Expect:** the provider's `oidc.issuerUri` = your public issuer URL exactly;
the SA's IAM policy has exactly one `roles/iam.workloadIdentityUser` binding
whose member starts with `principal://iam.googleapis.com/...` — **not**
`principalSet://...`.

### 3.3 CreateConnector (wif)

```bash
curl -s -X POST "$AUTHSEC_URL/authsec/discovery/gcp/connectors" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"scope_kind\":\"$SCOPE_KIND\",\"scope_id\":\"$SCOPE_ID2\",\"reader_project_id\":\"$READER_PROJECT\",\"display_name\":\"live e2e wif\",\"auth\":{\"method\":\"wif\",\"provider_resource\":\"<paste the printed value>\",\"reader_sa_email\":\"<paste the printed value>\"}}" \
  | tee create_wif.json | jq .
```
**This is the real test of GCP-D9's mechanism end to end** — it mints a
real `IssueCloudOnboardingToken`, performs a real STS token-exchange against
`sts.googleapis.com`, and a real `iamcredentials.generateAccessToken`
impersonation call, then a real `iam.serviceAccounts.get` and a real
`(organizations|folders|projects).get`.

**Expect on success:** HTTP 201, `data.status = "active"`, same shape as
§2.2 but `data.provider` still `"gcp"`.

**If this fails**, the error tells you exactly where in the chain it broke
— report the *exact* JSON body, do not summarize it:
- `{"error":"...", "fault":"customer_account", ...}` with message
  mentioning the credential exchange / pool → almost certainly §0's issuer
  reachability, or the pool/provider genuinely not matching (re-check
  §3.2's printed values were pasted exactly, no trailing whitespace).
- A 500 with no `fault` key → something AuthSec-side (e.g. no issuer
  configured at all) — check server logs.

### 3.4 DB check — the WIF-specific auth_ref shape

```bash
psql "$DATABASE_URL" -c \
  "SELECT auth_ref, attrs->>'auth_method', attrs->>'wif_provider_resource', attrs->>'pool_id', attrs->>'provider_id' FROM cloud_connector WHERE scope_id='$SCOPE_ID2';"
```
**Expect:** `auth_ref` = literally `wif:` followed by the exact
`provider_resource` string you pasted (verify byte-for-byte); `attrs`
carries `auth_method=wif`, and the full `pool_id`/`provider_id`/
`wif_provider_resource` — **no** `kv/data/secret/...` string anywhere.

### 3.5 Verify, list, get — same as §2.4/§2.5, same expectations.

### 3.6 Revoke — the WIF-specific no-Vault-call proof

```bash
curl -s -X DELETE "$AUTHSEC_URL/authsec/discovery/gcp/connectors/$(jq -r .data.id create_wif.json)" \
  -H "Authorization: Bearer $TOKEN" | jq .
```
**Expect:** 200, row kept, `status='revoked'` (same DB check as §2.7).
Since nothing was ever written to Vault for this connector, there is
nothing to independently "prove absence of" in Vault the way §2.7 proves
deletion for json_key — instead, confirm via server logs (if you have
`VAULT_ADDR` request logging on, or Vault's own audit log if enabled) that
**zero** Vault HTTP requests were made for this connector's id across
create→verify→revoke. If Vault audit logging isn't set up, this sub-check
is legitimately harder to observe live and can be marked
`UNVERIFIED — NO VAULT AUDIT LOG` rather than skipped silently; the unit
test tier already proves this structurally (`TestGcpOnboardLifecycle_WIF_NeverTouchesVault`),
so a live gap here is low-risk, not a blocker.

---

## 4. Workflow C — validation and error paths (both auth methods)

### 4.1 WIF pool/provider mismatch → `wif_pool_missing`, BEFORE any GCP call

```bash
curl -s -X POST "$AUTHSEC_URL/authsec/discovery/gcp/connectors" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"scope_kind\":\"$SCOPE_KIND\",\"scope_id\":\"$SCOPE_ID2\",\"reader_project_id\":\"$READER_PROJECT\",\"auth\":{\"method\":\"wif\",\"provider_resource\":\"projects/999999999999/locations/global/workloadIdentityPools/wrong-pool/providers/authsec-provider\",\"reader_sa_email\":\"authsec-reader@$READER_PROJECT.iam.gserviceaccount.com\"}}" \
  | jq .
```
**Expect:** HTTP 400, `"fault":"customer_account"`, error message about the
pool/provider not matching what was derived. This needs **no public issuer
at all** — it's a pure string comparison — so this specific sub-test works
even if you skipped Workflow B via §0(c).

### 4.2 Scope the reader cannot actually read → `scope_not_readable`

Pick a real project id you have **not** granted the reader SA any role on
(`$SCOPE_ID_DENIED`), then run CreateConnector (either auth method) against
it.
**Expect:** HTTP 400, `"fault":"customer_account"`, error mentioning the
scope could not be read. Then confirm **no row was created**:
```bash
curl -s "$AUTHSEC_URL/authsec/discovery/gcp/connectors" -H "Authorization: Bearer $TOKEN" \
  | jq '.data[] | select(.scope_id=="'"$SCOPE_ID_DENIED"'")'
```
**Expect:** empty output.

### 4.3 Malformed key → `key_invalid`, before any Vault write

```bash
curl -s -X POST "$AUTHSEC_URL/authsec/discovery/gcp/connectors" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"scope_kind\":\"$SCOPE_KIND\",\"scope_id\":\"$SCOPE_ID\",\"reader_project_id\":\"$READER_PROJECT\",\"auth\":{\"method\":\"json_key\",\"key_json\":\"{\\\"type\\\":\\\"service_account\\\"}\"}}" \
  | jq .
```
**Expect:** HTTP 400, `"fault":"customer_account"`, mentions the key is
malformed/missing fields. Confirm nothing landed in Vault for this attempt
(`vault kv list -mount=kv data/secret/workspaces/<workspace_id>/cloud-discovery/gcp/` —
the count of entries should be unchanged from before this call).

### 4.4 Invalid scope_kind → `invalid_scope_id`

```bash
curl -s -X POST "$AUTHSEC_URL/authsec/discovery/gcp/connectors" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"scope_kind":"account","scope_id":"x","reader_project_id":"y","auth":{"method":"json_key","key_json":"{}"}}' \
  | jq .
```
**Expect:** HTTP 400, `"fault":"customer_account"` — `"account"` is a valid
`cloud_connector.scope_kind` value at the DB-constraint level (it's AWS's),
but GCP-04's own service layer must reject it before ever touching GCP or
Vault.

---

## 5. Workflow D — Authorization

Get (or mint, via your normal flow) a second token scoped to
`discovery:read` **only** (no `discovery:admin`) in the same workspace.

```bash
export READONLY_TOKEN="<token with discovery:read only>"

curl -s -o /dev/null -w "%{http_code}\n" -X POST "$AUTHSEC_URL/authsec/discovery/gcp/connectors" \
  -H "Authorization: Bearer $READONLY_TOKEN" -H "Content-Type: application/json" -d '{}'
curl -s -o /dev/null -w "%{http_code}\n" -X DELETE "$AUTHSEC_URL/authsec/discovery/gcp/connectors/$CONNECTOR_ID" \
  -H "Authorization: Bearer $READONLY_TOKEN"
curl -s -o /dev/null -w "%{http_code}\n" "$AUTHSEC_URL/authsec/discovery/gcp/connectors" \
  -H "Authorization: Bearer $READONLY_TOKEN"
```
**Expect:** first two return **403** (`insufficient_scope`); the third
returns **200**.

---

## 6. Report template — fill this in with real evidence, not summaries

For every row: PASS (paste the actual response/output), FAIL (paste the
actual error), or UNVERIFIED (state exactly why — e.g. "no public issuer
available").

| # | Check | Result | Evidence |
|---|---|---|---|
| 0 | Public issuer reachable for WIF | | |
| 1.4 | Bearer token has discovery:read/admin | | |
| 2.1 | Onboarding package: both branches, correct role set | | |
| 2.1 | setup-reader.sh actually creates SA + grants (verified via gcloud) | | |
| 2.2 | json_key CreateConnector → 201, active, verified_at set | | |
| 2.2 | Key value absent from response body | | |
| 2.3 | auth_ref is a kv/data/secret/... path (DB) | | |
| 2.3 | attrs has no key material (DB) | | |
| 2.3 | Vault actually holds the key | | |
| 2.4 | VerifyConnector → 200, verified_at advances | | |
| 2.5 | Get/List correct, GCP-only filter | | |
| 2.6 | Reconnect → 200 not 201, same id | | |
| 2.6 | scan_generation/coverage unchanged after reconnect | | |
| 2.7 | Revoke → row kept, status=revoked, Vault secret purged | | |
| 3.1 | issuer_url in package = public URL, not localhost | | |
| 3.2 | Pool/provider created; binding is principal://, not principalSet:// | | |
| 3.3 | wif CreateConnector → 201 (real STS exchange succeeded) | | |
| 3.4 | auth_ref = "wif:"+provider_resource exactly (DB) | | |
| 3.5 | Verify/Get/List for wif connector | | |
| 3.6 | Revoke → row kept, status=revoked, no Vault call | | |
| 4.1 | Mismatched provider_resource → 400 wif_pool_missing, no row | | |
| 4.2 | Unreadable scope → 400 scope_not_readable, no row | | |
| 4.3 | Malformed key → 400 key_invalid, no Vault write | | |
| 4.4 | Bad scope_kind → 400 invalid_scope_id | | |
| 5 | discovery:read-only denied on mutations (403), allowed on reads (200) | | |

**Overall verdict:** PASS / PASS WITH GAPS / FAIL — list every gap
explicitly, and note which are genuine defects vs. environment limitations
(no public issuer, no Vault audit log, etc.) per §0 and §3.6's own honest-
UNVERIFIED guidance.
