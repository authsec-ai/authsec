# Connectors — deployment infra handoff

The connector backend (control plane + broker + OAuth connect + identity/audit +
per-workspace provider apps) is code-complete on `authsec-staging`. The
**connect-once flow is proven live** (GitHub connector → OAuth consent → token in
Vault → active connection → broker token minted with `connector:execute`).

Two host-side items must be in place for the **agent action-execute** path and
new features to work at runtime. Neither is a code change.

## 1. Edge proxy: forward `/broker/*` to the Go backend  ← BLOCKS agent execute

`app.authsec.ai` currently returns an **Express 404** for `/broker/*`
(`Cannot POST /broker/connectors/.../actions/...`, header `X-Powered-By: Express`).
The broker data plane lives in the **Go backend on :7468**, but the edge doesn't
route `/broker/*` there — so agent action calls never reach it.

**Fix:** add a proxy rule so `/broker/*` forwards to the backend, exactly like
`/authsec/*` already does. In the Caddy/edge config, wherever `/authsec/*` →
`backend:7468` is defined, add `/broker/*` → `backend:7468`.

**Verify:**
```bash
# inside the backend container — should be a real status (401/403/200), not Express HTML:
docker exec authsec-backend curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://localhost:7468/broker/connectors/x/actions/y -d '{}'
# through the edge — should stop returning "Cannot POST" Express HTML:
curl -s -i https://app.authsec.ai/broker/connectors/x/actions/y -X POST -d '{}'
```

## 2. Vault: enable a KV v2 engine at `kv/`  ← BLOCKS token storage

The backend writes secrets to `kv/data/secret/...` (KV **v2**). Logs showed
`no handler for route "kv/data/secret/..."` — Vault has no engine mounted at
`kv/`, so connector tokens (and native signing keys) fail to store.

**Fix:**
```bash
docker exec authsec-single-node-vault-1 vault secrets list          # check for kv/ (v2)
docker exec authsec-single-node-vault-1 vault secrets enable -path=kv -version=2 kv
```
(If Vault dev-mode resets on restart, this must be re-run or scripted into startup.)

## 3. Schema: advance the deployed DB (no wipe needed)

New tables ship in `001_bootstrap.sql`; on a live DB apply the deltas instead:
```bash
psql "$DATABASE_URL" -f migrations/deltas/connector_p2_p3_forward.sql        # catalog + core tables
psql "$DATABASE_URL" -f migrations/deltas/connector_identity_credstore.sql   # audit + provider-apps
```

## 4. Deploy hygiene (the recurring gotcha)

Every deploy that changes `001_bootstrap.sql` **must** rebuild the backend image
from current `authsec-staging` AND advance the DB. Most of the connector
debugging was code/DB drift: the container ran an older binary while the DB was
at a newer (or older) schema. After deploy, sanity-check:
```bash
docker exec authsec-backend strings ./main | grep -c "is not OAuth2"  # >=1 = current code
```

Once (1) and (2) are done and the DB is advanced, the full flow runs end to end:
connect a provider → grant an agent → agent calls `/broker/.../actions/...:execute`
→ AuthSec injects the credential, calls the SaaS, returns a redacted result with
an `identity` block, and writes a `connector_action_audit` row.
