#!/usr/bin/env bash
# verify_phase_a.sh — End-to-end smoke test for Phase A (membership + end-users + groups).
#
# Usage:
#   AUTHSEC_BASE_URL=http://localhost:7468 \
#   AUTHSEC_ADMIN_TOKEN=<jwt> \
#   AUTHSEC_TENANT_ID=<tenant uuid> \
#   AUTHSEC_USER_ID=<existing user uuid in tenant> \
#   ./scripts/verify_phase_a.sh
#
# Exits non-zero on the first failure. Prints per-step results.
set -euo pipefail

: "${AUTHSEC_BASE_URL:?AUTHSEC_BASE_URL required}"
: "${AUTHSEC_ADMIN_TOKEN:?AUTHSEC_ADMIN_TOKEN required}"
: "${AUTHSEC_TENANT_ID:?AUTHSEC_TENANT_ID required}"
: "${AUTHSEC_USER_ID:?AUTHSEC_USER_ID required}"

BASE="$AUTHSEC_BASE_URL/authsec/uflow/v2"
H="Authorization: Bearer $AUTHSEC_ADMIN_TOKEN"
ok()  { printf '\033[32m  ✓ %s\033[0m\n' "$*"; }
fail(){ printf '\033[31m  ✗ %s\033[0m\n' "$*"; exit 1; }
hdr() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

# ── 1. Membership backfill ─────────────────────────────────────
hdr "1. Existing user has a tenant_membership (created by migration 112)"
resp=$(curl -fsS -H "$H" "$BASE/tenants/$AUTHSEC_TENANT_ID/memberships/$AUTHSEC_USER_ID")
echo "$resp" | grep -q '"status":"active"' && ok "membership active" || fail "expected status=active, got: $resp"
echo "$resp" | grep -q '"source":"migration"' && ok "source=migration" || fail "expected source=migration, got: $resp"

# ── 2. Operator suspension ─────────────────────────────────────
hdr "2. Suspend the member"
curl -fsS -X PATCH -H "$H" -H "Content-Type: application/json" \
  -d '{"status":"suspended"}' \
  "$BASE/tenants/$AUTHSEC_TENANT_ID/memberships/$AUTHSEC_USER_ID" \
  | grep -q '"status":"suspended"' && ok "PATCH suspended" || fail "PATCH did not return suspended"

resp=$(curl -fsS -H "$H" "$BASE/tenants/$AUTHSEC_TENANT_ID/memberships/$AUTHSEC_USER_ID")
echo "$resp" | grep -q '"suspended_at"' && ok "suspended_at stamped" || fail "no suspended_at: $resp"

# Reactivate so subsequent tests don't break the user's other tooling
curl -fsS -X PATCH -H "$H" -H "Content-Type: application/json" \
  -d '{"status":"active"}' \
  "$BASE/tenants/$AUTHSEC_TENANT_ID/memberships/$AUTHSEC_USER_ID" >/dev/null
ok "reactivated"

# ── 3. End-user upsert ─────────────────────────────────────────
hdr "3. End-user state — set plan tier (upserts if missing)"
curl -fsS -X PATCH -H "$H" -H "Content-Type: application/json" \
  -d '{"plan_tier":"free"}' \
  "$BASE/tenants/$AUTHSEC_TENANT_ID/end-users/$AUTHSEC_USER_ID" \
  | grep -q '"plan_tier":"free"' && ok "plan_tier=free" || fail "PATCH plan failed"

# ── 4. End-user suspension via convenience endpoint ────────────
hdr "4. Suspend / reactivate end user"
curl -fsS -X POST -H "$H" -H "Content-Type: application/json" \
  -d '{"reason":"phase-a verify script"}' \
  "$BASE/tenants/$AUTHSEC_TENANT_ID/end-users/$AUTHSEC_USER_ID/suspend" \
  | grep -q '"status":"suspended"' && ok "POST suspend → suspended" || fail "suspend endpoint failed"

curl -fsS -X POST -H "$H" \
  "$BASE/tenants/$AUTHSEC_TENANT_ID/end-users/$AUTHSEC_USER_ID/reactivate" \
  | grep -q '"status":"active"' && ok "POST reactivate → active" || fail "reactivate failed"

# ── 5. End-user list & filter ──────────────────────────────────
hdr "5. List end users (no filter)"
count=$(curl -fsS -H "$H" "$BASE/tenants/$AUTHSEC_TENANT_ID/end-users" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["count"])')
[ "$count" -ge 1 ] && ok "list returned $count end user(s)" || fail "expected ≥1 end user"

# ── 6. Effective access ────────────────────────────────────────
hdr "6. Effective access explorer"
curl -fsS -H "$H" "$BASE/users/$AUTHSEC_USER_ID/effective-access" \
  | grep -q '"items"' && ok "effective-access returned items array" || fail "no items"

# ── 7. Members list with filter ────────────────────────────────
hdr "7. List members (status=active filter)"
curl -fsS -H "$H" "$BASE/tenants/$AUTHSEC_TENANT_ID/memberships?status=active" \
  | grep -q '"items"' && ok "filtered list returned items" || fail "no items"

printf '\n\033[32mAll Phase A endpoints OK.\033[0m\n'
