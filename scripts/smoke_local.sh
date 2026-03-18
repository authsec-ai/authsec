#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

compose() {
  docker compose "$@"
}

wait_for() {
  local name="$1"
  local url="$2"
  local attempts="${3:-60}"

  echo "Waiting for ${name}: ${url}"
  for _ in $(seq 1 "${attempts}"); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      echo "Ready: ${name}"
      return 0
    fi
    sleep 2
  done

  echo "Timed out waiting for ${name}" >&2
  return 1
}

make_seed_jwt() {
  python3 - <<'PY'
import base64
import hashlib
import hmac
import json
import time

secret = "authsecai"
tenant_id = "11111111-1111-1111-1111-111111111111"
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "local-smoke",
    "tenant_id": tenant_id,
    "email": "admin@test.com",
    "roles": ["admin"],
    "permissions": ["admin:access"],
    "iss": "authsec-ai/auth-manager",
    "iat": int(time.time()),
    "nbf": int(time.time()),
    "exp": int(time.time()) + 3600,
}

def enc(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()

msg = f"{enc(header)}.{enc(payload)}"
sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
print(f"{msg}.{sig}")
PY
}

wait_for_seed_tenant() {
  local token="$1"
  local attempts="${2:-90}"
  local status_url="http://localhost:7468/authsec/migration/tenants/11111111-1111-1111-1111-111111111111/migrations/status"

  echo "Waiting for seeded tenant DB migrations"
  for _ in $(seq 1 "${attempts}"); do
    local response
    response="$(curl -fsS -H "Authorization: Bearer ${token}" "${status_url}" 2>/dev/null || true)"
    if [[ -n "${response}" ]] && python3 -c 'import json,sys; print(json.load(sys.stdin).get("migration_status",""))' <<<"${response}" | grep -qx "completed"; then
      echo "Ready: Seeded tenant DB"
      return 0
    fi
    sleep 2
  done

  echo "Timed out waiting for seeded tenant DB migrations" >&2
  return 1
}

check_status() {
  local name="$1"
  local url="$2"
  local expected="$3"
  local status

  status="$(curl -s -o /dev/null -w "%{http_code}" "${url}")"
  if [[ "${status}" != "${expected}" ]]; then
    echo "Unexpected status for ${name}: got ${status}, want ${expected}" >&2
    return 1
  fi
  echo "OK ${name}: ${status}"
}

echo "Building and starting local stack..."
compose up -d --build

wait_for "AuthSec" "http://localhost:7468/authsec/uflow/health"
wait_for "Hydra" "http://localhost:4444/health/ready"
wait_for "Vault" "http://localhost:8200/v1/sys/health?standbyok=true"
wait_for "ICP Mock" "http://localhost:7001/health"
SEED_JWT="$(make_seed_jwt)"
wait_for_seed_tenant "${SEED_JWT}"

check_status "OIDC Discovery" "http://localhost:7468/.well-known/openid-configuration" "200"
check_status "JWKS" "http://localhost:7468/.well-known/jwks.json" "200"
check_status "Metrics" "http://localhost:7468/metrics" "200"
check_status "UFlow Health" "http://localhost:7468/authsec/uflow/health" "200"
check_status "WebAuthn Health" "http://localhost:7468/authsec/webauthn/health" "200"
check_status "ClientMS Health" "http://localhost:7468/authsec/clientms/health" "200"
check_status "HydraMgr Health" "http://localhost:7468/authsec/hmgr/health" "200"
check_status "OOCMgr Health" "http://localhost:7468/authsec/oocmgr/health" "200"
check_status "AuthMgr Health" "http://localhost:7468/authsec/authmgr/health" "200"
check_status "ExSvc Health" "http://localhost:7468/authsec/exsvc/health" "200"
check_status "SPIRE Health" "http://localhost:7468/authsec/spire/health" "200"
check_status "SDKMgr MCP Auth Health" "http://localhost:7468/authsec/sdkmgr/mcp-auth/health" "200"
check_status "SDKMgr Playground Health" "http://localhost:7468/authsec/sdkmgr/playground/health" "200"
check_status "UFlow Docs" "http://localhost:7468/authsec/uflow/docs" "200"
check_status "ClientMS Swagger" "http://localhost:7468/authsec/clientms/swagger" "200"
check_status "Migration Auth Gate" "http://localhost:7468/authsec/migration/tenants" "401"

echo
echo "Local stack smoke test passed."
echo "OTP and email payloads can be inspected with:"
echo "  docker compose logs authsec | grep 'LOCAL EMAIL'"
