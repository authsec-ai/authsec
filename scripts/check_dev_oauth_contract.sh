#!/usr/bin/env bash

set -euo pipefail

API_BASE_URL="${1:-https://dev.api.authsec.dev}"
APP_BASE_URL="${2:-https://dev.authsec.dev}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

expect_json() {
  local url="$1"
  local tmp_body
  local tmp_headers
  tmp_body="$(mktemp)"
  tmp_headers="$(mktemp)"

  curl -sS -o "$tmp_body" -D "$tmp_headers" "$url" >/dev/null
  grep -qi '^content-type: application/json' "$tmp_headers" || fail "$url did not return JSON"
  grep -q '<!doctype html>' "$tmp_body" && fail "$url returned SPA HTML"
  echo "OK  $url"
}

expect_json_field_prefix() {
  local url="$1"
  local field="$2"
  local prefix="$3"
  local tmp_body
  tmp_body="$(mktemp)"
  curl -ksS -o "$tmp_body" "$url" >/dev/null
  python3 - "$tmp_body" "$url" "$field" "$prefix" <<'PY'
import json, pathlib, sys
body_path, url, field, prefix = sys.argv[1:]
payload = json.loads(pathlib.Path(body_path).read_text())
value = payload.get(field, "")
if not isinstance(value, str) or not value.startswith(prefix):
    raise SystemExit(f"FAIL: {url} field {field!r} expected prefix {prefix!r}, got {value!r}")
print(f"OK  {url} field {field} -> {value}")
PY
}

expect_post_json() {
  local url="$1"
  local data="$2"
  local tmp_body
  local tmp_headers
  tmp_body="$(mktemp)"
  tmp_headers="$(mktemp)"

  curl -sS -o "$tmp_body" -D "$tmp_headers" -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data "$data" \
    "$url" >/dev/null
  grep -qi '^content-type: application/json' "$tmp_headers" || fail "$url did not return JSON"
  grep -q '<!doctype html>' "$tmp_body" && fail "$url returned SPA HTML"
  echo "OK  $url"
}

expect_not_found() {
  local url="$1"
  local status
  status="$(curl -sS -o /tmp/authsec_contract_$$.body -w '%{http_code}' "$url")"
  case "$status" in
    404|410) echo "OK  $url -> $status" ;;
    *) fail "$url expected 404/410 but got $status" ;;
  esac
}

expect_json "$API_BASE_URL/.well-known/oauth-authorization-server"
expect_json "$API_BASE_URL/.well-known/openid-configuration"
expect_json "$API_BASE_URL/oauth/jwks"
expect_post_json "$API_BASE_URL/oauth/introspect" 'token=bogus'
expect_not_found "$API_BASE_URL/authmgr/oauth/introspect"
expect_json_field_prefix "$API_BASE_URL/.well-known/oauth-authorization-server" "authorization_endpoint" "$API_BASE_URL/oauth/"
expect_json_field_prefix "$API_BASE_URL/.well-known/oauth-authorization-server" "token_endpoint" "$API_BASE_URL/oauth/"
expect_json_field_prefix "$API_BASE_URL/.well-known/openid-configuration" "issuer" "$API_BASE_URL"

app_oidc_status="$(curl -sS -o /tmp/authsec_app_oidc_$$.body -w '%{http_code}' "$APP_BASE_URL/.well-known/openid-configuration")"
if grep -q '<!doctype html>' /tmp/authsec_app_oidc_$$.body; then
  fail "$APP_BASE_URL/.well-known/openid-configuration returned SPA HTML"
fi
echo "OK  $APP_BASE_URL/.well-known/openid-configuration -> $app_oidc_status"
