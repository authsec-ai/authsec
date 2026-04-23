#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_in_readme() {
  local needle="$1"
  grep -q "$needle" "$ROOT/README.md" || {
    echo "FAIL: README missing $needle" >&2
    exit 1
  }
}

reject_in_readme() {
  local needle="$1"
  if grep -q "$needle" "$ROOT/README.md"; then
    echo "FAIL: README still contains $needle" >&2
    exit 1
  fi
}

require_in_readme '/.well-known/oauth-authorization-server'
require_in_readme '/oauth/introspect'
require_in_readme '/authsec/resource-servers'
require_in_readme '/authsec/authz'
require_in_readme '/authsec/auth/token'

reject_in_readme '/authsec/authmgr'

if rg -n '@Router /uflow|@Router /auth/' "$ROOT/controllers" >/tmp/authsec_doc_contract.$$; then
  echo "FAIL: stale Swagger routes remain:" >&2
  cat /tmp/authsec_doc_contract.$$ >&2
  exit 1
fi

echo "OK  README and Swagger route prefixes match the public contract"
