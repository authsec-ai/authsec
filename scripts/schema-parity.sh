#!/usr/bin/env bash
# Schema parity check (AS-080): a fresh bootstrap and an upgraded copy of an
# existing database must end with the same schema.
#
#   1. parity_fresh:    an empty database the backend bootstraps
#                       (001_bootstrap.sql, then every numbered migration).
#   2. parity_upgraded: a pg_dump copy of SOURCE_DB that the backend upgrades.
#   3. pg_dump --schema-only of both, normalised (column order inside a table,
#      dump noise), then diffed. Any difference fails.
#
# usage: scripts/schema-parity.sh <backend-binary> [SOURCE_DB]
#
# Connection: PGHOST PGPORT PGUSER PGPASSWORD (default 127.0.0.1:55432
# postgres/postgres). SOURCE_DB (default authsec) is only read. The two parity
# databases are dropped and recreated on every run. Never point this at a
# production server.
set -euo pipefail

bin="${1:?usage: $0 <backend-binary> [SOURCE_DB]}"
src="${2:-authsec}"
export PGHOST="${PGHOST:-127.0.0.1}" PGPORT="${PGPORT:-55432}" PGUSER="${PGUSER:-postgres}" PGPASSWORD="${PGPASSWORD:-postgres}"
out="${PARITY_OUT:-$(mktemp -d)}"
mkdir -p "$out"
fresh=parity_fresh
upgraded=parity_upgraded

psql_admin() { psql -X -q -v ON_ERROR_STOP=1 -c "SET client_min_messages = warning" -d postgres "$@"; }

for db in "$fresh" "$upgraded"; do
  psql_admin -c "DROP DATABASE IF EXISTS $db WITH (FORCE)"
  psql_admin -c "CREATE DATABASE $db"
done
pg_dump -d "$src" --no-owner --no-privileges | grep -v -e '^\\\(un\)\?restrict ' -e '^SET transaction_timeout' \
  | psql -X -q -v ON_ERROR_STOP=1 -d "$upgraded" >"$out/restore.log" 2>&1

boot() { # db port
  local db=$1 port=$2 log="$out/boot-$1.log"
  env DB_NAME="$db" PORT="$port" ENVIRONMENT=development \
    DB_HOST="$PGHOST" DB_PORT="$PGPORT" DB_USER="$PGUSER" DB_PASSWORD="$PGPASSWORD" DB_SSL_MODE=disable \
    JWT_SECRET="$(openssl rand -hex 32)" JWT_DEF_SECRET="$(openssl rand -hex 32)" JWT_SDK_SECRET="$(openssl rand -hex 32)" \
    WEBAUTHN_RP_NAME=x WEBAUTHN_RP_ID=localhost WEBAUTHN_ORIGIN=http://localhost \
    VAULT_ADDR= VAULT_TOKEN= AUTHSEC_DISABLE_HYDRA_RECONCILER=true \
    timeout 40 "$bin" >"$log" 2>&1 || true
  if ! grep -q 'master done: [0-9]* applied, 0 failed' "$log"; then
    echo "FAIL: migrations on $db did not finish cleanly (see $log):" >&2
    grep -E 'FAILED|master done' "$log" >&2 || tail -20 "$log" >&2
    exit 1
  fi
  grep -E 'master done' "$log"
}
boot "$fresh" 17491
boot "$upgraded" 17492

# Normalise a schema dump: drop dump noise, sort the column/constraint lines
# inside each CREATE TABLE (a column added by ALTER sits last in an upgraded
# table but in place in a fresh one), strip trailing commas. CHECK lines lose
# casts and parentheses: PostgreSQL prints an IN-list CHECK created by an
# older server as ANY ((ARRAY[...])::text[]) and a new one as
# ANY (ARRAY[(...)::text, ...]), with the same meaning.
normalise() {
  pg_dump -d "$1" --schema-only --no-owner --no-privileges \
    | grep -v -e '^--' -e '^\\\(un\)\?restrict ' -e '^SET ' -e '^SELECT pg_catalog.set_config' -e '^$' \
    | awk '
        /^CREATE TABLE / { intable = 1; print; n = 0; next }
        intable && /^\);/ { asort(cols); for (i = 1; i <= n; i++) print cols[i]; print; intable = 0; delete cols; next }
        intable { line = $0; sub(/,$/, "", line); cols[++n] = line; next }
        { print }' \
    | sed -E '/CHECK \(/{s/::(character varying|text)(\[\])?//g; s/[()]//g}'
}
normalise "$fresh" >"$out/fresh.sql"
normalise "$upgraded" >"$out/upgraded.sql"

if diff -u "$out/fresh.sql" "$out/upgraded.sql" >"$out/schema.diff"; then
  echo "schema parity: fresh bootstrap == upgraded $src ($(wc -l <"$out/fresh.sql") lines)"
else
  echo "schema parity FAILED: $(grep -c '^[-+][^-+]' "$out/schema.diff") differing lines; see $out/schema.diff" >&2
  exit 1
fi
