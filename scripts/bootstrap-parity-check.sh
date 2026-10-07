#!/usr/bin/env bash
# Bootstrap parity check (SPEC-iga-phase3-policy.md §6.1, T3.00).
#
# The rule (AGENTS.md, schema contract): every schema change brings
# migrations/master/001_bootstrap.sql to the same end state as the numbered
# chain. On a fresh database the runner applies 001 and then EVERY later file,
# so parity means two things: 001 alone produces the final schema, and the
# later files, run over it, change nothing. This script proves both.
#
# It builds scratch databases with the REAL runner -- scripts/bootstrap-parity
# calls internal/migration exactly as cmd/main.go does: GORM creates
# migration_logs, then one transaction per file, statements split by the
# runner's own splitter, each file recorded in migration_logs -- and compares:
#
#   a   the numbered chain: 001 as of BASE_REF, then the working tree's 002..N
#   b   the working tree's 001 alone
#   c   the working tree's 001..N in one runner pass (what a fresh install does)
#   c2  c, then 002..N applied a SECOND time (every later file is re-runnable)
#   a0  only when ORIG_REF is set: 001 as of BASE_REF, then 002..N as of
#       ORIG_REF. Proves that guards added to existing migrations do not change
#       what they do on the numbered path: raw pg_dump of a and a0 must be
#       byte-identical (only pg_dump's random \restrict key is removed).
#
# a, b, c and c2 must have identical normalised schema dumps and identical
# seeded rows. Exit status is non-zero on any difference; the diff is printed.
#
# Schema normalisation (pg_dump --schema-only --no-owner; privileges and
# COMMENTs are kept and compared):
#   - drop pg_dump's banner, per-object "-- Name: ...; Type: ..." headers, the
#     bare "--" lines around them, \restrict/\unrestrict, SET and set_config
#     lines, and blank lines;
#   - treat each remaining pg_dump object as one record and sort the records,
#     which removes emission-order noise and nothing else. Record text is
#     compared exactly: column order, types, defaults, generated columns,
#     CHECK/UNIQUE/FK definitions (including ON DELETE actions and
#     DEFERRABLE), index definitions (partial and expression), triggers,
#     function bodies, comments and grants.
#
# Data comparison: every row of every public table except migration_logs,
# as jsonb. Columns whose DEFAULT is volatile (gen_random_uuid(),
# uuid_generate_v*, now(), CURRENT_TIMESTAMP, clock_timestamp(), nextval())
# differ between any two runs of the same file, so timestamps of that kind are
# dropped and uuids of that kind are masked -- except fixed well-known ids
# (00000000-0000-0000-0000-...), which are compared.
#
# migrations/contract/ is NOT applied: the runner reads migrations/master only
# (plus migrations/permissions/master, which this script refuses to guess
# about). A contract file joins the check when it moves into migrations/master.
#
# Files are staged with CR line endings stripped, matching the LF blobs git
# stores and the Linux image the runner ships in: a Windows checkout with
# core.autocrlf would otherwise store \r inside every function body.
#
# Usage (from anywhere inside the repo):
#
#   PGHOST=localhost PGPORT=55433 PGUSER=authsec PGPASSWORD=... \
#     scripts/bootstrap-parity-check.sh
#
# Env:
#   BASE_REF   git ref whose 001 starts the numbered chain. Default 1f7c3cc:
#              the last 001 before T3.00, i.e. the bootstrap the oldest
#              chain-built databases started from. Any later 001 is a superset.
#   ORIG_REF   optional; git ref holding the 002..N to compare a against (a0).
#              Set it to the commit before your edits to existing migrations.
#   DB_PREFIX  scratch database name prefix (default p3b_parity). Databases are
#              dropped and recreated, and dropped again at exit unless KEEP_DBS=1.
#              NEVER point this at a database you care about.
#   OUT_DIR    where staged files, dumps and diffs are kept (default: mktemp -d)
#   PSQL, PG_DUMP  client binaries, PostgreSQL 16+ (default: from PATH)
#   PGSSLMODE  passed through to the runner DSN (default disable)
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

: "${PGHOST:=localhost}" "${PGPORT:=5432}" "${PGUSER:=postgres}" "${PGPASSWORD:=}"
export PGHOST PGPORT PGUSER PGPASSWORD
BASE_REF="${BASE_REF:-1f7c3cc}"
ORIG_REF="${ORIG_REF:-}"
DB_PREFIX="${DB_PREFIX:-p3b_parity}"
PSQL="${PSQL:-psql}"
PG_DUMP="${PG_DUMP:-pg_dump}"
OUT_DIR="${OUT_DIR:-$(mktemp -d)}"
SSLMODE="${PGSSLMODE:-disable}"
mkdir -p "$OUT_DIR"

if [ -d migrations/permissions/master ]; then
  echo "migrations/permissions/master exists; the runner loads it too. Teach this script how before trusting it." >&2
  exit 2
fi

DBS=(a b c)
[ -n "$ORIG_REF" ] && DBS+=(a0)

psql_admin() { "$PSQL" -X -q -v ON_ERROR_STOP=1 -d postgres "$@"; }
cleanup() {
  if [ "${KEEP_DBS:-0}" != "1" ]; then
    for d in "${DBS[@]}"; do psql_admin -c "DROP DATABASE IF EXISTS ${DB_PREFIX}_$d" >/dev/null 2>&1 || true; done
  fi
}
trap cleanup EXIT

echo "== staging (out: $OUT_DIR)"
lf() { sed 's/\r$//'; }
stage_worktree() { # $1 dest, then file globs relative to migrations/master
  local dest="$1"; shift; mkdir -p "$dest"
  for f in "$@"; do lf < "migrations/master/$f" > "$dest/$f"; done
}
stage_ref() { # $1 ref, $2 dest, then file names
  local ref="$1" dest="$2"; shift 2; mkdir -p "$dest"
  for f in "$@"; do git show "$ref:migrations/master/$f" | lf > "$dest/$f"; done
}
ALL=( $(cd migrations/master && ls -1 [0-9]*.sql | sort) )
LATER=( "${ALL[@]:1}" )
[ "${ALL[0]}" = "001_bootstrap.sql" ] || { echo "first migration is not 001_bootstrap.sql" >&2; exit 2; }
echo "chain: ${ALL[0]} .. ${ALL[${#ALL[@]}-1]} (${#ALL[@]} files); BASE_REF=$BASE_REF ORIG_REF=${ORIG_REF:-<unset>}"

rm -rf "$OUT_DIR/stage"; S="$OUT_DIR/stage"
stage_ref "$BASE_REF" "$S/a/master" 001_bootstrap.sql
stage_worktree "$S/a/master" "${LATER[@]}"
stage_worktree "$S/b/master" 001_bootstrap.sql
stage_worktree "$S/c/master" "${ALL[@]}"
stage_worktree "$S/later/master" "${LATER[@]}"
if [ -n "$ORIG_REF" ]; then
  ORIG_LATER=( $(git ls-tree --name-only "$ORIG_REF" migrations/master/ | sed 's#.*/##' | grep -E '^[0-9]+_.*\.sql$' | grep -v '^001_' | sort) )
  stage_ref "$BASE_REF" "$S/a0/master" 001_bootstrap.sql
  stage_ref "$ORIG_REF" "$S/a0/master" "${ORIG_LATER[@]}"
fi

echo "== building the runner wrapper"
APPLY="$OUT_DIR/bootstrap-parity$(go env GOEXE)"
go build -o "$APPLY" ./scripts/bootstrap-parity

dsn() { echo "host=$PGHOST port=$PGPORT user=$PGUSER password=$PGPASSWORD dbname=${DB_PREFIX}_$1 sslmode=$SSLMODE"; }
apply() { # $1 db, $2 staged dir, [$3 -rerun]
  if ! "$APPLY" ${3:-} -dsn "$(dsn "$1")" -dir "$2" > "$OUT_DIR/apply_$1${3:+_rerun}.log" 2>&1; then
    echo "FAIL: applying $2 to ${DB_PREFIX}_$1:" >&2
    grep -E 'PANIC|FAILED|run:|failed' "$OUT_DIR/apply_$1${3:+_rerun}.log" | tail -20 >&2
    exit 1
  fi
}

for d in "${DBS[@]}"; do
  psql_admin -c "DROP DATABASE IF EXISTS ${DB_PREFIX}_$d" -c "CREATE DATABASE ${DB_PREFIX}_$d" 2>/dev/null
done
echo "== a:  numbered chain";            apply a  "$S/a/master"
echo "== b:  001 alone";                 apply b  "$S/b/master"
echo "== c:  001..N, one runner pass";   apply c  "$S/c/master"
if [ -n "$ORIG_REF" ]; then echo "== a0: numbered chain, original files"; apply a0 "$S/a0/master"; fi

NORM_AWK='
function flush() { if (buf != "") print buf; buf = "" }
/^-- (Name|Data for Name): /                             { flush(); next }
/^--$/                                                    { next }
/^-- (PostgreSQL database dump|Dumped from|Dumped by)/  { next }
/^\\(restrict|unrestrict) /                               { next }
/^SET [a-z_]+ = /                                         { next }
/^SELECT pg_catalog\.set_config\(/                       { next }
/^[[:space:]]*$/                                          { next }
{ buf = (buf == "" ? $0 : buf "\001" $0) }
END { flush() }'

DATA_SQL=$(cat <<'SQL'
SELECT format(
  'SELECT %L || E''\t'' || ((to_jsonb(t) - %L::text[])%s)::text FROM public.%I t',
  c.relname,
  COALESCE(array_agg(a.attname ORDER BY a.attnum) FILTER (WHERE a.atttypid <> 'uuid'::regtype), '{}'),
  COALESCE(string_agg(format(
      ' || jsonb_build_object(%L, CASE WHEN t.%I IS NULL THEN NULL WHEN t.%I::text LIKE ''00000000-0000-0000-0000-%%'' THEN t.%I::text ELSE ''<volatile>'' END)',
      a.attname, a.attname, a.attname, a.attname), '' ORDER BY a.attnum) FILTER (WHERE a.atttypid = 'uuid'::regtype), ''),
  c.relname)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
 AND EXISTS (SELECT 1 FROM pg_attrdef d
              WHERE d.adrelid = a.attrelid AND d.adnum = a.attnum
                AND pg_get_expr(d.adbin, d.adrelid) ~* '(gen_random_uuid|uuid_generate_v|now\(\)|current_timestamp|clock_timestamp|statement_timestamp|transaction_timestamp|nextval\()')
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname <> 'migration_logs'
GROUP BY c.relname
ORDER BY c.relname
\gexec
SQL
)

snapshot() { # $1 label, $2 db suffix
  local f="$OUT_DIR/$1"
  "$PG_DUMP" --schema-only --no-owner -d "${DB_PREFIX}_$2" | tr -d '\r' > "$f.dump.sql"
  awk "$NORM_AWK" "$f.dump.sql" | LC_ALL=C sort > "$f.records"
  tr '\001' '\n' < "$f.records" > "$f.schema.sql"
  printf '%s\n' "$DATA_SQL" | "$PSQL" -X -q -At -v ON_ERROR_STOP=1 -d "${DB_PREFIX}_$2" | tr -d '\r' | LC_ALL=C sort > "$f.data"
}
snapshot a a; snapshot b b; snapshot c c
[ -n "$ORIG_REF" ] && snapshot a0 a0

echo "== c2: 002..N applied a second time over c"
apply c "$S/later/master" -rerun
snapshot c2 c

fail=0
compare() { # $1 $2 labels
  if cmp -s "$OUT_DIR/$1.records" "$OUT_DIR/$2.records"; then
    echo "ok:   schema $1 == $2 ($(wc -l < "$OUT_DIR/$1.records" | tr -d ' ') objects)"
  else
    fail=1; echo "FAIL: schema $1 != $2 (records only in $1: '<', only in $2: '>'):"
    LC_ALL=C comm -3 "$OUT_DIR/$1.records" "$OUT_DIR/$2.records" \
      | sed -e 's/^\t/> /' -e '/^> /!s/^/< /' | tr '\001' '\n' | head -200
  fi
  if cmp -s "$OUT_DIR/$1.data" "$OUT_DIR/$2.data"; then
    echo "ok:   data   $1 == $2 ($(wc -l < "$OUT_DIR/$1.data" | tr -d ' ') rows)"
  else
    fail=1; echo "FAIL: data $1 != $2:"; diff "$OUT_DIR/$1.data" "$OUT_DIR/$2.data" | head -100
  fi
}
echo "== comparing"
compare a b
compare b c
compare c c2
if [ -n "$ORIG_REF" ]; then
  compare a0 a
  if cmp -s "$OUT_DIR/a0.dump.sql" "$OUT_DIR/a.dump.sql" \
     || diff <(grep -v '^\\\(un\)\?restrict ' "$OUT_DIR/a0.dump.sql") \
             <(grep -v '^\\\(un\)\?restrict ' "$OUT_DIR/a.dump.sql") > "$OUT_DIR/a0_a.rawdiff"; then
    echo "ok:   raw pg_dump a0 == a, byte for byte (excluding the \\restrict key)"
  else
    fail=1; echo "FAIL: raw pg_dump a0 != a:"; head -100 "$OUT_DIR/a0_a.rawdiff"
  fi
fi

echo
if [ "$fail" -ne 0 ]; then echo "Bootstrap parity FAILED (artifacts in $OUT_DIR)."; exit 1; fi
echo "Bootstrap parity passed (artifacts in $OUT_DIR)."
