#!/usr/bin/env bash
# Is the code I pushed the code that is running?
#
# Until the version endpoint existed this had no answer. Deployments reference a
# floating `:production` tag, so the tag identifies no commit, and because the
# tag does not change between builds Kubernetes sees no diff and will not roll.
# Both failure modes are silent -- you build, push, and keep serving the old
# binary with nothing on screen to say so.
#
# Works for BOTH services. They serve the same JSON shape on purpose -- a shape
# that differed between them is a shape somebody reads wrong at 2am.
#
# Usage:
#   scripts/check-deployed-version.sh                      # backend, vs HEAD
#   scripts/check-deployed-version.sh <sha>                # backend, vs a commit
#   SERVICE=ui scripts/check-deployed-version.sh <sha>     # the console
#   API=https://other.host scripts/check-deployed-version.sh
#
# Exit codes are meant for CI as much as for a person:
#   0  deployed commit matches
#   1  deployed commit does NOT match  -- the deploy did not land
#   2  could not tell                  -- endpoint missing, unreachable, or the
#                                         binary was built without build args
set -uo pipefail

# SERVICE picks which of the two to ask, and only the host and path differ.
SERVICE="${SERVICE:-backend}"
case "$SERVICE" in
  backend) DEFAULT_API="https://prod.api.authsec.ai"; VERSION_PATH="/authsec/uflow/version"; HEALTH_PATH="/authsec/uflow/health" ;;
  ui)      DEFAULT_API="https://app.authsec.ai";      VERSION_PATH="/version";               HEALTH_PATH="/health" ;;
  *) echo "SERVICE must be 'backend' or 'ui', got '$SERVICE'" >&2; exit 2 ;;
esac

API="${API:-$DEFAULT_API}"
WANT="${1:-}"

if [ -z "$WANT" ]; then
  WANT="$(git rev-parse HEAD 2>/dev/null || true)"
fi
if [ -z "$WANT" ]; then
  echo "cannot determine the commit to compare against: pass one, or run inside a git repo" >&2
  exit 2
fi

URL="$API$VERSION_PATH"
BODY="$(curl -fsS --max-time 15 "$URL" 2>/dev/null || true)"

if [ -z "$BODY" ]; then
  cat >&2 <<MSG
UNKNOWN: $URL returned nothing.

Either the endpoint is not deployed yet -- which is itself the answer, since it
ships with the code you are checking for -- or the host is unreachable. Probe a
route you know exists to tell those apart:

  curl -o /dev/null -w '%{http_code}\\n' $API$HEALTH_PATH
MSG
  exit 2
fi

field() { printf '%s' "$BODY" | python3 -c "
import json,sys
try: print(json.load(sys.stdin).get('$1',''))
except Exception: print('')
"; }

GOT="$(field commit)"
INJECTED="$(field injected)"
BUILT="$(field built_at)"
BRANCH="$(field branch)"
UPTIME="$(field uptime_seconds)"

if [ "$INJECTED" != "True" ] && [ "$INJECTED" != "true" ]; then
  cat >&2 <<MSG
UNKNOWN: the running binary was built without build arguments.

It reports commit "$GOT". A binary built by a bare 'docker build' or 'go build'
says unknown, and unknown is NOT a mismatch with everything -- it means nobody
can say what is running. Build with the CI workflow, or pass:

  --build-arg GIT_COMMIT=\$(git rev-parse HEAD)
MSG
  exit 2
fi

echo "service $SERVICE ($API)"
echo "want   $WANT"
echo "got    $GOT"
echo "branch $BRANCH"
echo "built  $BUILT"
echo "uptime ${UPTIME}s"
echo

if [ "$GOT" = "$WANT" ]; then
  echo "MATCH: the deployed binary is the commit you asked about."
  exit 0
fi

cat <<MSG
MISMATCH: the deployed binary is NOT that commit.

A push does not deploy anything here: the workflows build, test and mirror, and
nothing in the cluster watches a registry. If you expected this to be live,
the image was not built, not pushed, or not rolled.

Note a rollout that reuses the same tag does nothing -- Kubernetes sees no diff.
A deploy needs a new tag, or an explicit:

  kubectl rollout restart deploy/$( [ "$SERVICE" = ui ] && echo prod-ui || echo prod-authsec ) -n authsec-prod
MSG
exit 1
