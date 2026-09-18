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

# WHY THIS RETRIES.
#
# `kubectl rollout status` returns when pods report Ready, which is earlier than
# when the service actually answers: the readiness gate can pass before the
# process serves, and during a rollout the ingress may still route to the old
# pod. A single request therefore races the rollout and loses -- the first run of
# this pipeline failed here 3 seconds before the new process came up, rolled
# back, and reported a broken deploy that had in fact succeeded.
#
# So poll until the answer settles. Every non-match is retried, including a
# mismatch, because mid-rollout the old pod answering is expected rather than
# final. Only the state that survives the whole budget is reported.
ATTEMPTS="${ATTEMPTS:-20}"
INTERVAL="${INTERVAL:-6}"

field() { printf '%s' "$1" | python3 -c "
import json,sys
try: print(json.load(sys.stdin).get('$2',''))
except Exception: print('')
"; }

GOT=""; INJECTED=""; BUILT=""; BRANCH=""; UPTIME=""; REASON=""
attempt=0
while [ "$attempt" -lt "$ATTEMPTS" ]; do
  attempt=$((attempt + 1))
  BODY="$(curl -fsS --max-time 10 "$URL" 2>/dev/null || true)"

  if [ -z "$BODY" ]; then
    REASON="unreachable"
  else
    GOT="$(field "$BODY" commit)"
    INJECTED="$(field "$BODY" injected)"
    BUILT="$(field "$BODY" built_at)"
    BRANCH="$(field "$BODY" branch)"
    UPTIME="$(field "$BODY" uptime_seconds)"

    if [ "$INJECTED" != "True" ] && [ "$INJECTED" != "true" ]; then
      REASON="not_injected"
    elif [ "$GOT" = "$WANT" ]; then
      REASON="match"
      break
    else
      REASON="mismatch"
    fi
  fi

  if [ "$attempt" -lt "$ATTEMPTS" ]; then
    printf 'waiting for %s (attempt %d/%d: %s)\n' "$SERVICE" "$attempt" "$ATTEMPTS" "$REASON"
    sleep "$INTERVAL"
  fi
done

if [ "$REASON" = "unreachable" ]; then
  cat >&2 <<MSG
UNKNOWN: $URL returned nothing after $((ATTEMPTS * INTERVAL))s.

Either the endpoint is not deployed yet -- which is itself the answer, since it
ships with the code you are checking for -- or the host is unreachable. Probe a
route you know exists to tell those apart:

  curl -o /dev/null -w '%{http_code}\\n' $API$HEALTH_PATH
MSG
  exit 2
fi

if [ "$REASON" = "not_injected" ]; then
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
echo "checks $attempt of $ATTEMPTS"
echo

if [ "$GOT" = "$WANT" ]; then
  echo "MATCH: the deployed binary is the commit you asked about."
  exit 0
fi

cat <<MSG
MISMATCH: after $((ATTEMPTS * INTERVAL))s the deployed binary is NOT that commit.

This is not a timing artifact -- the whole retry budget was spent and the answer
never changed. Something rolled, and it rolled to the wrong thing.

Most likely: the image was built from a different commit than the one being
checked, or the deployment is pinned to a floating tag. A rollout that reuses
the SAME tag does nothing at all, because Kubernetes sees no diff in the spec.

  kubectl describe deploy/$( [ "$SERVICE" = ui ] && echo prod-ui || echo prod-authsec ) -n authsec-prod | grep -i image
MSG
exit 1
