# SPEC: AuthSec production deployment on K3s

> **Status:** Canonical operational specification.
>
> This is the only active deployment path for `app.authsec.ai` and
> `prod.api.authsec.ai`. Any other deployment material in the workspace is outside
> the current production contract.

## Live topology

| Item | Current value |
|---|---|
| Cluster | single-node K3s |
| Node | `k3s-master` (`37.27.104.185`, `linux/amd64`) |
| Kubeconfig on node | `/etc/rancher/k3s/k3s.yaml` |
| Application namespace | `authsec-prod` |
| Database namespace | `database-prod` |
| OAuth namespace | `hydra-prod` |
| Vault namespace | `vault-prod` |
| Ingress namespace | `ingress` |
| Backend Deployment/container | `prod-authsec` / `prod-authsec` |
| UI Deployment/container | `prod-ui` / `prod-ui` |
| Helm release | `prod` in `authsec-prod` (ownership only; not a pipeline) |
| UI | `https://app.authsec.ai` and `https://*.app.authsec.ai` |
| API and OAuth issuer | `https://prod.api.authsec.ai` |

Credentials and the verified SSH host-key fingerprint live only in
`SPEC-deployment-k3s.local.md`, which is **not in this repository** and is not
linked from it — a link would 404 for everyone who clones.

It is a local, operator-held file at
`~/Desktop/authnull/.claude/specs/SPEC-deployment-k3s.local.md`, mode `0600`.
`.gitignore:12` also covers `.claude/specs/*.local.md` here, so a copy placed
alongside these specs stays untracked.

If you do not have it, ask the operator — do not reconstruct it from the
cluster, and never paste its contents into a spec, a commit, an issue or a
chat message.

## Sources that deploy

| Component | Local checkout | Branch |
|---|---|---|
| Backend | `/Users/pc/Desktop/authnull/authsec` | `authsec-staging` |
| Frontend | `/Users/pc/Desktop/authnull/Authsec-ui` | `authsec-staging` |

The requested source is the local working tree. Do not reset, clean, stash, or
silently replace local changes. Fetch/pull only when the operator explicitly asks
for remote branch heads. Record the commit and whether the working tree is dirty
before every build.

## Release invariants

- Build immutable, commit-labelled `linux/amd64` images locally with Docker
  Buildx. The K3s node is amd64 even when the developer machine is arm64.
- Import images directly into K3s containerd and deploy them with
  `imagePullPolicy: IfNotPresent`. Do not reuse the mutable registry
  `production` tag.
- Roll out backend first. Roll out the UI only after backend health, startup logs,
  migrations, OAuth discovery, and any new protected route are verified.
- The UI build must use `https://prod.api.authsec.ai` for both `VITE_API_URL` and
  `VITE_OAUTH_BASE_URL`.
- Never wipe a deployed namespace, PVC, Postgres database, or Vault data.
- A backend release containing migrations requires a pre-deploy `pg_dump`, then
  post-deploy verification of `migration_logs`.
- A Helm upgrade can overwrite a manual image patch. Inspect the running image
  after any Helm operation.
- **Every deployable build carries its commit, and every deploy is verified
  against it.** Both services serve the same JSON shape — a shape that differed
  between them is one somebody reads wrong at 2am:

  | Service | Endpoint | Injected by |
  |---|---|---|
  | Backend | `GET /authsec/uflow/version` | `-ldflags` into `internal/buildinfo` |
  | Console | `GET /version` | Docker `ENV`, read by `server.js` at runtime |

  `scripts/check-deployed-version.sh` checks either — `SERVICE=ui` switches
  host and path. Exit **0** match, **1** mismatch, **2** cannot tell. A build
  without build args reports `injected: false` and exits 2, because "nobody can
  say what is running" is a different answer from "it is the wrong commit". A
  deploy is not finished until it exits 0.
- **A rollout to an unchanged tag does nothing.** Kubernetes sees no diff and
  keeps the cached image, so "I pushed `:production` and restarted" can leave
  the old binary serving with nothing on screen to say so. This is not
  hypothetical: production ran a pre-Phase-1 binary for days behind
  `authsec:production` while the code sat pushed. Deploy the SHA tag.
- **CI/CD: `.github/workflows/deploy.yml` in BOTH repos deploys on push to
  `authsec-staging`.** It re-runs vet, migration hygiene, the isolation check
  and unit tests first — a direct push is not a pull request, so `pr-checks`
  never saw it — then builds a SHA-tagged image, `pg_dump`s to the PostgreSQL PVC before the new pods
  can migrate, points the deployment at the SHA, and fails the job unless the
  running commit matches. Verification failure rolls back automatically.

  The console's workflow is the same shape, minus the database backup — it owns
  no schema and runs no migrations, and a ceremonial dump would teach people the
  step is ceremonial. Its gates are **ratchets, not passes**: the project carries
  198 TypeScript and 17 ESLint errors, and a gate demanding they be fixed before
  anything can ship is a gate somebody deletes in week one. A change must not
  ADD any. Lower a ceiling when you fix some; never raise it. The TypeScript
  step also fails on a suspiciously LOW count, because a parse error reports as
  1 and hides every other diagnostic.

  Both require three repository secrets that do not exist yet:
  `REGISTRY_USERNAME`, `REGISTRY_PASSWORD`, `KUBECONFIG_B64`. Until they are
  added the workflow fails at the login step and nothing is deployed — which is
  the correct failure, not a silent one.

  **Order still matters and no workflow enforces it.** Backend first, console
  second: the console calls the API, and shipping it ahead of the endpoints it
  needs shows a customer errors that are not their problem.

  The `deploy` job targets the `production` GitHub Environment, so a required
  reviewer can be attached in repository settings without editing the workflow.
  **There is one cluster and it serves customers**; whether a push reaches it
  unattended is a decision for a person, and that setting is where it lives.

## Pre-release migration rehearsal and target gate

Before setting deployment credentials, resolve the target against the root
`AGENTS.md`: IGA development changes must not reach the customer-serving stack
without an explicitly approved cutover decision. A workflow file pointing at
`authsec-prod` does not itself authorize that cutover.

For every schema-bearing release:

1. Export the live schema with `pg_dump --schema-only --no-owner --no-privileges`
   through the documented SSH access. Store it privately; do not upload customer
   data to CI artifacts.
2. Restore it into a new isolated scratch PostgreSQL database. Apply every pending
   numbered migration with `ON_ERROR_STOP=1`. Never point this rehearsal at the
   deployed database.
3. Load `001_bootstrap.sql` into a second scratch database. Compare columns,
   defaults, nullability, constraints and indexes for the affected tables against
   the upgraded schema. A successful migration alone does not establish parity.
4. Run the integration suite against the upgraded scratch schema and record the
   failures explicitly. Bootstrap-only validation misses upgrade-path defects.
5. Before the actual rollout, take a full backup and verify its archive directory
   with `pg_restore --list`. The backend workflow keeps its private pre-release
   dump at `/bitnami/postgresql/authsec-release-backups/` on the PostgreSQL PVC,
   not in GitHub artifacts. This is a rollback copy, not an independent disaster
   recovery backup; retain the existing off-cluster backup procedure.

Both workflows serialize releases within their own repository and only attempt
rollback after their image update succeeded. Backend-before-UI ordering remains
an operator responsibility across the two repositories.

## Standard release

### 1. Identify and validate the source

```bash
cd /Users/pc/Desktop/authnull/authsec
git status --short --branch
git rev-parse HEAD
go build ./...
go vet ./...

cd /Users/pc/Desktop/authnull/Authsec-ui
git status --short --branch
git rev-parse HEAD
npm run type-check
npm run build -- --mode production
```

Inspect migration changes relative to the running backend revision:

```bash
git -C /Users/pc/Desktop/authnull/authsec diff --name-only <running-backend-revision>..HEAD -- migrations
```

### 2. Build immutable amd64 images

Use 12-character source revisions as tags when the working trees are clean. If a
tree is dirty, use a timestamped `local-*` tag and retain the exact `git status`
with the release record.

```bash
docker buildx build --platform linux/amd64 --load \
  -t docker.io/authsec-local/backend:<backend-revision> \
  /Users/pc/Desktop/authnull/authsec

docker buildx build --platform linux/amd64 --load \
  -t docker.io/authsec-local/ui:<ui-revision> \
  --build-arg VITE_API_URL=https://prod.api.authsec.ai \
  --build-arg VITE_OAUTH_BASE_URL=https://prod.api.authsec.ai \
  --build-arg VITE_APP_NAME=AuthSec \
  /Users/pc/Desktop/authnull/Authsec-ui
```

Confirm both images say `linux/amd64` before transfer.

### 3. Transfer and import

Create one archive in a temporary directory, copy it to the node, then import it
through K3s containerd:

```bash
AUTHSEC_TRANSFER_DIR="$(mktemp -d)"
AUTHSEC_IMAGE_ARCHIVE="$AUTHSEC_TRANSFER_DIR/authsec-deploy-images.tar.gz"
docker save \
  docker.io/authsec-local/backend:<backend-revision> \
  docker.io/authsec-local/ui:<ui-revision> \
  | gzip -1 > "$AUTHSEC_IMAGE_ARCHIVE"

scp "$AUTHSEC_IMAGE_ARCHIVE" root@37.27.104.185:/root/authsec-deploy-images.tar.gz
ssh root@37.27.104.185
```

On the node:

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
gzip -dc /root/authsec-deploy-images.tar.gz | k3s ctr images import -
k3s ctr images list | grep authsec-local
```

Do not touch a Deployment until both exact tags appear in the containerd list.

### 4. Back up when migrations are present

On the node:

```bash
mkdir -p /root/backups
AUTHSEC_BACKUP_PATH=/root/backups/authsec-pre-<backend-revision>-$(date +%Y%m%dT%H%M%S).dump
kubectl exec -n database-prod postgresql-primary-0 -- sh -c \
  'export PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")"; exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" -Fc' \
  > "$AUTHSEC_BACKUP_PATH"
test -s "$AUTHSEC_BACKUP_PATH" && sha256sum "$AUTHSEC_BACKUP_PATH"
```

### 5. Roll out backend, then UI

Patch only the intended container and record a change cause:

```bash
kubectl patch deployment prod-authsec -n authsec-prod --type=strategic -p \
  '{"spec":{"template":{"metadata":{"annotations":{"kubernetes.io/change-cause":"local authsec <backend-revision>"}},"spec":{"containers":[{"name":"prod-authsec","image":"docker.io/authsec-local/backend:<backend-revision>","imagePullPolicy":"IfNotPresent"}]}}}}'
kubectl rollout status deployment/prod-authsec -n authsec-prod --timeout=300s
```

After backend verification succeeds:

```bash
kubectl patch deployment prod-ui -n authsec-prod --type=strategic -p \
  '{"spec":{"template":{"metadata":{"annotations":{"kubernetes.io/change-cause":"local Authsec-ui <ui-revision>"}},"spec":{"containers":[{"name":"prod-ui","image":"docker.io/authsec-local/ui:<ui-revision>","imagePullPolicy":"IfNotPresent"}]}}}}'
kubectl rollout status deployment/prod-ui -n authsec-prod --timeout=300s
```

### 6. Verify

```bash
kubectl get deployment prod-authsec prod-ui -n authsec-prod
kubectl get pods -n authsec-prod
kubectl logs deployment/prod-authsec -n authsec-prod -c prod-authsec --since=10m
kubectl logs deployment/prod-ui -n authsec-prod --since=10m

curl -fsS https://prod.api.authsec.ai/authsec/uflow/health | jq .
curl -fsS https://prod.api.authsec.ai/.well-known/openid-configuration \
  | jq '.issuer,.token_endpoint,.jwks_uri'
curl -fsSI https://app.authsec.ai/
curl -fsS https://app.authsec.ai/config.js
```

Pass conditions:

- both Deployments are `1/1` ready with zero new restarts;
- migrations report applied/skipped without failure;
- backend health is `healthy`;
- issuer, token endpoint, and JWKS use `prod.api.authsec.ai`;
- UI returns `200` and runtime config uses `prod.api.authsec.ai`.

## Rollback

Inspect history before choosing a revision:

```bash
kubectl rollout history deployment/prod-authsec -n authsec-prod
kubectl rollout history deployment/prod-ui -n authsec-prod
```

Then roll back the affected component and wait for health:

```bash
kubectl rollout undo deployment/prod-authsec -n authsec-prod --to-revision=<revision>
kubectl rollout status deployment/prod-authsec -n authsec-prod --timeout=300s

kubectl rollout undo deployment/prod-ui -n authsec-prod --to-revision=<revision>
kubectl rollout status deployment/prod-ui -n authsec-prod --timeout=300s
```

Application rollback does not reverse a database migration. Any non-additive
migration requires its own forward recovery plan and a restore-tested backup.
