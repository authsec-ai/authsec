# Connectors — production K3s infrastructure handoff

The connector control plane, OAuth connection flow, broker, audit path, and
per-workspace provider applications run inside the `prod-authsec` backend in
namespace `authsec-prod`. This document contains only the current K3s runtime
checks. It does not describe a second deployment path.

Canonical release procedure:
[`../../../.claude/specs/SPEC-deployment-k3s.md`](../../../.claude/specs/SPEC-deployment-k3s.md).

## 1. Ingress must route broker traffic to the backend

`/broker/*` belongs to the Go backend, alongside `/authsec/*`, `/oauth/*`, and
`/.well-known/*`. A public Express HTML `404` means the request reached the UI
service and the production Ingress is incomplete.

Inspect the current rule:

```bash
ssh root@37.27.104.185
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl get ingress authsec-ingress -n authsec-prod -o yaml
kubectl get service -n authsec-prod
```

The `authsec-ingress` path table must send `/broker` with `Prefix` matching to the
backend service and backend port. Make the change in the production K3s release
source; a one-off live patch will be overwritten by a later Helm operation.

Verify the public path is protected by AuthSec rather than answered by Express:

```bash
curl -sS -i -X POST \
  https://prod.api.authsec.ai/broker/connectors/x/actions/y \
  -H 'Content-Type: application/json' -d '{}'
```

Expected without a token: an AuthSec JSON `401`/`403`, not an HTML `404`.

## 2. Vault must expose KV v2 at `kv/`

The backend stores connector credentials under the KV v2 API. Verify through the
running Vault pod:

```bash
kubectl exec -n vault-prod vault-0 -c vault -- vault secrets list -detailed
```

`kv/` must report type `kv` and version `2`. Do not enable or replace an engine
without first confirming the existing mount and data; changing a mounted secret
engine can make stored connector credentials unreachable.

## 3. Schema advances only through numbered migrations

Connector tables and indexes must ship through `migrations/master/NNN_*.sql`
with `001_bootstrap.sql` updated to the same final state. Do not apply the old
delta files manually to production.

Before a migration-bearing backend rollout, follow `/schema-change`: create a
compressed Postgres backup, deploy backend first, and confirm `migration_logs`
before deploying the UI.

## 4. Deployment and drift checks

```bash
kubectl get deployment prod-authsec prod-ui -n authsec-prod \
  -o custom-columns='NAME:.metadata.name,IMAGE:.spec.template.spec.containers[0].image,READY:.status.readyReplicas'
kubectl rollout history deployment/prod-authsec -n authsec-prod
kubectl logs deployment/prod-authsec -n authsec-prod -c prod-authsec --since=15m
```

The backend image must be the intended immutable local revision. A Helm operation
that restores a mutable registry tag is deployment drift and must be corrected
through the canonical K3s release flow.

## End-to-end pass condition

Connect a provider → grant an Agent → call
`/broker/.../actions/...:execute` → AuthSec injects the credential server-side,
calls the provider, returns a redacted result with identity attribution, and writes
the connector action audit record.
