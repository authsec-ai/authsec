# SPEC: Federated (bring-your-own) SPIFFE workload onboarding

> **Status:** Legacy-product feature, mostly blocked by the release lock on
> `app.authsec.ai` — new endpoints, schema and UI are not permitted there until
> cutover ([product spec §8](SPEC-agentic-access-management.md)).
>
> **One item is permitted now and should be split out:** the validator hardening
> below — enforcing that the SVID's trust domain matches the provider's — closes a
> decorative-field gap and is a security fix. The rest waits.
>
> Unrelated to Agentic IGA.

## Summary

AuthSec can register the **issuer** half of SPIFFE trust (`workload_identity_providers`)
but has no path — UI or API — to register the **subject** half: a service account whose
`spiffe_id` is an *external* SPIFFE ID issued by a customer's own SPIRE. Every workload
path mints an internal `spiffe://authsec.local/...` ID via `spiffeIDFor()`. The validator
already matches external IDs by string, but nothing can put one into the DB. This makes
"bring your own SPIRE" impossible through the product even though the backend supports it.

This spec adds **federated workload onboarding**: register an external SPIFFE workload
against a registered trust-domain provider, exact-ID match (option A), with the schema
shaped so prefix/pattern match (option B) is a non-breaking add later.

## Scope

**In scope:**
- Schema: `service_accounts.spiffe_match_type` (exact|prefix, default exact) + `workload_provider_id`
- Backend: `POST /authsec/applications/:id/access/federated-workload`
- Validator hardening: enforce SVID trust-domain == provider trust-domain (close decorative-field gap)
- UI: "Bring your own SPIRE (federated)" mode in the workload wizard
- Docs: update `flows/spiffe-workload.md` + end-to-end test runbook

**Out of scope (deferred):**
- Prefix/pattern subject matching (option B) — column exists, logic deferred
- Embedded SPIRE registry path (`ENABLE_EMBEDDED_SPIRE`) — separate decision
- Bundle-endpoint (`https_spiffe`) federation — OIDC/JWKS discovery only for v1

## Affected repos

| Repo | What changes | Why / why not |
|---|---|---|
| `authsec` | schema + new endpoint + validator trust-domain check | core gap is here |
| `Authsec-ui` | federated mode in workload wizard | the missing onboarding surface |
| `sdk-authsec` | none | SDK already presents an SVID at `/oauth/token`; no contract change |
| `authsec-doc` | none (defer) | covered by `flows/spiffe-workload.md` for now |
| Production K3s | standard backend/UI rollout with a pre-migration backup | no new cluster service or secret |

**SDK decision:** None. The workload already presents its SVID via `client_assertion_type=...:spiffe-svid`; registering it is an admin/console operation, not a machine-caller path.

## Backend spec (authsec)

### Schema (`001_bootstrap.sql`, `service_accounts`, inline)
```
spiffe_match_type text NOT NULL DEFAULT 'exact'
    CONSTRAINT service_accounts_spiffe_match_chk CHECK (spiffe_match_type IN ('exact','prefix')),
workload_provider_id uuid,   -- links a federated SA to its workload_identity_provider
```

### New endpoint
```
POST /authsec/applications/:id/access/federated-workload
Auth: admin session (workspace-scoped)
Body: {
  provider_id: uuid,            // a registered workload_identity_provider (kind=spiffe, active)
  external_spiffe_id: string,   // exact spiffe://<provider.trust_domain>/...
  role_id: uuid,                // must be rs-scoped role
  service_account_name: string  // (or service_account_id of an identity-less SA)
}
Response 201: { service_account_id, spiffe_id, client_id, role_name, token_endpoint }
Errors: 400 (bad spiffe id / trust-domain mismatch), 404 (provider/role/app), 409 (SA already has identity)
```
Logic: validate provider active+spiffe+same workspace → validate `external_spiffe_id`
starts `spiffe://` and its trust domain == `provider.trust_domain` → create/resolve SA →
set `spiffe_id=external`, `spiffe_match_type='exact'`, `workload_provider_id=provider.id` →
create confidential `spiffe-svid` client → grant rs-scoped role → register client →
`application_spiffe_identities` row with status `active` (federation is the attestation; no
embedded-SPIRE attest step). All in ONE tx (mirror `CreateWorkloadAccess`).

### Validator hardening (`client_auth.go authenticateSPIFFESVID`)
After resolving the SA by `spiffe_id`, if a provider with `trust_domain` was matched,
enforce the SVID `sub`'s trust domain equals `provider.trust_domain`. Reject otherwise.

## Frontend spec (Authsec-ui)

`CreateWorkloadWizard` gets a mode toggle on step 1:
- **AuthSec-managed SPIRE** (current behavior, unchanged)
- **Bring your own SPIRE (federated)** → step fields: pick/create provider (issuer+trust domain),
  enter exact external SPIFFE ID, pick role. Success step shows the `spire-agent api fetch jwt`
  + `curl /oauth/token` snippet. Calls the new federated endpoint.

## Acceptance criteria
- [ ] `POST .../access/federated-workload` with a valid external ID returns 201 and the SA has `spiffe_id` = external ID
- [ ] Trust-domain mismatch (ID under a different domain than the provider) → 400
- [ ] A real external SVID from that issuer authenticates at `/oauth/token` and returns an access token
- [ ] Introspect shows the federated workload's token (tf, sub=external spiffe id)
- [ ] `go build ./... && go vet ./...` exit 0; `npx tsc --noEmit` exit 0 in Authsec-ui
- [ ] After K3s deployment, `migration_logs` records the numbered migration and the two new columns have the correct defaults

## Implementation plan (one commit per step)
1. Schema: add the two columns inline in `001_bootstrap.sql`
2. Model: add `SpiffeMatchType` + `WorkloadProviderID` to the `ServiceAccount` struct
3. Backend: `CreateFederatedWorkloadAccess` handler + route
4. Validator: trust-domain enforcement
5. UI: wizard federated mode
6. Wipe+rebootstrap + end-to-end smoke with the external SPIRE
7. Docs: `flows/spiffe-workload.md` (managed vs federated) + runbook

## Related docs
| Doc | Why |
|---|---|
| `authsec/docs/primitives/schema.md` | single-state schema procedure |
| `authsec/docs/flows/spiffe-workload.md` | the flow being extended |
| `authsec/docs/primitives/spire.md` | SPIFFE primitives |
