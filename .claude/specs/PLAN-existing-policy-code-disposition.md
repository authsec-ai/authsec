# Policy implementation disposition

Decision: 13 October 2026, explicit product-owner instruction. The pre-Phase-3
agent-policy feature is removed, not migrated or exposed through a compatibility
product. There are no customers requiring retention of this feature. Do not add
customer-count gates, an archive/export project, a default-on legacy flag, or a
Legacy policies screen as dependencies of Phase 3.

## One policy product

`SPEC-iga-phase3-policy-requirements.md` defines the outcome and
`SPEC-iga-phase3-policy.md` defines the AWS-first implementation. Policy intent,
approvals, evidence, deployment and verification belong to `iga_gov_*`.
Provider-discovered policies in the graph remain evidence, not authored policies.

## Remove

- `AgentPolicyManager`, its entitlement/cluster policy reconciler and warning worker.
- `agent_policies`, `agent_policy_confirmations`, `agent_policy_actions`,
  `agent_policy_warnings`, `governance_notification_settings`.
- The old agent-policy, effective-policy, upcoming-actions, warning, notification
  settings APIs, including `/api/iga/v1/legacy/*`.
- `IGA_LEGACY_AGENT_POLICY`, the compatibility controller/service, Legacy policies
  UI, legacy notification copying, and tests specific to those removed features.
- Superseded hand-run SQL for those tables. Historical numbered migrations remain
  migration history; `158_retire_legacy_agent_policy.sql` removes their objects.
  Bootstrap describes the same final schema.

## Preserve separately

Recent workspace/multitenancy authorization, OAuth/OIDC, token revocation,
AuthSec runtime role bindings and provenance; AWS/GitHub/Kubernetes discovery;
identity graph collection, publication and evidence; shared email/webhook
transport, Vault and console primitives. These are not the removed policy model.

The enforcement plan (`enforcement_plans`, `GET /authsec/provisioning/enforcement-plan`,
`GET /authsec/governance/connectors/:id/enforcement-plans`) stays. The cluster
agent polls it for the quarantine set and reports its capabilities on it,
including `bindings`, which Kubernetes access policies (`146`) require. Its
entries no longer carry a `policy_id`.

Manual discovery quarantine, actuation instruction delivery and its lease reaper
are separate existing integration operations, not a fallback policy engine. They
must not be called by Phase 3. Future Kubernetes policy requires its own provider
adapter and evidence contracts, not reactivation of the deleted policy service.
No external NetworkPolicy or cloud resource is deleted merely by deleting local
policy code or tables.

## Verification

Trace startup, route registration, writers and UI callers: no executable reference
to the removed services or tables. Build and vet backend, type/lint/build UI,
run the applicable existing Phase 3 checks. Rehearse migration upgrade and fresh
bootstrap in separate scratch databases; verify the five tables are absent, `enforcement_plans` remains, and
retained graph, workspace and runtime tables still exist. Report performed
checks and remaining limitations; this document is not deployment evidence.
