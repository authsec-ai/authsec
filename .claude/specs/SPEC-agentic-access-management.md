# SPEC: AuthSec Agent Identity Governance

> **What the product is and why.** The delivery plan is
> [SPEC-iga-roadmap.md](SPEC-iga-roadmap.md); the phase in flight is
> [SPEC-iga-phase1-collect.md](SPEC-iga-phase1-collect.md).
>
> **Category:** AI Agent Identity Governance and Administration (Agentic IGA).
> **Verified 2026-09-15** against the live cluster and the tree at `aac6f5a`.

---

## 1. The problem

Agents appear in AI builder platforms, cloud accounts, repositories, Kubernetes
clusters and SaaS tenants. Each platform exposes a fragment:

- an agent definition without its downstream identity;
- a service principal without the agent consuming it;
- an OAuth grant without an accountable owner;
- an MCP configuration without proof it is deployed;
- a workload without its business purpose;
- a tool permission without the resources behind it;
- activity without a reliable mapping back to a logical agent.

Traditional IGA governs accounts and entitlements after onboarding, but does not
model agent definitions, instances, tools, models or delegation — nor distinguish
a business sponsor from a technical owner, an administrator from an invoker, or
the agent identity from the workload identity its runtime uses.

Agent-security products usually stop at inventory and findings. The customer gets
another dashboard and no repeatable way to certify access, remove it, and prove
the removal happened.

The gap between them is the product: **agent-aware discovery joined to real IGA
workflows.**

## 2. What we promise

For every supported agent, an evidence-backed record of: its definition,
instances and estate scopes; its owners and sponsors; the identities,
credentials, tools and entitlements it holds; who can administer or invoke it;
source coverage, freshness and conflicts; and its findings, lifecycle and review
history.

Three promises constrain every feature:

1. **Visibility with boundaries.** Report what each integration inspected,
   excluded, failed to read and last observed — per scope — alongside the kinds
   of agent no connected source can see at all. **Zero objects returned is never
   reported as complete coverage.**
2. **Accountability.** Agents are reviewable identities with owners, lifecycle,
   reviews and evidence.
3. **Closed-loop change.** An approved change is written through a separately
   authorized remediation path, then **verified by reading the source again**. A
   ticket response is not verified removal.

## 3. The two directions of access

Every page, finding, policy and review separates them.

**Inbound — human or system → agent.** Who can create, configure, publish or
operate it? Who can change its instructions, tools, model or data sources? Who
can invoke it? Which applications or other agents can call it? Is it shared with
named users, a group, the tenant, or the public?

**Outbound — agent → identity, tool, resource.** Which identity does it
authenticate as? Which roles, grants, keys or credentials does it use? Which
MCP servers, tools, APIs, models, databases, repositories and cloud resources
can it reach? Which of that access is shared, privileged, stale or inconsistent
with its purpose?

**An inbound permission never implies an outbound one.** A human allowed to use
an agent is not thereby the owner of that agent's downstream authority. This is
the distinction the graph exists to keep, and the one a flat dashboard blurs.

## 4. Domain model

These terms are distinct because the schema enforces the distinction. They are
not synonyms for different audiences.

**Human identity** — a person from an authoritative directory, with employment
status, manager and team. AuthSec does not become the HR source.

**Agent** — the logical AI-enabled product or role, for example "Refund
Reviewer". It persists across versions and deployments. It is *not* an OAuth
client, a service principal, a Kubernetes Deployment, a model, a repository or a
tool.

**Agent instance** — a source-native realization of that logical agent: a Bedrock
version or alias, an AgentCore runtime, a Kubernetes Deployment, a published SaaS
agent. Production and staging are distinct instances. An instance may not be
compute at all, which is why workload and instance stay separate.

**Estate scope** — a containment and risk boundary: cloud account, subscription,
resource group, cluster, namespace, tenant. Scopes form provider-qualified trees.

> **Containment does not create access inheritance.** An edge inherits down a
> scope tree only when the provider's authorization semantics say so, and the
> provider rule and originating entitlement are stored on every inherited edge.
> Findings anchor to the smallest affected scope; a parent may aggregate counts
> and maximum severity for navigation, but aggregation never creates a finding or
> changes a child's severity.

**Entitlement and resource** — an entitlement is a grantable permission; a
resource is what it names. A selector naming a resource is not proof that
resource exists.

### Ownership is not one relationship

Sponsor and technical owner are different roles, and a creator is neither.
Candidate evidence (a CODEOWNERS entry, a tag) is separate from confirmed
assignment, and confirmation, expiry and succession each have state. A code owner
reviews pull requests; accountability for an agent is something a person accepts.

## 5. Discovery integrations are not Action Connectors

AuthSec already ships **Action Connectors** — an outbound broker that executes
typed provider actions on behalf of agents ([SPEC-connectors.md](SPEC-connectors.md)).

A discovery integration is a different thing with a different credential: it
reads an estate to build inventory and evidence. Slack or GitHub support in the
connector framework provides no Slack or GitHub *estate discovery*. **Agentic IGA
must not depend on the connector framework.**

Remediation is a third category with its own credential and its own consent. The
discovery role can never write.

## 6. As built today

The product as it actually exists, so this document opens with reality.

| Surface | State |
|---|---|
| AWS discovery | **Working at a basic level.** Onboarding, connector create/verify/revoke, scan, and reads for identities, secrets, assume-edges, permissions, resources, workloads and usage — paginated and scoped to one connected account. Collectors cover IAM, Lambda, ECS, EC2, EKS, Bedrock and AgentCore, and coverage now reflects all three scan stages rather than IAM alone |
| Identity graph | **Not built.** This is the current milestone — see the roadmap |
| GitHub IGA provider | Present (`services/iga_github_provider.go`); binding hardened at `3e93618`. Not in the current milestone |
| Kubernetes collector | `authsec-iga-agent` runs in `authsec-system`, resyncing every six hours. A second source, out of scope until AWS delivers one source end to end |
| Governance and enforcement | Certification, agent policy, containment, eviction and destruction merged at `12cbaed`. Two known defects remain open (A4, A5 in the roadmap) |
| Legacy AuthSec Production | OAuth/OIDC, XAA, CIBA, SPIFFE, Action Connectors, Agent Guard — serving customers, release-locked |

**Honest limits of the discovery that exists.** No effective access — conditions
are stored, never evaluated, and SCPs, permission boundaries and session policies
are out of scope. No observed usage — no CloudTrail collector exists, so activity
is Access-Advisor *attempts*, which include denied ones. No resource inventory —
selectors are preserved, never enumerated.

## 7. Where we are going

**AWS first, to a working identity graph, then governance on top of it.**

The graph is the prerequisite for everything else: certification needs
trustworthy inventory and accountable reviewer routing; safe remediation needs
reviewed targets and reliable source verification. Building governance on an
inventory that duplicates on rescan would produce reviews nobody can explain.

Delivery order — detail in [the roadmap](SPEC-iga-roadmap.md):

1. **Foundations** — topology, membership authority, constraints, coverage
   manifest, query budgets. *Closed.*
2. **Connect and collect** — durable, evidenced, idempotent collection.
   *In flight.*
3. **Objects and identity graph** — stable objects, workload-to-identity edges.
4. **Entitlement graph** — statements, assignments, selectors.
5. **Traversal API** — bounded reads that admit what they could not see.
6. **Console** — walk a real path, change the source, rescan, see the change.

Then, and only then: ownership attestation, access certification, and one
constrained remediation with a confirming re-read.

**Other providers are integrations, not the organising principle.** The product
is multi-provider and the canonical model must not become AWS-shaped — a model
derived only from IAM roles and policy statements will need rework the first time
it meets app-role assignments and OAuth grants. Validate representative payloads
from a second provider against the canonical entities before freezing them. That
is a design check, not a delivery dependency, and it does not gate AWS.

## 8. Legacy coexistence and cutover

AuthSec operates two product lines during the build.

**Legacy AuthSec Production** (`app.authsec.ai`) remains the customer-serving
product and is **release-locked**: security, data-integrity, availability and
critical customer fixes only. Experimental IGA schema or API changes must never
deploy through it. Existing customers stay on this line until an explicit
migration window.

**Agentic IGA** runs inside the same service, database and `public` schema,
keeping the `iga_*` prefix. Breaking API and schema changes are allowed; existing
code may be reused, replaced or deleted; existing implementation is not a design
constraint. Development breakage must not mutate legacy production data,
credentials, deployments or artifacts.

That last clause rests on the release lock and on review, **not on
infrastructure**: one database, one pool, one process, one node. Legacy coupling
goes through a named bridge table and a CI check
([roadmap §2.1](SPEC-iga-roadmap.md)). Physical separation is a cutover
prerequisite, below.

### Cutover gate

A product milestone may be sold before public replacement of the legacy platform.
Public replacement requires:

0. **physical separation of the IGA stack** — own pods, database, storage,
   service identities, secrets, hostname and pipeline;
1. rehearsed data migration against a production-sized snapshot;
2. tenant-isolation and audit-integrity verification;
3. a pass/fail disposition for every legacy runtime capability — OAuth/OIDC
   issuance, XAA, CIBA, SPIFFE, Action Connector execution, Agent Guard,
   revocation and their audit records each get **migrate**, **retain** or
   **sunset** with documented customer impact;
4. a rollback path that does not lose governance evidence.

Historical audit evidence is never silently discarded or rewritten as new
Agentic IGA evidence.

## 9. Non-goals

- AuthSec is not the HR source, IAM provider, secrets manager, SIEM, CNAPP, or a
  replacement for every incumbent IGA.
- **No secrets are collected or displayed.** Existence, age and last use of a
  credential — never its value.
- Action Connectors are not discovery integrations, and discovery credentials
  never write.
- **Missing activity without telemetry is not unused access.**
- **A ticket or API response is not verified removal.**
- Repository scanning alone is not authoritative runtime discovery.
- AI assists; deterministic workflow and humans govern changes. AI never makes a
  final review or remediation decision.
- No runtime intent or lease authorization in this milestone; retained legacy
  runtime capabilities remain a separate plane.
- No claim of universal cloud, SaaS or endpoint coverage.
- No dozens of shallow integrations to raise a connector count.

## 10. Related documents

| Document | Owns |
|---|---|
| [SPEC-iga-roadmap.md](SPEC-iga-roadmap.md) | Delivery: current state, foundations, invariants, phases, gates |
| [SPEC-iga-phase1-collect.md](SPEC-iga-phase1-collect.md) | Phase 1 — collect: schema, tasks, acceptance |
| [SPEC-iga-phase2-graph.md](SPEC-iga-phase2-graph.md) | Phase 2 — the identity graph: model decision, migrations `024`–`029`, tasks, acceptance |
| [SPEC-aws-discovery.md](SPEC-aws-discovery.md) | AWS domain semantics — what a role, trust policy or instance profile means |
| [SPEC-github-discovery.md](SPEC-github-discovery.md) | GitHub source semantics; dormant |
| [AuthSec-AWS-Discovery-Lab-Team-Brief.md](AuthSec-AWS-Discovery-Lab-Team-Brief.md) | Lab fixtures for validation |
| [SPEC-connectors.md](SPEC-connectors.md) | Action Connectors — a different product |
| [SPEC-deployment-k3s.md](SPEC-deployment-k3s.md) | Production deployment |
