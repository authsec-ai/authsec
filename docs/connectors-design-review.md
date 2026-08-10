# AuthSec Connectors — Design Review

**The Connector Broker & Agent Identity: problem, architecture, and the road to enterprise-grade**

| | |
|---|---|
| **Status** | Decisions locked (D1–D6) — ready to build · core shipped, enterprise gaps scheduled (Track A) |
| **Date** | 2026-07-08 |
| **Scope** | `authsec` (backend) · `Authsec-ui` · `marco` reference agent |
| **Verified on** | Live single-node deployment |

> A self-contained review document. It states the problem the connector subsystem solves, describes what is built and proven today, lays out the enterprise deployment reality (with the industry patterns it's grounded in), names the places the current design is flawed, and proposes a prioritized path to close them. Written for reviewers who were not part of the build.

---

## Contents

1. [The problem](#1-the-problem)
2. [What we built & what it proves](#2-what-we-built--what-it-proves)
3. [Core architecture](#3-core-architecture)
4. [The identity model (three slots)](#4-the-identity-model--three-slots)
5. [Enterprise deployment reality](#5-enterprise-deployment-reality)
6. [Agent runtime topologies](#6-agent-runtime-topologies)
7. [Teams & multi-tenancy](#7-teams--multi-tenancy)
8. [The flaw register](#8-the-flaw-register)
9. [Proposed solution & roadmap](#9-proposed-solution--roadmap)
10. [Open decisions for reviewers](#10-open-decisions-for-reviewers)

---

## 1. The problem

AI agents are only useful when they can *act* in real systems — read a repo, post to Slack, pull analytics, file a ticket. To act, an agent needs credentials to those systems. Today, teams give agents that access in three ways, all bad:

| Common practice | Why it fails in an enterprise |
|---|---|
| Paste an API key into the agent (prompt / env / code) | The secret lives in model context, logs and traces; it leaks; rotating it means redeploying every agent that holds it. |
| One shared service-account token for all agents | Over-privileged, and when something goes wrong you cannot tell *which agent* or *which person* caused it — no attribution, no blast-radius control. |
| Hardcode an OAuth token | Silently expires; breaks the agent at 2am; no refresh, no revocation story. |

As an org adds more agents and more tools, this compounds into an unmanaged sprawl of long-lived secrets with no central control, no audit, and no way to answer the question every security team will ask: **"which agent did what, on whose behalf, and who authorized it?"**

**What AuthSec provides.** An **identity-aware outbound action broker**. An agent authenticates to AuthSec with its own identity, names a typed action (e.g. `github.listCommits`), and AuthSec — after authorizing the call — injects the credential *server-side*, performs the request, and returns only the result. The agent never sees the credential. Every action is authorized against the caller's identity and recorded. AuthSec is the control plane; the credential lives in its vault, not in the agent.

**Positioning:** broker, not iPaaS and not a token vault. The moat is identity + delegated authorization + audit, built on a real OAuth/OIDC token engine (M2M, XAA/ID-JAG, CIBA, SPIFFE) — not a nicer way to hand secrets to agents. Nearest comparables: Descope Outbound Apps, Arcade.dev, Composio, Paragon ActionKit; the delegation spine matches Okta Cross-App-Access and the MCP enterprise-managed-auth pattern.

---

## 2. What we built & what it proves

The core broker is shipped, deployed on the single-node environment, and proven end-to-end by a real agent. This is not a prototype claim — here is the evidence.

> **Proof of life (2026-07-08).** A LangChain agent holding only an AuthSec client credential read the last 10 commits of a private repo through the broker. It never held a GitHub token; AuthSec injected it server-side; the action was attributed to the agent's identity in the audit log.

```
agent (python) ── AuthSec token ──▶ POST /broker/connectors/…/actions/listCommits:execute  ▶ 200
broker ── injects GitHub OAuth token from Vault ──▶ api.github.com  ▶ commits
audit_events #156: connector.action.allow  action=listCommits  subject=<agent SA>  http=200  895ms
→ the GitHub credential never entered the agent's process, context, or logs.
```

### Shipped & verified

| Capability | State |
|---|---|
| Broker data plane — audience-bound token verifier, multi-gate policy chain, server-side credential injection, redacted results | ✅ live |
| Typed provider adapters — Slack `postMessage`, GitHub `createIssue` + `listCommits` (fixed endpoints, typed input, SSRF-guarded) | ✅ live |
| OAuth connect-once flow — authorize + callback, state + PKCE, token → Vault; per-workspace "bring your own OAuth app" | ✅ live |
| One-transaction grant — a single "Grant" wires assignment + broker registration + execute role binding (previously 3 manual SQL steps) | ✅ live |
| Durable action audit — `connector_action_audit`: subject, actor (client + spiffe), token family, outcome, deny reason, latency | ✅ live |
| **Agent (service-account) client-secret rotation** — rotate the *AuthSec-issued* M2M secret: mint-new + revoke-old, `client_id` preserved; backend + UI. *(Distinct from provider OAuth refresh lifecycle — see below.)* | ✅ live |
| **Provider OAuth refresh lifecycle** — refreshing the *third-party* connection token before expiry | ⚠️ on-demand only; needs refresh-under-lock + background worker (hardening list) |
| Admin console — connectors list, add wizard, detail drawer (Overview / Access / Actions / Activity / Use) | ✅ live |
| MCP surface — actions exposed as MCP tools on the same policy chain | ✅ live |
| Credential vending — **deliberately absent**: no endpoint returns a provider secret to a caller, by design | ✅ by design |

---

## 3. Core architecture

Five nouns and one runtime pipeline.

| Concept | Definition |
|---|---|
| **Provider** | A catalog entry for a third-party service (GitHub, Slack, Google). Defines auth methods, OAuth endpoints, available actions. |
| **Connector** | A workspace's configured instance of a provider. Holds non-secret config + a declarative contract. Secrets never stored here. |
| **Connection** | A credential binding for a connector — workspace-scoped (shared org credential) or user-scoped (per-employee). Secret in Vault; only lifecycle metadata in Postgres. |
| **Action** | A typed, invocable operation (`listCommits`) mapped to a fixed provider endpoint + method by an adapter. The only thing an agent can invoke — no arbitrary URLs. |
| **Assignment** | Grants one agent (client) permission to run a connector's actions. The authorization edge between an agent and a connector. |

### Runtime pipeline

```
AuthSec access token (audience = workspace Connector-Broker Resource Server)
  ▶ verify token (signature · DB · revocation · audience · registration · live RBAC) → AuthContext
  ▶ policy chain: connector enabled? · agent_accessible? · assignment allows (client × action)? · scope?
  ▶ connection select: user-scoped (by token subject) if delegated, else workspace-scoped
  ▶ refresh if near expiry ▶ inject credential into the typed adapter ▶ call provider
  ▶ return redacted result + write audit (actor · subject · action · outcome · latency)
```

**Key property:** the broker is its own OAuth Resource Server per workspace, so every runtime token is audience-bound to it (RFC 8707) — a token minted for another resource cannot be replayed here (confused-deputy guard). **The result returned to the caller is the provider action result; the external provider credential is never returned** — the broker injects it into the upstream call server-side and it stays inside the broker.

---

## 4. The identity model — three slots

This is the conceptual heart of the review. The industry (Strata, Entrust, IBM, and the "authenticated delegation" literature) has converged on: agents are a **first-class identity**, never a borrowed human badge nor a shared service account, carrying a **verifiable delegation chain** — *who authorized the agent, on whose behalf it acts, under what human accountability.* That chain has three slots:

| Slot | Who | When present | Identifier |
|---|---|---|---|
| **Actor** | The agent (and optionally the attested instance) | **always** | `Actor.client_id` when an `act` claim exists (XAA/CIBA), else `ClientID` for direct M2M (+ `spiffe_id`) |
| **Owner** | The human who deployed / owns the agent | **always** | `owner_email` / `owner_team` |
| **Subject** | The end user who invoked *this* action | when human-triggered | `sub` (via SSO + XAA) |

> **Implementation nuance (must fix for "actor always" to be true):** in current code `authCtx.Actor` is populated only for delegated tokens (XAA/CIBA); for direct M2M it is `nil` while `authCtx.ClientID` carries the agent. But the durable audit only fills `ActorClientID` when `Actor != nil`, so a direct-M2M action currently records **no actor**. The audit writer must fall back to `ClientID` — `actor := authCtx.Actor?.ClientID ?? authCtx.ClientID` — otherwise "actor always" is aspirational, not real.

**Resolving "no agent should run without a human identity."** Correct — via the **owner** slot, which is *always* present. The **subject** slot is present only when a human actually triggered the action. A 2am scheduled agent has no subject but always has an owner who authorized it — that is where accountability sits (the "Start Button" principle). So every audit row carries **actor + owner** at minimum, plus **subject** when a person was in the loop.

**"If Alice and Jane use the same server-side agent, do they run different instances?"** **No.** For a shared server-side agent: one process, one `client_id`, serving everyone. What changes per request is the **token**, not the process — Alice's request carries `sub=Alice`, Jane's carries `sub=Jane`, a moment apart, same deployment. This is the established OAuth **on-behalf-of** pattern (Microsoft OBO, Google per-user tokens): a shared backend serves many users via per-request user tokens, never a process per person. Spinning up an instance per user is a *deployment* choice (local agents), never an identity requirement.

**What SPIFFE does and doesn't answer.** SPIFFE attests the **workload** — "which machine/process," filling the *actor* slot cryptographically with short-lived identity. It says nothing about the human. SPIFFE alone never answers "who used it"; the human still rides on top as the subject via token exchange.

---

## 5. Enterprise deployment reality

The AuthSec console being admin-only is correct and matches Okta/Auth0 — three roles, only one uses the admin UI.

| Role | Uses AuthSec console? | What they do |
|---|---|---|
| **Platform admin** (IT/security) | ✅ Yes | Connects org apps, creates agents, grants access, sets policy, audits. |
| **Agent developer** (dev team) | ❌ No — receives creds | Builds/deploys agents; embeds the agent's identity. |
| **End user** (any employee) | ❌ Never | Uses the agent (chat, IDE, internal app). Touchpoints: an SSO login, and (future) a "connect my accounts" consent screen. |

> **Current stage:** while dogfooding, one person is admin + developer + user. The roles still exist even when one person wears all three hats — and they split the moment the sales team uses an agent they'll never configure.

### How a provider is actually onboarded — the GitHub reality

Providers authorize automation differently, and this exposes the sharpest current flaw. Our GitHub connector uses a **GitHub OAuth App**, which authenticates *as the human who clicked Authorize* — inheriting one person's entire access, mis-attributing every agent action to them, and breaking when they leave. Enterprises use **GitHub Apps**: an org-installed bot identity, fine-grained permissions, scoped to selected repos, short-lived installation tokens, no human attached. (Our Slack connector is correct *when it stores the bot token from a bot-scope OAuth install* — Slack hands one back natively; it would be wrong if a user token were stored instead, so this depends on the requested scopes.)

| Provider | Enterprise auth model | Our connector today |
|---|---|---|
| **GitHub** | GitHub App installed per org; installation tokens; repo-scoped | ❌ OAuth App — acts as one human |
| **Slack** | App install → bot token (org identity) | ✅ correct *when connected via bot-token OAuth scopes* (not a user token) |
| **Google** | Per-user OAuth (default) or service account w/ domain delegation | ⚠️ catalog-only; needs per-user |

The clean mapping (once GitHub App support lands): **one connector per GitHub org installation** — `github-eng`, `github-data` — repos scoped at install, agents granted per-connector. Orgs become natural blast-radius boundaries.

---

## 6. Agent runtime topologies

| Topology | Flow | State |
|---|---|---|
| **T1 · Server-side shared agent** | SA client_id + secret (server-side vault) → M2M token (resource=broker) → broker executes with org connection → audit: actor + owner (+ subject if human-triggered) | ✅ works today (subject propagation needs R4) |
| **T2 · Local per-user agent** | Public client_id, **no secret**, on each laptop → dev SSO login (PKCE) → XAA exchange (sub=dev, act=agent) → broker resolves dev's connection | ❌ blocked on R4 |
| **T3 · CI / ephemeral** | SPIFFE SVID (no long-lived secret) → M2M continuation → broker executes | ✅ platform supports |

- **T1** — one deployment serves everyone; secret in the org vault; per-request subject via token exchange. Works today; subject propagation needs R4.
- **T2** — one copy per laptop; **no secret distributed**; a public client + SSO + XAA distinguishes each by who's logged in. Blocked on R4. Until then, there is no secure recipe — sharing an M2M secret to laptops is an anti-pattern the product exists to eliminate, and must not be documented as supported.
- **T3** — SPIFFE-attested, no long-lived secret. Platform supports.

> **The distribution rule.** One `client_id` per *logical agent* — safe to embed everywhere. One `client_secret` per *server-side deployment* — in a vault. On end-user machines: **no secret at all** — public client + login. "A client_id per person" doesn't scale; "one secret shared with everyone" is a breach waiting to happen. Both are wrong.

---

## 7. Teams & multi-tenancy

Example: sales uses the Google agent, engineering uses the GitHub agent. Teams enter on two axes; only one exists today.

| Axis | Answers | Status |
|---|---|---|
| **Agent × connector** (assignments) | "The google-agent may use google connectors." Blast radius per agent. | ✅ works |
| **Group/subject × connector** | "Only members of group `sales` may be the on-behalf-of subject of a google action." Team-level gating of *who* an agent acts for. | ❌ missing |

Today "sales uses the google agent" is enforced at the agent's own front door (the app checks the user's role before invoking) — *outside* AuthSec's guarantee. The correct enforcement point is the broker chain, evaluating the XAA subject against allowed groups. AuthSec already has groups + directory sync; wiring subject policy into the broker is the teams feature, meaningful once delegation (R4) is live.

> **Workspace vs. team (decided — D3).** A **workspace** is an isolation boundary — its own broker Resource Server, connectors, and audit — right for subsidiaries or environments (prod/staging), too heavy for teams. **Teams are groups within one workspace**, not separate workspaces.

---

## 8. The flaw register

Stated directly for review. Nothing in the architecture is *wrong* — the broker, identity model, and grant flow hold up. What's incomplete is **coverage**: we built the org-level credential path first; enterprise reality needs the bot-credential path and the per-user path alongside it. All fixes slot into the existing model without redesign.

### F1 · HIGH — Connector credentials are human-tied (the GitHub problem)
The workspace connection stores an OAuth-App token belonging to whoever authorized it. The agent acts as that person everywhere they have access; when they leave, every agent on that connector silently breaks. Exposes most OAuth-App-style providers; Slack is immune *only when connected with bot-token scopes* (a user-token Slack install would have the same flaw).
**Fix:** per-provider app/bot credentials — for GitHub, a GitHub-App flow (install on org → store installation id → broker mints installation tokens). New `auth_method=github_app`; adapter + catalog change. **Highest-value enterprise fix.**

### F4 · HIGH — No legitimate recipe for locally-run agents
The only fully working runtime auth is M2M-with-secret, which quietly pushes laptop-distributed agents toward secret-sharing. The correct recipe (public client + SSO + XAA + user connections) is ~80% built — token engine and broker routing done, user-consent flow (R4) missing.
**Fix:** ship R4 (user-scope OAuth consent + per-user connection endpoints + revoke), then publish the T2 recipe as the supported way to run local agents.

### F7 · HIGH — No mandatory accountable owner on every action
The "owner" identity slot exists on service accounts (`owner_email`/`owner_team`) but is not required at creation and is not carried into the action audit. So an autonomous agent's action can lack a clear accountable human — the exact gap flagged in review ("who used the agent? I should have that entry").
**Fix:** require an owner when a service account is created; stamp owner into every `connector_action_audit` row alongside actor + subject. Small change, high governance value.

### F5 · MED — No team/group gating at the broker
The broker checks which agent calls, not which human it acts for. "Sales may use the google agent, engineering may not" is unenforceable inside AuthSec today.
**Fix:** subject policy on connectors — allowed groups/roles evaluated against the XAA subject in the broker chain. Ships with/after R4; groups + directory sync already exist.

### F3 · MED — No action-input policy
An agent granted `listCommits` can call it on any repo the org credential sees. Actions bound *what* an agent does, not *where*. Enterprises will demand "the release agent touches only `acme-eng/release-*`."
**Fix:** per-assignment input constraints (a predicate on action inputs), enforced in the broker chain between schema validation and execution. Composes with F1's provider-side repo scoping — defense in depth.

### F2 · MED — "One connector = one credential" is real but undocumented
One workspace connection per connector (the OAuth callback upserts it). Multi-org GitHub therefore needs connector-per-org — a fine model, but nothing tells the admin; someone will connect a second org into the same connector and clobber the first.
**Fix:** bless connector-per-installation (naming guidance in UI + docs); reconnect warns when replacing a connection with a different external account. This requires capturing non-secret external-account metadata on the connection at callback time — without it, connector-per-installation UX is blind: `external_account_id`, `external_account_name`, `external_org_id`, `external_org_name`, `connected_by`, `connected_at`.

### F6 · MED — Shared org credential = shared fate on provider quotas
Everything through one connected account = one provider rate limit for the whole company; one noisy agent starves the rest. True of every org-level-connection competitor too.
**Fix:** per-user connections (R4) shard quota + blame; per-(agent × connector) broker rate limits contain the noisy neighbor.

### F8 · HIGH — Audit conflates "authorized" with "succeeded"
`runAction` writes `allow` + HTTP 200 even when the provider itself returned 401/403/500 — the adapter's `Result.OK=false` is buried in the payload while the audit row reads as success. "Allow" is defensible as *"the broker authorized the attempt,"* but enterprise audit cannot tell an authorized-but-failed call from an authorized-and-succeeded one. Reference: `connector_broker_controller.go` runAction / audit write.
**Fix:** the current single overloaded `http_status` splits into four orthogonal fields on `connector_action_audit`:
- `authz_outcome` = `allow | deny` (did the broker permit the attempt)
- `broker_status` = the broker-side HTTP result (`200`, or `403 | 404 | 424` when the broker denies *before* calling the provider)
- `provider_status` = the real upstream HTTP status (`200 | 401 | 500 | …`), **null when the broker denied before the call**
- `action_outcome` = `success | provider_error | policy_deny`

Small schema delta + a few lines in the audit write. High value: it's the difference between "we logged that we allowed it" and "we can prove what actually happened." Example — broker authorized, provider rejected:
```json
{ "authz_outcome": "allow", "broker_status": 200, "provider_status": 403, "action_outcome": "provider_error" }
```

### F9 · MED — Cross-workspace grants are undefined (likely brittle)
`resolveClientPrincipals` resolves a `client_id` **globally**, then `GrantAssignmentTx` binds the service account into the *connector's* workspace — but the role-binding FK requires the SA to belong to that workspace. So granting a foreign-workspace agent access to a connector probably fails awkwardly rather than being cleanly allowed or cleanly rejected. Reference: `connector_repository.go` resolveClientPrincipals + GrantAssignmentTx.
**Fix:** make it an explicit decision (see D6). Either (a) connectors are **same-workspace only** for now — reject a foreign `client_id` at grant time with a clear error; or (b) design a real cross-workspace trust path (this is genuinely the A2A / cross-app case and should reuse the XAA/ID-JAG first-contact-approval machinery, not an ad-hoc binding).

> **Also on the hardening list (elevated by review — treat as near-term, not "someday"):** connection-schema hardening — `connector_connections` has **no `workspace_id`**, `subject_user_id` is `text`, and `UNIQUE(connector_id, scope, subject_user_id)` does **not** prevent duplicate workspace rows (Postgres treats NULL as distinct). Fix with `workspace_id` + composite FK, UUID subject, CHECK constraints, and **partial unique indexes**: `(workspace_id, connector_id) WHERE scope='workspace'` and `(workspace_id, connector_id, subject_user_id) WHERE scope='user'`. Plus: refresh-under-lock (advisory lock + CAS — a thundering herd of 50 agents on an expiring Google token can race refresh-token rotation); idempotency keys on mutating actions; a background refresh worker with health notifications.

---

## 9. Proposed solution & roadmap

**Plan of record: Track A** (decided — see D5). The GTM is *server-side agents using org tools*, so accountability, audit integrity, and provider identity are built before R4. R4 is real, scheduled work — it just isn't the first sale. (Track B, where R4 leads, is retained below only as the contingency if the GTM shifts to local per-user agents.)

**Track A — server-side agents using org tools · BUILD THIS ORDER:**

| # | Work item | Closes | Depends on |
|---|---|---|---|
| 1 | **F7 — mandatory accountable owner** (require at SA creation; snapshot owner into every audit row) | F7 | none — ship now |
| 2 | **Schema hardening + refresh lock + F8 provider-status audit** (workspace_id + partial uniques; advisory-lock refresh; authz/provider/action outcome triad) | F8, schema, refresh race | schema wipe window |
| 3 | **F1 — GitHub App / bot-credential support** (installation-token auth method + adapter) | F1, F2 | connection auth-method extension |
| 4 | **F3 — action-input constraints** (per-assignment predicate: owner/repo allowlist) | F3 | none |
| 5 | **R4 — user consent + per-user connections** | F4, F6; per-user Google, local agents | XAA engine (done) |
| 6 | **F5 — group/subject policy at the broker** | F5 | R4 |

**Track B — contingency only (local per-user agents first):** if the GTM shifts, promote R4 to #1 (it unblocks the entire topology), then F7 → schema/F8 → F1 → F5 → F3. Not the current plan.

**Cross-cutting (D6, decided):** land the one-line "same-workspace only" grant guard (closes F9) as part of item #1's grant-flow work — cheap, and it removes an undefined path before anything else touches grants.

### Target audit row (the north star)

```json
{
  "action": "github.listCommits", "latency_ms": 895,
  "authz_outcome":   "allow",           // did the broker permit the attempt (F8)
  "broker_status":   200,               // broker-side result; 403/404/424 on deny-before-call (F8)
  "provider_status": 200,               // real upstream HTTP status; null if broker denied (F8)
  "action_outcome":  "success",         // success | provider_error | policy_deny (F8)
  "actor":   { "client_id": "coding-agent", "spiffe_id": null },   // agent: Actor.client_id ?? ClientID — always
  "owner":   { "email": "priya@acme.com", "team": "platform" },    // accountable human — always (F7)
  "subject": { "sub": "alice@acme.com", "via": "xaa" },            // on-behalf-of — when human-triggered (R4)
  "connector": "github-eng", "token_family": "xaa"
}
```

Today we emit a single `allow`/`deny` + HTTP 200, and only actor + partial subject. F8 splits the outcome triad (authorized vs. succeeded); F7 adds owner-always; R4 makes subject real for server-side agents. That row is the entire product thesis in one record: which agent, on whose behalf, authorized by whom, did what, and whether it actually worked.

---

## 10. Resolved decisions

These were the open calls; they are now **decided** and are binding for the build. Rationale kept so the reasoning survives.

| # | Decision | **Resolved** | Rationale |
|---|---|---|---|
| **D1** | Accountability model | ✅ **"Owner always, subject when human-triggered."** Owner is required on every agent; subject is present only for delegated calls. | Guarantees the north-star audit row has an accountable human on every action. Makes **F7 a must-ship.** |
| **D2** | GitHub connector granularity | ✅ **Connector-per-GitHub-org-installation.** | Orgs become natural blast-radius boundaries; cleaner audit and assignment semantics; credentials differ per installation anyway. |
| **D3** | Teams vs. workspaces | ✅ **Teams = groups within one workspace.** Workspaces are reserved for real isolation (subsidiaries, prod/staging). | A workspace carries its own broker RS, connectors, and audit — too heavy for a team boundary. |
| **D4** | Local-agent-with-shared-secret | ✅ **Blocked/undocumented until R4.** Local agents are officially unsupported until the public-client + SSO + XAA recipe ships. | Prevents teams improvising secret-sharing — the exact anti-pattern the product exists to eliminate. |
| **D5** | Build track / priority order | ✅ **Track A — "server-side agents using org tools."** Build order: F7 → schema+F8 → GitHub App (F1) → action-input constraints (F3) → R4 → group policy (F5). | This is the credible initial enterprise story and front-loads the cheap, high-value credibility wins. R4 is real work but not the first sale; it lands at ~#5. |
| **D6** | Cross-workspace grants | ✅ **Same-workspace-only for now.** Reject a foreign `client_id` at grant time with a clear error (closes F9 cheaply). | A true cross-workspace trust path is the A2A case; design it later on the existing XAA first-contact-approval machinery, not an ad-hoc binding. |

> **Net effect for the builder:** the roadmap in §9 **Track A is the plan of record.** Start at F7, and treat D1–D6 as settled constraints rather than open questions. Each numbered item still gets its own `SPEC-*` doc (endpoints, DDL, acceptance criteria) before coding — this document is the north star and the "why," not the line-by-line build sheet.

---

*Grounded in: the live single-node deployment (M2M flow proven 2026-07-08, `audit_events` #150–156), `authsec@authsec-staging` code (connector broker controller, oauth service, XAA/ID-JAG token engine, service-account provisioning), provider auth models (GitHub Apps vs OAuth Apps, Slack bot tokens, Google per-user OAuth vs domain delegation), and the 2026 agentic-identity literature (Strata, Entrust, IBM, "Authenticated Delegation and Authorized AI Agents" arXiv 2501.09674, "The Start Button Problem" arXiv 2501.12498). Companion documents: SPEC-connectors.md, connectors-infra-handoff.md.*
