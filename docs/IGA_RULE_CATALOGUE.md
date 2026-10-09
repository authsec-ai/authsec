# GitHub agent discovery — detection rule catalogue

**Catalogue version: `1.0.0`** · implemented in `services/iga_provider.go` and
`services/iga_rules_v1.go` · fixtures in `services/iga_rules_fixtures_test.go`

> The catalogue version **is** the product's coverage claim. Bump it
> deliberately — and remember that bumping it **schedules a rescan**, because
> raw file bytes are discarded after parse and a corrected rule cannot be
> replayed over evidence we no longer hold.

---

## What a match proves, precisely

A match proves that **a file in a granted repository declares an agent**.

It does **not** prove the agent ran. It does not prove the agent still exists.
It does not prove the repository is active. Everything in this catalogue is
`declared` evidence, never `observed`.

## How a match becomes a finding

Per repository, once:

1. One recursive git tree listing — every path
2. Match paths against rule globs — typically 5–50 candidates of 30,000
3. Fetch **only** the matched blobs
4. Parse; **redact values, keep names**
5. Persist normalised fields + blob SHA; discard raw bytes
6. CODEOWNERS, last match wins, for ownership attribution
7. Emit a sighting, fingerprint `gh:{repo_native_id}:{path}`

On a 30,000-file repository we read roughly a dozen files. That is what makes
the customer conversation survivable: we are not taking a copy of their source,
we are reading named configuration files.

---

## The rules

| Rule | Confidence | Evidence mode | What it reads |
|---|---|---|---|
| `workflow.agent-invocation` | **high** | invocation_declared | Named agent action or CLI, plus trigger set, permissions block, runner |
| `workflow.reusable-and-composite` | medium | invocation_declared | Calls into a reusable workflow or local composite action |
| `workflow.self-hosted-runner` | low | tool_configuration | `runs-on: self-hosted` — context, **not** detection |
| `manifest.agent-declaration` | **high** | deployment_declared | Name, model, tools, prompt **presence and length only** |
| `manifest.mcp-server-config` | **high** | tool_configuration | Server names, transport, declared tools, env var **names** |
| `container.dockerfile` | medium | framework_dependency | Framework install, base image, ENV **names** |
| `container.compose` | medium | deployment_declared | Service images matching a framework token |
| `dependency.python` | low | framework_dependency | Agent framework in a Python manifest |
| `dependency.node` | low | framework_dependency | Agent framework in a Node manifest |
| `dependency.go` | low | framework_dependency | Agent framework in `go.mod` / `go.sum` |
| `iac.terraform` | medium | deployment_declared | Agent/managed-AI resources **and IAM role references** |
| `iac.kubernetes-in-repo` | medium | deployment_declared | In-repo manifests — **the correlation hook** |
| `iac.helm-values` | medium | deployment_declared | Chart values naming a framework image |
| `secret.reference` | low | secret_reference | Provider credential **names**, never values |

**CODEOWNERS is deliberately not a detection rule.** It yields ownership
attribution, not detection, so emitting sightings from it would manufacture an
agent row for every CODEOWNERS file. It is consumed through
`ListCodeowners`/`MatchCodeowners` with GitHub's last-match-wins precedence and
attached to rows that real rules produce.

## The combination rule — the one that decides product quality

A **LOW** signal alone is a **candidate**, never an agent. **Two independent**
LOW signals in the same repository promote to MEDIUM. Only **HIGH** may enter
the agent count (`CountsAsAgent`). Two matches of the *same* rule id count once
— independence is what makes the promotion meaningful.

Rationale, and it cuts both ways: for cluster admission, leaning permissive is
right, because a false positive costs one Ignore click and a miss is an
ungoverned agent. That trade is **wrong** here. A repository scan produces far
more candidates than an admission webhook, and an inventory carrying hundreds of
junk rows gets abandoned — at which point every real finding is missed too.

> **Be permissive about what you RECORD. Be strict about what you COUNT.**

---

## Known over-matching — documented, not hidden

Matching is case-insensitive substring, which is the right trade for recall and
has consequences. A customer who finds a false positive we already documented
trusts us more; one who finds an undocumented one stops trusting the number.

| Case | Behaviour | Fixture |
|---|---|---|
| A framework named only in a **comment** | **Fires.** A commented-out `vllm` still matches. | `container.compose/ADVERSARIAL` |
| A framework in a **disabled** Helm block | **Fires.** A declaration exists; whether it is enabled is runtime state. | `iac.helm-values/ADVERSARIAL` |
| A framework as a **dev-only** dependency | **Fires at LOW.** May be imported by nothing — which is why one LOW is never an agent. | `dependency.python/ADVERSARIAL` |
| **Generic** credential names (`API_TOKEN`, `APP_SECRET`) | **Fires, self-labelled** `noise_risk: high`. Matches ordinary applications too. | `secret.reference/ADVERSARIAL` |
| A lockfile-only framework entry | **Fires.** A lockfile entry is still a declaration of what the build pulls in. | `dependency.go/ADVERSARIAL` |

**Deliberately *not* over-matched.** The vocabulary is package and action names,
never bare words. `claude` in a comment is not `claude-code-action`; the token
`agent` is never used bare, because it appears in `user-agent`, `agent-pool`,
and every CI runner on earth.

## False negatives — blind spots no repository rule can see

State these in any coverage conversation. Sales must never imply otherwise.

- A framework installed **at build time** into a generically-named base image
  *(asserted by `container.dockerfile/ADVERSARIAL` so it stays honest)*
- A credential read from a **mounted file** rather than a named env var
- A credential fetched **at runtime** from Vault or a cloud secrets manager
- Env vars supplied via `envFrom`, where the key name never appears at all
- A **self-hosted model endpoint** with no recognisable credential name
- An agent invoked **by a human from a laptop** against the repo's API
- Anything in a repository the installation **was not granted**
- Anything in a **private fork** outside the organisation

The first and last matter most. The first is inherent to static analysis and
closes only with **runtime evidence** — a different source kind, not a better
rule. The last is inherent to the consent model, and is the correct trade: we
read only what the customer granted, and we say so.

## Per-rule failure notes

- **`workflow.agent-invocation`** — misses a workflow that shells out to an
  agent through a wrapper script; the marker is in the script, not the workflow.
- **`workflow.reusable-and-composite`** — a reusable workflow in a repository we
  were **not** granted is unreadable, so its callers resolve to an unknown
  target. Reported as `target_resolution: unresolved`, never as clean.
- **`manifest.agent-declaration`** — any parseable JSON at a manifest path
  fires, because the path itself is the declaration. Malformed JSON yields
  nothing rather than a guess.
- **`manifest.mcp-server-config`** — the globs claim every editor settings file,
  so the content test (an `mcpServers`/`servers` map) is what prevents an editor
  preference becoming an agent.
- **`iac.kubernetes-in-repo`** — requires `apiVersion` + `kind` before matching,
  which is what stops it claiming every YAML file in the directory.
- **`secret.reference`** — only `_API_KEY`, `_TOKEN`, `_SECRET` suffixes are
  harvested, so a provider credential named outside those shapes is invisible.

---

## Vocabulary ownership — decided

The same detection vocabulary is needed by **three** consumers: this repository
scanner, the Kubernetes admission collector, and agent-shield's per-command risk
scoring. Built independently they will diverge, and drift shows up as one channel
silently missing what the others catch — which reads to a customer as a product
bug, not a synchronisation problem. It also breaks the `iac.kubernetes-in-repo`
correlation hook, which requires the repo scanner and the cluster collector to
agree on what an agent looks like.

**Decision: a control-plane-served artefact with a compiled-in fallback**, and
the fetch must refuse an empty or unsafe payload so detection can never get
*worse* because a fetch failed.

**Current state:** the compiled-in fallback exists and is authoritative —
`agentFrameworkTokens`, `agentActionMarkers` and `providerCredentialNames` in
`services/iga_provider.go`, shared by both the `/api/iga/v1` pipeline and the
repo-scan channel through one `IGARuleCatalog`. The served-artefact half is
**not built**. Until it is, the two in-process consumers cannot drift, but
agent-shield is not yet wired to this source.

## Rescan consequence — design for it

Raw bytes are discarded after parse; only normalised fields and the provider
blob SHA are retained. This is the right privacy decision and the reason a
security review can pass. It has a cost that must be planned for, not discovered:

> **A rule or parser fix cannot be replayed over stored evidence. It requires a
> rescan.**

`rule_id` and `rule_version` on every observation identify *which* findings a
corrected rule produced, so a retraction can be precise. The rescan
infrastructure that actually re-derives them is AS-113. Both halves are
required — one without the other leaves stale findings with no path to
correction.

---

## The coverage claim

This is the text that may be used externally, and nothing beyond it.
**PM sign-off is still outstanding (AS-115).**

> We detect AI agents **declared** in the repositories you grant us — in CI/CD
> workflows, agent manifests, MCP server configurations, container and compose
> files, infrastructure-as-code, and dependency manifests. We report the secrets
> they reference **by name**, the permissions they are granted, and their code
> owner.
>
> We do not read repositories you have not granted. We do not retain your source
> code. We report what your organisation has **written down** that it intends to
> run — which is not the same as what is currently running.

## Verifying the catalogue

```bash
go test ./services/ -run 'TestRuleCatalogueFixtures|TestEveryRuleHasThreeFixtures|TestCombinationRule' -v
```

These are **unit** tests by design. The integration suite only runs when
`IGA_TEST_DSN` is set, so a catalogue regression would otherwise sail through an
ordinary `go test ./...`. `TestEveryRuleHasThreeFixtures` fails the build if any
rule ships with fewer than three fixtures, because an unfixtured rule is an
unmeasured coverage claim.
