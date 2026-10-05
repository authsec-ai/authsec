# SPEC — Console revamp: four screens, one Discovery, the object card

Status: **proposed** — design locked here before any implementation
(build sequence: plan → UI/UX → backend). Nothing below is implemented;
sections say what exists today where that matters.

## Summary

The IGA console grew one sidebar entry per data source and per governance
feature. A reader has to know AuthSec's internals to pick a screen: raw
inventory versus graph, sightings versus workloads, five governance pages
over one fragile policy backend. This revamp collapses the console to four
screens — **Accounts & clusters**, **Discovery**, **Policy**, **Logs** —
puts every discovered object behind one search with one set of filters, and
replaces the flat detail headers with an **object card** that explains an
object the way a trading card explains a creature: what it is, what it can
do, what to watch out for, where it came from.

Policy and Logs ship as **previews on sample data** until their backends are
dependable. They are drawn as the target screens so nothing is thrown away.

## Scope

In scope
- Sidebar and routing: four entries; every old route redirects; no dead links.
- Accounts & clusters: the connections table, reduced to what an operator
  decides from.
- Discovery: one screen over workloads, identities, resources and agent
  sightings, from every source, with an "as collected" view of the raw rows.
- The object card, in three sizes, and the object page header built on it.
- Policy and Logs preview screens on fixtures, labelled as such.
- The backend contract gaps the above needs (§Backend spec).

Out of scope
- New collection, new graph semantics, new governance behaviour.
- Deleting governance pages or their routes (see *Governance* below).
- Real Policy / Logs backends.

Governance. The five governance pages (Agent policies, Scheduled actions,
Policy warnings, Provenance, Access Certification, Separation of Duties,
Birthrights & Lifecycle, Enforcement queue) leave the sidebar. Their routes
and pages stay reachable by URL and keep working — the workspace rule is to
preserve governance functionality, and hiding navigation preserves it while
deleting pages would not. They fold into Policy and Logs when those are real.

## Affected repos

| Repo | Change |
|---|---|
| `Authsec-ui` | Sidebar, routes and redirects; Accounts & clusters page; Discovery page; `ObjectCard`; object page headers; Policy and Logs previews with fixtures |
| `authsec` | Three read-API additions (§Backend spec); no schema change |
| `authsec/.claude/specs/SPEC-iga-phase2-graph.md` | §2.14.2 navigation table points here |

## Information architecture

### The four screens

| Sidebar | Route | Question it answers | Replaces |
|---|---|---|---|
| **Accounts & clusters** | `/iga/sources` | What is connected, is it healthy, when did it last report? | Integrations; Detection Rules (moves inside a GitHub organisation) |
| **Discovery** | `/iga/discovery` | What has been found, and what can each thing do? | Agents & workloads, Cloud Inventory (3 tabs), Agent sightings, Kubernetes access, the Identities and Resources lists |
| **Policy** | `/iga/policy` | What have we decided should be true, and is it? | Agent policies, Policy warnings, Scheduled actions, SoD, Certification, Birthrights (later) |
| **Logs** | `/iga/logs` | What happened, when, by whom? | Provenance, Enforcement queue (later) |

Object pages keep their routes (`/iga/estate/:id`, `/iga/identities/:id`,
`/iga/resources/:id`, `/iga/external-principals/:id`, `/iga/integrations/:id`)
and are reached from Discovery and Accounts & clusters. Their breadcrumb reads
*Discovery › Workloads › refund-agent*.

Redirects (all `replace`): `/iga/integrations` → `/iga/sources`;
`/iga/estate`, `/iga/cloud`, `/iga/cloud/*`, `/iga/agents`, `/iga/k8s-access`,
`/iga/identities`, `/iga/resources` → `/iga/discovery` with the matching
`type=` and `view=` (below); `/iga/detection-rules` →
`/iga/sources?open=github-rules`.

### Why these four

- One screen per *verb*: connect, find, decide, review. A reader never has
  to know whether a thing lives in a raw table or the graph.
- Governance is a family of decisions over discovered objects, so it is one
  screen (Policy) with the objects linked, not seven screens the objects
  link to.
- Logs is where "what did AuthSec do about it" lives, which today is split
  across Provenance, Enforcement queue and scan histories.

## Screen 1 — Accounts & clusters

Title *Accounts & clusters*; subtitle *Connected AWS accounts, GCP projects,
Kubernetes clusters and GitHub organisations, and whether each is reporting.*
Primary action (white-on-blue): **Add account or cluster** → the existing
provider picker (AWS Quick Create / role ARN, GCP, Kubernetes agent, GitHub).

Table (fitted, no horizontal scroll), one row per connection:

| Column | Content | Why it is on the row |
|---|---|---|
| **Name** | Display name; id in mono under it (account id, project id, cluster, org); provider glyph | Identify |
| **Type** | AWS account · GCP project · Kubernetes cluster · GitHub organisation | Scan |
| **Status** | One word: *Connected* · *Needs attention* · *Revoked* · *Never scanned*. Hover: the cause in one sentence (the connector's stored error code, D-connector-error-code) | Decide whether to act |
| **Last scan** | Relative time and outcome: *Published* · *Failed* · *Running* · *Queued* | Freshness |
| **Coverage** | A state, never a percentage: *Complete* · *Partial — 2 surfaces* · *Denied — IAM* · *Unknown*. Hover: the surfaces | Whether to trust the result |
| **Scope** | *3 regions* · *all namespaces* · *12 repositories* | What it looks at |
| ⋯ | Scan now · Verify · Edit scope · Open · Revoke | Act |

Removed from the row: *Cadence* (every cloud source is on demand; it said
nothing), *Agents* and *Detail* (always "—"). Filters: Type chips, Status
chips, search. Row click opens the source's own panel (the existing AWS /
GCP connector drawers, the Kubernetes integration page, the GitHub
repository panel) — those stay; their headers adopt the card's facts row.

Detection Rules becomes **Scan rules** inside a GitHub organisation's panel
(it only ever applied to repository scans), with a secondary link from this
page's header menu for operators who look for it.

Empty state: *No account or cluster is connected yet. Connect one to start
discovering.* with the Add button. Loading, failed and empty stay distinct
(`AdaptiveTable` `loading` / `failure` / `emptyState`).

## Screen 2 — Discovery

### Mental model

One inventory of everything found. Three layers of narrowing, always in
this order and always visible: **what** (object type) → **where** (source,
account, region, cluster) → **state** (lifecycle, classification,
type-specific facets). One search box, server-side over the chosen type.

### Layout

```
Discovery                                   as of 29 Sep 16:30 · Refresh ↻
[ Search workloads by name, ARN or account                                 ]
( Workloads 10 ) ( Identities 77 ) ( Resources 14 ) ( Sightings 0 )  view: Graph | As collected
┌ Filters ──────────┐ ┌ list ───────────────────────────────────────┐ ┌ card ─────┐
│ Source             │ │ Name · where · what it runs as · last seen  │ │ ObjectCard│
│  ☐ 429418377036 8  │ │ …                                           │ │ compact   │
│  ☐ Akash (revoked)2│ │                                             │ │           │
│ Lifecycle          │ │                                             │ │ Open →    │
│ Classification     │ │                                             │ │ Graph →   │
│ Runtime            │ └─────────────────────────────────────────────┘ └───────────┘
└────────────────────┘
```

- **Type switcher** (segmented, with server counts): Workloads · Identities
  · Resources · Sightings. The URL carries `type=`. Counts are the graph
  lists' `total` (exact up to 10 000, else "10 000+", §5.2).
- **Filter rail**, collapsible, facets with server counts
  (`facets=` on the graph lists). Common: Source (account / project /
  cluster / org, with Revoked marked), Region, Lifecycle (Current · Stale ·
  Ended), Classification (Agent · Unclassified · Provider-native agent).
  Per type: Workloads — Runtime (Lambda, ECS, EC2, Bedrock agent, AgentCore,
  Kubernetes), Attribution (runs as a known identity / unattributed);
  Identities — Kind (Role · User · Group · Service account), Bindings (bound
  to a workload), Unused access; Resources — Kind (Exact · Selector ·
  External), Sensitivity, Named by a Deny; Sightings — Decision needed ·
  Registered · Quarantined · Ignored, Live only.
- **List**: fitted table, primary column the name with its kind and where it
  lives under it; the other columns are the type's three most decisive facts
  (Workloads: runs as · declared reach · last confirmed; Identities: bound
  workloads · policies · last confirmed; Resources: holders · kind ·
  account). Row click selects and opens the **compact card** at the right;
  Enter or double-click opens the object page; the card's *Graph* opens the
  object's graph tab.
- **View: Graph | As collected** (Workloads, Identities, Resources only).
  *Graph* is the canonical list — what AuthSec concluded, at a revision.
  *As collected* swaps in the raw rows of the same type from the last scan
  (today's Cloud Inventory tabs), keeping Source and Kind filters, and says
  so in one line: *Raw rows from the last scan, as the provider returned
  them. The graph view is what AuthSec concluded from them.* It exists to
  audit a scan and to see rows not yet in the graph (the lookup link
  "Open in graph" stays on each raw row).
- **Sightings** are the discovered-agents workflow (repositories, clusters):
  the row's card carries its decision actions (Claim · Provision ·
  Quarantine · Ignore) with the honest outcome copy already in place
  ("Quarantine recorded; it takes effect only where actuation is enabled").
- **Kubernetes** workloads appear under Workloads with Source = cluster and
  Runtime = Kubernetes; the chain workload → ServiceAccount → binding → role
  → rule is that workload's Graph tab and Identities tab. Needs backend gap
  B1 below; until then the Kubernetes facet is served by the existing
  `k8sGraphApi` routes behind the same UI, and the screen says when a
  cluster has not reported.
- **Freshness**: the header shows the publication the list is pinned to and
  a *Refresh* when a newer scan has published (existing `RevisionBanner`
  behaviour, moved into the header).

### What Discovery never does

Mix revisions in one list; show a count as exact when it is capped; call a
declared path effective access; hide a row because collection failed (it
shows the coverage state instead); call a stale row ended.

## Screen 3 — the object card

One component, `ObjectCard`, three sizes: **hero** (object page header),
**compact** (Discovery and graph selection), **tile** (hover / list
preview). Same anatomy, fewer rows as it shrinks. The analogy is a trading
card: a reader who has never seen the object learns what it is, what it can
do and what to be careful of in one look — without the card inventing a
score.

| Card part | Trading card | AuthSec card | Source |
|---|---|---|---|
| Frame colour | Element type | Category: workload / identity / resource / external — the `--color-object-*` tokens | kind |
| Portrait | Picture | **Neighbourhood sketch**: an SVG of ≤ 7 nodes — the object, what it runs as (or who runs as it), its top declared targets — drawn from the detail payload already loaded; click → Graph tab | detail + first identities / resources page |
| Name and stage | Name · stage · HP | Name · kind (*ECS task definition*, *IAM role*, *S3 selector*) · where (account label + id, region) · provider glyph | detail |
| Stat bar | HP / attack / defence | 3–4 counts, each exact or "N+", each a link to its tab. Workload: identities it runs as · resources it can reach (declared) · accounts crossed · days since confirmed. Identity: workloads bound · policies · statements (Allow / Deny) · roles it may assume. Resource: identities that reach it · statements naming it · excluded by · resource-policy Deny? | `used_by_count`, list totals, `named_by_count`, `excluded_by_count`, `resource_policy` |
| Moves | Attacks with cost | **Can do** — the top three declared capabilities in words with their action chips: *Invoke function:refund-tools* (`lambda:InvokeFunction`) · *Read s3://support-tickets/\** (`s3:GetObject` +2) · *Assume 2 roles*. "+N more" → Resources tab | grant lines / permissions |
| Weakness and resistance | Weakness / resistance | **Watch out** — honest qualifiers, each a link to its evidence: *Deny statements present* · *Conditions recorded, not evaluated* · *Stale since 3 Oct* · *Execution role not in inventory* · *Account coverage partial* · *Trust uses NotPrincipal* | limitations, lifecycle, coverage, `execution_role.state`, `provider_attrs.trust_*` |
| Flavour text | Italic lore | One plain sentence built from facts, same template every time: *An ECS task definition in 429418377036. It runs as RefundTaskRole, which a policy declares may invoke function:refund-tools. Declared access — not evaluated.* | composed client-side from the facts above |
| Set number | Set / number | ARN (copy) · source account · last confirmed · graph revision | detail, `meta.rev` |

Rules the card obeys
- Every number is a count the API returns, with its exactness; no derived
  "risk score", no colour that means danger. Red is reserved for *failed*.
- *Declared access — not evaluated* is always on the card, once.
- *Stale* and *ended* are visibly different from *current*, and from each
  other, and the card says since when.
- The portrait draws only loaded data; it never fetches to decorate. When
  nothing is loaded yet it shows the object alone with *Loading its
  neighbourhood…*, never an empty frame.
- Compact and tile drop rows in this order: set number → flavour → moves →
  portrait. The stat bar and Watch out stay to the smallest size.

Object pages: the hero card replaces today's one-row header; the Overview
tab below it keeps the panel layout (Panel / Facts) with the sections that
the card does not already say. The Graph, Identities, Resources, Changes
tabs are unchanged.

## Screen 4 — Policy (preview)

Banner on every Policy view: **Preview — sample data. Nothing here is
evaluated or enforced yet.** No API calls; fixtures in
`src/features/iga/policy/fixtures.ts`, shaped on
`SPEC-iga-phase3-policy-requirements.md` so the screens are the target UI.

- **Policies list**: Name · Applies to (a scope sentence: *ECS tasks in
  429418377036*) · Governs (in words: *which roles a workload may run as*) ·
  Mode (*Observe* · *Enforce*) · Status (*Active* · *Draft* · *Paused*) ·
  Last evaluated · Findings (count, link).
- **Policy detail**: the rules in plain English with the technical form
  underneath; the objects it applies to (object cards, tile size); findings
  (object · rule · since · state); history (who changed what, when).
- **Findings** tab across policies, filterable by policy, source, object
  type.
- Actions exist on screen but are disabled with *Preview* tooltips, so no
  control looks operational and does nothing.

## Screen 5 — Logs (preview)

Banner: **Preview — sample events.** Fixtures in
`src/features/iga/logs/fixtures.ts`.

- One **timeline** of events with a kind glyph and a one-line sentence:
  scan queued / running / published / failed; graph revision published;
  classification decided; sighting claimed / quarantined; enforcement
  applied / failed; grant appeared / ended; sign-in. Grouped by day.
- Filters: kind, source, actor, object, time range. Search.
- Event drawer: the facts, the actor, the objects (tile cards), *Open the
  object*, and the raw record collapsed.
- Export disabled with a *Preview* tooltip.

## Backend spec (authsec)

No schema change. Three read additions, each scoped by the authenticated
workspace, revision-pinned where the graph is involved:

| # | Addition | Consumer | Contract |
|---|---|---|---|
| B1 | **Provider facet on graph lists** | Discovery Kubernetes facet | `/api/iga/v1/workloads`, `/identities`, `/resources` accept `provider=aws\|k8s` (default: all providers the workspace has) and return a `provider` facet; today the lists hard-code `provider = 'aws'` (`internal/igaread/lists.go`). Kubernetes rows carry `provider: "k8s"` and their cluster as the source |
| B2 | **Type counts** | Discovery type switcher | `GET /api/iga/v1/summary` → `{ workloads, identities, resources, sightings: Exact }` at the pinned revision, honouring the same filters as the lists; one call instead of four `limit=1` reads |
| B3 | **Source health row** | Accounts & clusters | `GET /authsec/discovery/sources` (all providers) adds `status_reason_code`, `last_scan: {at, outcome}`, `coverage: {state, surfaces_short}`, `scope_summary`; the AWS and GCP connector lists already hold these fields in different shapes |

Everything else Discovery, the card and the object pages need is served
today (§5.3 of the graph spec, the discovery list routes, `/lookup`).

## Frontend spec (Authsec-ui)

New: `features/iga/sources/SourcesPage.tsx`; `features/iga/discovery/`
(`DiscoveryPage.tsx`, `TypeSwitcher.tsx`, `FilterRail.tsx`, lists per type
reusing today's columns, `AsCollectedView.tsx` wrapping the Cloud Inventory
tables); `features/iga/shared/components/ObjectCard/` (`ObjectCard.tsx`,
`NeighbourhoodSketch.tsx`, `cardFacts.ts` — the per-type fact derivations
and the flavour-sentence template); `features/iga/policy/` and
`features/iga/logs/` previews with fixtures.

Modified: `IgaSidebar.tsx` (four entries), `App.tsx` (routes + redirects),
`WorkloadPage` / `IdentityPage` / `ResourcePage` / `ExternalPrincipalPage`
(hero card header), `Breadcrumb.tsx` (labels), the connector drawers
(facts row).

Removed from navigation only: governance entries, Detection Rules, Agent
sightings, Cloud Inventory, Kubernetes access, Identities, Resources.
No page file is deleted in this revamp.

Conventions: `ConsolePage`; primary buttons white-on-blue
(`text-[length:var(--text-sm)] text-white`); every `SheetContent` has a
title and description; RTK Query via `baseApi.injectEndpoints`; URL carries
list state; `npx tsc -p tsconfig.app.json --noEmit`, eslint and `vite build`
with no new diagnostics; no new tests unless asked.

## Acceptance criteria

1. The sidebar shows exactly Accounts & clusters, Discovery, Policy, Logs.
   Every URL that existed before redirects to the right place with its
   filters; no 404 and no dead link in the console.
2. Accounts & clusters lists every connected source of every provider with
   Name, Type, Status, Last scan, Coverage, Scope; Cadence, Agents and
   Detail are gone; row actions work as before; Add opens the provider
   picker.
3. Discovery: switching type changes the list, the facets and the search
   placeholder, and the URL reproduces the view; facet counts match the
   list's total; *As collected* shows the raw rows for the same source and
   kind and says what it is; a Kubernetes workload is found under Workloads
   (B1) or the facet says the cluster has not reported.
4. Selecting a row shows the compact card with correct counts (checked
   against the object page's tabs for three objects of each type), a
   portrait drawn from loaded data, Watch out items that each open evidence,
   and the declared-not-evaluated line.
5. Object pages open from Discovery with the hero card; the Graph tab is
   unchanged; the breadcrumb reads Discovery › type › name and returns to
   the filtered list.
6. Policy and Logs show the preview banner, make no network calls, and have
   no control that appears to act.
7. Governance pages still load by direct URL.
8. Checks pass with no new diagnostics; an authenticated dry run of 1–7 on
   `app.authsec.ai` is recorded with screenshots before the work is called
   done. A passing build is not usability.

## Implementation plan

| Phase | Work | Done when |
|---|---|---|
| 0 | This spec reviewed and locked; §2.14.2 of the graph spec points here | Sign-off |
| 1 | Shell: sidebar, routes, redirects, breadcrumb labels; Policy and Logs placeholders with the preview banner | Every old URL lands somewhere right |
| 2 | Accounts & clusters on today's connector lists; B3 proposed to the backend, UI tolerant of its absence | Criterion 2 |
| 3 | Discovery: type switcher, filter rail, per-type lists, compact card slot, As collected, Sightings; Kubernetes facet on `k8sGraphApi` until B1 | Criterion 3 |
| 4 | ObjectCard (compact, hero, tile), NeighbourhoodSketch, cardFacts; object page headers | Criteria 4–5 |
| 5 | Policy and Logs previews on fixtures | Criterion 6 |
| 6 | Backend B1–B3 land; Discovery switches to them | Kubernetes rows in the graph list; one summary call |
| 7 | Authenticated dry runs, fixes, report | Criterion 8 |

Each phase ends with the UI reviewer, `tsc`, eslint and the build, and the
user inspecting the deployed screen before the next phase starts.

## Open decisions

- Naming: *Accounts & clusters* (chosen here) vs *Sources* / *Connections*.
  GitHub organisations also live there; the subtitle says so.
- Whether the filter rail is a left rail (desktop) collapsing to a sheet, or
  a top row of popover facets. Left rail is drawn here because the facet
  count is large.
- Whether governance routes get a small *More* entry at the foot of the
  sidebar for operators, or stay URL-only until Policy / Logs are real.

## Related docs

- `SPEC-iga-phase2-graph.md` §2.14 (experience), §5.3 (read API),
  §5.7 (proposed reads)
- `SPEC-iga-phase3-policy-requirements.md` (Policy preview shape)
- `SPEC-github-discovery.md` (scan rules), `SPEC-aws-quick-create-onboarding.md`
- `Authsec-ui/AGENTS.md` (console conventions)
