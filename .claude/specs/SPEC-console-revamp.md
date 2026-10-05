# SPEC — Console revamp: four destinations, one Discovery, honest summaries

Status: **proposed, revision 2** — design to lock before implementation.
Nothing below is implemented. Where today's code matters, the text says
what exists and where.

Fixed by decision: the four primary destinations — **Connections**,
**Discovery**, **Policy**, **Logs**. Secondary and detail screens are
unrestricted. The legacy governance screens are **removed**, not hidden.
New Policy functionality is outside this spec: it reserves the destination
and fixes the preview boundary, nothing more.

## Summary

The console grew one sidebar entry per data source and per governance
feature, so a reader had to know AuthSec's internals to pick a screen. This
revamp gives the console four destinations, one per task — connect, find,
decide, review — and puts the structure under them where it belongs: in
explicit secondary screens, one interaction rule, honest counts, and
summaries that never say more than the evidence does.

## Scope

In scope
- Sidebar and route map: four destinations; every earlier URL redirects
  with its parameters; retired pages show a retirement state.
- Removal of the legacy governance screens (contract below).
- Connections: a readiness model per connection, a first-success journey,
  coverage as a proper secondary screen.
- Discovery: provider-scoped, with a read contract per provider and object
  type, precise filter and count semantics, and a published / latest-
  collected view.
- Three summary compositions (list preview, detail header, graph inspector)
  with trustworthy facts.
- Responsive and investigation-context contracts for every list and
  detail.
- Logs preview boundary; Policy reserved destination and preview boundary.
- The backend dependencies, field by field.

Out of scope
- New collection, new graph semantics, new governance or policy behaviour.
- Backend retirement of governance workers, tables or records — a separate
  disposition; removing screens does not authorise it.
- The graph canvas design (§2.14.11 of the graph spec stands); only its
  regression checks are here.

## Removal contract — legacy governance screens

Remove the legacy governance screens from navigation, routing, search
results, contextual actions and internal links: Agent policies
(`/iga/policies`), Scheduled actions (`/iga/upcoming`), Policy warnings
(`/iga/policy-warnings`), Provenance (`/iga/provenance`), Access
Certification (`/iga/certification`, `/iga/certification/:id`), Separation
of Duties (`/iga/sod`), Birthrights & Lifecycle (`/iga/birthrights`),
Enforcement queue (`/iga/enforcement`).

- Their page components under `features/governance/` and their data hooks
  are removed **after checking shared consumers**. Today those consumers
  are: `App.tsx` (routes), `app/api/governanceApi.ts` (mutations also used
  by `features/discovery/ClaimAgentDialog.tsx` — claim and quarantine — and
  `features/discovery/EnforcementStatusCard.tsx`), and
  `features/governance/ActuationTokenDialog.tsx` (used by the Kubernetes
  integration page to mint an agent token — that is connection setup, not a
  governance screen, and moves to `features/discovery/`). The API slice
  keeps only the endpoints a retained consumer calls.
- Old bookmarks land on a **retired-page state**: the page title, one
  sentence (*This screen was retired. Decisions over discovered objects
  live under Policy; activity under Logs.*), and links to Discovery,
  Policy and Logs. It renders nothing of the old functionality and makes
  no governance API call.
- No search result, breadcrumb, row menu or detail-page link may reach a
  retired screen. The global search index and `Breadcrumb.tsx` labels for
  those segments are removed.
- Backend workers, tables and customer records are untouched by this spec.

## Information architecture

### Primary destinations

| Sidebar | Route | Task |
|---|---|---|
| **Connections** | `/iga/connections` | What is connected, is it reporting, is its data usable? |
| **Discovery** | `/iga/discovery` | What has been found, and what can each thing do? |
| **Policy** | `/iga/policy` | Reserved. Preview boundary only (below) |
| **Logs** | `/iga/logs` | What happened, when, by whom — preview |

"Connections" rather than "Accounts & clusters": it covers AWS accounts,
GCP projects, Kubernetes clusters and GitHub organisations without
straining. The subtitle names them.

### Secondary screens

| Primary | Secondary experiences (stable URLs unless marked drawer) |
|---|---|
| Connections | Add connection (provider picker → provider setup: AWS Quick Create / role ARN, GCP, Kubernetes agent, GitHub); connection detail `/iga/connections/:id` with tabs Overview · Scans · Coverage · Scope; scan detail `/iga/connections/:id/scans/:runId`; scope editor (drawer); scan rules for a GitHub organisation (`/iga/connections/:id/rules`) |
| Discovery | Workload detail `/iga/estate/:id` (Overview · Identities · Resources · Graph · Changes); identity detail `/iga/identities/:id`; resource detail `/iga/resources/:id`; external-principal detail `/iga/external-principals/:id`; sighting detail `/iga/sightings/:id`; the graph tab on each; evidence panel (`evidence=`, beside the content) |
| Policy | Reserved; outside this spec |
| Logs | Event detail (drawer) within the preview |

### One interaction rule

- **Row selection** (click, Space): quick inspection in place — the list
  preview opens beside the list; the list keeps its state.
- **Name link / Open details** (click the name, Enter on the row, the
  button in the preview): navigates to the stable detail URL.
- **Drawer**: one focused question or a short inspection (a scope editor,
  an event, a connector's facts).
- **Detail page**: investigation — history, relationships, evidence,
  multi-step configuration.
- Double-click is never the only way to open anything. Every action is
  reachable by keyboard and by a visible control; nothing depends on hover.

### Breadcrumb

The breadcrumb describes the route hierarchy and every segment is a link
that restores what it names: *Discovery › Workloads › refund-agent* — where
*Workloads* returns to Discovery with the type, filters, sort, page and
selection the reader left (the list state lives in the URL and in history
state; `listHrefWithFilters` already does this for the graph lists).

### Route map and redirects

Every earlier URL redirects (`replace`) and **carries its query string**,
the way `CloudInventoryRedirect` in `App.tsx` does today — never a bare
redirect that drops an account or tab parameter:

| From | To |
|---|---|
| `/iga/integrations`, `/iga/integrations/:id` | `/iga/connections`, `/iga/connections/:id` |
| `/iga/detection-rules` | `/iga/connections?open=github-rules` |
| `/iga/estate` | `/iga/discovery?provider=aws&type=workloads` (+ its filters) |
| `/iga/cloud`, `/iga/cloud/identities` | `/iga/discovery?provider=aws&type=identities&view=latest` (`account=` carried) |
| `/iga/cloud/compute` | `…&type=workloads&view=latest` |
| `/iga/cloud/resources` | `…&type=resources&view=latest` |
| `/iga/identities`, `/iga/resources` | `…&type=identities` / `…&type=resources` |
| `/iga/agents` | `/iga/discovery?type=sightings` (`status=`, `live=` carried) |
| `/iga/k8s-access` | `/iga/discovery?provider=k8s&type=workloads` |
| governance routes above | the retired-page state |

Object detail routes are unchanged.

## Connections

### Readiness model

A connection has four independent conditions. "Connected" alone does not
say whether its data is usable, so the UI never collapses them into one
badge.

| Dimension | States (customer wording) | Source today |
|---|---|---|
| Connection | Connected · Authentication failed · Revoked · Not yet verified | `CloudConnector.status`, `verified_at`, `last_error` + stored error code; `DiscoverySource.enabled`, `last_status` |
| Latest scan | Queued · Running · Finished · Failed · Never run | `cloud_scan_run` list; `DiscoverySource.last_sync_at` / `last_status`; Kubernetes heartbeat |
| Coverage | Complete · Partial — *n* surfaces · Denied — *surface* · Unknown | `CloudConnector.coverage` (per-surface states); Kubernetes coverage state; GitHub: repositories in scope vs scanned |
| Graph | Published *12 min ago* · Publishing · Publication failed · Not published | `/api/iga/v1/pipeline` and `/coverage` (AWS); Kubernetes writes are unrevisioned (see Discovery) |

### Table

One row per connection, fitted to the available width (priorities under
*Responsive contract*):

| Column | Content |
|---|---|
| Name | Display name; the id in mono beneath only when no friendly name exists (never both when they are the same); provider glyph + provider word |
| Type | AWS account · GCP project · Kubernetes cluster · GitHub organisation |
| Status | The **primary condition** (the worst of the four, in words) and **one supporting line** that says what is missing and what to do: *Partial — IAM users not read. Grant iam:ListUsers and scan again.* The full four-way breakdown is on the connection's Overview tab, never only on hover |
| Last scan | Relative time + outcome (*Finished 6 days ago* · *Failed 2 h ago* · *Running*) |
| Graph | *Published 12 min ago* · *Not published* · *Publication failed* — distinct from the scan outcome |
| Scope | *3 regions* · *all namespaces* · *12 repositories* |
| Actions | Per provider capability (below); unavailable actions are absent, not disabled without explanation |

Removed: Cadence, Agents, Detail. Filters: Type, Status, search.

### Actions by provider

| Action | AWS | GCP | Kubernetes | GitHub |
|---|---|---|---|---|
| Scan now | yes (queues a run; 409 while one is live, said as *A scan is already running*) | yes | no — the agent scans on its own schedule; the row says *Reports every N min* | yes (repository scan) |
| Verify | yes | yes | no | yes |
| Edit scope | regions | projects | namespaces are the agent's config; link to the install values | repositories |
| Scan rules | — | — | — | yes |
| Mint agent token | — | — | yes | — |
| Revoke | yes | yes | yes (disconnect) | yes |

**Revoke** confirms with its consequences first: *AuthSec stops reading
this account. Everything already discovered is kept and marked as no
longer reconfirmed; nothing is deleted. The role in the customer's account
is not removed — do that in AWS.* **Edit scope** says what changes apply
from: *Regions apply from the next scan; rows from regions you remove are
kept and marked stale at the next publication.*

### First successful journey

connect → verify → choose scope → scan → publication → open Discovery.
The connection's Overview tab is a five-step tracker with each step's state
and its next action, so the operator never has to infer "is it ready?" from
timestamps. *Scan finished* and *Graph published* are two steps; the last
step's button is *Open in Discovery* and is enabled only when a publication
includes this connection.

### Coverage screen

`/iga/connections/:id/coverage` — a proper screen, not a tooltip: grouped by
account / cluster, then region / namespace, then collection surface, each
with its state word and sentence (*Denied — the role lacks
iam:GenerateCredentialReport*), what is missing because of it, and what the
operator can do. Technical detail (the API name, the error string) sits
behind an expansion on each row; the row leads with the consequence.

## Discovery

### Scope rule

Discovery is **provider-scoped** until the read contracts are equal. The
header carries a Provider control (AWS · Kubernetes · GCP · GitHub, only
providers with a connection); the default is the provider with the most
recent publication. A combination the provider does not collect shows an
explicit *Not collected for Kubernetes* state with the reason — **never an
empty list**. There is no "all providers" view until B1 lands; the control
says so.

### Supported object types per provider (today)

| Provider | Workloads | Identities | Resources | Sightings | Read model |
|---|---|---|---|---|---|
| AWS | yes | yes | yes | — | graph lists `/api/iga/v1/*` (revisioned, keyset-paged, facets, `q`); latest-collected rows via `/authsec/discovery/aws/*` |
| Kubernetes | yes | yes (ServiceAccounts) | — | yes (cluster sightings) | `/authsec/discovery/k8s/*` via `k8sGraphApi` — **no revision, no cursor, `limit` only, no facets, no `q`**; unrevisioned writes into `iga_*` |
| GCP | — | yes (latest collected only) | — | — | `/authsec/discovery/gcp/*` |
| GitHub | — | — | — | yes (repository sightings) | `/authsec/discovery/agents` |

Each cell is the contract the UI may rely on. A cell with "—" renders the
explicit not-collected state.

### Layout

```
Discovery                      Provider [AWS ▾]        Published 29 Sep 16:30 · Newer publication: Refresh
[ Search workloads by name, ARN or account                                               ]
( Workloads 10 ) ( Identities 77 ) ( Resources 14 )          View: Published | Latest collected
Filters:  Source ▾   Region ▾   Lifecycle ▾   Runtime ▾   Attribution ▾        Clear all
┌ list ──────────────────────────────────────────────────┐ ┌ preview ────────────┐
│ Name · context · runs as · last confirmed               │ │ list preview         │
└─────────────────────────────────────────────────────────┘ └──────────────────────┘
```

- **Type switcher**: segmented, one segment per type the provider supports,
  with counts (semantics below). URL `type=`.
- **Filters** are a row of popover facets, not a persistent rail: a rail
  and a preview panel must never squeeze the same table. The row collapses
  into a single *Filters* sheet below 900 px of content width.
- **Search** is server-side over the chosen type (`q`); its placeholder
  names the type's searchable fields.
- **List**: fitted table; row selection opens the list preview; the name
  is a link to the detail.
- **View: Published | Latest collected** (AWS workloads, identities,
  resources). *Published* is the graph list at the pinned publication —
  what AuthSec concluded. *Latest collected* is the normalised inventory
  from the most recent scan (`cloud_*` rows via the discovery routes). Its
  one-line note: *Normalised rows from the latest scan, including rows not
  yet in a publication. Published is what AuthSec concluded from them.* It
  never claims to be the provider's raw response.
- **Freshness**: the pinned publication and a *Refresh* when a newer one
  exists. Refresh re-pins the lists; it never requests a scan (that is on
  Connections).

### Filter semantics

| Filter | Applies to | Notes |
|---|---|---|
| Source (account / project / cluster / org) | all types | Revoked sources are listed and marked |
| Region / namespace | workloads, resources (AWS); workloads, identities (K8s) | |
| Lifecycle: Current · Stale · Ended | Published view, all types | *Latest collected* has no lifecycle; the filter is removed when switching to it (visibly, with a chip that says why) |
| Classification: Agent (decided) · Provider-native agent · Unclassified | **workloads only** | The three are mutually exclusive by definition (`classification` enum); the facet says *Agent — classified by a person* and *Agent — provider-native* so they do not read as overlapping |
| Runtime | workloads | AWS: Lambda, ECS, EC2, Bedrock agent, AgentCore runtime, AgentCore gateway; K8s: workload |
| Attribution: runs as a known identity · unattributed | workloads, latest-collected only | |
| Identity kind: Role · User · Group · Service account | identities | |
| Bound to a workload; Unused access | identities (unused: latest-collected only) | |
| Representation: Exact reference · Selector | resources | **Separate from** External (the account the ARN states is not connected) — two facets |
| Sensitivity; Named by a Deny | resources | |
| Decision needed · Registered · Ignored; Live only | sightings | |

Rules
- Switching type keeps Source and Region; type-specific filters are
  **removed visibly** (an "x Removed: Runtime — not a resource filter" chip
  for one interaction) — never silently ignored.
- Facet counts reflect **every other active filter** (the server's
  `facets` do this, §5.2 of the graph spec); a facet whose count is not
  known shows *Unavailable*, not 0.
- Query, filters, sort, page and selected object are preserved on return
  from a detail (URL + history state).

### Count semantics

Every count on the screen is one of four states, rendered distinctly, and
the UI preserves the API's `ExactCount` distinction (`value: null` is
unknown, never zero):

| Shown | Meaning |
|---|---|
| `23` | exact |
| `At least 23` | lower bound (capped list, partial activity read) |
| `Unavailable` | the count timed out or the provider does not report it |
| `0` | a successful query established no matches |

A total is never derived from the page in hand. Type-switcher counts come
from B2 (one call) or, until then, from each list's own `total` /
`total_known` — never from `rows.length`.

### Sightings actions — inventory

| Action | Class | In this revamp |
|---|---|---|
| View, filter, open detail, open evidence | read-only discovery | yes |
| Claim (tie a sighting to an identity) | ownership / classification | yes — the existing `ClaimAgentDialog` claim path |
| Ignore | classification | yes |
| Classify a workload as agent / undo | classification | yes (already on workload pages) |
| Provision | provider-mutating | **no** — not offered in Discovery |
| Quarantine | enforcement | **no** — not offered; `EnforcementStatusCard` is not rendered in Discovery |

Provider policy documents remain available as read-only evidence; nothing
in Discovery authors policy or enforces anything.

### Kubernetes in Discovery

Served from `k8sGraphApi` under Provider = Kubernetes with the contract in
the table above. The workload → ServiceAccount → binding → role → rule
chain is the Kubernetes workload's Identities tab and its Graph tab. Because
Kubernetes writes are unrevisioned, the header shows *Reported <time>* from
the cluster heartbeat rather than a publication, and a cluster that has not
reported shows *No report from this cluster since <time>*.

## Summaries — three compositions

Not one universal card. Three compositions with distinct jobs; the facts
they show are defined with their calculation and completeness.

### List preview (beside a list)

- Name, kind, provider glyph.
- Account / cluster and region / namespace.
- One or two facts relevant to the type (below).
- One freshness or coverage exception, if any (*Stale since 3 Oct*;
  *Account coverage partial*).
- *Open details* · *Open graph*.
- No portrait, no identifiers beyond what disambiguates.

### Detail header (object pages)

- Compact identity and context: name, kind, account, region, lifecycle
  state and since-when.
- Classification where applicable, with who decided.
- The page's actions (Classify, Open graph, Copy ARN).
- No mandatory portrait. The neighbourhood sketch is **optional** and only
  on the Overview tab, drawn from data the tab has already loaded; when
  that data is not loaded and nothing will fetch it, the slot shows the
  Identities / Resources summary instead — never a permanent *Loading…*.

### Graph inspector (selection card + evidence)

- What was selected (one line).
- What the relationship means (one sentence, from `EDGE_MEANING`).
- Why AuthSec believes it (basis, confirmation, source API).
- One important qualification (the single most relevant limitation).
- Expandable evidence and technical details.
- The ARN, the relationship sentence and the declared-access line each
  appear **once** per inspector.

### Facts and their contracts

| Fact | Shown on | Calculation | Completeness |
|---|---|---|---|
| Runs as / ECS agent uses | workload preview, header | `execution_role` (task role) and `other` of type `task_execution_role` — **two labels, never merged into "Runs as"** | exact for the first page; *+N more* when `next_cursor` |
| Declared permissions — examples | workload / identity preview | The first grant lines of the Resources tab at the pinned revision, labelled *Examples of declared permissions*; Allow / Deny, conditions and `NotResource` exclusions are preserved on drill-down; **`NotResource` targets are never counted as destinations** | labelled as examples; no ranking is claimed |
| Resources named (count) | identity header | `named_by_count` / list `total` | `ExactCount` semantics |
| Workloads bound | identity preview, header | `used_by_count` — direct bindings via `executes_as` and `task_execution_role`, said as such | exact or capped (*3+*) |
| May assume (count) | identity header | trust-policy principals — **configured trust, never a proven assumption**; wording *may assume (declared)* | first page + `next_cursor` |
| Accounts crossed | not shown | no complete source; would require a traversal | — |
| Identities that reach a resource | resource preview, header | the Access tab's first page | *+N more* when paged |
| Qualifications | all | shown only when they answer the question at hand: *Permissions boundary present* on a declared permission, not on every object; *Stale since* on the object; *Coverage partial* on the account | — |

*Declared access — not evaluated* appears once per screen, in the header,
never per row.

## Responsive contract

Lists use `AdaptiveTable` `sizing="fit"` with explicit priorities, measured
against the **available content width** (sidebar open or collapsed; preview
open or closed), not the viewport.

Workload list, as the pattern for every list:

| Priority | Columns |
|---|---|
| Always | Name with kind and context beneath; the name link |
| 1 | Classification; lifecycle exception |
| 2 | Account / cluster |
| 3 | Region / namespace; last confirmed |
| Details (expansion / preview) | Full ARN (copy), secondary timestamps, technical metadata |

Rules
- Below 640 px of content width rows become stacked cards with the
  always-visible fields; details on expansion.
- Sorting stays reachable when its column is hidden (the sort control is
  in the toolbar, not only in the header).
- The account id is shown once when there is no friendly name; full ARNs
  live in details and copy controls, never as a column that forces width.
- The filter row collapses to a *Filters* sheet when it competes with the
  table; a preview panel closes to a drawer below 1100 px.
- Visible keyboard focus on every control; semantic links for navigation;
  labelled controls; contrast per the console tokens.
- Category colour is always paired with an icon and the kind in words.

## Investigation-context contract

- Search, filters, sort, page and selection survive opening and closing an
  object (URL + history state).
- Browser Back restores the list, its scroll position and the selection.
- An object's tabs keep the same object and the same pinned publication.
- An evidence link names its source and returns to the investigation it
  came from (`evidence=` beside the content; Back closes it).
- *Refresh* re-pins displayed data; *Scan now* requests a new scan; the two
  are never one control.
- A newer publication never replaces data mid-investigation: the banner
  offers Refresh; until then every read stays pinned (`409 revision_stale`
  handling as today).
- Redirected old URLs keep their account, source, tab and filter
  parameters.

Graph regression checks (the canvas design is unchanged; its surroundings
are not):
- Opening the inspector never hides the selected object (`rightInset`).
- Selecting never resets pan or zoom.
- Dragging one node never pans the canvas.
- The new detail header does not take graph height: on the Graph tab the
  header is its compact form.
- Back returns to the same graph context (`as=`, `node=`, `edge=`).

## Policy — reserved destination

`/iga/policy` is reserved. Within this spec it renders one screen: the
preview banner (*Preview — sample data. Nothing here is evaluated or
enforced.*), one paragraph on what Policy will hold, and a link to the
policy specification. Its sample-data screens, if any, are specified in
`SPEC-iga-phase3-policy.md`, not here. No retired governance screen, dialog
or API call is reachable from it.

## Logs — preview

`/iga/logs` renders a labelled preview on fixtures
(`features/iga/logs/fixtures.ts`), making no network call: a timeline of
events grouped by day (scan queued / running / finished / failed;
publication; classification decided; sighting claimed; connection added /
revoked), filters by kind, source, actor and time, an event drawer with the
facts and the raw record collapsed. Export is absent, not disabled. The
banner reads *Preview — sample events.* Nothing from the retired Provenance
or Enforcement screens is reused.

## Backend dependencies — field level

| UI fact | Current source | Available today | Completeness semantics | Required change | Fallback until then |
|---|---|---|---|---|---|
| Connection status + reason (all providers) | `CloudConnector.status/last_error`+ error code (AWS, GCP); `DiscoverySource.last_status/last_error` (K8s, GitHub) | yes, three shapes | — | B3: one `/authsec/discovery/connections` read with `status`, `status_reason_code`, `last_scan`, `coverage_state`, `graph`, `scope_summary` | UI adapter over the three lists |
| Latest scan state | `cloud_scan_run` list (AWS/GCP); `last_sync_at` (GitHub); heartbeat (K8s) | yes | exact | B3 | adapter |
| Coverage state per connection | `CloudConnector.coverage.surfaces` (AWS/GCP); K8s coverage; GitHub none | AWS/GCP yes; K8s partial; GitHub no | per-surface states | B3 (`coverage_state`, `surfaces_short`); GitHub reports repositories scanned vs in scope | *Unknown* for GitHub |
| Graph publication per connection | `/api/iga/v1/pipeline`, `/coverage` (AWS); none for K8s (unrevisioned) | AWS yes | exact | B3 includes `graph` for AWS; K8s shows *Reported <heartbeat>* | — |
| Type counts | each list's `total` / `total_known` | yes (AWS) | `ExactCount` | B2: `GET /api/iga/v1/summary` at the pinned rev honouring the same filters | four list reads with `limit=1` |
| Facet counts | `facets=` on graph lists | AWS yes; K8s no | server-side, other filters applied | B1 for K8s | K8s facets *Unavailable* |
| Kubernetes workloads / identities in a revisioned, paged, searchable list | `k8sGraphApi` (`limit` only) | partial | none | B1: K8s rows served by the graph lists with `provider=k8s`, revisioned or explicitly `graph_state: unrevisioned`, keyset-paged, `q`, facets | provider-scoped K8s view on `k8sGraphApi`, counts *At least N* |
| Stable provider-qualified source reference | connector id (AWS/GCP), source id (K8s/GitHub) | yes, two id spaces | — | B3 returns one `source_ref` per connection; graph rows reference it | adapter |
| Declared permissions examples | workload Resources tab first page; identity Permissions | yes | labelled examples | none | — |
| Workloads bound / resources named / may assume | `used_by_count`, `named_by_count`, used-by first page | yes | `ExactCount` / paged | none | — |
| Sighting ↔ identity link | `matched_client_id` | yes | — | none | — |
| Logs events | none | no | — | out of scope (preview) | fixtures |

B1–B3 are the three backend changes; the table is the measure of the work,
not the count.

## Delivery sequence

1. **Resolve scope, route map and read contracts** — this spec locked;
   B1–B3 contracts agreed with the backend (shapes, pagination, counts,
   failure) before UI work that depends on them.
2. **Shell and retirement** — four-entry sidebar; route map with
   parameter-preserving redirects; retired-page state; governance
   components removed after the shared-consumer check; Policy reserved
   screen; `Breadcrumb` labels.
3. **Connections end to end** — table, readiness model, connection detail
   with the five-step tracker, Scans, Coverage screen, Scope editor,
   provider-capability actions with consequence copy.
4. **AWS Discovery and detail journeys** — provider scope, type switcher,
   filter row, count states, Published / Latest collected, list preview,
   detail header, investigation-context contract, responsive priorities.
5. **Other providers through explicit contracts** — Kubernetes on
   `k8sGraphApi` with its stated limits; GCP identities (latest collected);
   GitHub sightings; not-collected states; then B1 when it lands.
6. **Shared summaries and graph integration** — the three compositions,
   the optional neighbourhood sketch, inspector de-duplication, graph
   regression checks.
7. **Verification** — preview isolation, responsiveness, the task
   walkthroughs below, the state matrix.

Each phase is reviewable on its own (UI reviewer, `tsc`, eslint, build) and
inspectable on a non-customer deployment; nothing requires a production
rollout per phase.

## Acceptance — task walkthroughs

| Customer task | Required outcome |
|---|---|
| Connect an AWS account | The tracker shows connection, scan progress and when Discovery is ready; the operator never infers readiness from timestamps |
| Investigate partial collection | From the Status line to the Coverage screen: the affected account, region and surface, what is missing, and what to do — without reading internal keys |
| Find a workload | Search / filter → open detail → inspect its identities → Back returns to the same list, filters, page and selection |
| Inspect a shared identity | The workloads bound are listed with the count's exactness; *+N more* when paged; task role and execution role distinguished |
| Inspect a permission | Declared action, target, conditions and evidence are visible, and nothing reads as proven access |
| Switch providers | Supported data or the explicit not-collected state; never an empty inventory that looks like "none" |
| Use a narrow viewport (≤ 900 px content width) | The main tasks complete with no horizontal table scroll; hidden columns are reachable in details; sorting remains available |
| Follow an old governance bookmark | The retirement state; no legacy screen or dialog appears; no governance API call is made |
| Refresh during an investigation | A newer publication is announced; data changes only on Refresh; Scan now is a different control |
| Keyboard only | Objects, filters, tabs, preview and evidence are all reachable without double-click or hover |

State matrix, required distinct on every list and detail: loading, empty,
filtered-empty, unauthorised, not found, failed request, partial
collection, stale, not collected for this provider, newer publication
available. None of them shares "No data".

Checks (`tsc -p tsconfig.app.json`, eslint, build) with no new diagnostics
are a precondition, not acceptance.

## Related docs

- `SPEC-iga-phase2-graph.md` §2.14 (experience; §2.14.2 points here), §5.2
  (`q`, facets, counts), §5.3 (read API), §5.7 (proposed reads)
- `SPEC-iga-phase3-policy.md` (Policy, outside this spec)
- `SPEC-github-discovery.md` (scan rules), `SPEC-aws-quick-create-onboarding.md`
- `Authsec-ui/AGENTS.md` (console conventions)
