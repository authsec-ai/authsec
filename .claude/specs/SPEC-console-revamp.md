# SPEC — Console revamp: four destinations, one Discovery, honest summaries

Status: **proposed, revision 4** — design to lock before implementation.
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
  sentence (*This screen was retired and has no replacement yet.*), and
  links to **Discovery** and **Connections**. Links to Policy or Logs, if
  shown, are labelled *(preview)*. It renders nothing of the old
  functionality and makes no governance API call.
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
| Status | The **primary condition** and **one supporting line**. Precedence, deterministic: Revoked › Authentication failed › Latest scan failed › Publication failed › Coverage partial / denied › Scan running / queued › Connected. The supporting line always says what still holds: *Latest scan failed · Inventory from 29 Sep remains available* — never implying data disappeared — then what to do: *Grant iam:ListUsers and scan again.* The full four-way breakdown is on the connection's Overview tab, never only on hover |
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

Actions are governed by authorisation as well as capability:
- Visibility follows the server's permission (`discovery:admin` for Scan,
  Verify, Edit scope, Revoke, Mint token; `discovery:read` sees the row and
  the detail). A read-only user sees no administrative control; the server
  enforces it regardless (403 is shown as *Your role cannot do this*, never
  as a failure).
- A submitted action disables its control and shows its pending state
  (*Queuing…*, *Verifying…*); a duplicate submission is refused client-side
  and a 409 from the server is shown as its meaning (*A scan is already
  running*).
- Failure keeps the control available with the cause and Retry; success
  refetches the row and the detail so the readiness model updates.

**Revoke** confirms with its consequences first, per provider. AWS / GCP:
*AuthSec stops reading this account. Everything already discovered is
kept. Rows this connection supported are no longer reconfirmed and show
as stale from the next publication; nothing is deleted. The role in your
account is not removed — do that in AWS.* Kubernetes: *The agent's token
is revoked; it stops reporting. Its last inventory is kept and marked
unreconfirmed.* GitHub: *Repository scans stop; sightings are kept.*
**Edit scope** (AWS regions, GitHub repositories): *Applies from the next
scan. Rows from a removed region are kept and show as stale from the next
publication.*

The stale transitions above are what the reconciliation rule gives (a
partition whose surfaces were not reached goes stale, never ended — graph
spec §4.10); they are **verified in the Connections dry run** before the
copy ships, and if a provider does not behave that way the copy says what
that provider actually does rather than asserting the rule.

### First successful journey

connect → verify → choose scope → scan → result available → open
Discovery. The connection's Overview tab is a tracker with each step's
state and its next action, so the operator never infers "is it ready?" from
timestamps. *Scan finished* and *Result available* are two steps, and what
"available" means is per provider:

| Provider | Discovery is ready when | *Open in Discovery* lands on |
|---|---|---|
| AWS, Published view | a publication includes this connection | `type=workloads&view=published&account=` |
| AWS, Latest collected view | the latest scan finished (any outcome short of failed), collection status shown | `view=latest&account=` |
| Kubernetes | a usable sweep exists for the cluster (`last_sweep.status` complete or partial) | `provider=k8s&source=` |
| GCP | collected identity inventory exists for the project | `provider=gcp&type=identities&source=` |
| GitHub | a completed discovery result exists for the organisation | `type=sightings&source=` — GitHub *workloads* appear in the inventory only once a GitHub writer records support rows (042 added the columns; nothing writes them yet); until then GitHub is sightings only |

A successful collection with **zero results** is ready: *ready* means the
result is available, not that objects were found; Discovery then shows the
successful-empty state for that source. The AWS tracker shows *Graph
published* as a sixth step for the Published view only.

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
providers with a connection). Default provider: the one the reader last
used (URL, then local preference); else the provider whose result is most
recently available by its own readiness rule (AWS publication, Kubernetes
sweep `observed_at`, GCP latest scan, GitHub latest result); else the only
connected provider; a workspace with no connection shows the connect-first
state with a link to Connections. A combination the provider does not collect shows an
explicit *Not collected for Kubernetes* state with the reason — **never an
empty list**. There is no "all providers" view until B1 lands; the control
says so.

### Supported object types per provider (today)

| Provider | Workloads | Identities | Resources | Sightings | Read model |
|---|---|---|---|---|---|
| AWS | yes | yes | yes | — | unified inventory (B1) for lists; detail from the §5.3 graph reads (revisioned); latest-collected rows via `/authsec/discovery/aws/*` |
| Kubernetes | yes | yes (ServiceAccounts) | — | yes (cluster sightings) | unified inventory (B1) once its fields land; until then `/authsec/discovery/k8s/*` via `k8sGraphApi` — **no revision, no cursor, `limit` only, no facets, no `q`**; writes into `iga_*` are unrevisioned |
| GitHub (graph rows) | schema only | schema only | — | — | 042 added GitHub provenance to the shared tables; no writer yet, so the inventory lists no GitHub object until one exists |
| GCP | — | yes (latest collected only) | — | — | `/authsec/discovery/gcp/*` |
| GitHub | — | — | — | yes (repository sightings) | `/authsec/discovery/agents` |

Each cell is the contract the UI may rely on. A cell with "—" renders the
explicit not-collected state.

### Control contract per provider and view

The controls offered are exactly what the read model supports; a control is
never shown that quietly acts on a capped local subset.

| Provider / view | Search | Filters | Sort | Pagination | Counts | Detail · graph |
|---|---|---|---|---|---|---|
| AWS Published | server `q` over name, full ARN, account id | Source, Region, Lifecycle, Classification, Runtime / Kind / Representation / External / Sensitivity / Named by Deny | route sort keys (`name`, `last_confirmed_at`, …) | keyset cursor, signed | `total` / `total_known` (`ExactCount`) | object pages; Graph tab |
| AWS Latest collected | **client-side over the loaded page only**, labelled *Search the N loaded rows* | Source and Kind server-side; Attribution, Unused access client-side over loaded rows, labelled | client-side over loaded rows | offset `limit`/`offset` (500 cap), *Load more* | `total` from the discovery route when returned, else *At least N loaded* | connector drawers; *Open in graph* via `/lookup` |
| Kubernetes | **none server-side**; client-side over the loaded `limit` rows, labelled *Search the N loaded workloads* | Source (cluster), Namespace — client-side over loaded rows, labelled | client-side | `limit` only; *Load more* raises the limit; no cursor | *At least N* until the response is shorter than the limit, then exact | Kubernetes workload / identity detail (`/iga/estate/:id`, `/iga/identities/:id` once B1; until then the K8s access detail); Graph tab |
| GCP identities | client-side over loaded rows, labelled | Source | client-side | offset | as AWS latest | connector drawer |
| GitHub sightings | server `q` (name, fingerprint) | Status, Live only | server | offset | exact | sighting detail |

Switching type keeps only the filters the new type supports (Source always;
Region only where the table above lists it); every removed filter is named
in a one-interaction chip. B1 brings Kubernetes rows under the inventory
contract with their publication state labelled; it does **not** by itself
enable an all-provider view — GCP keeps its own contract and GitHub has no
graph rows until its writer exists — and the Provider control stays until
then.

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
- **Publication state**: the pinned publication and a *Refresh* when a newer one
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
- Switching type keeps Source, and Region only where the new type supports
  it; every other filter is **removed visibly** (an "x Removed: Runtime —
  not a resource filter" chip for one interaction) — never silently ignored.
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

A total is never derived from the page in hand, and a cursor is never
turned into a number: *12 more* only when an exact total is known;
*More available* / *Load more* when only a cursor is; an incomplete
collection is stated beside the count, not folded into it. Type-switcher
counts come from B2 (one call) or, until then, from each list's own
`total` / `total_known` — never from `rows.length`.

### Sightings actions — inventory

| Action | Class | In this revamp |
|---|---|---|
| View, filter, open detail, open evidence | read-only discovery | yes |
| Claim (existing dialog and `claim` mutation) | **provisioning** — with the identity left blank, which its own copy calls the normal path, the backend mints a governed identity *and an OAuth client* (`services/discovery_claim_identity.go`) | **no** — the existing Claim flow is not offered in Discovery; the backend capability is untouched |
| Associate a sighting with an existing identity | ownership / classification | **only** as a new, narrower action with its own contract: pick an existing identity (required), no creation of any identity or client, server-enforced `iga:review`; specified and reviewed separately before it is built. Until then, sightings are read-only apart from Ignore |
| Ignore | classification | yes |
| Classify a workload as agent / undo | classification | yes (already on workload pages) |
| Provision | provider-mutating | **no** — not offered in Discovery |
| Quarantine | enforcement | **no** — not offered; `EnforcementStatusCard` is not rendered in Discovery |

Provider policy documents remain available as read-only evidence; nothing
in Discovery authors policy or enforces anything.

### Kubernetes in Discovery

Listed by the unified inventory under Provider = Kubernetes (B1); until B1's
fields land, from `k8sGraphApi` with the contract in the table above. The
workload → ServiceAccount → binding → role → rule chain is the Kubernetes
workload's Identities tab and its Graph tab. Kubernetes writes are
**unrevisioned**: the agent's sweep is written straight into the shared
tables, with no publication number and no "newer publication" prompt, so
every Kubernetes row carries `graph_state: unrevisioned` and an `as_of`
from the **sweep behind it**, and the header is built from that sweep
(`last_sweep`: `observed_at`, `status`, `complete`, `coverage`,
`cluster_scoped`), never from the agent heartbeat:

| Condition | Source | Shown |
|---|---|---|
| Connection health | last heartbeat | on Connections: *Agent online, heartbeat 2 min ago* |
| Inventory date | `last_sweep.observed_at` | Discovery header: *Inventory from sweep at <time>* |
| Coverage | `last_sweep.coverage` (`cluster_scoped`, `namespaces`) | the coverage state word and sentence |
| No sweep | `coverage: not_swept` | *No inventory received yet* — not an empty list |
| Heartbeat recent, sweep old | both | *Agent online; its last inventory is from <time>* — the discrepancy is stated |

## Summaries — three compositions

Not one universal card. Three compositions with distinct jobs; the facts
they show are defined with their calculation and completeness.

### List preview (beside a list)

- Name, kind, provider glyph.
- Account / cluster and region / namespace.
- One or two facts relevant to the type (below).
- One lifecycle or coverage exception, if any (*Stale since 3 Oct*;
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
| Runs as / ECS agent uses | workload preview, header | `execution_role` (task role) and `other` of type `task_execution_role` — **two labels, never merged into "Runs as"** | the rows shown are exact; the summary is complete only when there is no `next_cursor`; otherwise *More available* |
| Declared permissions — examples | workload / identity preview | The first grant lines of the Resources tab at the pinned revision, labelled *Examples of declared permissions*; Allow / Deny, conditions and `NotResource` exclusions are preserved on drill-down; **`NotResource` targets are never counted as destinations** | labelled as examples; no ranking is claimed |
| Resources named (count) | resource header only | `named_by_count` is a **resource-detail** field — statements naming that resource | `ExactCount` semantics |
| Resources an identity can reach (count) | — | no identity-scoped resource total exists; the identity's Permissions tab lists statements, not a resource total | **unavailable** — not summarised; the header links to Permissions |
| Workloads bound | identity preview, header | `used_by_count` — direct bindings via `executes_as` and `task_execution_role`, said as such | exact, or *At least 3* when capped |
| Trusted principals (incoming) | identity header | the Used-by tab's *principals* section: who the role's trust policy names — **incoming**: *Trusted to assume this role (declared)* — configured trust, never a proven assumption | first page; *More available* on `next_cursor` |
| May assume (outgoing) | — | which roles trust **this** identity — a different query (the graph's `can_assume` edges from this identity, `/graph` forward); shown only when a verified outgoing read supplies it; until then **not shown** | — |
| Accounts crossed | not shown | no complete source; would require a traversal | — |
| Identities that reach a resource | resource preview, header | the Access tab's first page | *12 more* only when an exact total is returned; *More available* when only a cursor is; incomplete collection stated separately from paging |
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
- A newer publication never silently replaces data mid-investigation —
  but the backend does **not** serve old revisions: once a newer publication
  is current, any read pinned to the old one is refused with `409
  revision_stale` (`internal/igaread/snapshot.go`). The contract is
  therefore:
  - content already loaded stays visible, labelled with its publication
    (*as of 29 Sep 16:30*); newer responses are never mixed in;
  - an uncached tab, page or evidence request that returns `409` shows a
    specific *A newer publication is current — refresh to continue* state
    in place of that panel, with the Refresh control; nothing else on the
    screen changes;
  - Refresh re-pins the whole investigation together, resets incompatible
    cursors and re-reads the selected object; if that object is retired or
    absent at the new publication, the page shows its retired state (its
    Overview and Changes, the other tabs saying they have no current data)
    and the list returns to the same filters without the selection.
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
| Facet counts | `facets=` on the graph lists and on the unified inventory (`provider`, `kind`, `scope`) | yes | server-side, other filters applied | B1 adds no facet; type-specific facets beyond those three stay on the graph lists for AWS | Kubernetes type-specific facets *Unavailable* |
| One paged, searchable, faceted list per object type over every provider | unified inventory `/api/iga/v1/inventory/*` (PR #75) | yes — cursors, capped totals, `provider` / `kind` / `scope` facets, `q` | §5.2; **no** `rev`, `published_at`, `graph_state` or `coverage` today | B1 (below) | AWS from the graph lists; Kubernetes from `k8sGraphApi`, counts *At least N* |
| GitHub objects in the inventory | shared tables + 042 columns | schema only | — | a GitHub writer for workloads, identities and support rows (outside this spec; owner: backend) | GitHub is sightings only |
| Stable provider-qualified source reference | connector id (AWS/GCP), source id (K8s/GitHub) | yes, two id spaces | — | B3 returns one `source_ref` per connection; graph rows reference it | adapter |
| Declared permissions examples | workload Resources tab first page; identity Permissions | yes | labelled examples | none | — |
| Workloads bound / resources named / may assume | `used_by_count`, `named_by_count`, used-by first page | yes | `ExactCount` / paged | none | — |
| Sighting ↔ identity link | `matched_client_id` | yes | — | none | — |
| Logs events | none | no | — | out of scope (preview) | fixtures |

The three backend changes, named in the table:

- **B1 — publication state on the unified inventory.** PR #75's
  `/api/iga/v1/inventory/{workloads,identities,resources}` are Discovery's
  list contract: one provider-neutral row per object AWS, Kubernetes and
  GitHub write into the shared `iga_*` tables, with `provider` / `kind` /
  `scope` facets, §5.2 cursors, capped totals and `q`. They gain what a
  reader needs to tell a numbered AWS publication from a live Kubernetes
  write. **Envelope:** `meta.rev` and `meta.published_at` — the AWS
  publication current at the snapshot, `null` when none (reported, not
  enforced: the inventory is not pinned); `meta.graph_state` —
  `published` (every row at that publication) · `unrevisioned` (no row is)
  · `mixed` · `not_published` (AWS rows requested, no publication);
  `meta.coverage[]` — the §5.2 notes for the AWS accounts in scope, plus
  one note per Kubernetes cluster from its latest sweep's coverage.
  **Per row:** `graph_state` (`published` for AWS rows, `unrevisioned` for
  Kubernetes and GitHub rows) and `as_of` (AWS: `published_at`;
  Kubernetes: the confirming sweep's `observed_at`; GitHub: `null` until a
  writer exists). The §5.3 graph lists stay AWS-only; detail pages keep
  reading them.
- **B2 — type counts.** `GET /api/iga/v1/inventory/summary` → one
  `ExactCount` per object type for the same filters, in one snapshot.
- **B3 — one connections read.** `GET /authsec/discovery/connections`
  across providers with `status`, `status_reason_code`, `last_scan`,
  `coverage_state`, `graph` and `scope_summary`, and one `source_ref` per
  connection.

The table is the measure of the work, not the count.

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
| Refresh during an investigation | A newer publication is announced; loaded content stays labelled with its publication; an uncached request shows the refresh-required state, not an error; Refresh re-pins everything together and handles a retired selection |
| Connect a GCP project or a cluster | *Open in Discovery* becomes available on that provider's own readiness rule, including a successful empty result |
| Act on a sighting | Only Ignore (and, once specified, Associate) is offered; nothing creates an identity or client |
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
