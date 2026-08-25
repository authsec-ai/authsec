# Task 101 — Recorded answers to the three capability questions

App: `authsec-discovery-sandbox321` (4704782) · Org: `authsec-sandbox` · Date: 2026-08-24 UTC
Probe App: `authsec-capability-probe` (4705654), zero permissions

## Q1 — Does the repositories endpoint reflect repository removal immediately?

**Yes, both directions, with no observable lag (sub-second).**

- **Addition**: with the installation granting both org repos, the very next
  `GET /installation/repositories` returned both `test-repo-1` and `bigtree`
  (`total_count: 2`). See `fixtures/repos/install-156264905-2repos.json`.
- **Removal**: after `bigtree` was removed from the installation in the UI, the
  very next call returned only `test-repo-1` (`total_count: 1` — see
  `fixtures/repos/install-156264905-page1.json`), and
  `GET /repos/authsec-sandbox/bigtree/git/trees/main?recursive=1` returned
  **404 Not Found** — an un-granted repo is indistinguishable from a repo that
  does not exist (GitHub hides it). See `fixtures/failure-modes/tree-bigtree-ungranted.json`.
- **Pagination**: with `per_page=1` the same endpoint returns a real
  `Link: rel="next"` header pointing at `?page=2` (and `rel="last"`) —
  `fixtures/repos/pagination-per-page1.http` — confirming the endpoint paginates
  past one page as expected.

Implication for the product: an installation that loses a repo mid-scan will
immediately start getting 404s on that repo — the product's existing 404→"absent"
handling (`ghError.IsAbsent`) is the correct response, and the scan result must
surface the transition (repos that 404 are not "clean", they are "gone").

## Q2 — Does the tree endpoint truncate at 100,000 entries / 7 MB as documented?

**The 7 MB response bound is the real constraint; truncation was observed at
40,269 entries, `truncated: true`.**

- `authsec-sandbox/bigtree` (66,000 files, path depth ~24 chars + ~105-char
  filenames) returns `truncated: true` with **40,269 entries** — far below the
  documented 100,000-entry ceiling. The raw response was ~7 MB
  (15,715,966 bytes pretty-printed — see fixture note). The 7 MB cap binds first.
- `truncated: true` is the ONLY signal in the response (`tree` array just ends;
  there is no `"truncated": false` on small repos and no partial-count field).
- Fixture: `fixtures/tree/tree-bigtree.json` (representative 100-entry excerpt +
  metadata; full payload is 15.7 MB pretty / ~7 MB raw, deliberately not committed).
  Contrast `fixtures/tree/tree-test-repo-1.json` (`truncated: false`, 6 entries).

Implication for the product: `GitHubProvider.ListTree` already checks `Truncated`
and degrades coverage — correct. The 100k-entry documentation is misleading; the
7 MB bound hits first for normal path shapes (~40k entries), so repos with more
than ~40k files will silently under-enumerate unless `truncated` is honored.

## Q3 — What happens to an in-flight token when the installation is revoked mid-scan?

**The token is invalidated immediately. No grace period observed.**

Test (2026-08-24 21:31 UTC): a fresh installation token for probe install
`156307174` was minted and used to poll `GET /installation/repositories` every
5 s. Polls returned **200 OK** at 21:31:08–21:31:46. The owner uninstalled the
App; the next poll (21:31:52, ≤5 s later) returned **401 Unauthorized —
"Bad credentials"**. The token stopped working the moment the installation was
deleted — it was not 403, not 404: the credential itself is dead.
Fixture: `fixtures/failure-modes/revoked-in-flight.json`.

Implication for the product: a scan interrupted by revocation will fail with
401 at the very next call, not silently continue. The product must treat 401 on
a minted installation token as "installation revoked" (surface re-install /
re-consent), and the per-installation token cache in
`internal/connectoradapters/githubapp.go` will serve a dead token until its
~1 h expiry unless 401s invalidate the cached entry — worth a product follow-up
(not part of this research task).

> Retest note: the first attempt was confounded by the probe installation's
> exhausted rate-limit bucket (403 "API rate limit exceeded" masked the
> revocation). The retest above was clean: the bucket had reset, and the
> transition 200→401 was observed within one 5 s poll gap.

## Bonus observations

1. **One installation per App per org**: the ticket's "install it twice" design
   was not possible — `GET /app/installations` shows a single installation for
   the org, and the second "install" was realized as an all→selected repository
   re-configuration of the same installation (`repository_selection` flipped
   from `all` to `selected`). See `fixtures/meta/installations.json` +
   `fixtures/meta/install-156264905.json`.
2. **`installation/repositories` with zero permissions returns 200-empty** — the
   probe App (permissions `{}`, no repos granted) returns
   `{"repositories": [], "total_count": 0}` with 200. An empty array here is
   *honest* (nothing granted) but indistinguishable from "all repos scanned and
   none found" at this layer — the product must treat 200-empty as "not
   enumerated", never "clean". `fixtures/failure-modes/probe-repos.json`.
3. **Repo-level vs org-level absent-permission failure modes differ**:
   repo-scoped endpoints with a missing permission return **404 Not Found**
   (even on granted repos), while org-scoped endpoints return
   **403 "Resource not accessible by integration"**. The two must never be
   collapsed in the UI. `fixtures/failure-modes/probe-{tree,codeowners,workflows,keys,commits,sbom}.json`
   vs `probe-{org-secrets,copilot-seats}.json`.
4. **`GET /orgs/{org}/copilot/billing/seats` returns 200-empty without a Copilot
   license or Copilot permission** (main App: 200 `{"seats": [], "total_seats": 0}`
   with no `copilot` permission; probe: 403). `copilot/usage` is 404 on this org.
5. **`GET /repos/{o}/{r}/copilot/agents` does not exist — 404 with full repo
   access, and this is a REQUIRED FIX for AS-104, not a handled condition.**
   The product's `ListNativeAgents` endpoint assumption is false in the sandbox.
   Crucially, the degradation is NOT safe: `ListNativeAgents` returns
   `(nil, nil)` on 404 (no error — `services/iga_github_provider.go`), and the
   intended short-circuit that would catch this (a check of
   `caps[ClassAgentProfile]`) never fires, because the live `Capabilities()`
   probe only exercises `ClassRepository`
   (`/installation/repositories?per_page=1`). Net effect: Lane A would report
   `complete_for_selected_scope` with **zero agents** on an org where the
   endpoint does not exist — exactly what the coverage spec forbids (unknown
   must never render as zero). Reference only — no product code was modified;
   the fix belongs to AS-104.
6. **Edge caching distorts rate-limit accounting**: repeated identical GETs are
   served from GitHub's edge cache and stop decrementing `X-RateLimit-Remaining`
   (a 300-request cold burst decremented 256; 1200 warm parallel requests barely
   moved the counter; the probe's 6400-request parallel burst eventually hit the
   5000 ceiling). Query-parameter variants of the same path do NOT bust the
   cache. See `RATE_LIMIT_BUDGET.md` §3.