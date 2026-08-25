# Task 101 — Rate-limit reality and scan budget

All numbers measured live against `authsec-sandbox` on 2026-08-24 with App
`authsec-discovery-sandbox321` (installation `156264905`, "all repositories").
Raw evidence in `fixtures/rate-limit/`, `fixtures/repos/*.http`, `fixtures/tree/*.http`.

## 1. Primary limits (observed)

| Bucket | Limit (header) | Observed behavior |
|---|---|---|
| `core` — installation token | `X-RateLimit-Limit: 5000` / hour / installation | Decrements 1:1 on origin (cache-miss) calls. Verified across 12 sequential fixture calls: 4999 → 4988. `X-RateLimit-Resource: core`. |
| `dependency_sbom` — SBOM endpoint | `X-RateLimit-Limit: 100` / hour | Separate bucket, returned on `GET /repos/{o}/{r}/dependency-graph/sbom` (observed `Remaining: 99` after 1 call — fixture `fixtures/sbom/sbom.http`). Independent of the 5000 core budget. |
| App JWT (app-level) calls | **no rate-limit headers returned** | `GET /app`, `GET /app/installations`, `GET /app/installations/{id}` all 200 with no `X-RateLimit-*` headers. GitHub documents a separate App-level bucket; headers are simply absent at this level. |
| Installation token mint | — | `POST /app/installations/{id}/access_tokens` mints a fresh token each time (fingerprints differed across 3 consecutive mints: `3e43c4f7cb29`, `c21dbf353161`, `78e6bb72ecc6`). Token ≈ 1h validity. |

## 2. Secondary limits (observed)

- **Not triggered** at ~114 req/min sustained for 3 min (300 sequential requests, all 200).
- **Not triggered** at ~960 req/min for 75 s (8 parallel workers × 150 requests, all 200, no `Retry-After`, no 403/429).
- Conclusion: on this fresh sandbox org, the secondary throttle did not engage below ~1000 req/min short-burst. Secondary behavior on an org with real traffic history is likely lower; treat >1000 req/min as unmeasured, not safe.

## 3. Edge caching (the surprise)

Identical GET requests stop counting against the bucket once GitHub's edge
cache serves them:

- Burst 1 (300 sequential, cold): bucket decremented 256.
- Burst 2 (8×150 parallel, warm): bucket barely moved (`Used: 66` total, of which ~13 were earlier fixture calls).
- Practical consequence: **repeated scans of unchanged repos are nearly free**;
  a re-scan that hits warm cache costs ~0 core quota. A fresh scan (or a repo
  that changed) pays full price.

## 4. One-repo scan cost (measured)

Product scan sequence on `authsec-sandbox/test-repo-1` (scan-sim, 1.74 s wall-clock):

| Step | Calls | Notes |
|---|---|---|
| `GET /installation/repositories?per_page=100` (enumeration) | 1 (+1 per 100 repos beyond the first page) | |
| `GET /repos/{o}/{r}/git/trees/{branch}?recursive=1` | 1 | `truncated: false` on this repo |
| CODEOWNERS probes (`.github/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS`) | 1..3, stop at first 200 | Observed 2 (404 then 200) |
| Blob fetches for rule-matched files | B (observed 2: `.github/workflows/ci.yml`, `package.json`) | B depends on repo contents; test-repo-1 is a curated minimal fixture |
| **Per repo total** | **5 calls** (1 + 2 + 2) | |

## 5. Full-scan budget (written)

Full scan of **N** repositories, all cache-cold:

```
calls(N) = ceil(N/100)   (installation/repositories pagination)
         + N × 5         (tree + CODEOWNERS + matched blobs, measured per repo)
```

| N | Calls | Wall-clock (1.74 s/repo, this network) |
|---|---|---|
| 10 | 11 | ~17 s |
| 100 | 501 | ~3 min |
| 300 | 1504 | ~9 min |
| 995 | 4979 | ~29 min |

**Ceiling: 5000 core calls/hour per installation.**
- Max fresh scans/hour at N=300: **3** (1504 × 3 = 4512, headroom 488).
- Max repositories scanned per hour (fresh): **~995**.
- The binding constraint for a full fresh scan of 300 repos is the **core bucket**,
  not wall-clock: 3 scans/hour fits in 27 min of continuous scanning.
- If the scan ever includes `dependency-graph/sbom` per repo, the separate
  **100/h `dependency_sbom` bucket** binds first: SBOM for at most 100 repos/hour,
  regardless of core budget.
- Re-scans of unchanged repos: edge cache makes them ≈ free (Section 3); the
  budget above is the worst case the UI must plan against.

## 6. Implication for the product

1. The product's per-installation token cache (55-min validity margin in
   `internal/connectoradapters/githubapp.go`) is safe: tokens are minted fresh
   each time but GitHub keeps the counter at installation level.
2. Scan scheduling must assume **5000/h worst case and 1504 calls per 300-repo
   scan**; a scan limit of 3/hour per installation is the honest ceiling.
3. The 403/429 handling in `services/iga_github_provider.go` (`rateLimitPause`)
   is calibrated correctly: 403 with `X-RateLimit-Remaining: 0` is a throttle;
   403 with quota left is a permission problem — exactly the 403≠404≠empty
   distinction the capability matrix records.
4. Fresh repos enumeration cost is trivial (1 call per 100 repos); the cost is
   dominated by per-repo tree + blob work.

> Primary-limit exhaustion was captured live: the probe App's installation was
> deliberately driven to `X-RateLimit-Remaining: 0` / `Used: 5000` and the exact
> 403 body ("API rate limit exceeded for installation ID 156281961 …") is
> committed in `fixtures/failure-modes/exhausted.json` — the main App's budget
> was never touched for this.

> Caveat — extrapolation, not measurement: the 300-repo cost is modeled from a
> single measured 1-repo scan-sim (5 calls, 1.74 s on this network), not an
> end-to-end 300-repo run — impossible in this 1–2 repo sandbox. The formula
> `calls(N) = ceil(N/100) + N×5` is sound, but it is a model, not a measurement
> at N=300; a real tenant is the verification.