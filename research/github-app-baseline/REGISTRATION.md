# Task 101 — GitHub App Registration: field-by-field record

App: **authsec-discovery-sandbox321** (id `4704782`, client_id `Iv23liYsLCNRk8EwoRV8`)
Owner org: **authsec-sandbox** (id `320674609`)
Registered: 2026-08-24 (fixture `fixtures/meta/app.json`, captured via `GET /app` with App-JWT auth)
Installation: id `156264905`, `repository_selection: "selected"` (fixture `fixtures/meta/install-156264905.json`, captured 22:03 UTC) — the single org installation was re-configured during testing (`all` → `selected`, repo grants added and removed; it currently grants both `test-repo-1` and `bigtree`, `total_count: 2` per `fixtures/repos/install-156264905-2repos.json`)

> Source of truth: `GET /app` returns everything GitHub exposes to the App's own
> JWT. Fields marked **[owner-supplied]** were confirmed by the App owner
> (webhook/callback/setup URLs and public/private are not returned by the API).

## Registration form, field by field

| Form field | Value (as observed) | Justification / notes |
|---|---|---|
| **GitHub App name** | `authsec-discovery-sandbox321` | Slug derived from name; `html_url: https://github.com/apps/authsec-discovery-sandbox321` |
| **Description** | `""` (empty) | Optional; shown on the App's public page. Empty here. |
| **Homepage URL** | `https://example.com` (`external_url`) | Placeholder; must be a real URL for the marketplace, not otherwise functional |
| **Callback URL** | none | App uses installation tokens only — no user OAuth flow, so no callback URL is set |
| **Setup URL** | none | No setup redirect configured |
| **Webhook URL** | none | Webhook **inactive**; no webhook URL set. Not used in this task (fixtures are all direct API captures) |
| **Webhook secret** | n/a | No webhook configured, so no secret is set (product env `IGA_GITHUB_WEBHOOK_SECRET` would apply only if the webhook is activated) |
| **Webhook active** | `events: []` → **no events subscribed** (observed) | `GET /app` shows `"events": []`; `GET /app/installations` also `"events": []`. No webhook deliveries possible until events are subscribed |
| **Public vs private** | **private — "Only on this account"** (owner-confirmed) | App visible/installable only on the `authsec-sandbox` org; no marketplace review applies |
| **Permissions** | see matrix below | All read-only. GitHub validates the permission name at save time; unknown permissions are rejected |
| **Webhook events** | none | Empirically confirmed in `fixtures/meta/app.json` + `installations.json` |

## Permissions requested (observed, all `read`)

Observed in `GET /app` and `GET /app/installations/{id}` `permissions` blocks:

| Permission | Level | Purpose (why the product wants it) |
|---|---|---|
| `actions` | read | Actions workflow listing (`GET /repos/{o}/{r}/actions/workflows`) |
| `administration` | read | Repo admin state; enables other read surfaces |
| `contents` | read | Git trees, blobs, CODEOWNERS (`/git/trees`, `/git/blobs`, `/contents`) |
| `members` | read | Org membership visibility |
| `metadata` | read | Always-on; required for installation/repositories |
| `organization_administration` | read | Org-level admin metadata |
| `organization_secrets` | read | Org Actions secrets list — **names only** (`GET /orgs/{org}/actions/secrets` returns names + metadata, never values) |
| `repository_hooks` | read | Repo webhook visibility |

> Note: `copilot` permission is **not** granted, yet `GET /orgs/authsec-sandbox/copilot/billing/seats`
> returned `200` with `{"seats": [], "total_seats": 0}` — recorded in the capability matrix.
> `GET /orgs/{org}/copilot/usage` returned `404` (see fixtures `fixtures/copilot/`).

## Which changes force re-consent

To be verified empirically per GitHub's current behavior; ticket records both
the form field and the consequence:

- **Adding or upgrading a permission** (e.g. `contents: read` → `contents: write`):
  GitHub requires the org owner to re-approve; existing installations show a
  "Request new permissions" prompt.
- **Removing a permission**: applied on next install update; does not force
  re-consent but narrows what the API returns (and can turn 200 into 403/404 —
  see failure-modes fixtures).
- **Changing webhook events**: does not require re-consent (no permission change).
- **Changing callback/setup URLs**: does not require re-consent.
- **Public ↔ private**: private→public requires a re-approval cycle for
  installations on other accounts.
- **Deleting the App**: revokes every installation and invalidates all tokens.

## Registration decisions recorded for the sandbox App

1. **No webhook configured at all** — webhook inactive, no URL, no secret, no
   events (`events: []`). The product's webhook surface
   (`/api/iga/v1/webhooks/github/...`, `routes/routes.go:280`) was not exercised
   in this task; adding the webhook + events is a registration-form change and
   does not force re-consent.
2. **Read-only permission set** — matches the "capability baseline" purpose of
   this task: everything recorded here is a GET surface; no write path was
   exercised.
3. **Private App, "Only on this account"** — installable only on the sandbox
   org; no external accounts, no marketplace.
4. **Single installation** per org — GitHub allows one installation of an App
   per org, so the ticket's "install twice" became an all→selected re-configuration
   of installation `156264905`, which WAS performed (Phase 3): repo grants were
   switched between "all" and "selected" and the API exposure was diffed
   (`fixtures/repos/install-156264905-page1.json` vs
   `install-156264905-2repos.json`; the API now reports `repository_selection:
   "selected"`).