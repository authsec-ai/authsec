# SPEC: [Feature name]

> Copy this template for every new feature spec. The spec is the contract
> between product intent and implementation. It lives in `.claude/specs/` and
> is referenced by the `/ship` skill and the subagent reviewers.
>
> Fill in every section before starting implementation. Leave nothing blank —
> a blank section means "we haven't thought about this yet."

## Summary

One paragraph. What is this feature? Who uses it? What problem does it solve?

## Scope

**In scope:**
- bullet each capability that WILL be built

**Out of scope (deferred):**
- bullet each thing that seems related but will NOT be in this change

## Affected repos

Answer every row — "none" is a valid and required answer, not a blank.

| Repo | What changes | Why / why not |
|---|---|---|
| `authsec` | (new endpoint? new table? new service? none?) | |
| `Authsec-ui` | (new page? new slice? existing page change? none?) | |
| `sdk-authsec` | (new SDK method? parity TODO? none?) | Does an SDK caller need to do this programmatically, not just via the admin console? |
| `authsec-doc` | (new doc page? update existing? none?) | Does a developer or operator need to know this exists to use it? |
| Production K3s | (new env/config/workload? none?) | Does this change the canonical K3s topology or deployment verification? |

**SDK decision rule:** if the answer is "none", write one sentence explaining why an SDK caller doesn't need this. Silence = unresolved.

## Backend spec (authsec)

### Schema changes

If the schema changes, describe the column/table change here.
Implementation: add the next numbered migration for deployed databases and update
`001_bootstrap.sql` to the same final state.
Reference: `authsec/docs/primitives/schema.md`

```sql
-- Describe the change (not the full SQL)
ALTER TABLE example ADD COLUMN foo TEXT; -- describe the intended end state
-- Implementation also updates 001_bootstrap.sql for fresh databases.
```

### New endpoints

For each new endpoint:

```
METHOD /path
Auth: [bearer token / admin session / none]
Request body: { field: type, ... }
Response 200: { field: type, ... }
Errors: 400 (validation), 401, 403, 404, 500
```

### Token flow changes (if any)

If this affects a token flow, reference the relevant flow doc and describe
what changes. The token engine invariants must be preserved — see
`authsec/docs/primitives/token-engine.md`.

## Frontend spec (Authsec-ui)

### New page(s)

For each new page, specify:
- Route path
- `ConsolePage` title / description / actions
- Table columns (if it has a table)
- Drawer fields (if it has a detail drawer)
- Which RTK Query slice serves it

### Modified page(s)

Describe the change to existing pages.

## SDK impact

**Answer this even if the answer is "none."**

Ask: *Could an SDK user (an agent, a workload, an MCP server) need to call this
programmatically — not just an admin clicking in the console?*

- If **yes**: which SDK(s)? New method signature? Parity status for the other 2?
- If **no**: one sentence why (e.g. "admin-only operation, no machine caller scenario").

Parity rule: if one SDK gets a new method, the other two get a TODO comment minimum.

## Acceptance criteria

Concrete, testable statements:

- [ ] `curl -X POST /new/endpoint ...` returns `{"status": "ok"}` with a valid token
- [ ] The new page shows in the sidebar under [section]
- [ ] `npx tsc --noEmit` exits 0 in Authsec-ui after the change
- [ ] `go build ./...` exits 0 in authsec after the change
- [ ] Introspect on the new token returns `{active: true, tf: "xxx", sub: "..."}`

## Implementation plan

Short ordered list of steps. Each step maps to one commit.

1. Schema: add `NNN_change.sql` and update table Y in `001_bootstrap.sql`
2. Model: update Go struct
3. Service: add `GetXxx` + `CreateXxx` methods
4. Controller: add route handler + route registration
5. UI slice: `injectEndpoints` on `baseApi`
6. UI page: `ConsolePage` + table + drawer
7. Build, K3s deploy, migration-ledger check, and smoke test
8. Commit each step

## Related docs

| Doc | Why relevant |
|---|---|
| `authsec/docs/primitives/schema.md` | schema change procedure |
| `authsec/docs/primitives/token-engine.md` | if token issuance is affected |
| `Authsec-ui/docs/console-standard.md` | console page pattern |
| `Authsec-ui/docs/rtk-query.md` | RTK Query slice pattern |
