# Discovery ingest auth: operator rollout

The discovery ingress (`POST /authsec/discovery/agent-registration`, `/sightings`,
`/lifecycle`, `/resync-manifest`, `/rbac-snapshot`) used to trust the
`workspace_id` in the request body. Now each call is checked against the
`Authorization: Bearer <ingest token>` the agent sends. The code is in
`discovery_ingest_auth.go`. The mode is set by `IGA_DISCOVERY_INGEST_AUTH` on
the control plane:

| mode | no token / unknown / revoked / expired token / token whose bound source was deleted / bound token used for another source | valid token for ANOTHER workspace |
|---|---|---|
| `off` | accepted, nothing checked | accepted, nothing checked |
| `warn` (default) | **accepted**, logged and counted | **403** |
| `enforce` | **401** `{"error":"ingest token required"}` | **403** |

**`warn` is the default, and it does not protect the ingress.** It exists so
agents installed before tokens existed keep working while tokens are rolled
out: in `warn` anyone who knows a workspace id can still write to that
workspace's inventory and graph. Until the mode is `enforce` the control plane
says so in three places:

- at startup, a `WARNING` banner after `discovery ingress auth mode: warn`;
- the gauge `discovery_ingest_auth_enforced{mode="warn"} 0` on
  `/authsec/metrics` (`1` with `mode="enforce"`). Alert on
  `discovery_ingest_auth_enforced == 0`;
- `GET /authsec/uflow/health` → `checks.discovery_ingest_auth`
  (`{"mode":"warn","enforced":false,"warning":"..."}`). This check never makes
  the service unhealthy.

Rollout is not finished until you have done step 4 below.

A token bound to a discovery source is valid only for calls that resolve to
that source. For sightings, lifecycle, resync and rbac-snapshot that is the
body's `discovery_source_id`. For registration it is the row the agent's
`(kind, instance_id)` already has. A call that names no source, or a
registration that would create a new source, does not resolve to it. Use an
unbound token (the default) for a new agent. Mint a bound token only for an
agent that has already registered.

## Rollout

1. **Mint a token** as a `discovery:admin` in the workspace:

   ```
   curl -X POST https://<control-plane>/authsec/discovery/ingest-tokens \
     -H "Authorization: Bearer <admin token>" -H "Content-Type: application/json" \
     -d '{"label": "prod-eu cluster"}'
   ```

   Optionally add `"discovery_source_id": "<id>"` to bind it to one registered
   source, and `"expires_at": "2027-10-01T00:00:00Z"` (RFC 3339) to make it
   expire. The expiry must be in the future and at most two years away (a 400
   otherwise); omitted, the token never expires. The response's `token`
   (`aid_...`) is shown once and cannot be recovered. Only its sha256 is
   stored. `GET /authsec/discovery/ingest-tokens` lists tokens by
   `token_prefix`, with `last_used_at`, `revoked_at`, `expires_at`, `expired`,
   `source_bound` and `source_deleted`.

2. **Put it in the agent's Helm secret**, not in a `--set` (a `--set` value can
   be recovered from the release history):

   ```
   kubectl -n <agent-ns> create secret generic authsec-iga-source \
     --from-literal=sourceToken='aid_...'
   helm upgrade <release> authsec-iga-agent --reuse-values \
     --set controlPlane.existingSecret=authsec-iga-source
   ```

   The agent already sends `SOURCE_TOKEN` as the bearer on every ingress call.

3. **Watch the warn logs go quiet.** In `warn` the control plane logs a line
   like `discovery ingest auth (warn): accepted /authsec/discovery/sightings for
   workspace <id> ... without a valid ingest token: missing`. It logs at most one
   line per workspace, route and reason per minute, with a count of the lines it
   suppressed. The same outcomes are counted in
   `auth_requests_total{auth_type="discovery_ingest"}` (results
   `accepted_token`, `accepted_unauthenticated_<missing|invalid|wrong_source>`,
   `rejected_other_workspace`). The token's `last_used_at` should also start
   moving (it is updated at most once a minute). When no
   `accepted_unauthenticated_*` result has grown for a full agent cycle
   (registration heartbeat, resync and RBAC sweep intervals), every agent is
   sending a valid token.

   A `403 ingest token is not valid for this workspace` means the agent's
   secret holds another workspace's token. This is refused in `warn` as well,
   because a token never authorises another workspace.

4. **Switch to enforce.** Before you do, check all three:

   - every agent's Secret holds a token: in `GET
     /authsec/discovery/ingest-tokens` each token you rolled out has a recent
     `last_used_at`, and none of them is `expired` or about to be;
   - `sum(increase(auth_requests_total{auth_type="discovery_ingest",result=~"accepted_unauthenticated_.*"}[<one full agent cycle>]))`
     is `0` (or the control plane has logged no `discovery ingest auth (warn):
     accepted` line for a full cycle);
   - no `rejected_other_workspace` is growing (a 403 is a mis-pasted secret
     that will still fail after the switch).

   Then set the variable on the control plane's Deployment and restart it, for
   example:

   ```
   kubectl -n <control-plane-ns> set env deployment/<control-plane> IGA_DISCOVERY_INGEST_AUTH=enforce
   kubectl -n <control-plane-ns> rollout status deployment/<control-plane>
   ```

   (or the same key in whatever manages the control plane's environment, so
   the next deploy does not revert it). Confirm it took on every replica:
   the startup log reads `discovery ingress auth mode: enforce` with no
   `WARNING` banner, `discovery_ingest_auth_enforced{mode="enforce"}` is `1`,
   and `checks.discovery_ingest_auth.enforced` is `true`. Any value other than
   `off`, `warn` or `enforce` is treated as `enforce`, so a typo cannot leave
   the ingress open. To back out, set it to `warn` and restart.

## Token lifecycle

A token stops working when any of these happens, and in every case its row is
**kept** (never deleted), so what it authorised stays attributable to it:

- **Revoked** (`DELETE /authsec/discovery/ingest-tokens/<id>`): takes effect on
  the next call. `revoked_at` is set; a second revoke keeps the first time.
- **Expired**: from `expires_at` on, the token is refused exactly like a revoked
  one (401 in `enforce`, accepted and counted as `invalid` in `warn`). The list
  shows `expired: true`. Nothing is written to the row; the expiry is checked
  on every call against the database clock.
- **Its bound source was deleted**: deleting a discovery source revokes every
  token bound to it in the same transaction, before the source row goes. The
  token is then listed with `revoked_at` set, `source_bound: true`,
  `discovery_source_id: null` and `source_deleted: true`. A bound token never
  becomes a workspace-wide token because its source is gone; the table refuses
  an unrevoked one (`discovery_ingest_tokens_bound_chk`), and verification
  refuses it as well. Unbound (workspace) tokens are not affected by deleting a
  source.

In `enforce`, an agent whose token stopped working gets 401 until it is given a
new one. Deleting the whole **workspace** deletes its tokens with it.

## Rotation

There is no in-place rotation; a token's secret never changes. To rotate, with
no gap:

1. **Mint a new token** (same binding, a new `expires_at` if you use expiry).
2. **Roll the agent's Secret** to the new token and restart the agent:

   ```
   kubectl -n <agent-ns> create secret generic authsec-iga-source \
     --from-literal=sourceToken='aid_<new>' --dry-run=client -o yaml | kubectl apply -f -
   kubectl -n <agent-ns> rollout restart deployment/<agent>
   ```

3. **Wait until the new token has a `last_used_at`** (written on its first use,
   then at most once a minute) and the old one's stops moving.
4. **Revoke the old token** (`DELETE /authsec/discovery/ingest-tokens/<old id>`).

Both tokens work between steps 1 and 4. With expiry, start a rotation well
before the old token's `expires_at`: once it passes, an agent still holding it
is refused in `enforce`.
