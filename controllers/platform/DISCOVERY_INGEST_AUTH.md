# Discovery ingest auth: operator rollout

The discovery ingress (`POST /authsec/discovery/agent-registration`, `/sightings`,
`/lifecycle`, `/resync-manifest`, `/rbac-snapshot`) used to trust the
`workspace_id` in the request body. Now each call is checked against the
`Authorization: Bearer <ingest token>` the agent sends. The code is in
`discovery_ingest_auth.go`. The mode is set by `IGA_DISCOVERY_INGEST_AUTH` on
the control plane:

| mode | no token / unknown / revoked token / bound token used for another source | valid token for ANOTHER workspace |
|---|---|---|
| `off` | accepted, nothing checked | accepted, nothing checked |
| `warn` (default) | **accepted**, logged and counted | **403** |
| `enforce` | **401** `{"error":"ingest token required"}` | **403** |

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
   source. The response's `token` (`aid_...`) is shown once and cannot be
   recovered. Only its sha256 is stored. `GET /authsec/discovery/ingest-tokens`
   lists tokens by `token_prefix` and `last_used_at`.

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

4. **Switch to enforce:** set `IGA_DISCOVERY_INGEST_AUTH=enforce` on the
   control plane and restart. The mode is logged at startup (`discovery ingress
   auth mode: enforce`). Any value other than `off`, `warn` or `enforce` is
   treated as `enforce`, so a typo cannot leave the ingress open.

**Revoking** (`DELETE /authsec/discovery/ingest-tokens/<id>`) takes effect on the
next call. In `enforce`, the agent that holds the revoked token gets 401 until
it receives a new one. The row is kept, with `revoked_at` set.
