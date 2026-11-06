# AuthSec agent gateway

A policy enforcement point you run next to your agents. It proxies MCP tool
calls (Streamable HTTP) and model calls (OpenAI-compatible and Anthropic
APIs), asks AuthSec over the OpenID AuthZEN Authorization API 1.0 whether
each call is allowed, enforces the answer, and forwards allowed calls with
**your** credentials. Spec: `.claude/specs/SPEC-agent-runtime-gateway.md`.

What reaches AuthSec: the agent's gateway id and selector attributes, the MCP
server and tool name or the provider and model, a SHA-256 digest of the tool
arguments, the tool definition hash, the decision, latency, HTTP status and
token counts. Never prompts, completions, tool arguments or results, provider
keys or MCP credentials.

## 1. Register the gateway in AuthSec

```sh
curl -X POST https://api.authsec.ai/authsec/api/iga/v1/agent-runtime/gateways \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"prod-cluster-1"}'
# -> data.credential = agw_...   (shown once; store it as a Secret)
```

Write tool policies (`/api/iga/v1/agent-runtime/tool-policies`) and choose
the workspace mode (`PUT /gateway-settings {"mode":"observe"|"enforce"}`;
observe allows what no policy decides, enforce denies it). Try a policy
without traffic with `POST /tool-policies/evaluate`.

## 2. Configure and run

```sh
agent-gateway gen-key        # one per agent: give the key to the agent, the sha256 to config.yaml
cp config.example.yaml config.yaml   # edit
docker build -f deploy/agent-gateway/Dockerfile -t authsec/agent-gateway:dev .
docker run -p 8080:8080 -v $PWD/config.yaml:/etc/agent-gateway/config.yaml:ro \
  -e AUTHSEC_GATEWAY_CREDENTIAL=agw_... -e OPENAI_API_KEY=sk-... authsec/agent-gateway:dev
```

Kubernetes: `values.yaml` is a minimal values file for a generic
Deployment/Service chart (Secrets for the credential and keys, a ConfigMap
for `config.yaml`, a small volume for tool pins, non-root, read-only root
filesystem). Keep the Service internal.

## 3. Point agents at it

| Agent uses | Set |
|---|---|
| OpenAI SDK | `base_url=http://agent-gateway:8080/llm/openai/v1`, `api_key=agk_...` |
| Anthropic SDK | `base_url=http://agent-gateway:8080/llm/anthropic`, `api_key=agk_...` |
| MCP client | server URL `http://agent-gateway:8080/mcp/<name>`, header `X-AuthSec-Agent-Key: agk_...` |

With mTLS (`tls.client_ca_file`), a client certificate's SPIFFE ID names the
agent instead of a key.

## Behaviour

- **Denied tool call**: JSON-RPC error `-31001` with `data.reason`
  (`policy_deny`, `not_allowlisted`, `default_deny`, `rate_limited`,
  `tool_definition_changed`, `tool_not_pinned`, `pdp_unavailable`).
- **Denied model call**: HTTP 403 in the provider's error format.
- **Header mismatch** (`Mcp-Method`/`Mcp-Name` vs body): 400, JSON-RPC `-32020`.
- **Tool definition changed** since it was pinned: calls refused until
  approved: `curl -X POST 127.0.0.1:9091/admin/pins/approve -H "Authorization:
  Bearer $AGENT_GATEWAY_ADMIN_TOKEN" -d '{"server":"github","tool":"create_issue"}'`.
- **AuthSec unreachable** (`fail_mode`): `auto` (default) denies tools and
  models covered by a deny policy, and everything in enforce mode; `closed`
  denies all; `open` allows all. Every such decision is logged and uploaded
  when AuthSec is back.
- Decisions are cached for the TTL AuthSec returns (workspace
  `cache_ttl_seconds`, default 30 s; never for rate-limited policies).
