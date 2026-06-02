# Running the demo locally on Windows + cloudflared

Companion to `mcp_v2_e2e_runbook.md`. The runbook assumes a public URL
at `https://mcp-dev.mcpauthz.com` resolves to your local MCP server.
This document gets you there on Windows with the cloudflared tunnel
config the demo expects.

If you already have the cloudflared tunnel running and serving
`mcp-dev.mcpauthz.com`, skip to the **Daily run** section.

---

## One-time cloudflared setup

The `authsec-mcp-demo` repo's `npm run share` script invokes:

```
cloudflared tunnel --config ~/.cloudflared/authsec-mcp-demo.yml run
```

It expects a tunnel already registered under your Cloudflare account
and a config file at `%USERPROFILE%\.cloudflared\authsec-mcp-demo.yml`.

### 1. Install cloudflared

The demo's `package.json` declares `cloudflared` as a dev-dep, but that
package installs the binary at `node_modules\cloudflared\bin\cloudflared.exe`,
not on your PATH. The npm script invokes it via `npx`, so you don't strictly
need a separate install — but the rest of these steps assume the binary
is reachable. Either:

**Option A — use the npm-installed binary directly** (no separate install):

```powershell
# From the authsec-mcp-demo directory after `npm install`:
$env:Path = "$pwd\node_modules\cloudflared\bin;$env:Path"
cloudflared --version
```

**Option B — install globally** (cleaner; works from any directory):

Download from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
or via winget:

```powershell
winget install --id=Cloudflare.cloudflared
```

### 2. Authenticate cloudflared

This opens a browser, you select the Cloudflare zone that owns
`mcpauthz.com`, and a cert.pem is written to
`%USERPROFILE%\.cloudflared\cert.pem`.

```powershell
cloudflared tunnel login
```

You need to be a member of the Cloudflare account that owns
`mcpauthz.com`. If you're not, ask whoever set that up to either
add you or share their tunnel credentials.

### 3. Create or reuse the tunnel

If a tunnel for `mcp-dev.mcpauthz.com` already exists in the
Cloudflare account, get its UUID and credentials file. List existing
tunnels:

```powershell
cloudflared tunnel list
```

If none exists, create one:

```powershell
cloudflared tunnel create authsec-mcp-demo
```

That prints a UUID and writes the credentials JSON to
`%USERPROFILE%\.cloudflared\<UUID>.json`. **Note the UUID — you need
it for the config file.**

### 4. Write the config file

Create `%USERPROFILE%\.cloudflared\authsec-mcp-demo.yml` with:

```yaml
tunnel: <UUID-from-step-3>
credentials-file: C:\Users\<your-username>\.cloudflared\<UUID-from-step-3>.json

ingress:
  - hostname: mcp-dev.mcpauthz.com
    service: http://localhost:8091
  - service: http_status:404
```

> Use the full Windows path on `credentials-file`. `~` does NOT expand in
> cloudflared YAML on Windows.

### 5. Route the DNS

```powershell
cloudflared tunnel route dns authsec-mcp-demo mcp-dev.mcpauthz.com
```

This creates a CNAME at Cloudflare pointing `mcp-dev.mcpauthz.com` at
your tunnel. One-time. If it errors with "An A, AAAA, or CNAME record
with that host already exists", that's fine — the DNS is already set up.

### 6. Verify

```powershell
cloudflared tunnel run authsec-mcp-demo
```

You should see `Registered tunnel connection` lines. In another
terminal:

```powershell
curl https://mcp-dev.mcpauthz.com/healthz
```

If the MCP server isn't running yet you'll get 502 — that's expected.
The point is to confirm the tunnel is reaching your local box.

`Ctrl-C` to stop. Now we run the real thing.

---

## Daily run

Three terminals. PowerShell is fine in all of them.

### Terminal 1 — local Postgres / your dev backend

Whatever you usually do to make `prod.api.authsec.ai` (or your local
dev API) reachable. If you're testing against deployed prod, you can
skip this terminal entirely.

### Terminal 2 — the MCP demo

```powershell
cd C:\Users\<you>\Desktop\Broadcom\authsec\authsec-mcp-demo
git checkout authsec-prod-mcp-v2
git pull
npm install                                    # first time only
Copy-Item .env.prod-mcp-v2 .env
# Open .env in an editor and set:
#   AUTHSEC_RESOURCE_SERVER_ID
#   AUTHSEC_INTROSPECTION_CLIENT_ID  (same UUID as above)
#   AUTHSEC_INTROSPECTION_CLIENT_SECRET
npm run share
```

`npm run share` boots two things concurrently:
- The MCP server on `localhost:8091`
- `cloudflared` pointing `mcp-dev.mcpauthz.com` at it

Watch for these log lines (mixed because concurrently prefixes each):
```
[mcp] MCP server listening on 0.0.0.0:8091
[mcp] [authsec] runtime initialized
[mcp] [authsec] scope matrix fetched: N tools
[mcp] [authsec] manifest published: M tools accepted
[tunnel] Registered tunnel connection ...
```

### Terminal 3 — runbook commands

In a fresh PowerShell, follow `mcp_v2_e2e_runbook.md`. PowerShell
equivalents to the bash commands in that doc:

#### Set env vars

```powershell
$env:AUTHSEC = "https://prod.api.authsec.ai"
$env:JWT = "eyJ..."           # admin JWT with tenant_id
```

#### Phase 1 — create the Application

```powershell
$body = @{
  name                  = "MCP Demo"
  application_type      = "mcp_server"
  public_base_url       = "https://mcp-dev.mcpauthz.com"
  protected_base_path   = "/mcp"
  resource_uri          = "https://mcp-dev.mcpauthz.com/mcp"
  scopes_supported      = @("mcp_demo.read","mcp_demo.write","mcp_demo.compute")
} | ConvertTo-Json

$resp = Invoke-RestMethod -Method Post `
  -Uri "$env:AUTHSEC/authsec/applications" `
  -Headers @{ Authorization = "Bearer $env:JWT" } `
  -ContentType "application/json" `
  -Body $body

$env:APP = $resp.id
"APP = $env:APP"
```

#### Phase 3 — rotate introspection secret

```powershell
$resp = Invoke-RestMethod -Method Post `
  -Uri "$env:AUTHSEC/authsec/applications/$env:APP/rotate-introspection-secret" `
  -Headers @{ Authorization = "Bearer $env:JWT" }
$env:RSSECRET = $resp.introspection_secret
"RSSECRET = $env:RSSECRET"
```

Paste `$env:APP` and `$env:RSSECRET` into the demo's `.env` and restart
`npm run share` (Ctrl-C in terminal 2 and re-run).

#### Phase 7 — DCR

```powershell
$body = @{
  client_name                = "MCP CLI Test Client"
  redirect_uris              = @("http://localhost:9999/cb")
  grant_types                = @("authorization_code","refresh_token")
  response_types             = @("code")
  token_endpoint_auth_method = "none"
  resource                   = "https://mcp-dev.mcpauthz.com/mcp"
  scope                      = "openid offline_access mcp_demo.read mcp_demo.compute"
} | ConvertTo-Json

$resp = Invoke-RestMethod -Method Post `
  -Uri "$env:AUTHSEC/authsec/oauth/v2/register" `
  -ContentType "application/json" -Body $body
$env:CLIENT = $resp.client_id
"CLIENT = $env:CLIENT"
```

#### Phase 8 — authorize → callback → token

Browser part: open the authorize URL just like the runbook says.
Catch the callback on Windows with PowerShell:

```powershell
# Minimal one-shot callback server. Run before clicking through the
# browser; it prints the ?code=... value once and exits.
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:9999/")
$listener.Start()
$ctx = $listener.GetContext()
$code = [System.Web.HttpUtility]::ParseQueryString($ctx.Request.Url.Query)["code"]
$ctx.Response.StatusCode = 200
$ctx.Response.OutputStream.Close()
$listener.Stop()
"CODE = $code"
$env:CODE = $code
```

Then exchange:

```powershell
$form = @{
  grant_type    = "authorization_code"
  client_id     = $env:CLIENT
  code          = $env:CODE
  redirect_uri  = "http://localhost:9999/cb"
  code_verifier = "verifier-string"
  resource      = "https://mcp-dev.mcpauthz.com/mcp"
}
$resp = Invoke-RestMethod -Method Post `
  -Uri "$env:AUTHSEC/authsec/oauth/v2/token" `
  -ContentType "application/x-www-form-urlencoded" `
  -Body $form
$env:ACCESS  = $resp.access_token
$env:REFRESH = $resp.refresh_token
"ACCESS = $env:ACCESS"
```

#### Phase 9 — introspect with Basic auth

```powershell
$creds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($env:APP):$($env:RSSECRET)"))
Invoke-RestMethod -Method Post `
  -Uri "$env:AUTHSEC/authsec/oauth/v2/introspect" `
  -Headers @{ Authorization = "Basic $creds" } `
  -ContentType "application/x-www-form-urlencoded" `
  -Body @{ token = $env:ACCESS }
```

#### Phase 10 — call an MCP tool

```powershell
$body = @{
  jsonrpc = "2.0"
  id      = 1
  method  = "tools/call"
  params  = @{
    name      = "add_numbers"
    arguments = @{ a = 2; b = 3 }
  }
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Method Post `
  -Uri "https://mcp-dev.mcpauthz.com/mcp" `
  -Headers @{ Authorization = "Bearer $env:ACCESS" } `
  -ContentType "application/json" `
  -Body $body
```

---

## Troubleshooting on Windows

| Symptom | Diagnosis |
| --- | --- |
| `cloudflared: command not found` | Either you skipped install or PATH isn't set. Try `node_modules\cloudflared\bin\cloudflared --version`. |
| Tunnel runs but `curl https://mcp-dev.mcpauthz.com` returns 502 | MCP server isn't up yet on `localhost:8091`, or `npm run dev:public` crashed. Check terminal 2's logs. |
| Tunnel exits with `failed to fetch the tunnel configuration` | Your `~/.cloudflared/authsec-mcp-demo.yml` references a tunnel UUID that doesn't exist in your Cloudflare account. Re-run `cloudflared tunnel list`. |
| Browser callback never returns the code | Windows Firewall is blocking port 9999. Allow it once when prompted, or use a different port (update both the listener and the `redirect_uri` in the registered client). |
| `Invoke-RestMethod` 401 on `/authsec/applications` | JWT is missing `tenant_id` or expired. Decode the JWT at jwt.io to confirm the claims. |
| `manifest published: HTTP 401` in terminal 2 logs | `AUTHSEC_INTROSPECTION_CLIENT_ID` ≠ `AUTHSEC_RESOURCE_SERVER_ID`, or the secret is wrong. They MUST both be the Application's UUID. |
| `scope matrix fetch: HTTP 404` | The backend doesn't have the SDK route alias I added (`/authsec/resource-servers/:id/sdk-policy`). Either deploy the latest `authsec-prod-mcp-v2` commit (`86d237c` or newer), or the SDK is computing a URL the backend doesn't serve. |
| Tools call returns 403 `insufficient_scope` | The access token's scope doesn't include what the tool requires. Check Phase 9 — what does introspect say the scope actually is? Hydra/consent may have narrowed it. |
| `npm run share` exits immediately on Windows | `concurrently -k` sometimes loses signals on Windows. Run the two commands in separate terminals: `npm run dev:public` in one, `npm run tunnel` in another. |
