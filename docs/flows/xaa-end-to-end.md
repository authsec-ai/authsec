# Flow: XAA End-to-End — From MCP Server to Tool Call

> How an AuthSec-protected MCP server and an XAA agent interact, start to finish.
>
> **Audience:** an engineer new to AuthSec who wants the *whole* mental model — from
> standing up a protected MCP server to an agent actually executing a tool on a user's
> behalf. This is a **workflow** doc: it explains *why each step exists* and *how the
> components talk to each other*, not how to install or configure anything.
>
> For deeper dives, see the linked primitives/flows at the bottom. If you haven't yet,
> skim `docs/authsec-platform-overview.md` (token families, participants) and
> `docs/flows/xaa-idjag.md` (the token mechanics) first.

---

## The shape of the whole thing

There are two phases. Everything in this doc is one or the other.

- **Phase 1 — Onboarding (mostly one-time, admin/build-time).** You teach AuthSec about
  your MCP server, what tools it has, what scopes those tools need, and you register the
  agent that will call it. Nothing is delegated yet; you're building the map.
- **Phase 2 — Runtime (per user, per session).** A user logs in, an agent obtains a
  delegated token on that user's behalf, and calls your tools. This is the XAA flow proper.

```
  PHASE 1 — ONBOARDING (build the map)
  ┌──────────────────────────────────────────────────────────────────────┐
  │ 1 Build protected MCP server   2 Register as Resource Server           │
  │ 3 Publish manifest (tools)     4 Configure scopes + roles              │
  │ 5 Register the AI agent (client)                                        │
  └──────────────────────────────────────────────────────────────────────┘

                          │
                          ▼  ▶ launch / run the app
                          │
  PHASE 2 — RUNTIME (walk the map)
  ┌──────────────────────────────────────────────────────────────────────┐
  │ 6 User logs in (OIDC) ─► Token A                                        │
  │ 7 Token Exchange ─► 8 ID-JAG (5-min assertion)                         │
  │ 9 JWT-Bearer redemption ─► 10 Access token (aud = your MCP server)     │
  │ 11 Agent calls a tool; your server verifies + enforces ─► result       │
  └──────────────────────────────────────────────────────────────────────┘
```

### The cast (who's involved)

- **You / the admin** — build the MCP server and onboard it.
- **The MCP server** — your protected API. In AuthSec terms, a **Resource Server (RS)**. MCP
  (Model Context Protocol) is how AI clients discover and call its **tools** — the callable
  actions it exposes, listed via `tools/list` and invoked via `tools/call`.
- **AuthSec** — the Authorization Server. It wears two hats: it *issues* delegation
  assertions and it *guards* your RS (decides who gets in, with what scopes).
- **The user** — the human whose authority is delegated (also called the **principal**, or
  **subject**, of a token).
- **The agent** — the AI client (Claude Code, a custom tool) that acts on the user's behalf.

### The tokens (three of them)

| Token | Born in | Lives | Audience | Purpose |
|---|---|---|---|---|
| **A — login token** | Step 6 (OIDC login) | session | where the user logged in | proof a real user authenticated |
| **B — ID-JAG** | Steps 7–8 (token-exchange) | ~5 min, one-shot | **AuthSec** (not your RS) | proof the user delegated to this agent |
| **C — access token** | Steps 9–10 (jwt-bearer) | ~1 hr, no refresh | **your MCP server** | the actual key to call your tools |

Each token is narrower and less powerful than the last. That funnel is the security model.

---

# Phase 1 — Onboarding

## Step 1 — Build the protected MCP server

**What happens.** You build an MCP server and put it behind AuthSec. "Protected" has a
concrete, testable meaning here — your server must do three things:

1. **Reject unauthenticated calls with a challenge.** An unauthenticated `tools/call` (or
   `tools/list`) returns `401` with a `WWW-Authenticate: Bearer …` header that includes a
   `resource_metadata` pointer. This is the RFC 9728 bearer challenge — it tells any MCP
   client *"you need a token, and here's where to learn how to get one."*
2. **Publish Protected Resource Metadata (PRM).** At
   `/.well-known/oauth-protected-resource`, your server advertises which Authorization
   Server protects it (AuthSec) and, optionally, which scopes it supports. This is the
   breadcrumb that lets clients — and AuthSec's own onboarding checks — discover how your
   server is secured.
3. **Verify AuthSec-issued tokens** on every call (covered in Step 11).

**Why it exists.** This is what makes your server a first-class OAuth resource rather than
an API with a bolted-on API key. The challenge + PRM pair is *discovery*: an agent that has
never seen your server can bootstrap the entire auth flow from a single `401`. It's also how
AuthSec validates that your server is genuinely reachable and genuinely protected before it
lets anyone rely on it.

## Step 2 — Register it as a Resource Server

**What happens.** You register the server with AuthSec as a **Resource Server (RS)**. The
one field that matters most is the **resource URI** — this becomes the *audience* that every
token minted for your server will carry, and the thing your server checks on every request.
AuthSec then runs a set of **readiness checks** against the live server:

- Is the PRM metadata URL reachable and non-empty?
- Does an unauthenticated call return the expected `401` bearer challenge?
- Is there a tool/scope snapshot yet (from manifest or discovery — Step 3)?
- Is a default access policy configured (Step 4)?
- Is at least one client registered, or is dynamic registration allowed (Step 5)?

Each check has a pass/fail state, and together they gate "is this RS ready for browser login
/ tool listing / tool enforcement."

**Why it exists.** The resource URI is the anchor of the whole confused-deputy defense: a
token minted for RS-A is worthless at RS-B because the audiences won't match. Registration is
also where AuthSec establishes the *identity* of your server so that later steps (scopes,
client approvals, token audience) all have something to bind to. The readiness checks exist
so onboarding fails loudly and early — you find out your server isn't returning a proper
challenge *now*, not when an agent's first real call mysteriously 500s.

> **How components interact:** AuthSec actively reaches out to your server (fetches PRM,
> sends an unauthenticated probe). Registration is not just a database row — it's a
> handshake that confirms your server behaves like a protected resource.

## Step 3 — Publish the manifest (tell AuthSec your tools)

**What happens.** AuthSec needs to know *what tools your server exposes* so it can reason
about per-tool authorization. There are two ways this inventory gets populated:

- **Path A — SDK manifest push.** Your server's AuthSec SDK **publishes a manifest** (the
  list of tools, a manifest version, a build id) to AuthSec. Every push is recorded as a
  *manifest attempt* (success / auth-failed / invalid / empty / error), which powers the
  "waiting for your first manifest…" polling UI during setup.
- **Path B — Discovery scan.** AuthSec actively connects to your server, runs the MCP
  `initialize` handshake, and calls `tools/list` (paginated) to enumerate tools itself. It
  also re-fetches PRM. If the server answers the scan with a `401` bearer challenge, AuthSec
  records that as *"reachable and properly protected"* and commits a zero-tool snapshot
  rather than treating it as a failure.

Either way, the result is a **tool inventory** tagged by source (SDK manifest, manual, or
scan), versioned by a **discovery generation number** so a half-finished scan never leaks
into policy.

**Why it exists.** XAA authorization is meaningful at the *tool* level — "this agent may
call `search` but not `delete`." That's only possible if AuthSec has a trustworthy list of
tools to hang scopes off of. The two paths exist for two realities: SDK-integrated servers
can *declare* their tools authoritatively (Path A), while servers you can't modify can still
be *discovered* over the wire (Path B). The generation number exists so tool policy is
always computed from one complete, coherent snapshot.

## Step 4 — Configure scopes (and the roles that grant them)

**What happens.** Now you connect tools to permissions to people. This is AuthSec's **RBAC**
(role-based access control), modeled as a chain:

```
  Role ─► permissions ─► OAuth scopes ─► (which tools they unlock)
   ▲
   └── a subject (user / service account) is bound to a Role (a "role binding") for this RS
```

Concretely:
- Your RS **declares the scopes it supports** (e.g. `tool:invoke`, `search:read`). Scopes it
  doesn't declare can never be granted — fail-closed.
- Each **tool is mapped to the scope(s) it requires** — this tool×scope map is the
  **scope matrix**.
- **Permissions map to scopes**, **roles bundle permissions**, and **role bindings** attach
  a subject (user, group, or service account) to a role for this RS.
- You typically set a **default access policy**: a default role automatically granted on a
  user's *first successful login* to this RS, so brand-new users aren't stranded with zero
  access.

**Why it exists.** This is the "authorization" half of the system, kept deliberately
separate from authentication. It's what lets AuthSec compute, at token time, the
**intersection** of *what was requested*, *what the RS supports*, and *what the subject's
roles actually grant* — and grant nothing more. The scope matrix is what turns a coarse
"has a valid token" into a fine-grained "may call *this specific tool*." The default policy
exists because otherwise every new user's first XAA attempt would resolve to zero scopes and
bounce to an admin approval queue — fine for high-security resources, needless friction for
open ones.

## Step 5 — Register the AI agent

**What happens.** The agent becomes an OAuth **client** known to AuthSec. Two routes:

- **Dynamic Client Registration (DCR)** — the agent self-registers with a single call and
  gets back a `client_id` and a management token. AI clients are auto-classified as `agent`
  from their software id. This is how tools like Claude Code onboard with zero manual setup.
- **Pre-registration** — an admin registers the client ahead of time.

For XAA the agent must be a **confidential client** (it authenticates with a real credential
— a client secret or, preferably, a private-key JWT), because in the redemption step it has
to prove *its own* identity, not just the user's.

The first time the agent tries to reach a new RS, AuthSec records the client↔RS connection.
If it's cross-workspace (or otherwise not pre-approved) it lands in a **pending approval**
state until an admin approves it. (This is separate from the per-user access request in
Step 9 — see the "three pending states" note in `xaa-idjag.md`.)

**Why it exists.** The agent needs a stable, authenticatable identity so that (a) it can be
held to credentials in the redemption step, (b) admins can govern which agents may reach
which resources, and (c) every token and audit record can name the acting party. DCR exists
because agents are numerous and ephemeral — hand-provisioning them doesn't scale.

> **End of Phase 1:** AuthSec now knows your server (RS + audience), its tools (manifest),
> what those tools require (scopes + roles), and the agent's identity. The map is built.

## Launch the application (the bridge to runtime)

Once the Resource Server and the AI agent are configured — and the RS's readiness checks
pass (Step 2) — the application can be **launched**: you run the MCP server so it's live and
ready to receive calls. Nothing has been delegated yet and no runtime token exists; you've
simply finished building the map and turned the server on.

From this point onward, everything is **runtime**. The remaining steps don't happen once —
they happen *every time* a user authenticates and the agent requests access to the MCP
server on that user's behalf. Onboarding was build-time and one-off; what follows is the
per-session loop.

---

# Phase 2 — Runtime (the XAA flow)

Here's the runtime in one picture; the steps below narrate it.

```
  User      Agent            AuthSec (issuing | redeeming)        Your MCP Server
   │          │                        │                                │
   │  login   │                        │                                │
   ├─────────────────────► OIDC (Hydra-backed) ─► Token A               │      Step 6
   │          │◄── Token A ────────────┤                                │
   │          │                        │                                │
   │          ├─ token-exchange ──────►│ (issuing hat)                  │      Step 7
   │          │   subject=Token A      │  mint ID-JAG                    │
   │          │◄── Token B (ID-JAG) ───┤  aud = AuthSec, ~5 min          │      Step 8
   │          │                        │                                │
   │          ├─ jwt-bearer ──────────►│ (redeeming hat)                │      Step 9
   │          │   assertion=Token B    │  authenticate agent            │
   │          │   + agent credential   │  verify+burn ID-JAG            │
   │          │                        │  map user, check approval,     │
   │          │                        │  intersect scopes              │
   │          │◄── Token C ────────────┤  aud = your RS, ~1 hr          │      Step 10
   │          │                        │                                │
   │          ├─ tools/call  Bearer Token C ───────────────────────────►│      Step 11
   │          │                        │◄─ verify (introspect/JWKS) ─────┤
   │          │◄──────────────── tool result ──────────────────────────┤
```

## Step 6 — User authentication (where Token A comes from)

**What happens.** The user logs in interactively through AuthSec (OIDC authorization_code +
PKCE; the interactive protocol runs on Hydra underneath, with AuthSec wrapping it in policy
and context binding). The user ends up holding **Token A**, an ordinary access token. If a
default access policy is set (Step 4), their first successful login auto-binds the default
role, so they immediately have some effective scopes for your RS.

**Why it exists.** Everything downstream is *delegation of the user's authority* — so a real
user has to have authenticated at least once. Token A is the seed: the proof that a genuine
human is behind whatever the agent later does. Without it, there is nothing to delegate.

## Step 7 — Token Exchange (ask for a delegation assertion)

**What happens.** The agent presents Token A back to AuthSec and asks to exchange it for a
delegation assertion — `grant_type=token-exchange`, explicitly requesting the ID-JAG token
type, and naming the target `resource` (your RS's URI) and the `scope` it wants. AuthSec
(wearing its **issuing** hat):

- validates the presented subject token (it accepts a few token shapes here),
- confirms the token really belongs to *this* agent (client binding),
- and — importantly — does **not** yet check RS approval or resolve scopes. Issuance is
  intentionally light.

**Why it exists — and why it's a separate call.** This step answers one question:
*"is this a legitimate delegation?"* It deliberately does **not** answer *"what may the
agent ultimately do at the resource?"* — that belongs to whoever guards the resource. Keeping
the two apart is what lets the issuing and redeeming roles be different servers (federation),
gives two independent verification checkpoints, and keeps the disposable delegation proof
separate from the actual power. Think *"get a notarized letter"* — you're not being admitted
anywhere yet, you're getting a portable, verifiable statement of delegation.

## Step 8 — The ID-JAG (the delegation assertion)

**What happens.** AuthSec mints **Token B, the ID-JAG** — a short-lived (~5 minutes), signed
statement that says *"user U delegated to agent A, targeting resource R, for scopes S."* Its
audience is **AuthSec itself** (the redeeming AS), *not* your MCP server. It is **not stored**
and it grants **no access** on its own.

**Why it exists.** This is the piece that makes cross-application delegation safe. The naive
alternative — forwarding the user's Token A to your server — is a classic confused-deputy
risk: Token A is audience-bound elsewhere and carries far too much authority. The ID-JAG
replaces "hand over a powerful, reusable key" with "issue a narrow, disposable, independently
verifiable *claim*." It names all four facts (who, through whom, where, how much), it's
signed so it can be verified without trusting the bearer, and it expires almost immediately
so a leak is nearly worthless. Crucially, it's a *claim, not a key*: possessing it gets you
nothing until you redeem it — and redemption is where all the gates live.

## Step 9 — JWT-Bearer redemption (the strict gate)

**What happens.** The agent brings the ID-JAG back to AuthSec — `grant_type=jwt-bearer`,
`assertion=<the ID-JAG>` — this time also authenticating with **its own** credential. AuthSec
(wearing its **redeeming** hat) runs the full gauntlet:

1. **Authenticate the agent** for real (client secret / private-key JWT). Step 7 was
   permissive; this is where a stranger is stopped.
2. **Validate the ID-JAG** — signature, type, audience (must be this AS), bound client, not
   expired. (Self-issued assertions verify against AuthSec's own keys; federated ones against
   a registered trusted issuer's published keys.)
3. **Resolve your RS** from the `resource` and confirm the ID-JAG was for it; reject
   self-delegation (a resource's own client can't use an ID-JAG to reach itself).
4. **Map the subject** to a local user (provisioning one on first contact if policy allows).
5. **Check the agent is approved** for your RS. If not, AuthSec records a **pending access
   request**, notifies admins, and returns a "pending" response with a status URL the agent
   can poll — first contact becomes a reviewable event, not a dead end.
6. **Resolve scopes** — the intersection of *requested* ⊆ *ID-JAG-delegated* ∩
   *RS-supported* ∩ *the user's RBAC-effective* scopes. Zero scopes → also a pending request.
   Fail-closed: the assertion can never grant more than the user actually holds.
7. **Mint the token and burn the ID-JAG atomically** — the access token is issued *and* the
   ID-JAG is marked one-time-used in a single operation. If it was already redeemed, the
   whole thing aborts and no token is produced.

**Why it exists.** This is the *authorization* half of the two-call design, owned by the
resource's guardian. It's where cheap-and-trusting (Step 7) becomes strict-and-suspicious.
Every check shrinks what can go wrong if any single credential leaked. The atomic burn is the
replay defense: a delegation letter is spent exactly once.

> **Note — roles bind to the user, not the agent.** The role granted at approval is always
> attached to the *user* (the delegated principal), never to the AI agent — which is why the
> issued token names the user as its subject and the agent only as its actor. The agent holds
> no permissions of its own; everything it may do flows from the user's roles. This anchors
> least-privilege and revocation on the human: revoke the user's role and every agent acting
> on their behalf loses that access at once.

## Step 10 — Access token issuance

**What happens.** Out comes **Token C**, a native AuthSec access token:

- **audience = your RS's resource URI** — usable only at your server,
- **subject = the user**, **actor = the agent** (the `act` claim) — so your server applies
  the *user's* permissions while knowing which agent acted,
- **scope = the narrowed set** from Step 9,
- **provenance** back to the exact ID-JAG and issuer that produced it,
- **~1 hour, non-refreshable** — when it expires, the agent delegates again.

**Why it exists.** This is the only credential your server ever trusts, and it's been
engineered to be safe to trust: minted for you alone, scope-limited to the user's real
entitlements, carrying both identities, revocable, and fully traceable.

## Step 11 — MCP tool execution

**What happens.** The agent finally calls your server: `Authorization: Bearer <Token C>` on a
`tools/call`. Your server (via the AuthSec SDK/gateway in front of it) does two things:

1. **Verify the token.** It confirms the token is a genuine AuthSec-native token (by key id),
   checks the signature, that it isn't expired or revoked, that its **audience is your RS**,
   that the agent's connection to your RS is still approved, and it **re-resolves scopes live**
   against current RBAC (so a role revoked a minute ago takes effect immediately — the token's
   baked-in scope is re-checked, never blindly trusted). The output is a clean identity: the
   principal (user), the actor (agent), and the effective scopes.
2. **Enforce the scope matrix.** Using the tool×scope map from Step 4:
   - **`tools/list` is filtered** to only the tools the token's scopes permit — the agent
     never even sees tools it can't use.
   - **`tools/call` is denied** if the specific tool's required scope isn't present.

If both pass, your server executes the tool and returns the result.

**Why it exists.** This is the payoff and the final trust boundary. Verification means your
server never takes the agent's word for anything — it independently confirms a cryptographic,
audience-bound, still-valid, still-authorized token. Live scope re-resolution means
authorization decisions reflect *now*, not token-mint time. The scope matrix is what makes
authorization *per tool* instead of all-or-nothing. And because the token names both user and
agent, every tool call is auditable end-to-end: *this call → this agent → this user → that
original login.*

---

## How to hold the whole model in your head

- **Onboarding builds a map; runtime walks it.** Steps 1–5 make your server known,
  discoverable, and scoped, and give the agent an identity. Steps 6–11 use that map to turn
  "a user exists" into "this agent may call this tool as this user, right now."
- **Two calls, because two questions.** Token-exchange asks *"is this a real delegation?"*
  JWT-bearer asks *"what may you do at this resource?"* Different owners, different trust
  domains, so different calls.
- **Three tokens, each narrower than the last.** Login token → delegation assertion →
  resource-bound access token. Broad identity funnels down to one action at one resource.
- **The resource server is the trust boundary.** The audience on Token C, checked by your
  server, is what makes the whole thing safe against replay and confused deputies.
- **AuthSec does the suspicious work; your server just verifies the signed result.** By the
  time Token C reaches you, the agent was authenticated, the assertion was verified and
  burned, approval was checked, and scopes were narrowed to the user's real entitlements.

---

## Related

- `docs/flows/xaa-idjag.md` — the token-exchange and jwt-bearer mechanics in detail
  (claims, gates, replay guard, trusted issuers, the "three pending states").
- `docs/flows/oidc-login.md` — Step 6 in detail (how Token A is produced).
- `docs/flows/mcp-discovery.md` — discovery + dynamic client registration (Steps 3 and 5).
- `docs/primitives/rbac-scopes.md` — the role → permission → scope chain and the 3-way
  intersection (Step 4).
- `docs/primitives/token-engine.md` — how native tokens are minted, signed, and verified.
- `docs/primitives/identity-principals.md` — principal (user) vs actor (agent).
- `docs/authsec-platform-overview.md` — the platform-wide overview (token families,
  feature flags, participants).
