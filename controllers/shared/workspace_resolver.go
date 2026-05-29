// Package shared — workspace_resolver.go
//
// Canonical workspace resolution for end-user login/registration flows.
//
// Background: AuthSec v3 used a "tenant_mappings" table to bridge an OAuth
// client_id to a workspace_id. That was wrong by OAuth 2.1 + the MCP
// authorization spec — OAuth clients (Claude Desktop, Cursor, an IDE plugin,
// a CLI) are GLOBAL software, not workspace-owned. Resource Servers (MCP
// servers) ARE workspace-owned. The (user, workspace) tuple is what matters
// for end-user identity; the OAuth client is workspace-agnostic.
//
// Furthermore, the same email may exist as DIFFERENT user_ids in DIFFERENT
// workspaces (Slack/GitHub model). So email alone CANNOT identify a workspace
// either — workspace MUST come from a separate, unambiguous source.
//
// Sources accepted, in priority:
//  1. Host header (subdomain) — the canonical source for hosted-UI flows
//  2. Hydra login_challenge — for OAuth-initiated flows
//  3. Explicit ?workspace=<id-or-slug> query param — for in-app workspace switching
//
// Source that is NOT accepted: a client_id from a request body. There is no
// general client_id → workspace mapping in a correct OAuth 2.1 model.
package shared

import (
	"fmt"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// WorkspaceFromHost resolves the workspace from the Host header. This is the
// canonical source for hosted-UI flows where the UI navigates to a workspace's
// hostname (e.g., aditya.dev.authsec.dev).
//
// Matching strategy:
//  1. Exact match on workspaces.workspace_domain (full hostname)
//  2. Subdomain (leftmost label) matched against workspaces.workspace_domain OR workspaces.slug
//
// Returns uuid.Nil and an error if no workspace matches. Callers should treat
// "no workspace from host" as a hard error for endpoints that REQUIRE workspace
// context (login, registration, etc.) — the right HTTP status is usually 400
// or 404 ("unknown workspace"), not 500.
func WorkspaceFromHost(c *gin.Context) (uuid.UUID, error) {
	host := strings.ToLower(strings.TrimSpace(c.Request.Host))
	// Strip port if present (Host header is "<host>[:<port>]")
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return uuid.Nil, fmt.Errorf("empty Host header")
	}

	db := config.GetDatabase()
	if db == nil {
		return uuid.Nil, fmt.Errorf("database not initialized")
	}

	// 1. Exact match on full hostname.
	var id uuid.UUID
	if err := db.QueryRow(
		`SELECT id FROM workspaces WHERE LOWER(workspace_domain) = $1 LIMIT 1`,
		host,
	).Scan(&id); err == nil {
		return id, nil
	}

	// 2. Leftmost label as slug or as truncated workspace_domain.
	if dot := strings.IndexByte(host, '.'); dot > 0 {
		slug := host[:dot]
		if err := db.QueryRow(
			`SELECT id FROM workspaces WHERE LOWER(slug) = $1 OR LOWER(workspace_domain) = $1 LIMIT 1`,
			slug,
		).Scan(&id); err == nil {
			return id, nil
		}
	}

	return uuid.Nil, fmt.Errorf("no workspace matches host %q", host)
}

// lookupWorkspaceRef resolves a workspace reference that may be a UUID, a slug,
// or a workspace_domain. Returns uuid.Nil + error if it doesn't resolve.
func lookupWorkspaceRef(ref string) (uuid.UUID, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return uuid.Nil, fmt.Errorf("empty workspace reference")
	}
	db := config.GetDatabase()
	if db == nil {
		return uuid.Nil, fmt.Errorf("database not initialized")
	}
	// UUID form — validate existence.
	if id, err := uuid.Parse(ref); err == nil {
		var exists bool
		if qErr := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM workspaces WHERE id = $1)`, id).Scan(&exists); qErr == nil && exists {
			return id, nil
		}
		return uuid.Nil, fmt.Errorf("workspace %s not found", ref)
	}
	// Slug or workspace_domain form.
	lower := strings.ToLower(ref)
	var id uuid.UUID
	if err := db.QueryRow(
		`SELECT id FROM workspaces WHERE LOWER(slug) = $1 OR LOWER(workspace_domain) = $1 LIMIT 1`,
		lower,
	).Scan(&id); err == nil {
		return id, nil
	}
	return uuid.Nil, fmt.Errorf("workspace %q not found", ref)
}

// ResolveWorkspace is the canonical resolver for end-user login/registration
// handlers. The handler passes whatever explicit workspace reference it parsed
// from the request body (e.g. CustomLoginStatus.WorkspaceID, which the UI sets
// from the page-data response that resolved the Hydra login_challenge).
//
// Resolution order:
//  1. explicit (request-body workspace_id / slug / domain) — what the UI sends
//     after resolving the OAuth login_challenge
//  2. ?workspace= query parameter
//  3. Host header (workspace subdomain)
//
// Notably absent: email-based lookup. Email is ambiguous across workspaces
// (same email, different workspace, different user_id), so it cannot determine
// the workspace. One of the three sources above must be present.
func ResolveWorkspace(c *gin.Context, explicit string) (uuid.UUID, error) {
	if strings.TrimSpace(explicit) != "" {
		return lookupWorkspaceRef(explicit)
	}
	if q := strings.TrimSpace(c.Query("workspace")); q != "" {
		return lookupWorkspaceRef(q)
	}
	return WorkspaceFromHost(c)
}

// RequireWorkspaceFromRequest is the no-explicit-value variant for handlers
// that don't carry a workspace field in their request body. Tries ?workspace=
// then Host header.
func RequireWorkspaceFromRequest(c *gin.Context) (uuid.UUID, error) {
	return ResolveWorkspace(c, "")
}

// WorkspaceFromHydraChallenge resolves the workspace for an OAuth-initiated
// flow by calling Hydra's Admin API to fetch the login challenge, then mapping
// the requested resource URI (RFC 8707) to a resource_servers row, which
// carries workspace_id.
//
// PHASE-A SCOPE: stubbed. The current UI flow does not pass a login_challenge
// to /uflow/user/login/status — it uses the host header. This function is
// declared so handlers serving OAuth-initiated paths can call it; the full
// Hydra Admin API integration ships when the federated/OAuth flow is exercised
// end-to-end.
//
// Until implemented, returns uuid.Nil + a "not implemented" error so callers
// fall through to WorkspaceFromHost.
func WorkspaceFromHydraChallenge(c *gin.Context, challenge string) (uuid.UUID, error) {
	if challenge == "" {
		return uuid.Nil, fmt.Errorf("no login_challenge provided")
	}
	// TODO Phase A.1: call Hydra Admin API GET /admin/oauth2/auth/requests/login?challenge=...
	// Extract requested_audience / resource (RFC 8707), look up
	// resource_servers.workspace_id by resource_uri.
	return uuid.Nil, fmt.Errorf("hydra-challenge workspace resolution not yet implemented")
}
