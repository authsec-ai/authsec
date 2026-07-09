package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/tokens"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/utils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type OAuthASService struct {
	db        *gorm.DB
	authzCtx  *AuthorizationContextService
	rsService *ResourceServerService
	jwksCache *jwksCache
}

var (
	// ErrResourceInferenceUnavailable means no single compatible resource server
	// could be determined for a client when the request omitted RFC 8707 resource.
	ErrResourceInferenceUnavailable = errors.New("resource inference unavailable")
	// ErrResourceInferenceAmbiguous means more than one compatible resource server
	// matched, so the caller must send resource explicitly.
	ErrResourceInferenceAmbiguous = errors.New("resource inference ambiguous")
)

func NewOAuthASService(db *gorm.DB) *OAuthASService {
	return &OAuthASService{
		db:        db,
		authzCtx:  NewAuthorizationContextService(db),
		rsService: NewResourceServerService(db),
		jwksCache: &jwksCache{},
	}
}

// ASMetadata returns the OIDC Discovery / RFC 8414 Authorization Server Metadata.
// This is a superset: OIDC Discovery 1.0 extends RFC 8414 with id_token, userinfo,
// and session management fields. Both /.well-known/openid-configuration and
// /.well-known/oauth-authorization-server serve this same document.
func (s *OAuthASService) ASMetadata(baseURL string) map[string]interface{} {
	meta := map[string]interface{}{
		// RFC 8414 core
		"issuer":                   baseURL,
		"authorization_endpoint":   baseURL + "/oauth/authorize",
		"token_endpoint":           baseURL + "/oauth/token",
		"registration_endpoint":    baseURL + "/oauth/register",
		"introspection_endpoint":   baseURL + "/oauth/introspect",
		"revocation_endpoint":      baseURL + "/oauth/revoke",
		"jwks_uri":                 baseURL + "/oauth/jwks",
		"response_types_supported": []string{"code"},
		"response_modes_supported": []string{"query"},
		// client_credentials is intentionally NOT advertised when XAA_M2M is off.
		// The flag re-adds it (and confidential auth methods) when native M2M ships.
		"grant_types_supported":                         s.m2mGrantTypes(),
		"token_endpoint_auth_methods_supported":         s.m2mTokenAuthMethods(),
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":    []string{"none"},
		"code_challenge_methods_supported":              []string{"S256"},
		"resource_indicators_supported":                 true,

		// OIDC Discovery 1.0 extensions
		"userinfo_endpoint":                     baseURL + "/oauth/userinfo",
		"end_session_endpoint":                  baseURL + "/oauth/logout",
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			"email", "email_verified", "name", "preferred_username", "picture",
		},
	}

	// CIBA (OpenID Connect CIBA Core 1.0) endpoints — only advertised when XAA_CIBA is on.
	if config.AppConfig != nil && config.AppConfig.XAACiba {
		meta["backchannel_authentication_endpoint"] = baseURL + "/oauth/bc-authorize"
		meta["backchannel_token_delivery_modes_supported"] = []string{"poll"}
		meta["backchannel_user_code_parameter_supported"] = false
	}

	// Token exchange / ID-JAG issuance (RFC 8693 + draft-ietf-oauth-identity-assertion-authz-grant-04).
	if config.AppConfig != nil && config.AppConfig.XAAIssuance {
		meta["identity_chaining_requested_token_types_supported"] = []string{
			"urn:ietf:params:oauth:token-type:id-jag",
		}
		meta["authorization_grant_profiles_supported"] = []string{
			"urn:ietf:params:oauth:grant-profile:id-jag",
		}
	}

	return meta
}

// m2mGrantTypes returns the grant_types_supported list for AS metadata.
// client_credentials is only advertised when XAA_M2M is enabled.
// jwt-bearer is only advertised when XAA_REDEMPTION is enabled.
// CIBA grant is only advertised when XAA_CIBA is enabled.
// token-exchange is only advertised when XAA_ISSUANCE is enabled.
func (s *OAuthASService) m2mGrantTypes() []string {
	base := []string{"authorization_code", "refresh_token"}
	if config.AppConfig != nil && config.AppConfig.XAAm2m {
		base = append(base, "client_credentials")
	}
	if config.AppConfig != nil && config.AppConfig.XAARedemption {
		base = append(base, "urn:ietf:params:oauth:grant-type:jwt-bearer")
	}
	if config.AppConfig != nil && config.AppConfig.XAACiba {
		base = append(base, "urn:openid:params:grant-type:ciba")
	}
	if config.AppConfig != nil && config.AppConfig.XAAIssuance {
		base = append(base, "urn:ietf:params:oauth:grant-type:token-exchange")
	}
	return base
}

// m2mTokenAuthMethods returns the token_endpoint_auth_methods_supported list.
// private_key_jwt and client_secret_basic are only advertised when XAA_M2M is on.
func (s *OAuthASService) m2mTokenAuthMethods() []string {
	base := []string{"none", "client_secret_basic", "client_secret_post"}
	if config.AppConfig != nil && config.AppConfig.XAAm2m {
		base = append(base, "private_key_jwt")
	}
	return base
}

// GetServiceAccountByClientID resolves the service account whose oauth_client_id
// matches the provided MCPOAuthClient.ID. Returns (nil, nil) when no SA is linked.
func (s *OAuthASService) GetServiceAccountByClientID(ctx context.Context, clientUUID uuid.UUID) (*models.ServiceAccount, error) {
	var sa models.ServiceAccount
	err := config.DB.WithContext(ctx).
		Where("oauth_client_id = ?", clientUUID).
		First(&sa).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &sa, nil
}

// resolveClientKind maps a DCR request to a client_kind value.
// It uses the explicit client_kind field first, then falls back to
// software_id heuristics so Claude Code, Cursor, etc. auto-classify as agents.
func resolveClientKind(req DCRRequest) string {
	if req.ClientKind != "" {
		switch req.ClientKind {
		case "agent", "m2m", "cli", "human_app":
			return req.ClientKind
		}
	}
	// Heuristic: well-known AI agent software_id prefixes
	sid := strings.ToLower(req.SoftwareID)
	for _, prefix := range []string{
		"anthropic/", "openai/", "cursor/", "github/copilot",
		"codeium/", "sourcegraph/", "deepseek/", "cohere/",
	} {
		if strings.Contains(sid, prefix) {
			return "agent"
		}
	}
	return "human_app" // safe default
}

// nilableString returns nil for an empty string, otherwise a pointer to the value.
func nilableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// RegisterDCRClient creates a new OAuth client via Dynamic Client Registration (RFC 7591).
// When the request includes OIDC scopes (openid, offline_access), the Hydra client and
// MCPOAuthClient are configured to support id_token issuance and refresh_token grants.
// Returns the client and the raw registration_access_token (RFC 7592) to be returned to the caller.
func (s *OAuthASService) RegisterDCRClient(req DCRRequest, rs *models.ResourceServer) (*models.MCPOAuthClient, string, error) {
	if rs != nil && !rs.AllowsRegistrationMode("dcr") {
		return nil, "", fmt.Errorf("resource server does not allow DCR")
	}

	clientID := uuid.New().String()
	hydraClientID := clientID

	// Determine OIDC capabilities from requested scope
	hydraScope, grantTypes, supportsRefresh := resolveOIDCClientCapabilities(req.Scope)

	// Register in Hydra
	err := hydraAdminCreateClient(hydraClient{
		ClientID:      hydraClientID,
		ClientName:    req.ClientName,
		GrantTypes:    grantTypes,
		RedirectURIs:  req.RedirectURIs,
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         hydraScope,
	})
	if err != nil {
		return nil, "", fmt.Errorf("register hydra client for DCR: %w", err)
	}

	// Home workspace is known only when the client bound itself to a resource
	// at registration time. Unbound clients (rs == nil) adopt a home workspace
	// on their first lazy bind at /authorize (see BindClientToRS).
	var homeWorkspaceID *uuid.UUID
	if rs != nil {
		ws := rs.WorkspaceID
		homeWorkspaceID = &ws
	}

	client := &models.MCPOAuthClient{
		ClientID:                clientID,
		HydraClientID:           hydraClientID,
		ClientName:              req.ClientName,
		RedirectURIs:            pq.StringArray(req.RedirectURIs),
		GrantTypes:              pq.StringArray(grantTypes),
		ResponseTypes:           pq.StringArray{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   req.Scope,
		RegistrationType:        "dcr",
		SupportsRefreshToken:    supportsRefresh,
		PostLogoutRedirectURIs:  pq.StringArray(req.PostLogoutRedirectURIs),
		ClientKind:              resolveClientKind(req),
		SoftwareID:              nilableString(req.SoftwareID),
		SoftwareVersion:         nilableString(req.SoftwareVersion),
		HomeWorkspaceID:         homeWorkspaceID,
	}

	if err := s.authzCtx.CreateMCPOAuthClient(client); err != nil {
		// Try to roll back Hydra. If the delete fails too, mark the row
		// pending_delete (when present) so the reconciler retries — better
		// than silently leaking a Hydra-side orphan.
		if delErr := hydraAdminDeleteClient(hydraClientID); delErr != nil {
			now := time.Now()
			errStr := "rollback after authsec create failed: " + delErr.Error()
			_ = s.db.Model(&models.MCPOAuthClient{}).
				Where("hydra_client_id = ?", hydraClientID).
				Updates(map[string]interface{}{
					"sync_status":        models.MCPClientSyncPendingDelete,
					"sync_last_error":    errStr,
					"sync_last_error_at": now,
				}).Error
		}
		return nil, "", fmt.Errorf("store DCR client: %w", err)
	}

	// Generate and store a RFC 7592 registration_access_token (best-effort;
	// if generation fails the client is still usable, just without self-management).
	var rawRAT string
	if rat, ratHash, ratErr := generateRegistrationAccessToken(); ratErr == nil {
		rawRAT = rat
		if dbErr := s.db.Model(client).Update("registration_access_token_hash", ratHash); dbErr.Error == nil {
			client.RegistrationAccessTokenHash = &ratHash
		}
	} else {
		log.Printf("[DCR] generateRegistrationAccessToken failed for client=%s: %v", client.ClientID, ratErr)
	}

	// When rs is non-nil, bind the client to the RS up-front. When nil, the
	// client is registered unbound; binding is deferred to /authorize, which
	// enforces the resource parameter (RFC 8707) and creates the join row
	// lazily at that point. This accommodates DCR clients (e.g. Claude Code)
	// that follow RFC 7591 strictly and omit `resource` at registration time.
	if rs != nil {
		if _, err := s.authzCtx.EnsureClientRegistration(rs.ID, client.ID, rs.WorkspaceID, "dcr", models.ClientRegStatusApproved); err != nil {
			return nil, "", fmt.Errorf("create DCR client registration: %w", err)
		}
	}

	return client, rawRAT, nil
}

// GetOAuthClient looks up an MCP OAuth client by its public client_id.
func (s *OAuthASService) GetOAuthClient(clientID string) (*models.MCPOAuthClient, error) {
	return s.authzCtx.GetMCPOAuthClientByClientID(clientID)
}

// GetMCPOAuthClientByHydraID looks up an MCP OAuth client by its Hydra client_id.
// Introspection uses this because access-token introspections carry the Hydra
// client_id (the internal UUID), not the public AuthSec client_id.
func (s *OAuthASService) GetMCPOAuthClientByHydraID(hydraClientID string) (*models.MCPOAuthClient, error) {
	return s.authzCtx.GetMCPOAuthClientByHydraID(hydraClientID)
}

// GetMCPOAuthClientByClientID resolves the AuthSec client by its public
// client_id. Native-token introspection uses this because native tokens carry
// the AuthSec client_id (not the Hydra internal UUID) in the client_id claim.
func (s *OAuthASService) GetMCPOAuthClientByClientID(clientID string) (*models.MCPOAuthClient, error) {
	return s.authzCtx.GetMCPOAuthClientByClientID(clientID)
}

// EnsureHydraClientHasRSScopes is the lazy-binding fix for DCR'd clients
// whose Hydra `scope` field doesn't yet cover the scopes a Resource Server
// publishes. Symptom this addresses: Claude Code (and any spec-compliant
// MCP client) typically calls DCR with `scope=""` (RFC 7591 allows it),
// expecting the AS to grant resource-bound scopes lazily at /authorize.
// Without this, Hydra hits the request with
//
//	"The OAuth 2.0 Client is not allowed to request scope 'demo_server:admin'"
//
// because the client's stored scope set is empty.
//
// Behaviour:
//   - Compute the union of the client's current Hydra `scope` and the RS's
//     `scopes_supported`.
//   - If the union equals the current set → no-op (idempotent, no Hydra call).
//   - Otherwise PUT the union back to Hydra and persist the new scope on the
//     MCPOAuthClient row so subsequent reconciler runs see it.
//
// Security: this only widens the SET OF SCOPES THE CLIENT MAY REQUEST. The
// actual grant at /authorize still requires user consent, and AuthSec's
// scope_resolver still enforces RBAC + per-tool checks at runtime. So we are
// not silently authorizing anything — we're just making sure the client can
// _ask_ for any scope its bound RS publishes.
func (s *OAuthASService) EnsureHydraClientHasRSScopes(client *models.MCPOAuthClient, rs *models.ResourceServer) error {
	if client == nil || rs == nil || len(rs.ScopesSupported) == 0 {
		return nil
	}

	currentScopes := strings.Fields(client.Scope)
	scopeSet := make(map[string]struct{}, len(currentScopes)+len(rs.ScopesSupported))
	for _, s := range currentScopes {
		scopeSet[s] = struct{}{}
	}

	added := false
	for _, s := range rs.ScopesSupported {
		if s == "" {
			continue
		}
		if _, ok := scopeSet[s]; !ok {
			scopeSet[s] = struct{}{}
			added = true
		}
	}
	if !added {
		return nil // already a superset; nothing to do
	}

	// Stable order keeps Hydra-side updates idempotent across reconciler runs.
	merged := make([]string, 0, len(scopeSet))
	for s := range scopeSet {
		merged = append(merged, s)
	}
	sort.Strings(merged)
	mergedScope := strings.Join(merged, " ")

	// Read current Hydra-side client so we preserve every other field
	// (redirect_uris, grant_types, response_types, token_endpoint_auth_method,
	// ...). Without the GET-then-PUT pattern, the PUT would wipe them.
	hc, err := hydraAdminGetClient(client.HydraClientID)
	if err != nil {
		return fmt.Errorf("ensure rs scopes: fetch hydra client: %w", err)
	}
	hc.Scope = mergedScope

	if err := hydraAdminUpdateClient(client.HydraClientID, *hc); err != nil {
		return fmt.Errorf("ensure rs scopes: update hydra client: %w", err)
	}

	// Persist the same change locally so the reconciler sees the truth.
	client.Scope = mergedScope
	if err := s.authzCtx.UpdateMCPOAuthClient(client); err != nil {
		// Hydra now diverges from our DB — surface but don't fail the auth
		// flow; the reconciler will sync drift.
		log.Printf("[MCP_AUTH] EnsureHydraClientHasRSScopes: hydra updated but db update failed for client=%s rs=%s: %v",
			client.ClientID, rs.ResourceURI, err)
	}
	return nil
}

// GetClientRegistration checks the join table.
func (s *OAuthASService) GetClientRegistration(rsID, clientID uuid.UUID) (*models.ResourceServerClientRegistration, error) {
	return s.authzCtx.GetClientRegistration(rsID, clientID)
}

// CheckClientApprovedForRS is the read-only brokering gate for XAA redemption.
// It checks whether the client has an approved registration for the given RS
// in the target workspace without any side effects (no row creation, no
// home_workspace_id stamping). Use this instead of BindClientToRS in redemption
// paths (per plan spec).
//
// Returns true only when a registration row exists with status='approved'.
// The caller should treat all other cases (not found, pending, denied, revoked)
// as access_denied and record an access_request coordination row.
func (s *OAuthASService) CheckClientApprovedForRS(ctx context.Context, clientID, rsID uuid.UUID) (bool, error) {
	reg, err := s.authzCtx.GetClientRegistration(rsID, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return reg.Status == "approved", nil
}

// UpsertAccessRequest creates or refreshes the single open pending access_request
// row for (workspace, rs, subject_type, subject_id, client). Returns the request
// ID for inclusion in the error response to the requester.
//
// authorizationDetails is the raw RFC 9396 `authorization_details` JSON from the
// request (or "" when none); requestedRarID is the server-side RAR handle when
// present. §2 keeps at most one open pending row per (subject, rs, client), but
// the row now PRESERVES the latest structured authorization payload so the admin
// approves with full context (finding #2) — a refresh overwrites with the newest
// request rather than dropping the RAR/step-up detail.
func (s *OAuthASService) UpsertAccessRequest(
	ctx context.Context,
	workspaceID, rsID uuid.UUID,
	subjectType string, subjectID uuid.UUID,
	requestedByClient, requestedScopes string,
	authorizationDetails string, requestedRarID *uuid.UUID,
) (uuid.UUID, error) {
	now := time.Now().UTC()
	expires := now.Add(7 * 24 * time.Hour)

	// nil-able jsonb: pass NULL when no authorization_details were supplied.
	var authDetails interface{}
	if strings.TrimSpace(authorizationDetails) != "" {
		authDetails = authorizationDetails
	}
	var rarID interface{}
	if requestedRarID != nil {
		rarID = *requestedRarID
	}

	// Attempt atomic upsert: insert a new pending row OR refresh an existing
	// pending row (partial-unique index on status='pending'), refreshing the
	// structured payload too.
	var reqID uuid.UUID
	err := config.DB.WithContext(ctx).Raw(`
		INSERT INTO access_requests
			(id, workspace_id, resource_server_id, subject_type, subject_id,
			 requested_by_client, requested_scopes, requested_rar_id, authorization_details,
			 status, created_at, updated_at, expires_at)
		VALUES
			(gen_random_uuid(), ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
		ON CONFLICT (workspace_id, resource_server_id, subject_type, subject_id, requested_by_client)
			WHERE status = 'pending'
		DO UPDATE SET updated_at = EXCLUDED.updated_at,
		              requested_scopes = EXCLUDED.requested_scopes,
		              requested_rar_id = EXCLUDED.requested_rar_id,
		              authorization_details = EXCLUDED.authorization_details,
		              expires_at = EXCLUDED.expires_at
		RETURNING id`,
		workspaceID, rsID, subjectType, subjectID,
		requestedByClient, requestedScopes, rarID, authDetails,
		now, now, expires,
	).Scan(&reqID).Error
	if err != nil {
		return uuid.Nil, err
	}
	return reqID, nil
}

// ConnectionSubjectScopeGap reports the subjects on open access_requests for a
// (resource server, client) pair that currently resolve ZERO effective scopes.
// Approving a connection authorizes the client↔RS link but does NOT create role
// bindings — so these subjects will get an empty token until an admin assigns a
// role. Governance surfaces use this to avoid implying usable access exists
// (finding #1: "approved" must not lie). Returns subject_id strings.
func (s *OAuthASService) ConnectionSubjectScopeGap(ctx context.Context, appID, clientID string) ([]string, error) {
	rsUUID, err := uuid.Parse(appID)
	if err != nil {
		return nil, fmt.Errorf("invalid resource server id: %w", err)
	}
	var rs models.ResourceServer
	if err := s.db.WithContext(ctx).Where("id = ?", rsUUID).First(&rs).Error; err != nil {
		return nil, err
	}

	type arRow struct {
		SubjectType string
		SubjectID   string
	}
	var rows []arRow
	if err := s.db.WithContext(ctx).Raw(`
		SELECT subject_type, subject_id::text AS subject_id
		FROM access_requests
		WHERE resource_server_id = ? AND requested_by_client = ?
		  AND status IN ('pending','approved')`,
		rsUUID, clientID,
	).Scan(&rows).Error; err != nil {
		return nil, err
	}

	resolver := NewScopeResolver(s.db)
	wsStr := rs.WorkspaceID.String()
	rsStr := rs.ID.String()
	var without []string
	for _, row := range rows {
		// uuid.Nil legacy placeholder rows carry no real subject — skip.
		if row.SubjectID == "" || row.SubjectID == uuid.Nil.String() {
			continue
		}
		has, herr := resolver.PrincipalHasEffectiveScopes(ctx, row.SubjectType, wsStr, row.SubjectID, rsStr)
		if herr != nil {
			continue // best-effort; never block approval on a status probe
		}
		if !has {
			without = append(without, row.SubjectID)
		}
	}
	return without, nil
}

// NotifyAdminsOfPendingAccessRequest fires a goroutine that looks up workspace
// admins and emails each one about the new pending access_request. Errors are
// logged but never returned — notification is advisory, not blocking.
func (s *OAuthASService) NotifyAdminsOfPendingAccessRequest(
	workspaceID, rsID uuid.UUID,
	requestID uuid.UUID,
	requestedByClient, requestedScopes string,
	expiresAt time.Time,
	expiryWarning bool,
) {
	go func() {
		// Load RS name for the email body.
		var rsName string
		s.db.Raw("SELECT name FROM resource_servers WHERE id = ?", rsID).Scan(&rsName)
		if rsName == "" {
			rsName = rsID.String()
		}

		// Load workspace admin emails.
		type adminRow struct {
			Email string
		}
		var admins []adminRow
		s.db.Raw(`
			SELECT DISTINCT u.email
			FROM users u
			JOIN role_bindings rb ON u.id = rb.user_id AND rb.workspace_id = ?
			JOIN roles r ON rb.role_id = r.id AND r.workspace_id = ?
			WHERE u.active = true AND u.workspace_id = ?
			  AND LOWER(r.name) IN ('admin', 'administrator', 'owner', 'super_admin')`,
			workspaceID, workspaceID, workspaceID,
		).Scan(&admins)

		if len(admins) == 0 {
			log.Printf("[AccessRequest] no admins found for workspace=%s to notify about req=%s", workspaceID, requestID)
			return
		}

		selfIssuer := ""
		if config.AppConfig != nil {
			selfIssuer = config.AppConfig.OAuthBaseURL()
		}
		statusURL := selfIssuer + "/oauth/access-requests/" + requestID.String()

		for _, a := range admins {
			_ = utils.SendAccessRequestNotificationEmail(
				a.Email, requestID.String(),
				requestedByClient, rsName, requestedScopes,
				statusURL, expiresAt, expiryWarning,
			)
		}
	}()
}

// EnsureClientRegistration upserts a join row with an explicit status.
func (s *OAuthASService) EnsureClientRegistration(rsID, clientID, workspaceID uuid.UUID, regType, status string) (*models.ResourceServerClientRegistration, error) {
	return s.authzCtx.EnsureClientRegistration(rsID, clientID, workspaceID, regType, status)
}

// EnsureClientRegistrationTx is EnsureClientRegistration bound to a transaction
// handle, so a caller can commit the registration atomically with the rest of a
// machine-access creation (workload / api-credential).
func (s *OAuthASService) EnsureClientRegistrationTx(db *gorm.DB, rsID, clientID, workspaceID uuid.UUID, regType, status string) (*models.ResourceServerClientRegistration, error) {
	return s.authzCtx.EnsureClientRegistrationTx(db, rsID, clientID, workspaceID, regType, status)
}

// ErrCrossWorkspacePending is returned by BindClientToRS when a client whose
// home workspace differs from the RS's workspace attempts a lazy bind. The
// registration row is created as pending_approval; the workspace admin must
// approve it before the client can authorize.
var ErrCrossWorkspacePending = errors.New("client requires admin approval in this workspace")

// BindClientToRS implements adopt-on-first-bind for lazy client registration
// at /authorize:
//
//	home == nil            → stamp home = rs.WorkspaceID, create reg approved
//	home == rs.WorkspaceID → create reg approved
//	home != rs.WorkspaceID → create reg pending_approval, ErrCrossWorkspacePending
//
// Rationale: mcp_oauth_clients is global (one issuer serves every workspace,
// and MCP clients cache one DCR registration per issuer), so the same
// client_id may legitimately need access to several workspaces — but silently
// auto-approving it in EVERY workspace let a client minted by workspace A
// attach itself to workspace B's MCP servers with zero admin gating.
func (s *OAuthASService) BindClientToRS(client *models.MCPOAuthClient, rs *models.ResourceServer, regType string) error {
	if client.HomeWorkspaceID == nil {
		// First bind anywhere: try to stamp this workspace as home via a
		// conditional UPDATE so only one winner is possible under concurrency.
		ws := rs.WorkspaceID
		result := s.db.Model(&models.MCPOAuthClient{}).
			Where("id = ? AND home_workspace_id IS NULL", client.ID).
			Update("home_workspace_id", ws)
		if result.Error != nil {
			return fmt.Errorf("stamp home workspace: %w", result.Error)
		}
		if result.RowsAffected > 0 {
			// We won the race: this workspace is now home; approve immediately.
			client.HomeWorkspaceID = &ws
			_, err := s.authzCtx.EnsureClientRegistration(rs.ID, client.ID, rs.WorkspaceID, regType, models.ClientRegStatusApproved)
			return err
		}
		// RowsAffected == 0: another goroutine already stamped a different
		// workspace as home. Re-read from DB so we can make the correct call.
		var current models.MCPOAuthClient
		if err := s.db.Select("id, home_workspace_id").First(&current, "id = ?", client.ID).Error; err != nil {
			return fmt.Errorf("re-read client after concurrent home stamp: %w", err)
		}
		client.HomeWorkspaceID = current.HomeWorkspaceID
		log.Printf("[MCP_AUTH] BindClientToRS: lost IS NULL race for client=%s, actual home=%v", client.ClientID, client.HomeWorkspaceID)
		// Fall through to the standard home-vs-rs.WorkspaceID check.
	}

	if client.HomeWorkspaceID != nil && *client.HomeWorkspaceID == rs.WorkspaceID {
		_, err := s.authzCtx.EnsureClientRegistration(rs.ID, client.ID, rs.WorkspaceID, regType, models.ClientRegStatusApproved)
		return err
	}

	// Cross-workspace: park the registration for admin review.
	if _, err := s.authzCtx.EnsureClientRegistration(rs.ID, client.ID, rs.WorkspaceID, regType, models.ClientRegStatusPendingApproval); err != nil {
		return fmt.Errorf("create pending registration: %w", err)
	}
	log.Printf("[MCP_AUTH] BindClientToRS: cross-workspace bind parked as pending_approval client=%s home_ws=%v rs_ws=%s rs=%s",
		client.ClientID, client.HomeWorkspaceID, rs.WorkspaceID, rs.ResourceURI)
	return ErrCrossWorkspacePending
}

// ApprovalRoleBinding is the optional role grant an admin can attach to a
// connection approval so that approve becomes one atomic act: bind role +
// approve registration + flip access_request (plan §1). When nil, approval is
// connection-only and the subject gets no scopes until a role is assigned
// separately (the default; decision #1).
type ApprovalRoleBinding struct {
	RoleID      uuid.UUID
	SubjectType string // "user" | "service_account"
	SubjectID   uuid.UUID
}

// ApproveClientRegistration flips a pending_approval registration to approved
// and flips any open access_requests for this (client, RS) to 'approved', in one
// transaction. Connection-only — no role binding is created (decision #1).
func (s *OAuthASService) ApproveClientRegistration(rsID, clientID string) error {
	return s.ApproveClientRegistrationWithBinding(rsID, clientID, nil)
}

// ApproveClientRegistrationWithBinding is ApproveClientRegistration plus an
// optional atomic role grant. When binding != nil, it ALSO creates an RS-scoped
// role_binding for the named principal in the SAME transaction, so registration,
// access_requests, and RBAC are committed together (plan §1's atomic-approve
// invariant). The role is validated to belong to the RS's workspace first, so an
// admin cannot graft a foreign-workspace role onto the grant.
func (s *OAuthASService) ApproveClientRegistrationWithBinding(rsID, clientID string, binding *ApprovalRoleBinding) error {
	rsUUID, err := uuid.Parse(rsID)
	if err != nil {
		return fmt.Errorf("invalid RS ID: %w", err)
	}
	client, err := s.authzCtx.GetMCPOAuthClientByClientID(clientID)
	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}

	// When binding, resolve the RS (for workspace) and validate the role lives in
	// that workspace before opening the transaction.
	var rs models.ResourceServer
	var roleName string
	if binding != nil {
		if binding.SubjectID == uuid.Nil {
			return fmt.Errorf("role binding requires a subject_id")
		}
		if binding.SubjectType != "user" && binding.SubjectType != "service_account" {
			return fmt.Errorf("role binding subject_type must be 'user' or 'service_account'")
		}
		if err := s.db.Where("id = ?", rsUUID).First(&rs).Error; err != nil {
			return fmt.Errorf("resource server not found: %w", err)
		}
		if err := s.db.Raw(
			`SELECT name FROM roles WHERE id = ? AND workspace_id = ? LIMIT 1`,
			binding.RoleID, rs.WorkspaceID,
		).Scan(&roleName).Error; err != nil || roleName == "" {
			return fmt.Errorf("role %s not found in this workspace", binding.RoleID)
		}
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		// Try pending_approval → approved first (normal DCR approval flow).
		result := tx.Model(&models.ResourceServerClientRegistration{}).
			Where("resource_server_id = ? AND oauth_client_id = ? AND status = ?",
				rsUUID, client.ID, models.ClientRegStatusPendingApproval).
			Update("status", models.ClientRegStatusApproved)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			// The registration may already be approved (e.g. XAA cross-workspace
			// flow where the client was auto-registered during bootstrap). In that
			// case the admin is approving the access_request + binding a role, not
			// the registration itself. Verify the registration exists at all.
			var count int64
			tx.Model(&models.ResourceServerClientRegistration{}).
				Where("resource_server_id = ? AND oauth_client_id = ? AND status = ?",
					rsUUID, client.ID, models.ClientRegStatusApproved).
				Count(&count)
			if count == 0 {
				return fmt.Errorf("no pending registration found for this client")
			}
		}

		// Optional atomic role grant — RS-scoped so the resolver honors it for
		// this RS (scope_type='resource_server' AND scope_id=rs.id). Idempotent:
		// skip if an equivalent binding already exists.
		if binding != nil {
			ws := rs.WorkspaceID
			scopeType := "resource_server"
			rb := models.RoleBinding{
				WorkspaceID:      &ws,
				RoleID:           binding.RoleID,
				RoleName:         roleName,
				ScopeType:        &scopeType,
				ScopeID:          &rs.ID,
				AssignmentSource: "connection_approval",
				Conditions:       []byte("{}"),
				CreatedAt:        time.Now().UTC(),
			}
			if binding.SubjectType == "service_account" {
				rb.ServiceAccountID = &binding.SubjectID
			} else {
				rb.UserID = &binding.SubjectID
			}
			// Idempotent + race-proof: the uq_rb_user_rs / uq_rb_sa_rs partial
			// unique indexes make a duplicate (workspace, role, RS, subject)
			// binding a no-op rather than a second row. No check-then-act window.
			if cerr := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&rb).Error; cerr != nil {
				return fmt.Errorf("create role binding: %w", cerr)
			}
		}

		// Flip open access_requests for this (client, RS) to approved. Check the
		// error so a failure rolls the whole approval back (no split-brain where
		// the registration is approved but the access_request stays pending).
		now := time.Now().UTC()
		if aerr := tx.Exec(`
			UPDATE access_requests
			SET status='approved', updated_at=?, decided_at=?
			WHERE resource_server_id=? AND requested_by_client=? AND status='pending'`,
			now, now, rsUUID, clientID).Error; aerr != nil {
			return fmt.Errorf("flip access_requests: %w", aerr)
		}
		return nil
	})
}

// DenyClientRegistration removes a pending_approval registration and flips any
// open access_requests to 'denied'. Unlike Revoke, it removes the registration
// row entirely (the client never had access, so there's nothing to preserve).
func (s *OAuthASService) DenyClientRegistration(rsID, clientID string) error {
	rsUUID, err := uuid.Parse(rsID)
	if err != nil {
		return fmt.Errorf("invalid RS ID: %w", err)
	}
	client, err := s.authzCtx.GetMCPOAuthClientByClientID(clientID)
	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		result := tx.Where(
			"resource_server_id = ? AND oauth_client_id = ? AND status = ?",
			rsUUID, client.ID, models.ClientRegStatusPendingApproval).
			Delete(&models.ResourceServerClientRegistration{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("no pending registration found for this client")
		}
		now := time.Now().UTC()
		if aerr := tx.Exec(`
			UPDATE access_requests
			SET status='denied', updated_at=?, decided_at=?
			WHERE resource_server_id=? AND requested_by_client=? AND status='pending'`,
			now, now, rsUUID, clientID).Error; aerr != nil {
			return fmt.Errorf("flip access_requests: %w", aerr)
		}
		return nil
	})
}

// InferSingleResourceURIForClient resolves a missing RFC 8707 resource parameter
// only when there is exactly one safe candidate.
//
// Compatibility rules:
//   - Preferred source: exactly one approved active RS registration for the client.
//   - DCR-only fallback: if the client is currently unbound and the deployment has
//     exactly one active RS that allows DCR, use that single RS. This keeps single-
//     resource developer setups interoperable with clients that omit `resource`.
//   - Any 0 or >1 candidate outcome is treated as unavailable/ambiguous.
func (s *OAuthASService) InferSingleResourceURIForClient(client *models.MCPOAuthClient) (string, error) {
	if client == nil {
		return "", ErrResourceInferenceUnavailable
	}

	resourceSet := make(map[string]struct{})

	var regs []models.ResourceServerClientRegistration
	if err := s.db.Where(&models.ResourceServerClientRegistration{
		OAuthClientID: client.ID,
		Status:        "approved",
	}).Find(&regs).Error; err != nil {
		return "", fmt.Errorf("list client registrations: %w", err)
	}

	for _, reg := range regs {
		rs, err := s.rsService.GetByID(reg.ResourceServerID.String())
		if err != nil || rs == nil || !rs.Active {
			continue
		}
		resourceSet[rs.ResourceURI] = struct{}{}
	}

	switch len(resourceSet) {
	case 1:
		return onlyResourceURI(resourceSet), nil
	case 0:
		// Continue to the DCR compatibility fallback below.
	default:
		return "", ErrResourceInferenceAmbiguous
	}

	if client.RegistrationType != "dcr" {
		return "", ErrResourceInferenceUnavailable
	}

	var servers []models.ResourceServer
	if err := s.db.Where("active = ?", true).Find(&servers).Error; err != nil {
		return "", fmt.Errorf("list active resource servers: %w", err)
	}
	for _, rs := range servers {
		if rs.AllowsRegistrationMode("dcr") {
			resourceSet[rs.ResourceURI] = struct{}{}
		}
	}

	switch len(resourceSet) {
	case 1:
		return onlyResourceURI(resourceSet), nil
	case 0:
		return "", ErrResourceInferenceUnavailable
	default:
		return "", ErrResourceInferenceAmbiguous
	}
}

func onlyResourceURI(resourceSet map[string]struct{}) string {
	for resourceURI := range resourceSet {
		return resourceURI
	}
	return ""
}

// StoreAuthRequestContext saves the bridge context before redirecting to Hydra.
func (s *OAuthASService) StoreAuthRequestContext(ctx *models.AuthRequestContext) error {
	return s.authzCtx.StoreAuthRequestContext(ctx)
}

// UpdateAuthRequestContextPAR sets the Hydra request_uri and aligned expiry after PAR.
func (s *OAuthASService) UpdateAuthRequestContextPAR(state, requestURI string, expiresAt time.Time) error {
	return s.authzCtx.UpdateAuthRequestContextPAR(state, requestURI, expiresAt)
}

// ConsumeAuthRequestContext marks context as consumed after token exchange.
func (s *OAuthASService) ConsumeAuthRequestContext(state string) error {
	return s.authzCtx.ConsumeAuthRequestContext(state)
}

// GetAuthRequestContextByContextID looks up auth context by server-generated context_id.
// Requires consent_completed = true AND consumed = false. FAIL CLOSED.
func (s *OAuthASService) GetAuthRequestContextByContextID(contextID string) (*models.AuthRequestContext, error) {
	return s.authzCtx.GetAuthRequestContextByContextID(contextID)
}

// GetActiveAuthRequestContextByHydraRequestURI retrieves a live auth context by Hydra request_uri.
func (s *OAuthASService) GetActiveAuthRequestContextByHydraRequestURI(requestURI string) (*models.AuthRequestContext, error) {
	return s.authzCtx.GetActiveAuthRequestContextByHydraRequestURI(requestURI)
}

// ValidateIntrospectionCredentials checks RS credentials for introspection.
// Dual-read: tries bcrypt hash first, falls back to plaintext for un-migrated rows.
// Opportunistically backfills plaintext → hash on successful legacy validation.
func (s *OAuthASService) ValidateIntrospectionCredentials(rsID, secret string) (*models.ResourceServer, error) {
	rs, err := s.rsService.GetByID(rsID)
	if err != nil {
		return nil, fmt.Errorf("unknown resource server: %w", err)
	}

	// Primary path: bcrypt hash
	if rs.IntrospectionSecretHash != "" {
		if bcryptErr := bcrypt.CompareHashAndPassword([]byte(rs.IntrospectionSecretHash), []byte(secret)); bcryptErr != nil {
			return nil, fmt.Errorf("invalid introspection credentials")
		}
		return rs, nil
	}

	// Legacy path: plaintext comparison + opportunistic backfill
	if rs.IntrospectionSecret != "" {
		if rs.IntrospectionSecret != secret {
			return nil, fmt.Errorf("invalid introspection credentials")
		}
		// Backfill: compute hash, store it, clear plaintext
		hashed, hashErr := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
		if hashErr == nil {
			log.Printf("[MCP_AUTH] ValidateIntrospectionCredentials: backfilling hash for RS %s", rsID)
			s.db.Model(&models.ResourceServer{}).Where("id = ?", rs.ID).Updates(map[string]interface{}{
				"introspection_secret_hash": string(hashed),
				"introspection_secret":      "",
			})
		}
		return rs, nil
	}

	return nil, fmt.Errorf("no credentials configured for resource server")
}

// ProxyToHydraPublic forwards a request to Hydra's public endpoint.
// WARNING: Do NOT use this for POST handlers that call ParseForm() — the body will be drained.
// Use ProxyFormToHydraPublic instead.
func (s *OAuthASService) ProxyToHydraPublic(path string, r *http.Request, w http.ResponseWriter) {
	targetURL := config.AppConfig.HydraPublicURL + path

	var body io.Reader
	if r.Body != nil {
		body = r.Body
	}

	proxyReq, err := http.NewRequest(r.Method, targetURL, body)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	proxyReq.Header = r.Header.Clone()
	if r.URL.RawQuery != "" {
		proxyReq.URL.RawQuery = r.URL.RawQuery
	}

	resp, err := CircuitDoHydra(proxyReq)
	if err != nil {
		http.Error(w, "authorization server unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ProxyFormToHydraPublic re-encodes the parsed form data and forwards it to Hydra.
// Use this instead of ProxyToHydraPublic when the request body has been drained by ParseForm().
func (s *OAuthASService) ProxyFormToHydraPublic(path string, form url.Values, header http.Header, w http.ResponseWriter) {
	targetURL := config.AppConfig.HydraPublicURL + path
	encoded := form.Encode()

	proxyReq, err := http.NewRequest("POST", targetURL, strings.NewReader(encoded))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	proxyReq.Header = header.Clone()
	proxyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	proxyReq.Header.Del("Content-Length") // let http.Client recompute

	resp, err := CircuitDoHydra(proxyReq)
	if err != nil {
		http.Error(w, "authorization server unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// ProxyFormToHydraPublicCapture re-encodes form data, sends to Hydra, and returns
// the raw response body + status instead of writing directly to the client.
// The caller is responsible for forwarding the response.
func (s *OAuthASService) ProxyFormToHydraPublicCapture(path string, form url.Values, header http.Header) (int, []byte, http.Header, error) {
	targetURL := config.AppConfig.HydraPublicURL + path
	encoded := form.Encode()

	proxyReq, err := http.NewRequest("POST", targetURL, strings.NewReader(encoded))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("create proxy request: %w", err)
	}
	proxyReq.Header = header.Clone()
	proxyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	proxyReq.Header.Del("Content-Length")
	// Strip Accept-Encoding inherited from the upstream browser request. When this
	// header is explicitly set, net/http disables transparent gzip decoding, and the
	// caller would receive a raw compressed body (e.g. when Hydra is reached via a
	// CDN that adds br/gzip) — making json.Unmarshal fail on the first byte. With
	// the header removed, the Transport adds "Accept-Encoding: gzip" itself and
	// transparently decodes the response.
	proxyReq.Header.Del("Accept-Encoding")

	resp, err := CircuitDoHydra(proxyReq)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("hydra unavailable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, resp.Header, fmt.Errorf("read hydra response: %w", err)
	}

	return resp.StatusCode, body, resp.Header, nil
}

// IntrospectViaHydraAdmin calls Hydra's admin introspection endpoint (no auth needed, internal network only).
// IMPORTANT: The Hydra admin API must NOT be externally reachable — it listens on a separate port
// (typically 4445) that should be firewalled to internal network only.
func (s *OAuthASService) IntrospectViaHydraAdmin(token string) (map[string]interface{}, error) {
	targetURL := config.AppConfig.HydraAdminURL + "/admin/oauth2/introspect"
	form := url.Values{"token": {token}}

	proxyReq, err := http.NewRequest("POST", targetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create introspect request: %w", err)
	}
	proxyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := CircuitDoHydra(proxyReq)
	if err != nil {
		return nil, fmt.Errorf("hydra admin unavailable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read introspect response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse introspect response: %w", err)
	}

	return result, nil
}

// RevokeHydraToken revokes a single token via Hydra's public revocation endpoint.
// Best-effort, fire-and-forget — errors are logged but not returned.
// Prefer RevokeFullTokenSet for post-Hydra rejection paths.
func (s *OAuthASService) RevokeHydraToken(token string) {
	if err := s.revokeOneToken(token); err != nil {
		log.Printf("[MCP_AUTH] RevokeHydraToken: %v", err)
	}
}

// revokeOneToken is the low-level synchronous revocation primitive.
//
// Error semantics:
//   - Transport/circuit-breaker failure → error
//   - Hydra responds with non-200 (e.g. 429 rate-limited, 503 unavailable) → error.
//     RFC 7009 §2.2 requires the revocation endpoint to return HTTP 200 for any
//     successfully processed request, including unknown tokens. A non-200 means the
//     server did not process the revocation; the token may still be live.
//   - Hydra responds with 200 → nil (revocation confirmed)
func (s *OAuthASService) revokeOneToken(token string) error {
	if token == "" {
		return nil
	}
	form := url.Values{"token": {token}}
	targetURL := config.AppConfig.HydraPublicURL + "/oauth2/revoke"
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, circuitErr := CircuitDoHydra(req)
	// Always drain and close the body. CircuitDoHydra returns (resp, err) for 5xx
	// responses — the resp is non-nil even in the error path — so the body must be
	// closed regardless of whether circuitErr is set.
	if resp != nil {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
	}
	if circuitErr != nil {
		return fmt.Errorf("Hydra revoke transport/circuit error: %w", circuitErr)
	}
	// Any non-200 status is a revocation failure. 4xx responses (e.g. 429 Too Many
	// Requests) are not caught by the circuit breaker but still indicate the token
	// was not revoked. Return an error so the caller can log the failure and decide
	// the denial policy (always 403 regardless, per plan).
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Hydra revoke returned non-200 status %d", resp.StatusCode)
	}
	return nil
}

// RevokeFullTokenSet revokes both the access token and refresh token (when present)
// via Hydra's public revocation endpoint. Per RFC 7009, revoking a refresh token
// cascades to all associated access tokens for that grant, but we also revoke the
// access token explicitly as a defensive measure for opaque token deployments.
//
// Returns an error if either revocation call fails. The caller is responsible for
// deciding the response to the client — the plan specifies that hard denials
// (RBAC fail, missing context) must return 403 regardless of revocation outcome,
// and revocation errors must be logged but must not change the 403 to a 502.
func (s *OAuthASService) RevokeFullTokenSet(accessToken, refreshToken string) error {
	var errs []error
	// Revoke refresh token first: Hydra cascades this to all associated access tokens.
	if refreshToken != "" {
		if err := s.revokeOneToken(refreshToken); err != nil {
			errs = append(errs, fmt.Errorf("refresh token revoke: %w", err))
		}
	}
	// Also explicitly revoke access token (defensive — catches opaque token deployments
	// where the cascade may not cover the specific access token instance).
	if accessToken != "" {
		if err := s.revokeOneToken(accessToken); err != nil {
			errs = append(errs, fmt.Errorf("access token revoke: %w", err))
		}
	}
	return errors.Join(errs...)
}

// RevokeHydraLoginSession revokes all login sessions for a subject via Hydra admin API.
// Used by RP-initiated logout (OIDC RP-Initiated Logout 1.0).
func (s *OAuthASService) RevokeHydraLoginSession(subject string) error {
	targetURL := config.AppConfig.HydraAdminURL + "/admin/oauth2/auth/sessions/login?subject=" + url.QueryEscape(subject)
	req, err := http.NewRequest("DELETE", targetURL, nil)
	if err != nil {
		return fmt.Errorf("create revoke request: %w", err)
	}
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return fmt.Errorf("hydra admin unavailable: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hydra returned status %d", resp.StatusCode)
	}
	log.Printf("[MCP_AUTH] RevokeHydraLoginSession: revoked sessions for sub=%s", subject)
	return nil
}

// revokeHydraConsentForSubject calls Hydra Admin API to revoke all consent
// sessions for a subject. Side effect: every access token issued via those
// consents becomes invalid on its next introspection (Hydra's grant-state
// check returns active=false). Refresh tokens tied to those consents also
// become unusable. This is Hydra's atomic "log this user out everywhere"
// primitive — narrower than DROP USER but broader than per-token revoke.
func (s *OAuthASService) revokeHydraConsentForSubject(subject string) error {
	target := config.AppConfig.HydraAdminURL + "/admin/oauth2/auth/sessions/consent?subject=" + url.QueryEscape(subject) + "&all=true"
	req, err := http.NewRequest("DELETE", target, nil)
	if err != nil {
		return fmt.Errorf("create revoke-consent request: %w", err)
	}
	resp, err := CircuitDoHydra(req)
	if err != nil {
		return fmt.Errorf("hydra admin unavailable: %w", err)
	}
	resp.Body.Close()
	// 204 = revoked, 404 = nothing to revoke (also fine — idempotent semantics).
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("hydra returned status %d", resp.StatusCode)
	}
	return nil
}

// RevokeUserTokensForWorkspace invalidates a user's active OAuth tokens + consent
// in a specific workspace, immediately after an RBAC mutation removes or narrows
// their permissions. Phase H-5 is the security keystone: without it, removing
// a role from a user only takes effect when their access token naturally
// expires (now ~10 min after H-3) or when the SDK's scope-matrix refreshes
// (now ~30 s after H-2). Calling this helper drops that window to "instant"
// (next request fails introspection) for the cost of forcing re-consent on
// the user's next interaction.
//
// Strategy:
//
//  1. UPDATE oauth_consent_grants SET revoked_at=now() WHERE workspace_id=? AND user_id=? AND revoked_at IS NULL
//     — our /authorize re-validates RBAC against consent state on every flow,
//     so any new token issuance will see the fresh permission set.
//  2. DELETE Hydra consent sessions for subject=user_id
//     — invalidates all in-flight access tokens issued via those consents.
//     On the user's next protected call, introspection returns active=false
//     and the SDK responds 401 → user gets routed back through /authorize
//     → fresh consent runs the updated RBAC check.
//
// Idempotent: zero-row UPDATEs and 404s from Hydra are normal and non-fatal.
// Best-effort: call sites SHOULD fire-and-forget (`go s.RevokeUserTokensForWorkspace(...)`)
// so the RBAC mutation response returns immediately. Revocation failures are
// logged but don't fail the mutation — the audit trail tells us what fired.
//
// Scope: revokes ALL Hydra consent for the subject (Hydra doesn't index by
// workspace), but only marks oauth_consent_grants for the affected workspace
// as revoked. A user in multiple workspaces stays logged into workspaces A+B+C
// — they'll just have to re-consent on the next /authorize for any of them,
// which is the standards-correct behaviour anyway (RBAC could have changed
// in any workspace they're a member of).
func (s *OAuthASService) RevokeUserTokensForWorkspace(userID, workspaceID uuid.UUID) error {
	if userID == uuid.Nil || workspaceID == uuid.Nil {
		return nil // no-op; caller passed an empty UUID (e.g. group-binding deletion)
	}

	// 1. Mark consent grants revoked in our DB. Use raw SQL so we get a clean
	// "RowsAffected" we can log — useful for confirming the helper actually
	// did something when an operator runs revoke and watches the logs.
	res := s.db.Exec(
		`UPDATE oauth_consent_grants
		    SET revoked_at = NOW()
		  WHERE workspace_id = ? AND user_id = ? AND revoked_at IS NULL`,
		workspaceID, userID,
	)
	if res.Error != nil {
		log.Printf("[MCP_AUTH] RevokeUserTokensForWorkspace: UPDATE consent grants failed user=%s ws=%s: %v",
			userID, workspaceID, res.Error)
		// Don't return — still try Hydra revoke; partial success is better than nothing.
	}

	// 2. Tell Hydra to invalidate all issued tokens for this subject.
	if err := s.revokeHydraConsentForSubject(userID.String()); err != nil {
		log.Printf("[MCP_AUTH] RevokeUserTokensForWorkspace: hydra consent revoke failed user=%s ws=%s: %v",
			userID, workspaceID, err)
		// Don't return — DB-side revocation already succeeded (or partially
		// succeeded), so on the next /authorize the user will be denied at
		// our policy gate even if Hydra still thinks they have a session.
	}

	log.Printf("[MCP_AUTH] RevokeUserTokensForWorkspace: revoked user=%s ws=%s (grants_marked=%d)",
		userID, workspaceID, res.RowsAffected)
	return nil
}

// FetchJWKS returns the public JWKS: the cached Hydra keys, with the native
// NativeSealer keys APPENDED when XAA_NATIVE_SEALER is on. The native keys are
// additive on this public union only — they are NEVER inserted into the
// Hydra-only jwksCache used for ID-token/logout verification (§4), so logout and
// no-kid ID-token fallback are unaffected.
func (s *OAuthASService) FetchJWKS() (json.RawMessage, error) {
	raw, err := s.jwksCache.get()
	if err != nil {
		return nil, err
	}
	if config.AppConfig == nil || !config.AppConfig.XAANativeSealer {
		return raw, nil
	}
	native := tokens.NativeKeys().PublicJWKS()
	if len(native) == 0 {
		return raw, nil
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if uerr := json.Unmarshal(raw, &doc); uerr != nil {
		// If Hydra's JWKS is unparseable for some reason, return it untouched
		// rather than risk dropping its keys.
		log.Printf("[MCP_AUTH] FetchJWKS: could not parse Hydra JWKS to append native keys: %v", uerr)
		return raw, nil
	}
	for _, k := range native {
		b, merr := json.Marshal(k)
		if merr != nil {
			continue
		}
		doc.Keys = append(doc.Keys, b)
	}
	merged, merr := json.Marshal(doc)
	if merr != nil {
		return raw, nil
	}
	return merged, nil
}

// ResolveCIMDClient fetches a CIMD document, validates it, and upserts the client.
func (s *OAuthASService) ResolveCIMDClient(cimdURL string) (*models.MCPOAuthClient, error) {
	// Check cache first
	existing, err := s.authzCtx.GetMCPOAuthClientByClientID(cimdURL)
	if err == nil && existing.CIMDCachedAt != nil {
		if time.Since(*existing.CIMDCachedAt) < 5*time.Minute {
			return existing, nil
		}
	}

	// Fetch CIMD document
	cimdMeta, err := fetchCIMDDocument(cimdURL)
	if err != nil {
		// If we have a cached version less than 1 hour old, use it
		if existing != nil && existing.CIMDCachedAt != nil && time.Since(*existing.CIMDCachedAt) < time.Hour {
			return existing, nil
		}
		return nil, fmt.Errorf("fetch CIMD document: %w", err)
	}

	// Validate client_id matches URL
	if cimdMeta.ClientID != cimdURL {
		return nil, fmt.Errorf("CIMD client_id mismatch: document says %q but fetched from %q", cimdMeta.ClientID, cimdURL)
	}

	now := time.Now()

	if existing != nil {
		// Update existing
		existing.ClientName = cimdMeta.ClientName
		redirectsChanged := !stringSlicesEqual([]string(existing.RedirectURIs), cimdMeta.RedirectURIs)
		existing.CIMDCachedAt = &now

		// Bug 10: If redirect URIs changed, stage them for admin review instead of auto-applying.
		if redirectsChanged {
			// Validate structural correctness of incoming URIs before staging.
			// Malformed URIs are rejected here to prevent them from reaching Hydra at approval time.
			if err := validateRedirectURIs(cimdMeta.RedirectURIs); err != nil {
				return nil, fmt.Errorf("CIMD document contains invalid redirect_uri: %w", err)
			}
			existing.PendingRedirectURIs = pq.StringArray(cimdMeta.RedirectURIs)
			existing.RedirectReviewPending = true
			// Do NOT update Hydra client — pending review
			log.Printf("[MCP_AUTH] ResolveCIMDClient: redirect change detected for %s, staged for review", cimdURL)
		}

		if err := s.authzCtx.UpdateMCPOAuthClient(existing); err != nil {
			return nil, fmt.Errorf("update CIMD client: %w", err)
		}
		return existing, nil
	}

	// Create new CIMD client — scope is determined by the CIMD metadata document.
	// Do NOT default to OIDC scopes; CIMD clients opt into OIDC by declaring scopes in their document.

	// Validate redirect URIs structurally before creating the Hydra client.
	if err := validateRedirectURIs(cimdMeta.RedirectURIs); err != nil {
		return nil, fmt.Errorf("CIMD document contains invalid redirect_uri: %w", err)
	}

	hydraClientID := uuid.New().String()
	cimdScope := cimdMeta.Scope // from CIMD document; empty = auth-code-only (MCP default)
	cimdHydraScope, cimdGrantTypes, cimdSupportsRefresh := resolveOIDCClientCapabilities(cimdScope)
	err = hydraAdminCreateClient(hydraClient{
		ClientID:      hydraClientID,
		ClientName:    cimdMeta.ClientName,
		GrantTypes:    cimdGrantTypes,
		RedirectURIs:  cimdMeta.RedirectURIs,
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         cimdHydraScope,
	})
	if err != nil {
		return nil, fmt.Errorf("create Hydra client for CIMD: %w", err)
	}

	client := &models.MCPOAuthClient{
		ClientID:                cimdURL,
		HydraClientID:           hydraClientID,
		ClientName:              cimdMeta.ClientName,
		RedirectURIs:            pq.StringArray(cimdMeta.RedirectURIs),
		GrantTypes:              pq.StringArray(cimdGrantTypes),
		ResponseTypes:           pq.StringArray{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   cimdScope,
		RegistrationType:        "cimd",
		CIMDUrl:                 cimdURL,
		CIMDCachedAt:            &now,
		SupportsRefreshToken:    cimdSupportsRefresh,
	}

	if err := s.authzCtx.CreateMCPOAuthClient(client); err != nil {
		if delErr := hydraAdminDeleteClient(hydraClientID); delErr != nil {
			now := time.Now()
			errStr := "rollback after authsec create failed: " + delErr.Error()
			_ = s.db.Model(&models.MCPOAuthClient{}).
				Where("hydra_client_id = ?", hydraClientID).
				Updates(map[string]interface{}{
					"sync_status":        models.MCPClientSyncPendingDelete,
					"sync_last_error":    errStr,
					"sync_last_error_at": now,
				}).Error
		}
		return nil, fmt.Errorf("store CIMD client: %w", err)
	}

	return client, nil
}

// PreRegisterClient creates a client + Hydra client + join row with registration_type="prereg".
func (s *OAuthASService) PreRegisterClient(rs *models.ResourceServer, req DCRRequest) (*models.MCPOAuthClient, error) {
	if !rs.AllowsRegistrationMode("prereg") {
		return nil, fmt.Errorf("resource server does not allow pre-registration")
	}

	clientID := uuid.New().String()
	hydraClientID := clientID

	hydraScope, grantTypes, supportsRefresh := resolveOIDCClientCapabilities(req.Scope)

	err := hydraAdminCreateClient(hydraClient{
		ClientID:      hydraClientID,
		ClientName:    req.ClientName,
		GrantTypes:    grantTypes,
		RedirectURIs:  req.RedirectURIs,
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         hydraScope,
	})
	if err != nil {
		return nil, fmt.Errorf("register hydra client for prereg: %w", err)
	}

	client := &models.MCPOAuthClient{
		ClientID:                clientID,
		HydraClientID:           hydraClientID,
		ClientName:              req.ClientName,
		RedirectURIs:            pq.StringArray(req.RedirectURIs),
		GrantTypes:              pq.StringArray(grantTypes),
		ResponseTypes:           pq.StringArray{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   req.Scope,
		RegistrationType:        "prereg",
		SupportsRefreshToken:    supportsRefresh,
		PostLogoutRedirectURIs:  pq.StringArray(req.PostLogoutRedirectURIs),
		ClientKind:              resolveClientKind(req),
		SoftwareID:              nilableString(req.SoftwareID),
		SoftwareVersion:         nilableString(req.SoftwareVersion),
		HomeWorkspaceID:         &rs.WorkspaceID,
	}

	if err := s.authzCtx.CreateMCPOAuthClient(client); err != nil {
		if delErr := hydraAdminDeleteClient(hydraClientID); delErr != nil {
			now := time.Now()
			errStr := "rollback after authsec create failed: " + delErr.Error()
			_ = s.db.Model(&models.MCPOAuthClient{}).
				Where("hydra_client_id = ?", hydraClientID).
				Updates(map[string]interface{}{
					"sync_status":        models.MCPClientSyncPendingDelete,
					"sync_last_error":    errStr,
					"sync_last_error_at": now,
				}).Error
		}
		return nil, fmt.Errorf("store prereg client: %w", err)
	}

	if _, err := s.authzCtx.EnsureClientRegistration(rs.ID, client.ID, rs.WorkspaceID, "prereg", models.ClientRegStatusApproved); err != nil {
		return nil, fmt.Errorf("create prereg client registration: %w", err)
	}

	return client, nil
}

// RegisterAgentClient mints a CONFIDENTIAL agent OAuth client for the A2A flow.
// It carries both legs the cross-app agent needs:
//   - authorization_code + refresh_token: the user-login leg (PKCE via Hydra),
//   - urn:ietf:params:oauth:grant-type:token-exchange: the AuthSec-native ID-JAG
//     issuance leg, which requires confidential client auth.
//
// The client is homed in workspaceID so its ID-JAG carries that issuance
// workspace (§19 makes the call genuinely cross-workspace). The Hydra client is
// public/PKCE for the login leg; the secret is used only for the token-exchange
// leg (checked against oauth_client_secrets by AuthenticateClient). Returns the
// client_id and the one-time plaintext secret.
func (s *OAuthASService) RegisterAgentClient(workspaceID uuid.UUID, name string, redirectURIs []string) (string, string, error) {
	if strings.TrimSpace(name) == "" {
		return "", "", fmt.Errorf("name is required")
	}
	if len(redirectURIs) == 0 {
		return "", "", fmt.Errorf("at least one redirect URI is required")
	}

	clientUUID := uuid.New()
	clientIDStr := clientUUID.String()

	if err := hydraAdminCreateClient(hydraClient{
		ClientID:      clientIDStr,
		ClientName:    name,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		RedirectURIs:  redirectURIs,
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         "openid profile email offline_access",
	}); err != nil {
		return "", "", fmt.Errorf("register hydra client for agent: %w", err)
	}

	now := time.Now().UTC()
	mcpClient := &models.MCPOAuthClient{
		ID:            clientUUID,
		ClientID:      clientIDStr,
		HydraClientID: clientIDStr,
		ClientName:    name,
		RedirectURIs:  pq.StringArray(redirectURIs),
		GrantTypes:    pq.StringArray{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		ResponseTypes: pq.StringArray{"code"},
		// "dcr" so the agent self-binds to each RS it targets via
		// adopt-on-first-bind: same-workspace auto-approves; a cross-workspace
		// RS (the A2A case, §19) parks as pending_approval until that
		// workspace's owner approves — the first-contact signal. "admin" is the
		// workspace default-client type and no RS accepts it from a caller.
		RegistrationType:                "dcr",
		ClientKind:                      "agent",
		SyncStatus:                      "active",
		IsConfidential:                  true,
		HomeWorkspaceID:                 &workspaceID,
		AllowedTokenEndpointAuthMethods: pq.StringArray{"client_secret_basic"},
		Scope:                           "openid profile email offline_access",
		SupportsRefreshToken:            true,
		CreatedAt:                       now,
		UpdatedAt:                       now,
	}
	if err := s.authzCtx.CreateMCPOAuthClient(mcpClient); err != nil {
		_ = hydraAdminDeleteClient(clientIDStr)
		return "", "", fmt.Errorf("store agent client: %w", err)
	}

	secret, genErr := GenerateClientSecret()
	if genErr != nil {
		return "", "", genErr
	}
	hash, hashErr := HashClientSecret(secret)
	if hashErr != nil {
		return "", "", hashErr
	}
	if err := s.db.Create(&models.OAuthClientSecret{
		ID:         uuid.New(),
		ClientID:   mcpClient.ID,
		SecretHash: hash,
	}).Error; err != nil {
		return "", "", fmt.Errorf("store agent secret: %w", err)
	}

	// Phase 6 groundwork: back the agent client with a service_account. Broker
	// authorization binds connector:execute via role_bindings.service_account_id,
	// so an XAA agent whose actor must hold broker scopes needs an SA to bind to.
	// Best-effort — a failure here doesn't fail agent registration (the SA can be
	// linked later); idempotent via the uq_sa_client index on oauth_client_id.
	if err := s.db.Exec(`
		INSERT INTO service_accounts (id, workspace_id, name, description, status, oauth_client_id, created_at, updated_at)
		VALUES (gen_random_uuid(), ?, ?, 'Service account backing agent client', 'active', ?, now(), now())
		ON CONFLICT (oauth_client_id) WHERE oauth_client_id IS NOT NULL DO NOTHING`,
		workspaceID, name, mcpClient.ID).Error; err != nil {
		log.Printf("[RegisterAgentClient] failed to create backing service account for client %s: %v", clientIDStr, err)
	}

	return clientIDStr, secret, nil
}

// ListClientsForRS returns all client registrations for a resource server.
func (s *OAuthASService) ListClientsForRS(rsID string) ([]map[string]interface{}, error) {
	rsUUID, err := uuid.Parse(rsID)
	if err != nil {
		return nil, fmt.Errorf("invalid RS ID: %w", err)
	}

	var regs []models.ResourceServerClientRegistration
	if err := s.db.Where("resource_server_id = ?", rsUUID).Find(&regs).Error; err != nil {
		return nil, err
	}

	result := make([]map[string]interface{}, 0, len(regs))
	for _, reg := range regs {
		var client models.MCPOAuthClient
		if err := s.db.Where("id = ?", reg.OAuthClientID).First(&client).Error; err != nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"client_id":         client.ClientID,
			"client_name":       client.ClientName,
			"registration_type": reg.RegistrationType,
			"status":            reg.Status,
		})
	}
	return result, nil
}

// RevokeClientRegistration sets a client's join-table status to "revoked" for an RS.
func (s *OAuthASService) RevokeClientRegistration(rsID, clientID string) error {
	rsUUID, err := uuid.Parse(rsID)
	if err != nil {
		return fmt.Errorf("invalid RS ID: %w", err)
	}

	// Find the MCP client by public client_id
	client, err := s.authzCtx.GetMCPOAuthClientByClientID(clientID)
	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}

	result := s.db.Model(&models.ResourceServerClientRegistration{}).
		Where("resource_server_id = ? AND oauth_client_id = ?", rsUUID, client.ID).
		Update("status", models.ClientRegStatusRevoked)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("client registration not found")
	}

	// Hydra-side hygiene: when this was the client's LAST approved
	// registration, flush all its access tokens so they don't linger until
	// TTL. Best-effort — the introspection registration gate is the
	// authoritative access cut; a flush failure must not fail the revoke.
	var remaining int64
	if cntErr := s.db.Model(&models.ResourceServerClientRegistration{}).
		Where("oauth_client_id = ? AND status = ?", client.ID, models.ClientRegStatusApproved).
		Count(&remaining).Error; cntErr != nil {
		log.Printf("[MCP_AUTH] RevokeClientRegistration: count remaining approved regs failed for client=%s: %v — skipping token flush", client.ClientID, cntErr)
		return nil
	}
	if remaining == 0 {
		if flushErr := hydraAdminDeleteClientTokens(client.HydraClientID); flushErr != nil {
			log.Printf("[MCP_AUTH] RevokeClientRegistration: hydra token flush failed for client=%s: %v — tokens expire at TTL; introspection gate already denies them", client.ClientID, flushErr)
		} else {
			log.Printf("[MCP_AUTH] RevokeClientRegistration: flushed hydra tokens for client=%s (last approved registration revoked)", client.ClientID)
		}
	}
	return nil
}

// ApprovePendingRedirects copies pending redirect URIs to approved, updates Hydra, clears flag.
func (s *OAuthASService) ApprovePendingRedirects(clientID string) error {
	client, err := s.authzCtx.GetMCPOAuthClientByClientID(clientID)
	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}

	if !client.RedirectReviewPending {
		return fmt.Errorf("no pending redirect changes")
	}

	// Validate staged redirect URIs structurally before promoting to Hydra.
	// (They were validated when staged but re-validate here as a defence-in-depth.)
	if err := validateRedirectURIs([]string(client.PendingRedirectURIs)); err != nil {
		return fmt.Errorf("pending redirect URIs are invalid: %w", err)
	}

	// Copy pending → approved
	client.RedirectURIs = client.PendingRedirectURIs
	client.PendingRedirectURIs = nil
	client.RedirectReviewPending = false

	// Update Hydra client — preserve OIDC capabilities
	hydraScope, grantTypes, _ := resolveOIDCClientCapabilities(client.Scope)
	err = hydraAdminUpdateClient(client.HydraClientID, hydraClient{
		ClientID:      client.HydraClientID,
		ClientName:    client.ClientName,
		GrantTypes:    grantTypes,
		RedirectURIs:  []string(client.RedirectURIs),
		ResponseTypes: []string{"code"},
		TokenEndpoint: "none",
		Scope:         hydraScope,
	})
	if err != nil {
		return fmt.Errorf("update Hydra client redirects: %w", err)
	}

	return s.authzCtx.UpdateMCPOAuthClient(client)
}

// RFC7592UpdateRequest carries mutable fields from a PUT /oauth/register/:client_id body.
// Only listed fields may be changed; grant_types and token_endpoint_auth_method are read-only
// (escalation prevention).
type RFC7592UpdateRequest struct {
	ClientName      string   `json:"client_name"`
	RedirectURIs    []string `json:"redirect_uris"`
	SoftwareVersion string   `json:"software_version,omitempty"`
}

// UpdateClientMetadata applies a RFC 7592 PUT update to a client.
//   - client_name and software_version are applied immediately + synced to Hydra.
//   - redirect_uris changes are staged as pending (redirect_review_pending=true);
//     an admin must call ApprovePendingRedirects before they take effect.
//     This prevents a client from silently widening its own callback surface.
//
// Returns whether redirect review was triggered.
func (s *OAuthASService) UpdateClientMetadata(client *models.MCPOAuthClient, req RFC7592UpdateRequest) (redirectReviewPending bool, err error) {
	updates := map[string]interface{}{}

	if req.ClientName != "" && req.ClientName != client.ClientName {
		client.ClientName = req.ClientName
		updates["client_name"] = req.ClientName
	}

	if req.SoftwareVersion != "" && (client.SoftwareVersion == nil || req.SoftwareVersion != *client.SoftwareVersion) {
		client.SoftwareVersion = &req.SoftwareVersion
		updates["software_version"] = req.SoftwareVersion
	}

	// Check whether redirect_uris changed.
	redirectsChanged := false
	if len(req.RedirectURIs) > 0 {
		existing := make(map[string]struct{}, len(client.RedirectURIs))
		for _, u := range client.RedirectURIs {
			existing[u] = struct{}{}
		}
		for _, u := range req.RedirectURIs {
			if _, ok := existing[u]; !ok {
				redirectsChanged = true
				break
			}
		}
		if !redirectsChanged && len(req.RedirectURIs) != len(client.RedirectURIs) {
			redirectsChanged = true
		}
	}

	if redirectsChanged {
		if err = validateRedirectURIs(req.RedirectURIs); err != nil {
			return false, fmt.Errorf("invalid redirect_uris: %w", err)
		}
		updates["pending_redirect_uris"] = pq.StringArray(req.RedirectURIs)
		updates["redirect_review_pending"] = true
		redirectReviewPending = true
	}

	if len(updates) == 0 {
		return false, nil // nothing to do
	}

	if err = s.db.Model(client).Updates(updates).Error; err != nil {
		return false, fmt.Errorf("db update failed: %w", err)
	}

	// Sync non-redirect changes to Hydra immediately (name). Redirects only sync after admin approval.
	if _, hasName := updates["client_name"]; hasName {
		hydraScope, grantTypes, _ := resolveOIDCClientCapabilities(client.Scope)
		_ = hydraAdminUpdateClient(client.HydraClientID, hydraClient{
			ClientID:      client.HydraClientID,
			ClientName:    client.ClientName,
			GrantTypes:    grantTypes,
			RedirectURIs:  []string(client.RedirectURIs),
			ResponseTypes: []string{"code"},
			TokenEndpoint: client.TokenEndpointAuthMethod,
			Scope:         hydraScope,
		})
	}

	return redirectReviewPending, nil
}

// --- DCR Request/Response types ---

type DCRRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Resource                string   `json:"resource"`
	Scope                   string   `json:"scope"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	// ClientKind is a non-standard AuthSec extension; auto-inferred if absent.
	// Values: human_app | agent | m2m | cli
	ClientKind string `json:"client_kind,omitempty"`
}

type DCRResponse struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Resource                string   `json:"resource"`
	Scope                   string   `json:"scope,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	ClientKind              string   `json:"client_kind,omitempty"`
	// RFC 7592 fields — only present in registration responses
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`
}

// generateRegistrationAccessToken creates a random 32-byte hex token and its SHA-256 hash.
// The raw token is returned to the client; only the hash is stored in the DB.
func generateRegistrationAccessToken() (raw string, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	raw = hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return
}

// GetClientByRegistrationToken validates a raw RFC 7592 registration_access_token and
// returns the matching client. Returns an error if the token is absent or does not match.
func (s *OAuthASService) GetClientByRegistrationToken(clientID, rawRAT string) (*models.MCPOAuthClient, error) {
	client, err := s.authzCtx.GetMCPOAuthClientByClientID(clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found")
	}
	if client.RegistrationAccessTokenHash == nil {
		return nil, fmt.Errorf("client has no registration token")
	}
	sum := sha256.Sum256([]byte(rawRAT))
	gotHash := hex.EncodeToString(sum[:])
	// Constant-time compare — a plain != on the hash is a timing oracle that
	// lets a remote caller recover the stored hash byte-by-byte (CWE-208).
	if subtle.ConstantTimeCompare([]byte(gotHash), []byte(*client.RegistrationAccessTokenHash)) != 1 {
		return nil, fmt.Errorf("invalid registration access token")
	}
	return client, nil
}

// RevokeClientSelf deletes a client and its Hydra counterpart (RFC 7592 DELETE).
func (s *OAuthASService) RevokeClientSelf(client *models.MCPOAuthClient) error {
	if err := hydraAdminDeleteClient(client.HydraClientID); err != nil {
		log.Printf("[RFC7592] hydra delete failed for %s: %v — marking pending_delete", client.ClientID, err)
	}
	return s.db.Delete(client).Error
}

// resolveOIDCClientCapabilities determines the Hydra client scope and grant types.
// Hydra must know every scope that may appear on /oauth2/auth; otherwise it
// rejects the browser flow with invalid_scope before AuthSec can apply its own
// RS/RBAC policy checks.
//
// Phase H-3: refresh_token is now ALWAYS in grant_types regardless of whether the
// client requested offline_access. Rationale:
//
//   - Hydra's TTL_ACCESS_TOKEN dropped from 1h → 10m to make permission revocation
//     propagate within minutes (Phase H goal). With 10-minute access tokens, every
//     OAuth client *needs* refresh tokens to avoid forcing the user to re-consent
//     every 10 minutes — that would be a worse UX than the old 1h access tokens.
//   - The OAuth 2.1 spec + MCP authz spec both allow public clients to use refresh
//     tokens when bound to a single resource server (RFC 8707) + PKCE. AuthSec already
//     enforces both at /oauth/authorize.
//   - Hydra OAUTH2_GRANT_REFRESH_TOKEN_ROTATION_GRACE_PERIOD=30s ensures rotation is
//     enforced — a leaked refresh token is revocable on first reuse.
//   - The `supportsRefresh` return is now true when EITHER the client explicitly
//     asked for offline_access OR has any non-empty scope (i.e. wants resource access).
//     Public-OIDC-only flows (scope=openid only, no resources) still get supportsRefresh
//     based on the original opt-in semantics for back-compat with id-token-only clients.
func resolveOIDCClientCapabilities(scope string) (string, []string, bool) {
	grantTypes := []string{"authorization_code"}

	if scope == "" {
		// No scope requested at DCR time (common for MCP clients — they bind scopes
		// later at /authorize via the resource parameter). Still grant refresh_token
		// so the eventual resource-bound tokens can be refreshed without re-consent.
		grantTypes = append(grantTypes, "refresh_token")
		return "", grantTypes, true
	}

	seen := make(map[string]struct{})
	var hydraScopes []string
	explicitOfflineAccess := false
	for _, s := range strings.Fields(scope) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		hydraScopes = append(hydraScopes, s)
		if s == "offline_access" {
			explicitOfflineAccess = true
		}
	}

	grantTypes = append(grantTypes, "refresh_token")
	// supportsRefresh tracks whether the client originally asked for refresh-token
	// flows. Public flows that didn't ask still get refresh tokens issued (per H-3
	// rationale above) but we surface the original opt-in for callers that need it
	// (the MCPOAuthClient.SupportsRefreshToken column drives older UI badges).
	return strings.Join(hydraScopes, " "), grantTypes, explicitOfflineAccess
}

// --- CIMD types ---

type cimdDocument struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	LogoURI      string   `json:"logo_uri,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	Scope        string   `json:"scope,omitempty"` // OIDC scopes the client opts into (e.g. "openid profile email")
}

// blockedCIDRs is the set of IP ranges that CIMD fetch must never reach.
// Covers loopback, RFC 1918 private, link-local (cloud metadata endpoints),
// IPv6 ULA, unspecified, and shared address space (RFC 6598).
var blockedCIDRs = mustParseCIDRs([]string{
	"127.0.0.0/8",    // loopback IPv4
	"::1/128",        // loopback IPv6
	"10.0.0.0/8",     // RFC 1918
	"172.16.0.0/12",  // RFC 1918
	"192.168.0.0/16", // RFC 1918
	"169.254.0.0/16", // link-local / cloud metadata (AWS 169.254.169.254, Azure, GCP)
	"fd00::/8",       // IPv6 ULA
	"0.0.0.0/8",      // unspecified
	"100.64.0.0/10",  // shared address space (RFC 6598)
})

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("invalid CIDR %q: %v", cidr, err))
		}
		out = append(out, network)
	}
	return out
}

func isBlockedIP(ip net.IP) bool {
	for _, network := range blockedCIDRs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// fetchCIMDDocument fetches and parses a CIMD metadata document from an HTTPS URL.
// SSRF protection: resolves DNS before dialing and re-checks resolved IPs at connect
// time (anti-rebinding). Rejects any URL that resolves to a reserved/private IP.
func fetchCIMDDocument(cimdURL string) (*cimdDocument, error) {
	parsed, err := url.Parse(cimdURL)
	if err != nil || parsed.Scheme != "https" {
		return nil, fmt.Errorf("CIMD URL must be HTTPS: %s", cimdURL)
	}

	hostname := parsed.Hostname()

	// Pre-resolve DNS and validate all returned IPs before opening a connection.
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), hostname)
	if err != nil {
		return nil, fmt.Errorf("CIMD DNS resolution failed for %s: %w", hostname, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("CIMD URL %s resolved to no addresses", hostname)
	}
	for _, addr := range addrs {
		if isBlockedIP(addr.IP) {
			return nil, fmt.Errorf("CIMD URL %s resolves to a reserved address (%s)", cimdURL, addr.IP)
		}
	}

	// Custom transport: re-checks the resolved IP at dial time to prevent DNS rebinding
	// (time-of-check / time-of-use gap between the pre-resolution above and connect).
	baseDialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, fmt.Errorf("invalid dial address %q: %w", address, splitErr)
			}
			ips, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, host)
			if lookupErr != nil {
				return nil, fmt.Errorf("CIMD dial DNS failed: %w", lookupErr)
			}
			for _, ip := range ips {
				if isBlockedIP(ip.IP) {
					return nil, fmt.Errorf("CIMD connect blocked: resolved to reserved IP %s", ip.IP)
				}
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("CIMD dial: no addresses for %s", host)
			}
			return baseDialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
	}
	httpClient := &http.Client{Timeout: 10 * time.Second, Transport: transport}

	resp, err := httpClient.Get(cimdURL)
	if err != nil {
		return nil, fmt.Errorf("fetch CIMD: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CIMD fetch status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read CIMD body: %w", err)
	}

	var doc cimdDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse CIMD: %w", err)
	}

	return &doc, nil
}

// validateRedirectURIs checks redirect URIs for structural correctness before Hydra sync.
//
// Redirect URIs are callback identifiers — the AS never fetches them server-side during
// the OAuth flow, so SSRF IP-blocklists do NOT apply here. Validation is structural only:
// absolute URL, no fragment, https scheme (or http for localhost in dev).
func validateRedirectURIs(uris []string) error {
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() {
			return fmt.Errorf("redirect URI must be an absolute URL: %q", raw)
		}
		if u.Fragment != "" {
			return fmt.Errorf("redirect URI must not contain a fragment: %q", raw)
		}
		if u.Scheme != "https" {
			// Allow http only for localhost (existing repo policy for dev convenience).
			// url.Hostname() strips brackets, so IPv6 loopback arrives as "::1" not "[::1]".
			host := u.Hostname()
			if u.Scheme != "http" || (host != "localhost" && host != "127.0.0.1" && host != "::1") {
				return fmt.Errorf("redirect URI must use https (or http for localhost): %q", raw)
			}
		}
	}
	return nil
}

// --- JWKS cache ---

type jwksCache struct {
	mu        sync.RWMutex
	data      json.RawMessage
	fetchedAt time.Time
}

func (c *jwksCache) get() (json.RawMessage, error) {
	c.mu.RLock()
	if c.data != nil && time.Since(c.fetchedAt) < 5*time.Minute {
		data := c.data
		c.mu.RUnlock()
		return data, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if c.data != nil && time.Since(c.fetchedAt) < 5*time.Minute {
		return c.data, nil
	}

	jwksURL := config.AppConfig.HydraPublicURL + "/.well-known/jwks.json"
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Get(jwksURL)
	if err != nil {
		if c.data != nil {
			return c.data, nil // stale cache is better than error
		}
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}

	c.data = json.RawMessage(body)
	c.fetchedAt = time.Now()
	return c.data, nil
}

// EnrichUserinfoClaims enriches session-based claims with data from the local user table and
// OIDC identity repository. Falls back to session claims if DB lookups fail (graceful degradation).
// The sub may be a UUID (AdminUser.ID) or a composite like "google-<providerUserID>".
func (s *OAuthASService) EnrichUserinfoClaims(claims map[string]interface{}, sub string, scopeSet map[string]bool) {
	if sub == "" {
		return
	}

	// Try to load user by UUID (email/password logins use AdminUser.ID as sub)
	userID, parseErr := uuid.Parse(sub)
	if parseErr != nil {
		// sub is not a UUID — could be a social login composite ID like "google-email-abc123".
		// Session claims are sufficient for these; no local user row to enrich from.
		return
	}

	var user models.AdminUser
	if err := s.db.Where("id = ?", userID).First(&user).Error; err != nil {
		log.Printf("[MCP_AUTH] EnrichUserinfoClaims: user lookup failed sub=%s: %v", sub, err)
		return
	}

	// Enrich profile claims if not already set by session
	if scopeSet["profile"] {
		if _, exists := claims["name"]; !exists && user.Name != "" {
			claims["name"] = user.Name
		}
		if _, exists := claims["preferred_username"]; !exists && user.Username != "" {
			claims["preferred_username"] = user.Username
		}
		if _, exists := claims["picture"]; !exists && user.AvatarURL != "" {
			claims["picture"] = user.AvatarURL
		}
		if !user.UpdatedAt.IsZero() {
			claims["updated_at"] = user.UpdatedAt.Unix()
		}
	}

	if scopeSet["email"] {
		if _, exists := claims["email"]; !exists && user.Email != "" {
			claims["email"] = user.Email
		}
	}

	// Load most recent OIDC identity for federated claims
	if user.WorkspaceID != nil {
		var identity models.OIDCUserIdentity
		err := s.db.Where("user_id = ? AND workspace_id = ?", userID, *user.WorkspaceID).
			Order("last_login_at DESC NULLS LAST").
			First(&identity).Error
		if err == nil && identity.ProfileData != "" {
			// Parse the JSONB profile_data for additional claims
			var profileData map[string]interface{}
			if jsonErr := json.Unmarshal([]byte(identity.ProfileData), &profileData); jsonErr == nil {
				// Merge federated claims that aren't already set
				if scopeSet["email"] {
					if _, exists := claims["email_verified"]; !exists {
						if ev, ok := profileData["email_verified"]; ok {
							claims["email_verified"] = ev
						}
					}
				}
				if scopeSet["profile"] {
					if _, exists := claims["given_name"]; !exists {
						if v, ok := profileData["given_name"].(string); ok && v != "" {
							claims["given_name"] = v
						}
					}
					if _, exists := claims["family_name"]; !exists {
						if v, ok := profileData["family_name"].(string); ok && v != "" {
							claims["family_name"] = v
						}
					}
					if _, exists := claims["locale"]; !exists {
						if v, ok := profileData["locale"].(string); ok && v != "" {
							claims["locale"] = v
						}
					}
				}
			}
		}
	}
}

// VerifyIDTokenHint verifies an id_token JWT signature against the AS JWKS and returns the
// "sub" claim. Used by EndSession to securely identify the subject for session revocation.
// Unlike introspection (which is for access tokens), this validates the id_token signature directly.
func (s *OAuthASService) VerifyIDTokenHint(idToken, expectedIssuer, expectedAudience string) (string, error) {
	jwksData, err := s.jwksCache.get()
	if err != nil {
		return "", fmt.Errorf("fetch JWKS for id_token verification: %w", err)
	}

	// Parse JWKS
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwksData, &jwks); err != nil {
		return "", fmt.Errorf("parse JWKS: %w", err)
	}

	// Build a map of kid → RSA public key
	keyMap := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		keyMap[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}

	// Parse and verify the JWT
	token, err := jwt.Parse(idToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			// No kid — try the first available key
			for _, k := range keyMap {
				return k, nil
			}
			return nil, fmt.Errorf("no RSA keys in JWKS")
		}
		key, ok := keyMap[kid]
		if !ok {
			return nil, fmt.Errorf("kid %q not found in JWKS", kid)
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}))
	if err != nil {
		return "", fmt.Errorf("id_token verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid id_token claims")
	}

	if expectedIssuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != expectedIssuer {
			return "", fmt.Errorf("id_token issuer mismatch")
		}
	}

	if expectedAudience != "" && !audienceContains(claims["aud"], expectedAudience) {
		return "", fmt.Errorf("id_token audience mismatch")
	}

	expUnix, ok := numericClaimToInt64(claims["exp"])
	if !ok {
		return "", fmt.Errorf("id_token missing exp claim")
	}
	if time.Unix(expUnix, 0).Before(time.Now()) {
		return "", fmt.Errorf("id_token expired")
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("id_token missing sub claim")
	}
	return sub, nil
}

func audienceContains(raw interface{}, expected string) bool {
	switch v := raw.(type) {
	case string:
		return v == expected
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == expected {
				return true
			}
		}
	}
	return false
}

func numericClaimToInt64(raw interface{}) (int64, bool) {
	switch v := raw.(type) {
	case float64:
		return int64(v), true
	case float32:
		return int64(v), true
	case int64:
		return v, true
	case int32:
		return int64(v), true
	case int:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	}
	return 0, false
}

// --- Helpers ---

func IsHTTPSURL(s string) bool {
	return strings.HasPrefix(s, "https://")
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]bool, len(a))
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if !m[s] {
			return false
		}
	}
	return true
}

// WorkspaceClientItem is the DTO returned by GET /authsec/clients.
type WorkspaceClientItem struct {
	ClientID           string     `json:"client_id"`
	ClientName         string     `json:"client_name"`
	ClientKind         string     `json:"client_kind"`
	RegistrationType   string     `json:"registration_type"`
	SoftwareID         *string    `json:"software_id,omitempty"`
	SoftwareVersion    *string    `json:"software_version,omitempty"`
	Status             string     `json:"status"`
	SyncStatus         string     `json:"sync_status"`
	ResourceServerID   string     `json:"resource_server_id"`
	ResourceServerName string     `json:"resource_server_name"`
	RedirectURIs       []string   `json:"redirect_uris"`
	Tags               []string   `json:"tags"`
	LastTokenIssuedAt  *time.Time `json:"last_token_issued_at,omitempty"`
	// AdoptedElsewhere is true when the client's home workspace is a DIFFERENT
	// workspace than the caller's. We expose only this boolean — never the
	// foreign workspace UUID — so one tenant can't enumerate another tenant's
	// workspace IDs by listing a globally-shared client.
	AdoptedElsewhere bool      `json:"adopted_elsewhere"`
	CreatedAt        time.Time `json:"created_at"`
}

// CrossWorkspaceConnectionEntry is one row in the workspace-admin "Connections"
// view — a foreign client's registration (or pending access_request) against
// one of this workspace's resource servers.
type CrossWorkspaceConnectionEntry struct {
	// registration-side fields (nil when this is an access_request only row)
	RegistrationID     *uuid.UUID `json:"registration_id,omitempty"`
	RegistrationStatus *string    `json:"registration_status,omitempty"`
	RegistrationType   *string    `json:"registration_type,omitempty"`
	RegisteredAt       *time.Time `json:"registered_at,omitempty"`
	// client info
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	ClientKind string `json:"client_kind"`
	// RS this connection targets
	ResourceServerID   uuid.UUID `json:"resource_server_id"`
	ResourceServerName string    `json:"resource_server_name"`
	// access_request fields (nil when no open request)
	AccessRequestID      *uuid.UUID `json:"access_request_id,omitempty"`
	AccessRequestStatus  *string    `json:"access_request_status,omitempty"`
	RequestedScopes      *string    `json:"requested_scopes,omitempty"`
	RequestedRarID       *uuid.UUID `json:"requested_rar_id,omitempty"`
	AuthorizationDetails *string    `json:"authorization_details,omitempty"` // raw RFC 9396 RAR JSON
	AccessRequestedAt    *time.Time `json:"access_requested_at,omitempty"`
	// relationship classification
	IsCrossWorkspace bool `json:"is_cross_workspace"`
}

// ListCrossWorkspaceConnections returns all cross-workspace client registrations
// and open access_requests for resource servers owned by workspaceID. This is
// the data for the Connections governance view — the admin sees who wants/has
// access from other workspaces and can Approve or Deny.
func (s *OAuthASService) ListCrossWorkspaceConnections(workspaceID uuid.UUID) ([]CrossWorkspaceConnectionEntry, error) {
	type rawReg struct {
		RegID            uuid.UUID
		RegStatus        string
		RegType          string
		RegCreatedAt     time.Time
		ClientID         string
		ClientName       string
		ClientKind       string
		HomeWorkspaceID  *uuid.UUID
		ResourceServerID uuid.UUID
		RSName           string
	}

	sqlDB, err := s.db.DB()
	if err != nil {
		return nil, err
	}

	// All registrations for this workspace's RSes, plus the client's home workspace
	// so we can flag cross-workspace connections.
	regRows, err := sqlDB.QueryContext(context.Background(), `
		SELECT
			r.id, r.status, r.registration_type, r.created_at,
			c.client_id, c.client_name, c.client_kind, c.home_workspace_id,
			rs.id, rs.name
		FROM resource_server_client_registrations r
		JOIN mcp_oauth_clients     c  ON c.id = r.oauth_client_id
		JOIN resource_servers      rs ON rs.id = r.resource_server_id
		WHERE r.workspace_id = $1
		ORDER BY r.created_at DESC
	`, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("list cross-workspace registrations: %w", err)
	}
	defer regRows.Close()

	regByClient := make(map[string]*CrossWorkspaceConnectionEntry)
	var order []string
	for regRows.Next() {
		var row rawReg
		if err := regRows.Scan(
			&row.RegID, &row.RegStatus, &row.RegType, &row.RegCreatedAt,
			&row.ClientID, &row.ClientName, &row.ClientKind, &row.HomeWorkspaceID,
			&row.ResourceServerID, &row.RSName,
		); err != nil {
			return nil, err
		}
		key := row.ClientID + "|" + row.ResourceServerID.String()
		isCross := row.HomeWorkspaceID != nil && *row.HomeWorkspaceID != workspaceID
		regID := row.RegID
		regStatus := row.RegStatus
		regType := row.RegType
		regAt := row.RegCreatedAt
		entry := &CrossWorkspaceConnectionEntry{
			RegistrationID:     &regID,
			RegistrationStatus: &regStatus,
			RegistrationType:   &regType,
			RegisteredAt:       &regAt,
			ClientID:           row.ClientID,
			ClientName:         row.ClientName,
			ClientKind:         row.ClientKind,
			ResourceServerID:   row.ResourceServerID,
			ResourceServerName: row.RSName,
			IsCrossWorkspace:   isCross,
		}
		regByClient[key] = entry
		order = append(order, key)
	}
	if err := regRows.Err(); err != nil {
		return nil, err
	}

	// Overlay open access_requests onto the registration entries.
	arRows, err := sqlDB.QueryContext(context.Background(), `
		SELECT
			ar.id, ar.status, ar.requested_scopes, ar.created_at,
			ar.requested_by_client, ar.resource_server_id,
			ar.requested_rar_id, ar.authorization_details,
			c.client_name, c.client_kind, c.home_workspace_id,
			rs.name
		FROM access_requests ar
		JOIN resource_servers rs ON rs.id = ar.resource_server_id
		LEFT JOIN mcp_oauth_clients c ON c.client_id = ar.requested_by_client
		WHERE ar.workspace_id = $1
		ORDER BY ar.created_at DESC
	`, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("list access_requests: %w", err)
	}
	defer arRows.Close()

	for arRows.Next() {
		var (
			arID              uuid.UUID
			arStatus          string
			requestedScopes   string
			arCreatedAt       time.Time
			requestedByClient string
			rsID              uuid.UUID
			requestedRarID    *uuid.UUID
			authzDetails      *string
			clientName        *string
			clientKind        *string
			homeWsID          *uuid.UUID
			rsName            string
		)
		if err := arRows.Scan(
			&arID, &arStatus, &requestedScopes, &arCreatedAt,
			&requestedByClient, &rsID,
			&requestedRarID, &authzDetails,
			&clientName, &clientKind, &homeWsID,
			&rsName,
		); err != nil {
			return nil, err
		}
		key := requestedByClient + "|" + rsID.String()
		arIDCopy := arID
		arStatusCopy := arStatus
		requestedScopesCopy := requestedScopes
		arCreatedAtCopy := arCreatedAt
		if entry, ok := regByClient[key]; ok {
			// Overlay onto the existing registration entry.
			entry.AccessRequestID = &arIDCopy
			entry.AccessRequestStatus = &arStatusCopy
			entry.RequestedScopes = &requestedScopesCopy
			entry.RequestedRarID = requestedRarID
			entry.AuthorizationDetails = authzDetails
			entry.AccessRequestedAt = &arCreatedAtCopy
		} else {
			// access_request with no registration yet — still show it.
			isCross := homeWsID != nil && *homeWsID != workspaceID
			cName := ""
			if clientName != nil {
				cName = *clientName
			}
			cKind := ""
			if clientKind != nil {
				cKind = *clientKind
			}
			entry := &CrossWorkspaceConnectionEntry{
				ClientID:             requestedByClient,
				ClientName:           cName,
				ClientKind:           cKind,
				ResourceServerID:     rsID,
				ResourceServerName:   rsName,
				AccessRequestID:      &arIDCopy,
				AccessRequestStatus:  &arStatusCopy,
				RequestedScopes:      &requestedScopesCopy,
				RequestedRarID:       requestedRarID,
				AuthorizationDetails: authzDetails,
				AccessRequestedAt:    &arCreatedAtCopy,
				IsCrossWorkspace:     isCross,
			}
			regByClient[key] = entry
			order = append(order, key)
		}
	}
	if err := arRows.Err(); err != nil {
		return nil, err
	}

	result := make([]CrossWorkspaceConnectionEntry, 0, len(order))
	for _, key := range order {
		if entry, ok := regByClient[key]; ok {
			result = append(result, *entry)
		}
	}
	return result, nil
}

// RevokeNativeTokenByJTI inserts a revoked_tokens row for the given JTI.
// It first verifies the token belongs to the requesting workspace so an admin
// from workspace A cannot revoke tokens belonging to workspace B.
func (s *OAuthASService) RevokeNativeTokenByJTI(workspaceID uuid.UUID, jtiStr string) error {
	jti, err := uuid.Parse(jtiStr)
	if err != nil {
		return fmt.Errorf("invalid jti: %w", err)
	}

	var nt models.NativeToken
	if err := s.db.Where("jti = ?", jti).First(&nt).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("token not found")
		}
		return err
	}
	if nt.WorkspaceID != workspaceID {
		return fmt.Errorf("token not found")
	}
	if nt.ExpiresAt.Before(time.Now().UTC()) {
		return fmt.Errorf("token already expired")
	}

	now := time.Now().UTC()
	return s.db.Exec(`
		INSERT INTO revoked_tokens (iss, token_type, jti, revoked_at, expires_at)
		VALUES (?, 'access_token', ?, ?, ?)
		ON CONFLICT (iss, token_type, jti) DO NOTHING`,
		nt.Iss, jti, now, nt.ExpiresAt,
	).Error
}

// ListWorkspaceClients returns all OAuth clients registered to any resource
// server that belongs to the given workspace. If resourceServerID is non-nil,
// results are filtered to that single RS (used by the app-scoped Clients tab).
func (s *OAuthASService) ListWorkspaceClients(workspaceID uuid.UUID, resourceServerID *uuid.UUID) ([]WorkspaceClientItem, error) {
	var regs []models.ResourceServerClientRegistration
	q := s.db.Where("workspace_id = ?", workspaceID)
	if resourceServerID != nil {
		q = q.Where("resource_server_id = ?", *resourceServerID)
	}
	if err := q.Find(&regs).Error; err != nil {
		return nil, err
	}

	if len(regs) == 0 {
		return []WorkspaceClientItem{}, nil
	}

	// Collect all RS IDs + client IDs.
	rsIDs := make([]uuid.UUID, 0, len(regs))
	clientIDs := make([]uuid.UUID, 0, len(regs))
	for _, r := range regs {
		rsIDs = append(rsIDs, r.ResourceServerID)
		clientIDs = append(clientIDs, r.OAuthClientID)
	}

	// Fetch resource servers (for name lookup).
	var rsList []models.ResourceServer
	if err := s.db.Where("id IN ?", rsIDs).Find(&rsList).Error; err != nil {
		return nil, err
	}
	rsMap := make(map[uuid.UUID]models.ResourceServer, len(rsList))
	for _, rs := range rsList {
		rsMap[rs.ID] = rs
	}

	// Fetch clients.
	var clients []models.MCPOAuthClient
	if err := s.db.Where("id IN ?", clientIDs).Find(&clients).Error; err != nil {
		return nil, err
	}
	clientMap := make(map[uuid.UUID]models.MCPOAuthClient, len(clients))
	for _, c := range clients {
		clientMap[c.ID] = c
	}

	result := make([]WorkspaceClientItem, 0, len(regs))
	for _, reg := range regs {
		c, cOK := clientMap[reg.OAuthClientID]
		rs, rsOK := rsMap[reg.ResourceServerID]
		if !cOK {
			continue
		}
		rsName := ""
		rsIDStr := reg.ResourceServerID.String()
		if rsOK {
			rsName = rs.Name
		}

		tags := []string(c.Tags)
		if tags == nil {
			tags = []string{}
		}
		redirectURIs := []string(c.RedirectURIs)
		if redirectURIs == nil {
			redirectURIs = []string{}
		}

		result = append(result, WorkspaceClientItem{
			ClientID:           c.ClientID,
			ClientName:         c.ClientName,
			ClientKind:         c.ClientKind,
			RegistrationType:   reg.RegistrationType,
			SoftwareID:         c.SoftwareID,
			SoftwareVersion:    c.SoftwareVersion,
			Status:             reg.Status,
			SyncStatus:         c.SyncStatus,
			ResourceServerID:   rsIDStr,
			ResourceServerName: rsName,
			RedirectURIs:       redirectURIs,
			Tags:               tags,
			LastTokenIssuedAt:  c.LastTokenIssuedAt,
			AdoptedElsewhere:   c.HomeWorkspaceID != nil && *c.HomeWorkspaceID != workspaceID,
			CreatedAt:          c.CreatedAt,
		})
	}
	return result, nil
}
