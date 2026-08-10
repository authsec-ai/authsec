package services

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec/internal/tokens"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// oidcCoreScopes are AS-level scopes defined by OpenID Connect Core 1.0.
// These bypass the RS scopes_supported check ONLY when the client has opted into OIDC
// (i.e. the client's registered Scope includes "openid").
var oidcCoreScopes = map[string]bool{
	"openid":         true,
	"profile":        true,
	"email":          true,
	"offline_access": true,
	"address":        true,
	"phone":          true,
}

// BlockReason classifies why a requested scope was not granted.
type BlockReason string

const (
	BlockNotInRSSupported BlockReason = "not_in_rs_supported"
	BlockNoRBACBinding    BlockReason = "no_rbac_binding"
	BlockOIDCNotAllowed   BlockReason = "oidc_not_allowed"
)

// ScopeDiagnostic records the resolution outcome for a single scope.
type ScopeDiagnostic struct {
	Scope   string      `json:"scope"`
	Granted bool        `json:"granted"`
	Reason  BlockReason `json:"reason,omitempty"`
}

// ScopeResolutionReport is the full diagnostic output of a scope resolution run.
type ScopeResolutionReport struct {
	Requested     []string          `json:"requested"`
	RSSupported   []string          `json:"rs_supported"`
	UserEffective []string          `json:"user_effective"`
	Grantable     []string          `json:"grantable"`
	Diagnostics   []ScopeDiagnostic `json:"diagnostics"`
}

// IsOIDCCoreScope returns true if the scope is an OIDC core scope.
func IsOIDCCoreScope(s string) bool {
	return oidcCoreScopes[s]
}

// clientIsOIDC checks whether the client is OIDC-capable.
//
// Fail-closed: a client is OIDC-capable only when it explicitly registered the
// "openid" scope. An empty scope is NOT treated as OIDC — that would silently
// grant openid/profile/email to agent/M2M clients that never asked for identity
// (the very thing XAA/M2M must not do). offline_access (refresh-token capability)
// is handled independently of this function — see ValidateRequestedScopes and
// resolveOIDCClientCapabilities — so a non-OIDC DCR client still gets its refresh
// token without being mislabeled OIDC-capable.
func clientIsOIDC(client *models.MCPOAuthClient) bool {
	if client == nil {
		return false
	}
	for _, s := range strings.Fields(client.Scope) {
		if s == "openid" {
			return true
		}
	}
	return false
}

// ScopeResolver resolves grantable scopes for MCP OAuth using a 3-way intersection:
//
//	granted = requested_scopes ∩ RS.scopes_supported ∩ user_effective_scopes
//
// where user_effective_scopes = user → role_bindings → roles → permissions → oauth_scope_permissions → oauth_scopes.
//
// FAIL-CLOSED:
//   - RS must declare scopes_supported. Empty = no RS scopes granted.
//   - User must have RBAC role bindings with permission→scope mappings. No bindings = no scopes.
//   - OIDC core scopes bypass both RS and RBAC checks, only for OIDC-capable clients.
type ScopeResolver struct {
	db *gorm.DB
}

func NewScopeResolver(db *gorm.DB) *ScopeResolver {
	return &ScopeResolver{db: db}
}

// ResolveGrantableScopes performs the 3-way intersection and returns the grantable scope list.
// Backward-compatible wrapper around ResolveWithReport.
func (r *ScopeResolver) ResolveGrantableScopes(
	ctx context.Context,
	workspaceID, userID, resourceServerID string,
	requestedScopes []string,
	rs *models.ResourceServer,
	client *models.MCPOAuthClient,
) ([]string, error) {
	report, err := r.ResolveWithReport(ctx, workspaceID, userID, resourceServerID, requestedScopes, rs, client)
	if err != nil {
		return nil, err
	}
	return report.Grantable, nil
}

// HasEffectiveScopes reports whether the user currently has any RBAC-derived scopes for the resource server.
func (r *ScopeResolver) HasEffectiveScopes(
	ctx context.Context,
	workspaceID, userID, resourceServerID string,
) (bool, error) {
	userEffective, err := r.resolveUserEffectiveScopes(ctx, workspaceID, userID, resourceServerID)
	if err != nil {
		return false, err
	}
	return len(userEffective) > 0, nil
}

// PrincipalHasEffectiveScopes reports whether the principal (user or service
// account) currently resolves any RBAC-derived scopes for the resource server.
// Governance surfaces use this to honestly show "approved but no usable scopes
// yet" — connection approval grants the client access to the RS, but the subject
// still needs a role binding to obtain any scopes.
func (r *ScopeResolver) PrincipalHasEffectiveScopes(
	ctx context.Context,
	subjectType, workspaceID, subjectID, resourceServerID string,
) (bool, error) {
	if subjectType == "service_account" {
		scopes, err := r.resolveServiceAccountEffectiveScopes(ctx, workspaceID, subjectID, resourceServerID)
		if err != nil {
			return false, err
		}
		return len(scopes) > 0, nil
	}
	return r.HasEffectiveScopes(ctx, workspaceID, subjectID, resourceServerID)
}

// ResolveWithReport performs the 3-way intersection and returns a full diagnostic report.
// All controller call sites must pass string-form UUIDs (.String()) to match this API.
func (r *ScopeResolver) ResolveWithReport(
	ctx context.Context,
	workspaceID, userID, resourceServerID string,
	requestedScopes []string,
	rs *models.ResourceServer,
	client *models.MCPOAuthClient,
) (*ScopeResolutionReport, error) {
	isOIDC := clientIsOIDC(client)

	// Build RS supported set and snapshot for report
	rsSupported := make(map[string]struct{})
	var rsSupportedList []string
	if rs != nil {
		for _, s := range rs.ScopesSupported {
			rsSupported[s] = struct{}{}
			rsSupportedList = append(rsSupportedList, s)
		}
	}

	// Resolve user's effective OAuth scopes from RBAC.
	// Propagate DB/query errors to callers — transient failures must not be silently
	// converted into empty RBAC sets and misreported as no_rbac_binding diagnostics.
	userEffective, err := r.resolveUserEffectiveScopes(ctx, workspaceID, userID, resourceServerID)
	if err != nil {
		log.Printf("[SCOPE_RESOLVER] RBAC scope resolution failed user=%s tenant=%s rs=%s: %v",
			userID, workspaceID, resourceServerID, err)
		return nil, fmt.Errorf("resolving user RBAC scopes: %w", err)
	}

	// Build sorted user_effective list for deterministic report output
	var userEffectiveList []string
	for s := range userEffective {
		userEffectiveList = append(userEffectiveList, s)
	}
	sort.Strings(userEffectiveList)

	seen := make(map[string]struct{}, len(requestedScopes))
	var grantable []string
	var diagnostics []ScopeDiagnostic

	for _, s := range requestedScopes {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}

		// offline_access is an AS-level refresh capability, not an identity
		// claim. MCP clients may request it without also being OIDC clients;
		// ValidateRequestedScopes applies the same rule before authorization.
		if s == "offline_access" {
			grantable = append(grantable, s)
			diagnostics = append(diagnostics, ScopeDiagnostic{Scope: s, Granted: true})
			continue
		}

		// OIDC core scopes pass through only when the client is OIDC-capable.
		if oidcCoreScopes[s] {
			if isOIDC {
				grantable = append(grantable, s)
				diagnostics = append(diagnostics, ScopeDiagnostic{Scope: s, Granted: true})
			} else {
				diagnostics = append(diagnostics, ScopeDiagnostic{Scope: s, Granted: false, Reason: BlockOIDCNotAllowed})
			}
			continue
		}

		// RS-specific scopes: 3-way intersection with explicit reason tracking
		if _, ok := rsSupported[s]; !ok {
			diagnostics = append(diagnostics, ScopeDiagnostic{Scope: s, Granted: false, Reason: BlockNotInRSSupported})
			continue
		}
		if _, ok := userEffective[s]; !ok {
			diagnostics = append(diagnostics, ScopeDiagnostic{Scope: s, Granted: false, Reason: BlockNoRBACBinding})
			continue
		}
		grantable = append(grantable, s)
		diagnostics = append(diagnostics, ScopeDiagnostic{Scope: s, Granted: true})
	}

	return &ScopeResolutionReport{
		Requested:     requestedScopes,
		RSSupported:   rsSupportedList,
		UserEffective: userEffectiveList,
		Grantable:     grantable,
		Diagnostics:   diagnostics,
	}, nil
}

// resolveUserEffectiveScopes returns the set of OAuth scope strings the user is entitled to
// based on their RBAC role bindings for a specific resource server.
//
// Resolution chain: role_bindings → roles → role_permissions → permissions → oauth_scope_permissions → oauth_scopes
//
// Expired role bindings (expires_at <= NOW()) are excluded.
// Also performs wildcard expansion: if the user has permission mapped to scope "tools:*",
// all child scopes like "tools:weather:read" are included.
func (r *ScopeResolver) resolveUserEffectiveScopes(
	ctx context.Context,
	workspaceID, userID, resourceServerID string,
) (map[string]struct{}, error) {
	result := make(map[string]struct{})

	workspaceUUID, err := uuid.Parse(workspaceID)
	if err != nil {
		return result, nil // invalid UUID = no scopes (fail-closed)
	}
	rsUUID, err := uuid.Parse(resourceServerID)
	if err != nil {
		return result, nil
	}

	// Suspension gate: if an end-user-state row exists for (workspace, user) and
	// it's not 'active', the user is suspended/disabled — return zero scopes so
	// token issuance (oauth_as_controller.tokenAuthCodeGrant) fails with
	// insufficient_scope and introspection flips active=false on the very next
	// request. Operators/members don't have a row in workspace_end_user_states,
	// so they're unaffected by this check.
	//
	// Done as a separate cheap query (PK lookup) rather than a JOIN so the
	// fail-closed signal is unambiguous in logs — and so a missing row for an
	// end-user that somehow slipped past Phase A admin tooling doesn't silently
	// look like "allowed".
	var endUserStatus string
	row := r.db.WithContext(ctx).
		Raw(`SELECT status FROM workspace_end_user_states WHERE workspace_id = ? AND user_id::text = ? LIMIT 1`, workspaceUUID, userID).
		Row()
	if scanErr := row.Scan(&endUserStatus); scanErr == nil && endUserStatus != "" && endUserStatus != "active" {
		return result, nil
	}

	// Single query: user → role_bindings → roles → role_permissions → permissions → oauth_scope_permissions → oauth_scopes
	// This resolves the full RBAC chain to OAuth scope strings.
	//
	// RS-scope safety: bindings are accepted ONLY when their scope_type/scope_id
	// either:
	//   - is global (both NULL — applies tenant-wide), or
	//   - is wildcard ('*' — explicit "all RSes" binding), or
	//   - is RS-scoped to THIS RS (scope_type='resource_server' AND scope_id=rsUUID).
	// A binding scoped to a DIFFERENT RS must not contribute scopes here, even
	// though oauth_scopes.resource_server_id already filters the joined scope
	// rows — without this, a binding to admin on RS-A would still grant
	// admin-level access on RS-B because both roles likely share the
	// "rs-{id}:admin" naming and admin role's permissions chain to the
	// queried RS's scopes via oauth_scope_permissions.
	var scopeStrings []string
	err = r.db.WithContext(ctx).
		Table("role_bindings rb").
		Select("DISTINCT os.scope_string").
		Joins("JOIN roles ro ON rb.role_id = ro.id").
		Joins("JOIN role_permissions rp ON ro.id = rp.role_id").
		Joins("JOIN permissions p ON rp.permission_id = p.id").
		Joins("JOIN oauth_scope_permissions osp ON osp.permission_id = p.id").
		Joins("JOIN oauth_scopes os ON osp.scope_id = os.id").
		Where("(rb.user_id::text = ? OR rb.group_id IN (SELECT ug.group_id FROM user_groups ug WHERE ug.user_id::text = ?))", userID, userID).
		Where("(rb.workspace_id IS NULL OR rb.workspace_id = ?)", workspaceUUID).
		Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())").
		Where("(ro.workspace_id IS NULL OR ro.workspace_id = ?)", workspaceUUID).
		Where("(p.workspace_id IS NULL OR p.workspace_id = ?)", workspaceUUID).
		Where("os.workspace_id = ? AND os.resource_server_id = ?", workspaceUUID, rsUUID).
		Where(`
			rb.scope_type IS NULL
			OR rb.scope_type = '*'
			OR (rb.scope_type = 'resource_server' AND rb.scope_id::text = ?)
		`, rsUUID.String()).
		Pluck("os.scope_string", &scopeStrings).Error

	if err != nil {
		return result, err
	}

	for _, s := range scopeStrings {
		result[s] = struct{}{}
	}

	// Expand wildcards: if user has "tools:*", also grant "tools:weather:read", etc.
	if len(result) > 0 {
		r.expandWildcards(ctx, workspaceUUID, rsUUID, result)
	}

	return result, nil
}

// expandWildcards checks if any granted scope is a wildcard (ends with ":*") and expands
// it to include all child scopes from the oauth_scopes table.
func (r *ScopeResolver) expandWildcards(ctx context.Context, workspaceID, rsID uuid.UUID, effectiveSet map[string]struct{}) {
	var wildcards []string
	for s := range effectiveSet {
		if strings.HasSuffix(s, ":*") {
			wildcards = append(wildcards, s)
		}
	}
	if len(wildcards) == 0 {
		return
	}

	// Load all scopes for this RS to check which ones fall under a wildcard
	var allScopes []string
	r.db.WithContext(ctx).
		Model(&models.OAuthScope{}).
		Where("workspace_id = ? AND resource_server_id = ?", workspaceID, rsID).
		Pluck("scope_string", &allScopes)

	for _, scope := range allScopes {
		if _, already := effectiveSet[scope]; already {
			continue
		}
		// Check if any wildcard is an ancestor of this scope
		for _, wc := range wildcards {
			prefix := strings.TrimSuffix(wc, "*")
			if strings.HasPrefix(scope, prefix) {
				effectiveSet[scope] = struct{}{}
				break
			}
		}
	}
}

// ValidateRequestedScopes checks if all requested scopes are valid for this client + RS.
// OIDC core scopes are valid only for OIDC-capable clients (client.Scope contains "openid").
// RS-specific scopes are fail-closed against RS.ScopesSupported.
func ValidateRequestedScopes(scopes []string, rs *models.ResourceServer, client *models.MCPOAuthClient) []string {
	isOIDC := clientIsOIDC(client)

	rsSupported := make(map[string]struct{})
	if rs != nil {
		for _, s := range rs.ScopesSupported {
			rsSupported[s] = struct{}{}
		}
	}

	var invalid []string
	for _, s := range scopes {
		if s == "" {
			continue
		}
		// offline_access is always allowed — it controls refresh tokens,
		// not OIDC identity. MCP clients need it for long-lived sessions.
		if s == "offline_access" {
			continue
		}
		// OIDC identity scopes (openid, profile, email, etc.): valid only
		// for clients that opted into OIDC (scope includes "openid").
		if oidcCoreScopes[s] {
			if !isOIDC {
				invalid = append(invalid, s)
			}
			continue
		}
		// RS-specific: must be in RS supported set
		if _, ok := rsSupported[s]; !ok {
			invalid = append(invalid, s)
		}
	}
	return invalid
}

// RSSpecificScopes filters out OIDC core scopes, returning only RS-specific scopes.
// Used by the strict-subset enforcement logic in token exchange and refresh.
func RSSpecificScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s != "" && !oidcCoreScopes[s] {
			out = append(out, s)
		}
	}
	return out
}

// HasAccessBearingScope reports whether a resolved scope set contains anything
// beyond the offline_access protocol capability. offline_access authorizes the
// authorization server to issue refresh tokens; by itself it is not an identity
// claim or a permission to use a protected resource.
//
// Keep this check separate from RSSpecificScopes: existing OIDC authorization
// flows may legitimately carry identity scopes such as openid/profile, while an
// offline_access-only result must never satisfy an access/RBAC gate.
func HasAccessBearingScope(scopes []string) bool {
	for _, scope := range scopes {
		if scope != "" && scope != "offline_access" {
			return true
		}
	}
	return false
}

// PartitionScopes splits a scope list into OIDC core scopes and RS-specific scopes.
// Used by introspection to avoid running RBAC resolution against OIDC-only tokens.
func PartitionScopes(scopes []string) (oidc []string, rsSpecific []string) {
	for _, s := range scopes {
		if s == "" {
			continue
		}
		if oidcCoreScopes[s] {
			oidc = append(oidc, s)
		} else {
			rsSpecific = append(rsSpecific, s)
		}
	}
	return
}

// ScopeSetEqual returns true when a and b contain exactly the same scope strings
// (order-independent). Used for strict-subset detection at token exchange and refresh.
func ScopeSetEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, s := range a {
		set[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

// ResolvePrincipalEffectiveScopes is the dispatcher used by native grant handlers
// and native introspection. It routes user subjects to the existing RBAC chain
// and service_account subjects to the SA-keyed chain. requestedScopes, rs, and
// client are the same as ResolveGrantableScopes — the result is the 3-way
// intersection (requested ∩ rs_supported ∩ principal_effective).
func (r *ScopeResolver) ResolvePrincipalEffectiveScopes(
	ctx context.Context,
	principal tokens.Principal,
	resourceServerID string,
	requestedScopes []string,
	rs *models.ResourceServer,
	client *models.MCPOAuthClient,
) ([]string, error) {
	switch principal.SubjectType {
	case tokens.SubjectTypeUser:
		return r.ResolveGrantableScopes(
			ctx,
			principal.WorkspaceID.String(),
			principal.SubjectID.String(),
			resourceServerID,
			requestedScopes,
			rs,
			client,
		)
	case tokens.SubjectTypeServiceAccount:
		effective, err := r.resolveServiceAccountEffectiveScopes(
			ctx,
			principal.WorkspaceID.String(),
			principal.SubjectID.String(),
			resourceServerID,
		)
		if err != nil {
			return nil, err
		}
		return r.intersectWithRS(requestedScopes, effective, rs, client), nil
	default:
		return nil, fmt.Errorf("unknown principal subject_type %q", principal.SubjectType)
	}
}

// resolveServiceAccountEffectiveScopes resolves the OAuth scopes a service account
// is entitled to via its role_bindings, using the same join chain as the user
// resolver but keyed on role_bindings.service_account_id. Only active SAs
// (status='active') produce scopes — a disabled or suspended SA gets zero.
func (r *ScopeResolver) resolveServiceAccountEffectiveScopes(
	ctx context.Context,
	workspaceID, serviceAccountID, resourceServerID string,
) (map[string]struct{}, error) {
	result := make(map[string]struct{})

	workspaceUUID, err := uuid.Parse(workspaceID)
	if err != nil {
		return result, nil
	}
	rsUUID, err := uuid.Parse(resourceServerID)
	if err != nil {
		return result, nil
	}
	saUUID, err := uuid.Parse(serviceAccountID)
	if err != nil {
		return result, nil
	}

	// Gate: SA must be active.
	var saStatus string
	row := r.db.WithContext(ctx).
		Raw(`SELECT status FROM service_accounts WHERE workspace_id = ? AND id = ? LIMIT 1`,
			workspaceUUID, saUUID).Row()
	if scanErr := row.Scan(&saStatus); scanErr != nil || saStatus != "active" {
		return result, nil
	}

	// Same join chain as the user resolver, but keyed on service_account_id.
	var scopeStrings []string
	err = r.db.WithContext(ctx).
		Table("role_bindings rb").
		Select("DISTINCT os.scope_string").
		Joins("JOIN roles ro ON rb.role_id = ro.id").
		Joins("JOIN role_permissions rp ON ro.id = rp.role_id").
		Joins("JOIN permissions p ON rp.permission_id = p.id").
		Joins("JOIN oauth_scope_permissions osp ON osp.permission_id = p.id").
		Joins("JOIN oauth_scopes os ON osp.scope_id = os.id").
		Where("rb.service_account_id = ?", saUUID).
		Where("(rb.workspace_id IS NULL OR rb.workspace_id = ?)", workspaceUUID).
		Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())").
		Where("(ro.workspace_id IS NULL OR ro.workspace_id = ?)", workspaceUUID).
		Where("(p.workspace_id IS NULL OR p.workspace_id = ?)", workspaceUUID).
		Where("os.workspace_id = ? AND os.resource_server_id = ?", workspaceUUID, rsUUID).
		Where(`
			rb.scope_type IS NULL
			OR rb.scope_type = '*'
			OR (rb.scope_type = 'resource_server' AND rb.scope_id::text = ?)
		`, rsUUID.String()).
		Pluck("os.scope_string", &scopeStrings).Error

	if err != nil {
		return result, err
	}

	for _, s := range scopeStrings {
		result[s] = struct{}{}
	}

	if len(result) > 0 {
		r.expandWildcards(ctx, workspaceUUID, rsUUID, result)
	}

	return result, nil
}

// ServiceAccountEffectiveScopes is the public, list-form accessor for a service
// account's RBAC-derived scopes on a resource server (sorted, deduped). It is
// used by the token-test/simulate dry run, which needs the actual scope list —
// not just the boolean PrincipalHasEffectiveScopes — to show the admin exactly
// what a real mint would grant. This is pre-RS-supported intersection (the raw
// RBAC entitlement); callers that want the mintable set should intersect with
// rs.scopes_supported as the real grant path does.
func (r *ScopeResolver) ServiceAccountEffectiveScopes(
	ctx context.Context,
	workspaceID, serviceAccountID, resourceServerID string,
) ([]string, error) {
	set, err := r.resolveServiceAccountEffectiveScopes(ctx, workspaceID, serviceAccountID, resourceServerID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

// intersectWithRS applies the RS-supported and OIDC-capability filters to an
// already-resolved effective set. Used by ResolvePrincipalEffectiveScopes so
// service accounts go through the same final gate as user scopes.
func (r *ScopeResolver) intersectWithRS(
	requestedScopes []string,
	effective map[string]struct{},
	rs *models.ResourceServer,
	client *models.MCPOAuthClient,
) []string {
	isOIDC := clientIsOIDC(client)
	rsSupported := make(map[string]struct{})
	if rs != nil {
		for _, s := range rs.ScopesSupported {
			rsSupported[s] = struct{}{}
		}
	}

	seen := make(map[string]struct{}, len(requestedScopes))
	var grantable []string
	for _, s := range requestedScopes {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}

		if oidcCoreScopes[s] {
			if isOIDC {
				grantable = append(grantable, s)
			}
			continue
		}
		if _, ok := rsSupported[s]; !ok {
			continue
		}
		if _, ok := effective[s]; !ok {
			continue
		}
		grantable = append(grantable, s)
	}
	return grantable
}

// ScopesLost returns the RS-specific scopes that are present in granted but absent
// from current. A non-empty result means partial scope loss has occurred.
func ScopesLost(granted, current []string) []string {
	currentSet := make(map[string]struct{}, len(current))
	for _, s := range current {
		currentSet[s] = struct{}{}
	}
	var lost []string
	for _, s := range granted {
		if _, ok := currentSet[s]; !ok {
			lost = append(lost, s)
		}
	}
	sort.Strings(lost)
	return lost
}
