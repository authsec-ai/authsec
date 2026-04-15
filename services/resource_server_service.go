package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"strings"

	mcpclient "github.com/authsec-ai/authsec/internal/mcp"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type ResourceServerService struct {
	db *gorm.DB
}

func NewResourceServerService(db *gorm.DB) *ResourceServerService {
	return &ResourceServerService{db: db}
}

type CreateResourceServerRequest struct {
	TenantID          uuid.UUID `json:"tenant_id"`
	Name              string    `json:"name"`
	PublicBaseURL     string    `json:"public_base_url"`
	ProtectedBasePath string    `json:"protected_base_path"`
	ScopesSupported   []string  `json:"scopes_supported"`
	RegistrationModes []string  `json:"registration_modes"`
}

type ResourceServerResponse struct {
	ID                    string   `json:"id"`
	IssuerURL             string   `json:"issuer_url"`
	ResourceURL           string   `json:"resource_url"`
	JWKSURI               string   `json:"jwks_uri"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	IntrospectionSecret   string   `json:"introspection_secret,omitempty"`
	ValidationMode        string   `json:"validation_mode"`
	ScopesSupported       []string `json:"scopes_supported"`
}

func (s *ResourceServerService) Create(req CreateResourceServerRequest, baseURL string) (*models.ResourceServer, *ResourceServerResponse, error) {
	// Bug 11: HTTPS validation
	parsed, err := url.Parse(req.PublicBaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public_base_url: %w", err)
	}
	isLocal := parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1"
	if parsed.Scheme != "https" && !isLocal {
		return nil, nil, fmt.Errorf("public_base_url must use HTTPS (http allowed only for localhost)")
	}

	publicURL := strings.TrimRight(req.PublicBaseURL, "/")
	basePath := req.ProtectedBasePath
	if basePath == "" {
		basePath = "/mcp"
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	resourceURI := publicURL + basePath

	secret, err := generateIntrospectionSecret()
	if err != nil {
		return nil, nil, fmt.Errorf("generate introspection secret: %w", err)
	}

	modes := req.RegistrationModes
	if len(modes) == 0 {
		modes = []string{"dcr", "cimd", "prereg"}
	}

	// Bug 12: Store bcrypt hash, not plaintext
	hashedSecret, hashErr := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if hashErr != nil {
		return nil, nil, fmt.Errorf("hash introspection secret: %w", hashErr)
	}

	rs := &models.ResourceServer{
		TenantID:                req.TenantID,
		Name:                    req.Name,
		PublicBaseURL:           publicURL,
		ProtectedBasePath:       basePath,
		ResourceURI:             resourceURI,
		ScopesSupported:         req.ScopesSupported,
		RegistrationModes:       modes,
		IntrospectionSecret:     "", // Not stored in plaintext for new rows
		IntrospectionSecretHash: string(hashedSecret),
		Active:                  true,
	}

	if err := s.db.Create(rs).Error; err != nil {
		return nil, nil, fmt.Errorf("create resource server: %w", err)
	}

	// Trigger MCP discovery in background — populates scope registry and tool map.
	// Best-effort: failure doesn't block RS creation.
	go func() {
		discoverCtx := context.Background()
		if _, discoverErr := s.DiscoverAndSync(discoverCtx, rs); discoverErr != nil {
			log.Printf("[MCP_DISCOVERY] background discovery failed for RS %s (%s): %v",
				rs.Name, rs.PublicBaseURL, discoverErr)
		}
	}()

	resp := &ResourceServerResponse{
		ID:                    rs.ID.String(),
		IssuerURL:             baseURL,
		ResourceURL:           rs.ResourceURI,
		JWKSURI:               baseURL + "/oauth/jwks",
		IntrospectionEndpoint: baseURL + "/oauth/introspect",
		IntrospectionSecret:   secret,
		ValidationMode:        "auto",
		ScopesSupported:       rs.ScopesSupported,
	}

	return rs, resp, nil
}

func (s *ResourceServerService) GetByID(id string) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ? AND active = true", id).First(&rs).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *ResourceServerService) GetByResourceURI(uri string) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("resource_uri = ? AND active = true", uri).First(&rs).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *ResourceServerService) ListByTenant(tenantID string) ([]models.ResourceServer, error) {
	var servers []models.ResourceServer
	if err := s.db.Where("tenant_id = ? AND active = true", tenantID).Find(&servers).Error; err != nil {
		return nil, err
	}
	return servers, nil
}

func (s *ResourceServerService) Update(id string, updates map[string]interface{}) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ?", id).First(&rs).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&rs).Updates(updates).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *ResourceServerService) Delete(id string) error {
	return s.db.Where("id = ?", id).Delete(&models.ResourceServer{}).Error
}

// GetByIDAndTenant fetches a resource server by ID with tenant ownership check.
func (s *ResourceServerService) GetByIDAndTenant(id, tenantID string) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ? AND tenant_id = ? AND active = true", id, tenantID).First(&rs).Error; err != nil {
		return nil, err
	}
	return &rs, nil
}

// UpdateByTenant updates a resource server with tenant ownership check.
// If public_base_url or protected_base_path change, resource_uri is recomputed.
func (s *ResourceServerService) UpdateByTenant(id, tenantID string, updates map[string]interface{}) (*models.ResourceServer, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ? AND tenant_id = ?", id, tenantID).First(&rs).Error; err != nil {
		return nil, err
	}
	if err := s.db.Model(&rs).Updates(updates).Error; err != nil {
		return nil, err
	}

	// Recompute resource_uri if either component changed
	_, urlChanged := updates["public_base_url"]
	_, pathChanged := updates["protected_base_path"]
	if urlChanged || pathChanged {
		// Re-read to get the applied values
		s.db.Where("id = ?", id).First(&rs)
		newURI := strings.TrimRight(rs.PublicBaseURL, "/") + rs.ProtectedBasePath
		if newURI != rs.ResourceURI {
			s.db.Model(&rs).Update("resource_uri", newURI)
			rs.ResourceURI = newURI
		}
	}

	return &rs, nil
}

// DeleteByTenant deletes a resource server with tenant ownership check.
func (s *ResourceServerService) DeleteByTenant(id, tenantID string) error {
	result := s.db.Where("id = ? AND tenant_id = ?", id, tenantID).Delete(&models.ResourceServer{})
	if result.RowsAffected == 0 {
		return fmt.Errorf("resource server not found")
	}
	return result.Error
}

// RotateIntrospectionSecret generates a new secret, stores its bcrypt hash, returns plaintext once.
func (s *ResourceServerService) RotateIntrospectionSecret(id, tenantID string) (string, error) {
	var rs models.ResourceServer
	if err := s.db.Where("id = ? AND tenant_id = ?", id, tenantID).First(&rs).Error; err != nil {
		return "", fmt.Errorf("resource server not found")
	}

	secret, err := generateIntrospectionSecret()
	if err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash secret: %w", err)
	}

	if err := s.db.Model(&rs).Updates(map[string]interface{}{
		"introspection_secret_hash": string(hashed),
		"introspection_secret":      "", // clear plaintext
	}).Error; err != nil {
		return "", err
	}

	return secret, nil
}

func generateIntrospectionSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sec_" + hex.EncodeToString(b), nil
}

// DiscoverAndSync performs MCP discovery (PRM + tools/list) for a resource server,
// populates the scope registry and tool-scope map.
// Called on Create and on explicit Rescan.
func (s *ResourceServerService) DiscoverAndSync(ctx context.Context, rs *models.ResourceServer) (*DiscoverySyncResult, error) {
	client := mcpclient.NewClient()
	result, err := client.Discover(ctx, rs.PublicBaseURL)
	if err != nil {
		return nil, fmt.Errorf("MCP discovery failed: %w", err)
	}

	syncResult := &DiscoverySyncResult{}

	// Sync scopes from PRM
	scopeRegistry := NewScopeRegistryService(s.db)
	if result.PRM != nil && len(result.PRM.ScopesSupported) > 0 {
		scopes, err := scopeRegistry.SyncFromPRM(rs.TenantID, rs.ID, result.PRM.ScopesSupported)
		if err != nil {
			return nil, fmt.Errorf("scope sync: %w", err)
		}
		syncResult.ScopesDiscovered = len(scopes)

		// Update RS.ScopesSupported to match PRM
		s.db.Model(rs).Update("scopes_supported", result.PRM.ScopesSupported)
	}

	// Upsert discovered tools
	for _, tool := range result.Tools {
		mcpTool := models.MCPTool{
			TenantID:         rs.TenantID,
			ResourceServerID: rs.ID,
			Name:             tool.Name,
			Title:            tool.Title,
			Description:      tool.Description,
			InputSchema:      tool.InputSchema,
			Annotations:      tool.Annotations,
		}

		existing := models.MCPTool{}
		if err := s.db.Where("resource_server_id = ? AND name = ?", rs.ID, tool.Name).First(&existing).Error; err == nil {
			// Update existing
			s.db.Model(&existing).Updates(map[string]interface{}{
				"title":        tool.Title,
				"description":  tool.Description,
				"input_schema": tool.InputSchema,
				"annotations":  tool.Annotations,
			})
		} else {
			s.db.Create(&mcpTool)
		}
	}
	syncResult.ToolsDiscovered = len(result.Tools)

	// Auto-map tools to scopes
	var scopeStrings []string
	if result.PRM != nil {
		scopeStrings = result.PRM.ScopesSupported
	}
	mappings, unmapped := MapToolsToScopes(result.Tools, scopeStrings)
	syncResult.UnmappedScopes = unmapped

	// Persist tool-scope mappings
	for _, m := range mappings {
		var tool models.MCPTool
		if err := s.db.Where("resource_server_id = ? AND name = ?", rs.ID, m.ToolName).First(&tool).Error; err != nil {
			continue
		}
		var scope models.OAuthScope
		if err := s.db.Where("tenant_id = ? AND resource_server_id = ? AND scope_string = ?", rs.TenantID, rs.ID, m.ScopeString).First(&scope).Error; err != nil {
			continue
		}

		mapping := models.MCPToolScopeMap{
			ToolID:      tool.ID,
			ScopeID:     scope.ID,
			AutoMatched: m.AutoMatched,
		}
		s.db.Where("tool_id = ? AND scope_id = ?", tool.ID, scope.ID).FirstOrCreate(&mapping)
	}

	// Seed default roles if this is a first scan (no roles exist for this RS)
	s.seedDefaultRoles(rs, scopeRegistry)

	log.Printf("[MCP_DISCOVERY] RS %s: %d tools, %d scopes, %d unmapped",
		rs.Name, syncResult.ToolsDiscovered, syncResult.ScopesDiscovered, len(syncResult.UnmappedScopes))

	return syncResult, nil
}

// seedDefaultRoles creates "admin" (all scopes) and "readonly" (:read scopes) roles
// for a resource server if no roles exist yet.
//
// It bridges the RBAC → OAuth scope chain by:
// 1. Creating RBAC permissions for each discovered scope
// 2. Mapping those permissions to oauth_scopes via oauth_scope_permissions
// 3. Creating "rs:<name>:admin" and "rs:<name>:readonly" roles
// 4. Linking permissions to roles via role_permissions
func (s *ResourceServerService) seedDefaultRoles(rs *models.ResourceServer, scopeRegistry *ScopeRegistryService) {
	// Check if we already seeded roles for this RS (by naming convention)
	adminRoleName := fmt.Sprintf("rs:%s:admin", rs.Name)
	var existingRole models.RBACRole
	if err := s.db.Where("name = ? AND tenant_id = ?", adminRoleName, rs.TenantID).First(&existingRole).Error; err == nil {
		return // already seeded
	}

	// Load all oauth_scopes for this RS
	scopes, err := scopeRegistry.ListByResourceServer(rs.TenantID, rs.ID)
	if err != nil || len(scopes) == 0 {
		return
	}

	// 1. Create RBAC permissions for each scope and map them
	var allPermIDs []uuid.UUID
	var readPermIDs []uuid.UUID
	for _, scope := range scopes {
		// Create an RBAC permission: resource = scope_string, action = "access"
		perm := models.RBACPermission{
			TenantID:    &rs.TenantID,
			Resource:    scope.ScopeString,
			Action:      "access",
			Description: fmt.Sprintf("OAuth scope: %s", scope.DisplayName),
		}
		// Upsert
		existing := models.RBACPermission{}
		if err := s.db.Where("tenant_id = ? AND resource = ? AND action = ?", rs.TenantID, perm.Resource, perm.Action).First(&existing).Error; err == nil {
			perm = existing
		} else {
			s.db.Create(&perm)
		}
		allPermIDs = append(allPermIDs, perm.ID)

		// Classify as readonly if the scope contains "read" or doesn't contain "write"/"delete"/"admin"
		lower := strings.ToLower(scope.ScopeString)
		isRead := strings.Contains(lower, "read") || strings.Contains(lower, ":list") ||
			(!strings.Contains(lower, "write") && !strings.Contains(lower, "delete") &&
				!strings.Contains(lower, "admin") && !strings.Contains(lower, "create") &&
				!strings.HasSuffix(lower, ":*"))
		if isRead {
			readPermIDs = append(readPermIDs, perm.ID)
		}

		// 2. Map permission → oauth_scope
		osp := models.OAuthScopePermission{ScopeID: scope.ID, PermissionID: perm.ID}
		s.db.Where("scope_id = ? AND permission_id = ?", scope.ID, perm.ID).FirstOrCreate(&osp)
	}

	// 3. Create roles
	adminRole := models.RBACRole{
		TenantID:    &rs.TenantID,
		Name:        adminRoleName,
		Description: fmt.Sprintf("Full access to %s (auto-generated)", rs.Name),
	}
	s.db.Create(&adminRole)

	readonlyRoleName := fmt.Sprintf("rs:%s:readonly", rs.Name)
	readonlyRole := models.RBACRole{
		TenantID:    &rs.TenantID,
		Name:        readonlyRoleName,
		Description: fmt.Sprintf("Read-only access to %s (auto-generated)", rs.Name),
	}
	s.db.Create(&readonlyRole)

	// 4. Link permissions to roles
	for _, permID := range allPermIDs {
		s.db.FirstOrCreate(&models.RolePermission{RoleID: adminRole.ID, PermissionID: permID})
	}
	for _, permID := range readPermIDs {
		s.db.FirstOrCreate(&models.RolePermission{RoleID: readonlyRole.ID, PermissionID: permID})
	}

	log.Printf("[MCP_DISCOVERY] seedDefaultRoles: created roles %q (%d perms) and %q (%d perms) for RS %s",
		adminRoleName, len(allPermIDs), readonlyRoleName, len(readPermIDs), rs.Name)
}

// DiscoverySyncResult contains the outcome of a discovery + sync operation.
type DiscoverySyncResult struct {
	ToolsDiscovered  int      `json:"tools_discovered"`
	ScopesDiscovered int      `json:"scopes_discovered"`
	UnmappedScopes   []string `json:"unmapped_scopes"`
}
