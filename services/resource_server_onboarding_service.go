package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	ResourceServerAccessAssignmentTrigger = "first_successful_login"
	ResourceServerAccessAssignmentSource  = "default_policy"
)

type ResourceServerRoleOption struct {
	RoleID      string `json:"role_id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	IsGenerated bool   `json:"is_generated"`
	Recommended bool   `json:"recommended"`
	Permissions int64  `json:"permissions"`
}

type ResourceServerAccessPolicyResponse struct {
	Enabled           bool                       `json:"enabled"`
	DefaultRoleID     *string                    `json:"default_role_id,omitempty"`
	DefaultRoleName   *string                    `json:"default_role_name,omitempty"`
	AssignmentTrigger string                     `json:"assignment_trigger"`
	AssignmentSource  string                     `json:"assignment_source"`
	RoleOptions       []ResourceServerRoleOption `json:"role_options"`
}

type UpdateResourceServerAccessPolicyRequest struct {
	Enabled       bool   `json:"enabled"`
	DefaultRoleID string `json:"default_role_id"`
}

type ResourceServerValidationCheck struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Observed string `json:"observed,omitempty"`
}

type ResourceServerValidationResult struct {
	Status          string                          `json:"status"`
	LastValidatedAt time.Time                       `json:"last_validated_at"`
	Checks          []ResourceServerValidationCheck `json:"checks"`
}

type ResourceServerOnboardingService struct {
	db            *gorm.DB
	scopeResolver *ScopeResolver
	httpClient    *http.Client
}

func NewResourceServerOnboardingService(db *gorm.DB) *ResourceServerOnboardingService {
	return &ResourceServerOnboardingService{
		db:            db,
		scopeResolver: NewScopeResolver(db),
		httpClient: &http.Client{
			Timeout: 8 * time.Second,
		},
	}
}

func (s *ResourceServerOnboardingService) GetAccessPolicy(resourceServerID, tenantID string) (*ResourceServerAccessPolicyResponse, error) {
	rsUUID, tenantUUID, err := parseTenantScopedIDs(resourceServerID, tenantID)
	if err != nil {
		return nil, err
	}

	roleOptions, err := s.listRoleOptions(rsUUID, tenantUUID)
	if err != nil {
		return nil, err
	}

	var policy models.ResourceServerAccessPolicy
	err = s.db.Preload("DefaultRole").
		Where("resource_server_id = ? AND tenant_id = ?", rsUUID, tenantUUID).
		First(&policy).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	resp := &ResourceServerAccessPolicyResponse{
		Enabled:           false,
		AssignmentTrigger: ResourceServerAccessAssignmentTrigger,
		AssignmentSource:  ResourceServerAccessAssignmentSource,
		RoleOptions:       roleOptions,
	}
	if err == nil {
		resp.Enabled = policy.Enabled
		resp.AssignmentTrigger = policy.AssignmentTrigger
		resp.AssignmentSource = policy.AssignmentSource
		if policy.DefaultRoleID != nil {
			roleID := policy.DefaultRoleID.String()
			resp.DefaultRoleID = &roleID
		}
		if policy.DefaultRole != nil {
			roleName := policy.DefaultRole.Name
			resp.DefaultRoleName = &roleName
		}
	}

	return resp, nil
}

func (s *ResourceServerOnboardingService) UpdateAccessPolicy(resourceServerID, tenantID string, req UpdateResourceServerAccessPolicyRequest) (*ResourceServerAccessPolicyResponse, error) {
	rsUUID, tenantUUID, err := parseTenantScopedIDs(resourceServerID, tenantID)
	if err != nil {
		return nil, err
	}

	roleOptions, err := s.listRoleOptions(rsUUID, tenantUUID)
	if err != nil {
		return nil, err
	}

	var defaultRoleID *uuid.UUID
	var defaultRoleName *string
	if req.Enabled {
		if strings.TrimSpace(req.DefaultRoleID) == "" {
			return nil, fmt.Errorf("default_role_id is required when access policy is enabled")
		}
		roleUUID, parseErr := uuid.Parse(req.DefaultRoleID)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid default_role_id")
		}
		if !roleOptionContains(roleOptions, roleUUID.String()) {
			return nil, fmt.Errorf("default role is not compatible with this resource server")
		}
		defaultRoleID = &roleUUID
		for _, option := range roleOptions {
			if option.RoleID == roleUUID.String() {
				name := option.Name
				defaultRoleName = &name
				break
			}
		}
	}

	var existing models.ResourceServerAccessPolicy
	err = s.db.Where("resource_server_id = ? AND tenant_id = ?", rsUUID, tenantUUID).First(&existing).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			return nil, err
		}
		existing = models.ResourceServerAccessPolicy{
			TenantID:          tenantUUID,
			ResourceServerID:  rsUUID,
			Enabled:           req.Enabled,
			DefaultRoleID:     defaultRoleID,
			AssignmentTrigger: ResourceServerAccessAssignmentTrigger,
			AssignmentSource:  ResourceServerAccessAssignmentSource,
		}
		if createErr := s.db.Create(&existing).Error; createErr != nil {
			return nil, createErr
		}
	} else {
		if updateErr := s.db.Model(&existing).Updates(map[string]interface{}{
			"enabled":            req.Enabled,
			"default_role_id":    defaultRoleID,
			"assignment_trigger": ResourceServerAccessAssignmentTrigger,
			"assignment_source":  ResourceServerAccessAssignmentSource,
			"updated_at":         time.Now().UTC(),
		}).Error; updateErr != nil {
			return nil, updateErr
		}
	}

	return &ResourceServerAccessPolicyResponse{
		Enabled:           req.Enabled,
		DefaultRoleID:     stringPtr(defaultRoleID),
		DefaultRoleName:   defaultRoleName,
		AssignmentTrigger: ResourceServerAccessAssignmentTrigger,
		AssignmentSource:  ResourceServerAccessAssignmentSource,
		RoleOptions:       roleOptions,
	}, nil
}

func (s *ResourceServerOnboardingService) GetAccessPolicySummary(resourceServerID, tenantID string) (bool, *string, error) {
	rsUUID, tenantUUID, err := parseTenantScopedIDs(resourceServerID, tenantID)
	if err != nil {
		return false, nil, err
	}

	type policyRow struct {
		Enabled bool
		Name    *string
	}

	var row policyRow
	err = s.db.Table("resource_server_access_policies p").
		Select("p.enabled, r.name").
		Joins("LEFT JOIN roles r ON r.id = p.default_role_id").
		Where("p.resource_server_id = ? AND p.tenant_id = ?", rsUUID, tenantUUID).
		Take(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil, nil
		}
		return false, nil, err
	}

	return row.Enabled, row.Name, nil
}

func (s *ResourceServerOnboardingService) EnsureDefaultAccessBinding(ctx context.Context, userID, tenantID string, rs *models.ResourceServer) (bool, error) {
	if rs == nil {
		return false, fmt.Errorf("resource server is required")
	}

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return false, nil
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return false, nil
	}

	var policy models.ResourceServerAccessPolicy
	err = s.db.Where("resource_server_id = ? AND tenant_id = ? AND enabled = true", rs.ID, tenantUUID).First(&policy).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, err
	}
	if policy.DefaultRoleID == nil {
		return false, nil
	}

	hasAccess, err := s.scopeResolver.HasEffectiveScopes(ctx, tenantID, userID, rs.ID.String())
	if err != nil {
		return false, err
	}
	if hasAccess {
		return false, nil
	}

	var user models.ExtendedUser
	if err := s.db.Select("id", "email", "username").Where("id = ?", userUUID).First(&user).Error; err != nil {
		return false, err
	}
	username := ""
	if user.Username != nil {
		username = *user.Username
	}

	var role models.RBACRole
	if err := s.db.Where("id = ? AND tenant_id = ?", *policy.DefaultRoleID, tenantUUID).First(&role).Error; err != nil {
		return false, fmt.Errorf("default role not found")
	}

	var existingCount int64
	if err := s.db.Model(&models.RoleBinding{}).
		Where("tenant_id = ? AND user_id = ? AND role_id = ? AND scope_type IS NULL AND scope_id IS NULL",
			tenantUUID, userUUID, role.ID).
		Count(&existingCount).Error; err != nil {
		return false, err
	}
	if existingCount > 0 {
		return false, nil
	}

	metadata, err := json.Marshal(map[string]string{
		"resource_server_id": rs.ID.String(),
		"resource_uri":       rs.ResourceURI,
		"trigger":            ResourceServerAccessAssignmentTrigger,
	})
	if err != nil {
		return false, err
	}

	binding := models.RoleBinding{
		TenantID:           &tenantUUID,
		UserID:             &userUUID,
		Username:           firstNonEmpty(username, user.Email),
		RoleID:             role.ID,
		RoleName:           role.Name,
		Conditions:         json.RawMessage([]byte("{}")),
		AssignmentSource:   ResourceServerAccessAssignmentSource,
		AssignmentMetadata: json.RawMessage(metadata),
		CreatedAt:          time.Now().UTC(),
	}
	if err := s.db.Create(&binding).Error; err != nil {
		return false, err
	}

	return true, nil
}

func (s *ResourceServerOnboardingService) ValidateResourceServer(rs *models.ResourceServer, clientCount int, accessPolicyEnabled bool) (*ResourceServerValidationResult, error) {
	if rs == nil {
		return nil, fmt.Errorf("resource server is required")
	}

	metadataStatus, metadataMessage, metadataObserved := s.checkMetadataURL(rs.ResourceURI)
	challengeStatus, challengeMessage, challengeObserved := s.checkMCPChallenge(rs.ResourceURI)

	discoveryStatus := "failing"
	discoveryMessage := "Run discovery to populate tool and scope state."
	if rs.LastSuccessfulGeneration > 0 {
		discoveryStatus = "passing"
		discoveryMessage = fmt.Sprintf("Discovery snapshot generation %d is available.", rs.LastSuccessfulGeneration)
	}

	defaultAccessStatus := "failing"
	defaultAccessMessage := "No default access policy is enabled."
	if accessPolicyEnabled {
		defaultAccessStatus = "passing"
		defaultAccessMessage = "Default first-login access policy is enabled."
	}

	clientReadyStatus := "failing"
	clientReadyMessage := "Register at least one OAuth client for this resource server."
	if clientCount > 0 {
		clientReadyStatus = "passing"
		clientReadyMessage = fmt.Sprintf("%d OAuth client registration(s) are available.", clientCount)
	}

	browserReadyStatus := "failing"
	browserReadyMessage := "Browser login is not ready yet."
	if metadataStatus == "passing" && challengeStatus == "passing" && clientCount > 0 {
		browserReadyStatus = "passing"
		browserReadyMessage = "Browser login prerequisites are satisfied."
	}

	toolsListReadyStatus := "failing"
	toolsListReadyMessage := "Tool filtering is not ready yet."
	if rs.LastSuccessfulGeneration > 0 && clientCount > 0 {
		toolsListReadyStatus = "passing"
		toolsListReadyMessage = "Tool discovery and client registration are ready for tools/list filtering."
	}

	toolsCallReadyStatus := "failing"
	toolsCallReadyMessage := "Blocked tool enforcement is not ready yet."
	if rs.LastSuccessfulGeneration > 0 {
		toolsCallReadyStatus = "passing"
		toolsCallReadyMessage = "Scope matrix is available for tools/call enforcement."
	}

	checks := []ResourceServerValidationCheck{
		{Key: "metadata", Label: "Metadata URL", Status: metadataStatus, Message: metadataMessage, Observed: metadataObserved},
		{Key: "challenge", Label: "401 challenge", Status: challengeStatus, Message: challengeMessage, Observed: challengeObserved},
		{Key: "discovery", Label: "Discovery snapshot", Status: discoveryStatus, Message: discoveryMessage},
		{Key: "default_access", Label: "Default access policy", Status: defaultAccessStatus, Message: defaultAccessMessage},
		{Key: "client_registration", Label: "Client registration", Status: clientReadyStatus, Message: clientReadyMessage},
		{Key: "browser_login", Label: "Browser login", Status: browserReadyStatus, Message: browserReadyMessage},
		{Key: "tools_list_filter", Label: "tools/list filter", Status: toolsListReadyStatus, Message: toolsListReadyMessage},
		{Key: "tools_call_deny", Label: "tools/call deny", Status: toolsCallReadyStatus, Message: toolsCallReadyMessage},
	}

	overallStatus := "passed"
	var failureMessages []string
	for _, check := range checks {
		if check.Status != "passing" {
			overallStatus = "failing"
			failureMessages = append(failureMessages, fmt.Sprintf("%s: %s", check.Label, check.Message))
		}
	}

	now := time.Now().UTC()
	updates := map[string]interface{}{
		"last_validated_at":      &now,
		"last_validation_status": overallStatus,
	}
	if overallStatus == "failing" {
		errorMessage := strings.Join(failureMessages, " | ")
		updates["last_validation_error"] = errorMessage
	} else {
		updates["last_validation_error"] = nil
	}
	if err := s.db.Model(&models.ResourceServer{}).Where("id = ?", rs.ID).Updates(updates).Error; err != nil {
		return nil, err
	}

	return &ResourceServerValidationResult{
		Status:          overallStatus,
		LastValidatedAt: now,
		Checks:          checks,
	}, nil
}

func (s *ResourceServerOnboardingService) CountRegisteredClients(resourceServerID uuid.UUID) (int64, error) {
	var count int64
	err := s.db.Model(&models.ResourceServerClientRegistration{}).
		Where("resource_server_id = ? AND status = ?", resourceServerID, "approved").
		Count(&count).Error
	return count, err
}

func (s *ResourceServerOnboardingService) listRoleOptions(resourceServerID, tenantID uuid.UUID) ([]ResourceServerRoleOption, error) {
	type roleRow struct {
		ID          uuid.UUID
		Name        string
		Description string
		IsSystem    bool
		Permissions int64
	}

	var rows []roleRow
	err := s.db.Table("roles r").
		Select("DISTINCT r.id, r.name, r.description, r.is_system, COUNT(DISTINCT rp.permission_id) AS permissions").
		Joins("JOIN role_permissions rp ON rp.role_id = r.id").
		Joins("JOIN permissions p ON p.id = rp.permission_id").
		Joins("JOIN oauth_scope_permissions osp ON osp.permission_id = p.id").
		Joins("JOIN oauth_scopes os ON os.id = osp.scope_id").
		Where("r.tenant_id = ?", tenantID).
		Where("os.resource_server_id = ? AND os.tenant_id = ?", resourceServerID, tenantID).
		Group("r.id, r.name, r.description, r.is_system").
		Order("r.name").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	options := make([]ResourceServerRoleOption, 0, len(rows))
	readonlyName := fmt.Sprintf("rs-%s:readonly", resourceServerID.String())
	adminName := fmt.Sprintf("rs-%s:admin", resourceServerID.String())
	for _, row := range rows {
		options = append(options, ResourceServerRoleOption{
			RoleID:      row.ID.String(),
			Name:        row.Name,
			Description: row.Description,
			IsGenerated: row.Name == readonlyName || row.Name == adminName,
			Recommended: row.Name == readonlyName,
			Permissions: row.Permissions,
		})
	}
	return options, nil
}

func (s *ResourceServerOnboardingService) checkMetadataURL(resourceURI string) (string, string, string) {
	metadataURL := buildMetadataURL(resourceURI)
	req, err := http.NewRequest(http.MethodGet, metadataURL, nil)
	if err != nil {
		return "failing", "Metadata URL could not be constructed.", metadataURL
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "failing", fmt.Sprintf("Metadata fetch failed: %v", err), metadataURL
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode != http.StatusOK {
		return "failing", fmt.Sprintf("Metadata endpoint returned %d.", resp.StatusCode), metadataURL
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return "failing", "Metadata endpoint returned an empty body.", metadataURL
	}

	return "passing", "Metadata endpoint returned a non-empty 200 response.", metadataURL
}

func (s *ResourceServerOnboardingService) checkMCPChallenge(resourceURI string) (string, string, string) {
	req, err := http.NewRequest(http.MethodPost, resourceURI, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if err != nil {
		return "failing", "MCP endpoint URL is invalid.", resourceURI
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "failing", fmt.Sprintf("Challenge request failed: %v", err), resourceURI
	}
	defer resp.Body.Close()

	authHeader := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode != http.StatusUnauthorized {
		return "failing", fmt.Sprintf("Unauthenticated MCP request returned %d instead of 401.", resp.StatusCode), authHeader
	}
	if !strings.Contains(strings.ToLower(authHeader), "resource_metadata=") {
		return "failing", "401 response did not include a resource_metadata Bearer challenge.", authHeader
	}

	return "passing", "Unauthenticated MCP request returned a Bearer challenge.", authHeader
}

func buildMetadataURL(resourceURI string) string {
	uri := strings.TrimSpace(resourceURI)
	if uri == "" {
		return "/.well-known/oauth-protected-resource"
	}
	parts := strings.SplitN(uri, "://", 2)
	if len(parts) != 2 {
		return "/.well-known/oauth-protected-resource"
	}

	schemeHost := parts[0] + "://"
	rest := parts[1]
	hostAndPath := strings.SplitN(rest, "/", 2)
	origin := schemeHost + hostAndPath[0]
	if len(hostAndPath) == 1 || hostAndPath[1] == "" {
		return origin + "/.well-known/oauth-protected-resource"
	}

	path := "/" + strings.Trim(hostAndPath[1], "/")
	return origin + "/.well-known/oauth-protected-resource" + path
}

func parseTenantScopedIDs(resourceServerID, tenantID string) (uuid.UUID, uuid.UUID, error) {
	rsUUID, err := uuid.Parse(resourceServerID)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid resource server ID")
	}
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid tenant ID")
	}
	return rsUUID, tenantUUID, nil
}

func roleOptionContains(options []ResourceServerRoleOption, roleID string) bool {
	for _, option := range options {
		if option.RoleID == roleID {
			return true
		}
	}
	return false
}

func stringPtr(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	value := id.String()
	return &value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
