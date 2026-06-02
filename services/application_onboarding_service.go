package services

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ApplicationOnboardingService is the lean tenant-scoped equivalent of the
// dev branch's ResourceServerOnboardingService. It deliberately drops:
//
//   - role-option enumeration (no scan of available roles against the RS's
//     scope grants)
//   - DefaultRole GORM preload (no join into a Role model)
//   - EnsureDefaultAccessBinding (no first-login auto-binding)
//
// Callers that want richer policy semantics should call into the dev
// backend or wait for a future port of the full RBAC stack. See
// docs/mcp_oauth_v2.md "Things explicitly NOT done" for context.
type ApplicationOnboardingService struct {
	httpClient *http.Client
}

func NewApplicationOnboardingService() *ApplicationOnboardingService {
	return &ApplicationOnboardingService{
		httpClient: &http.Client{Timeout: 8 * time.Second},
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Access policy
// ─────────────────────────────────────────────────────────────────────────

// ApplicationAccessPolicyResponse mirrors the dev response shape so the UI
// can hit either backend without conditional rendering. RoleOptions is
// always an empty slice on the backport (see PHASE3-NOTE in the model).
type ApplicationAccessPolicyResponse struct {
	Enabled           bool        `json:"enabled"`
	DefaultRoleID     *string     `json:"default_role_id,omitempty"`
	DefaultRoleName   *string     `json:"default_role_name,omitempty"`
	AssignmentTrigger string      `json:"assignment_trigger"`
	AssignmentSource  string      `json:"assignment_source"`
	RoleOptions       []roleStub  `json:"role_options"`
}

// roleStub is here so the JSON contract matches dev (which sends a typed
// role-option object). We always emit `[]` so consumers parse but get nothing.
type roleStub struct{}

// UpdateApplicationAccessPolicyRequest is the inbound body for PUT.
type UpdateApplicationAccessPolicyRequest struct {
	Enabled       bool   `json:"enabled"`
	DefaultRoleID string `json:"default_role_id"`
}

// GetAccessPolicy returns the current policy row (or a disabled default if no
// row exists yet). No role-options enumeration on the backport.
func (s *ApplicationOnboardingService) GetAccessPolicy(tenantID string, applicationID uuid.UUID) (*ApplicationAccessPolicyResponse, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	var policy models.ApplicationAccessPolicy
	err = tenantDB.Where("application_id = ? AND tenant_id = ?", applicationID, tenantID).
		First(&policy).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	resp := &ApplicationAccessPolicyResponse{
		Enabled:           false,
		AssignmentTrigger: "first_successful_login",
		AssignmentSource:  "default_policy",
		RoleOptions:       []roleStub{},
	}
	if err == nil {
		resp.Enabled = policy.Enabled
		resp.AssignmentTrigger = policy.AssignmentTrigger
		resp.AssignmentSource = policy.AssignmentSource
		if policy.DefaultRoleID != nil {
			s := policy.DefaultRoleID.String()
			resp.DefaultRoleID = &s
		}
	}
	return resp, nil
}

// UpdateAccessPolicy upserts the policy row. When Enabled=true,
// DefaultRoleID is required; we persist it as-is without validating against
// available roles (PHASE3-NOTE on the model).
func (s *ApplicationOnboardingService) UpdateAccessPolicy(
	tenantID string,
	applicationID uuid.UUID,
	req UpdateApplicationAccessPolicyRequest,
) (*ApplicationAccessPolicyResponse, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return nil, fmt.Errorf("get tenant db: %w", err)
	}

	var defaultRoleID *uuid.UUID
	if req.Enabled {
		if strings.TrimSpace(req.DefaultRoleID) == "" {
			return nil, fmt.Errorf("default_role_id is required when access policy is enabled")
		}
		parsed, parseErr := uuid.Parse(req.DefaultRoleID)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid default_role_id")
		}
		defaultRoleID = &parsed
	}

	var existing models.ApplicationAccessPolicy
	err = tenantDB.Where("application_id = ? AND tenant_id = ?", applicationID, tenantID).
		First(&existing).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		existing = models.ApplicationAccessPolicy{
			TenantID:          tenantID,
			ApplicationID:     applicationID,
			Enabled:           req.Enabled,
			DefaultRoleID:     defaultRoleID,
			AssignmentTrigger: "first_successful_login",
			AssignmentSource:  "default_policy",
		}
		if createErr := tenantDB.Create(&existing).Error; createErr != nil {
			return nil, createErr
		}
	} else {
		if updateErr := tenantDB.Model(&existing).Updates(map[string]interface{}{
			"enabled":            req.Enabled,
			"default_role_id":    defaultRoleID,
			"assignment_trigger": "first_successful_login",
			"assignment_source":  "default_policy",
			"updated_at":         time.Now().UTC(),
		}).Error; updateErr != nil {
			return nil, updateErr
		}
	}

	resp := &ApplicationAccessPolicyResponse{
		Enabled:           req.Enabled,
		AssignmentTrigger: "first_successful_login",
		AssignmentSource:  "default_policy",
		RoleOptions:       []roleStub{},
	}
	if defaultRoleID != nil {
		s := defaultRoleID.String()
		resp.DefaultRoleID = &s
	}
	return resp, nil
}

// GetAccessPolicySummary returns the enabled flag without the full payload.
// Used by Validate to decide whether the access-policy check passes.
func (s *ApplicationOnboardingService) GetAccessPolicySummary(tenantID string, applicationID uuid.UUID) (bool, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return false, fmt.Errorf("get tenant db: %w", err)
	}
	var policy models.ApplicationAccessPolicy
	err = tenantDB.Where("application_id = ? AND tenant_id = ?", applicationID, tenantID).
		First(&policy).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return policy.Enabled, nil
}

// ─────────────────────────────────────────────────────────────────────────
// Client count
// ─────────────────────────────────────────────────────────────────────────

// CountRegisteredClients returns the number of approved client registrations
// for the Application. Used by Validate + TestLogin.
func (s *ApplicationOnboardingService) CountRegisteredClients(tenantID string, applicationID uuid.UUID) (int64, error) {
	tenantDB, err := config.GetTenantGORMDB(tenantID)
	if err != nil {
		return 0, fmt.Errorf("get tenant db: %w", err)
	}
	var count int64
	err = tenantDB.Model(&models.ResourceServerClientRegistration{}).
		Where("resource_server_id = ? AND status = ?", applicationID, models.RegistrationStatusApproved).
		Count(&count).Error
	return count, err
}

// ─────────────────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────────────────

// ApplicationValidationCheck is one row of the Validate response.
type ApplicationValidationCheck struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Observed string `json:"observed,omitempty"`
}

// ApplicationValidationResult is the top-level Validate response.
type ApplicationValidationResult struct {
	Status          string                       `json:"status"`
	LastValidatedAt time.Time                    `json:"last_validated_at"`
	Checks          []ApplicationValidationCheck `json:"checks"`
}

// ValidateResourceServer runs live onboarding-style checks against an
// Application row and returns the aggregated status. Backport scope:
//
//   - state check: row's state column
//   - clients check: at least one registered client
//   - access-policy check: policy row exists and enabled
//   - reachability check: HEAD the public_base_url (8s timeout)
//
// The dev branch additionally validates against mcp_tools scope coverage
// and scope-resolver health — not ported here (no mcp_tools on the
// backport). The result is NOT persisted on the row; the dev branch
// updates last_validated_at / last_validation_status / last_validation_error
// on resource_servers but we skip the write to keep this read-only-ish.
func (s *ApplicationOnboardingService) ValidateResourceServer(
	rs *models.ResourceServer,
	clientCount int,
	accessPolicyEnabled bool,
) *ApplicationValidationResult {
	checks := []ApplicationValidationCheck{}

	// State check
	stateCheck := ApplicationValidationCheck{
		Key:      "state",
		Label:    "Application state",
		Observed: rs.State,
	}
	switch rs.State {
	case models.RSStateReady:
		stateCheck.Status = "pass"
		stateCheck.Message = "Application is ready"
	case models.RSStateNeedsSetup, models.RSStatePendingScan:
		stateCheck.Status = "warn"
		stateCheck.Message = "Application setup is incomplete"
	default:
		stateCheck.Status = "fail"
		stateCheck.Message = "Application is in an error state"
	}
	checks = append(checks, stateCheck)

	// Clients check
	clientsCheck := ApplicationValidationCheck{
		Key:      "clients",
		Label:    "Registered OAuth clients",
		Observed: fmt.Sprintf("%d", clientCount),
	}
	if clientCount > 0 {
		clientsCheck.Status = "pass"
		clientsCheck.Message = "At least one OAuth client is registered"
	} else {
		clientsCheck.Status = "warn"
		clientsCheck.Message = "No OAuth clients have registered yet"
	}
	checks = append(checks, clientsCheck)

	// Access policy check
	accessCheck := ApplicationValidationCheck{
		Key:      "access_policy",
		Label:    "Default access policy",
		Observed: fmt.Sprintf("enabled=%t", accessPolicyEnabled),
	}
	if accessPolicyEnabled {
		accessCheck.Status = "pass"
		accessCheck.Message = "Default access policy is configured"
	} else {
		accessCheck.Status = "warn"
		accessCheck.Message = "No default access policy — new users will require manual role assignment"
	}
	checks = append(checks, accessCheck)

	// Reachability check (outbound probe)
	reachCheck := ApplicationValidationCheck{
		Key:      "reachability",
		Label:    "Public base URL reachability",
		Observed: rs.PublicBaseURL,
	}
	if strings.TrimSpace(rs.PublicBaseURL) == "" {
		reachCheck.Status = "fail"
		reachCheck.Message = "public_base_url is empty"
	} else {
		probe, err := http.NewRequest(http.MethodHead, rs.PublicBaseURL, nil)
		if err != nil {
			reachCheck.Status = "fail"
			reachCheck.Message = "invalid public_base_url: " + err.Error()
		} else {
			resp, err := s.httpClient.Do(probe)
			if err != nil {
				reachCheck.Status = "fail"
				reachCheck.Message = "unreachable: " + err.Error()
			} else {
				defer resp.Body.Close()
				// 2xx, 3xx, 401, 403 are all fine — the URL is reachable; auth
				// failure on a HEAD is expected for many MCP servers.
				if resp.StatusCode < 500 {
					reachCheck.Status = "pass"
					reachCheck.Message = fmt.Sprintf("HEAD returned %d", resp.StatusCode)
				} else {
					reachCheck.Status = "fail"
					reachCheck.Message = fmt.Sprintf("HEAD returned %d", resp.StatusCode)
				}
			}
		}
	}
	checks = append(checks, reachCheck)

	// Aggregate status: fail if any check failed, warn if any check warned, else pass.
	overall := "pass"
	for _, c := range checks {
		if c.Status == "fail" {
			overall = "fail"
			break
		}
		if c.Status == "warn" && overall == "pass" {
			overall = "warn"
		}
	}

	return &ApplicationValidationResult{
		Status:          overall,
		LastValidatedAt: time.Now().UTC(),
		Checks:          checks,
	}
}
