package platform

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/delegation"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// DelegationPolicyController manages delegation policies that govern
// which roles can delegate trust to AI agent types, within one workspace.
// Every statement goes through internal/tenancy, so another workspace's
// policy or agent is answered as not found.
type DelegationPolicyController struct{}

func NewDelegationPolicyController() *DelegationPolicyController {
	return &DelegationPolicyController{}
}

// --- Request/Response types ---

type CreateDelegationPolicyRequest struct {
	RoleName           string   `json:"role_name" binding:"required"`
	AgentType          string   `json:"agent_type" binding:"required"`
	AllowedPermissions []string `json:"allowed_permissions"`
	MaxTTLSeconds      int      `json:"max_ttl_seconds"`
	Enabled            *bool    `json:"enabled"`
	ClientID           string   `json:"client_id"`
	// Audience is accepted for compatibility and ignored: creating a
	// policy no longer issues a token.
	Audience []string `json:"audience"`
}

type UpdateDelegationPolicyRequest struct {
	RoleName           *string  `json:"role_name"`
	AgentType          *string  `json:"agent_type"`
	AllowedPermissions []string `json:"allowed_permissions"`
	MaxTTLSeconds      *int     `json:"max_ttl_seconds"`
	Enabled            *bool    `json:"enabled"`
	ClientID           *string  `json:"client_id"`
}

// delegationAgentRef parses a policy's client_id and checks that it names an
// active ai_agent in the request's workspace. It writes the error response
// and returns false when it doesn't.
func delegationAgentRef(c *gin.Context, raw string) (*uuid.UUID, bool) {
	cid, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid client_id format"})
		return nil, false
	}
	if err := validateClientActive(c, cid); err != nil {
		if status := tenancy.HTTPStatus(err); status != http.StatusNotFound {
			c.JSON(status, gin.H{"error": "Failed to validate agent"})
			return nil, false
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found or not active"})
		return nil, false
	}
	return &cid, true
}

// capPolicyTTL keeps a policy's max TTL within the delegated-token maximum.
func capPolicyTTL(seconds int) int {
	return int(delegation.CapTTL(time.Duration(seconds) * time.Second).Seconds())
}

func respondDelegationLookupError(c *gin.Context, err error) {
	if status := tenancy.HTTPStatus(err); status != http.StatusNotFound {
		c.JSON(status, gin.H{"error": "Failed to load delegation policy"})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "Delegation policy not found"})
}

// CreateDelegationPolicy creates a new delegation policy in the caller's workspace.
func (dc *DelegationPolicyController) CreateDelegationPolicy(c *gin.Context) {
	workspaceID, err := tenancy.Workspace(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in authentication token"})
		return
	}

	var req CreateDelegationPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	if req.MaxTTLSeconds <= 0 {
		req.MaxTTLSeconds = 3600
	}
	req.MaxTTLSeconds = capPolicyTTL(req.MaxTTLSeconds)
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	allowedPerms := req.AllowedPermissions
	if allowedPerms == nil {
		allowedPerms = []string{}
	}
	permsJSON, _ := json.Marshal(allowedPerms)

	userIDStr := delegationContextString(c, "user_id")
	var createdBy *uuid.UUID
	if uid, err := uuid.Parse(userIDStr); err == nil {
		createdBy = &uid
	}

	// client_id references the ai_agent resource_servers.id this policy is
	// scoped to; it must be an agent of this workspace.
	var clientID *uuid.UUID
	if req.ClientID != "" {
		var ok bool
		if clientID, ok = delegationAgentRef(c, req.ClientID); !ok {
			return
		}
	}

	policy := models.DelegationPolicy{
		ID:                 uuid.New(),
		WorkspaceID:        workspaceID,
		RoleName:           req.RoleName,
		AgentType:          req.AgentType,
		AllowedPermissions: permsJSON,
		MaxTTLSeconds:      req.MaxTTLSeconds,
		Enabled:            enabled,
		ClientID:           clientID,
		CreatedBy:          createdBy,
	}

	if err := config.DB.WithContext(c.Request.Context()).Create(&policy).Error; err != nil {
		if isDuplicateKeyError(err) {
			c.JSON(http.StatusConflict, gin.H{
				"error": "A delegation policy for this role and agent type already exists",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create delegation policy"})
		return
	}

	middlewares.Audit(c, "delegation_policy", policy.ID.String(), "create", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"role_name":           req.RoleName,
			"agent_type":          req.AgentType,
			"allowed_permissions": req.AllowedPermissions,
			"max_ttl_seconds":     req.MaxTTLSeconds,
			"enabled":             enabled,
			"client_id":           req.ClientID,
		},
	})

	// Creating a policy grants nothing by itself. Identity provisioning and
	// delegated JWT-SVIDs are explicit admin actions
	// (/uflow/admin/agents/:id/provision-identity and /delegate-token), which
	// intersect the policy with the caller's own permissions.
	c.JSON(http.StatusCreated, gin.H{"policy": policy})
}

// ListDelegationPolicies lists the caller's workspace's delegation policies.
func (dc *DelegationPolicyController) ListDelegationPolicies(c *gin.Context) {
	query, err := tenancy.DB(c, config.DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in authentication token"})
		return
	}

	if roleName := c.Query("role_name"); roleName != "" {
		query = query.Where("role_name = ?", roleName)
	}
	if agentType := c.Query("agent_type"); agentType != "" {
		query = query.Where("agent_type = ?", agentType)
	}
	if enabled := c.Query("enabled"); enabled == "true" {
		query = query.Where("enabled = true")
	} else if enabled == "false" {
		query = query.Where("enabled = false")
	}

	policies := []models.DelegationPolicy{}
	if err := query.Order("created_at DESC").Find(&policies).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list delegation policies"})
		return
	}

	c.JSON(http.StatusOK, policies)
}

// GetDelegationPolicy retrieves a single delegation policy by ID.
func (dc *DelegationPolicyController) GetDelegationPolicy(c *gin.Context) {
	policyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy ID"})
		return
	}

	var policy models.DelegationPolicy
	if err := tenancy.Get(c, config.DB, &policy, policyID); err != nil {
		respondDelegationLookupError(c, err)
		return
	}

	c.JSON(http.StatusOK, policy)
}

// UpdateDelegationPolicy updates an existing delegation policy.
func (dc *DelegationPolicyController) UpdateDelegationPolicy(c *gin.Context) {
	policyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy ID"})
		return
	}

	var policy models.DelegationPolicy
	if err := tenancy.Get(c, config.DB, &policy, policyID); err != nil {
		respondDelegationLookupError(c, err)
		return
	}

	var req UpdateDelegationPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	if req.RoleName != nil {
		policy.RoleName = *req.RoleName
	}
	if req.AgentType != nil {
		policy.AgentType = *req.AgentType
	}
	if req.AllowedPermissions != nil {
		permsJSON, _ := json.Marshal(req.AllowedPermissions)
		policy.AllowedPermissions = permsJSON
	}
	if req.MaxTTLSeconds != nil {
		policy.MaxTTLSeconds = capPolicyTTL(*req.MaxTTLSeconds)
	}
	if req.Enabled != nil {
		policy.Enabled = *req.Enabled
	}
	if req.ClientID != nil {
		if *req.ClientID == "" {
			policy.ClientID = nil
		} else {
			cid, ok := delegationAgentRef(c, *req.ClientID)
			if !ok {
				return
			}
			policy.ClientID = cid
		}
	}
	policy.UpdatedAt = time.Now()

	scoped, err := tenancy.DB(c, config.DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in authentication token"})
		return
	}
	if err := scoped.Save(&policy).Error; err != nil {
		if isDuplicateKeyError(err) {
			c.JSON(http.StatusConflict, gin.H{
				"error": "A delegation policy for this role and agent type already exists",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update delegation policy"})
		return
	}

	middlewares.Audit(c, "delegation_policy", policyID.String(), "update", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"role_name":       policy.RoleName,
			"agent_type":      policy.AgentType,
			"max_ttl_seconds": policy.MaxTTLSeconds,
			"enabled":         policy.Enabled,
		},
	})

	c.JSON(http.StatusOK, policy)
}

// DeleteDelegationPolicy deletes a delegation policy.
func (dc *DelegationPolicyController) DeleteDelegationPolicy(c *gin.Context) {
	policyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy ID"})
		return
	}

	scoped, err := tenancy.DB(c, config.DB)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id not found in authentication token"})
		return
	}
	result := scoped.Where("id = ?", policyID).Delete(&models.DelegationPolicy{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete delegation policy"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Delegation policy not found"})
		return
	}

	middlewares.Audit(c, "delegation_policy", policyID.String(), "delete", nil)

	c.JSON(http.StatusOK, gin.H{"status": "deleted", "id": policyID.String()})
}
