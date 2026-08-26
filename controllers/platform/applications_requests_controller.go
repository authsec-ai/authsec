package platform

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// governanceActor resolves the human performing an approval, for provenance.
// Denormalised label alongside the id because a deactivated user's row can be
// removed, and "approved by <null>" is useless in an audit months later.
func (ctrl *ApplicationsController) governanceActor(c *gin.Context) (*uuid.UUID, string) {
	raw, err := middlewares.ResolveUserID(c)
	if err != nil || raw == "" {
		return nil, c.GetString("client_id")
	}
	parsed, perr := uuid.Parse(raw)
	if perr != nil || parsed == uuid.Nil {
		return nil, raw
	}
	label := c.GetString("email")
	if label == "" {
		label = raw
	}
	return &parsed, label
}

// ── GET /authsec/applications/:id/requests ────────────────────────────────────

type requestActingUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type requestItem struct {
	RequestID       string             `json:"request_id"`
	RequestType     string             `json:"request_type"`
	Status          string             `json:"status"`
	RequesterClient string             `json:"requester_client_id"`
	RequesterName   string             `json:"requester_name"`
	ActingUser      *requestActingUser `json:"acting_user,omitempty"` // nil when subject_type=service_account or user not found
	SourceWorkspace string             `json:"source_workspace,omitempty"`
	RequestedScopes []string           `json:"requested_scopes"`
	CreatedAt       string             `json:"created_at"`
	ExpiresAt       string             `json:"expires_at,omitempty"`
}

// ListRequests returns pending (and recent) access requests for this application.
// GET /authsec/applications/:id/requests
func (ctrl *ApplicationsController) ListRequests(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	type rawRow struct {
		RequestID       string     `gorm:"column:request_id"`
		Status          string     `gorm:"column:status"`
		SubjectType     string     `gorm:"column:subject_type"`
		SubjectID       string     `gorm:"column:subject_id"`
		RequestedScopes string     `gorm:"column:requested_scopes"`
		ClientID        string     `gorm:"column:client_id"`
		ClientName      string     `gorm:"column:client_name"`
		HomeWorkspaceID *uuid.UUID `gorm:"column:home_workspace_id"`
		WorkspaceName   string     `gorm:"column:workspace_name"`
		UserEmail       string     `gorm:"column:user_email"`
		UserName        string     `gorm:"column:user_name"`
		CreatedAt       time.Time  `gorm:"column:created_at"`
		ExpiresAt       *time.Time `gorm:"column:expires_at"`
	}

	var rows []rawRow
	err = config.DB.Raw(`
		SELECT
			ar.id::text            AS request_id,
			ar.status              AS status,
			ar.subject_type        AS subject_type,
			ar.subject_id::text    AS subject_id,
			ar.requested_scopes    AS requested_scopes,
			c.client_id            AS client_id,
			COALESCE(c.client_name, ar.requested_by_client) AS client_name,
			c.home_workspace_id    AS home_workspace_id,
			COALESCE(w.name, '')   AS workspace_name,
			COALESCE(u.email, '')  AS user_email,
			COALESCE(u.name, '')   AS user_name,
			ar.created_at          AS created_at,
			ar.expires_at          AS expires_at
		FROM access_requests ar
		LEFT JOIN mcp_oauth_clients c ON c.client_id = ar.requested_by_client
		LEFT JOIN workspaces w ON w.id = c.home_workspace_id
		LEFT JOIN users u ON u.id = ar.subject_id::uuid AND ar.subject_type = 'user'
		WHERE ar.workspace_id = ?
		  AND ar.resource_server_id = ?
		  AND ar.status IN ('pending','approved','denied')
		ORDER BY ar.created_at DESC
		LIMIT 200
	`, workspaceID, rs.ID).Scan(&rows).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	items := make([]requestItem, 0, len(rows))
	for _, r := range rows {
		scopes := []string{}
		if strings.TrimSpace(r.RequestedScopes) != "" {
			for _, s := range strings.Split(r.RequestedScopes, " ") {
				if s != "" {
					scopes = append(scopes, s)
				}
			}
		}

		item := requestItem{
			RequestID:       r.RequestID,
			RequestType:     "a2a_access",
			Status:          r.Status,
			RequesterClient: r.ClientID,
			RequesterName:   r.ClientName,
			RequestedScopes: scopes,
			CreatedAt:       r.CreatedAt.UTC().Format(time.RFC3339),
		}
		if r.ExpiresAt != nil {
			item.ExpiresAt = r.ExpiresAt.UTC().Format(time.RFC3339)
		}
		if r.WorkspaceName != "" {
			item.SourceWorkspace = r.WorkspaceName
		}
		if r.SubjectType == "user" && r.UserEmail != "" {
			item.ActingUser = &requestActingUser{
				ID:    r.SubjectID,
				Email: r.UserEmail,
				Name:  r.UserName,
			}
		}
		items = append(items, item)
	}

	c.JSON(http.StatusOK, gin.H{"items": items})
}

// ── POST /authsec/applications/:id/requests/:rid/approve ─────────────────────

// ApproveRequest is a thin wrapper around ApproveClientRegistrationWithBinding.
// The frontend sends only role_id — this handler resolves the acting user from
// the access_request and calls the existing atomic approve-with-role service.
// POST /authsec/applications/:id/requests/:rid/approve
func (ctrl *ApplicationsController) ApproveRequest(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	ridStr := c.Param("rid")
	rid, err := uuid.Parse(ridStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request_id"})
		return
	}

	var req struct {
		RoleID string `json:"role_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role_id required"})
		return
	}
	roleUUID, err := uuid.Parse(req.RoleID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role_id"})
		return
	}

	// Load the access_request (must belong to this workspace + RS).
	var ar models.AccessRequest
	if err := config.DB.
		Where("id = ? AND workspace_id = ? AND resource_server_id = ?", rid, workspaceID, rs.ID).
		First(&ar).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}
	if ar.Status != models.AccessRequestPending {
		c.JSON(http.StatusConflict, gin.H{
			"error":  "request is no longer pending",
			"status": ar.Status,
		})
		return
	}

	// The acting user is the mapped subject. Per the plan, approval is only
	// valid for subject_type='user' (A2A binds the role to the acting user,
	// never to the agent/client).
	if ar.SubjectType != "user" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "approval requires a mapped user subject (subject_type must be 'user')",
		})
		return
	}

	// Verify the acting user exists in this workspace. If MapSubject/JIT didn't
	// create the user, block approval with subject_mapping_failed.
	var actingUser struct {
		ID    uuid.UUID
		Email string
	}
	if err := config.DB.Table("users").
		Select("id, email").
		Where("id = ? AND workspace_id = ?", ar.SubjectID, workspaceID).
		Take(&actingUser).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "subject_mapping_failed",
			"message": "the acting user could not be mapped to a workspace user — " +
				"resolve the identity mapping or enable JIT provisioning before approving",
		})
		return
	}

	// Validate the role is RS-scoped to this application.
	var role models.RBACRole
	if err := config.DB.Where("id = ? AND workspace_id = ?", roleUUID, workspaceID).First(&role).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "role not found"})
		return
	}
	if !strings.HasPrefix(role.Name, "rs-"+rs.ID.String()+":") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role is not scoped to this application"})
		return
	}

	// Honour the duration the REQUEST asked for. access_requests.expires_at has always
	// existed and this path ignored it, so a request for time-boxed access was granted
	// permanently. requested_duration is the governance-era field and wins when set,
	// because it is what the requester actually typed.
	var expiresAt *time.Time
	if ar.RequestedDuration != nil && *ar.RequestedDuration > 0 {
		t := time.Now().Add(*ar.RequestedDuration)
		expiresAt = &t
	} else if ar.ExpiresAt != nil && ar.ExpiresAt.After(time.Now()) {
		expiresAt = ar.ExpiresAt
	}

	origin := ar.RequestOrigin
	if origin == "" {
		origin = models.GrantOriginSelfService
	}

	// Approve the connection + bind the role + flip the access_request + record WHY,
	// atomically. Previously this created a permanent binding and wrote no provenance,
	// so nothing downstream could say who approved it or on what grounds.
	actingApprover, approverLabel := ctrl.governanceActor(c)
	grant, err := services.NewProvisioningManager(config.DB, ctrl.oauthSvc).
		GrantEntitlement(workspaceID, services.GrantEntitlementInput{
			ResourceServerID: rs.ID,
			ClientID:         ar.RequestedByClient,
			RoleID:           &roleUUID,
			SubjectType:      "user",
			SubjectID:        actingUser.ID,
			SubjectLabel:     actingUser.Email,
			AccessRequestID:  &ar.ID,
			Origin:           origin,
			Justification:    ar.Justification,
			Purpose:          ar.Purpose,
			ExpiresAt:        expiresAt,
			ActingUser:       actingApprover,
			ActingUserLabel:  approverLabel,
		})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if grant.LegacyStandingDefault {
		log.Printf("access request %s approved as a PERMANENT grant: neither the request nor "+
			"the approval supplied a duration (role=%s app=%s)", ar.ID, roleUUID, rs.ID)
	}

	// connection_id is the public client_id — the same identifier the connections
	// list exposes and that revoke/approve/deny + ConnectionSubjectScopeGap all
	// resolve by. (Returning the registration-row UUID here, the old bug, gave the
	// caller an id that the connection mutations couldn't act on.)
	connectionID := ar.RequestedByClient

	// Resolve the assignment ID for the response.
	var assignmentID string
	var bindingRow struct {
		ID uuid.UUID `gorm:"column:id"`
	}
	if qErr := config.DB.Table("role_bindings").
		Select("id").
		Where("workspace_id = ? AND user_id = ? AND role_id = ?", workspaceID, actingUser.ID, roleUUID).
		Where("scope_type = 'resource_server' AND scope_id = ?", rs.ID).
		Limit(1).Scan(&bindingRow).Error; qErr == nil && bindingRow.ID != uuid.Nil {
		assignmentID = bindingRow.ID.String()
	}

	auditAdminMutation(c, workspaceID.String(), "access_request_approved", "access_request",
		rid.String(), http.StatusOK, nil, map[string]interface{}{
			"application_id": id,
			"acting_user_id": actingUser.ID.String(),
			"role_id":        roleUUID.String(),
			"connection_id":  connectionID,
			"assignment_id":  assignmentID,
		})

	resp := gin.H{
		"status":         "approved",
		"connection_id":  connectionID,
		"assignment_id":  assignmentID,
		"acting_user_id": actingUser.ID.String(),
	}
	if gap, gerr := ctrl.oauthSvc.ConnectionSubjectScopeGap(c.Request.Context(), id, connectionID); gerr == nil && len(gap) > 0 {
		resp["warnings"] = gap
	}
	c.JSON(http.StatusOK, resp)
}

// ── POST /authsec/applications/:id/requests/:rid/deny ────────────────────────

// DenyRequest wraps DenyClientRegistration for the per-request path.
// POST /authsec/applications/:id/requests/:rid/deny
func (ctrl *ApplicationsController) DenyRequest(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	id := c.Param("id")
	rs, err := ctrl.service.GetByIDAndTenant(id, workspaceID.String())
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "application not found"})
		return
	}

	ridStr := c.Param("rid")
	rid, err := uuid.Parse(ridStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request_id"})
		return
	}

	var req struct {
		Reason string `json:"reason,omitempty"`
	}
	_ = c.ShouldBindJSON(&req)

	var ar models.AccessRequest
	if err := config.DB.
		Where("id = ? AND workspace_id = ? AND resource_server_id = ?", rid, workspaceID, rs.ID).
		First(&ar).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "request not found"})
		return
	}
	if ar.Status != models.AccessRequestPending {
		c.JSON(http.StatusConflict, gin.H{
			"error":  "request is no longer pending",
			"status": ar.Status,
		})
		return
	}

	if err := ctrl.oauthSvc.DenyClientRegistration(rs.ID.String(), ar.RequestedByClient); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Persist the reason if provided.
	if req.Reason != "" {
		config.DB.Model(&models.AccessRequest{}).
			Where("id = ?", rid).
			Update("reason", req.Reason)
	}

	auditAdminMutation(c, workspaceID.String(), "access_request_denied", "access_request",
		rid.String(), http.StatusOK, nil, map[string]interface{}{
			"application_id": id,
			"reason":         req.Reason,
		})
	c.JSON(http.StatusOK, gin.H{"status": "denied"})
}
