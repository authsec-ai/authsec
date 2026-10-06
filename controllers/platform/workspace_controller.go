package platform

import (
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type WorkspaceController struct{}

func NewWorkspaceController() *WorkspaceController {
	return &WorkspaceController{}
}

func (wc *WorkspaceController) SwitchWorkspace(c *gin.Context) {
	workspaceID, err := uuid.Parse(c.Param("workspace_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid workspace_id"})
		return
	}

	claims, _ := c.Get("claims")
	mapClaims, _ := claims.(jwt.MapClaims)
	userID, err := workspaceUserID(c, mapClaims)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id missing from token"})
		return
	}

	var membership models.WorkspaceMembership
	if err := config.DB.
		Where("workspace_id = ? AND user_id = ? AND status = ?", workspaceID, userID, models.MembershipStatusActive).
		First(&membership).Error; err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "workspace membership not found or inactive"})
		return
	}

	clientID := ""
	if raw, ok := mapClaims["client_id"].(string); ok {
		clientID = raw
	}
	email := ""
	if raw, ok := mapClaims["email_id"].(string); ok {
		email = raw
	} else if raw, ok := mapClaims["email"].(string); ok {
		email = raw
	}

	token, err := config.TokenService.GenerateWorkspaceToken(
		userID,
		workspaceID,
		membership.ID,
		clientID,
		email,
		24*time.Hour,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue workspace token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":            token,
		"token_type":              "Bearer",
		"workspace_id":            workspaceID,
		"workspace_membership_id": membership.ID,
	})
}

func workspaceUserID(c *gin.Context, claims jwt.MapClaims) (uuid.UUID, error) {
	if raw := c.GetString("user_id"); raw != "" {
		if parsed, err := uuid.Parse(raw); err == nil {
			return parsed, nil
		}
	}
	for _, key := range []string{"user_id", "sub"} {
		if raw, ok := claims[key].(string); ok {
			if parsed, err := uuid.Parse(raw); err == nil {
				return parsed, nil
			}
		}
	}
	return uuid.Nil, http.ErrNoCookie
}

// ListMyWorkspaces lists the workspaces the signed-in user may switch to:
// their home workspace and every workspace with an active membership. It
// returns nothing about workspaces the user does not belong to.
func (wc *WorkspaceController) ListMyWorkspaces(c *gin.Context) {
	claims, _ := c.Get("claims")
	mapClaims, _ := claims.(jwt.MapClaims)
	userID, err := workspaceUserID(c, mapClaims)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_id missing from token"})
		return
	}
	current := c.GetString("workspace_id")

	type row struct {
		WorkspaceID     uuid.UUID `json:"workspace_id"`
		Name            string    `json:"name"`
		WorkspaceDomain string    `json:"workspace_domain"`
		Role            string    `json:"role"`
		Current         bool      `json:"current"`
	}
	var rows []row
	// TENANT-EXEMPT: lists the caller's own memberships across workspaces, keyed by the verified user id.
	if err := config.DB.Raw(`
		SELECT w.id AS workspace_id, COALESCE(w.name, '') AS name,
		       COALESCE(w.workspace_domain, '') AS workspace_domain,
		       COALESCE(r.name, '') AS role
		  FROM workspace_memberships m
		  JOIN workspaces w ON w.id = m.workspace_id
		  LEFT JOIN roles r ON r.id = m.role_id
		 WHERE m.user_id = ? AND m.status = 'active' AND w.status = 'active'
		UNION
		SELECT w.id, COALESCE(w.name, ''), COALESCE(w.workspace_domain, ''), ''
		  FROM users u
		  JOIN workspaces w ON w.id = u.workspace_id
		 WHERE u.id = ? AND u.deleted_at IS NULL AND COALESCE(u.active, true) AND w.status = 'active'
		   AND NOT EXISTS (SELECT 1 FROM workspace_memberships m2 -- TENANT-EXEMPT: same caller-own listing
		                    WHERE m2.workspace_id = u.workspace_id AND m2.user_id = u.id)
		 ORDER BY 2`, userID, userID).Scan(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list workspaces"})
		return
	}
	for i := range rows {
		rows[i].Current = rows[i].WorkspaceID.String() == current
	}
	c.JSON(http.StatusOK, gin.H{"workspaces": rows})
}
