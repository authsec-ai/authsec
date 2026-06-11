package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// SCIMConnectionsController serves the operator-only SCIM connection
// management API. The opaque connection_id + bearer token returned by Create
// drive the new `/scim/v2/c/:scim_connection_id/...` route (v4 §13).
//
// Mint flow:
//
//	POST /authsec/scim-connections { "identity_provider_id"?, "default_client_id"?, "default_project_id"? }
//	→ { "id", "token", "workspace_id" }    -- token returned exactly once
//
// The plaintext token is shown to the operator a single time on creation;
// only the SHA-256 hash is persisted in scim_connections.token_hash. Rotation
// happens by creating a new connection and revoking the old one — the v4
// plan calls for a two-token grace window which is best implemented by
// keeping both connections active in parallel.
type SCIMConnectionsController struct{}

func NewSCIMConnectionsController() *SCIMConnectionsController {
	return &SCIMConnectionsController{}
}

type scimConnectionCreateRequest struct {
	IdentityProviderID *string `json:"identity_provider_id,omitempty"`
	DefaultClientID    *string `json:"default_client_id,omitempty"`
	DefaultProjectID   *string `json:"default_project_id,omitempty"`
}

type scimConnectionCreateResponse struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	// Token is the plaintext bearer token. Shown once — operators must save it
	// immediately. Subsequent reads return only the hash.
	Token    string `json:"token"`
	Endpoint string `json:"endpoint"`
}

// Create handles POST /authsec/scim-connections.
func (ctrl *SCIMConnectionsController) Create(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	var req scimConnectionCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// An empty body is acceptable — every field is optional.
		req = scimConnectionCreateRequest{}
	}

	var idpID *uuid.UUID
	if req.IdentityProviderID != nil && *req.IdentityProviderID != "" {
		parsed, perr := uuid.Parse(*req.IdentityProviderID)
		if perr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid identity_provider_id"})
			return
		}
		// Ensure the IDP belongs to this workspace before pinning it.
		var ipRow models.IdentityProvider
		if err := config.DB.Where("id = ? AND workspace_id = ?", parsed, workspaceID).First(&ipRow).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "identity provider not found in workspace"})
			return
		}
		idpID = &parsed
	}

	var defaultClient, defaultProject *uuid.UUID
	if req.DefaultClientID != nil && *req.DefaultClientID != "" {
		parsed, perr := uuid.Parse(*req.DefaultClientID)
		if perr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid default_client_id"})
			return
		}
		defaultClient = &parsed
	}
	if req.DefaultProjectID != nil && *req.DefaultProjectID != "" {
		parsed, perr := uuid.Parse(*req.DefaultProjectID)
		if perr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid default_project_id"})
			return
		}
		defaultProject = &parsed
	}

	// 32 bytes of randomness = 256 bits of entropy. Encoded as URL-safe
	// base64 (no padding) so the resulting token is ~43 characters.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])

	conn := &models.SCIMConnection{
		ID:                 uuid.New(),
		WorkspaceID:        workspaceID,
		IdentityProviderID: idpID,
		TokenHash:          hashHex,
		DefaultClientID:    defaultClient,
		DefaultProjectID:   defaultProject,
		Status:             "active",
		CreatedAt:          time.Now(),
	}

	if err := config.DB.Create(conn).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	base := strings.TrimRight(config.AppConfig.OAuthBaseURL(), "/")
	endpoint := fmt.Sprintf("%s/authsec/uflow/scim/v2/c/%s", base, conn.ID.String())

	c.JSON(http.StatusCreated, scimConnectionCreateResponse{
		ID:          conn.ID.String(),
		WorkspaceID: workspaceID.String(),
		Token:       token,
		Endpoint:    endpoint,
	})
}

// Rotate handles POST /authsec/scim-connections/:id/rotate.
// Mints a new bearer token, moves the current token to the previous slot with a
// 5-minute grace window so the IdP can swap tokens without a provisioning gap.
func (ctrl *SCIMConnectionsController) Rotate(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	connectionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scim connection id"})
		return
	}

	var conn models.SCIMConnection
	if err := config.DB.Where("id = ? AND workspace_id = ?", connectionID, workspaceID).First(&conn).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scim connection not found"})
		return
	}
	if conn.Status != "active" {
		c.JSON(http.StatusConflict, gin.H{"error": "cannot rotate a non-active connection"})
		return
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}
	newToken := base64.RawURLEncoding.EncodeToString(raw)
	newHash := sha256.Sum256([]byte(newToken))
	newHashHex := hex.EncodeToString(newHash[:])

	// Move current token to previous slot with 5-min grace window.
	graceCutoff := time.Now().Add(5 * time.Minute)
	if err := config.DB.Model(&conn).Updates(map[string]interface{}{
		"previous_token_hash":       conn.TokenHash,
		"previous_token_expires_at": graceCutoff,
		"token_hash":                newHashHex,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	base := strings.TrimRight(config.AppConfig.OAuthBaseURL(), "/")
	endpoint := fmt.Sprintf("%s/authsec/uflow/scim/v2/c/%s", base, conn.ID.String())

	c.JSON(http.StatusOK, gin.H{
		"id":       conn.ID.String(),
		"token":    newToken,
		"endpoint": endpoint,
		"previous_token_expires_at": graceCutoff,
	})
}

// ListEvents handles GET /authsec/scim-connections/:id/events.
// Returns the last N SCIM operations logged against this connection.
func (ctrl *SCIMConnectionsController) ListEvents(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	connectionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scim connection id"})
		return
	}

	// Verify ownership before returning events.
	var conn models.SCIMConnection
	if err := config.DB.Select("id").Where("id = ? AND workspace_id = ?", connectionID, workspaceID).First(&conn).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scim connection not found"})
		return
	}

	limit := 100
	var events []models.SCIMEvent
	if err := config.DB.
		Where("scim_connection_id = ?", connectionID).
		Order("ts DESC").
		Limit(limit).
		Find(&events).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, events)
}

// List handles GET /authsec/scim-connections — returns metadata only, never
// the token or hash.
func (ctrl *SCIMConnectionsController) List(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	var rows []models.SCIMConnection
	if err := config.DB.
		Where("workspace_id = ?", workspaceID).
		Order("created_at DESC").
		Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rows)
}

// Revoke handles DELETE /authsec/scim-connections/:id — marks the connection
// revoked rather than deleting the row so audit trails remain intact.
func (ctrl *SCIMConnectionsController) Revoke(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	connectionID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scim connection id"})
		return
	}

	now := time.Now()
	result := config.DB.Model(&models.SCIMConnection{}).
		Where("id = ? AND workspace_id = ?", connectionID, workspaceID).
		Updates(map[string]interface{}{
			"status":     "revoked",
			"revoked_at": now,
		})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "scim connection not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}
