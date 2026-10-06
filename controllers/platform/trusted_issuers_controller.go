package platform

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/controllers/shared"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// TrustedIssuersController handles workspace-scoped CRUD for external issuers
// that may present ID-JAGs for XAA redemption.
//
// Routes (all require workspace admin JWT):
//
//	GET    /authsec/trusted-issuers         list workspace issuers
//	POST   /authsec/trusted-issuers         create issuer
//	POST   /authsec/trusted-issuers/test    validate an assertion against stored config
//	DELETE /authsec/trusted-issuers/:id     revoke issuer + bulk-revoke live XAA tokens
//
// Every route acts only on issuers owned by the token's workspace. Platform
// issuers (workspace_id NULL) are not visible to, and cannot be changed by,
// workspace admins.
type TrustedIssuersController struct {
	xaaService *services.XAAService
}

func NewTrustedIssuersController() *TrustedIssuersController {
	return &TrustedIssuersController{
		xaaService: services.NewXAAService(config.DB),
	}
}

// listTrustedIssuersResponse is the list envelope.
type listTrustedIssuersResponse struct {
	Items []models.TrustedIssuer `json:"items"`
}

// createTrustedIssuerBody is the inbound payload for POST /trusted-issuers.
type createTrustedIssuerBody struct {
	Iss                   string   `json:"iss"`
	JWKSUri               string   `json:"jwks_uri"`
	ProviderName          string   `json:"provider_name"`
	AllowedAlgs           []string `json:"allowed_algs,omitempty"`
	AllowedAuds           []string `json:"allowed_auds,omitempty"`
	ClockSkewSecs         int      `json:"clock_skew_secs,omitempty"`
	WorkspaceClaimMapping string   `json:"workspace_claim_mapping,omitempty"`
	SubjectMapping        string   `json:"subject_mapping,omitempty"`
	JITProvisioning       bool     `json:"jit_provisioning,omitempty"`
}

// testTrustedIssuerBody is the inbound payload for POST /trusted-issuers/test.
type testTrustedIssuerBody struct {
	Assertion string `json:"assertion"`
	ClientID  string `json:"client_id,omitempty"`
}

// reservedProviderPrefix marks provider names AuthSec uses itself (e.g. the
// self-issued "authsec:id-jag"); a workspace issuer may not claim one, or its
// ID-JAGs would resolve identities linked under the system provider.
const reservedProviderPrefix = "authsec:"

// List handles GET /authsec/trusted-issuers — returns the trusted issuers owned
// by the token's workspace.
func (ctrl *TrustedIssuersController) List(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	var issuers []models.TrustedIssuer
	if err := config.DB.WithContext(c.Request.Context()).
		Where("workspace_id = ?", workspaceID).
		Order("created_at DESC").
		Find(&issuers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "couldn't list trusted issuers"})
		return
	}

	if issuers == nil {
		issuers = []models.TrustedIssuer{}
	}
	c.JSON(http.StatusOK, listTrustedIssuersResponse{Items: issuers})
}

// Create handles POST /authsec/trusted-issuers — registers a new external issuer.
func (ctrl *TrustedIssuersController) Create(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	var body createTrustedIssuerBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}
	if body.Iss == "" || body.JWKSUri == "" || body.ProviderName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "iss, jwks_uri, and provider_name are required"})
		return
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(body.ProviderName)), reservedProviderPrefix) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": fmt.Sprintf("provider_name prefix %q is reserved", reservedProviderPrefix)})
		return
	}

	algs := pq.StringArray(body.AllowedAlgs)
	if len(algs) == 0 {
		algs = pq.StringArray{"RS256"}
	}
	auds := pq.StringArray(body.AllowedAuds)
	if auds == nil {
		auds = pq.StringArray{}
	}
	skew := body.ClockSkewSecs
	if skew == 0 {
		skew = 30
	}

	now := time.Now().UTC()
	issuer := models.TrustedIssuer{
		ID:              uuid.New(),
		Iss:             body.Iss,
		JWKSUri:         body.JWKSUri,
		ProviderName:    body.ProviderName,
		AllowedAlgs:     algs,
		AllowedAuds:     auds,
		ClockSkewSecs:   skew,
		JITProvisioning: body.JITProvisioning,
		Status:          "active",
		CreatedAt:       now,
		UpdatedAt:       now,
		WorkspaceID:     &workspaceID,
	}
	if body.WorkspaceClaimMapping != "" {
		issuer.WorkspaceClaimMapping = &body.WorkspaceClaimMapping
	}
	if body.SubjectMapping != "" {
		issuer.SubjectMapping = &body.SubjectMapping
	}

	if err := config.DB.WithContext(c.Request.Context()).Create(&issuer).Error; err != nil {
		if isDuplicateKeyError(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "message": fmt.Sprintf("issuer %q is already registered", body.Iss)})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "couldn't create trusted issuer"})
		return
	}

	c.JSON(http.StatusCreated, issuer)
}

// Test handles POST /authsec/trusted-issuers/test — validates an ID-JAG assertion
// against stored issuer config without creating any tokens.
func (ctrl *TrustedIssuersController) Test(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	var body testTrustedIssuerBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}
	if body.Assertion == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "assertion is required"})
		return
	}
	clientID := body.ClientID
	if clientID == "" {
		clientID = "test-client"
	}

	// Only this workspace's own issuers may be tested: validating against
	// another workspace's (or the platform's) issuer would disclose its config.
	var owned int64
	if unverified, _, perr := new(jwt.Parser).ParseUnverified(body.Assertion, jwt.MapClaims{}); perr == nil {
		if uc, ok := unverified.Claims.(jwt.MapClaims); ok {
			if iss, _ := uc["iss"].(string); iss != "" {
				if err := config.DB.WithContext(c.Request.Context()).
					Model(&models.TrustedIssuer{}).
					Where("iss = ? AND workspace_id = ?", iss, workspaceID).
					Count(&owned).Error; err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
					return
				}
			}
		}
	}
	if owned == 0 {
		c.JSON(http.StatusOK, gin.H{
			"pass":   false,
			"reason": services.ErrUntrustedIssuer.Error(),
		})
		return
	}

	selfIssuer := config.AppConfig.OAuthBaseURL()
	claims, _, err := ctrl.xaaService.ValidateIDJAG(
		c.Request.Context(), body.Assertion, clientID, selfIssuer,
	)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"pass":   false,
			"reason": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"pass":       true,
		"iss":        claims.Issuer,
		"sub":        claims.Subject,
		"client_id":  claims.ClientID,
		"jti":        claims.JTI,
		"issued_at":  claims.IssuedAt,
		"expires_at": claims.ExpiresAt,
	})
}

// Revoke handles DELETE /authsec/trusted-issuers/:id — marks the issuer as
// revoked and bulk-inserts its still-live XAA native tokens into revoked_tokens.
func (ctrl *TrustedIssuersController) Revoke(c *gin.Context) {
	workspaceID, err := shared.ResolveWorkspaceIDFromToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "workspace_id required in JWT"})
		return
	}

	issuerID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "invalid issuer id"})
		return
	}

	ctx := c.Request.Context()
	db := config.DB.WithContext(ctx)

	var issuer models.TrustedIssuer
	// Another workspace's issuer, or a platform issuer, is not found here.
	if err := db.Where("id = ? AND workspace_id = ?", issuerID, workspaceID).First(&issuer).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "message": "trusted issuer not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	if issuer.Status == "revoked" {
		c.JSON(http.StatusOK, gin.H{"status": "revoked"})
		return
	}

	// Bulk-revoke active XAA native tokens from this issuer in a transaction.
	now := time.Now().UTC()
	txErr := db.Transaction(func(tx *gorm.DB) error {
		// Mark issuer revoked.
		if err := tx.Exec(
			`UPDATE trusted_issuers SET status = 'revoked', revoked_at = ? WHERE id = ?`,
			now, issuerID,
		).Error; err != nil {
			return err
		}

		// Bulk-insert live XAA tokens from this issuer into revoked_tokens. The
		// issuer only ever minted into its own workspace, so only that
		// workspace's tokens are touched.
		return tx.Exec(`
			INSERT INTO revoked_tokens (iss, kind, jti, revoked_at, reason, expires_at)
			SELECT iss, 'access_token', jti::text, ?, 'issuer_revoked', expires_at
			FROM native_tokens
			WHERE token_family = 'xaa'
			  AND source_grant_iss = ?
			  AND workspace_id = ?
			  AND revoked_at IS NULL
			  AND expires_at > NOW()
			ON CONFLICT (iss, kind, jti) DO NOTHING`,
			now, issuer.Iss, workspaceID,
		).Error
	})
	if txErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "message": "revocation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}
