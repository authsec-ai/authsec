package shared

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/directory/adldap"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ADInventoryController is the discovery API for the AD inventory adapter.
// Configure and run are discovery:admin. Reading runs, coverage and objects
// is discovery:read. The bind password is never accepted or returned.
type ADInventoryController struct {
	Svc *services.ADInventoryService
}

// NewADInventoryController wires the adapter to the process database and the
// ENVIRONMENT production flag.
func NewADInventoryController(db *gorm.DB) *ADInventoryController {
	return &ADInventoryController{Svc: &services.ADInventoryService{
		DB:         db,
		Production: adProduction,
	}}
}

type inventoryConfigBody struct {
	ConfigID           uuid.UUID `json:"config_id"`
	Server             string    `json:"server"`
	Username           string    `json:"username"`
	UseSSL             *bool     `json:"use_ssl"`
	StartTLS           bool      `json:"start_tls"`
	SkipVerify         bool      `json:"skip_verify"`
	InsecureSkipVerify bool      `json:"insecure_skip_verify"`
	CABundle           *string   `json:"ca_bundle"`
	PageSize           int       `json:"page_size"`
	ChangeTracking     bool      `json:"change_tracking"`
	TrackingMode       string    `json:"tracking_mode"`
	Scopes             []struct {
		BaseDN        string   `json:"base_dn"`
		ObjectClasses []string `json:"object_classes"`
	} `json:"scopes"`
}

// PutConfig replaces approved scopes and the additive connection settings.
func (h *ADInventoryController) PutConfig(c *gin.Context) {
	ws, ok := workspaceFromToken(c)
	if !ok {
		return
	}
	var body inventoryConfigBody
	if err := c.ShouldBindJSON(&body); err != nil || body.ConfigID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config_id and a JSON body are required"})
		return
	}
	existing, err := h.Svc.GetConfig(c.Request.Context(), ws, body.ConfigID)
	if err != nil {
		writeInventoryErr(c, err)
		return
	}
	useSSL := existing.UseSSL
	if body.UseSSL != nil {
		useSSL = *body.UseSSL
	}
	scopes := make([]services.InventoryScope, 0, len(body.Scopes))
	for _, sc := range body.Scopes {
		scopes = append(scopes, services.InventoryScope{BaseDN: sc.BaseDN, ObjectClasses: sc.ObjectClasses, Enabled: true})
	}
	cfg := services.InventoryConfig{
		ConfigID: body.ConfigID, Server: body.Server, Username: body.Username,
		UseSSL: useSSL, StartTLS: body.StartTLS,
		SkipVerify: body.SkipVerify || body.InsecureSkipVerify,
		PageSize:   body.PageSize, ChangeTracking: body.ChangeTracking,
		TrackingMode: body.TrackingMode, Scopes: scopes,
	}
	if body.CABundle != nil {
		cfg.CABundle = *body.CABundle
		cfg.CABundleSet = true
	}
	saved, err := h.Svc.PutConfig(c.Request.Context(), ws, cfg)
	if err != nil {
		writeInventoryErr(c, err)
		return
	}
	middlewares.Audit(c, "ad_inventory", body.ConfigID.String(), "update_config", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"workspace_id":    ws.String(),
			"config_id":       body.ConfigID.String(),
			"scope_count":     len(saved.Scopes),
			"change_tracking": saved.ChangeTracking,
			"skip_verify":     saved.SkipVerify,
		},
	})
	c.JSON(http.StatusOK, saved)
}

// GetConfig returns the inventory settings for one stored AD connection.
func (h *ADInventoryController) GetConfig(c *gin.Context) {
	ws, ok := workspaceFromToken(c)
	if !ok {
		return
	}
	configID, err := uuid.Parse(c.Query("config_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config_id is required"})
		return
	}
	cfg, err := h.Svc.GetConfig(c.Request.Context(), ws, configID)
	if err != nil {
		writeInventoryErr(c, err)
		return
	}
	c.JSON(http.StatusOK, cfg)
}

type inventoryRunBody struct {
	ConfigID uuid.UUID `json:"config_id"`
}

// StartRun executes a scoped inventory read against the stored connection.
func (h *ADInventoryController) StartRun(c *gin.Context) {
	ws, ok := workspaceFromToken(c)
	if !ok {
		return
	}
	var body inventoryRunBody
	if err := c.ShouldBindJSON(&body); err != nil || body.ConfigID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config_id is required"})
		return
	}
	actor := c.GetString("email_id")
	if actor == "" {
		actor = c.GetString("user_id")
	}
	view, err := h.Svc.Run(c.Request.Context(), ws, body.ConfigID, actor)
	if err != nil {
		writeInventoryErr(c, err)
		return
	}
	middlewares.Audit(c, "ad_inventory", view.ID.String(), "start_run", &middlewares.AuditChanges{
		After: map[string]interface{}{
			"workspace_id": ws.String(),
			"config_id":    body.ConfigID.String(),
			"status":       view.Status,
			"objects_seen": view.ObjectsSeen,
		},
	})
	c.JSON(http.StatusOK, view)
}

// GetRun returns one run's status and coverage.
func (h *ADInventoryController) GetRun(c *gin.Context) {
	ws, ok := workspaceFromToken(c)
	if !ok {
		return
	}
	runID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid run id"})
		return
	}
	view, err := h.Svc.GetRun(c.Request.Context(), ws, runID)
	if err != nil {
		writeInventoryErr(c, err)
		return
	}
	c.JSON(http.StatusOK, view)
}

// ListObjects returns a page of sanitized directory objects. Payloads are
// re-read through the allowlisted struct, so a secret attribute does not leave
// the database even if one was planted in a row.
func (h *ADInventoryController) ListObjects(c *gin.Context) {
	ws, ok := workspaceFromToken(c)
	if !ok {
		return
	}
	configID, err := uuid.Parse(c.Query("config_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config_id is required"})
		return
	}
	limit, _ := strconv.Atoi(c.Query("limit"))
	offset, _ := strconv.Atoi(c.Query("offset"))
	page, err := h.Svc.ListObjects(c.Request.Context(), ws, configID, limit, offset)
	if err != nil {
		writeInventoryErr(c, err)
		return
	}
	c.JSON(http.StatusOK, page)
}

func workspaceFromToken(c *gin.Context) (uuid.UUID, bool) {
	raw := strings.TrimSpace(c.GetString("workspace_id"))
	id, err := uuid.Parse(raw)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "workspace_id is required"})
		return uuid.Nil, false
	}
	return id, true
}

func writeInventoryErr(c *gin.Context, err error) {
	msg := err.Error()
	switch {
	case errors.Is(err, adldap.ErrSkipVerifyRefused):
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
	case errors.Is(err, gorm.ErrRecordNotFound) || strings.Contains(msg, "not found"):
		c.JSON(http.StatusNotFound, gin.H{"error": msg})
	case strings.Contains(msg, "no administrator-approved"),
		strings.Contains(msg, "tracking_mode"),
		strings.Contains(msg, "disabled"),
		strings.Contains(msg, "base DN"):
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
	}
}

func adProduction() bool {
	return config.AppConfig != nil && strings.EqualFold(config.AppConfig.Environment, "production")
}
