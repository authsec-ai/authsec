package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CollectorController serves TRD 2 enrollment and collector administration.
// Credential plaintext is returned only from the issue, enroll and rotate
// responses. Read responses are built from CollectorView, which has no secret fields.
type CollectorController struct {
	svc *services.CollectorEnrollmentService
}

// NewCollectorController constructs the controller.
func NewCollectorController(svc *services.CollectorEnrollmentService) *CollectorController {
	return &CollectorController{svc: svc}
}

// Now is the service clock, shared with the collector middleware.
func (ctl *CollectorController) Now() time.Time { return ctl.svc.Now() }

func (ctl *CollectorController) workspace(c *gin.Context) (uuid.UUID, bool) {
	raw := c.GetString("workspace_id")
	id, err := uuid.Parse(raw)
	if err != nil || raw == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return uuid.Nil, false
	}
	return id, true
}

func writeCollectorErr(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrCollectorUnauthorized),
		errors.Is(err, services.ErrCollectorExpired),
		errors.Is(err, services.ErrCollectorUsed):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	case errors.Is(err, services.ErrCollectorConflict),
		errors.Is(err, services.ErrCollectorKind),
		errors.Is(err, services.ErrCollectorScope):
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	case errors.Is(err, services.ErrCollectorVersion):
		c.JSON(http.StatusConflict, gin.H{"error": "conflict"})
	case errors.Is(err, services.ErrCollectorNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	case errors.Is(err, services.ErrCollectorInvalid):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid"})
	default:
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "payload_too_large"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
	}
}

func bindJSON(c *gin.Context, dst any) bool {
	dec := json.NewDecoder(c.Request.Body)
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			writeCollectorErr(c, services.ErrCollectorInvalid)
			return false
		}
		var syn *json.SyntaxError
		var typ *json.UnmarshalTypeError
		if errors.As(err, &syn) || errors.As(err, &typ) {
			writeCollectorErr(c, fmt.Errorf("%w: %v", services.ErrCollectorInvalid, err))
			return false
		}
		writeCollectorErr(c, err)
		return false
	}
	return true
}

// CreateEnrollment handles POST /api/iga/v2/collector-enrollments.
func (ctl *CollectorController) CreateEnrollment(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	var body struct {
		Kind        string `json:"kind"`
		EstateScope struct {
			Kind        string `json:"kind"`
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
		} `json:"estate_scope"`
		NamespaceAllowlist []string        `json:"namespace_allowlist"`
		CapabilityCeiling  json.RawMessage `json:"capability_ceiling"`
		ExpiresInSeconds   int             `json:"expires_in_seconds"`
	}
	if !bindJSON(c, &body) {
		return
	}
	var estateID *uuid.UUID
	if body.EstateScope.ID != "" {
		id, err := uuid.Parse(body.EstateScope.ID)
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid"})
			return
		}
		estateID = &id
	}
	issued, err := ctl.svc.IssueEnrollment(ws, services.IssueEnrollmentInput{
		Kind: body.Kind, EstateScopeKind: body.EstateScope.Kind, EstateScopeID: estateID,
		EstateDisplayName: body.EstateScope.DisplayName, Namespaces: body.NamespaceAllowlist,
		CapabilityCeiling: body.CapabilityCeiling,
		ExpiresIn:         time.Duration(body.ExpiresInSeconds) * time.Second,
		CreatedBy:         c.GetString("client_id"),
	})
	if err != nil {
		writeCollectorErr(c, err)
		return
	}
	c.JSON(http.StatusCreated, issued)
}

// Enroll handles POST /api/iga/v2/collectors/enroll.
func (ctl *CollectorController) Enroll(c *gin.Context) {
	en := middlewares.EnrollmentFrom(c)
	if en == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var body struct {
		InstallationPublicKey string         `json:"installation_public_key"`
		InstallationNonce     string         `json:"installation_nonce"`
		Kind                  string         `json:"kind"`
		Version               string         `json:"version"`
		NativeHints           map[string]any `json:"native_hints"`
		WorkspaceID           string         `json:"workspace_id"`
		EstateID              string         `json:"estate_id"`
		HostID                string         `json:"host_id"`
	}
	if !bindJSON(c, &body) {
		return
	}
	in := services.EnrollInput{
		EnrollmentID: en.ID, PublicKeyB64: body.InstallationPublicKey,
		Nonce: body.InstallationNonce, Kind: body.Kind, Version: body.Version,
		NativeHints: body.NativeHints, HostID: body.HostID,
	}
	if body.WorkspaceID != "" {
		id, err := uuid.Parse(body.WorkspaceID)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		in.WorkspaceID = &id
	}
	if body.EstateID != "" {
		id, err := uuid.Parse(body.EstateID)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		in.EstateID = &id
	}
	result, err := ctl.svc.Enroll(in)
	if err != nil {
		writeCollectorErr(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// Rotate handles POST /api/iga/v2/collectors/self/credentials/rotate.
func (ctl *CollectorController) Rotate(c *gin.Context) {
	p := middlewares.CollectorFrom(c)
	if p == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var body struct {
		Nonce        string   `json:"nonce"`
		RequestedAt  string   `json:"requested_at"`
		NewPublicKey string   `json:"new_public_key"`
		Signature    string   `json:"signature"`
		Scopes       []string `json:"scopes"`
		WorkspaceID  string   `json:"workspace_id"`
		HostID       string   `json:"host_id"`
		EstateID     string   `json:"estate_id"`
	}
	if !bindJSON(c, &body) {
		return
	}
	if body.HostID != "" || (body.WorkspaceID != "" && body.WorkspaceID != p.WorkspaceID.String()) ||
		(body.EstateID != "" && body.EstateID != p.EstateScopeID.String()) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	at, err := time.Parse(time.RFC3339, body.RequestedAt)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid"})
		return
	}
	result, err := ctl.svc.Rotate(services.RotateInput{
		WorkspaceID: p.WorkspaceID, CollectorID: p.CollectorID, CredentialID: p.CredentialID,
		CurrentScopes: p.Scopes, Nonce: body.Nonce, RequestedAt: at, RequestedAtRaw: body.RequestedAt,
		NewPublicKey: body.NewPublicKey, Signature: body.Signature, Scopes: body.Scopes,
	})
	if err != nil {
		writeCollectorErr(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// Revoke handles POST /api/iga/v2/collectors/:id/revoke.
func (ctl *CollectorController) Revoke(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	var body struct {
		Reason          string `json:"reason"`
		ExpectedVersion int64  `json:"expected_version"`
	}
	if !bindJSON(c, &body) {
		return
	}
	if err := ctl.svc.Revoke(ws, id, body.ExpectedVersion, body.Reason); err != nil {
		writeCollectorErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// Get handles GET /api/iga/v2/collectors/:id.
func (ctl *CollectorController) Get(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	view, err := ctl.svc.Get(ws, id)
	if err != nil {
		writeCollectorErr(c, err)
		return
	}
	c.JSON(http.StatusOK, view)
}

// GetSelf handles GET /api/iga/v2/collectors/self. Requires policy_read.
func (ctl *CollectorController) GetSelf(c *gin.Context) {
	p := middlewares.CollectorFrom(c)
	if p == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	view, err := ctl.svc.Get(p.WorkspaceID, p.CollectorID)
	if err != nil {
		writeCollectorErr(c, err)
		return
	}
	c.JSON(http.StatusOK, view)
}

// SetLegacyIngress handles PUT /authsec/discovery/settings/legacy-ingress.
func (ctl *CollectorController) SetLegacyIngress(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	var body struct {
		Disabled bool `json:"disabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil && !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid"})
		return
	}
	if err := ctl.svc.SetLegacyIngress(ws, body.Disabled, c.GetString("client_id")); err != nil {
		writeCollectorErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"legacy_discovery_ingress_disabled": body.Disabled})
}
