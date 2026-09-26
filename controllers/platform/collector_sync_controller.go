package platform

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/pkg/collectorcontract"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CollectorSyncController serves POST /api/iga/v2/agent-sync and receipt lookup.
// Authentication has already run. This type owns decompression and the size caps.
type CollectorSyncController struct {
	svc *services.CollectorSyncService
}

// NewCollectorSyncController constructs the controller.
func NewCollectorSyncController(svc *services.CollectorSyncService) *CollectorSyncController {
	return &CollectorSyncController{svc: svc}
}

// Service returns the ingest service so tests can set quota and failure hooks.
func (ctl *CollectorSyncController) Service() *services.CollectorSyncService { return ctl.svc }

// AgentSync handles POST /api/iga/v2/agent-sync.
func (ctl *CollectorSyncController) AgentSync(c *gin.Context) {
	p := middlewares.CollectorFrom(c)
	if p == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	raw, err := readSyncBody(c)
	if err != nil {
		writeSyncErr(c, err)
		return
	}
	body, err := ctl.svc.Accept(p, raw)
	if err != nil {
		writeSyncErr(c, err)
		return
	}
	c.Data(http.StatusOK, "application/json", body)
}

// GetReceipt handles GET /api/iga/v2/receipts/:id.
func (ctl *CollectorSyncController) GetReceipt(c *gin.Context) {
	p := middlewares.CollectorFrom(c)
	if p == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	body, err := ctl.svc.Receipt(p, id)
	if err != nil {
		writeSyncErr(c, err)
		return
	}
	c.Data(http.StatusOK, "application/json", body)
}

// AuthorizeEpoch handles POST /api/iga/v2/collectors/:id/epoch.
func (ctl *CollectorSyncController) AuthorizeEpoch(c *gin.Context) {
	ws, ok := collectorWorkspace(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	var body struct {
		AuthorizedNextEpoch string `json:"authorized_next_epoch"`
		ExpectedVersion     int64  `json:"expected_version"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid"})
		return
	}
	next, err := uuid.Parse(body.AuthorizedNextEpoch)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid"})
		return
	}
	version, err := ctl.svc.AuthorizeEpoch(ws, id, body.ExpectedVersion, next)
	if err != nil {
		writeCollectorErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"authorized_next_epoch": next, "row_version": version})
}

func collectorWorkspace(c *gin.Context) (uuid.UUID, bool) {
	raw := c.GetString("workspace_id")
	id, err := uuid.Parse(raw)
	if err != nil || raw == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return uuid.Nil, false
	}
	return id, true
}

func readSyncBody(c *gin.Context) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(c.GetHeader("Content-Encoding")))
	switch enc {
	case "", "identity":
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, collectorcontract.DecompressedMaxBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(body)) > collectorcontract.DecompressedMaxBytes {
			return nil, errSyncTooLarge
		}
		return body, nil
	case "gzip":
		if c.Request.ContentLength > collectorcontract.CompressedMaxBytes {
			return nil, errSyncTooLarge
		}
		compressed, err := io.ReadAll(io.LimitReader(c.Request.Body, collectorcontract.CompressedMaxBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(compressed)) > collectorcontract.CompressedMaxBytes {
			return nil, errSyncTooLarge
		}
		zr, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, &collectorcontract.ContractError{Kind: "invalid", Fields: []collectorcontract.FieldError{{
				Path: "$", Message: "gzip body is not valid",
			}}}
		}
		defer func() { _ = zr.Close() }()
		plain, err := io.ReadAll(io.LimitReader(zr, collectorcontract.DecompressedMaxBytes+1))
		if err != nil {
			return nil, &collectorcontract.ContractError{Kind: "invalid", Fields: []collectorcontract.FieldError{{
				Path: "$", Message: "gzip body is not valid",
			}}}
		}
		if int64(len(plain)) > collectorcontract.DecompressedMaxBytes {
			return nil, errSyncTooLarge
		}
		return plain, nil
	default:
		return nil, &collectorcontract.ContractError{Kind: "invalid", Fields: []collectorcontract.FieldError{{
			Path: "content-encoding", Message: "unsupported content encoding",
		}}}
	}
}

var errSyncTooLarge = errors.New("sync payload too large")

func writeSyncErr(c *gin.Context, err error) {
	var quota *services.QuotaError
	if errors.As(err, &quota) {
		c.Header("Retry-After", "1")
		if quota.RetryAfter > 1 {
			c.Header("Retry-After", itoaHeader(quota.RetryAfter))
		}
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
		return
	}
	var contract *collectorcontract.ContractError
	if errors.As(err, &contract) {
		if contract.Kind == "upgrade" {
			c.JSON(http.StatusUpgradeRequired, gin.H{
				"error": "upgrade_required", "supported_versions": contract.Supported,
			})
			return
		}
		if contract.Kind == "forbidden" {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid", "fields": contract.Fields})
		return
	}
	switch {
	case errors.Is(err, errSyncTooLarge):
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "payload_too_large"})
	case errors.Is(err, services.ErrSyncForbidden):
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	case errors.Is(err, services.ErrSyncConflict):
		c.JSON(http.StatusConflict, gin.H{"error": "conflict"})
	case errors.Is(err, services.ErrSyncNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	case errors.Is(err, services.ErrSyncUnavailable):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "unavailable"})
	default:
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "payload_too_large"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
	}
}

func itoaHeader(n int) string {
	if n < 1 {
		return "1"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
