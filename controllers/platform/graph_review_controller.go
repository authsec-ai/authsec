package platform

import (
	"errors"
	"net/http"

	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
)

// GraphReviewController serves the graph-review surface under /api/iga/v2.
//
// A graph review records a governance decision (attest, remediate, reject)
// against a specific entity at a specific graph revision. It is the audit
// record that proves a human looked at a graph diff and acted on it.
type GraphReviewController struct {
	svc *services.GraphReviewService
}

// NewGraphReviewController constructs the controller.
func NewGraphReviewController(svc *services.GraphReviewService) *GraphReviewController {
	return &GraphReviewController{svc: svc}
}

// workspace resolves the caller's workspace from the token. Never from the body.
func (ctl *GraphReviewController) workspace(c *gin.Context) (string, bool) {
	raw := c.GetString("workspace_id")
	if raw == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return "", false
	}
	return raw, true
}

// graphReviewError maps a service error to the right HTTP status.
func graphReviewError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrGraphReviewNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
	case errors.Is(err, services.ErrInvalidDecision):
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal"})
	}
}

// CreateGraphReview handles POST /api/iga/v2/graph-reviews.
func (ctl *GraphReviewController) CreateGraphReview(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	var body services.CreateGraphReviewInput
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// The decided_by identity comes from the token, not the body.
	decidedBy := c.GetString("user_id")
	out, err := ctl.svc.Create(c.Request.Context(), ws, decidedBy, body)
	if err != nil {
		graphReviewError(c, err)
		return
	}
	c.JSON(http.StatusCreated, out)
}

// GetGraphReview handles GET /api/iga/v2/graph-reviews/:id.
func (ctl *GraphReviewController) GetGraphReview(c *gin.Context) {
	ws, ok := ctl.workspace(c)
	if !ok {
		return
	}
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing id"})
		return
	}
	out, err := ctl.svc.Get(c.Request.Context(), ws, id)
	if err != nil {
		graphReviewError(c, err)
		return
	}
	c.JSON(http.StatusOK, out)
}
