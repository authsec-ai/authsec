package platform

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/authsec-ai/authsec/config"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// IGAGraphReadController serves the Phase 2 graph reads under /api/iga/v1
// (SPEC-iga-phase2-graph.md §5.3). M0 ships only /capabilities; the rest of
// the catalogue is M1 (T2.3, T6.x).
type IGAGraphReadController struct {
	gate func() *services.GraphProjectionGate
}

// NewIGAGraphReadController reads the process-wide projection gate on every
// request, so a gate verified after startup is reported as soon as it is.
func NewIGAGraphReadController() *IGAGraphReadController {
	return &IGAGraphReadController{gate: services.GraphProjection}
}

// graphFeatures is what THIS build serves. Every value is false until the
// route exists: the console hides a feature it is told is unavailable, and a
// feature reported available with no route behind it would render as empty
// rather than as unavailable -- which §2.14.7 forbids.
func graphFeatures() gin.H {
	return gin.H{
		"workloads": false, "identities": false, "resources": false,
		"graph": false, "evidence": false, "changes": false,
		"classification": false, "coverage": false,
	}
}

// GetCapabilities handles GET /api/iga/v1/capabilities (§5.3): what this
// deployment supports. Any authenticated caller; no permission beyond a token.
//
// graph_projection is on | off | misconfigured, with the reason when it is
// not on. "misconfigured" is the fail-closed state (§2.8): the switch is on and
// schema verification failed or errored, so the scan worker claims nothing and
// the projector is not running.
func (ctl *IGAGraphReadController) GetCapabilities(c *gin.Context) {
	mode, reason, head := ctl.gate().Status()
	if head == "" && config.DB != nil {
		// Off, or never verified: report the migration head we can see, so an
		// operator can tell "off" from "on against an old schema".
		if h, err := repositories.MigrationHead(config.DB); err == nil && h > 0 {
			head = fmt.Sprintf("%03d", h)
		}
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{
		"graph_projection": mode,
		"reason":           nullIfEmpty(reason),
		"features":         graphFeatures(),
		"schema_head":      nullIfEmpty(head),
	}})
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
