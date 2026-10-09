package platform

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/authsec-ai/authsec/services"
)

// The §7.8 metrics route (T3.18), under the gated /api/iga/v1/policy group:
//
//	GET /metrics?from&to&cursor&limit   governance:read
//
// The token's workspace's hourly rows from iga_gov_metrics_hourly (§8.12)
// whose hour starts in [from, to) (RFC 3339; default the last 24 hours),
// oldest first, cursor-paged (limit <= 200). meta.summary is the range's
// headline: the latest row's posture (with posture_as_of), the changes
// summed over the range (reversed exclusions subtracted), missing hours
// reported as missing (never as zeros), and the routes that remain for
// every service excluded with a known route now, named. Read-only: no
// event, no audit row.
func (ctl *IGAGovPolicyController) GetMetrics(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	limit, err := limitParam(c)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	from, to, err := services.ParseGovMetricsRange(c.Query("from"), c.Query("to"), time.Now())
	if err != nil {
		govErrorOut(c, err)
		return
	}
	page, err := services.NewGovMetrics(ctl.db(), ctl.key).List(c.Request.Context(), ws, from, to, c.Query("cursor"), limit)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": page.Rows, "meta": gin.H{"next_cursor": page.NextCursor, "from": from, "to": to,
		"summary": page.Summary}})
}
