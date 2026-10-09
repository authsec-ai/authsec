package platform

import "github.com/gin-gonic/gin"

// Resource detail and Access (§5.3 Resources, T6.3): GET /resources/:id and
// GET /resources/:id/access. GET /resources/:id/changes is the Changes task's
// (iga_graph_read_changes.go).
//
// The handlers hand the route id and the query string to internal/igaread,
// which owns the §5.1 snapshot, the 404 rules (D-4, D-5, D-6), the cursor and
// every query behind both routes. serve() has already applied the 503 gate and
// taken the workspace from the token; neither the id nor the query string ever
// names a workspace.

// GetResource handles GET /api/iga/v1/resources/:id.
func (ctl *IGAGraphReadController) GetResource(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.ResourceDetail(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}

// GetResourceAccess handles GET /api/iga/v1/resources/:id/access.
func (ctl *IGAGraphReadController) GetResourceAccess(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.ResourceAccess(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}
