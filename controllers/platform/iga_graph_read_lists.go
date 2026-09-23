package platform

import "github.com/gin-gonic/gin"

// Lists (§5.3): GET /workloads, /identities, /resources (T6.2), and /lookup
// (T6.8).
//
// The handlers only hand the request's query string to internal/igaread,
// which owns the §5.2 list contract -- parameters, the snapshot, cursors,
// totals, facets and coverage -- and every query behind it. serve() has
// already applied the 503 gate and taken the workspace from the token; the
// query string never names a workspace.

// ListWorkloads handles GET /api/iga/v1/workloads.
func (ctl *IGAGraphReadController) ListWorkloads(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.ListWorkloads(g.C.Request.Context(), g.WS, g.C.Request.URL.Query())
	})
}

// ListIdentities handles GET /api/iga/v1/identities.
func (ctl *IGAGraphReadController) ListIdentities(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.ListIdentities(g.C.Request.Context(), g.WS, g.C.Request.URL.Query())
	})
}

// ListResources handles GET /api/iga/v1/resources.
func (ctl *IGAGraphReadController) ListResources(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.ListResources(g.C.Request.Context(), g.WS, g.C.Request.URL.Query())
	})
}

// Lookup handles GET /api/iga/v1/lookup?cloud_ref=cloud_identity:<id>|cloud_workload:<id>.
func (ctl *IGAGraphReadController) Lookup(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.Lookup(g.C.Request.Context(), g.WS, g.C.Request.URL.Query())
	})
}
