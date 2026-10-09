package platform

import "github.com/gin-gonic/gin"

// Traversal (§5.3 Graph, §5.4, T6.4): GET /graph, /graph/expand and
// /graph/path.
//
// The handlers only hand the request's query string to internal/igaread,
// which owns §5.4 -- parameters, the snapshot, the per-level queries, the
// budgets, the time reserve and the continuation -- and every query behind
// it. serve() has already applied the 503 gate and taken the workspace from
// the token; the query string never names a workspace.

// GetGraph handles GET /api/iga/v1/graph?root=<ref>&direction=forward|reverse&assume_hops=N.
func (ctl *IGAGraphReadController) GetGraph(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.Graph(g.C.Request.Context(), g.WS, g.C.Request.URL.Query())
	})
}

// ExpandGraph handles GET /api/iga/v1/graph/expand?node=<ref>&edge=<kind>&direction=...&cursor=.
func (ctl *IGAGraphReadController) ExpandGraph(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.ExpandGraph(g.C.Request.Context(), g.WS, g.C.Request.URL.Query())
	})
}

// GetGraphPath handles GET /api/iga/v1/graph/path?from=<ref>&to=<ref>.
func (ctl *IGAGraphReadController) GetGraphPath(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.GraphPath(g.C.Request.Context(), g.WS, g.C.Request.URL.Query())
	})
}
