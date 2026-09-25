package platform

import "github.com/gin-gonic/gin"

// Evidence and limitations (§5.3 Evidence, T6.5; D-20..D-24, D-79, D-80).
//
// The handler only hands the query string to internal/igaread, which owns the
// claim parsing, the snapshot, the facts, freshness and the limitations
// vocabulary. serve() has already applied the 503 gate and taken the
// workspace from the token; the query string never names a workspace.

// GetEvidence handles GET /api/iga/v1/evidence?claim=<claim or object ref>
// [&claim=...][&include=raw][&rev=N]: why the product claims this -- the
// claim's sentence, its four status dimensions, the supporting facts,
// freshness and limitations; the stored observation records only with
// include=raw.
func (ctl *IGAGraphReadController) GetEvidence(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.Evidence(g.C.Request.Context(), g.WS, g.C.Request.URL.Query())
	})
}
