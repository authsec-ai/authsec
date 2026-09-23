package platform

import "github.com/gin-gonic/gin"

// Workload detail and tabs (§5.3 Agents & workloads, T6.3):
//
//	GET /api/iga/v1/workloads/:id              the list row plus continuity,
//	                                           provider_attrs, sources and the
//	                                           latest classification decision
//	GET /api/iga/v1/workloads/:id/identities   execution / other / groups /
//	                                           may_assume, each section paged
//	GET /api/iga/v1/workloads/:id/resources    one row per target, one line
//	                                           per grant, paged by resource
//
// internal/igaread owns the reads -- parameters, the snapshot, cursors,
// coverage -- and every query behind them. serve() has already applied the
// 503 gate and taken the workspace from the token; the route id is checked
// against THIS workspace inside the snapshot, and anything else is 404.

// GetWorkload handles GET /api/iga/v1/workloads/:id.
//
// meta.capabilities.can_classify (D-83) is decided here, after the snapshot:
// it needs the caller's session (the verified-human rule and iga:review, by
// the same tests the classification POST applies), which igaread does not
// see, over the classification and lifecycle the snapshot read. It is always
// stated; a database error while checking membership is the request's 500,
// never a false or a true.
func (ctl *IGAGraphReadController) GetWorkload(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		d, err := g.Reader.WorkloadDetail(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
		if err != nil {
			return nil, err
		}
		can, err := ctl.classificationCapability(g.C, g.WS, d.Classification(), d.Lifecycle())
		if err != nil {
			return nil, err
		}
		d.SetCanClassify(can)
		return d, nil
	})
}

// GetWorkloadIdentities handles GET /api/iga/v1/workloads/:id/identities.
func (ctl *IGAGraphReadController) GetWorkloadIdentities(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.WorkloadIdentities(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}

// GetWorkloadResources handles GET /api/iga/v1/workloads/:id/resources.
func (ctl *IGAGraphReadController) GetWorkloadResources(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.WorkloadResources(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}
