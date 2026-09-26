package platform

import "github.com/gin-gonic/gin"

// Runtime reads (TRD 2 S12b). Each is iga:read, behind the graph gate.
// runtime-policy-status is not_configured until A6.

func (ctl *IGAGraphReadController) GetRuntimeInstances(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.RuntimeInstances(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}

func (ctl *IGAGraphReadController) GetObservedAccess(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.ObservedAccess(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}

func (ctl *IGAGraphReadController) GetRuntimePolicyStatus(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.RuntimePolicyStatus(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}

func (ctl *IGAGraphReadController) GetObservedUse(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.ObservedUse(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}
