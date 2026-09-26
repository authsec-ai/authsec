package platform

import "github.com/gin-gonic/gin"

// RegisterIGAGraphReadRoutes mounts the §5.3 graph catalogue on the
// authenticated /api/iga/v1 group. require builds the permission middleware
// (middlewares.Require in production); tests pass a recorder, so the
// permission each route demands is asserted against this one table rather
// than a copy of it (T6.7).
//
// Every read needs iga:read; a classification DECISION needs iga:review (and a
// verified human, checked in the handler); /capabilities needs only a token.
// No new permission is introduced (§5.3).
func RegisterIGAGraphReadRoutes(g gin.IRoutes, ctl *IGAGraphReadController, require func(resource, action string) gin.HandlerFunc) {
	read := require("iga", "read")

	g.GET("/capabilities", ctl.GetCapabilities)
	g.GET("/pipeline", read, ctl.GetPipeline)
	g.GET("/coverage", read, ctl.GetCoverage)

	g.GET("/workloads", read, ctl.ListWorkloads)
	g.GET("/workloads/:id", read, ctl.GetWorkload)
	g.GET("/workloads/:id/identities", read, ctl.GetWorkloadIdentities)
	g.GET("/workloads/:id/resources", read, ctl.GetWorkloadResources)
	g.GET("/workloads/:id/changes", read, ctl.GetWorkloadChanges)
	g.POST("/workloads/:id/classification", require("iga", "review"), ctl.ClassifyWorkload)
	g.POST("/workloads/:id/agent-registration", require("discovery", "claim"), ctl.RegisterWorkloadAgent)
	g.GET("/workloads/:id/classification", read, ctl.GetWorkloadClassification)

	g.GET("/identities", read, ctl.ListIdentities)
	g.GET("/identities/:id", read, ctl.GetIdentity)
	g.GET("/identities/:id/used-by", read, ctl.GetIdentityUsedBy)
	g.GET("/identities/:id/permissions", read, ctl.GetIdentityPermissions)
	g.GET("/identities/:id/changes", read, ctl.GetIdentityChanges)

	g.GET("/external-principals/:id", read, ctl.GetExternalPrincipal)
	g.GET("/external-principals/:id/referenced-by", read, ctl.GetExternalPrincipalReferencedBy)

	g.GET("/resources", read, ctl.ListResources)
	g.GET("/resources/:id", read, ctl.GetResource)
	g.GET("/resources/:id/access", read, ctl.GetResourceAccess)
	g.GET("/resources/:id/changes", read, ctl.GetResourceChanges)

	g.GET("/graph", read, ctl.GetGraph)
	g.GET("/graph/expand", read, ctl.ExpandGraph)
	g.GET("/graph/path", read, ctl.GetGraphPath)
	g.GET("/evidence", read, ctl.GetEvidence)
	g.GET("/lookup", read, ctl.Lookup)
}
