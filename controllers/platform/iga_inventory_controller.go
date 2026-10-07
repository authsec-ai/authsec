package platform

import "github.com/gin-gonic/gin"

// The unified inventory (unified-discovery CONTRACT, "The API"):
//
//	GET /api/iga/v1/inventory/workloads
//	GET /api/iga/v1/inventory/identities
//	GET /api/iga/v1/inventory/resources
//	GET /api/iga/v1/inventory/summary
//
// Every workload, identity and resource AWS, Kubernetes and GitHub put in the
// shared iga_* tables, in one provider-neutral row. internal/igaread owns the
// reads (inventory.go): parameters, the snapshot, cursors, totals and facets.
//
// The routes are served by the graph read controller, so they share its
// contract exactly: 503 graph_unavailable unless IGA_GRAPH_PROJECTION is on
// and verified, the workspace only from the token, and every error in the
// §5.2 envelope. They are mounted on their own /api/iga/v1 group with the same
// GraphEnvelope / GraphRequire wrapping as the graph catalogue, and are not in
// RegisterIGAGraphReadRoutes: that table is the frozen §5.3 catalogue its
// contract tests enumerate.

// MountIGAInventoryRoutes mounts the inventory on its own /api/iga/v1 group
// of r, behind auth, with each route's permission middleware built by
// require, both wrapped by GraphEnvelope -- as MountIGAGraphReadRoutes mounts
// the graph catalogue. Production calls it from routes.SetupIGARoutes.
func MountIGAInventoryRoutes(r gin.IRouter, ctl *IGAGraphReadController, auth gin.HandlerFunc, require func(resource, action string) gin.HandlerFunc) {
	g := r.Group("/api/iga/v1")
	g.Use(GraphEnvelope(auth))
	RegisterIGAInventoryRoutes(g, ctl, GraphRequire(require))
}

// RegisterIGAInventoryRoutes mounts the inventory routes on an authenticated
// /api/iga/v1 group. Every one needs iga:read; no new permission.
func RegisterIGAInventoryRoutes(g gin.IRoutes, ctl *IGAGraphReadController, require func(resource, action string) gin.HandlerFunc) {
	read := require("iga", "read")
	g.GET("/inventory/workloads", read, ctl.ListInventoryWorkloads)
	g.GET("/inventory/identities", read, ctl.ListInventoryIdentities)
	g.GET("/inventory/resources", read, ctl.ListInventoryResources)
	g.GET("/inventory/summary", read, ctl.GetInventorySummary)
}

// ListInventoryWorkloads handles GET /api/iga/v1/inventory/workloads.
func (ctl *IGAGraphReadController) ListInventoryWorkloads(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.ListInventoryWorkloads(g.C.Request.Context(), g.C.Request.URL.Query())
	})
}

// ListInventoryIdentities handles GET /api/iga/v1/inventory/identities.
func (ctl *IGAGraphReadController) ListInventoryIdentities(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.ListInventoryIdentities(g.C.Request.Context(), g.C.Request.URL.Query())
	})
}

// ListInventoryResources handles GET /api/iga/v1/inventory/resources.
func (ctl *IGAGraphReadController) ListInventoryResources(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.ListInventoryResources(g.C.Request.Context(), g.C.Request.URL.Query())
	})
}

// GetInventorySummary handles GET /api/iga/v1/inventory/summary: one count per
// object type for the same filters as the three lists.
func (ctl *IGAGraphReadController) GetInventorySummary(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.InventorySummary(g.C.Request.Context(), g.C.Request.URL.Query())
	})
}
