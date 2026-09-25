package platform

import "github.com/gin-gonic/gin"

// Identity and external-principal detail and tabs (§5.3 Identities, External
// principals, T6.3):
//
//	GET /identities/:id                      the identity's Overview
//	GET /identities/:id/used-by              workloads, principals, members
//	GET /identities/:id/permissions          policies, boundary, inherited, activity
//	GET /external-principals/:id             the far end of a trust
//	GET /external-principals/:id/referenced-by  the can_assume edges from it
//
// The handlers only hand the route id and the query string to
// internal/igaread, which owns the contract -- parameters (400), the §5.1
// snapshot, the 404 rules (D-4..D-6), cursors, and every query behind it.
// serve() has already applied the 503 gate and taken the workspace from the
// token; neither the id nor the query string ever names a workspace.

// GetIdentity handles GET /api/iga/v1/identities/:id.
func (ctl *IGAGraphReadController) GetIdentity(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.GetIdentity(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}

// GetIdentityUsedBy handles GET /api/iga/v1/identities/:id/used-by.
func (ctl *IGAGraphReadController) GetIdentityUsedBy(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.IdentityUsedBy(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}

// GetIdentityPermissions handles GET /api/iga/v1/identities/:id/permissions.
func (ctl *IGAGraphReadController) GetIdentityPermissions(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.IdentityPermissions(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}

// GetExternalPrincipal handles GET /api/iga/v1/external-principals/:id.
func (ctl *IGAGraphReadController) GetExternalPrincipal(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.GetExternalPrincipal(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}

// GetExternalPrincipalReferencedBy handles
// GET /api/iga/v1/external-principals/:id/referenced-by.
func (ctl *IGAGraphReadController) GetExternalPrincipalReferencedBy(c *gin.Context) {
	ctl.serve(c, func(g graphCall) (any, error) {
		return g.Reader.ExternalPrincipalReferencedBy(g.C.Request.Context(), g.WS, g.C.Param("id"), g.C.Request.URL.Query())
	})
}
