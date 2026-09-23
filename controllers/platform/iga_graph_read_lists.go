package platform

import "github.com/gin-gonic/gin"

// Lists (§5.3): GET /workloads, /identities, /resources, and /lookup (T6.2, T6.8).
//
// STUB: every handler answers 501 until its task lands. Replace this file whole.

func (ctl *IGAGraphReadController) ListWorkloads(c *gin.Context)  { ctl.notYet(c) }
func (ctl *IGAGraphReadController) ListIdentities(c *gin.Context) { ctl.notYet(c) }
func (ctl *IGAGraphReadController) ListResources(c *gin.Context)  { ctl.notYet(c) }
func (ctl *IGAGraphReadController) Lookup(c *gin.Context)         { ctl.notYet(c) }
