package platform

import "github.com/gin-gonic/gin"

// Workload detail and tabs (§5.3 Agents & workloads, T6.3).
//
// STUB: every handler answers 501 until its task lands. Replace this file whole.

func (ctl *IGAGraphReadController) GetWorkload(c *gin.Context)           { ctl.notYet(c) }
func (ctl *IGAGraphReadController) GetWorkloadIdentities(c *gin.Context) { ctl.notYet(c) }
func (ctl *IGAGraphReadController) GetWorkloadResources(c *gin.Context)  { ctl.notYet(c) }
