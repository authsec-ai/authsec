package platform

import "github.com/gin-gonic/gin"

// Pipeline and coverage (§5.3 Integration, scan and pipeline, T2.3).
//
// STUB: every handler answers 501 until its task lands. Replace this file whole.

func (ctl *IGAGraphReadController) GetPipeline(c *gin.Context) { ctl.notYet(c) }
func (ctl *IGAGraphReadController) GetCoverage(c *gin.Context) { ctl.notYet(c) }
