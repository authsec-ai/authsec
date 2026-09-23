package platform

import "github.com/gin-gonic/gin"

// Changes (§5.3 Changes, T5.4 read side).
//
// STUB: every handler answers 501 until its task lands. Replace this file whole.

func (ctl *IGAGraphReadController) GetWorkloadChanges(c *gin.Context) { ctl.notYet(c) }
func (ctl *IGAGraphReadController) GetIdentityChanges(c *gin.Context) { ctl.notYet(c) }
func (ctl *IGAGraphReadController) GetResourceChanges(c *gin.Context) { ctl.notYet(c) }
