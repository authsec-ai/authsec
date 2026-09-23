package platform

import "github.com/gin-gonic/gin"

// Identity and external-principal detail and tabs (§5.3 Identities, External principals, T6.3).
//
// STUB: every handler answers 501 until its task lands. Replace this file whole.

func (ctl *IGAGraphReadController) GetIdentity(c *gin.Context)                      { ctl.notYet(c) }
func (ctl *IGAGraphReadController) GetIdentityUsedBy(c *gin.Context)                { ctl.notYet(c) }
func (ctl *IGAGraphReadController) GetIdentityPermissions(c *gin.Context)           { ctl.notYet(c) }
func (ctl *IGAGraphReadController) GetExternalPrincipal(c *gin.Context)             { ctl.notYet(c) }
func (ctl *IGAGraphReadController) GetExternalPrincipalReferencedBy(c *gin.Context) { ctl.notYet(c) }
