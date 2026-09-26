package routes

import (
	platformCtrl "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// MountRuntimePolicy registers /api/iga/v2/runtime-policies when IGA_V2_POLICY
// is on. When the flag is off the routes are not registered, so a request is
// 404 and nothing is evaluated. auth is the existing user middleware.
func MountRuntimePolicy(r gin.IRouter, db *gorm.DB, auth gin.HandlerFunc) {
	if r == nil || db == nil || auth == nil || !services.V2PolicyEnabled() {
		return
	}
	ctl := platformCtrl.NewRuntimePolicyController(services.NewRuntimePolicyService(db))
	g := r.Group("/api/iga/v2/runtime-policies", auth)

	g.GET("", middlewares.Require("runtime_policy", "read"), ctl.List)
	g.GET("/simulations/:simulation_id", middlewares.Require("runtime_policy", "read"), ctl.NotImplemented(false))
	g.POST("/candidates", middlewares.Require("runtime_policy", "write"), ctl.NotImplemented(false))
	g.POST("", middlewares.Require("runtime_policy", "write"), ctl.Create)

	g.GET("/:id", middlewares.Require("runtime_policy", "read"), ctl.Get)
	g.GET("/:id/rollouts", middlewares.Require("runtime_policy", "read"), ctl.NotImplemented(false))
	g.PUT("/:id/draft", middlewares.Require("runtime_policy", "write"), ctl.PutDraft)
	g.POST("/:id/validate", middlewares.Require("runtime_policy", "write"), ctl.Validate)
	g.POST("/:id/simulations", middlewares.Require("runtime_policy", "write"), ctl.NotImplemented(false))
	g.POST("/:id/approvals", middlewares.Require("runtime_policy", "approve"), ctl.Approve)
	g.POST("/:id/publications", middlewares.Require("runtime_policy", "enforce"), ctl.NotImplemented(true))
	g.POST("/:id/rollback", middlewares.Require("runtime_policy", "enforce"), ctl.NotImplemented(true))
	g.POST("/:id/revoke", middlewares.Require("runtime_policy", "enforce"), ctl.NotImplemented(true))
}
