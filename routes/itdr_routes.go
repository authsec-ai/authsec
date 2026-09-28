package routes

import (
	platformCtrl "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// MountITDR registers /api/iga/v2/itdr when IGA_V2_ITDR is on.
// When the flag is off the routes are not registered and nothing is evaluated.
func MountITDR(r gin.IRouter, db *gorm.DB, auth gin.HandlerFunc) {
	if r == nil || db == nil || auth == nil || !services.V2ITDREnabled() {
		return
	}
	svc := services.NewITDRService(db)
	ctl := platformCtrl.NewITDRController(svc)
	g := r.Group("/api/iga/v2/itdr", auth)

	// Detection rules
	rules := g.Group("/detection-rules")
	rules.GET("", middlewares.Require("itdr", "read"), ctl.ListDetectionRules)
	rules.POST("", middlewares.Require("itdr", "write"), ctl.CreateDetectionRule)
	rules.GET("/:rule_id", middlewares.Require("itdr", "read"), ctl.GetDetectionRule)
	rules.PUT("/:rule_id", middlewares.Require("itdr", "write"), ctl.UpdateDetectionRule)

	// Findings
	findings := g.Group("/findings")
	findings.GET("", middlewares.Require("itdr", "read"), ctl.ListFindings)
	findings.POST("", middlewares.Require("itdr", "write"), ctl.CreateFinding)
	findings.GET("/:finding_id", middlewares.Require("itdr", "read"), ctl.GetFinding)
	findings.PUT("/:finding_id/status", middlewares.Require("itdr", "write"), ctl.UpdateFindingStatus)

	// Response plans
	findings.GET("/:finding_id/response-plans", middlewares.Require("itdr", "read"), ctl.ListResponsePlans)
	g.POST("/response-plans", middlewares.Require("itdr", "write"), ctl.CreateResponsePlan)
	g.POST("/response-plans/:plan_id/approve", middlewares.Require("itdr", "approve"), ctl.ApproveResponsePlan)
	g.PUT("/response-plans/:plan_id/status", middlewares.Require("itdr", "write"), ctl.TransitionResponsePlan)

	// Escalation leases
	leases := g.Group("/escalation-leases")
	leases.GET("", middlewares.Require("itdr", "read"), ctl.ListEscalationLeases)
	leases.POST("", middlewares.Require("itdr", "write"), ctl.CreateEscalationLease)
	leases.POST("/:lease_id/redeem", middlewares.Require("itdr", "write"), ctl.RedeemEscalationLease)
}
