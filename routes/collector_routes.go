package routes

import (
	"log"
	"time"

	platformCtrl "github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	collectorBodyLimit  = 64 << 10
	collectorRatePerMin = 600
)

// NewCollectorController builds the enrollment service. A nil DB or a sealer
// failure leaves the v2 routes unmounted; legacy discovery is unaffected.
func NewCollectorController(db *gorm.DB) *platformCtrl.CollectorController {
	if db == nil {
		return nil
	}
	svc, err := services.NewCollectorEnrollmentService(db, nil)
	if err != nil {
		log.Printf("[collector] enrollment service unavailable: %v", err)
		return nil
	}
	return platformCtrl.NewCollectorController(svc)
}

// MountCollectorV2 registers /api/iga/v2 collector routes.
// humanAuth is the existing user middleware (AuthMiddleware in production).
// Every route 404s when IGA_V2_INGEST is off, before the body is read.
func MountCollectorV2(r gin.IRouter, db *gorm.DB, ctl *platformCtrl.CollectorController, humanAuth gin.HandlerFunc) {
	if r == nil || db == nil || ctl == nil || humanAuth == nil {
		return
	}
	now := ctl.Now
	v2 := r.Group("/api/iga/v2", middlewares.RequireV2Ingest())

	admin := v2.Group("")
	admin.Use(humanAuth, middlewares.CollectorRateLimit(collectorRatePerMin, time.Minute), middlewares.LimitBody(collectorBodyLimit))
	admin.POST("/collector-enrollments", middlewares.Require("discovery", "admin"), ctl.CreateEnrollment)
	admin.POST("/collectors/:id/revoke", middlewares.Require("discovery", "admin"), ctl.Revoke)
	admin.GET("/collectors/:id", middlewares.Require("discovery", "read"), ctl.Get)

	// Static machine paths are registered beside :id. Gin prefers the static
	// segment, so /collectors/enroll and /collectors/self are not captured as ids.
	enroll := v2.Group("")
	enroll.Use(
		middlewares.CollectorRateLimit(collectorRatePerMin, time.Minute),
		middlewares.AuthenticateEnrollment(db, now),
		middlewares.LimitBody(collectorBodyLimit),
	)
	enroll.POST("/collectors/enroll", ctl.Enroll)

	machine := v2.Group("")
	machine.Use(
		middlewares.CollectorRateLimit(collectorRatePerMin, time.Minute),
		middlewares.AuthenticateCollector(db, now),
		middlewares.LimitBody(collectorBodyLimit),
	)
	machine.POST("/collectors/self/credentials/rotate", ctl.Rotate)
	machine.GET("/collectors/self", middlewares.RequireCollectorScope(models.CollectorScopePolicyRead), ctl.GetSelf)
}
