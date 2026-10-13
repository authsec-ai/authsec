package platform

import (
	"errors"
	"log"
	"net/http"

	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PolicyDemoController serves the Policy UI demo, /api/policy-demo/v1:
// create, list, read, edit, pause, resume and delete a time-boxed S3 access
// policy for an agent, and preview the AWS documents it would produce. It is a
// demonstration of the authoring flow: nothing is deployed to AWS.
type PolicyDemoController struct {
	svc *services.PolicyDemoService
}

func NewPolicyDemoController(db *gorm.DB) *PolicyDemoController {
	return &PolicyDemoController{svc: services.NewPolicyDemoService(db)}
}

// MountPolicyDemoRoutes mounts the demo behind the shared AuthMiddleware. The
// workspace is the token's, never a parameter.
func MountPolicyDemoRoutes(r gin.IRouter, ctl *PolicyDemoController) {
	g := r.Group("/api/policy-demo/v1")
	g.Use(middlewares.AuthMiddleware())
	g.GET("/policies", ctl.List)
	g.POST("/policies", ctl.Create)
	g.POST("/policies/preview", ctl.Preview)
	g.POST("/policies/seed", ctl.Seed)
	g.GET("/policies/:id", ctl.Get)
	g.PUT("/policies/:id", ctl.Update)
	g.POST("/policies/:id/pause", ctl.Pause)
	g.POST("/policies/:id/resume", ctl.Resume)
	g.DELETE("/policies/:id", ctl.Delete)
}

func demoWorkspace(c *gin.Context) (uuid.UUID, bool) {
	ws, err := uuid.Parse(c.GetString("workspace_id"))
	if err != nil || ws == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": gin.H{"code": "unauthenticated", "message": "No workspace in the token."}})
		return uuid.Nil, false
	}
	return ws, true
}

func demoUser(c *gin.Context) *uuid.UUID {
	s, err := middlewares.ResolveUserID(c)
	if err != nil {
		return nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return nil
	}
	return &id
}

func demoID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "not_found", "message": "That policy does not exist."}})
		return uuid.Nil, false
	}
	return id, true
}

func demoFail(c *gin.Context, err error) {
	var de *services.PolicyDemoError
	if errors.As(err, &de) {
		body := gin.H{"code": de.Code, "message": de.Message}
		if de.Field != "" {
			body["field"] = de.Field
		}
		c.JSON(de.Status, gin.H{"error": body})
		return
	}
	log.Printf("[policy-demo] %s %s: %v", c.Request.Method, c.FullPath(), err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "internal", "message": "Something went wrong. Try again."}})
}

func (ctl *PolicyDemoController) List(c *gin.Context) {
	ws, ok := demoWorkspace(c)
	if !ok {
		return
	}
	rows, err := ctl.svc.List(ws, c.Query("q"), c.Query("phase"), c.Query("resource"))
	if err != nil {
		demoFail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

func (ctl *PolicyDemoController) Get(c *gin.Context) {
	ws, ok := demoWorkspace(c)
	if !ok {
		return
	}
	id, ok := demoID(c)
	if !ok {
		return
	}
	v, err := ctl.svc.Get(ws, id)
	if err != nil {
		demoFail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": v})
}

func (ctl *PolicyDemoController) bind(c *gin.Context) (services.PolicyDemoInput, bool) {
	var in services.PolicyDemoInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "invalid_body", "message": "The request body is not valid JSON for a policy."}})
		return in, false
	}
	return in, true
}

func (ctl *PolicyDemoController) Create(c *gin.Context) {
	ws, ok := demoWorkspace(c)
	if !ok {
		return
	}
	in, ok := ctl.bind(c)
	if !ok {
		return
	}
	v, err := ctl.svc.Create(ws, demoUser(c), in)
	if err != nil {
		demoFail(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": v})
}

func (ctl *PolicyDemoController) Preview(c *gin.Context) {
	if _, ok := demoWorkspace(c); !ok {
		return
	}
	in, ok := ctl.bind(c)
	if !ok {
		return
	}
	v, err := ctl.svc.Preview(in)
	if err != nil {
		demoFail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": v})
}

func (ctl *PolicyDemoController) Update(c *gin.Context) {
	ws, ok := demoWorkspace(c)
	if !ok {
		return
	}
	id, ok := demoID(c)
	if !ok {
		return
	}
	in, ok := ctl.bind(c)
	if !ok {
		return
	}
	v, err := ctl.svc.Update(ws, id, in)
	if err != nil {
		demoFail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": v})
}

func (ctl *PolicyDemoController) setPaused(c *gin.Context, paused bool) {
	ws, ok := demoWorkspace(c)
	if !ok {
		return
	}
	id, ok := demoID(c)
	if !ok {
		return
	}
	v, err := ctl.svc.SetPaused(ws, id, paused)
	if err != nil {
		demoFail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": v})
}

func (ctl *PolicyDemoController) Pause(c *gin.Context)  { ctl.setPaused(c, true) }
func (ctl *PolicyDemoController) Resume(c *gin.Context) { ctl.setPaused(c, false) }

func (ctl *PolicyDemoController) Delete(c *gin.Context) {
	ws, ok := demoWorkspace(c)
	if !ok {
		return
	}
	id, ok := demoID(c)
	if !ok {
		return
	}
	if err := ctl.svc.Delete(ws, id); err != nil {
		demoFail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"id": id, "deleted": true}})
}

func (ctl *PolicyDemoController) Seed(c *gin.Context) {
	ws, ok := demoWorkspace(c)
	if !ok {
		return
	}
	rows, err := ctl.svc.Seed(ws, demoUser(c))
	if err != nil {
		demoFail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}
