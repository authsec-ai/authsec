package platform

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/services"
)

// The IaC-source routes of §7.9 (SPEC-iga-phase3-policy.md; T3.17), under
// /authsec/discovery/aws beside the enforcement binding:
//
//	GET    /aws/connectors/:id/iac-sources        governance:enforce  sources of the account, with GitHub permission state
//	POST   /aws/connectors/:id/iac-sources        governance:enforce  map a repository directory (format, discovery_source_id, repository, base_branch, directory, role_match)
//	DELETE /aws/connectors/:id/iac-sources/:sid   governance:enforce  remove a mapping (409 iac_source_in_use once PRs were opened from it)
//
// The Phase 3 rules apply (§7 intro): the IGA_POLICY gate, the workspace
// from the token only, another workspace's connector or source 404, the
// {data, meta} / {error} envelope, an iga_gov_event in the service's
// transaction and an audit_events row here.

// CloudIaCSourceController serves the IaC-source routes.
type CloudIaCSourceController struct {
	db   *gorm.DB
	gate func() *services.PolicyGate
}

// NewCloudIaCSourceController builds the controller over the process-wide gate.
func NewCloudIaCSourceController(db *gorm.DB) *CloudIaCSourceController {
	return &CloudIaCSourceController{db: db, gate: services.PolicyGateState}
}

// WithPolicyGate makes the routes read g (tests).
func (ctl *CloudIaCSourceController) WithPolicyGate(g *services.PolicyGate) *CloudIaCSourceController {
	ctl.gate = func() *services.PolicyGate { return g }
	return ctl
}

// RegisterIaCSourceRoutes mounts the routes on the authenticated
// /authsec/discovery group.
func RegisterIaCSourceRoutes(discovery gin.IRouter, ctl *CloudIaCSourceController, require func(resource, action string) gin.HandlerFunc) {
	req := GraphRequire(require)
	g := discovery.Group("/aws/connectors/:id/iac-sources", ctl.Gate())
	g.GET("", req("governance", "enforce"), ctl.List)
	g.POST("", req("governance", "enforce"), ctl.Create)
	g.DELETE("/:sid", req("governance", "enforce"), ctl.Delete)
}

// Gate is the IGA_POLICY middleware (fail closed).
func (ctl *CloudIaCSourceController) Gate() gin.HandlerFunc {
	return func(c *gin.Context) {
		var gate *services.PolicyGate
		if ctl.gate != nil {
			gate = ctl.gate()
		}
		if state, reason, _ := gate.Status(); state != services.PolicyOn {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, PolicyUnavailableBody(reason))
			return
		}
		c.Next()
	}
}

func iacFail(c *gin.Context, err error) {
	var ge *services.GovError
	if errors.As(err, &ge) {
		c.AbortWithStatusJSON(ge.Status, ge.Body())
		return
	}
	log.Printf("[iac-source] %s %s: %v", c.Request.Method, c.FullPath(), err)
	enfFail(c, http.StatusInternalServerError, "internal_error", "The request could not be completed.", nil)
}

func (ctl *CloudIaCSourceController) scope(c *gin.Context) (ws, connectorID uuid.UUID, ok bool) {
	ws, okWS := tokenWorkspace(c)
	if !okWS {
		enfFail(c, http.StatusUnauthorized, "unauthenticated", "No workspace in the token.", nil)
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		iacFail(c, services.GovNotFound())
		return
	}
	return ws, id, true
}

// List handles GET.
func (ctl *CloudIaCSourceController) List(c *gin.Context) {
	ws, id, ok := ctl.scope(c)
	if !ok {
		return
	}
	out, err := services.NewGovIaCSourceService(ctl.db).List(c.Request.Context(), ws, id)
	if err != nil {
		iacFail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "meta": gin.H{"as_of": time.Now().UTC(), "next_cursor": nil}})
}

// Create handles POST.
func (ctl *CloudIaCSourceController) Create(c *gin.Context) {
	ws, id, ok := ctl.scope(c)
	if !ok {
		return
	}
	user, ok := enfUser(c)
	if !ok {
		return
	}
	var in services.GovIaCSourceInput
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		iacFail(c, services.GovBadParam("body", "Invalid request body: "+err.Error()))
		return
	}
	v, err := services.NewGovIaCSourceService(ctl.db).Create(c.Request.Context(), ws, id, user, in)
	if err != nil {
		iacFail(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "create_iac_source", "iga_gov_iac_source", v.ID.String(), http.StatusCreated, nil,
		gin.H{"connector_id": id, "repository": v.Repository, "directory": v.Directory, "format": v.Format,
			"permissions": v.Permissions.State})
	c.JSON(http.StatusCreated, gin.H{"data": v, "meta": gin.H{"as_of": time.Now().UTC()}})
}

// Delete handles DELETE /:sid.
func (ctl *CloudIaCSourceController) Delete(c *gin.Context) {
	ws, id, ok := ctl.scope(c)
	if !ok {
		return
	}
	user, ok := enfUser(c)
	if !ok {
		return
	}
	sid, err := uuid.Parse(c.Param("sid"))
	if err != nil {
		iacFail(c, services.GovNotFound())
		return
	}
	if err := services.NewGovIaCSourceService(ctl.db).Delete(c.Request.Context(), ws, id, sid, user); err != nil {
		iacFail(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "delete_iac_source", "iga_gov_iac_source", sid.String(), http.StatusOK, nil,
		gin.H{"connector_id": id})
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"id": sid, "deleted": true}, "meta": gin.H{"as_of": time.Now().UTC()}})
}
