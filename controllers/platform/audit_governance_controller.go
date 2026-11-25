package platform

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
)

// Audit governance (SPEC-secops-backend-upgrade.md F7 / P18, AS-177;
// services/audit_governance*.go):
//
//	GET  /api/iga/v1/audit/events?actor=&action=&from=&to=&cursor=&limit=  governance:read
//	GET  /api/iga/v1/audit/verify?from=&to=                                 governance:read
//	GET  /api/iga/v1/audit/anchors                                          governance:read
//	GET  /api/iga/v1/audit/write-failures                                   governance:read
//	GET  /api/iga/v1/audit/retention                                        governance:read
//	PUT  /api/iga/v1/audit/retention {record_class, retain_days, reason, break_glass?}  governance:author
//	     (the same or longer: applied, 200; shorter: tier 3, 202 pending change)
//	GET  /api/iga/v1/audit/legal-holds                                      governance:read
//	POST /api/iga/v1/audit/legal-holds {from, to, reason}                   governance:author
//	POST /api/iga/v1/audit/legal-holds/:id/release {reason, break_glass?}   governance:author (tier 3)
//	GET  /api/iga/v1/audit/changes?status=                                  governance:read
//	POST /api/iga/v1/audit/changes/:id/approve {reason?}                    governance:approve (not the requester)
//	POST /api/iga/v1/audit/changes/:id/reject  {reason?}                    governance:approve (not the requester)
//	POST /api/iga/v1/audit/changes/:id/review  {note?}                      governance:approve (break-glass review)
//	GET  /api/iga/v1/audit/operators/:id/decisions?from=&to=                governance:read
//	GET  /api/iga/v1/audit/operator-alerts?actor=                           governance:read
//	GET  /api/iga/v1/audit/suspensions                                      governance:read
//	POST /authsec/admin/operators/:id/suspend   {reason}                    governance:emergency
//	POST /authsec/admin/operators/:id/unsuspend {reason, break_glass?}      governance:emergency (tier 3)
//
// The workspace is the token's (AuthMiddleware); another workspace's ids are
// 404. Writes need a verified workspace member session (humanActor) and
// write their audit_events row in the change's own transaction.

// AuditGovernanceController serves the routes above.
type AuditGovernanceController struct {
	db func() *gorm.DB
}

// NewAuditGovernanceControllerFor builds the controller over the graph
// controller's database.
func NewAuditGovernanceControllerFor(g *IGAGraphReadController) *AuditGovernanceController {
	return &AuditGovernanceController{db: g.db}
}

// NewAuditGovernanceController is the production controller (config.DB).
func NewAuditGovernanceController() *AuditGovernanceController {
	return &AuditGovernanceController{db: func() *gorm.DB { return config.DB }}
}

// MountAuditGovernanceRoutes mounts /api/iga/v1/audit and
// /authsec/admin/operators on r behind auth.
func MountAuditGovernanceRoutes(r gin.IRouter, ctl *AuditGovernanceController, auth gin.HandlerFunc) {
	read := middlewares.Require("governance", "read")
	author := middlewares.Require("governance", "author")
	approve := middlewares.Require("governance", "approve")
	emergency := middlewares.Require("governance", "emergency")

	g := r.Group("/api/iga/v1/audit")
	g.Use(auth, ctl.requireSchema)
	g.GET("/events", read, ctl.ListEvents)
	g.GET("/verify", read, ctl.Verify)
	g.GET("/anchors", read, ctl.ListAnchors)
	g.GET("/write-failures", read, ctl.ListWriteFailures)
	g.GET("/retention", read, ctl.GetRetention)
	g.PUT("/retention", author, ctl.PutRetention)
	g.GET("/legal-holds", read, ctl.ListLegalHolds)
	g.POST("/legal-holds", author, ctl.PlaceLegalHold)
	g.POST("/legal-holds/:id/release", author, ctl.ReleaseLegalHold)
	g.GET("/changes", read, ctl.ListChanges)
	g.POST("/changes/:id/approve", approve, ctl.ApproveChange)
	g.POST("/changes/:id/reject", approve, ctl.RejectChange)
	g.POST("/changes/:id/review", approve, ctl.ReviewChange)
	g.GET("/operators/:id/decisions", read, ctl.OperatorDecisions)
	g.GET("/operator-alerts", read, ctl.ListOperatorAlerts)
	g.GET("/suspensions", read, ctl.ListSuspensions)

	op := r.Group("/authsec/admin/operators")
	op.Use(auth, ctl.requireSchema)
	op.POST("/:id/suspend", emergency, ctl.Suspend)
	op.POST("/:id/unsuspend", emergency, ctl.Unsuspend)
}

func (ctl *AuditGovernanceController) requireSchema(c *gin.Context) {
	// TENANT-EXEMPT: the 167-169 schema check reads the Postgres catalog only.
	if err := services.RequireAuditGovernance(ctl.db()); err != nil {
		govErrorOut(c, err)
	}
}

// TENANT-EXEMPT: not a statement here: the service runs every statement in a
// transaction under row-level security for the token's workspace.
func (ctl *AuditGovernanceController) svc() *services.AuditGovService {
	return services.NewAuditGovService(ctl.db())
}

// actor is the verified member making a write, or a 403/500 written.
func (ctl *AuditGovernanceController) actor(c *gin.Context, ws uuid.UUID) (services.AuditActor, bool) {
	// TENANT-EXEMPT: not a statement here: humanActor checks the membership under the token's workspace (tenancy.QueryRowContext).
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			policyErr(c, http.StatusForbidden, "forbidden", "Audit governance changes require a verified workspace member session.", nil)
			return services.AuditActor{}, false
		}
		policyInternal(c, err)
		return services.AuditActor{}, false
	}
	id, err := uuid.Parse(uid)
	if err != nil {
		policyErr(c, http.StatusForbidden, "forbidden", "Audit governance changes require a verified workspace member session.", nil)
		return services.AuditActor{}, false
	}
	return services.AuditActor{UserID: id, RequestID: c.GetString("request_id"), Method: c.Request.Method,
		Path: c.Request.URL.Path, ClientIP: c.ClientIP(), UserAgent: c.GetHeader("User-Agent")}, true
}

func pathUUID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		policyNotFound(c)
		return uuid.Nil, false
	}
	return id, true
}

// timeParam parses an RFC 3339 query parameter; def when absent.
func timeParam(c *gin.Context, name string, def time.Time) (time.Time, bool) {
	v := c.Query(name)
	if v == "" {
		return def, true
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		govErrorOut(c, services.GovBadParam(name, name+" must be an RFC 3339 time."))
		return time.Time{}, false
	}
	return t, true
}

func auditBindBody(c *gin.Context, dst any) bool {
	if c.Request.ContentLength == 0 {
		return true
	}
	if err := c.ShouldBindJSON(dst); err != nil {
		govErrorOut(c, services.GovBadParam("body", "The body must be a JSON object."))
		return false
	}
	return true
}

// ListEvents handles GET /audit/events.
func (ctl *AuditGovernanceController) ListEvents(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	f := services.AuditEventFilter{Actor: c.Query("actor"), Action: c.Query("action")}
	if c.Query("from") != "" {
		t, ok := timeParam(c, "from", time.Time{})
		if !ok {
			return
		}
		f.From = &t
	}
	if c.Query("to") != "" {
		t, ok := timeParam(c, "to", time.Time{})
		if !ok {
			return
		}
		f.To = &t
	}
	limit := 0
	if v := c.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > services.MaxGovPage {
			govErrorOut(c, services.GovBadParam("limit", "limit must be between 1 and 200."))
			return
		}
		limit = n
	}
	rows, next, err := ctl.svc().Events(c.Request.Context(), ws, f, c.Query("cursor"), limit)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "meta": gin.H{"next_cursor": next}})
}

// Verify handles GET /audit/verify (default: the last 24 hours).
func (ctl *AuditGovernanceController) Verify(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	now := time.Now().UTC()
	from, ok := timeParam(c, "from", now.Add(-24*time.Hour))
	if !ok {
		return
	}
	to, ok := timeParam(c, "to", now)
	if !ok {
		return
	}
	rep, err := ctl.svc().Verify(c.Request.Context(), ws, from, to)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rep})
}

// ListAnchors handles GET /audit/anchors.
func (ctl *AuditGovernanceController) ListAnchors(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := ctl.svc().Anchors(c.Request.Context(), ws, 100)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	if rows == nil {
		rows = []services.AuditAnchor{}
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// ListWriteFailures handles GET /audit/write-failures.
func (ctl *AuditGovernanceController) ListWriteFailures(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := ctl.svc().WriteFailures(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// GetRetention handles GET /audit/retention.
func (ctl *AuditGovernanceController) GetRetention(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := ctl.svc().Retention(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

type putRetentionBody struct {
	RecordClass string `json:"record_class"`
	RetainDays  int    `json:"retain_days"`
	Reason      string `json:"reason"`
	BreakGlass  bool   `json:"break_glass"`
}

func changeStatus(r *services.AuditChangeResult) int {
	if r.Applied {
		return http.StatusOK
	}
	return http.StatusAccepted
}

// PutRetention handles PUT /audit/retention.
func (ctl *AuditGovernanceController) PutRetention(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	a, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body putRetentionBody
	if err := c.ShouldBindJSON(&body); err != nil {
		govErrorOut(c, services.GovBadParam("body", `The body must be JSON: {"record_class": "...", "retain_days": 365, "reason": "..."}.`))
		return
	}
	res, err := ctl.svc().SetRetention(c.Request.Context(), ws, a, body.RecordClass, body.RetainDays, body.Reason, body.BreakGlass)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(changeStatus(res), gin.H{"data": res})
}

// ListLegalHolds handles GET /audit/legal-holds.
func (ctl *AuditGovernanceController) ListLegalHolds(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := ctl.svc().LegalHolds(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	if rows == nil {
		rows = []services.AuditLegalHold{}
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

type legalHoldBody struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Reason string    `json:"reason"`
}

// PlaceLegalHold handles POST /audit/legal-holds.
func (ctl *AuditGovernanceController) PlaceLegalHold(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	a, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body legalHoldBody
	if err := c.ShouldBindJSON(&body); err != nil {
		govErrorOut(c, services.GovBadParam("body", `The body must be JSON: {"from": "<RFC 3339>", "to": "<RFC 3339>", "reason": "..."}.`))
		return
	}
	h, err := ctl.svc().PlaceLegalHold(c.Request.Context(), ws, a, body.From, body.To, body.Reason)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": h})
}

type tier3Body struct {
	Reason     string `json:"reason"`
	BreakGlass bool   `json:"break_glass"`
}

// ReleaseLegalHold handles POST /audit/legal-holds/:id/release (tier 3).
func (ctl *AuditGovernanceController) ReleaseLegalHold(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c)
	if !ok {
		return
	}
	a, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body tier3Body
	if !auditBindBody(c, &body) {
		return
	}
	res, err := ctl.svc().RequestLegalHoldRelease(c.Request.Context(), ws, a, id, body.Reason, body.BreakGlass)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(changeStatus(res), gin.H{"data": res})
}

// ListChanges handles GET /audit/changes.
func (ctl *AuditGovernanceController) ListChanges(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := ctl.svc().Changes(c.Request.Context(), ws, c.Query("status"))
	if err != nil {
		govErrorOut(c, err)
		return
	}
	if rows == nil {
		rows = []services.AuditChangeView{}
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

type decisionBody struct {
	Reason string `json:"reason"`
	Note   string `json:"note"`
}

func (ctl *AuditGovernanceController) decide(c *gin.Context, what string) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c)
	if !ok {
		return
	}
	a, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body decisionBody
	if !auditBindBody(c, &body) {
		return
	}
	var (
		ch  *services.AuditChangeView
		err error
	)
	switch what {
	case "approve":
		ch, err = ctl.svc().ApproveChange(c.Request.Context(), ws, a, id, body.Reason)
	case "reject":
		ch, err = ctl.svc().RejectChange(c.Request.Context(), ws, a, id, body.Reason)
	default:
		ch, err = ctl.svc().ReviewBreakGlass(c.Request.Context(), ws, a, id, body.Note)
	}
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": ch})
}

// ApproveChange handles POST /audit/changes/:id/approve.
func (ctl *AuditGovernanceController) ApproveChange(c *gin.Context) { ctl.decide(c, "approve") }

// RejectChange handles POST /audit/changes/:id/reject.
func (ctl *AuditGovernanceController) RejectChange(c *gin.Context) { ctl.decide(c, "reject") }

// ReviewChange handles POST /audit/changes/:id/review.
func (ctl *AuditGovernanceController) ReviewChange(c *gin.Context) { ctl.decide(c, "review") }

// OperatorDecisions handles GET /audit/operators/:id/decisions (default: the
// last 7 days). It lists; it never reverses.
func (ctl *AuditGovernanceController) OperatorDecisions(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c)
	if !ok {
		return
	}
	now := time.Now().UTC()
	from, ok := timeParam(c, "from", now.Add(-7*24*time.Hour))
	if !ok {
		return
	}
	to, ok := timeParam(c, "to", now)
	if !ok {
		return
	}
	rows, err := ctl.svc().OperatorDecisions(c.Request.Context(), ws, id, from, to)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "meta": gin.H{"operator_id": id, "from": from, "to": to,
		"note": "Listed for review; nothing is reversed automatically."}})
}

// ListOperatorAlerts handles GET /audit/operator-alerts.
func (ctl *AuditGovernanceController) ListOperatorAlerts(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := ctl.svc().OperatorAlerts(c.Request.Context(), ws, c.Query("actor"))
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// ListSuspensions handles GET /audit/suspensions.
func (ctl *AuditGovernanceController) ListSuspensions(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := ctl.svc().Suspensions(c.Request.Context(), ws)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// Suspend handles POST /authsec/admin/operators/:id/suspend.
func (ctl *AuditGovernanceController) Suspend(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c)
	if !ok {
		return
	}
	a, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body tier3Body
	if !auditBindBody(c, &body) {
		return
	}
	sp, err := ctl.svc().Suspend(c.Request.Context(), ws, a, id, body.Reason)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": sp})
}

// Unsuspend handles POST /authsec/admin/operators/:id/unsuspend (tier 3).
func (ctl *AuditGovernanceController) Unsuspend(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, ok := pathUUID(c)
	if !ok {
		return
	}
	a, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	var body tier3Body
	if !auditBindBody(c, &body) {
		return
	}
	res, err := ctl.svc().RequestUnsuspend(c.Request.Context(), ws, a, id, body.Reason, body.BreakGlass)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(changeStatus(res), gin.H{"data": res})
}
