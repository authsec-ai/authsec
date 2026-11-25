package platform

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
)

// History and metrics (SPEC-secops-backend-upgrade.md W9). Under
// /api/iga/v1, workspace from the token (AuthMiddleware), governance error
// envelope; another workspace's rows read as absent (404):
//
//	GET  /snapshots?kind=&stable_id=&as_of=&cursor=&limit=   governance:read
//	GET  /snapshots/days?from=&to=                            governance:read
//	GET  /snapshots/verify?from=&to=                          governance:read
//	GET  /snapshots/holds                                     governance:read
//	POST /snapshots/hold  (alias /snapshots/holds)            governance:author {from, to, kinds?, reason}
//	POST /snapshots/holds/:id/release                         governance:author {reason, break_glass?}   tier 3
//	POST /snapshots/:id/redact                                governance:author {reason, break_glass?}   tier 3
//	GET  /metrics/soc?period=7d|30d|90d                       governance:read
//	GET  /metrics/posture?as_of=                              governance:read
//	GET  /reports/ciso?month=YYYY-MM                          governance:read
//	GET  /reports/population?from=&to=&kind=&cursor=&limit=   governance:read
//	POST /exports                                             governance:author {from, to, kinds?, reason, break_glass?} tier 3
//	GET  /exports                                             governance:read
//	GET  /exports/:id/download                                governance:read (requester or approver only)
//	GET  /history-approvals?state=&review_due=                governance:read
//	GET  /history-approvals/:id                               governance:read
//	POST /history-approvals/:id/approve                       governance:approve {reason?}  (not the requester)
//	POST /history-approvals/:id/reject                        governance:approve {reason?}  (not the requester)
//	POST /history-approvals/:id/withdraw                      governance:author  (the requester)
//	POST /history-approvals/:id/review                        governance:approve {note?}    (break-glass, not the requester)
//
// A tier-3 request answers 202 with the pending request, or 200 with the
// applied one when break_glass applied it.

// IGAHistoryController serves the routes above.
type IGAHistoryController struct {
	db func() *gorm.DB
}

// NewIGAHistoryControllerFor shares the graph controller's database.
func NewIGAHistoryControllerFor(g *IGAGraphReadController) *IGAHistoryController {
	return &IGAHistoryController{db: g.db}
}

// NewIGAHistoryControllerWith builds a controller over db (tests).
func NewIGAHistoryControllerWith(db *gorm.DB) *IGAHistoryController {
	return &IGAHistoryController{db: func() *gorm.DB { return db }}
}

// MountIGAHistoryRoutes mounts the routes on g (the authenticated /api/iga/v1
// group) with their permissions.
func MountIGAHistoryRoutes(g *gin.RouterGroup, ctl *IGAHistoryController) {
	RegisterIGAHistoryRoutes(g.Group("", TierGuard()), ctl, middlewares.Require("governance", "read"),
		middlewares.Require("governance", "author"), middlewares.Require("governance", "approve"))
}

// RegisterIGAHistoryRoutes is the route table.
func RegisterIGAHistoryRoutes(g gin.IRoutes, ctl *IGAHistoryController, read, author, approve gin.HandlerFunc) {
	g.GET("/snapshots", read, ctl.ListSnapshots)
	g.GET("/snapshots/days", read, ctl.ListDays)
	g.GET("/snapshots/verify", read, ctl.Verify)
	g.GET("/snapshots/holds", read, ctl.ListHolds)
	g.POST("/snapshots/hold", author, ctl.PlaceHold)
	g.POST("/snapshots/holds", author, ctl.PlaceHold)
	g.POST("/snapshots/holds/:id/release", author, ctl.ReleaseHold)
	g.POST("/snapshots/:id/redact", author, ctl.Redact)
	g.GET("/metrics/soc", read, ctl.SOC)
	g.GET("/metrics/posture", read, ctl.Posture)
	g.GET("/reports/ciso", read, ctl.CISO)
	g.GET("/reports/population", read, ctl.Population)
	g.POST("/exports", author, ctl.CreateExport)
	g.GET("/exports", read, ctl.ListExports)
	g.GET("/exports/:id/download", read, ctl.DownloadExport)
	g.GET("/history-approvals", read, ctl.ListApprovals)
	g.GET("/history-approvals/:id", read, ctl.GetApproval)
	g.POST("/history-approvals/:id/approve", approve, ctl.Approve)
	g.POST("/history-approvals/:id/reject", approve, ctl.Reject)
	g.POST("/history-approvals/:id/withdraw", author, ctl.Withdraw)
	g.POST("/history-approvals/:id/review", approve, ctl.Review)
}

// TENANT-EXEMPT: not a statement here: the service runs every statement in a
// transaction under row-level security for the token's workspace.
func (ctl *IGAHistoryController) svc() *services.HistoryService {
	return services.NewHistoryService(ctl.db())
}

// actor is the verified member making a write, or a 403/500 written.
func (ctl *IGAHistoryController) actor(c *gin.Context, ws uuid.UUID) (uuid.UUID, bool) {
	// TENANT-EXEMPT: not a statement here: humanActor checks the membership under the token's workspace (tenancy.QueryRowContext).
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			policyErr(c, http.StatusForbidden, "forbidden", "This change requires a verified workspace member session.", nil)
			return uuid.Nil, false
		}
		policyInternal(c, err)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(uid)
	if err != nil {
		policyErr(c, http.StatusForbidden, "forbidden", "This change requires a verified workspace member session.", nil)
		return uuid.Nil, false
	}
	return id, true
}

// write runs a mutation: token workspace, verified actor, the call, the
// audit row, and the {data, meta} envelope.
func (ctl *IGAHistoryController) write(c *gin.Context, fn func(ws, actor uuid.UUID) (any, int, *audited, error)) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	data, status, au, err := fn(ws, actor)
	if err != nil {
		govError(c, err)
		return
	}
	if au != nil {
		auditAdminMutation(c, ws.String(), au.action, au.resource, au.id, status, au.before, au.after)
	}
	c.JSON(status, gin.H{"data": data, "meta": gin.H{}})
}

func historyParamID(c *gin.Context) (uuid.UUID, error) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return uuid.Nil, services.GovNotFound()
	}
	return id, nil
}

// historyTime parses a date or RFC 3339 query value; def when absent.
func historyTime(c *gin.Context, name string, def time.Time) (time.Time, error) {
	v := strings.TrimSpace(c.Query(name))
	if v == "" {
		return def, nil
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, services.GovBadParam(name, name+" must be a date (YYYY-MM-DD) or an RFC 3339 time.")
	}
	return t.UTC(), nil
}

func historyLimit(c *gin.Context) int {
	n, _ := strconv.Atoi(c.Query("limit"))
	return n
}

/* ---------------------------------- reads ----------------------------------- */

// ListSnapshots handles GET /snapshots.
func (ctl *IGAHistoryController) ListSnapshots(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		asOf, err := historyTime(c, "as_of", time.Now().UTC())
		if err != nil {
			return nil, nil, err
		}
		p, err := ctl.svc().SnapshotsAsOf(c.Request.Context(), ws, c.Query("kind"), c.Query("stable_id"), asOf, c.Query("cursor"), historyLimit(c))
		if err != nil {
			return nil, nil, err
		}
		return p.Items, gin.H{"as_of": p.AsOf, "kind": p.Kind, "next_cursor": p.NextCursor}, nil
	})
}

// ListDays handles GET /snapshots/days.
func (ctl *IGAHistoryController) ListDays(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		now := time.Now().UTC()
		from, err := historyTime(c, "from", now.AddDate(0, 0, -30))
		if err != nil {
			return nil, nil, err
		}
		to, err := historyTime(c, "to", now)
		if err != nil {
			return nil, nil, err
		}
		d, err := ctl.svc().SnapshotDays(c.Request.Context(), ws, from, to)
		return d, nil, err
	})
}

// Verify handles GET /snapshots/verify.
func (ctl *IGAHistoryController) Verify(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		now := time.Now().UTC()
		from, err := historyTime(c, "from", now.AddDate(0, 0, -30))
		if err != nil {
			return nil, nil, err
		}
		to, err := historyTime(c, "to", now)
		if err != nil {
			return nil, nil, err
		}
		v, err := ctl.svc().VerifyChain(c.Request.Context(), ws, from, to)
		return v, nil, err
	})
}

// ListHolds handles GET /snapshots/holds.
func (ctl *IGAHistoryController) ListHolds(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		h, err := ctl.svc().ListHolds(c.Request.Context(), ws)
		return h, nil, err
	})
}

// SOC handles GET /metrics/soc.
func (ctl *IGAHistoryController) SOC(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		r, err := ctl.svc().SOC(c.Request.Context(), ws, c.Query("period"))
		return r, nil, err
	})
}

// Posture handles GET /metrics/posture.
func (ctl *IGAHistoryController) Posture(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		var asOf *time.Time
		if c.Query("as_of") != "" {
			t, err := historyTime(c, "as_of", time.Time{})
			if err != nil {
				return nil, nil, err
			}
			asOf = &t
		}
		r, err := ctl.svc().Posture(c.Request.Context(), ws, asOf)
		return r, nil, err
	})
}

// CISO handles GET /reports/ciso.
func (ctl *IGAHistoryController) CISO(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		r, err := ctl.svc().CISO(c.Request.Context(), ws, c.Query("month"))
		return r, nil, err
	})
}

// Population handles GET /reports/population.
func (ctl *IGAHistoryController) Population(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		now := time.Now().UTC()
		from, err := historyTime(c, "from", now.AddDate(0, 0, -30))
		if err != nil {
			return nil, nil, err
		}
		to, err := historyTime(c, "to", now)
		if err != nil {
			return nil, nil, err
		}
		var kinds []string
		for _, k := range c.QueryArray("kind") {
			for _, p := range strings.Split(k, ",") {
				if p = strings.TrimSpace(p); p != "" {
					kinds = append(kinds, p)
				}
			}
		}
		p, err := ctl.svc().Population(c.Request.Context(), ws, from, to, kinds, c.Query("cursor"), historyLimit(c))
		if err != nil {
			return nil, nil, err
		}
		return p.Items, gin.H{"window": p.Window, "kinds": p.Kinds, "next_cursor": p.NextCursor}, nil
	})
}

// ListExports handles GET /exports.
func (ctl *IGAHistoryController) ListExports(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		e, err := ctl.svc().ListExports(c.Request.Context(), ws)
		return e, nil, err
	})
}

// ListApprovals handles GET /history-approvals.
func (ctl *IGAHistoryController) ListApprovals(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		a, err := ctl.svc().ListApprovals(c.Request.Context(), ws, c.Query("state"), c.Query("review_due") == "true")
		return a, nil, err
	})
}

// GetApproval handles GET /history-approvals/:id.
func (ctl *IGAHistoryController) GetApproval(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := historyParamID(c)
		if err != nil {
			return nil, nil, err
		}
		a, err := ctl.svc().GetApproval(c.Request.Context(), ws, id)
		return a, nil, err
	})
}

// DownloadExport handles GET /exports/:id/download: the bundle's bytes with
// their sha256 in X-Content-SHA256.
func (ctl *IGAHistoryController) DownloadExport(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.actor(c, ws)
	if !ok {
		return
	}
	id, err := historyParamID(c)
	if err != nil {
		govError(c, err)
		return
	}
	meta, body, err := ctl.svc().DownloadExport(c.Request.Context(), ws, actor, id)
	if err != nil {
		govError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "history.export_downloaded", "iga_export", meta.ID.String(), http.StatusOK, nil,
		gin.H{"sha256": meta.SHA256, "size_bytes": meta.SizeBytes})
	c.Header("X-Content-SHA256", meta.SHA256)
	c.Header("Content-Disposition", `attachment; filename="authsec-history-export-`+meta.ID.String()+`.json"`)
	c.Data(http.StatusOK, "application/json", body)
}

/* ---------------------------------- writes ---------------------------------- */

type historyHoldBody struct {
	From   string   `json:"from"`
	To     string   `json:"to"`
	Kinds  []string `json:"kinds"`
	Reason string   `json:"reason"`
}

// PlaceHold handles POST /snapshots/hold.
func (ctl *IGAHistoryController) PlaceHold(c *gin.Context) {
	ctl.write(c, func(ws, actor uuid.UUID) (any, int, *audited, error) {
		var b historyHoldBody
		if err := bindBody(c, &b, "{from, to, kinds?, reason}"); err != nil {
			return nil, 0, nil, err
		}
		from, err := time.Parse("2006-01-02", b.From)
		if err != nil {
			return nil, 0, nil, services.GovBadParam("from", "from must be YYYY-MM-DD.")
		}
		to, err := time.Parse("2006-01-02", b.To)
		if err != nil {
			return nil, 0, nil, services.GovBadParam("to", "to must be YYYY-MM-DD.")
		}
		h, err := ctl.svc().PlaceHold(c.Request.Context(), ws, actor, from, to, b.Kinds, b.Reason)
		if err != nil {
			return nil, 0, nil, err
		}
		return h, http.StatusCreated, &audited{"history.hold_placed", "iga_snapshot_hold", h.ID.String(), nil,
			gin.H{"from": h.From, "to": h.To, "kinds": h.Kinds, "reason": h.Reason}}, nil
	})
}

type historyChangeBody struct {
	Reason     string `json:"reason"`
	BreakGlass bool   `json:"break_glass"`
}

// request records a tier-3 request and answers 202 (pending) or 200
// (applied by break-glass).
func (ctl *IGAHistoryController) request(c *gin.Context, ws, actor uuid.UUID, req services.HistoryChangeRequest) (any, int, *audited, error) {
	a, err := ctl.svc().RequestChange(c.Request.Context(), ws, actor, req)
	if err != nil {
		return nil, 0, nil, err
	}
	status, event := http.StatusAccepted, "history.change_requested"
	if a.State == "applied" {
		status, event = http.StatusOK, "history.break_glass_applied"
	}
	return a, status, &audited{event, "iga_history_approval", a.ID.String(), nil,
		gin.H{"action": a.Action, "subject_id": a.SubjectID, "params_hash": a.ParamsHash, "break_glass": a.BreakGlass, "reason": a.Reason}}, nil
}

// ReleaseHold handles POST /snapshots/holds/:id/release (tier 3).
func (ctl *IGAHistoryController) ReleaseHold(c *gin.Context) {
	ctl.write(c, func(ws, actor uuid.UUID) (any, int, *audited, error) {
		id, err := historyParamID(c)
		if err != nil {
			return nil, 0, nil, err
		}
		var b historyChangeBody
		if err := bindBody(c, &b, "{reason, break_glass?}"); err != nil {
			return nil, 0, nil, err
		}
		return ctl.request(c, ws, actor, services.HistoryChangeRequest{Action: services.HistoryActionHoldRelease, SubjectID: &id,
			Reason: b.Reason, BreakGlass: b.BreakGlass})
	})
}

// Redact handles POST /snapshots/:id/redact (tier 3).
func (ctl *IGAHistoryController) Redact(c *gin.Context) {
	ctl.write(c, func(ws, actor uuid.UUID) (any, int, *audited, error) {
		id, err := historyParamID(c)
		if err != nil {
			return nil, 0, nil, err
		}
		var b historyChangeBody
		if err := bindBody(c, &b, "{reason, break_glass?}"); err != nil {
			return nil, 0, nil, err
		}
		return ctl.request(c, ws, actor, services.HistoryChangeRequest{Action: services.HistoryActionSnapshotRedact, SubjectID: &id,
			Reason: b.Reason, BreakGlass: b.BreakGlass})
	})
}

type historyExportBody struct {
	From       string   `json:"from"`
	To         string   `json:"to"`
	Kinds      []string `json:"kinds"`
	Reason     string   `json:"reason"`
	BreakGlass bool     `json:"break_glass"`
}

// CreateExport handles POST /exports (tier 3).
func (ctl *IGAHistoryController) CreateExport(c *gin.Context) {
	ctl.write(c, func(ws, actor uuid.UUID) (any, int, *audited, error) {
		var b historyExportBody
		if err := bindBody(c, &b, "{from, to, kinds?, reason, break_glass?}"); err != nil {
			return nil, 0, nil, err
		}
		params := map[string]any{"from": b.From, "to": b.To, "kinds": b.Kinds}
		return ctl.request(c, ws, actor, services.HistoryChangeRequest{Action: services.HistoryActionBulkExport, Params: params,
			Reason: b.Reason, BreakGlass: b.BreakGlass})
	})
}

type historyDecisionBody struct {
	Reason string `json:"reason"`
	Note   string `json:"note"`
}

func (ctl *IGAHistoryController) decide(c *gin.Context, event string, fn func(ws, actor, id uuid.UUID, b historyDecisionBody) (*services.HistoryApproval, error)) {
	ctl.write(c, func(ws, actor uuid.UUID) (any, int, *audited, error) {
		id, err := historyParamID(c)
		if err != nil {
			return nil, 0, nil, err
		}
		var b historyDecisionBody
		if c.Request.ContentLength > 0 {
			if err := bindBody(c, &b, "{reason?, note?}"); err != nil {
				return nil, 0, nil, err
			}
		}
		a, err := fn(ws, actor, id, b)
		if err != nil {
			return nil, 0, nil, err
		}
		return a, http.StatusOK, &audited{event, "iga_history_approval", a.ID.String(), nil,
			gin.H{"action": a.Action, "state": a.State, "result": a.Result}}, nil
	})
}

// Approve handles POST /history-approvals/:id/approve.
func (ctl *IGAHistoryController) Approve(c *gin.Context) {
	ctl.decide(c, "history.change_approved", func(ws, actor, id uuid.UUID, b historyDecisionBody) (*services.HistoryApproval, error) {
		return ctl.svc().Approve(c.Request.Context(), ws, actor, id, b.Reason)
	})
}

// Reject handles POST /history-approvals/:id/reject.
func (ctl *IGAHistoryController) Reject(c *gin.Context) {
	ctl.decide(c, "history.change_rejected", func(ws, actor, id uuid.UUID, b historyDecisionBody) (*services.HistoryApproval, error) {
		return ctl.svc().Reject(c.Request.Context(), ws, actor, id, b.Reason)
	})
}

// Withdraw handles POST /history-approvals/:id/withdraw.
func (ctl *IGAHistoryController) Withdraw(c *gin.Context) {
	ctl.decide(c, "history.change_withdrawn", func(ws, actor, id uuid.UUID, _ historyDecisionBody) (*services.HistoryApproval, error) {
		return ctl.svc().Withdraw(c.Request.Context(), ws, actor, id)
	})
}

// Review handles POST /history-approvals/:id/review.
func (ctl *IGAHistoryController) Review(c *gin.Context) {
	ctl.decide(c, "history.break_glass_reviewed", func(ws, actor, id uuid.UUID, b historyDecisionBody) (*services.HistoryApproval, error) {
		return ctl.svc().Review(c.Request.Context(), ws, actor, id, b.Note)
	})
}
