package platform

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/config"
	"github.com/authsec-ai/authsec/internal/authz"
	"github.com/authsec-ai/authsec/middlewares"
	"github.com/authsec-ai/authsec/services"
)

// Tiers on the wire (SPEC-secops-backend-upgrade.md P3, W5;
// services/governance_tiers.go holds the map).
//
// TierGuard runs on every route of the tiered surfaces, after
// AuthMiddleware and before the route's own permission middleware (which
// stays: the right of each tier-0/1 route is the one it had). It
//
//   - marks the request context as a person's or an automation identity's
//     (middlewares.IsAutomationIdentity), so the second-person rule
//     (services.CheckApprover, CheckTier3Requester) can refuse an automation
//     identity whatever route reached it;
//   - looks the route up in the tier map: a write route the map does not name
//     is refused (403 tier_unmapped; fail closed); reads pass;
//   - applies RequireTier for the route's action.
//
// RequireTier is also called by a handler whose tier depends on its body
// (identity-level containment is tier 2).
const (
	govTierActionKey = "governance_action"
	govTierKey       = "governance_tier"
)

// TierGuard is the tier middleware of the tiered surfaces.
func TierGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		automation := middlewares.IsAutomationIdentity(c)
		c.Request = c.Request.WithContext(services.WithGovActorAutomation(c.Request.Context(), automation))
		action, ok := services.GovRouteAction(c.Request.Method, c.FullPath())
		if !ok {
			if !services.GovIsWriteMethod(c.Request.Method) || c.FullPath() == "" {
				c.Next()
				return
			}
			log.Printf("[tiers] refused %s %s: the route has no tier", c.Request.Method, c.FullPath())
			policyErr(c, http.StatusForbidden, "tier_unmapped", "This action has no governance tier; it is refused until it has one.", nil)
			return
		}
		if !RequireTier(c, action) {
			return
		}
		c.Next()
	}
}

// RequireTier applies action's tier to the request and reports whether it may
// go on; when not, the response is written (and the request aborted).
//
//	tier 0, 1  the route's own right (as today); automation identities allowed
//	tier 2     a person (never an automation identity) with the route's right
//	tier 3     a person; the service applies the second-person rule
//	tier 4     a person holding governance:remediate
func RequireTier(c *gin.Context, action string) bool {
	if err := TierError(c, action); err != nil {
		govErrorOut(c, err)
		return false
	}
	return true
}

// TierError is RequireTier's decision as an error (nil: allowed), for a
// handler that writes its own errors.
func TierError(c *gin.Context, action string) error {
	a, ok := services.GovActionFor(action)
	if !ok {
		return fmt.Errorf("tiers: action %q is not in the tier map", action)
	}
	automation := middlewares.IsAutomationIdentity(c)
	if automation {
		c.Request = c.Request.WithContext(services.WithGovActorAutomation(c.Request.Context(), true))
	}
	if automation && a.Tier > services.GovTier1 {
		return services.NewGovError(http.StatusForbidden, services.GovCodeAutomationTier,
			"An automation identity may perform tier-0 and tier-1 actions only; a person must do this.",
			map[string]any{"action": action, "tier": a.Tier})
	}
	if a.Tier == services.GovTier4 && !authz.Allows(c, "governance", "remediate") {
		return services.NewGovError(http.StatusForbidden, "forbidden", "This action writes to your cloud: it needs governance:remediate.",
			map[string]any{"required_permissions": []string{"governance:remediate"}, "action": action})
	}
	c.Set(govTierActionKey, action)
	c.Set(govTierKey, int(a.Tier))
	return nil
}

/* ------------------------------------------------------------------------- */
/*                                 Approvals                                  */
/* ------------------------------------------------------------------------- */

// Approvals inbox routes, under /api/iga/v1 (services/governance_approvals.go):
//
//	GET  /approvals?kind=                          governance:read  pending second-person requests of every kind
//	GET  /approvals/reviews?kind=&overdue=true     governance:read  break-glass changes awaiting their review
//	POST /approvals/reviews/:kind/:id  {note?}     governance:approve, a second person (tier 3)
//
// The workspace is the token's; another workspace's request is never listed
// and its id is 404.

// ApprovalsController serves the routes above.
type ApprovalsController struct {
	db func() *gorm.DB
}

// NewApprovalsControllerFor builds the controller over the graph controller's
// database.
func NewApprovalsControllerFor(g *IGAGraphReadController) *ApprovalsController {
	return &ApprovalsController{db: g.db}
}

// NewApprovalsController is the production controller (config.DB).
func NewApprovalsController() *ApprovalsController {
	// TENANT-EXEMPT: not a statement: the handle the service opens its workspace transactions on.
	return &ApprovalsController{db: func() *gorm.DB { return config.DB }}
}

// MountApprovalsRoutes mounts the routes on g (the authenticated /api/iga/v1
// group) behind the tier guard.
func MountApprovalsRoutes(g *gin.RouterGroup, ctl *ApprovalsController) {
	a := g.Group("/approvals", TierGuard())
	read := middlewares.Require("governance", "read")
	a.GET("", read, ctl.List)
	a.GET("/reviews", read, ctl.ListReviews)
	a.POST("/reviews/:kind/:id", middlewares.Require("governance", "approve"), ctl.Review)
}

// TENANT-EXEMPT: not a statement here: the service runs every statement in a transaction under row-level security for the token's workspace.
func (ctl *ApprovalsController) svc() *services.ApprovalsService {
	return services.NewApprovalsService(ctl.db())
}

// List handles GET /approvals.
func (ctl *ApprovalsController) List(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	rows, err := ctl.svc().Pending(c.Request.Context(), ws, c.Query("kind"))
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "meta": gin.H{"kinds": services.ApprovalKinds()}})
}

// ListReviews handles GET /approvals/reviews.
func (ctl *ApprovalsController) ListReviews(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	overdue := false
	switch strings.ToLower(c.Query("overdue")) {
	case "", "false":
	case "true":
		overdue = true
	default:
		govErrorOut(c, services.GovBadParam("overdue", "overdue must be true or false."))
		return
	}
	rows, err := ctl.svc().Reviews(c.Request.Context(), ws, c.Query("kind"), overdue)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// Review handles POST /approvals/reviews/:kind/:id: the review of a
// break-glass change by a second person. Coverage declarations, audit
// changes and history changes are reviewed by their own handlers (same
// rule, their own audit records); the other kinds here.
func (ctl *ApprovalsController) Review(c *gin.Context) {
	kind := c.Param("kind")
	if !services.IsApprovalKind(kind) {
		govErrorOut(c, services.ApprovalKindError())
		return
	}
	switch kind {
	case services.ApprovalKindCoverageDeclare:
		(&AgentEvidenceController{db: ctl.db}).Review(c)
		return
	case services.ApprovalKindAuditChange:
		(&AuditGovernanceController{db: ctl.db}).ReviewChange(c)
		return
	case services.ApprovalKindHistoryChange:
		(&IGAHistoryController{db: ctl.db}).Review(c)
		return
	}
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		policyNotFound(c)
		return
	}
	// TENANT-EXEMPT: not a statement here: humanActor checks the membership under the token's workspace (tenancy.QueryRowContext).
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			policyErr(c, http.StatusForbidden, "forbidden", "Reviewing a change requires a verified workspace member session.", nil)
			return
		}
		policyInternal(c, err)
		return
	}
	reviewer, err := uuid.Parse(uid)
	if err != nil {
		policyErr(c, http.StatusForbidden, "forbidden", "Reviewing a change requires a verified workspace member session.", nil)
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	if c.Request.ContentLength != 0 {
		if err := strictJSON(c, &body); err != nil {
			govErrorOut(c, services.GovBadParam("body", `The body must be JSON: {"note": "..."}.`))
			return
		}
	}
	out, err := ctl.svc().ReviewBreakGlass(c.Request.Context(), ws, kind, id, reviewer, body.Note)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "approvals.break_glass_review", kind, id.String(), http.StatusOK, nil, out)
	c.JSON(http.StatusOK, gin.H{"data": out})
}
