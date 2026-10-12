package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

// The owner review routes of SPEC-iga-phase3-policy.md §7.4 (T3.12), under
// the gated /api/iga/v1/policy group:
//
//	GET  /reviews?mine=true&status&cursor&limit  member (mine) / governance:read (all)
//	GET  /reviews/:id                            an owner asked in it, or governance:read
//	POST /reviews/:id/respond                    an owner asked in it
//	POST /reviews/:id/exception                  governance:approve (not the version's author)
//	POST /reviews/:id/remind                     governance:author
//
// The workspace is the token's only; another workspace's review is 404.
// Every mutation needs a verified human member (the decision is a person's),
// writes its iga_gov_event in the service's transaction, and an
// audit_events row here (auditAdminMutation).
//
// DECISION: "member" routes (§7.4) carry no permission middleware; the
// handler decides: GET /reviews without mine=true, and GET /reviews/:id for
// a caller who is not an owner, fall back to governance:read -- the same
// middleware the other reads use, run in the handler.

func (ctl *IGAGovPolicyController) reviewService() *services.IGAGovOwnerReviewService {
	return services.NewIGAGovOwnerReviewService(ctl.db())
}

// govErrorOut renders a service error in the §7 envelope.
func govErrorOut(c *gin.Context, err error) {
	var ge *services.GovError
	switch {
	case errors.As(err, &ge):
		c.AbortWithStatusJSON(ge.Status, ge.Body())
	case errors.Is(err, services.ErrNotReviewOwner):
		policyErr(c, http.StatusForbidden, "not_review_owner", "Only an owner asked in this review can respond.", nil)
	default:
		policyInternal(c, err)
	}
}

// optionalHuman is the verified human behind the request, or uuid.Nil.
func (ctl *IGAGovPolicyController) optionalHuman(c *gin.Context, ws uuid.UUID) uuid.UUID {
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		return uuid.Nil
	}
	id, err := uuid.Parse(uid)
	if err != nil {
		return uuid.Nil
	}
	return id
}

// runFallback runs a permission middleware inside a handler; false when it
// denied (the response is written).
func runFallback(c *gin.Context, mw gin.HandlerFunc) bool {
	mw(c)
	return !c.IsAborted()
}

// strictJSON decodes the body refusing unknown members.
func strictJSON(c *gin.Context, dst any) error {
	raw, err := c.GetRawData()
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(dst)
}

// ListReviews handles GET /reviews.
func (ctl *IGAGovPolicyController) ListReviews(readPerm gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		ws, ok := policyWorkspace(c)
		if !ok {
			return
		}
		mine := c.Query("mine") == "true"
		var viewer uuid.UUID
		if mine {
			if viewer, ok = ctl.policyActor(c, ws); !ok {
				return
			}
		} else {
			if !runFallback(c, readPerm) {
				return
			}
			viewer = ctl.optionalHuman(c, ws)
		}
		limit, err := limitParam(c)
		if err != nil {
			govErrorOut(c, err)
			return
		}
		rows, next, err := ctl.reviewService().List(c.Request.Context(), ws,
			services.GovReviewFilter{Mine: mine, Viewer: viewer, Statuses: listParam(c, "status")}, c.Query("cursor"), limit, ctl.key)
		if err != nil {
			govErrorOut(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": rows, "meta": gin.H{"next_cursor": next}})
	}
}

// GetReview handles GET /reviews/:id.
func (ctl *IGAGovPolicyController) GetReview(readPerm gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		ws, ok := policyWorkspace(c)
		if !ok {
			return
		}
		id, err := uuid.Parse(c.Param("id"))
		if err != nil {
			policyNotFound(c)
			return
		}
		svc := ctl.reviewService()
		viewer := ctl.optionalHuman(c, ws)
		owner := false
		if viewer != uuid.Nil {
			if owner, err = svc.IsOwnerOf(ctl.db(), ws, id, viewer); err != nil {
				govErrorOut(c, err)
				return
			}
		} else if _, err := svc.View(c.Request.Context(), ws, id, uuid.Nil); err != nil {
			// Not found before permission: another workspace's id is 404 for everyone.
			govErrorOut(c, err)
			return
		}
		if !owner && !runFallback(c, readPerm) {
			return
		}
		v, err := svc.View(c.Request.Context(), ws, id, viewer)
		if err != nil {
			govErrorOut(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": v, "meta": gin.H{}})
	}
}

// RespondReview handles POST /reviews/:id/respond.
func (ctl *IGAGovPolicyController) RespondReview(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.policyActor(c, ws)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		policyNotFound(c)
		return
	}
	var in services.GovRespondInput
	if err := strictJSON(c, &in); err != nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter",
			"The body must be JSON: {response, retain_items, age_confirmations, route_confirmations, comment}.", gin.H{"parameter": "body"})
		return
	}
	in.Via = "ui"
	res, err := ctl.reviewService().Respond(c.Request.Context(), ws, actor, id, in)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "respond", "iga_gov_owner_review", id.String(), http.StatusOK, res.Before, res.Response)
	c.JSON(http.StatusOK, gin.H{"data": res, "meta": gin.H{}})
}

// ExceptReview handles POST /reviews/:id/exception: {reason}.
func (ctl *IGAGovPolicyController) ExceptReview(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.policyActor(c, ws)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		policyNotFound(c)
		return
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if err := strictJSON(c, &b); err != nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "The body must be JSON: {reason}.", gin.H{"parameter": "body"})
		return
	}
	before, after, err := ctl.reviewService().Except(c.Request.Context(), ws, actor, id, strings.TrimSpace(b.Reason))
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "except", "iga_gov_owner_review", id.String(), http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"data": after, "meta": gin.H{}})
}

// RemindReview handles POST /reviews/:id/remind.
func (ctl *IGAGovPolicyController) RemindReview(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.policyActor(c, ws)
	if !ok {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		policyNotFound(c)
		return
	}
	reminded, err := ctl.reviewService().Remind(c.Request.Context(), ws, actor, id)
	if err != nil {
		govErrorOut(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "remind", "iga_gov_owner_review", id.String(), http.StatusOK, nil, gin.H{"reminded_user_ids": reminded})
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"review_id": id, "reminded_user_ids": reminded}, "meta": gin.H{}})
}
