package platform

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// The owners routes of SPEC-iga-phase3-policy.md §7.1 (T3.07), under the
// gated /api/iga/v1/policy group:
//
//	GET    /owners?object_kind&object_id   governance:read  owners, incl. derived consumer owners
//	PUT    /owners                         iga:admin        the object's manual owners (set / clear)
//	PATCH  /owners/:id                     iga:admin        one owner's review date (DECISION, below)
//	GET    /owner-rules?cursor&limit       iga:admin        tag rules
//	POST   /owner-rules                    iga:admin        create a tag rule
//	DELETE /owner-rules/:id                iga:admin        delete a tag rule and the owners it assigned
//
// The workspace is the token's only; another workspace's object, owner or
// rule id is 404 not_found, never 403. Every mutation writes iga_gov_event in
// its transaction (the service) and auditAdminMutation (here), and requires a
// verified human member of the workspace (DECISION: an owner assignment and
// a rule are a person's decisions, recorded with their user id as
// created_by / actor; a service token is 403 forbidden).
//
// DECISION: PATCH /owners/:id is not in §7.1's table. It exists because
// missing_review_date's remedy is "Set review date" on an owner record
// (§2.5), which a tag-rule owner cannot otherwise get without being turned
// into a manual one by PUT.

// ownersService is the ownership service over this controller's database.
func (ctl *IGAGovPolicyController) ownersService() *services.IGAGovOwnershipService {
	return services.NewIGAGovOwnershipService(ctl.db())
}

// policyErr writes the §7 error envelope {error: {code, message, detail}}.
func policyErr(c *gin.Context, status int, code, msg string, detail gin.H) {
	if detail == nil {
		detail = gin.H{}
	}
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"code": code, "message": msg, "detail": detail}})
}

func policyNotFound(c *gin.Context) {
	policyErr(c, http.StatusNotFound, "not_found", "Not found.", nil)
}

func policyInternal(c *gin.Context, err error) {
	log.Printf("[policy] %s %s: %v", c.Request.Method, c.FullPath(), err)
	policyErr(c, http.StatusInternalServerError, "internal", "Internal error.", nil)
}

// policyWorkspace is the token's workspace, or a 401 written.
func policyWorkspace(c *gin.Context) (uuid.UUID, bool) {
	ws, ok := tokenWorkspace(c)
	if !ok {
		policyErr(c, http.StatusUnauthorized, "unauthenticated", "No workspace in the token.", nil)
	}
	return ws, ok
}

// policyActor is the verified human member making a mutation, or a 403/500
// written.
func (ctl *IGAGovPolicyController) policyActor(c *gin.Context, ws uuid.UUID) (uuid.UUID, bool) {
	uid, err := humanActor(c, ctl.db(), ws)
	if err != nil {
		if errors.Is(err, errNotWorkspaceHuman) {
			policyErr(c, http.StatusForbidden, "forbidden", "Owner changes require a verified workspace member session.", nil)
			return uuid.Nil, false
		}
		policyInternal(c, err)
		return uuid.Nil, false
	}
	id, err := uuid.Parse(uid)
	if err != nil {
		policyErr(c, http.StatusForbidden, "forbidden", "Owner changes require a verified workspace member session.", nil)
		return uuid.Nil, false
	}
	return id, true
}

// ownerServiceError maps a service error to the envelope.
func ownerServiceError(c *gin.Context, err error) {
	var in *services.OwnerInputError
	switch {
	case errors.As(err, &in):
		policyErr(c, http.StatusBadRequest, "invalid_parameter", in.Error(), gin.H{"parameter": in.Field, "reason": in.Reason})
	case errors.Is(err, services.ErrOwnerObjectNotFound), errors.Is(err, services.ErrOwnerNotFound),
		errors.Is(err, services.ErrOwnerRuleNotFound):
		policyNotFound(c)
	case errors.Is(err, services.ErrOwnerRuleExists):
		policyErr(c, http.StatusConflict, "owner_rule_exists", err.Error(), nil)
	default:
		policyInternal(c, err)
	}
}

func parseObjectRef(c *gin.Context, kind, id string) (string, uuid.UUID, bool) {
	if kind != models.GovObjectWorkload && kind != models.GovObjectIdentityAccount {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "object_kind must be workload or identity_account",
			gin.H{"parameter": "object_kind"})
		return "", uuid.Nil, false
	}
	oid, err := uuid.Parse(id)
	if err != nil || oid == uuid.Nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "object_id must be a UUID", gin.H{"parameter": "object_id"})
		return "", uuid.Nil, false
	}
	return kind, oid, true
}

// GetOwners handles GET /owners?object_kind&object_id.
func (ctl *IGAGovPolicyController) GetOwners(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	kind, id, ok := parseObjectRef(c, c.Query("object_kind"), c.Query("object_id"))
	if !ok {
		return
	}
	out, err := ctl.ownersService().Owners(c.Request.Context(), ws, kind, id)
	if err != nil {
		ownerServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "meta": gin.H{}})
}

type putOwnersBody struct {
	ObjectKind string `json:"object_kind"`
	ObjectID   string `json:"object_id"`
	Owners     *[]struct {
		UserID      string  `json:"user_id"`
		Role        string  `json:"role"`
		ReviewDueAt *string `json:"review_due_at"`
	} `json:"owners"`
}

func parseDue(c *gin.Context, field string, v *string) (*time.Time, bool) {
	if v == nil || *v == "" {
		return nil, true
	}
	t, err := time.Parse(time.RFC3339, *v)
	if err != nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", field+" must be an RFC 3339 time or null", gin.H{"parameter": field})
		return nil, false
	}
	return &t, true
}

// PutOwners handles PUT /owners: {object_kind, object_id, owners: [{user_id,
// role, review_due_at}]} -- the object's manual owners become exactly the
// list; [] clears them.
func (ctl *IGAGovPolicyController) PutOwners(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.policyActor(c, ws)
	if !ok {
		return
	}
	var b putOwnersBody
	if err := c.ShouldBindJSON(&b); err != nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "The body must be JSON: {object_kind, object_id, owners}.", gin.H{"parameter": "body"})
		return
	}
	kind, id, ok := parseObjectRef(c, b.ObjectKind, b.ObjectID)
	if !ok {
		return
	}
	if b.Owners == nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "owners is required ([] clears the manual owners)", gin.H{"parameter": "owners"})
		return
	}
	want := make([]services.OwnerAssignment, 0, len(*b.Owners))
	for i, o := range *b.Owners {
		uid, err := uuid.Parse(o.UserID)
		if err != nil || uid == uuid.Nil {
			field := "owners[" + strconv.Itoa(i) + "].user_id"
			policyErr(c, http.StatusBadRequest, "invalid_parameter", field+" must be a UUID", gin.H{"parameter": field})
			return
		}
		due, ok := parseDue(c, "owners["+strconv.Itoa(i)+"].review_due_at", o.ReviewDueAt)
		if !ok {
			return
		}
		want = append(want, services.OwnerAssignment{UserID: uid, Role: o.Role, ReviewDueAt: due})
	}
	change, err := ctl.ownersService().SetManualOwners(c.Request.Context(), ws, actor, kind, id, want)
	if err != nil {
		ownerServiceError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "set_owners", "iga_gov_owner", kind+":"+id.String(), http.StatusOK,
		change.Before.Owners, change.After.Owners)
	c.JSON(http.StatusOK, gin.H{"data": change.After, "meta": gin.H{}})
}

// PatchOwner handles PATCH /owners/:id: {review_due_at: <RFC 3339> | null}.
func (ctl *IGAGovPolicyController) PatchOwner(c *gin.Context) {
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
	var raw map[string]json.RawMessage
	if err := c.ShouldBindJSON(&raw); err != nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "The body must be JSON: {review_due_at}.", gin.H{"parameter": "body"})
		return
	}
	v, present := raw["review_due_at"]
	if !present || len(raw) != 1 {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "The body must be exactly {review_due_at: <RFC 3339 time> | null}.",
			gin.H{"parameter": "review_due_at"})
		return
	}
	var s *string
	if err := json.Unmarshal(v, &s); err != nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "review_due_at must be an RFC 3339 time or null", gin.H{"parameter": "review_due_at"})
		return
	}
	due, ok := parseDue(c, "review_due_at", s)
	if !ok {
		return
	}
	before, after, err := ctl.ownersService().SetReviewDate(c.Request.Context(), ws, actor, id, due)
	if err != nil {
		ownerServiceError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "set_review_date", "iga_gov_owner", id.String(), http.StatusOK, before, after)
	c.JSON(http.StatusOK, gin.H{"data": after, "meta": gin.H{}})
}

// ListOwnerRules handles GET /owner-rules?cursor&limit (cursor: the last id
// of the previous page; limit 1-200, default 200).
func (ctl *IGAGovPolicyController) ListOwnerRules(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	limit := 200
	if l := c.Query("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 200 {
			policyErr(c, http.StatusBadRequest, "invalid_parameter", "limit must be 1-200", gin.H{"parameter": "limit"})
			return
		}
		limit = n
	}
	after := uuid.Nil
	if cur := c.Query("cursor"); cur != "" {
		id, err := uuid.Parse(cur)
		if err != nil {
			policyErr(c, http.StatusBadRequest, "cursor_invalid", "The cursor is not valid.", gin.H{"parameter": "cursor"})
			return
		}
		after = id
	}
	rules, more, err := ctl.ownersService().ListRules(c.Request.Context(), ws, after, limit)
	if err != nil {
		policyInternal(c, err)
		return
	}
	var next any
	if more && len(rules) > 0 {
		next = rules[len(rules)-1].ID.String()
	}
	if rules == nil {
		rules = []models.IGAGovOwnerRule{}
	}
	c.JSON(http.StatusOK, gin.H{"data": rules, "meta": gin.H{"next_cursor": next}})
}

// CreateOwnerRule handles POST /owner-rules: {tag_key, applies_to?, role?}.
func (ctl *IGAGovPolicyController) CreateOwnerRule(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.policyActor(c, ws)
	if !ok {
		return
	}
	var b struct {
		TagKey    string `json:"tag_key"`
		AppliesTo string `json:"applies_to"`
		Role      string `json:"role"`
	}
	if err := c.ShouldBindJSON(&b); err != nil {
		policyErr(c, http.StatusBadRequest, "invalid_parameter", "The body must be JSON: {tag_key, applies_to, role}.", gin.H{"parameter": "body"})
		return
	}
	rule, err := ctl.ownersService().CreateRule(c.Request.Context(), ws, actor, b.TagKey, b.AppliesTo, b.Role)
	if err != nil {
		ownerServiceError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "create", "iga_gov_owner_rule", rule.ID.String(), http.StatusCreated, nil, rule)
	c.JSON(http.StatusCreated, gin.H{"data": rule, "meta": gin.H{}})
}

// DeleteOwnerRule handles DELETE /owner-rules/:id.
func (ctl *IGAGovPolicyController) DeleteOwnerRule(c *gin.Context) {
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
	rule, removed, err := ctl.ownersService().DeleteRule(c.Request.Context(), ws, actor, id)
	if err != nil {
		ownerServiceError(c, err)
		return
	}
	auditAdminMutation(c, ws.String(), "delete", "iga_gov_owner_rule", id.String(), http.StatusOK, rule, nil)
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"id": id, "deleted": true, "owners_removed": removed}, "meta": gin.H{}})
}
