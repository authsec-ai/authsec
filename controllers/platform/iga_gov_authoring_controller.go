package platform

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

// The §7.3 policies, versions and plans routes (T3.11) and the §7.5
// approval routes (T3.13), under the gated /api/iga/v1/policy group:
//
//	GET   /policies                                  governance:read    Phase 3 policies, cursor-paged
//	POST  /proposals                                 governance:author  from findings, a template or Discovery context
//	GET   /policies/:id                              governance:read    policy, current version, controls
//	PATCH /policies/:id                              governance:author  {name?, purpose?, owner_user_id?}
//	POST  /policies/:id/pause | /resume              governance:enforce {reason}
//	POST  /policies/:id/archive                      governance:author  409 policy_controls_roles
//	GET   /policies/:id/versions[/:no]               governance:read
//	POST  /policies/:id/versions                     governance:author  {intent, base_version_no}; 409 version_conflict
//	POST  /policies/:id/versions/:no/propose         governance:author  compile from live reads and fresh bundles
//	GET   /policies/:id/versions/:no/plans           governance:read    plans, acceptance items, hashes to approve
//	POST  /policies/:id/versions/:no/withdraw        governance:author
//	GET   /approvals?status                          governance:approve versions awaiting the caller
//	POST  /policies/:id/versions/:no/approve         governance:approve hashes + acceptances; 403 self_approval
//	POST  /policies/:id/versions/:no/reject          governance:approve {reason}
//
// The workspace is the token's only; another workspace's id is 404. Every
// mutation requires a verified human member (the actor recorded as author,
// approver or acceptor), writes iga_gov_event in its transaction (the
// service) and audit_events through auditAdminMutation (here).

func (ctl *IGAGovPolicyController) authoring() *services.GovAuthoring {
	var live services.LiveReader
	if ctl.live != nil {
		live = ctl.live()
	}
	return services.NewGovAuthoring(ctl.db(), live)
}

// govError writes a service error in the §7 envelope.
func govError(c *gin.Context, err error) {
	var ge *services.GovError
	if errors.As(err, &ge) {
		c.AbortWithStatusJSON(ge.Status, ge.Body())
		return
	}
	log.Printf("[policy] %s %s: %v", c.Request.Method, c.FullPath(), err)
	c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": gin.H{
		"code": "internal_error", "message": "The request could not be completed.", "detail": gin.H{}}})
}

// mutationActor is the verified human member making a policy decision.
func (ctl *IGAGovPolicyController) mutationActor(c *gin.Context, ws uuid.UUID) (uuid.UUID, bool) {
	uid, err := humanActor(c, ctl.db(), ws)
	if err == nil {
		if id, perr := uuid.Parse(uid); perr == nil {
			return id, true
		}
	}
	if err != nil && !errors.Is(err, errNotWorkspaceHuman) {
		policyInternal(c, err)
		return uuid.Nil, false
	}
	policyErr(c, http.StatusForbidden, "forbidden", "Policy changes and decisions require a verified workspace member session.", nil)
	return uuid.Nil, false
}

// govMetaKey carries a mutation's response meta (e.g. evaluated_rev).
const govMetaKey = "gov_mutation_meta"

// audited is what a mutation reports to auditAdminMutation.
type audited struct {
	action, resource, id string
	before, after        any
}

// govMutation runs a mutating route: token workspace, verified human actor,
// the service call, the audit row, and the {data, meta} envelope.
func (ctl *IGAGovPolicyController) govMutation(c *gin.Context, status int, fn func(ws, actor uuid.UUID) (any, *audited, error)) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	actor, ok := ctl.mutationActor(c, ws)
	if !ok {
		return
	}
	data, au, err := fn(ws, actor)
	if err != nil {
		govError(c, err)
		return
	}
	if au != nil {
		auditAdminMutation(c, ws.String(), au.action, au.resource, au.id, status, au.before, au.after)
	}
	meta := gin.H{}
	if m, ok := c.Get(govMetaKey); ok {
		if mm, ok := m.(gin.H); ok {
			meta = mm
		}
	}
	c.JSON(status, gin.H{"data": data, "meta": meta})
}

func bindBody(c *gin.Context, v any, shape string) error {
	if err := c.ShouldBindJSON(v); err != nil {
		return services.GovBadParam("body", "The body must be JSON: "+shape+".")
	}
	return nil
}

func versionNoParam(c *gin.Context) (int, error) {
	n, err := strconv.Atoi(c.Param("no"))
	if err != nil || n <= 0 {
		return 0, services.GovNotFound()
	}
	return n, nil
}

/* --------------------------------- reads ---------------------------------- */

// ListPolicies handles GET /policies.
func (ctl *IGAGovPolicyController) ListPolicies(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		limit, err := limitParam(c)
		if err != nil {
			return nil, nil, err
		}
		list, next, err := ctl.authoring().ListPolicies(c.Request.Context(), ws, services.GovPolicyFilter{
			Family: c.Query("family"), Provider: c.Query("provider"), Status: c.Query("status"), Lifecycle: c.Query("lifecycle"),
			Q: c.Query("q"), Cursor: c.Query("cursor"), Limit: limit})
		if err != nil {
			return nil, nil, err
		}
		return list, gin.H{"next_cursor": next}, nil
	})
}

// GetPolicy handles GET /policies/:id.
func (ctl *IGAGovPolicyController) GetPolicy(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		p, err := ctl.authoring().GetPolicy(c.Request.Context(), ws, id)
		return p, nil, err
	})
}

// ListVersions handles GET /policies/:id/versions.
func (ctl *IGAGovPolicyController) ListVersions(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		vs, err := ctl.authoring().ListVersions(c.Request.Context(), ws, id)
		return vs, gin.H{"next_cursor": nil}, err
	})
}

// GetVersion handles GET /policies/:id/versions/:no.
func (ctl *IGAGovPolicyController) GetVersion(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		no, err := versionNoParam(c)
		if err != nil {
			return nil, nil, err
		}
		v, err := ctl.authoring().GetVersion(c.Request.Context(), ws, id, no)
		return v, nil, err
	})
}

// VersionPlans handles GET /policies/:id/versions/:no/plans.
func (ctl *IGAGovPolicyController) VersionPlans(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		no, err := versionNoParam(c)
		if err != nil {
			return nil, nil, err
		}
		p, err := ctl.authoring().Plans(c.Request.Context(), ws, id, no)
		return p, nil, err
	})
}

// ListApprovals handles GET /approvals?status=pending|decided (T3.13).
func (ctl *IGAGovPolicyController) ListApprovals(c *gin.Context) {
	ws, ok := policyWorkspace(c)
	if !ok {
		return
	}
	caller, ok := ctl.mutationActor(c, ws)
	if !ok {
		return
	}
	limit, err := limitParam(c)
	if err != nil {
		govError(c, err)
		return
	}
	list, next, err := ctl.authoring().ListApprovals(c.Request.Context(), ws, caller, c.Query("status"), c.Query("cursor"), limit)
	if err != nil {
		govError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": list, "meta": gin.H{"next_cursor": next}})
}

/* ------------------------------- mutations -------------------------------- */

// CreateProposal handles POST /proposals.
func (ctl *IGAGovPolicyController) CreateProposal(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		var req services.ProposalRequest
		if err := bindBody(c, &req, "{from: {finding_ids}} | {template, keys} | {context: {object_id}}"); err != nil {
			return nil, nil, err
		}
		res, err := ctl.authoring().CreateProposal(c.Request.Context(), ws, actor, req)
		if err != nil {
			return nil, nil, err
		}
		c.Set(govMetaKey, gin.H{"evaluated_rev": res.EvaluatedRev})
		return res, &audited{"create_proposal", "iga_gov_policy", res.Policy.ID.String(), nil, res.Version}, nil
	})
}

// PatchPolicy handles PATCH /policies/:id.
func (ctl *IGAGovPolicyController) PatchPolicy(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var raw map[string]json.RawMessage
		if err := bindBody(c, &raw, "{name?, purpose?, owner_user_id?}"); err != nil {
			return nil, nil, err
		}
		var p services.GovPolicyPatch
		for k, v := range raw {
			switch k {
			case "name", "purpose":
				var s string
				if err := json.Unmarshal(v, &s); err != nil {
					return nil, nil, services.GovBadParam(k, k+" must be a string.")
				}
				if k == "name" {
					p.Name = &s
				} else {
					p.Purpose = &s
				}
			case "owner_user_id":
				var s *string
				if err := json.Unmarshal(v, &s); err != nil {
					return nil, nil, services.GovBadParam(k, "owner_user_id must be a uuid or null.")
				}
				if s == nil {
					p.ClearOwner = true
					continue
				}
				u, err := uuid.Parse(*s)
				if err != nil {
					return nil, nil, services.GovBadParam(k, "owner_user_id must be a uuid or null.")
				}
				p.OwnerUserID = &u
			default:
				return nil, nil, services.GovBadParam(k, "Only name, purpose and owner_user_id can be changed.")
			}
		}
		before, after, err := ctl.authoring().PatchPolicy(c.Request.Context(), ws, actor, id, p)
		if err != nil {
			return nil, nil, err
		}
		return after, &audited{"update", "iga_gov_policy", id.String(), before, after}, nil
	})
}

func (ctl *IGAGovPolicyController) lifecycle(c *gin.Context, to string) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			Reason string `json:"reason"`
		}
		if err := bindBody(c, &b, "{reason}"); err != nil {
			return nil, nil, err
		}
		p, err := ctl.authoring().SetLifecycle(c.Request.Context(), ws, actor, id, to, b.Reason)
		if err != nil {
			return nil, nil, err
		}
		action := "pause"
		if to == "active" {
			action = "resume"
		}
		return p, &audited{action, "iga_gov_policy", id.String(), nil, gin.H{"lifecycle": to, "reason": b.Reason}}, nil
	})
}

// PausePolicy handles POST /policies/:id/pause.
func (ctl *IGAGovPolicyController) PausePolicy(c *gin.Context) { ctl.lifecycle(c, "paused") }

// ResumePolicy handles POST /policies/:id/resume.
func (ctl *IGAGovPolicyController) ResumePolicy(c *gin.Context) { ctl.lifecycle(c, "active") }

// ArchivePolicy handles POST /policies/:id/archive.
func (ctl *IGAGovPolicyController) ArchivePolicy(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			Reason string `json:"reason"`
		}
		_ = c.ShouldBindJSON(&b) // the reason is optional
		p, err := ctl.authoring().ArchivePolicy(c.Request.Context(), ws, actor, id, b.Reason)
		if err != nil {
			return nil, nil, err
		}
		return p, &audited{"archive", "iga_gov_policy", id.String(), nil, gin.H{"lifecycle": "archived"}}, nil
	})
}

// CreateVersion handles POST /policies/:id/versions.
func (ctl *IGAGovPolicyController) CreateVersion(c *gin.Context) {
	ctl.govMutation(c, http.StatusCreated, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			Intent        json.RawMessage `json:"intent"`
			BaseVersionNo *int            `json:"base_version_no"`
		}
		if err := bindBody(c, &b, "{intent, base_version_no}"); err != nil {
			return nil, nil, err
		}
		if b.BaseVersionNo == nil {
			return nil, nil, services.GovBadParam("base_version_no", "base_version_no is required (the version you edited).")
		}
		if len(b.Intent) == 0 {
			return nil, nil, services.GovBadParam("intent", "intent is required.")
		}
		v, err := ctl.authoring().CreateVersion(c.Request.Context(), ws, actor, id, *b.BaseVersionNo, b.Intent)
		if err != nil {
			return nil, nil, err
		}
		return v, &audited{"create_version", "iga_gov_policy_version", v.ID.String(), nil, gin.H{"policy_id": id, "no": v.No,
			"intent_hash": v.IntentHash, "base_version_no": *b.BaseVersionNo}}, nil
	})
}

// ProposeVersion handles POST /policies/:id/versions/:no/propose.
func (ctl *IGAGovPolicyController) ProposeVersion(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		no, err := versionNoParam(c)
		if err != nil {
			return nil, nil, err
		}
		res, err := ctl.authoring().Propose(c.Request.Context(), ws, actor, id, no)
		if err != nil {
			return nil, nil, err
		}
		return res, &audited{"propose", "iga_gov_policy_version", res.Version.ID.String(), nil,
			gin.H{"status": res.Version.Status, "hashes": res.Plans.Hashes}}, nil
	})
}

// WithdrawVersion handles POST /policies/:id/versions/:no/withdraw.
func (ctl *IGAGovPolicyController) WithdrawVersion(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		no, err := versionNoParam(c)
		if err != nil {
			return nil, nil, err
		}
		var b struct {
			Reason string `json:"reason"`
		}
		_ = c.ShouldBindJSON(&b)
		v, err := ctl.authoring().WithdrawVersion(c.Request.Context(), ws, actor, id, no, b.Reason)
		if err != nil {
			return nil, nil, err
		}
		return v, &audited{"withdraw", "iga_gov_policy_version", v.ID.String(), nil, gin.H{"status": v.Status, "reason": b.Reason}}, nil
	})
}
