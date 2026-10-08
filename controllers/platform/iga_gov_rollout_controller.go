package platform

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

// The §7.5 rollout routes (T3.15), under the gated /api/iga/v1/policy group:
//
//	GET  /policies/:id/rollout[?version_no]  governance:read    the active (else newest) rollout, deployments, acceptances, actions
//	POST /policies/:id/rollout/start         governance:enforce {version_no?, reason?}: observation, or the canary once approved and observed
//	POST /policies/:id/rollout/expand        governance:enforce {accept_not_available: [{gate, reason}], reason?}; 409 gates_not_passed
//	POST /policies/:id/rollout/pause         governance:enforce {reason}
//	POST /policies/:id/rollout/resume        governance:enforce {reason}
//
// The workspace is the token's only; another workspace's policy is 404.
// Every mutation requires a verified human member, writes iga_gov_event in
// its transaction (the service) and audit_events (here).

func (ctl *IGAGovPolicyController) rollout() *services.GovRollout {
	var live services.LiveReader
	if ctl.live != nil {
		live = ctl.live()
	}
	return services.NewGovRollout(ctl.db(), live)
}

func rolloutAudit(action string, v *services.GovRolloutView, extra gin.H) *audited {
	after := gin.H{"stage": v.Rollout.Stage, "version_no": v.VersionNo}
	for k, x := range extra {
		after[k] = x
	}
	if v.Rollout.ID == uuid.Nil {
		// A remove_control version has no rollout row: audit the policy.
		return &audited{action, "iga_gov_policy", v.PolicyID.String(), nil, after}
	}
	return &audited{action, "iga_gov_rollout", v.Rollout.ID.String(), nil, after}
}

// GetRollout handles GET /policies/:id/rollout.
func (ctl *IGAGovPolicyController) GetRollout(c *gin.Context) {
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var no *int
		if s := c.Query("version_no"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 {
				return nil, nil, services.GovBadParam("version_no", "version_no must be a positive integer.")
			}
			no = &n
		}
		v, err := ctl.rollout().Get(c.Request.Context(), ws, id, no)
		return v, nil, err
	})
}

// StartRollout handles POST /policies/:id/rollout/start.
func (ctl *IGAGovPolicyController) StartRollout(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var in services.GovRolloutStartInput
		if c.Request.ContentLength != 0 {
			if err := bindBody(c, &in, "{version_no?, reason?}"); err != nil {
				return nil, nil, err
			}
		}
		v, err := ctl.rollout().Start(c.Request.Context(), ws, actor, id, in)
		if err != nil {
			return nil, nil, err
		}
		return v, rolloutAudit("rollout_start", v, gin.H{"reason": in.Reason}), nil
	})
}

// ExpandRollout handles POST /policies/:id/rollout/expand.
func (ctl *IGAGovPolicyController) ExpandRollout(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var in services.GovRolloutExpandInput
		if c.Request.ContentLength != 0 {
			if err := bindBody(c, &in, "{accept_not_available: [{gate, reason}], reason?}"); err != nil {
				return nil, nil, err
			}
		}
		v, err := ctl.rollout().Expand(c.Request.Context(), ws, actor, id, in)
		if err != nil {
			return nil, nil, err
		}
		return v, rolloutAudit("rollout_expand", v, gin.H{"accepted_gates": in.AcceptNotAvailable, "reason": in.Reason}), nil
	})
}

// PauseRollout handles POST /policies/:id/rollout/pause.
func (ctl *IGAGovPolicyController) PauseRollout(c *gin.Context) {
	ctl.rolloutReason(c, "rollout_pause")
}

// ResumeRollout handles POST /policies/:id/rollout/resume.
func (ctl *IGAGovPolicyController) ResumeRollout(c *gin.Context) {
	ctl.rolloutReason(c, "rollout_resume")
}

func (ctl *IGAGovPolicyController) rolloutReason(c *gin.Context, action string) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		var in services.GovRolloutReasonInput
		if err := bindBody(c, &in, "{reason}"); err != nil {
			return nil, nil, err
		}
		var v *services.GovRolloutView
		if action == "rollout_pause" {
			v, err = ctl.rollout().Pause(c.Request.Context(), ws, actor, id, in.Reason)
		} else {
			v, err = ctl.rollout().Resume(c.Request.Context(), ws, actor, id, in.Reason)
		}
		if err != nil {
			return nil, nil, err
		}
		return v, rolloutAudit(action, v, gin.H{"reason": in.Reason}), nil
	})
}
