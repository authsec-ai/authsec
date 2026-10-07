package platform

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

// The §7.5 approval decisions (T3.13): approve binds the intent, impact,
// plan and material hashes the approver saw plus one acceptance per
// unanalysed item and evidence gap; the author can never decide (403
// self_approval, admins included); a hash that changed since the approver
// loaded the plans is 409 impact_changed / plan_changed. GET /approvals is
// in iga_gov_authoring_controller.go with the other reads.

// ApproveVersion handles POST /policies/:id/versions/:no/approve.
func (ctl *IGAGovPolicyController) ApproveVersion(c *gin.Context) {
	ctl.govMutation(c, http.StatusOK, func(ws, actor uuid.UUID) (any, *audited, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		no, err := versionNoParam(c)
		if err != nil {
			return nil, nil, err
		}
		var req services.GovApproveRequest
		if err := bindBody(c, &req, "{intent_hash, impact_hashes, plan_hashes, material_hashes, acceptances, reason?}"); err != nil {
			return nil, nil, err
		}
		req.Channel = "ui"
		res, err := ctl.authoring().Approve(c.Request.Context(), ws, actor, id, no, req)
		if err != nil {
			return nil, nil, err
		}
		return res, &audited{"approve", "iga_gov_policy_version", res.Version.ID.String(), nil,
			gin.H{"approval_id": res.Approval.ID, "acceptances": len(res.Acceptances), "plan_hashes": res.Approval.PlanHashes}}, nil
	})
}

// RejectVersion handles POST /policies/:id/versions/:no/reject.
func (ctl *IGAGovPolicyController) RejectVersion(c *gin.Context) {
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
		if err := bindBody(c, &b, "{reason}"); err != nil {
			return nil, nil, err
		}
		ap, err := ctl.authoring().Reject(c.Request.Context(), ws, actor, id, no, b.Reason)
		if err != nil {
			return nil, nil, err
		}
		return ap, &audited{"reject", "iga_gov_policy_version", ap.VersionID.String(), nil, gin.H{"approval_id": ap.ID, "reason": ap.Reason}}, nil
	})
}
