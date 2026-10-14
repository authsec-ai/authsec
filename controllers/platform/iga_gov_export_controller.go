package platform

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/services"
)

// ExportVersion handles GET /policies/:id/versions/:no/export (§7.3, J1;
// T3.17): every approved target's boundary document, AWS CLI and Terraform
// snippets. With ?download=<plan_id>, that plan's artifact is returned as a
// JSON file attachment (the "downloadable artifact per plan").
func (ctl *IGAGovPolicyController) ExportVersion(c *gin.Context) {
	if dl := c.Query("download"); dl != "" {
		ws, ok := tokenWorkspace(c)
		if !ok {
			policyErr(c, http.StatusUnauthorized, "unauthenticated", "No workspace in the token.", nil)
			return
		}
		planID, err := uuid.Parse(dl)
		if err != nil {
			govError(c, services.GovBadParam("download", "download must be a plan id of this version."))
			return
		}
		id, err := uuidParam(c, "id")
		if err != nil {
			govError(c, err)
			return
		}
		no, err := versionNoParam(c)
		if err != nil {
			govError(c, err)
			return
		}
		v, err := ctl.authoring().ExportVersion(c.Request.Context(), ws, id, no)
		if err != nil {
			govError(c, err)
			return
		}
		for _, p := range v.Plans {
			if p.PlanID == planID {
				raw, _ := json.MarshalIndent(p, "", "  ")
				c.Header("Content-Disposition", `attachment; filename="authsec-plan-`+planID.String()+`.json"`)
				c.Data(http.StatusOK, "application/json", raw)
				return
			}
		}
		govError(c, services.GovNotFound())
		return
	}
	govCall(c, func(ws uuid.UUID) (any, any, error) {
		id, err := uuidParam(c, "id")
		if err != nil {
			return nil, nil, err
		}
		no, err := versionNoParam(c)
		if err != nil {
			return nil, nil, err
		}
		v, err := ctl.authoring().ExportVersion(c.Request.Context(), ws, id, no)
		return v, nil, err
	})
}
