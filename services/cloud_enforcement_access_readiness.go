package services

import (
	"context"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// Access-policy readiness (GET /access-policies/readiness): per AWS account
// of the workspace, whether its enforcement binding can apply access
// policies -- verified, template v2, the grants capability proven
// (RequireEnforcementV2). It lives outside the iga_* files because it reads
// cloud_enforcement_binding and cloud_connector.

// AccessReadinessAccount is one AWS account.
type AccessReadinessAccount struct {
	AccountID       string    `json:"account_id"`
	ConnectorID     uuid.UUID `json:"connector_id"`
	BindingState    string    `json:"binding_state"`
	TemplateVersion string    `json:"template_version"`
	Ready           bool      `json:"ready"`
	Reason          string    `json:"reason"`
}

// AccessReadiness is the readiness view.
type AccessReadiness struct {
	Available bool                     `json:"available"`
	Reason    string                   `json:"reason"`
	Accounts  []AccessReadinessAccount `json:"accounts"`
}

// AccessPolicyReadiness reads the workspace's AWS accounts and bindings.
func AccessPolicyReadiness(ctx context.Context, db *gorm.DB, ws uuid.UUID) (*AccessReadiness, error) {
	out := &AccessReadiness{Accounts: []AccessReadinessAccount{}}
	out.Available, out.Reason = AccessPoliciesStatus(db)
	var conns []models.CloudConnector
	if err := db.WithContext(ctx).Where("workspace_id = ? AND provider = ? AND scope_kind = ? AND status = ?", ws, "aws", "account", "active").
		Order("scope_id").Find(&conns).Error; err != nil {
		return nil, err
	}
	for _, c := range conns {
		a := AccessReadinessAccount{AccountID: c.ScopeID, ConnectorID: c.ID, BindingState: "none"}
		var b []models.CloudEnforcementBinding
		if err := db.WithContext(ctx).Where("workspace_id = ? AND connector_id = ? AND state <> ?", ws, c.ID,
			models.EnforcementBindingRevoked).Order("updated_at DESC").Limit(1).Find(&b).Error; err != nil {
			return nil, err
		}
		if len(b) > 0 {
			a.BindingState, a.TemplateVersion = b[0].State, b[0].TemplateVersion
		}
		if err := RequireEnforcementV2(ctx, db, ws, c.ID, EnforcementFeatureGrants); err != nil {
			code, _ := errCode(accessBindingErr(err))
			a.Reason = code
		} else {
			a.Ready = true
		}
		out.Accounts = append(out.Accounts, a)
	}
	return out, nil
}
