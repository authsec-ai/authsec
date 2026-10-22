package services

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/tenancy"
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

// AccessReadinessAzureSubscription is one connected Azure subscription:
// ready when AuthSec's Azure app can write and delete role assignments on it
// (the live check the preview runs, cached for a minute).
type AccessReadinessAzureSubscription struct {
	SubscriptionID string    `json:"subscription_id"`
	Name           string    `json:"name"`
	ConnectorID    uuid.UUID `json:"connector_id"`
	Ready          bool      `json:"ready"`
	Reason         string    `json:"reason"`
}

// AccessReadiness is the readiness view.
type AccessReadiness struct {
	Available          bool                               `json:"available"`
	Reason             string                             `json:"reason"`
	Accounts           []AccessReadinessAccount           `json:"accounts"`
	AzureSubscriptions []AccessReadinessAzureSubscription `json:"azure_subscriptions"`
}

// AccessPolicyReadiness reads the workspace's AWS accounts and bindings.
func AccessPolicyReadiness(ctx context.Context, db *gorm.DB, ws uuid.UUID) (*AccessReadiness, error) {
	out := &AccessReadiness{Accounts: []AccessReadinessAccount{}, AzureSubscriptions: []AccessReadinessAzureSubscription{}}
	// TENANT-EXEMPT: the 137 schema check reads the Postgres catalog only.
	out.Available, out.Reason = AccessPoliciesStatus(db)
	var subs []models.CloudConnector
	err := tenancy.InWorkspaceRead(ctx, db, ws, func(tx *gorm.DB) error {
		if err := accessReadinessTx(ctx, tx, ws, out); err != nil {
			return err
		}
		return tx.Where("workspace_id = ? AND provider = ? AND scope_kind = ? AND status = ?", ws, models.CloudProviderAzure,
			models.CloudScopeSubscription, models.CloudConnectorActive).Order("scope_id").Find(&subs).Error
	})
	if err != nil {
		return out, err
	}
	// The Azure checks call Azure, so they run after the transaction.
	// TENANT-EXEMPT: the 144 schema check reads the Postgres catalog only.
	schemaOK, schemaReason := AzureAccessSchemaStatus(db)
	for _, c := range subs {
		var attrs models.AzureSubscriptionAttrs
		_ = json.Unmarshal(c.Attrs, &attrs)
		tenant := attrs.TenantID
		if tenant == "" && c.ParentScopeID != nil {
			tenant = *c.ParentScopeID
		}
		s := AccessReadinessAzureSubscription{SubscriptionID: c.ScopeID, Name: attrs.DisplayName, ConnectorID: c.ID}
		if s.Name == "" {
			s.Name = c.ScopeID
		}
		switch {
		case !schemaOK:
			s.Reason = GovCodeAccessUnavailable + ": " + schemaReason
		default:
			s.Ready, s.Reason = azureWriteReady(ctx, ws, strings.ToLower(tenant), c.ScopeID)
		}
		out.AzureSubscriptions = append(out.AzureSubscriptions, s)
	}
	return out, nil
}

func accessReadinessTx(ctx context.Context, db *gorm.DB, ws uuid.UUID, out *AccessReadiness) error {
	var conns []models.CloudConnector
	if err := db.Where("workspace_id = ? AND provider = ? AND scope_kind = ? AND status = ?", ws, "aws", "account", "active").
		Order("scope_id").Find(&conns).Error; err != nil {
		return err
	}
	for _, c := range conns {
		a := AccessReadinessAccount{AccountID: c.ScopeID, ConnectorID: c.ID, BindingState: "none"}
		var b []models.CloudEnforcementBinding
		if err := db.Where("workspace_id = ? AND connector_id = ? AND state <> ?", ws, c.ID,
			models.EnforcementBindingRevoked).Order("updated_at DESC").Limit(1).Find(&b).Error; err != nil {
			return err
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
	return nil
}
