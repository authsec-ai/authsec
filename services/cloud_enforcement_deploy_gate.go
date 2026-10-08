package services

import (
	"context"
	"os"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/vault"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// The production deployment environment (T3.16): the binding gate and the
// AWS access of the deploy, verify, drift_check and resolve_unknown jobs.
// It lives outside the iga_* files because it reads cloud_enforcement_binding
// (scripts/ci-iga-isolation-check.sh).

// NewEnforcementBindingDeployGate is GovBindingGate over T3.09's binding
// service: the account's binding must exist, and EnsureFresh (a self-test
// younger than an hour, re-run otherwise, §3.6) must leave it verified.
// 409 enforcement_not_enabled / binding_partial / binding_not_verified.
func NewEnforcementBindingDeployGate(svc *EnforcementBindingService) GovBindingGate {
	return func(ctx context.Context, ws, connectorID uuid.UUID) error {
		var rows []models.CloudEnforcementBinding
		if err := svc.db.WithContext(ctx).Where("workspace_id = ? AND connector_id = ? AND state <> ?", ws, connectorID,
			models.EnforcementBindingRevoked).Order("updated_at DESC").Limit(1).Find(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return govConflict("enforcement_not_enabled", "The account has no enforcement binding; set it up in Policy › Setup.", nil)
		}
		b, err := svc.EnsureFresh(ctx, ws, rows[0].ID, DefaultBindingSelfTestMaxAge)
		if err != nil {
			return err
		}
		switch b.State {
		case models.EnforcementBindingVerified:
			return nil
		case models.EnforcementBindingPartial:
			return govConflict("binding_partial", "The enforcement self-test found missing permissions.", map[string]any{"binding_id": b.ID})
		}
		return govConflict("binding_not_verified", "The enforcement binding is not verified.", map[string]any{"binding_id": b.ID, "state": b.State})
	}
}

// NewProductionGovDeployEnv builds the deployment environment from the
// process's Vault client and callback configuration.
func NewProductionGovDeployEnv(db *gorm.DB, vc vault.VaultClient) GovDeployEnv {
	cfg, _ := LoadAWSCallbackConfig()
	bind := NewEnforcementBindingService(db, vc, cfg, os.Getenv("AUTHSEC_AWS_DISCOVERY_PRINCIPAL_ARN"))
	access := NewAWSEnforcementAccess(repositories.NewCloudConnectorRepository(db), NewAWSOnboardingService(db, vc), bind)
	return GovDeployEnv{AWS: access, Binding: NewEnforcementBindingDeployGate(bind), Trail: ObservationEnforcementTrail{DB: db}}
}
