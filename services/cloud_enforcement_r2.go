package services

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/awsenforce"
	"github.com/authsec-ai/authsec/models"
)

// Enforcement template v2 for R2 (SPEC-iga-phase3-policy.md §12.3;
// DECISION R2-14, R2-15 in internal/awsenforce/iamv2.go). It lives outside
// the iga_* files because it reads cloud_enforcement_binding
// (scripts/ci-iga-isolation-check.sh).
//
// DECISION R2-16: new enforcement bindings are offered template v2 only
// while IGA_POLICY_R2 is switched on; with it off the session, Quick Create
// link, binding view and accepted versions are exactly R1a's. An existing v1
// binding keeps working for R1a; every R2 feature requires the account's
// binding to be on v2 with the feature's self-test capabilities ok
// (RequireEnforcementV2), so a v1 customer re-runs setup to opt in.

// EnforcementTemplateVersionForNewBindings is v2 while IGA_POLICY_R2 is on,
// else v1.
func EnforcementTemplateVersionForNewBindings() string {
	if PolicyR2GateState().Enabled() {
		return awsdiscovery.EnforcementTemplateVersionV2
	}
	return awsdiscovery.EnforcementTemplateVersion
}

// KnownEnforcementTemplateVersionNow is the version a callback or a manual
// bind may report: v1 always, v2 only while IGA_POLICY_R2 is on.
func KnownEnforcementTemplateVersionNow(v string) bool {
	if awsdiscovery.IsEnforcementTemplateV2(v) {
		return PolicyR2GateState().Enabled()
	}
	return awsdiscovery.KnownEnforcementTemplateVersion(v)
}

// KnownEnforcementTemplateVersionsNow lists those versions.
func KnownEnforcementTemplateVersionsNow() []string {
	if PolicyR2GateState().Enabled() {
		return []string{awsdiscovery.EnforcementTemplateVersion, awsdiscovery.EnforcementTemplateVersionV2}
	}
	return []string{awsdiscovery.EnforcementTemplateVersion}
}

// R2 binding refusals.
const (
	GovCodeBindingTemplateV1      = "binding_template_v1"
	GovCodeBindingCapabilityGone  = "binding_capability_missing"
	GovCodeBindingNotVerifiedR2   = "binding_not_verified"
	EnforcementFeatureGrants      = awsenforce.FeatureTemporaryGrants
	EnforcementFeatureRevoke      = awsenforce.FeatureSessionRevoke
	EnforcementFeatureLambdaSplit = awsenforce.FeatureLambdaSplit
)

// RequireEnforcementV2 is nil when the connector's live enforcement binding
// is verified, was bound with template v2, and its stored self-test shows
// every capability feature needs as ok (awsenforce.V2CapabilitiesFor). It
// reads the database only; the caller runs the binding gate (EnsureFresh)
// first when the self-test must be fresh.
func RequireEnforcementV2(ctx context.Context, db *gorm.DB, ws, connectorID uuid.UUID, feature string) error {
	var rows []models.CloudEnforcementBinding
	if err := db.WithContext(ctx).Where("workspace_id = ? AND connector_id = ? AND state <> ?", ws, connectorID,
		models.EnforcementBindingRevoked).Order("updated_at DESC").Limit(1).Find(&rows).Error; err != nil {
		return err
	}
	if len(rows) == 0 {
		return govConflict(GovCodeEnforcementNotEnabled, "The account has no enforcement binding; set it up in Policy › Setup.", nil)
	}
	b := rows[0]
	if b.State != models.EnforcementBindingVerified {
		return govConflict(GovCodeBindingNotVerifiedR2, "The enforcement binding is not verified.",
			map[string]any{"binding_id": b.ID, "state": b.State})
	}
	if !awsdiscovery.IsEnforcementTemplateV2(b.TemplateVersion) {
		return govConflict(GovCodeBindingTemplateV1, "This feature needs the enforcement stack on template v2; update the stack in Policy › Setup.",
			map[string]any{"binding_id": b.ID, "template_version": b.TemplateVersion,
				"required_template_version": awsdiscovery.EnforcementTemplateVersionV2})
	}
	caps := map[string]awsenforce.CapabilityResult{}
	if len(b.Capabilities) > 0 {
		_ = json.Unmarshal(b.Capabilities, &caps)
	}
	if missing := awsenforce.MissingV2Capabilities(caps, feature); len(missing) > 0 {
		return govConflict(GovCodeBindingCapabilityGone, "The enforcement self-test has not proven what this feature needs: "+
			strings.Join(missing, "; ")+".", map[string]any{"binding_id": b.ID, "feature": feature, "missing": missing})
	}
	return nil
}
