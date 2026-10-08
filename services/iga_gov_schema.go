package services

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	repositories "github.com/authsec-ai/authsec/repository"
)

// Phase 3 schema verification (SPEC-iga-phase3-policy.md §4.3, T3.02).
//
// IGA_POLICY=on requires a verified Phase 3 schema, checked by existence
// exactly as VerifyGraphSchema checks the graph's. This file is ONLY that
// check; the gate that runs it is iga_gov_gate.go (PolicyGate), its routes
// and the capabilities block controllers/platform/iga_gov_policy_controller.go.

// PolicySchemaHead is the last Phase 3 migration (047-056; the spec's
// original 044-053, moved up as a unit when 044-046 landed first).
const PolicySchemaHead = "056"

// policyRelations is every relation 047-056 create: each table, the sequence
// behind iga_gov_event.id, and every explicitly named index. The indexes are
// listed because several of them ARE the invariant -- one live control per
// role, one in-flight deployment per role, one open attempt per deployment,
// one approved version per policy -- and an index that failed to build is
// invisible to a table check.
var policyRelations = []string{
	// 047_iga_gov_ownership
	"iga_gov_owner_rule", "iga_gov_owner", "uq_iga_gov_owner",
	// 048_iga_gov_findings
	"iga_gov_evaluation", "iga_gov_activity_evidence", "iga_gov_finding", "iga_gov_finding_result",
	"iga_gov_finding_rule", "idx_iga_gov_finding_open", "idx_iga_gov_finding_identity",
	// 049_iga_gov_policy
	"iga_gov_policy", "iga_gov_policy_version", "iga_gov_document", "iga_gov_control", "iga_gov_target",
	"uq_iga_gov_policy_version_one_approved", "uq_iga_gov_control_live", "uq_iga_gov_target_one_canary",
	// 050_iga_gov_plans_reviews
	"iga_gov_evidence_bundle", "iga_gov_plan", "iga_gov_owner_review", "iga_gov_owner_response",
	"iga_gov_approval", "iga_gov_revalidation", "uq_iga_gov_plan_current", "uq_iga_gov_approval_live",
	// 051_iga_gov_rollout
	"iga_gov_rollout", "iga_gov_acceptance", "iga_gov_deployment", "iga_gov_attempt", "iga_gov_verification",
	"iga_gov_service_outcome", "iga_gov_service_posture", "iga_gov_artifact", "iga_gov_workload_migration",
	"iga_gov_health_report", "iga_gov_validation", "iga_gov_validation_item",
	"uq_iga_gov_acceptance_item", "uq_iga_gov_deployment_inflight", "uq_iga_gov_attempt_open",
	"uq_iga_gov_artifact_live", "uq_iga_gov_validation_session",
	// 052_iga_gov_jobs_events
	"iga_gov_job", "iga_gov_event", "iga_gov_event_id_seq", "iga_gov_metrics_hourly",
	"uq_iga_gov_job_open", "idx_iga_gov_job_claim", "idx_iga_gov_event_policy",
	// 053_cloud_enforcement_binding
	"cloud_enforcement_binding", "iga_gov_iac_source", "iga_gov_iac_change", "uq_cloud_enforcement_binding_live",
	// 054_slack_and_notifications
	"workspace_slack_integration", "slack_user_link", "iga_gov_notification", "uq_workspace_slack_team",
	// 055_iga_gov_settings_permissions
	"iga_gov_settings",
	// 056_cloud_resource_policy
	"cloud_policy_document", "cloud_resource_policy_coverage", "cloud_resource_policy_observation",
	"idx_cloud_rpo_scan_form",
	// 057_slack_link_one_per_member (review fix P0-3): one Slack link per
	// member; the Slack linking code relies on it against concurrent links.
	"uq_slack_user_link_member",
}

// policyColumns are columns a relation check cannot prove. 047-056 add no
// column to an existing table (§6.1; 055's only change to one is its
// permission rows, data, not schema), but 055's iga_gov_settings gained the
// notification channel columns after its first draft (p3-wire): a database
// built from that draft has the table without them, so they are checked by
// name: IGA_POLICY stays unavailable on such a database (rebuild it; 055
// is CREATE TABLE IF NOT EXISTS and never alters an existing table).
var policyColumns = []string{
	"iga_gov_settings.notify_email_enabled",
	"iga_gov_settings.notify_webhook_url",
	"iga_gov_settings.notify_webhook_secret_ref",
	"iga_gov_settings.notify_channels_source",
	"iga_gov_settings.notify_channels_copied_at",
}

// PolicySchemaColumns returns the "table.column" names VerifyPolicySchema
// checks by name.
func PolicySchemaColumns() []string { return append([]string(nil), policyColumns...) }

// PolicySchemaRelations returns the relations VerifyPolicySchema requires.
func PolicySchemaRelations() []string { return append([]string(nil), policyRelations...) }

// VerifyPolicySchema reports what Phase 3 needs that the database lacks.
//
// As VerifyGraphSchema: a database ERROR is returned as an error for the
// caller to retry (never treated as an answer), and a MISSING relation or
// column is an error naming every one, because it means IGA_POLICY is on
// against a schema that cannot run it.
func VerifyPolicySchema(db *gorm.DB) error {
	var missing []string
	for _, rel := range policyRelations {
		ok, err := repositories.HasRelation(db, rel)
		if err != nil {
			return fmt.Errorf("policy schema verification could not run: %w", err)
		}
		if !ok {
			missing = append(missing, rel)
		}
	}
	for _, qc := range policyColumns {
		table, col, _ := strings.Cut(qc, ".")
		ok, err := repositories.HasColumn(db, table, col)
		if err != nil {
			return fmt.Errorf("policy schema verification could not run: %w", err)
		}
		if !ok {
			missing = append(missing, qc)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("IGA_POLICY=on needs migrations 047-%s; missing: %s",
			PolicySchemaHead, strings.Join(missing, ", "))
	}
	return nil
}
