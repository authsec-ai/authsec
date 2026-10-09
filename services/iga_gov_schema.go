package services

import (
	"fmt"
	"sort"
	"strings"

	"gorm.io/gorm"

	repositories "github.com/authsec-ai/authsec/repository"
)

// Phase 3 schema verification (SPEC-iga-phase3-policy.md §4.3, T3.02).
//
// IGA_POLICY=on requires a verified Phase 3 schema, checked by existence
// as VerifyGraphSchema checks the graph's -- relations and added columns --
// and, since the R1a review fix ("gate leaks"), every trigger and key
// CHECK / UNIQUE constraint of 047-056 by name (triggers enabled,
// constraints validated): a relation check alone passes a database whose
// invariants are gone. This file is ONLY that
// check; the gate that runs it is iga_gov_gate.go (PolicyGate), its routes
// and the capabilities block controllers/platform/iga_gov_policy_controller.go.

// PolicySchemaHead is the last Phase 3 migration (047-059; the spec's
// original 044-053, moved up as a unit when 044-046 landed first).
const PolicySchemaHead = "059"

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
	// 058_roll_gate_acceptance (fix/p3-roll): one gate_not_available
	// acceptance per (rollout, gate, window).
	"uq_iga_gov_acceptance_gate",
	// 059_tidy_eval_pruned (fix/p3-tidy): finding reads answer 410 from it
	"iga_gov_evaluation_pruned",
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

// policyTriggers is every trigger 047-056 create, as "table.trigger"
// (review fix R1a P2 "gate leaks"). The triggers ARE invariants a relation
// check cannot see: the append-only event log, immutable documents,
// bundles, versions and observations, the evaluation and attempt state
// machines, the frozen evidence and results, the control fence and the
// posture order. A trigger that is missing or DISABLED leaves the gate
// unavailable.
var policyTriggers = []string{
	// 048
	"iga_gov_evaluation.iga_gov_evaluation_transition", "iga_gov_finding.iga_gov_finding_monotonic",
	"iga_gov_activity_evidence.iga_gov_activity_evidence_frozen", "iga_gov_finding_result.iga_gov_finding_result_frozen",
	// 049
	"iga_gov_policy_version.iga_gov_policy_version_immutable", "iga_gov_document.iga_gov_document_insert",
	"iga_gov_document.iga_gov_document_immutable", "iga_gov_control.iga_gov_control_fence",
	// 050
	"iga_gov_evidence_bundle.iga_gov_bundle_insert", "iga_gov_evidence_bundle.iga_gov_bundle_immutable",
	"iga_gov_revalidation.iga_gov_revalidation_immutable",
	// 051
	"iga_gov_acceptance.iga_gov_acceptance_immutable", "iga_gov_attempt.iga_gov_attempt_transition",
	"iga_gov_service_posture.iga_gov_service_posture_order",
	// 052
	"iga_gov_event.iga_gov_event_no_update",
	// 056
	"cloud_policy_document.cloud_policy_document_insert", "cloud_policy_document.cloud_policy_document_immutable",
	"cloud_resource_policy_observation.cloud_rpo_immutable", "cloud_resource_policy_coverage.cloud_rpc_immutable",
}

// policyConstraints are the key constraints of 047-056 by "table.name": every
// explicitly named CHECK (the cross-column rules the spec names, e.g.
// iga_gov_finding_exception_chk, iga_gov_pd_authority_chk), every UNIQUE
// constraint (the identities upserts and composite FKs key on), and the one
// named FK 049 adds by ALTER. Unnamed single-column CHECKs (enums) are not
// listed: they are created with their table.
var policyConstraints = []string{
	// 047
	"iga_gov_owner.iga_gov_owner_one_chk", "iga_gov_owner.iga_gov_owner_rule_chk", "iga_gov_owner.iga_gov_owner_workspace_id_id_key",
	"iga_gov_owner_rule.iga_gov_owner_rule_workspace_id_id_key",
	"iga_gov_owner_rule.iga_gov_owner_rule_workspace_id_tag_key_applies_to_role_key",
	// 048
	"iga_gov_activity_evidence.iga_gov_ae_scan_chk", "iga_gov_activity_evidence.iga_gov_ae_route_chk",
	"iga_gov_activity_evidence.iga_gov_ae_collected_chk",
	"iga_gov_finding.iga_gov_finding_exception_chk", "iga_gov_finding.iga_gov_finding_rev_order_chk",
	"iga_gov_finding.iga_gov_finding_workspace_id_fingerprint_key", "iga_gov_finding.iga_gov_finding_workspace_id_id_key",
	"iga_gov_finding_rule.iga_gov_finding_rule_workspace_id_id_key",
	// 049
	"iga_gov_policy.iga_gov_policy_workspace_id_id_key", "iga_gov_policy.iga_gov_policy_workspace_id_name_key",
	"iga_gov_policy.iga_gov_policy_current_version_fk",
	"iga_gov_policy_version.iga_gov_policy_version_policy_id_version_no_key",
	"iga_gov_policy_version.iga_gov_policy_version_workspace_id_id_key",
	"iga_gov_policy_version.iga_gov_policy_version_workspace_id_id_policy_id_key",
	"iga_gov_control.iga_gov_rc_baseline_chk", "iga_gov_control.iga_gov_control_workspace_id_id_key",
	"iga_gov_control.iga_gov_control_workspace_id_id_policy_id_key",
	"iga_gov_target.iga_gov_target_version_id_control_id_key", "iga_gov_target.iga_gov_target_workspace_id_id_key",
	"iga_gov_target.iga_gov_target_workspace_id_id_version_id_control_id_key",
	"iga_gov_target.iga_gov_target_workspace_id_id_version_id_key",
	// 050
	"iga_gov_evidence_bundle.iga_gov_evidence_bundle_workspace_id_bundle_hash_key",
	"iga_gov_evidence_bundle.iga_gov_evidence_bundle_workspace_id_id_key",
	"iga_gov_plan.iga_gov_plan_ineligible_chk", "iga_gov_plan.iga_gov_plan_attachment_chk", "iga_gov_plan.iga_gov_plan_kind_chk",
	"iga_gov_plan.iga_gov_plan_disposition_chk", "iga_gov_plan.iga_gov_plan_first_attachment_chk",
	"iga_gov_plan.iga_gov_plan_workspace_id_id_key", "iga_gov_plan.iga_gov_plan_workspace_id_id_material_hash_key",
	"iga_gov_plan.iga_gov_plan_workspace_id_id_version_id_control_id_kind_del_key",
	"iga_gov_plan.iga_gov_plan_workspace_id_id_version_id_key",
	"iga_gov_owner_review.iga_gov_owner_review_exception_chk", "iga_gov_owner_review.iga_gov_owner_review_version_id_key",
	"iga_gov_owner_review.iga_gov_owner_review_workspace_id_id_key",
	"iga_gov_owner_response.iga_gov_orr_response_chk", "iga_gov_owner_response.iga_gov_owner_response_review_id_user_id_key",
	"iga_gov_owner_response.iga_gov_owner_response_workspace_id_id_key",
	"iga_gov_approval.iga_gov_approval_reject_reason_chk", "iga_gov_approval.iga_gov_approval_workspace_id_id_key",
	"iga_gov_approval.iga_gov_approval_workspace_id_id_version_id_key",
	"iga_gov_revalidation.iga_gov_rv_result_chk", "iga_gov_revalidation.iga_gov_revalidation_workspace_id_id_key",
	"iga_gov_revalidation.iga_gov_revalidation_workspace_id_id_plan_id_result_key",
	// 051
	"iga_gov_rollout.iga_gov_rollout_version_id_key", "iga_gov_rollout.iga_gov_rollout_workspace_id_id_key",
	"iga_gov_acceptance.iga_gov_acc_subject_chk", "iga_gov_acceptance.iga_gov_acceptance_workspace_id_id_key",
	"iga_gov_deployment.iga_gov_pd_unknown_chk", "iga_gov_deployment.iga_gov_pd_recovered_chk",
	"iga_gov_deployment.iga_gov_pd_revalidation_chk", "iga_gov_deployment.iga_gov_pd_delivery_state_chk",
	"iga_gov_deployment.iga_gov_pd_authority_chk", "iga_gov_deployment.iga_gov_deployment_workspace_id_id_key",
	"iga_gov_deployment.iga_gov_deployment_workspace_id_id_control_id_recovers_depl_key",
	"iga_gov_attempt.iga_gov_at_status_chk", "iga_gov_attempt.iga_gov_at_resolved_chk",
	"iga_gov_attempt.iga_gov_attempt_deployment_id_op_seq_attempt_no_key", "iga_gov_attempt.iga_gov_attempt_workspace_id_id_key",
	"iga_gov_verification.iga_gov_verification_deployment_id_dimension_key",
	"iga_gov_verification.iga_gov_verification_workspace_id_id_key",
	"iga_gov_service_outcome.iga_gov_so_routes_chk", "iga_gov_service_outcome.iga_gov_so_outcome_chk",
	"iga_gov_service_posture.iga_gov_sp_routes_chk", "iga_gov_service_posture.iga_gov_sp_in_force_chk",
	"iga_gov_service_posture.iga_gov_sp_evidence_chk",
	"iga_gov_artifact.iga_gov_artifact_workspace_id_id_key",
	"iga_gov_workload_migration.iga_gov_wm_roles_chk", "iga_gov_workload_migration.iga_gov_wm_moved_chk",
	"iga_gov_workload_migration.iga_gov_workload_migration_plan_id_subject_kind_subject_arn_key",
	"iga_gov_workload_migration.iga_gov_workload_migration_workspace_id_id_key",
	"iga_gov_health_report.iga_gov_hr_problem_detail_chk", "iga_gov_health_report.iga_gov_health_report_workspace_id_id_key",
	"iga_gov_validation.iga_gov_vr_window_chk", "iga_gov_validation.iga_gov_vr_correlation_chk",
	"iga_gov_validation.iga_gov_validation_workspace_id_id_key",
	"iga_gov_validation_item.iga_gov_vi_result_chk",
	// 052
	"iga_gov_job.iga_gov_job_workspace_id_id_key",
	// 053
	"cloud_enforcement_binding.cloud_enforcement_binding_workspace_id_id_key",
	"iga_gov_iac_source.iga_gov_iac_source_workspace_id_id_key",
	"iga_gov_iac_change.iga_gov_ic_merged_chk", "iga_gov_iac_change.iga_gov_iac_change_deployment_id_key",
	"iga_gov_iac_change.iga_gov_iac_change_workspace_id_id_key",
	// 054
	"iga_gov_notification.iga_gov_pn_sent_chk", "iga_gov_notification.iga_gov_notification_workspace_id_id_key",
	"iga_gov_notification.iga_gov_notification_subject_kind_subject_id_channel_recipi_key",
	// 056
	"cloud_resource_policy_coverage.cloud_rpc_complete_chk", "cloud_resource_policy_coverage.cloud_rpc_reason_chk",
	"cloud_resource_policy_observation.cloud_rpo_document_chk",
	// 058_roll_gate_acceptance (fix/p3-roll): an acceptance of a rollout's
	// gate names that rollout's version (the key and the FK that enforces it).
	"iga_gov_rollout.iga_gov_rollout_workspace_id_id_version_id_key",
	"iga_gov_acceptance.iga_gov_acceptance_rollout_version_fkey",
}

// PolicySchemaTriggers returns the "table.trigger" names VerifyPolicySchema
// requires (present and enabled).
func PolicySchemaTriggers() []string { return append([]string(nil), policyTriggers...) }

// PolicySchemaConstraints returns the "table.constraint" names
// VerifyPolicySchema requires (present and validated).
func PolicySchemaConstraints() []string { return append([]string(nil), policyConstraints...) }

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
	// Triggers and key constraints, by name: two catalog queries, so the
	// check stays cheap however many there are.
	haveTriggers, err := repositories.EnabledTriggers(db, policyTriggers)
	if err != nil {
		return fmt.Errorf("policy schema verification could not run: %w", err)
	}
	missing = append(missing, absentNames(policyTriggers, haveTriggers, "trigger ")...)
	haveConstraints, err := repositories.ValidatedConstraints(db, policyConstraints)
	if err != nil {
		return fmt.Errorf("policy schema verification could not run: %w", err)
	}
	missing = append(missing, absentNames(policyConstraints, haveConstraints, "constraint ")...)
	if len(missing) > 0 {
		return fmt.Errorf("IGA_POLICY=on needs migrations 047-%s; missing: %s",
			PolicySchemaHead, strings.Join(missing, ", "))
	}
	return nil
}

// absentNames lists the names of want not in have, prefixed, sorted.
func absentNames(want, have []string, prefix string) []string {
	got := make(map[string]bool, len(have))
	for _, h := range have {
		got[h] = true
	}
	var out []string
	for _, w := range want {
		if !got[w] {
			out = append(out, prefix+w)
		}
	}
	sort.Strings(out)
	return out
}
