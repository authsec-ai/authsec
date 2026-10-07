package igagovschema_test

import (
	"fmt"
	"strings"
)

// lit declares a token that renders as the given SQL literal text.
func (w *world) lit(name, sqlText string) {
	if _, dup := w.vals[name]; dup {
		panic("duplicate fixture name " + name)
	}
	w.vals[name] = sqlText
}

// str declares a token that renders as a quoted SQL string.
func (w *world) str(name, s string) { w.lit(name, "'"+strings.ReplaceAll(s, "'", "''")+"'") }

// row builds an INSERT from ordered (column, SQL value) pairs: the defaults,
// with any column named in overrides replaced (or appended when not a
// default). A value of "-" drops the column so its DEFAULT applies.
func row(table string, defaults []string, overrides ...string) string {
	if len(defaults)%2 != 0 || len(overrides)%2 != 0 {
		panic("row: odd column/value list for " + table)
	}
	cols := []string{}
	vals := map[string]string{}
	for i := 0; i < len(defaults); i += 2 {
		cols = append(cols, defaults[i])
		vals[defaults[i]] = defaults[i+1]
	}
	for i := 0; i < len(overrides); i += 2 {
		if _, ok := vals[overrides[i]]; !ok {
			cols = append(cols, overrides[i])
		}
		vals[overrides[i]] = overrides[i+1]
	}
	var cs, vs []string
	for _, c := range cols {
		if vals[c] == "-" {
			continue
		}
		cs = append(cs, c)
		vs = append(vs, vals[c])
	}
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(cs, ", "), strings.Join(vs, ", "))
}

// planDefaults is an eligible direct apply that installs boundary X with
// document X, compiled from bundle 1 at rev 1. Probes override what they test.
func planDefaults(id, version, target, control string) []string {
	return []string{
		"id", "{" + id + "}",
		"workspace_id", "{ws1}",
		"version_id", "{" + version + "}",
		"target_id", "{" + target + "}",
		"control_id", "{" + control + "}",
		"kind", "'apply'",
		"delivery", "'direct'",
		"eligibility", "'eligible'",
		"basis", "'live_read'",
		"basis_read_at", "now()",
		"precondition", `'{"role_id":"AROA"}'`,
		"precondition_hash", "'ph-" + id + "'",
		"desired_attachment", "'present'",
		"desired_boundary_arn", "{bX}",
		"desired_document_hash", "{docX}",
		"artifact_disposition", "'keep'",
		"evidence_bundle_id", "{bun1}",
		"evidence_rev", "1",
		"impact", "'{}'",
		"impact_hash", "'imh-" + id + "'",
		"operations", `'[{"op":"CreatePolicy"}]'`,
		"diff", "'{}'",
		"plan_hash", "'plh-" + id + "'",
		"material_hash", "'mh-" + id + "'",
	}
}

func plan(id, version, target, control string, overrides ...string) string {
	return row("iga_gov_plan", planDefaults(id, version, target, control), overrides...)
}

// deployment is a direct apply of plan by approval, queued.
func deployment(id, version, planID, control, approval string, overrides ...string) string {
	appr := "NULL"
	if approval != "" {
		appr = "{" + approval + "}"
	}
	return row("iga_gov_deployment", []string{
		"id", "{" + id + "}",
		"workspace_id", "{ws1}",
		"version_id", "{" + version + "}",
		"plan_id", "{" + planID + "}",
		"control_id", "{" + control + "}",
		"approval_id", appr,
		"kind", "'apply'",
		"delivery", "'direct'",
		"state", "'queued'",
	}, overrides...)
}

func approval(id, version, planID string) string {
	return row("iga_gov_approval", []string{
		"id", "{" + id + "}",
		"workspace_id", "{ws1}",
		"version_id", "{" + version + "}",
		"decision", "'approve'",
		"decided_by", "{u2}",
		"channel", "'ui'",
		"intent_hash", "'ih-" + version + "'",
		"impact_hashes", "ARRAY['imh-" + planID + "']",
		"plan_hashes", "ARRAY['plh-" + planID + "']",
		"material_hashes", "ARRAY['mh-" + planID + "']",
		"evidence_rev", "1",
		"expires_at", "now() + interval '7 days'",
	})
}

func version(id, ws, policy string, no int, rev int) string {
	return row("iga_gov_policy_version", []string{
		"id", "{" + id + "}",
		"workspace_id", "{" + ws + "}",
		"policy_id", "{" + policy + "}",
		"version_no", fmt.Sprint(no),
		"intent", `'{"kind":"right_size_services"}'`,
		"intent_hash", "'ih-" + id + "'",
		"catalog_version", "1",
		"evidence_rev", fmt.Sprint(rev),
		"created_by", "{u1}",
	})
}

func control(id, policy, role, identity string, overrides ...string) string {
	return row("iga_gov_control", []string{
		"id", "{" + id + "}",
		"workspace_id", "{ws1}",
		"connector_id", "{conn}",
		"account_id", "{acct}",
		"role_id", "{" + role + "}",
		"role_arn", "{arn_" + role + "}",
		"identity_account_id", "{" + identity + "}",
		"policy_id", "{" + policy + "}",
		"boundary_policy_arn", "{bX}",
	}, overrides...)
}

// posture is a pending exclusion row for role A's sqs at the control's
// sequence 0, with route facts from rev 1.
func posture(overrides ...string) string {
	return row("iga_gov_service_posture", []string{
		"workspace_id", "{ws1}",
		"account_id", "{acct}",
		"role_id", "{roleA}",
		"service", "'sqs'",
		"control_id", "{ctlA}",
		"current_deployment_id", "NULL",
		"boundary_document_hash", "NULL",
		"exclusion", "'pending'",
		"enforcement_seq", "0",
		"enforcement_observed_at", "now()",
		"route_state", "'none_observed'",
		"routes", "'[]'",
		"evidence_rev", "1",
		"evidence_scan_run_id", "{r1}",
	}, overrides...)
}

func serviceOutcome(deploymentID, service string, overrides ...string) string {
	return row("iga_gov_service_outcome", []string{
		"workspace_id", "{ws1}",
		"deployment_id", "{" + deploymentID + "}",
		"service", "'" + service + "'",
		"change", "'newly_excluded'",
		"exclusion", "'applied'",
		"route_state", "'none_observed'",
		"routes", "'[]'",
		"restriction", "'not_observed'",
		"outcome", "'removed'",
	}, overrides...)
}

func evidence(rev int, service string, overrides ...string) string {
	return row("iga_gov_activity_evidence", []string{
		"workspace_id", "{ws1}",
		"rev", fmt.Sprint(rev),
		"identity_account_id", "{iaA}",
		"role_id", "{roleA}",
		"service", "'" + service + "'",
		"state", "'collected'",
		"report_generated_at", "now() - interval '1 day'",
		"grant_age_basis", "'predates_observation'",
		"scan_run_id", fmt.Sprintf("{r%d}", rev),
	}, overrides...)
}

func acceptance(overrides ...string) string {
	return row("iga_gov_acceptance", []string{
		"workspace_id", "{ws1}",
		"kind", "'evidence_gap'",
		"item_key", "'unanalysed_form:ecr_repository'",
		"item_hash", "'sha256:gap'",
		"version_id", "{p1v1}",
		"approval_id", "{apA1}",
		"plan_id", "{plA1}",
		"evidence_bundle_id", "{bun1}",
		"reason", "'no ECR repository policy grants this role'",
		"accepted_by", "{u2}",
	}, overrides...)
}

func revalidation(overrides ...string) string {
	return row("iga_gov_revalidation", []string{
		"workspace_id", "{ws1}",
		"plan_id", "{plB1}",
		"approved_material_hash", "'mh-plB1'",
		"evidence_bundle_id", "{bun1}",
		"evidence_rev", "2",
		"basis_read_at", "now()",
		"material_hash", "'mh-plB1'",
		"result", "'unchanged'",
	}, overrides...)
}

func attempt(overrides ...string) string {
	return row("iga_gov_attempt", []string{
		"workspace_id", "{ws1}",
		"deployment_id", "{dB2}",
		"op_seq", "0",
		"attempt_no", "1",
		"lease_version", "1",
		"operation", "'CreatePolicy'",
		"request_hash", "'sha256:req0'",
		"document_hash", "{docX}",
		"status", "'prepared'",
	}, overrides...)
}

func migrationRow(overrides ...string) string {
	return row("iga_gov_workload_migration", []string{
		"workspace_id", "{ws1}",
		"plan_id", "{plSplit}",
		"control_id", "{ctlB}",
		"subject_kind", "'ecs_service'",
		"subject_arn", "'arn:aws:ecs:us-east-1:111111111111:service/prod/refunds'",
		"from_role_arn", "{arn_roleB}",
		"to_role_arn", "'arn:aws:iam::111111111111:role/RefundTaskRole-dedicated'",
		"from_workload_keys", "ARRAY['aws:ecs:task-definition/refunds:7']",
		"to_workload_keys", "ARRAY['aws:ecs:task-definition/refunds:8']",
		"state", "'moved'",
		"evidence", `'{"ecs":{"pages":1,"items":3,"failed":0}}'`,
		"evidence_complete", "true",
		"remaining_old_refs", "0",
		"checked_at", "now()",
	}, overrides...)
}
