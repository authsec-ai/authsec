package igagovschema_test

// SPEC-iga-phase3-policy.md §6.3, "One complete path across two accounts":
// the R1a journey in the order the spec prescribes, every statement required
// to succeed, each step COMMITTED (so deferred constraints are checked at the
// commits the workers would make), and every evaluation and observer
// transaction taking its locks in the shared order of §8.7: control ->
// posture -> finding. Each plan is compiled from its own evidence bundle.
//
// The final row is compared with the block the spec prints, line for line.

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

type journey struct {
	t  *testing.T
	db *sql.DB
	w  *world
}

// txn runs one committed transaction; every statement must succeed.
func (j *journey) txn(label string, f func(s *step)) {
	j.t.Helper()
	tx, err := j.db.Begin()
	if err != nil {
		j.t.Fatal(err)
	}
	s := &step{t: j.t, x: tx, w: j.w}
	f(s)
	s.exec(`SET CONSTRAINTS ALL IMMEDIATE`)
	if s.err != nil || len(s.bad) > 0 {
		_ = tx.Rollback()
		j.t.Fatalf("%s: %v %v", label, func() string {
			if s.err != nil {
				return describe(s.err)
			}
			return ""
		}(), s.bad)
	}
	if err := tx.Commit(); err != nil {
		j.t.Fatalf("%s: commit: %s", label, describe(err))
	}
}

func (j *journey) val(q string) string {
	j.t.Helper()
	s := &step{t: j.t, x: j.db, w: j.w}
	v := s.val(q)
	if len(s.bad) > 0 {
		j.t.Fatal(s.bad)
	}
	return v
}

// lockOrder is §8.7's shared order for every evaluation and observer
// transaction: the control row, then the role's posture rows, then findings.
func lockOrder(s *step) {
	s.exec(`SELECT id FROM iga_gov_control WHERE id = {ctl} FOR UPDATE`)
	s.exec(`SELECT service FROM iga_gov_service_posture WHERE workspace_id = {ws} AND role_id = {roleA} ORDER BY service FOR UPDATE`)
	s.exec(`SELECT id FROM iga_gov_finding WHERE workspace_id = {ws} AND identity_account_id = {iaA} ORDER BY id FOR UPDATE`)
}

func TestPhase3OneCompletePath(t *testing.T) {
	db, _ := testDB(t)
	w := newWorld()
	w.id("ws", "uAuthor", "uApprover", "uOwner", "cA", "cB", "e1", "b1", "e2", "e3", "iaA", "wl",
		"pol", "ctl", "v1", "v2", "t1", "t2", "bun1", "bun2", "bun3",
		"apply1", "undo1", "apply2", "undo2", "rev1", "rev2", "resp1", "resp2", "ap1", "ap2", "acc",
		"ro1", "ro2", "dep1", "dep2", "dep3", "rv", "fSqs", "fSns", "artPol", "artAtt")
	w.str("acct", "111111111111")
	w.str("roleA", "AROAREFUNDTASKROLE0001")
	w.str("roleArn", "arn:aws:iam::111111111111:role/RefundTaskRole")
	w.str("bX", "arn:aws:iam::111111111111:policy/authsec/AuthSecBoundary-AROAREFUNDTASKROLE0001")
	w.str("queue", "arn:aws:sqs:us-east-1:111111111111:refunds")
	w.doc("d1", `{"Statement":[{"Effect":"Allow","NotAction":["sqs:*"],"Resource":"*"}],"Version":"2012-10-17"}`)
	w.doc("d2", `{"Statement":[{"Effect":"Allow","NotAction":["sns:*","sqs:*"],"Resource":"*"}],"Version":"2012-10-17"}`)
	w.doc("qpol", `{"Statement":[{"Action":"sqs:SendMessage","Effect":"Allow","Principal":{"AWS":"arn:aws:sts::111111111111:assumed-role/RefundTaskRole/batch"},"Resource":"arn:aws:sqs:us-east-1:111111111111:refunds"}],"Version":"2012-10-17"}`)
	w.doc("b1h", `{"sources":[{"connector_run":"e1","kind":"aws_publication","rev":1,"trust":"trusted"}],"target":{"account_id":"111111111111","role_id":"AROAREFUNDTASKROLE0001"}}`)
	w.doc("b2h", `{"sources":[{"connector_run":"e1","kind":"aws_publication","rev":2,"trust":"trusted"}],"target":{"account_id":"111111111111","role_id":"AROAREFUNDTASKROLE0001"}}`)
	w.doc("b3h", `{"sources":[{"connector_run":"e2","kind":"aws_publication","rev":3,"trust":"trusted"}],"target":{"account_id":"111111111111","role_id":"AROAREFUNDTASKROLE0001"}}`)
	j := &journey{t: t, db: db, w: w}

	// Two accounts, one workspace: account A (111…) and account B (222…).
	j.txn("world", func(s *step) {
		s.exec(`INSERT INTO workspaces (id, name, workspace_type) VALUES ({ws}, 'p3 path', 'team')`)
		s.exec(`INSERT INTO users (id, email, workspace_id) VALUES ({uAuthor}, 'author@p3path.test', {ws}),
		          ({uApprover}, 'approver@p3path.test', {ws}), ({uOwner}, 'owner@p3path.test', {ws})`)
		s.exec(`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref) VALUES
		          ({cA}, {ws}, 'aws', 'account', '111111111111', 'vault://p3path/a'),
		          ({cB}, {ws}, 'aws', 'account', '222222222222', 'vault://p3path/b')`)
		s.exec(`INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key, display_name)
		        VALUES ({iaA}, {ws}, 'role', 'aws', 'aws:iam:role:111111111111:RefundTaskRole', 'immutable', 'AROAREFUNDTASKROLE0001', 'RefundTaskRole')`)
		s.exec(`INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key, display_name)
		        VALUES ({wl}, {ws}, 'ecs_task', 'aws:ecs:task-definition/refund-agent:3', 'refund-agent')`)
		s.exec(`INSERT INTO iga_gov_owner (workspace_id, object_kind, workload_id, user_id, role, source, created_by)
		        VALUES ({ws}, 'workload', {wl}, {uOwner}, 'accountable', 'manual', {uAuthor})`)
		s.exec(`INSERT INTO iga_gov_settings (workspace_id, enforcement_mode, updated_by) VALUES ({ws}, 'enforce', {uAuthor})`)
	})

	// evaluation writes, in ONE transaction fenced on the projection job
	// (§2.5): evidence, finding upserts, results, then complete.
	evaluate := func(rev int, run string, results []string, routeFacts func(s *step)) {
		j.txn(fmt.Sprintf("evaluate rev %d", rev), func(s *step) {
			lockOrder(s)
			for _, svc := range []string{"sqs", "sns", "s3"} {
				last := "NULL"
				if svc == "s3" {
					last = "now() - interval '2 hours'"
				}
				s.exec(fmt.Sprintf(`INSERT INTO iga_gov_activity_evidence (workspace_id, rev, identity_account_id, role_id, service, state,
				          last_authenticated_at, report_generated_at, grant_age_basis, scan_run_id, route_usage)
				        VALUES ({ws}, %d, {iaA}, {roleA}, '%s', 'collected', %s, now() - interval '5 hours', 'predates_observation', {%s}, 'none_observed')`,
					rev, svc, last, run))
			}
			s.exec(fmt.Sprintf(`INSERT INTO iga_gov_finding (id, workspace_id, fingerprint, kind, family, severity, confidence,
			            identity_account_id, role_id, connector_id, detail_key, first_seen_rev, last_evaluated_rev)
			          VALUES ({fSqs}, {ws}, 'sha256:unused_service|AROAREFUNDTASKROLE0001|sqs', 'unused_service', 'cloud_access', 'high', 'age_unverified', {iaA}, {roleA}, {cA}, 'sqs', %[1]d, %[1]d),
			                 ({fSns}, {ws}, 'sha256:unused_service|AROAREFUNDTASKROLE0001|sns', 'unused_service', 'cloud_access', 'medium', 'age_unverified', {iaA}, {roleA}, {cA}, 'sns', %[1]d, %[1]d)
			          ON CONFLICT (workspace_id, fingerprint) DO UPDATE
			            SET last_evaluated_rev = EXCLUDED.last_evaluated_rev, last_evaluated_at = now()
			          WHERE iga_gov_finding.last_evaluated_rev < EXCLUDED.last_evaluated_rev`, rev))
			for _, f := range results {
				s.exec(fmt.Sprintf(`INSERT INTO iga_gov_finding_result (workspace_id, rev, finding_id, severity, confidence, detail, evidence_scan_run_id)
				        VALUES ({ws}, %d, {%s}, 'high', 'age_unverified', '{"qualified_days":112,"grant_age_basis":"predates_observation"}', {%s})`, rev, f, run))
			}
			if routeFacts != nil {
				routeFacts(s)
			}
			s.rows(1, fmt.Sprintf(`UPDATE iga_gov_evaluation SET status = 'complete', finished_at = now()
			                      WHERE workspace_id = {ws} AND rev = %d AND status = 'running'`, rev))
		})
	}
	// publication and the evaluation row commit together (§2.5 step 1).
	publish := func(rev int, run string, manifest string) {
		j.txn(fmt.Sprintf("publish rev %d", rev), func(s *step) {
			s.exec(fmt.Sprintf(`INSERT INTO iga_publication (workspace_id, rev, published_at, scan_run_id, manifest)
			        VALUES ({ws}, %d, now(), {%s}, %s)`, rev, run, manifest))
			s.exec(fmt.Sprintf(`INSERT INTO iga_gov_evaluation (workspace_id, rev, status) VALUES ({ws}, %d, 'running')`, rev))
		})
	}
	// collect: a scan run with its immutable resource-policy evidence (§3.9).
	collect := func(run, conn string, gen int, queuePolicy bool) {
		j.txn("collect "+run, func(s *step) {
			s.exec(fmt.Sprintf(`INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, published_at)
			        VALUES ({%s}, {ws}, {%s}, %d, 'published', now())`, run, conn, gen))
			if conn != "cA" {
				return
			}
			s.exec(fmt.Sprintf(`INSERT INTO cloud_resource_policy_coverage (workspace_id, connector_id, scan_run_id, resource_form, region, state, enumerated, read_ok)
			        VALUES ({ws}, {cA}, {%s}, 'sqs_queue', 'us-east-1', 'complete', 1, 1)`, run))
			if queuePolicy {
				s.exec(`INSERT INTO cloud_policy_document (workspace_id, document_hash, canonical, document)
				        VALUES ({ws}, {qpol}, {qpol.c}, {qpol.c}::jsonb) ON CONFLICT (workspace_id, document_hash) DO NOTHING`)
				s.exec(fmt.Sprintf(`INSERT INTO cloud_resource_policy_observation (workspace_id, scan_run_id, resource_form, region, resource_arn, policy_present, document_hash, read_at)
				        VALUES ({ws}, {%s}, 'sqs_queue', 'us-east-1', {queue}, true, {qpol}, now())`, run))
			} else {
				s.exec(fmt.Sprintf(`INSERT INTO cloud_resource_policy_observation (workspace_id, scan_run_id, resource_form, region, resource_arn, policy_present, read_at)
				        VALUES ({ws}, {%s}, 'sqs_queue', 'us-east-1', {queue}, false, now())`, run))
			}
		})
	}
	// attempts: one write-ahead record per AWS mutation, prepared ->
	// dispatched -> completed (§8.1).
	attempts := func(s *step, dep string, ops ...string) {
		for i, op := range ops {
			id := fmt.Sprintf("(SELECT id FROM iga_gov_attempt WHERE deployment_id = {%s} AND op_seq = %d)", dep, i)
			s.exec(fmt.Sprintf(`INSERT INTO iga_gov_attempt (workspace_id, deployment_id, op_seq, attempt_no, lease_version, operation, request_hash, status)
			        VALUES ({ws}, {%s}, %d, 1, 1, '%s', 'sha256:req-%s-%d', 'prepared')`, dep, i, op, op, i))
			s.exec(`UPDATE iga_gov_attempt SET status = 'dispatched', signed_at = now(), dispatched_at = now() WHERE id = ` + id)
			s.exec(`UPDATE iga_gov_attempt SET status = 'completed', completed_at = now(), outcome = 'ok', request_id = 'req-` + op + `' WHERE id = ` + id)
		}
	}
	event := func(s *step, ev, actorKind, actor string) {
		s.exec(fmt.Sprintf(`INSERT INTO iga_gov_event (workspace_id, event, actor_kind, actor_id, policy_id) VALUES ({ws}, '%s', '%s', %s, {pol})`, ev, actorKind, actor))
	}

	/* ---- 1. rev 1: account A's first scan, publication, evaluation ---- */
	collect("e1", "cA", 1, false)
	publish(1, "e1", `jsonb_build_object('aws:111111111111', {e1}::text)`)
	evaluate(1, "e1", []string{"fSqs", "fSns"}, nil)

	/* ---- 2. version 1 removes sqs: bundle, plans, review, approval with one
	   acceptance, apply verified, history, observer swap 0 -> 1 ---- */
	j.txn("author v1", func(s *step) {
		s.exec(`INSERT INTO iga_gov_policy (id, workspace_id, name, purpose, family, provider, owner_user_id, created_by)
		        VALUES ({pol}, {ws}, 'refund-agent right-size', 'remove unused services', 'cloud_access', 'aws', {uAuthor}, {uAuthor})`)
		s.exec(`INSERT INTO iga_gov_control (id, workspace_id, connector_id, account_id, role_id, role_arn, identity_account_id, policy_id, boundary_policy_arn)
		        VALUES ({ctl}, {ws}, {cA}, {acct}, {roleA}, {roleArn}, {iaA}, {pol}, {bX})`)
		s.exec(`INSERT INTO iga_gov_policy_version (id, workspace_id, policy_id, version_no, intent, intent_hash, catalog_version, evidence_rev, status, created_by)
		        VALUES ({v1}, {ws}, {pol}, 1, '{"kind":"right_size_services","remove":[{"service":"sqs"}]}', 'sha256:intent-v1', 1, 1, 'in_review', {uAuthor})`)
		s.exec(`UPDATE iga_gov_policy SET current_version_id = {v1} WHERE id = {pol}`)
		s.exec(`INSERT INTO iga_gov_target (id, workspace_id, version_id, policy_id, control_id, is_canary) VALUES ({t1}, {ws}, {v1}, {pol}, {ctl}, true)`)
		s.exec(`UPDATE iga_gov_finding SET status = 'under_review', status_changed_at = now() WHERE id = {fSqs}`)
		event(s, "policy.created", "user", "{uAuthor}::text")
	})
	j.txn("compile v1", func(s *step) {
		s.exec(`INSERT INTO iga_gov_evidence_bundle (id, workspace_id, provider, trust, bundle_hash, canonical, facts)
		        VALUES ({bun1}, {ws}, 'aws', 'partial', {b1h}, {b1h.c}, {b1h.c}::jsonb)`)
		s.exec(`INSERT INTO iga_gov_document (workspace_id, document_hash, canonical, document) VALUES ({ws}, {d1}, {d1.c}, {d1.c}::jsonb)`)
		s.exec(plan("apply1", "v1", "t1", "ctl", "workspace_id", "{ws}", "desired_document_hash", "{d1}", "evidence_bundle_id", "{bun1}",
			"first_attachment", "true", "resource_policy_scan_run_id", "{e1}", "unanalysed", `'[{"form":"ecr_repository"}]'`))
		s.exec(plan("undo1", "v1", "t1", "ctl", "workspace_id", "{ws}", "kind", "'undo'", "desired_attachment", "'absent'",
			"desired_boundary_arn", "NULL", "desired_document_hash", "NULL", "before_document_hash", "{d1}",
			"replaced_boundary_arn", "{bX}", "artifact_disposition", "'delete'", "evidence_bundle_id", "{bun1}"))
	})
	review := func(review, resp, version, applyPlan string, ageConfirmed string) {
		j.txn("owner review "+version, func(s *step) {
			s.exec(fmt.Sprintf(`INSERT INTO iga_gov_owner_review (id, workspace_id, version_id, impact_hashes, deadline_at)
			        VALUES ({%s}, {ws}, {%s}, ARRAY['imh-%s'], now() + interval '3 days')`, review, version, applyPlan))
			s.exec(fmt.Sprintf(`INSERT INTO iga_gov_owner_response (id, workspace_id, review_id, user_id, owner_of, delivery, delivery_channels,
			          response, age_confirmations, responded_at, responded_via)
			        VALUES ({%s}, {ws}, {%s}, {uOwner}, '[{"workload_id":"refund-agent"}]', 'delivered', ARRAY['email'],
			          'acknowledge', '%s', now(), 'ui')`, resp, review, ageConfirmed))
			s.rows(1, fmt.Sprintf(`UPDATE iga_gov_owner_review SET status = 'complete', closed_at = now() WHERE id = {%s} AND status = 'open'`, review))
		})
	}
	review("rev1", "resp1", "v1", "apply1", `[{"service":"sqs","not_added_recently":true}]`)
	j.txn("approve v1", func(s *step) {
		s.exec(`INSERT INTO iga_gov_approval (id, workspace_id, version_id, decision, decided_by, channel, intent_hash, impact_hashes,
		          plan_hashes, material_hashes, evidence_rev, expires_at)
		        VALUES ({ap1}, {ws}, {v1}, 'approve', {uApprover}, 'ui', 'sha256:intent-v1', ARRAY['imh-apply1'],
		          ARRAY['plh-apply1','plh-undo1'], ARRAY['mh-apply1','mh-undo1'], 1, now() + interval '7 days')`)
		// The one accepted uncertainty: the unanalysed ECR repository-policy form.
		s.exec(acceptance("id", "{acc}", "workspace_id", "{ws}", "kind", "'unanalysed_form'", "item_key", "'ecr_repository'",
			"version_id", "{v1}", "approval_id", "{ap1}", "plan_id", "{apply1}", "evidence_bundle_id", "{bun1}", "accepted_by", "{uApprover}"))
		s.exec(`UPDATE iga_gov_policy_version SET status = 'approved', status_changed_at = now() WHERE id = {v1}`)
		s.exec(`INSERT INTO iga_gov_rollout (id, workspace_id, version_id, stage, canary_started_at) VALUES ({ro1}, {ws}, {v1}, 'canary', now())`)
		event(s, "version.approved", "user", "{uApprover}::text")
	})
	j.txn("deploy v1", func(s *step) {
		s.exec(deployment("dep1", "v1", "apply1", "ctl", "ap1", "workspace_id", "{ws}"))
		s.exec(`UPDATE iga_gov_deployment SET state = 'applying', attempts = 1 WHERE id = {dep1}`)
		attempts(s, "dep1", "CreatePolicy", "PutRolePermissionsBoundary")
		// Baseline: the role had no boundary before AuthSec's first change.
		s.exec(`UPDATE iga_gov_control SET state = 'active', baseline_captured_at = now() WHERE id = {ctl}`)
		s.exec(`INSERT INTO iga_gov_artifact (id, workspace_id, control_id, kind, native_arn, owned_by, state, document_hash, last_deployment_id)
		        VALUES ({artPol}, {ws}, {ctl}, 'boundary_policy', {bX}, 'authsec_direct', 'present', {d1}, {dep1}),
		               ({artAtt}, {ws}, {ctl}, 'boundary_attachment', {roleArn}, 'authsec_direct', 'present', {d1}, {dep1})`)
		s.exec(`UPDATE iga_gov_deployment SET state = 'applied_unverified', applied_at = now() WHERE id = {dep1}`)
	})
	j.txn("verify v1", func(s *step) {
		s.exec(`INSERT INTO iga_gov_verification (workspace_id, deployment_id, dimension, outcome, evidence)
		        VALUES ({ws}, {dep1}, 'artifact', 'passed', '{"document_hash_matches":true}')`)
		s.exec(serviceOutcome("dep1", "sqs", "workspace_id", "{ws}"))
		s.exec(`UPDATE iga_gov_deployment SET state = 'verified', verified_at = now() WHERE id = {dep1}`)
		s.exec(`UPDATE iga_gov_rollout SET stage = 'complete', updated_at = now() WHERE id = {ro1}`)
	})
	j.txn("observer v1 (0 -> 1)", func(s *step) {
		lockOrder(s)
		s.rows(1, `UPDATE iga_gov_control SET enforcement_seq = 1 WHERE id = {ctl} AND enforcement_seq = 0`)
		s.exec(row("iga_gov_service_posture", []string{"workspace_id", "{ws}", "account_id", "{acct}", "role_id", "{roleA}", "service", "'sqs'",
			"control_id", "{ctl}", "current_deployment_id", "{dep1}", "boundary_document_hash", "{d1}", "exclusion", "'applied'",
			"enforcement_seq", "1", "enforcement_observed_at", "now()", "route_state", "'none_observed'", "routes", "'[]'",
			"evidence_rev", "1", "evidence_scan_run_id", "{e1}"}))
		s.exec(`UPDATE iga_gov_finding SET status = 'resolved', resolved_by_deployment_id = {dep1}, status_changed_at = now() WHERE id = {fSqs}`)
	})
	if got := j.val(`SELECT outcome FROM iga_gov_service_posture WHERE workspace_id = {ws} AND service = 'sqs'`); got != "removed" {
		t.Fatalf("after version 1, sqs posture = %q, want removed", got)
	}

	/* ---- 3. rev 2: account B publishes; role A's facts still cite e1 ---- */
	collect("b1", "cB", 1, false)
	publish(2, "b1", `jsonb_build_object('aws:111111111111', {e1}::text, 'aws:222222222222', {b1}::text)`)
	evaluate(2, "e1", []string{"fSns"}, func(s *step) {
		s.exec(`UPDATE iga_gov_service_posture SET evidence_rev = 2, evidence_scan_run_id = {e1}
		        WHERE workspace_id = {ws} AND role_id = {roleA}`)
	})

	/* ---- 4. version 2 removes sqs and sns ---- */
	j.txn("author v2", func(s *step) {
		s.exec(`INSERT INTO iga_gov_policy_version (id, workspace_id, policy_id, version_no, intent, intent_hash, catalog_version, evidence_rev, status, created_by)
		        VALUES ({v2}, {ws}, {pol}, 2, '{"kind":"right_size_services","remove":[{"service":"sqs"},{"service":"sns"}]}', 'sha256:intent-v2', 1, 2, 'in_review', {uAuthor})`)
		s.exec(`INSERT INTO iga_gov_target (id, workspace_id, version_id, policy_id, control_id, is_canary) VALUES ({t2}, {ws}, {v2}, {pol}, {ctl}, true)`)
		s.exec(`UPDATE iga_gov_finding SET status = 'under_review', status_changed_at = now() WHERE id = {fSns}`)
	})
	j.txn("compile v2", func(s *step) {
		s.exec(`INSERT INTO iga_gov_evidence_bundle (id, workspace_id, provider, trust, bundle_hash, canonical, facts)
		        VALUES ({bun2}, {ws}, 'aws', 'trusted', {b2h}, {b2h.c}, {b2h.c}::jsonb)`)
		s.exec(`INSERT INTO iga_gov_document (workspace_id, document_hash, canonical, document) VALUES ({ws}, {d2}, {d2.c}, {d2.c}::jsonb)`)
		// The apply changes the default version of the SAME AuthSec policy, so
		// its undo restores document 1 under that policy and keeps it (§2.8).
		s.exec(plan("apply2", "v2", "t2", "ctl", "workspace_id", "{ws}", "desired_document_hash", "{d2}", "before_document_hash", "{d1}",
			"evidence_bundle_id", "{bun2}", "evidence_rev", "2", "resource_policy_scan_run_id", "{e1}"))
		s.exec(plan("undo2", "v2", "t2", "ctl", "workspace_id", "{ws}", "kind", "'undo'", "desired_document_hash", "{d1}", "before_document_hash", "{d2}",
			"evidence_bundle_id", "{bun2}", "evidence_rev", "2"))
	})
	review("rev2", "resp2", "v2", "apply2", `[{"service":"sns","not_added_recently":true}]`)
	j.txn("approve v2", func(s *step) {
		s.exec(`INSERT INTO iga_gov_approval (id, workspace_id, version_id, decision, decided_by, channel, intent_hash, impact_hashes,
		          plan_hashes, material_hashes, evidence_rev, expires_at)
		        VALUES ({ap2}, {ws}, {v2}, 'approve', {uApprover}, 'ui', 'sha256:intent-v2', ARRAY['imh-apply2'],
		          ARRAY['plh-apply2','plh-undo2'], ARRAY['mh-apply2','mh-undo2'], 2, now() + interval '7 days')`)
		s.exec(`UPDATE iga_gov_policy_version SET status = 'superseded', status_changed_at = now() WHERE id = {v1}`)
		s.exec(`UPDATE iga_gov_policy_version SET status = 'approved', status_changed_at = now() WHERE id = {v2}`)
		s.exec(`UPDATE iga_gov_policy SET current_version_id = {v2}, updated_at = now() WHERE id = {pol}`)
		s.exec(`INSERT INTO iga_gov_rollout (id, workspace_id, version_id, stage, canary_started_at) VALUES ({ro2}, {ws}, {v2}, 'canary', now())`)
	})
	j.txn("deploy v2", func(s *step) {
		s.exec(deployment("dep2", "v2", "apply2", "ctl", "ap2", "workspace_id", "{ws}"))
		s.exec(`UPDATE iga_gov_deployment SET state = 'applying', attempts = 1 WHERE id = {dep2}`)
		attempts(s, "dep2", "CreatePolicyVersion")
		s.exec(`UPDATE iga_gov_artifact SET document_hash = {d2}, last_deployment_id = {dep2}, updated_at = now() WHERE control_id = {ctl}`)
		s.exec(`UPDATE iga_gov_deployment SET state = 'applied_unverified', applied_at = now() WHERE id = {dep2}`)
	})
	j.txn("verify v2", func(s *step) {
		s.exec(`INSERT INTO iga_gov_verification (workspace_id, deployment_id, dimension, outcome) VALUES ({ws}, {dep2}, 'artifact', 'passed')`)
		s.exec(serviceOutcome("dep2", "sqs", "workspace_id", "{ws}", "change", "'already_excluded'"))
		s.exec(serviceOutcome("dep2", "sns", "workspace_id", "{ws}"))
		s.exec(`UPDATE iga_gov_deployment SET state = 'verified', verified_at = now() WHERE id = {dep2}`)
		s.exec(`UPDATE iga_gov_deployment SET state = 'superseded', state_reason = 'version 2 verified', updated_at = now() WHERE id = {dep1}`)
		s.exec(`UPDATE iga_gov_rollout SET stage = 'complete', updated_at = now() WHERE id = {ro2}`)
	})
	j.txn("observer v2 (1 -> 2)", func(s *step) {
		lockOrder(s)
		s.rows(1, `UPDATE iga_gov_control SET enforcement_seq = 2 WHERE id = {ctl} AND enforcement_seq = 1`)
		s.exec(`UPDATE iga_gov_service_posture SET current_deployment_id = {dep2}, boundary_document_hash = {d2}, enforcement_seq = 2,
		          enforcement_observed_at = now() WHERE workspace_id = {ws} AND role_id = {roleA} AND service = 'sqs'`)
		s.exec(row("iga_gov_service_posture", []string{"workspace_id", "{ws}", "account_id", "{acct}", "role_id", "{roleA}", "service", "'sns'",
			"control_id", "{ctl}", "current_deployment_id", "{dep2}", "boundary_document_hash", "{d2}", "exclusion", "'applied'",
			"enforcement_seq", "2", "enforcement_observed_at", "now()", "route_state", "'none_observed'", "routes", "'[]'",
			"evidence_rev", "2", "evidence_scan_run_id", "{e1}"}))
		s.exec(`UPDATE iga_gov_finding SET status = 'resolved', resolved_by_deployment_id = {dep2}, status_changed_at = now() WHERE id = {fSns}`)
	})

	/* ---- 5. interleaving: A rescans, rev 3 publishes; the undo approved at
	   rev 2 revalidates (unchanged) and commits before rev 3's evaluation ---- */
	collect("e2", "cA", 2, false)
	publish(3, "e2", `jsonb_build_object('aws:111111111111', {e2}::text, 'aws:222222222222', {b1}::text)`)
	j.txn("revalidate undo at rev 3", func(s *step) {
		// The deploy job builds a NEW bundle from rev 3 and recompiles the same
		// intent in memory; the approved plan and its bundle are never rewritten.
		s.exec(`INSERT INTO iga_gov_evidence_bundle (id, workspace_id, provider, trust, bundle_hash, canonical, facts)
		        VALUES ({bun3}, {ws}, 'aws', 'trusted', {b3h}, {b3h.c}, {b3h.c}::jsonb)`)
		s.exec(row("iga_gov_revalidation", []string{"id", "{rv}", "workspace_id", "{ws}", "plan_id", "{undo2}",
			"approved_material_hash", "'mh-undo2'", "evidence_bundle_id", "{bun3}", "evidence_rev", "3", "resource_policy_scan_run_id", "{e2}",
			"basis_read_at", "now()", "material_hash", "'mh-undo2'", "result", "'unchanged'"}))
	})
	j.txn("undo v2 (proceeds on the approved plan)", func(s *step) {
		s.exec(deployment("dep3", "v2", "undo2", "ctl", "ap2", "workspace_id", "{ws}", "kind", "'undo'",
			"revalidation_id", "{rv}", "revalidation_result", "'unchanged'"))
		s.exec(`UPDATE iga_gov_deployment SET state = 'applying', attempts = 1 WHERE id = {dep3}`)
		attempts(s, "dep3", "CreatePolicyVersion")
		s.exec(`UPDATE iga_gov_artifact SET document_hash = {d1}, last_deployment_id = {dep3}, updated_at = now() WHERE control_id = {ctl}`)
		s.exec(`INSERT INTO iga_gov_verification (workspace_id, deployment_id, dimension, outcome) VALUES ({ws}, {dep3}, 'artifact', 'passed')`)
		// Per-service recomputation from the restored version-1 boundary:
		// sqs stays excluded (no history row), sns is un-excluded.
		s.exec(serviceOutcome("dep3", "sns", "workspace_id", "{ws}", "change", "'newly_unexcluded'", "exclusion", "'reverted'", "outcome", "'not_removed'"))
		s.exec(`UPDATE iga_gov_deployment SET state = 'verified', applied_at = now(), verified_at = now() WHERE id = {dep3}`)
		s.exec(`UPDATE iga_gov_deployment SET state = 'undone', state_reason = 'undone by its undo plan', updated_at = now() WHERE id = {dep2}`)
		s.exec(`UPDATE iga_gov_rollout SET stage = 'undone', updated_at = now() WHERE id = {ro2}`)
	})
	j.txn("observer undo (2 -> 3)", func(s *step) {
		lockOrder(s)
		s.rows(1, `UPDATE iga_gov_control SET enforcement_seq = 3 WHERE id = {ctl} AND enforcement_seq = 2`)
		s.exec(`UPDATE iga_gov_service_posture SET current_deployment_id = {dep3}, boundary_document_hash = {d1}, enforcement_seq = 3,
		          enforcement_observed_at = now() WHERE workspace_id = {ws} AND role_id = {roleA} AND service = 'sqs'`)
		s.exec(`UPDATE iga_gov_service_posture SET exclusion = 'not_applied', current_deployment_id = {dep3}, boundary_document_hash = {d1},
		          enforcement_seq = 3, enforcement_observed_at = now() WHERE workspace_id = {ws} AND role_id = {roleA} AND service = 'sns'`)
		s.exec(`UPDATE iga_gov_finding SET status = 'reopened', resolved_by_deployment_id = NULL, status_changed_at = now() WHERE id = {fSns}`)
	})
	// A drift check that read sequence 2 loses its swap and writes nothing.
	j.txn("stale drift check", func(s *step) {
		lockOrder(s)
		s.rows(0, `UPDATE iga_gov_control SET enforcement_seq = 3 WHERE id = {ctl} AND enforcement_seq = 2`)
	})
	// The delayed rev-3 evaluation commits ROUTE facts only.
	evaluate(3, "e2", []string{"fSqs", "fSns"}, func(s *step) {
		s.exec(`UPDATE iga_gov_service_posture SET route_state = 'none_observed', routes = '[]', evidence_rev = 3, evidence_scan_run_id = {e2}
		        WHERE workspace_id = {ws} AND role_id = {roleA}`)
	})
	// Checkpoint (§6.3 step 5).
	for q, want := range map[string]string{
		`SELECT outcome || '/' || (SELECT status FROM iga_gov_finding WHERE id = {fSqs}) FROM iga_gov_service_posture WHERE workspace_id = {ws} AND service = 'sqs'`: "removed/resolved",
		`SELECT outcome FROM iga_gov_service_posture WHERE workspace_id = {ws} AND service = 'sns'`:                                                                  "not_removed",
		`SELECT count(*) FROM iga_gov_service_posture WHERE workspace_id = {ws} AND outcome = 'removed'`:                                                             "1",
		`SELECT count(*) FROM iga_gov_service_outcome WHERE workspace_id = {ws} AND change = 'newly_excluded'`:                                                       "2",
	} {
		if got := j.val(q); got != want {
			t.Errorf("step 5 checkpoint: got %q, want %q: %s", got, want, q)
		}
	}

	/* ---- 6. rev 4: the refunds queue policy now grants a session of the role ---- */
	collect("e3", "cA", 3, true)
	publish(4, "e3", `jsonb_build_object('aws:111111111111', {e3}::text, 'aws:222222222222', {b1}::text)`)
	evaluate(4, "e3", []string{"fSqs", "fSns"}, func(s *step) {
		s.exec(`UPDATE iga_gov_service_posture SET route_state = 'bypass_known',
		          routes = '[{"resource":"arn:aws:sqs:us-east-1:111111111111:refunds","principal":"role_session"}]',
		          evidence_rev = 4, evidence_scan_run_id = {e3}
		        WHERE workspace_id = {ws} AND role_id = {roleA} AND service = 'sqs'`)
		s.exec(`UPDATE iga_gov_service_posture SET evidence_rev = 4, evidence_scan_run_id = {e3}
		        WHERE workspace_id = {ws} AND role_id = {roleA} AND service = 'sns'`)
		// Lifecycle follows the CURRENT posture (P-11): sqs excluded with a
		// known route -> mitigated.
		s.exec(`UPDATE iga_gov_finding f SET status = 'mitigated', status_changed_at = now()
		          FROM iga_gov_service_posture p
		         WHERE f.id = {fSqs} AND p.workspace_id = f.workspace_id AND p.role_id = f.role_id AND p.service = f.detail_key
		           AND p.outcome = 'excluded_routes_remain'`)
	})

	/* ---- the final row ---- */
	labels := map[string]string{}
	for _, r := range []string{"e1", "b1", "e2", "e3"} {
		labels[strings.Trim(strings.TrimSuffix(w.vals[r], "::uuid"), "'")] = r
	}
	q := func(sqlText string) []string {
		rows, err := db.Query(w.sql(sqlText))
		if err != nil {
			t.Fatalf("%s: %v", sqlText, err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
		return out
	}
	var runs []string
	for _, r := range q(`SELECT rev || ':' || scan_run_id FROM iga_gov_activity_evidence WHERE workspace_id = {ws} AND service = 'sqs' ORDER BY rev`) {
		rev, id, _ := strings.Cut(r, ":")
		runs = append(runs, rev+":"+labels[id])
	}
	revals := q(`SELECT count(*) FILTER (WHERE r.result = 'unchanged') || ' unchanged / plan_hash kept ' ||
	                    bool_and(p.plan_hash = ANY (a.plan_hashes) AND p.superseded_at IS NULL)
	               FROM iga_gov_revalidation r JOIN iga_gov_plan p ON p.id = r.plan_id
	               JOIN iga_gov_deployment d ON d.revalidation_id = r.id JOIN iga_gov_approval a ON a.id = d.approval_id
	              WHERE r.workspace_id = {ws}`)
	posture := q(`SELECT string_agg(service || '=' || outcome || '@rev' || evidence_rev || '/seq' || enforcement_seq, ', ' ORDER BY service)
	                FROM iga_gov_service_posture WHERE workspace_id = {ws}`)
	findings := q(`SELECT string_agg(detail_key || '=' || status, ', ' ORDER BY detail_key) FROM iga_gov_finding WHERE workspace_id = {ws}`)
	deps := q(`SELECT string_agg(kind || ':' || state, ', ' ORDER BY created_at, kind) FROM iga_gov_deployment WHERE workspace_id = {ws}`)
	changes := q(`SELECT count(*) FILTER (WHERE change = 'newly_excluded') || ' excluded / ' ||
	                     count(*) FILTER (WHERE change = 'newly_unexcluded') || ' unexcluded' FROM iga_gov_service_outcome WHERE workspace_id = {ws}`)
	// "bundles": the bundles the plans were compiled from. The revalidation's
	// own rev-3 bundle is a third row, asserted separately below.
	bundles := q(`SELECT count(DISTINCT evidence_bundle_id) FROM iga_gov_plan WHERE workspace_id = {ws}`)
	acc := q(`SELECT count(*) FROM iga_gov_acceptance WHERE workspace_id = {ws}`)
	seq := q(`SELECT enforcement_seq FROM iga_gov_control WHERE id = {ctl}`)

	got := strings.Join([]string{
		"evidence run per rev  " + strings.Join(runs, ", "),
		"deployments           " + deps[0],
		"posture               " + posture[0],
		"changes               " + changes[0],
		"findings              " + findings[0],
		"bundles               " + bundles[0],
		"revalidations         " + revals[0],
		"acceptances           " + acc[0],
		"control sequence      " + seq[0],
	}, "\n")
	want := strings.Join([]string{
		"evidence run per rev  1:e1, 2:e1, 3:e2, 4:e3",
		"deployments           apply:superseded, apply:undone, undo:verified",
		"posture               sns=not_removed@rev4/seq3, sqs=excluded_routes_remain@rev4/seq3",
		"changes               2 excluded / 1 unexcluded",
		"findings              sns=reopened, sqs=mitigated",
		"bundles               2",
		"revalidations         1 unchanged / plan_hash kept true",
		"acceptances           1",
		"control sequence      3",
	}, "\n")
	t.Logf("final row:\n%s", got)
	if got != want {
		t.Errorf("final row differs from §6.3:\n got:\n%s\nwant:\n%s", got, want)
	}

	// Beyond the printed row: each revision's results cite that revision's
	// run for the role, every evaluation is complete, and the evidence
	// bundles are three rows (two compiled plans + the revalidation's).
	if got := j.val(`SELECT count(*) FROM iga_gov_evaluation WHERE workspace_id = {ws} AND status = 'complete'`); got != "4" {
		t.Errorf("complete evaluations = %s, want 4", got)
	}
	if got := j.val(`SELECT count(*) FROM iga_gov_finding_result r JOIN iga_publication p ON p.workspace_id = r.workspace_id AND p.rev = r.rev
	                  WHERE r.workspace_id = {ws} AND r.evidence_scan_run_id <> (p.manifest ->> 'aws:111111111111')::uuid`); got != "0" {
		t.Errorf("%s finding results cite a run other than the role's partition in their revision's manifest", got)
	}
	if got := j.val(`SELECT count(*) FROM iga_gov_evidence_bundle WHERE workspace_id = {ws}`); got != "3" {
		t.Errorf("evidence bundle rows = %s, want 3", got)
	}
}
