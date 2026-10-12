package igagovschema_test

// SPEC-iga-phase3-policy.md §6.3, "Probes": each statement runs in its own
// sub-transaction (a SAVEPOINT) against fixtures for two workspaces, two
// policies, two roles and one connected account. Probes run IN ORDER over one
// outer transaction: an accepted probe's rows stay (later probes build on
// them, exactly as the table reads -- DB34 persists the failed state DB35
// retries, DB86-DB105 walk one role's posture through its epochs), a refused
// probe is rolled back to its savepoint. Constraints deferred to commit are
// forced with SET CONSTRAINTS ALL IMMEDIATE inside every probe, so a deferred
// violation is observed in the probe that caused it. The outer transaction is
// rolled back at the end.
//
// Each refusal is asserted EXACTLY: SQLSTATE plus the constraint or index the
// server names (CHECK / FK / unique), the column (NOT NULL / generated), or
// the PL/pgSQL function that raised (triggers; plus the message when one
// function raises for several reasons). Where a row breaks two CHECKs,
// PostgreSQL reports the first by name; the probe names that one and says
// which other also refuses it.

import (
	"fmt"
	"testing"
)

type probe struct {
	id   string
	name string
	// pre runs before the probe's savepoint and is KEPT: fixture rows a
	// probe's statement needs that are not themselves under test.
	pre  func(s *step)
	do   func(s *step)
	want outcome
	// after runs inside the savepoint of an accepted probe: value checks.
	after func(s *step)
}

func msgTrigger(fn, msg string) outcome {
	o := triggerException(fn)
	o.msg = msg
	o.label += " (" + msg + ")"
	return o
}

// probeWorld names every fixture and builds it inside tx.
func probeWorld(t *testing.T, x execer) *world {
	t.Helper()
	w := newWorld()
	w.id("ws1", "ws2", "u1", "u2", "u3", "conn", "connW2",
		"r1", "r2", "r3", "r4", "r5", "rW2",
		"iaA", "iaB", "wl1", "ap1",
		"p1", "p2", "p3", "p1v1", "p1v2", "p2v1", "p3v1",
		"ctlA", "ctlB", "ctlA2", "tA1", "tB1", "tA2", "tP2",
		"bun1", "bunW2",
		"plA1", "plA1u", "plA1x", "plB1", "plB1u", "plA2", "plSplit", "plP2",
		"apA1", "apA2", "apP2", "dA1", "dA2", "dB1", "dB2", "dP2", "dS0", "dS1",
		"fA", "fNone", "ro1", "val1", "acc1", "rvU", "rvM", "at1")
	w.str("acct", "111111111111")
	w.str("roleA", "AROAAAAAAAAAAAAAAAAAA")
	w.str("roleB", "AROABBBBBBBBBBBBBBBBB")
	w.str("arn_roleA", "arn:aws:iam::111111111111:role/RefundTaskRole")
	w.str("arn_roleB", "arn:aws:iam::111111111111:role/PaymentsTaskRole")
	w.str("bX", "arn:aws:iam::111111111111:policy/authsec/AuthSecBoundary-AROAAAAAAAAAAAAAAAAAA")
	w.str("bY", "arn:aws:iam::111111111111:policy/authsec/AuthSecBoundary-AROAAAAAAAAAAAAAAAAAA-v2")
	w.str("bShared", "arn:aws:iam::111111111111:policy/platform/SharedBoundary")
	w.str("bCopy", "arn:aws:iam::111111111111:policy/authsec/AuthSecSplit-AROABBBBBBBBBBBBBBBBB")
	w.str("bucket", "arn:aws:s3:::refunds-exports")
	w.doc("docX", `{"Statement":[{"Effect":"Allow","NotAction":["ec2:*","sqs:*"],"Resource":"*"}],"Version":"2012-10-17"}`)
	w.doc("docY", `{"Statement":[{"Effect":"Allow","NotAction":["ec2:*","sns:*","sqs:*"],"Resource":"*"}],"Version":"2012-10-17"}`)
	w.doc("docS", `{"Statement":[{"Effect":"Allow","NotAction":["iam:*"],"Resource":"*"}],"Version":"2012-10-17"}`)
	w.doc("pdoc1", `{"Statement":[{"Action":"s3:GetObject","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Resource":"arn:aws:s3:::refunds-exports/*"}],"Version":"2012-10-17"}`)
	w.doc("pdoc2", `{"Statement":[{"Action":"s3:PutObject","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::222222222222:root"},"Resource":"arn:aws:s3:::refunds-exports/*"}],"Version":"2012-10-17"}`)
	w.doc("bun1h", `{"sources":[{"connector_run":"r1","kind":"aws_publication","rev":1,"trust":"trusted"}],"target":{"account_id":"111111111111","role_id":"AROAAAAAAAAAAAAAAAAAA"}}`)
	w.doc("bunW2h", `{"sources":[{"kind":"aws_publication","rev":1,"trust":"trusted"}],"target":{"account_id":"111111111111","role_id":"AROAAAAAAAAAAAAAAAAAA"}}`)
	w.doc("bunEmpty", `{"sources":[],"target":{"role_id":"AROAAAAAAAAAAAAAAAAAA"}}`)

	s := &step{t: t, x: x, w: w}
	for _, q := range []string{
		`INSERT INTO workspaces (id, name, workspace_type) VALUES ({ws1}, 'p3 probes one', 'team'), ({ws2}, 'p3 probes two', 'team')`,
		`INSERT INTO users (id, email, workspace_id) VALUES
		   ({u1}, 'author@p3probe.test', {ws1}), ({u2}, 'approver@p3probe.test', {ws1}), ({u3}, 'other@p3probe.test', {ws2})`,
		// Two workspaces connected to one AWS account (§2.3).
		`INSERT INTO cloud_connector (id, workspace_id, provider, scope_kind, scope_id, auth_ref) VALUES
		   ({conn}, {ws1}, 'aws', 'account', '111111111111', 'vault://p3probe/a'),
		   ({connW2}, {ws2}, 'aws', 'account', '111111111111', 'vault://p3probe/b')`,
		`INSERT INTO cloud_scan_run (id, workspace_id, connector_id, generation, status, published_at) VALUES
		   ({r1}, {ws1}, {conn}, 1, 'published', now()), ({r2}, {ws1}, {conn}, 2, 'published', now()),
		   ({r3}, {ws1}, {conn}, 3, 'published', now()), ({r4}, {ws1}, {conn}, 4, 'published', now()),
		   ({r5}, {ws1}, {conn}, 5, 'published', now()), ({rW2}, {ws2}, {connW2}, 1, 'published', now())`,
		`INSERT INTO iga_publication (workspace_id, rev, published_at, scan_run_id, manifest)
		 SELECT {ws1}, n, now(), r, jsonb_build_object('aws:111111111111', r::text)
		   FROM (VALUES (1, {r1}), (2, {r2}), (3, {r3}), (4, {r4}), (5, {r5})) v(n, r)`,
		`INSERT INTO iga_publication (workspace_id, rev, published_at, scan_run_id, manifest)
		 VALUES ({ws2}, 1, now(), {rW2}, jsonb_build_object('aws:111111111111', {rW2}::text))`,
		`INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key, continuity, immutable_key, display_name) VALUES
		   ({iaA}, {ws1}, 'role', 'aws', 'aws:iam:role:111111111111:RefundTaskRole', 'immutable', 'AROAAAAAAAAAAAAAAAAAA', 'RefundTaskRole'),
		   ({iaB}, {ws1}, 'role', 'aws', 'aws:iam:role:111111111111:PaymentsTaskRole', 'immutable', 'AROABBBBBBBBBBBBBBBBB', 'PaymentsTaskRole')`,
		`INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key) VALUES ({wl1}, {ws1}, 'ecs_task', 'aws:ecs:task-definition/refunds:7')`,
		`INSERT INTO agent_policies (id, workspace_id, name, selector) VALUES ({ap1}, {ws1}, 'legacy selector policy', '{"labels":{"team":"refunds"}}')`,
		`INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by) VALUES
		   ({p1}, {ws1}, 'refund right-size', 'cloud_access', 'aws', {u1}),
		   ({p2}, {ws1}, 'refund replacement', 'cloud_access', 'aws', {u1}),
		   ({p3}, {ws2}, 'other workspace', 'cloud_access', 'aws', {u3})`,
		version("p1v1", "ws1", "p1", 1, 1),
		version("p1v2", "ws1", "p1", 2, 2),
		version("p2v1", "ws1", "p2", 1, 1),
		row("iga_gov_policy_version", []string{"id", "{p3v1}", "workspace_id", "{ws2}", "policy_id", "{p3}", "version_no", "1",
			"intent", `'{"kind":"right_size_services"}'`, "intent_hash", "'ih-p3v1'", "catalog_version", "1", "evidence_rev", "1", "created_by", "{u3}"}),
		`UPDATE iga_gov_policy SET current_version_id = {p1v1} WHERE id = {p1}`,
		`UPDATE iga_gov_policy SET current_version_id = {p2v1} WHERE id = {p2}`,
		`INSERT INTO iga_gov_document (workspace_id, document_hash, canonical, document) VALUES
		   ({ws1}, {docX}, {docX.c}, {docX.c}::jsonb), ({ws1}, {docY}, {docY.c}, {docY.c}::jsonb), ({ws1}, {docS}, {docS.c}, {docS.c}::jsonb)`,
		control("ctlA", "p1", "roleA", "iaA"),
		control("ctlB", "p1", "roleB", "iaB"),
		`INSERT INTO iga_gov_target (id, workspace_id, version_id, policy_id, control_id, is_canary) VALUES
		   ({tA1}, {ws1}, {p1v1}, {p1}, {ctlA}, true), ({tB1}, {ws1}, {p1v1}, {p1}, {ctlB}, false),
		   ({tA2}, {ws1}, {p1v2}, {p1}, {ctlA}, true)`,
		`INSERT INTO iga_gov_evidence_bundle (id, workspace_id, provider, trust, bundle_hash, canonical, facts) VALUES
		   ({bun1}, {ws1}, 'aws', 'partial', {bun1h}, {bun1h.c}, {bun1h.c}::jsonb),
		   ({bunW2}, {ws2}, 'aws', 'trusted', {bunW2h}, {bunW2h.c}, {bunW2h.c}::jsonb)`,
		plan("plA1", "p1v1", "tA1", "ctlA", "unanalysed", `'[{"form":"ecr_repository"}]'`),
		plan("plA1x", "p1v1", "tA1", "ctlA", "delivery", "'export'", "superseded_at", "now()"),
		plan("plB1", "p1v1", "tB1", "ctlB"),
		plan("plA2", "p1v2", "tA2", "ctlA", "desired_boundary_arn", "{bY}", "desired_document_hash", "{docY}", "evidence_rev", "2"),
		approval("apA1", "p1v1", "plA1"),
		approval("apA2", "p1v2", "plA2"),
		deployment("dA1", "p1v1", "plA1", "ctlA", "apA1"),
		`INSERT INTO iga_gov_evaluation (workspace_id, rev, status) VALUES ({ws1}, 1, 'running')`,
		`INSERT INTO iga_gov_finding (id, workspace_id, fingerprint, kind, family, severity, confidence,
		     identity_account_id, role_id, connector_id, detail_key, first_seen_rev, last_evaluated_rev)
		   VALUES ({fA}, {ws1}, 'sha256:fp-unused-sqs-A', 'unused_service', 'cloud_access', 'high', 'age_unverified',
		     {iaA}, {roleA}, {conn}, 'sqs', 1, 2)`,
		`INSERT INTO cloud_policy_document (workspace_id, document_hash, canonical, document) VALUES
		   ({ws1}, {pdoc1}, {pdoc1.c}, {pdoc1.c}::jsonb), ({ws1}, {pdoc2}, {pdoc2.c}, {pdoc2.c}::jsonb)`,
		`INSERT INTO cloud_resource_policy_coverage (workspace_id, connector_id, scan_run_id, resource_form, region, state, enumerated, read_ok)
		   VALUES ({ws1}, {conn}, {r1}, 's3_bucket', 'us-east-1', 'complete', 1, 1)`,
		`INSERT INTO cloud_resource_policy_observation (workspace_id, scan_run_id, resource_form, region, resource_arn, policy_present, document_hash, read_at)
		   VALUES ({ws1}, {r1}, 's3_bucket', 'us-east-1', {bucket}, true, {pdoc1}, now())`,
		`SET CONSTRAINTS ALL IMMEDIATE`,
		`SET CONSTRAINTS ` + deferredPhase3 + ` DEFERRED`,
	} {
		s.exec(q)
		if s.err != nil {
			t.Fatalf("fixture: %s\n%s", describe(s.err), w.sql(q))
		}
	}
	return w
}

func probes() []probe {
	x := func(qs ...string) func(*step) {
		return func(s *step) {
			for _, q := range qs {
				s.exec(q)
			}
		}
	}
	return []probe{
		/* ---------------------------- legacy, policy --------------------------- */
		{id: "DB1", name: "Legacy agent_policies row still insertable unchanged by 047-056", want: accepted(),
			do: x(`INSERT INTO agent_policies (workspace_id, name, selector) VALUES ({ws1}, 'legacy probe', '{"labels":{"app":"refunds"}}')`)},
		{id: "DB2", name: "A governance policy cannot reference a legacy agent policy",
			want: fkViolation("iga_gov_policy_version_workspace_id_policy_id_fkey"),
			do: x(row("iga_gov_policy_version", []string{"workspace_id", "{ws1}", "policy_id", "{ap1}", "version_no", "1",
				"intent", "'{}'", "intent_hash", "'ih'", "catalog_version", "1", "evidence_rev", "1", "created_by", "{u1}"}))},
		{id: "DB3", name: "Governance policy with an unsupported provider (R1k adds k8s)",
			want: checkViolation("iga_gov_policy_provider_check"),
			do:   x(`INSERT INTO iga_gov_policy (workspace_id, name, family, provider, created_by) VALUES ({ws1}, 'k8s', 'cloud_access', 'k8s', {u1})`)},
		{id: "DB4", name: "Governance policy with an unknown family",
			want: checkViolation("iga_gov_policy_family_check"),
			do:   x(`INSERT INTO iga_gov_policy (workspace_id, name, family, provider, created_by) VALUES ({ws1}, 'x', 'access_review', 'aws', {u1})`)},
		{id: "DB5", name: "Second live control for role A, owned by p2",
			want: uniqueViolation("uq_iga_gov_control_live"),
			do:   x(row("iga_gov_control", []string{"workspace_id", "{ws1}", "connector_id", "{conn}", "account_id", "{acct}", "role_id", "{roleA}", "role_arn", "{arn_roleA}", "identity_account_id", "{iaA}", "policy_id", "{p2}", "boundary_policy_arn", "{bX}"}))},
		{id: "DB6", name: "p2 version targets p1's control",
			want: fkViolation("iga_gov_target_workspace_id_control_id_policy_id_fkey"),
			do:   x(`INSERT INTO iga_gov_target (workspace_id, version_id, policy_id, control_id) VALUES ({ws1}, {p2v1}, {p2}, {ctlA})`)},
		{id: "DB7", name: "Second in-flight deployment on role A from another version",
			want: uniqueViolation("uq_iga_gov_deployment_inflight"),
			do:   x(deployment("dA2", "p1v2", "plA2", "ctlA", "apA2"))},
		{id: "DB8", name: "Version 1 deployment using version 2's approval",
			want: fkViolation("iga_gov_deployment_workspace_id_approval_id_version_id_fkey"),
			do:   x(deployment("dA2", "p1v1", "plA1", "ctlA", "apA2", "state", "'blocked'"))},
		{id: "DB9", name: "Version 1 deployment using version 2's plan",
			want: fkViolation("iga_gov_deployment_workspace_id_plan_id_version_id_control_fkey"),
			do:   x(deployment("dA2", "p1v1", "plA2", "ctlA", "apA1", "state", "'blocked'"))},
		{id: "DB10", name: "apply deployment with no approval and no emergency",
			want: checkViolation("iga_gov_pd_authority_chk"),
			do:   x(deployment("dA2", "p1v1", "plA1", "ctlA", "", "state", "'blocked'"))},
		{id: "DB11", name: "Rollout stage partial", want: accepted(),
			do: x(`INSERT INTO iga_gov_rollout (id, workspace_id, version_id, stage) VALUES ({ro1}, {ws1}, {p1v1}, 'partial')`)},
		{id: "DB12", name: "Metrics row at hh:05",
			want: checkViolation("iga_gov_metrics_hourly_hour_check"),
			do:   x(`INSERT INTO iga_gov_metrics_hourly (workspace_id, hour) VALUES ({ws1}, '2026-10-07 10:05:00+00')`)},
		{id: "DB13", name: "Version intent updated",
			want: triggerException("iga_gov_policy_version_immutable"),
			do:   x(`UPDATE iga_gov_policy_version SET intent = '{"kind":"right_size_services","remove":[]}' WHERE id = {p1v1}`)},
		{id: "DB14", name: "Two approved versions of one policy",
			want: uniqueViolation("uq_iga_gov_policy_version_one_approved"),
			pre:  x(`UPDATE iga_gov_policy_version SET status = 'approved', status_changed_at = now() WHERE id = {p1v1}`),
			do:   x(`UPDATE iga_gov_policy_version SET status = 'approved', status_changed_at = now() WHERE id = {p1v2}`)},
		{id: "DB15", name: "Event updated",
			want: triggerException("iga_gov_event_immutable"),
			pre:  x(`INSERT INTO iga_gov_event (workspace_id, event, actor_kind, actor_id, policy_id) VALUES ({ws1}, 'policy.created', 'user', {u1}::text, {p1})`),
			do:   x(`UPDATE iga_gov_event SET event = 'policy.renamed' WHERE workspace_id = {ws1}`)},
		{id: "DB16", name: "Event deleted outside purge",
			want: triggerException("iga_gov_event_immutable"),
			do:   x(`DELETE FROM iga_gov_event WHERE workspace_id = {ws1}`)},
		{id: "DB17", name: "Target in workspace 2 on workspace 1's control",
			want: fkViolation("iga_gov_target_workspace_id_control_id_policy_id_fkey"),
			do:   x(`INSERT INTO iga_gov_target (workspace_id, version_id, policy_id, control_id) VALUES ({ws2}, {p3v1}, {p3}, {ctlA})`)},

		/* ------------------------------ bundles, plans ------------------------- */
		{id: "DB18", name: "Plan without an evidence bundle",
			want: notNullViolation("evidence_bundle_id"),
			do:   x(plan("plA1", "p1v1", "tA1", "ctlA", "id", "gen_random_uuid()", "evidence_bundle_id", "NULL", "superseded_at", "now()"))},
		{id: "DB19", name: "Evidence bundle whose hash does not match its facts",
			want: msgTrigger("iga_gov_bundle_insert_check", "hash does not match"),
			do: x(`INSERT INTO iga_gov_evidence_bundle (workspace_id, provider, trust, bundle_hash, canonical, facts)
			       VALUES ({ws1}, 'aws', 'trusted', {bunW2h}, {bun1h.c}, {bun1h.c}::jsonb)`)},
		{id: "DB20", name: "Evidence bundle naming no source",
			want: msgTrigger("iga_gov_bundle_insert_check", "must name at least one source"),
			do: x(`INSERT INTO iga_gov_evidence_bundle (workspace_id, provider, trust, bundle_hash, canonical, facts)
			       VALUES ({ws1}, 'aws', 'trusted', {bunEmpty}, {bunEmpty.c}, {bunEmpty.c}::jsonb)`)},
		{id: "DB21", name: "Evidence bundle rewritten after use",
			want: triggerException("authsec_row_immutable"),
			do:   x(`UPDATE iga_gov_evidence_bundle SET trust = 'trusted' WHERE id = {bun1}`)},
		{id: "DB22", name: "Plan using another workspace's evidence bundle",
			want: fkViolation("iga_gov_plan_workspace_id_evidence_bundle_id_fkey"),
			do:   x(plan("plA1", "p1v1", "tA1", "ctlA", "id", "gen_random_uuid()", "evidence_bundle_id", "{bunW2}", "superseded_at", "now()"))},
		{id: "DB23", name: "Undo plan to no boundary", want: accepted(),
			do: x(plan("plA1u", "p1v1", "tA1", "ctlA", "kind", "'undo'", "desired_attachment", "'absent'",
				"desired_boundary_arn", "NULL", "desired_document_hash", "NULL", "before_document_hash", "{docX}",
				"replaced_boundary_arn", "{bX}", "artifact_disposition", "'delete'"))},
		// Also refused by iga_gov_plan_kind_chk (apply must be present);
		// PostgreSQL names the alphabetically first failing CHECK.
		{id: "DB24", name: "apply plan with an absent boundary",
			want: checkViolation("iga_gov_plan_disposition_chk"),
			do: x(plan("plB1", "p1v1", "tB1", "ctlB", "id", "gen_random_uuid()", "desired_attachment", "'absent'",
				"desired_boundary_arn", "NULL", "desired_document_hash", "NULL", "superseded_at", "now()"))},
		{id: "DB25", name: "present plan without a document",
			want: checkViolation("iga_gov_plan_attachment_chk"),
			do: x(plan("plB1", "p1v1", "tB1", "ctlB", "id", "gen_random_uuid()", "desired_document_hash", "NULL",
				"superseded_at", "now()"))},
		{id: "DB26", name: "Deployment of role A's plan locking role B",
			want: fkViolation("iga_gov_deployment_workspace_id_plan_id_version_id_control_fkey"),
			do:   x(deployment("dA2", "p1v1", "plA1", "ctlB", "apA1", "state", "'blocked'"))},
		{id: "DB27", name: "apply plan run as undo",
			want: fkViolation("iga_gov_deployment_workspace_id_plan_id_version_id_control_fkey"),
			do:   x(deployment("dA2", "p1v1", "plA1", "ctlA", "apA1", "kind", "'undo'", "state", "'blocked'"))},
		{id: "DB28", name: "direct plan delivered as a PR",
			want: fkViolation("iga_gov_deployment_workspace_id_plan_id_version_id_control_fkey"),
			do:   x(deployment("dA2", "p1v1", "plA1", "ctlA", "apA1", "delivery", "'iac_pr'", "state", "'blocked'"))},
		{id: "DB29", name: "Role B's own plan while role A is in flight", want: accepted(),
			do: x(deployment("dB1", "p1v1", "plB1", "ctlB", "apA1"))},
		{id: "DB30", name: "Control active without a baseline",
			want: checkViolation("iga_gov_rc_baseline_chk"),
			do:   x(`UPDATE iga_gov_control SET state = 'active' WHERE id = {ctlB}`)},

		/* ------------------------- evaluation and findings ---------------------- */
		{id: "DB31", name: "Finding result inserted before its finding exists",
			want: fkViolation("iga_gov_finding_result_workspace_id_finding_id_fkey"),
			do: x(`INSERT INTO iga_gov_finding_result (workspace_id, rev, finding_id, severity, confidence, evidence_scan_run_id)
			       VALUES ({ws1}, 1, {fNone}, 'high', 'age_unverified', {r1})`)},
		{id: "DB32", name: "Evidence written while the evaluation runs", want: accepted(),
			do: x(evidence(1, "sqs"))},
		{id: "DB33", name: "Evaluation failed; evidence write on replay without the retry transition",
			want: triggerException("iga_gov_evaluation_rows_frozen"),
			do: x(`UPDATE iga_gov_evaluation SET status = 'failed', finished_at = now(), error = 'budget exceeded' WHERE workspace_id = {ws1} AND rev = 1`,
				evidence(1, "ec2"))},
		{id: "DB34", name: "Persist the failed state", want: accepted(),
			do: x(`UPDATE iga_gov_evaluation SET status = 'failed', finished_at = now(), error = 'budget exceeded' WHERE workspace_id = {ws1} AND rev = 1`)},
		{id: "DB35", name: "Retry without incrementing attempts",
			want: triggerException("iga_gov_evaluation_transition"),
			do:   x(`UPDATE iga_gov_evaluation SET status = 'running' WHERE workspace_id = {ws1} AND rev = 1`)},
		{id: "DB36", name: "Fenced retry failed -> running, attempts + 1, then evidence and result", want: accepted(),
			do: func(s *step) {
				s.rows(1, `UPDATE iga_gov_evaluation SET status = 'running', attempts = attempts + 1, finished_at = NULL, error = ''
				           WHERE workspace_id = {ws1} AND rev = 1 AND status = 'failed'`)
				s.exec(evidence(1, "s3"))
				s.exec(`INSERT INTO iga_gov_finding_result (workspace_id, rev, finding_id, severity, confidence, detail, evidence_scan_run_id)
				        VALUES ({ws1}, 1, {fA}, 'high', 'age_unverified', '{"qualified_days":112}', {r1})`)
			},
			after: func(s *step) {
				s.eq("2", `SELECT attempts FROM iga_gov_evaluation WHERE workspace_id = {ws1} AND rev = 1`)
			}},
		{id: "DB37", name: "Completed evaluation reopened on replay",
			want: triggerException("iga_gov_evaluation_transition"),
			pre:  x(`UPDATE iga_gov_evaluation SET status = 'complete', finished_at = now() WHERE workspace_id = {ws1} AND rev = 1`),
			do:   x(`UPDATE iga_gov_evaluation SET status = 'running', attempts = attempts + 1 WHERE workspace_id = {ws1} AND rev = 1`)},
		{id: "DB38", name: "Result changed after completion",
			want: triggerException("iga_gov_evaluation_rows_frozen"),
			do:   x(`UPDATE iga_gov_finding_result SET severity = 'low' WHERE workspace_id = {ws1} AND rev = 1 AND finding_id = {fA}`)},
		{id: "DB39", name: "Finding moved to an older revision",
			want: triggerException("iga_gov_finding_monotonic"),
			do:   x(`UPDATE iga_gov_finding SET last_evaluated_rev = 1 WHERE id = {fA}`)},

		/* ---------------------------- split and delivery ----------------------- */
		{id: "DB40", name: "split plan delivered direct",
			want: checkViolation("iga_gov_plan_kind_chk"),
			do: x(plan("plSplit", "p1v1", "tB1", "ctlB", "kind", "'split'", "desired_attachment", "'unchanged'",
				"desired_boundary_arn", "NULL", "desired_document_hash", "NULL"))},
		{id: "DB41", name: "split plan as a PR", want: accepted(),
			do: x(plan("plSplit", "p1v1", "tB1", "ctlB", "kind", "'split'", "delivery", "'iac_pr'", "desired_attachment", "'unchanged'",
				"desired_boundary_arn", "NULL", "desired_document_hash", "NULL"))},
		{id: "DB42", name: "split_revert plan (unchanged boundary) as a PR", want: accepted(),
			do: x(plan("plA1", "p1v1", "tB1", "ctlB", "id", "gen_random_uuid()", "kind", "'split_revert'", "delivery", "'iac_pr'",
				"desired_attachment", "'unchanged'", "desired_boundary_arn", "NULL", "desired_document_hash", "NULL"))},
		{id: "DB43", name: "split_revert plan delivered direct",
			want: checkViolation("iga_gov_plan_kind_chk"),
			do: x(plan("plA1", "p1v1", "tB1", "ctlB", "id", "gen_random_uuid()", "kind", "'split_revert'",
				"desired_attachment", "'unchanged'", "desired_boundary_arn", "NULL", "desired_document_hash", "NULL", "superseded_at", "now()"))},
		{id: "DB44", name: "undo plan claiming an unchanged boundary",
			want: checkViolation("iga_gov_plan_kind_chk"),
			do: x(plan("plA1", "p1v1", "tB1", "ctlB", "id", "gen_random_uuid()", "kind", "'undo'",
				"desired_attachment", "'unchanged'", "desired_boundary_arn", "NULL", "desired_document_hash", "NULL", "superseded_at", "now()"))},
		{id: "DB45", name: "export deployment in awaiting_merge",
			want: checkViolation("iga_gov_pd_delivery_state_chk"),
			do:   x(deployment("dA2", "p1v1", "plA1x", "ctlA", "apA1", "delivery", "'export'", "state", "'awaiting_merge'"))},
		{id: "DB46", name: "Restriction outcome not_applicable", want: accepted(),
			do: x(`INSERT INTO iga_gov_verification (workspace_id, deployment_id, dimension, outcome) VALUES ({ws1}, {dA1}, 'restriction', 'not_applicable')`)},

		/* -------------------------------- validations -------------------------- */
		{id: "DB47", name: "Validation with an ordinary session name",
			want: checkViolation("iga_gov_vr_correlation_chk"),
			do: x(`INSERT INTO iga_gov_validation (workspace_id, deployment_id, created_by, role_id, correlation, session_name, window_start, window_end)
			       VALUES ({ws1}, {dA1}, {u1}, {roleA}, 'assumed_session', 'refund-debug', now() - interval '1 hour', now())`)},
		{id: "DB48", name: "Validation with a dedicated session and per-action items", want: accepted(),
			do: x(`INSERT INTO iga_gov_validation (id, workspace_id, deployment_id, created_by, role_id, correlation, session_name, window_start, window_end)
			       VALUES ({val1}, {ws1}, {dA1}, {u1}, {roleA}, 'assumed_session', 'authsec-validate-7f3a9c', now() - interval '1 hour', now())`,
				`INSERT INTO iga_gov_validation_item (workspace_id, validation_id, action, expected) VALUES
				   ({ws1}, {val1}, 'sqs:SendMessage', 'denied'), ({ws1}, {val1}, 's3:GetObject', 'allowed')`)},
		{id: "DB49", name: "Item matched while an opposite outcome was seen",
			want: checkViolation("iga_gov_vi_result_chk"),
			do: x(`INSERT INTO iga_gov_validation_item (workspace_id, validation_id, action, expected, result, matched_events, opposite_events)
			       VALUES ({ws1}, {val1}, 'sqs:ReceiveMessage', 'denied', 'matched', 1, 1)`)},
		{id: "DB50", name: "Item contradicted with an opposite outcome", want: accepted(),
			do: x(`INSERT INTO iga_gov_validation_item (workspace_id, validation_id, action, expected, result, matched_events, opposite_events)
			       VALUES ({ws1}, {val1}, 'sqs:DeleteMessage', 'denied', 'contradicted', 0, 1)`)},

		/* ------------------------- resource-policy evidence ---------------------- */
		{id: "DB51", name: "Resource-policy coverage complete with a failed read",
			want: checkViolation("cloud_rpc_complete_chk"),
			do: x(`INSERT INTO cloud_resource_policy_coverage (workspace_id, connector_id, scan_run_id, resource_form, region, state, enumerated, read_ok, read_failed)
			       VALUES ({ws1}, {conn}, {r1}, 'sqs_queue', 'us-east-1', 'complete', 3, 2, 1)`)},
		{id: "DB52", name: "Resource-policy coverage partial without a reason",
			want: checkViolation("cloud_rpc_reason_chk"),
			do: x(`INSERT INTO cloud_resource_policy_coverage (workspace_id, connector_id, scan_run_id, resource_form, region, state, enumerated, read_ok, read_failed)
			       VALUES ({ws1}, {conn}, {r1}, 'kms_key', 'us-east-1', 'partial', 3, 2, 1)`)},
		{id: "DB53", name: "Observation for a (form, region) with no coverage row",
			want: fkViolation("cloud_resource_policy_observa_workspace_id_scan_run_id_res_fkey"),
			do: x(`INSERT INTO cloud_resource_policy_observation (workspace_id, scan_run_id, resource_form, region, resource_arn, policy_present, read_at)
			       VALUES ({ws1}, {r1}, 'sqs_queue', 'eu-west-1', 'arn:aws:sqs:eu-west-1:111111111111:refunds', false, now())`)},
		{id: "DB54", name: "Observation marked present without a document",
			want: checkViolation("cloud_rpo_document_chk"),
			do: x(`INSERT INTO cloud_resource_policy_observation (workspace_id, scan_run_id, resource_form, region, resource_arn, policy_present, read_at)
			       VALUES ({ws1}, {r1}, 's3_bucket', 'us-east-1', 'arn:aws:s3:::other-bucket', true, now())`)},
		{id: "DB55", name: "Scan N observations survive a rescan", want: accepted(),
			do: x(`INSERT INTO cloud_resource_policy_coverage (workspace_id, connector_id, scan_run_id, resource_form, region, state, enumerated, read_ok)
			       VALUES ({ws1}, {conn}, {r2}, 's3_bucket', 'us-east-1', 'complete', 1, 1)`,
				`INSERT INTO cloud_resource_policy_observation (workspace_id, scan_run_id, resource_form, region, resource_arn, policy_present, document_hash, read_at)
				   VALUES ({ws1}, {r2}, 's3_bucket', 'us-east-1', {bucket}, true, {pdoc2}, now())`),
			after: func(s *step) {
				s.eq("1", `SELECT count(*) FROM cloud_resource_policy_observation WHERE scan_run_id = {r1} AND resource_arn = {bucket} AND document_hash = {pdoc1}`)
				s.eq("2", `SELECT count(*) FROM cloud_resource_policy_observation WHERE workspace_id = {ws1} AND resource_arn = {bucket}`)
			}},
		{id: "DB56", name: "Observation rewritten in place",
			want: triggerException("authsec_row_immutable"),
			do:   x(`UPDATE cloud_resource_policy_observation SET policy_present = false, document_hash = NULL WHERE scan_run_id = {r1}`)},
		{id: "DB57", name: "Coverage rewritten in place",
			want: triggerException("authsec_row_immutable"),
			do:   x(`UPDATE cloud_resource_policy_coverage SET state = 'partial', reason = 'rewritten' WHERE scan_run_id = {r1}`)},

		/* ------------------------ attachment and disposition --------------------- */
		{id: "DB58", name: "Absent attachment that keeps the artifact",
			want: checkViolation("iga_gov_plan_disposition_chk"),
			do: x(plan("plA1", "p1v2", "tA2", "ctlA", "id", "gen_random_uuid()", "kind", "'undo'", "desired_attachment", "'absent'",
				"desired_boundary_arn", "NULL", "desired_document_hash", "NULL", "superseded_at", "now()"))},
		{id: "DB59", name: "apply plan that retains a shared artifact",
			want: checkViolation("iga_gov_plan_disposition_chk"),
			do: x(plan("plA1", "p1v2", "tA2", "ctlA", "id", "gen_random_uuid()", "replaced_boundary_arn", "{bShared}",
				"artifact_disposition", "'retain_shared'", "superseded_at", "now()"))},
		{id: "DB60", name: "Role-only recovery: detach here, retain the shared policy", want: accepted(),
			do: x(plan("plA1", "p1v2", "tA2", "ctlA", "id", "gen_random_uuid()", "kind", "'undo'", "desired_attachment", "'absent'",
				"desired_boundary_arn", "NULL", "desired_document_hash", "NULL", "before_document_hash", "{docS}",
				"replaced_boundary_arn", "{bShared}", "artifact_disposition", "'retain_shared'"))},
		{id: "DB61", name: "Role-only recovery to an earlier document under a new policy", want: accepted(),
			do: x(plan("plB1u", "p1v1", "tB1", "ctlB", "kind", "'undo'", "desired_boundary_arn", "{bY}", "desired_document_hash", "{docX}",
				"before_document_hash", "{docY}", "replaced_boundary_arn", "{bX}", "artifact_disposition", "'retain_shared'"))},
		{id: "DB62", name: "First attachment without a named resource-policy scan",
			want: checkViolation("iga_gov_plan_first_attachment_chk"),
			do:   x(plan("plA1", "p1v2", "tA2", "ctlA", "id", "gen_random_uuid()", "first_attachment", "true", "superseded_at", "now()"))},
		{id: "DB63", name: "First attachment naming the scan whose evidence it used", want: accepted(),
			do: x(plan("plA1", "p1v2", "tA2", "ctlA", "id", "gen_random_uuid()", "first_attachment", "true",
				"resource_policy_scan_run_id", "{r1}", "superseded_at", "now()"))},

		/* ---------------------------- content-addressed ------------------------ */
		{id: "DB64", name: "Document whose hash does not match its canonical text",
			want: msgTrigger("authsec_document_insert_check", "document_hash does not match"),
			do: x(`INSERT INTO iga_gov_document (workspace_id, document_hash, canonical, document)
			       VALUES ({ws1}, {docY}, {docS.c}, {docS.c}::jsonb)`)},
		{id: "DB65", name: "Document whose jsonb differs from its canonical text",
			want: msgTrigger("authsec_document_insert_check", "does not equal its canonical text"),
			do: x(`INSERT INTO cloud_policy_document (workspace_id, document_hash, canonical, document)
			       VALUES ({ws1}, {docS}, {docS.c}, {docX.c}::jsonb)`)},
		{id: "DB66", name: "Policy document rewritten under its hash",
			want: triggerException("authsec_row_immutable"),
			do:   x(`UPDATE cloud_policy_document SET canonical = {pdoc2.c}, document = {pdoc2.c}::jsonb WHERE document_hash = {pdoc1}`)},
		{id: "DB67", name: "Boundary document rewritten under its hash",
			want: triggerException("authsec_row_immutable"),
			do:   x(`UPDATE iga_gov_document SET document = '{}' WHERE document_hash = {docX}`)},
		{id: "DB68", name: "Duplicate insert of the same content", want: accepted(),
			do: x(`INSERT INTO iga_gov_document (workspace_id, document_hash, canonical, document)
			       VALUES ({ws1}, {docX}, {docX.c}, {docX.c}::jsonb) ON CONFLICT (workspace_id, document_hash) DO NOTHING`,
				`INSERT INTO cloud_policy_document (workspace_id, document_hash, canonical, document)
				   VALUES ({ws1}, {pdoc1}, {pdoc1.c}, {pdoc1.c}::jsonb) ON CONFLICT (workspace_id, document_hash) DO NOTHING`),
			after: func(s *step) {
				s.eq("1", `SELECT count(*) FROM iga_gov_document WHERE document_hash = {docX}`)
				s.eq("1", `SELECT count(*) FROM cloud_policy_document WHERE document_hash = {pdoc1}`)
			}},
		{id: "DB69", name: "Delete a document an observation references",
			want: fkViolation("cloud_resource_policy_observati_workspace_id_document_hash_fkey"),
			do:   x(`DELETE FROM cloud_policy_document WHERE document_hash = {pdoc1}`)},

		/* ------------------------- per-deployment history ---------------------- */
		{id: "DB70", name: "Outcome removed while a bypass route is known",
			want: checkViolation("iga_gov_so_outcome_chk"),
			do: x(serviceOutcome("dA1", "sqs", "route_state", "'bypass_known'",
				"routes", `'[{"resource":"arn:aws:sqs:us-east-1:111111111111:refunds","principal":"role_session"}]'`))},
		{id: "DB71", name: "Outcome removed with routes listed",
			want: checkViolation("iga_gov_so_routes_chk"),
			do: x(serviceOutcome("dA1", "sns",
				"routes", `'[{"resource":"arn:aws:sns:us-east-1:111111111111:refunds","principal":"role_session"}]'`))},
		{id: "DB72", name: "Outcome removed before the exclusion is applied",
			want: checkViolation("iga_gov_so_outcome_chk"),
			do:   x(serviceOutcome("dA1", "ec2", "exclusion", "'pending'"))},
		{id: "DB73", name: "Outcome excluded, bypass route known", want: accepted(),
			do: x(serviceOutcome("dA1", "sqs", "route_state", "'bypass_known'",
				"routes", `'[{"resource":"arn:aws:sqs:us-east-1:111111111111:refunds","principal":"role_session"}]'`,
				"outcome", "'excluded_routes_remain'"))},
		{id: "DB74", name: "Outcome excluded, routes not analysed", want: accepted(),
			do: x(serviceOutcome("dA1", "sns", "route_state", "'not_analysed'", "routes", `'[{"form":"ecr_repository"}]'`,
				"outcome", "'excluded_routes_unknown'"))},
		{id: "DB75", name: "Outcome removed while a denied-expected test call succeeded",
			want: checkViolation("iga_gov_so_outcome_chk"),
			do:   x(serviceOutcome("dA1", "ec2", "restriction", "'contradicted'"))},
		{id: "DB76", name: "Outcome not removed because the test contradicted the exclusion", want: accepted(),
			do: x(serviceOutcome("dA1", "ec2", "restriction", "'contradicted'", "outcome", "'not_removed'"))},
		{id: "DB77", name: "Finding mitigated", want: accepted(),
			do: x(`UPDATE iga_gov_finding SET status = 'mitigated', status_changed_at = now() WHERE id = {fA}`)},

		/* ---------------------- evidence from the role's connector -------------- */
		{id: "DB78", name: "Open a running evaluation for rev 5", want: accepted(),
			do: x(`INSERT INTO iga_gov_evaluation (workspace_id, rev, status) VALUES ({ws1}, 5, 'running')`)},
		{id: "DB79", name: "Collected activity evidence without its connector run",
			want: checkViolation("iga_gov_ae_scan_chk"),
			do:   x(evidence(5, "sqs", "scan_run_id", "NULL"))},
		{id: "DB80", name: "Route usage concluded without its connector run",
			want: checkViolation("iga_gov_ae_route_chk"),
			do: x(evidence(5, "sqs", "state", "'not_collected'", "reason", "'outside the activity sample'",
				"report_generated_at", "NULL", "scan_run_id", "NULL", "route_usage", "'none_observed'"))},
		{id: "DB81", name: "Evidence naming the role connector's run from the manifest", want: accepted(),
			do: x(evidence(5, "sqs", "route_usage", "'none_observed'")),
			after: func(s *step) {
				s.eq("true", `SELECT (e.scan_run_id = (p.manifest ->> 'aws:111111111111')::uuid)::text
				                FROM iga_gov_activity_evidence e
				                JOIN iga_publication p ON p.workspace_id = e.workspace_id AND p.rev = e.rev
				               WHERE e.workspace_id = {ws1} AND e.rev = 5 AND e.service = 'sqs'`)
			}},

		/* ------------------------------ current posture ------------------------ */
		{id: "DB82", name: "Posture outcome written by a caller",
			want: generatedColumn("outcome"),
			do:   x(posture("outcome", "'removed'"))},
		{id: "DB83", name: "Posture exclusion applied with no boundary in force",
			want: checkViolation("iga_gov_sp_in_force_chk"),
			do:   x(posture("exclusion", "'applied'"))},
		{id: "DB84", name: "Posture route conclusion without its connector run",
			want: checkViolation("iga_gov_sp_evidence_chk"),
			do:   x(posture("evidence_scan_run_id", "NULL"))},
		{id: "DB85", name: "Posture inserted with a sequence the control does not hold",
			want: msgTrigger("iga_gov_service_posture_order", "inserted with enforcement_seq"),
			do:   x(posture("enforcement_seq", "5"))},
		{id: "DB86", name: "Verification wins the compare-and-swap (0 -> 1) and records the exclusion; outcome derives removed", want: accepted(),
			do: func(s *step) {
				s.rows(1, `UPDATE iga_gov_control SET enforcement_seq = 1 WHERE id = {ctlA} AND enforcement_seq = 0`)
				s.exec(posture("current_deployment_id", "{dA1}", "boundary_document_hash", "{docX}", "exclusion", "'applied'", "enforcement_seq", "1"))
			},
			after: func(s *step) { s.eq("removed", postureOutcome) }},
		{id: "DB87", name: "Second current posture row for the same role and service",
			want: uniqueViolation("iga_gov_service_posture_pkey"),
			do:   x(posture("enforcement_seq", "1"))},
		{id: "DB88", name: "Publication at rev 2 records a session bypass; outcome derives excluded_routes_remain", want: accepted(),
			do: x(`UPDATE iga_gov_service_posture SET route_state = 'bypass_known',
			         routes = '[{"resource":"arn:aws:sqs:us-east-1:111111111111:refunds","principal":"role_session"}]',
			         evidence_rev = 2, evidence_scan_run_id = {r2}
			       WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`),
			after: func(s *step) { s.eq("excluded_routes_remain", postureOutcome) }},
		{id: "DB89", name: "Route facts overwritten from older evidence",
			want: msgTrigger("iga_gov_service_posture_order", "cannot be replaced by rev"),
			do: x(`UPDATE iga_gov_service_posture SET route_state = 'none_observed', routes = '[]', evidence_rev = 1, evidence_scan_run_id = {r1}
			       WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`)},
		{id: "DB90", name: "Drift readback wins the compare-and-swap (1 -> 2): boundary gone, outcome derives not_removed", want: accepted(),
			do: func(s *step) {
				s.rows(1, `UPDATE iga_gov_control SET enforcement_seq = 2 WHERE id = {ctlA} AND enforcement_seq = 1`)
				s.exec(`UPDATE iga_gov_service_posture SET exclusion = 'not_applied', enforcement_seq = 2, enforcement_observed_at = now()
				        WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`)
			},
			after: func(s *step) { s.eq("not_removed", postureOutcome) }},
		{id: "DB91", name: "Delayed evaluation (rev 5, snapshot taken before the drift) writes route facts only; outcome stays not_removed", want: accepted(),
			do: x(`UPDATE iga_gov_service_posture SET route_state = 'none_observed', routes = '[]', evidence_rev = 5, evidence_scan_run_id = {r5}
			       WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`),
			after: func(s *step) { s.eq("not_removed", postureOutcome) }},
		{id: "DB92", name: "Delayed evaluation tries to restore the boundary state it snapshotted",
			want: msgTrigger("iga_gov_service_posture_order", "need a newer observation"),
			do: x(`UPDATE iga_gov_service_posture SET exclusion = 'applied', enforcement_seq = 1
			       WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`)},
		{id: "DB93", name: "Stale readback (saw sequence 1) loses the compare-and-swap and cannot write",
			want: msgTrigger("iga_gov_service_posture_order", "need a newer observation"),
			do: func(s *step) {
				s.rows(0, `UPDATE iga_gov_control SET enforcement_seq = 2 WHERE id = {ctlA} AND enforcement_seq = 1`)
				s.exec(`UPDATE iga_gov_service_posture SET exclusion = 'applied', enforcement_seq = 2
				        WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`)
			}},
		{id: "DB94", name: "Successive deployments count each exclusion once", want: accepted(),
			do: x(deployment("dA2", "p1v2", "plA2", "ctlA", "apA2", "state", "'verified'", "verified_at", "now()"),
				serviceOutcome("dA2", "sqs", "change", "'already_excluded'")),
			after: func(s *step) {
				s.eq("1", `SELECT count(*) FROM iga_gov_service_outcome o JOIN iga_gov_deployment d ON d.workspace_id = o.workspace_id AND d.id = o.deployment_id
				            WHERE d.control_id = {ctlA} AND o.service = 'sqs' AND o.change = 'newly_excluded'`)
				s.eq("1", `SELECT count(*) FROM iga_gov_service_outcome WHERE deployment_id = {dA2} AND change = 'already_excluded'`)
			}},
		{id: "DB95", name: "Outcome history requires the change relative to the previous boundary",
			want: notNullViolation("change"),
			do:   x(serviceOutcome("dA2", "sns", "change", "NULL"))},

		/* ------------------------ the control as the epoch ---------------------- */
		{id: "DB96", name: "Posture moved to another role's control",
			want: msgTrigger("iga_gov_service_posture_order", "cannot belong to control"),
			do: x(`UPDATE iga_gov_service_posture SET control_id = {ctlB}
			       WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`)},
		{id: "DB97", name: "Replacement control created while the old one is still live",
			want: uniqueViolation("uq_iga_gov_control_live"),
			do:   x(control("ctlA2", "p2", "roleA", "iaA"))},
		{id: "DB98", name: "Retire role A's control: final observation advances 2 -> 3 in the retiring statement", want: accepted(),
			do: func(s *step) {
				s.rows(1, `UPDATE iga_gov_control SET state = 'removed', enforcement_seq = 3, updated_at = now()
				           WHERE id = {ctlA} AND enforcement_seq = 2`)
			}},
		{id: "DB99", name: "Retired control's worker cannot advance its sequence",
			want: msgTrigger("iga_gov_control_fence", "sequence cannot advance"),
			do:   x(`UPDATE iga_gov_control SET enforcement_seq = 4 WHERE id = {ctlA}`)},
		{id: "DB100", name: "Retired control cannot be reactivated",
			want: msgTrigger("iga_gov_control_fence", "cannot be reactivated"),
			do:   x(`UPDATE iga_gov_control SET state = 'active', baseline_captured_at = now() WHERE id = {ctlA}`)},
		{id: "DB101", name: "Replacement control for role A (owned by p2, sequence starts at 0)", want: accepted(),
			do:    x(control("ctlA2", "p2", "roleA", "iaA", "boundary_policy_arn", "{bY}")),
			after: func(s *step) { s.eq("0", `SELECT enforcement_seq FROM iga_gov_control WHERE id = {ctlA2}`) }},
		{id: "DB102", name: "Handoff with a sequence the new control does not hold",
			want: msgTrigger("iga_gov_service_posture_order", "must carry the new control"),
			do: x(`UPDATE iga_gov_service_posture SET control_id = {ctlA2}, enforcement_seq = 5
			       WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`)},
		{id: "DB103", name: "Replacement control's first deployment verifies; swap 0 -> 1 hands the posture over; outcome removed; finding resolved", want: accepted(),
			pre: x(`INSERT INTO iga_gov_target (id, workspace_id, version_id, policy_id, control_id, is_canary) VALUES ({tP2}, {ws1}, {p2v1}, {p2}, {ctlA2}, true)`,
				plan("plP2", "p2v1", "tP2", "ctlA2", "desired_boundary_arn", "{bY}", "desired_document_hash", "{docY}"),
				approval("apP2", "p2v1", "plP2"),
				deployment("dP2", "p2v1", "plP2", "ctlA2", "apP2", "state", "'verified'", "applied_at", "now()", "verified_at", "now()")),
			do: func(s *step) {
				s.rows(1, `UPDATE iga_gov_control SET state = 'active', baseline_captured_at = now(), enforcement_seq = 1
				           WHERE id = {ctlA2} AND enforcement_seq = 0`)
				s.exec(`UPDATE iga_gov_service_posture SET control_id = {ctlA2}, enforcement_seq = 1, exclusion = 'applied',
				          current_deployment_id = {dP2}, boundary_document_hash = {docY}, enforcement_observed_at = now()
				        WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`)
				s.exec(`UPDATE iga_gov_finding SET status = 'resolved', resolved_by_deployment_id = {dP2}, status_changed_at = now() WHERE id = {fA}`)
			},
			after: func(s *step) {
				s.eq("removed", postureOutcome)
				s.eq("true", `SELECT (control_id = {ctlA2})::text FROM iga_gov_service_posture WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`)
				s.eq("resolved", `SELECT status FROM iga_gov_finding WHERE id = {fA}`)
			}},
		{id: "DB104", name: "Retired control's late observation after the handoff",
			want: msgTrigger("iga_gov_service_posture_order", "only from a retired one"),
			do: x(`UPDATE iga_gov_service_posture SET control_id = {ctlA}, enforcement_seq = 3, exclusion = 'not_applied'
			       WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`)},
		{id: "DB105", name: "Replacement control's next observation (1 -> 2) updates the handed-over row", want: accepted(),
			do: func(s *step) {
				s.rows(1, `UPDATE iga_gov_control SET enforcement_seq = 2 WHERE id = {ctlA2} AND enforcement_seq = 1`)
				s.exec(`UPDATE iga_gov_service_posture SET restriction = 'observed', enforcement_seq = 2, enforcement_observed_at = now()
				        WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`)
			},
			after: func(s *step) {
				s.eq("removed", postureOutcome)
				s.eq("2", `SELECT enforcement_seq FROM iga_gov_service_posture WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`)
			}},

		/* --------------------------- the replaced policy ------------------------ */
		{id: "DB106", name: "Plan deleting a replaced policy it does not name",
			want: checkViolation("iga_gov_plan_disposition_chk"),
			do: x(plan("plA1", "p1v1", "tA1", "ctlA", "id", "gen_random_uuid()", "kind", "'undo'", "desired_attachment", "'absent'",
				"desired_boundary_arn", "NULL", "desired_document_hash", "NULL", "artifact_disposition", "'delete'", "superseded_at", "now()"))},
		{id: "DB107", name: "Plan deleting the policy it installs",
			want: checkViolation("iga_gov_plan_disposition_chk"),
			do: x(plan("plA1", "p1v1", "tA1", "ctlA", "id", "gen_random_uuid()", "kind", "'undo'",
				"replaced_boundary_arn", "{bX}", "artifact_disposition", "'delete'", "superseded_at", "now()"))},
		{id: "DB108", name: "Undo of a split copy: shared boundary restored, the copy named and deleted", want: accepted(),
			do: x(plan("plA1", "p1v1", "tB1", "ctlB", "id", "gen_random_uuid()", "kind", "'undo'", "delivery", "'iac_pr'",
				"desired_boundary_arn", "{bShared}", "desired_document_hash", "{docS}", "before_document_hash", "{docX}",
				"replaced_boundary_arn", "{bCopy}", "artifact_disposition", "'delete'", "superseded_at", "now()"))},

		/* ------------------------------- revalidation -------------------------- */
		{id: "DB109", name: "Revalidation claiming unchanged with a different material hash",
			want: checkViolation("iga_gov_rv_result_chk"),
			do:   x(revalidation("material_hash", "'mh-other'"))},
		{id: "DB110", name: "Revalidation against a hash the plan was not approved with",
			want: fkViolation("iga_gov_revalidation_workspace_id_plan_id_approved_materia_fkey"),
			do:   x(revalidation("approved_material_hash", "'mh-wrong'", "material_hash", "'mh-wrong'"))},
		{id: "DB111", name: "Unchanged rescan recorded as a revalidation; the approved plan is not rewritten", want: accepted(),
			do: x(revalidation("id", "{rvU}")),
			after: func(s *step) {
				s.eq("plh-plB1|mh-plB1|", `SELECT plan_hash || '|' || material_hash || '|' || coalesce(superseded_at::text, '') FROM iga_gov_plan WHERE id = {plB1}`)
			}},
		{id: "DB112", name: "Material change recorded with its changes", want: accepted(),
			do: x(revalidation("id", "{rvM}", "evidence_rev", "3", "material_hash", "'mh-plB1-rescan'", "result", "'material_change'",
				"changes", `'[{"input":"impact","detail":"new consumer"}]'`))},
		{id: "DB113", name: "Revalidation rewritten",
			want: triggerException("authsec_row_immutable"),
			do:   x(`UPDATE iga_gov_revalidation SET evidence_rev = 3 WHERE id = {rvU}`)},
		{id: "DB114", name: "Deployment proceeding on a material-change revalidation",
			want: fkViolation("iga_gov_deployment_workspace_id_revalidation_id_plan_id_re_fkey"),
			do: x(deployment("dB2", "p1v1", "plB1", "ctlB", "apA1", "state", "'blocked'",
				"revalidation_id", "{rvM}", "revalidation_result", "'unchanged'"))},
		{id: "DB115", name: "Deployment proceeding on the unchanged revalidation", want: accepted(),
			pre: x(`UPDATE iga_gov_deployment SET state = 'verified', applied_at = now(), verified_at = now() WHERE id = {dB1}`),
			do:  x(deployment("dB2", "p1v1", "plB1", "ctlB", "apA1", "revalidation_id", "{rvU}", "revalidation_result", "'unchanged'"))},

		/* -------------------------------- acceptances -------------------------- */
		{id: "DB116", name: "Evidence gap accepted without a reason",
			want: checkViolation("iga_gov_acceptance_reason_check"),
			do:   x(acceptance("reason", "''"))},
		{id: "DB117", name: "Evidence gap accepted against the approval, plan and bundle", want: accepted(),
			do: x(acceptance("id", "{acc1}"))},
		{id: "DB118", name: "Acceptance from another version's approval",
			want: fkViolation("iga_gov_acceptance_workspace_id_approval_id_version_id_fkey"),
			do:   x(acceptance("approval_id", "{apA2}", "item_key", "'evidence_gap:freshness'"))},
		{id: "DB119", name: "Acceptance rewritten",
			want: triggerException("authsec_row_immutable"),
			do:   x(`UPDATE iga_gov_acceptance SET reason = 'changed my mind' WHERE id = {acc1}`)},
		{id: "DB120", name: "Unavailable gate accepted without an evidence window",
			want: checkViolation("iga_gov_acc_subject_chk"),
			do: x(acceptance("kind", "'gate_not_available'", "item_key", "'gate:cloudtrail_denials'", "approval_id", "NULL", "plan_id", "NULL",
				"evidence_bundle_id", "NULL", "rollout_id", "{ro1}", "stage", "'canary'"))},
		{id: "DB121", name: "Unavailable gate accepted for its stage and window", want: accepted(),
			do: x(acceptance("kind", "'gate_not_available'", "item_key", "'gate:cloudtrail_denials'", "approval_id", "NULL", "plan_id", "NULL",
				"evidence_bundle_id", "NULL", "rollout_id", "{ro1}", "stage", "'canary'",
				"window_start", "now() - interval '48 hours'", "window_end", "now()"))},

		/* ---------------------- write-ahead attempts, recovery ------------------ */
		{id: "DB122", name: "Attempt recorded as dispatched without a prepared record",
			want: msgTrigger("iga_gov_attempt_transition", "recorded as prepared before it is dispatched"),
			do:   x(attempt("status", "'dispatched'", "signed_at", "now()", "dispatched_at", "now()"))},
		{id: "DB123", name: "Prepared attempt with its exact request, committed before dispatch", want: accepted(),
			pre: x(`UPDATE iga_gov_deployment SET state = 'applying' WHERE id = {dB2}`),
			do:  x(attempt("id", "{at1}"))},
		{id: "DB124", name: "Second open attempt on the same deployment",
			want: uniqueViolation("uq_iga_gov_attempt_open"),
			do:   x(attempt("op_seq", "1"))},
		{id: "DB125", name: "Prepared request changed before dispatch",
			want: msgTrigger("iga_gov_attempt_transition", "prepared request of an attempt is immutable"),
			do:   x(`UPDATE iga_gov_attempt SET request_hash = 'sha256:other' WHERE id = {at1}`)},
		{id: "DB126", name: "Dispatched without a signing time",
			want: checkViolation("iga_gov_at_status_chk"),
			do:   x(`UPDATE iga_gov_attempt SET status = 'dispatched', dispatched_at = now() WHERE id = {at1}`)},
		{id: "DB127", name: "Dispatched with its signing time, committed immediately before the call", want: accepted(),
			do: x(`UPDATE iga_gov_attempt SET status = 'dispatched', signed_at = now(), dispatched_at = now() WHERE id = {at1}`)},
		{id: "DB128", name: "No response: the dispatched attempt becomes unknown", want: accepted(),
			do: x(`UPDATE iga_gov_attempt SET status = 'unknown' WHERE id = {at1}`)},
		{id: "DB129", name: "Unknown attempt reported as completed",
			want: msgTrigger("iga_gov_attempt_transition", "is not allowed"),
			do:   x(`UPDATE iga_gov_attempt SET status = 'completed', completed_at = now(), outcome = 'ok' WHERE id = {at1}`)},
		{id: "DB130", name: "Outcome unknown without a settle time",
			want: checkViolation("iga_gov_pd_unknown_chk"),
			do:   x(`UPDATE iga_gov_deployment SET state = 'outcome_unknown', outcome_unknown_op = 'PutRolePermissionsBoundary' WHERE id = {dB2}`)},
		{id: "DB131", name: "Undo started on the role while a mutation's outcome is unknown",
			want: uniqueViolation("uq_iga_gov_deployment_inflight"),
			pre: x(`UPDATE iga_gov_deployment SET state = 'outcome_unknown', outcome_unknown_op = 'PutRolePermissionsBoundary',
			          settle_after = now() + interval '15 minutes' WHERE id = {dB2}`),
			do: x(deployment("dS0", "p1v1", "plB1u", "ctlB", "apA1", "kind", "'undo'"))},
		{id: "DB132", name: "Unresolved outcome still holds the role: another deployment is refused",
			want: uniqueViolation("uq_iga_gov_deployment_inflight"),
			pre:  x(`UPDATE iga_gov_deployment SET state = 'outcome_unresolved' WHERE id = {dB2}`),
			do:   x(deployment("dS0", "p1v1", "plB1", "ctlB", "apA1"))},
		{id: "DB133", name: "Unresolved deployment released without a successor",
			want: checkViolation("iga_gov_pd_recovered_chk"),
			do:   x(`UPDATE iga_gov_deployment SET state = 'recovered' WHERE id = {dB2}`)},
		{id: "DB134", name: "Release naming a successor that does not name it back",
			want: fkViolation("iga_gov_pd_recovered_by_fk"),
			do: x(deployment("dS0", "p1v1", "plB1", "ctlB", "apA1", "state", "'blocked'"),
				`UPDATE iga_gov_deployment SET state = 'recovered', recovered_by_deployment_id = {dS0} WHERE id = {dB2}`,
				`SET CONSTRAINTS ALL IMMEDIATE`)},
		{id: "DB135", name: "Atomic handoff: the unresolved deployment and its operator-approved successor in one transaction", want: accepted(),
			do: x(`UPDATE iga_gov_deployment SET state = 'recovered', recovered_by_deployment_id = {dS1} WHERE id = {dB2}`,
				deployment("dS1", "p1v1", "plB1u", "ctlB", "apA1", "kind", "'undo'", "recovers_deployment_id", "{dB2}"),
				`SET CONSTRAINTS ALL IMMEDIATE`),
			after: func(s *step) {
				s.eq("1", `SELECT count(*) FROM iga_gov_deployment WHERE control_id = {ctlB}
				             AND state IN ('queued','applying','outcome_unknown','outcome_unresolved','awaiting_merge','awaiting_apply')`)
			}},
		{id: "DB136", name: "Unknown attempt resolved from readback and CloudTrail", want: accepted(),
			do: x(`UPDATE iga_gov_attempt SET resolved_as = 'applied', resolved_at = now() WHERE id = {at1}`)},
		{id: "DB137", name: "Resolved attempt re-resolved",
			want: msgTrigger("iga_gov_attempt_transition", "stays resolved"),
			do:   x(`UPDATE iga_gov_attempt SET resolved_as = 'not_applied' WHERE id = {at1}`)},

		/* ---------------------------------- NULL cases -------------------------- */
		{id: "DB138", name: "Revalidation 'unchanged' with no material hash",
			want: checkViolation("iga_gov_rv_result_chk"),
			do:   x(revalidation("material_hash", "NULL"))},
		{id: "DB139", name: "Gate acceptance with no stage and no window end",
			want: checkViolation("iga_gov_acc_subject_chk"),
			do: x(acceptance("kind", "'gate_not_available'", "item_key", "'gate:health_reports'", "approval_id", "NULL", "plan_id", "NULL",
				"evidence_bundle_id", "NULL", "rollout_id", "{ro1}", "stage", "NULL", "window_start", "now()", "window_end", "NULL"))},
		{id: "DB140", name: "Migration marked moved with no count of what remains on the old role",
			want: checkViolation("iga_gov_wm_moved_chk"),
			do:   x(migrationRow("remaining_old_refs", "NULL"))},
		{id: "DB141", name: "Migration marked moved while tasks still run on the old revision",
			want: checkViolation("iga_gov_wm_moved_chk"),
			do:   x(migrationRow("remaining_old_refs", "2"))},
		{id: "DB142", name: "Migration marked moved on incomplete evidence",
			want: checkViolation("iga_gov_wm_moved_chk"),
			do:   x(migrationRow("evidence_complete", "false"))},
		{id: "DB143", name: "ECS service moved: complete evidence, no task on the old revision, revisions linked not merged", want: accepted(),
			do: x(migrationRow()),
			after: func(s *step) {
				s.eq("true", `SELECT (from_workload_keys <> to_workload_keys AND NOT (from_workload_keys && to_workload_keys))::text
				                FROM iga_gov_workload_migration WHERE plan_id = {plSplit}`)
			}},
	}
}

const postureOutcome = `SELECT outcome FROM iga_gov_service_posture WHERE workspace_id = {ws1} AND role_id = {roleA} AND service = 'sqs'`

// TestPhase3SchemaProbes runs DB1-DB143 (§6.3) in order.
func TestPhase3SchemaProbes(t *testing.T) {
	db, _ := testDB(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	w := probeWorld(t, tx)

	ps := probes()
	if len(ps) != 143 {
		t.Fatalf("the §6.3 table has 143 probes; this suite has %d", len(ps))
	}
	passed := 0
	for i, p := range ps {
		if p.id != fmt.Sprintf("DB%d", i+1) {
			t.Fatalf("probe %d is %s; the suite must follow the §6.3 table order", i+1, p.id)
		}
		p := p
		ok := t.Run(p.id, func(t *testing.T) {
			t.Logf("%s %s -> %s", p.id, p.name, p.want.label)
			if p.pre != nil {
				s := &step{t: t, x: tx, w: w}
				p.pre(s)
				if s.err != nil || len(s.bad) > 0 {
					t.Fatalf("pre-state for %s failed: %v %v", p.id, s.err, s.bad)
				}
			}
			mustExec(t, tx, "SAVEPOINT probe")
			s := &step{t: t, x: tx, w: w}
			p.do(s)
			if s.err == nil {
				s.exec(`SET CONSTRAINTS ALL IMMEDIATE`)
			}
			matched, why := p.want.match(s.err)
			if matched && p.want.accepted && p.after != nil {
				p.after(s)
			}
			if p.want.accepted && matched {
				mustExec(t, tx, "SET CONSTRAINTS "+deferredPhase3+" DEFERRED")
				mustExec(t, tx, "RELEASE SAVEPOINT probe")
			} else {
				mustExec(t, tx, "ROLLBACK TO SAVEPOINT probe")
				mustExec(t, tx, "RELEASE SAVEPOINT probe")
				mustExec(t, tx, "SET CONSTRAINTS "+deferredPhase3+" DEFERRED")
			}
			if !matched {
				t.Errorf("%s %s: want %s; %s", p.id, p.name, p.want.label, why)
			}
			for _, b := range s.bad {
				t.Errorf("%s: %s", p.id, b)
			}
		})
		if ok {
			passed++
		}
	}
	t.Logf("§6.3 probes: %d of %d matched", passed, len(ps))
	if passed != len(ps) {
		t.Errorf("§6.3 probes: %d of %d matched", passed, len(ps))
	}
}

func mustExec(t *testing.T, x execer, q string) {
	t.Helper()
	if _, err := x.Exec(q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
