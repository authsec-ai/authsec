package integration

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// T3.03 (SPEC-iga-phase3-policy.md §2.6): the 500-identity Access Advisor
// sample puts first every identity a workload runs as (executes_as), every
// role an ECS task definition names as its execution role
// (task_execution_role), and every role under a live AuthSec control; then
// the rest in byte order of the ARN (D-86). The coverage names the sample:
// the prioritised ARNs and the last ARN of the rest, and ActivitySampled reads
// them back.
//
// The fixture puts every prioritised role PAST the byte-order cap: 600 roles
// "role/A-bulk-NNN" (uppercase, so they sort before every real role) fill the
// first 500 places, so without the priority none of them would be read.
//
// Safeguards (mutation-checked): the priority in ActivitySample's ORDER BY,
// the control clause (state <> 'removed'), and the Prioritized stamp.
func TestP3T303ActivitySamplePrioritisesBoundAndControlledRoles(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "p3-t303-activity-sample")
	defer cleanWorkloadTables(t, db, ws)

	svc, snap := s3bActivityFixture(t, db, ws, 0) // ops-readonly, summarizer-agent, ci-deployer
	const acct = "arn:aws:iam::429418377036:"
	ecsExecARN, controlledARN, removedARN := acct+"role/zz-ecs-exec", acct+"role/zz-controlled", acct+"role/zz-removed-control"
	if err := db.Exec(`INSERT INTO cloud_identity (workspace_id, connector_id, kind, native_id, name, attrs, last_seen_generation)
	                   SELECT ?, ?, 'iam_role', ? || 'role/A-bulk-' || lpad(g::text, 3, '0'), 'A-bulk-' || g,
	                          jsonb_build_object('unique_id', 'AROABULK' || g), ?
	                     FROM generate_series(1, 600) g`, ws, snap.ConnectorID, acct, snap.Generation).Error; err != nil {
		t.Fatalf("bulk roles: %v", err)
	}
	for arn, roleID := range map[string]string{ecsExecARN: "AROAECSEXEC", controlledARN: "AROACONTROLLED", removedARN: "AROAREMOVED"} {
		if err := db.Exec(`INSERT INTO cloud_identity (workspace_id, connector_id, kind, native_id, name, attrs, last_seen_generation)
		                   VALUES (?, ?, 'iam_role', ?, ?, jsonb_build_object('unique_id', ?::text), ?)`,
			ws, snap.ConnectorID, arn, arn[strings.LastIndex(arn, "/")+1:], roleID, snap.Generation).Error; err != nil {
			t.Fatalf("role %s: %v", arn, err)
		}
	}

	// executes_as: a Lambda runs as summarizer-agent.
	agentID := s3bIdentityID(t, db, ws, agentRoleARN)
	if err := db.Exec(`INSERT INTO cloud_workload (workspace_id, connector_id, identity_id, runtime_kind, native_id, name, region, last_seen_generation)
	                   VALUES (?, ?, ?, 'lambda_function', 'arn:aws:lambda:us-east-1:429418377036:function:summarize', 'summarize', 'us-east-1', ?)`,
		ws, snap.ConnectorID, agentID, snap.Generation).Error; err != nil {
		t.Fatalf("lambda: %v", err)
	}
	// task_execution_role: an ECS task definition names zz-ecs-exec as its
	// execution role; its task role is not in inventory.
	if err := db.Exec(`INSERT INTO cloud_workload (workspace_id, connector_id, runtime_kind, native_id, name, region, attrs, last_seen_generation)
	                   VALUES (?, ?, 'ecs_task_definition', 'arn:aws:ecs:us-east-1:429418377036:task-definition/refunds:7', 'refunds', 'us-east-1',
	                           jsonb_build_object('execution_role_arn', ?::text), ?)`,
		ws, snap.ConnectorID, ecsExecARN, snap.Generation).Error; err != nil {
		t.Fatalf("ecs: %v", err)
	}
	// A live control on zz-controlled; a REMOVED one on zz-removed-control.
	p3Control(t, db, ws, snap.ConnectorID, controlledARN, "AROACONTROLLED", "active")
	p3Control(t, db, ws, snap.ConnectorID, removedARN, "AROAREMOVED", "removed")

	fake := &s3bActivity{}
	out := s3bWorkloadScan(t, db, ws, svc, snap, fake, nil)

	prioritized := []string{agentRoleARN, ecsExecARN, controlledARN}
	sort.Strings(prioritized)
	if len(fake.submitted) != 500 {
		t.Fatalf("sampled %d identities, want the cap, 500", len(fake.submitted))
	}
	first := append([]string(nil), fake.submitted[:3]...)
	sort.Strings(first)
	if strings.Join(first, "|") != strings.Join(prioritized, "|") {
		t.Fatalf("the first three reports requested were %v, want the workload-bound and controlled roles %v", first, prioritized)
	}
	rest := fake.submitted[3:]
	for i, arn := range rest {
		if want := acct + "role/A-bulk-" + p3Pad(i+1); arn != want {
			t.Fatalf("after the prioritised roles, report %d was %s, want %s (the rest in byte order of the ARN)", i+4, arn, want)
		}
	}

	cov := out.Surfaces[models.SurfaceActivity]
	if cov.State != models.CloudCoveragePartial {
		t.Fatalf("activity = %+v, want partial (606 identities, cap 500)", cov)
	}
	if want := acct + "role/A-bulk-497"; cov.CappedAfter != want {
		t.Fatalf("capped_after = %q, want %q (the last ARN of the rest)", cov.CappedAfter, want)
	}
	if strings.Join(cov.Prioritized, "|") != strings.Join(prioritized, "|") {
		t.Fatalf("prioritized = %v, want %v", cov.Prioritized, prioritized)
	}
	// What the scan records is what a reader can tell: sampled or not.
	for arn, want := range map[string]bool{
		agentRoleARN: true, ecsExecARN: true, controlledARN: true,
		acct + "role/A-bulk-001": true, acct + "role/A-bulk-497": true,
		acct + "role/A-bulk-498": false, acct + "role/A-bulk-600": false,
		removedARN: false, plainRoleARN: false, ciUserARN: false,
	} {
		if got := cov.ActivitySampled(arn); got != want {
			t.Errorf("ActivitySampled(%s) = %v, want %v", arn, got, want)
		}
	}
	// Stored as such in the run's coverage (cloud_scan_run.coverage, jsonb),
	// for the evaluator's activity_not_read (T3.06).
	raw, err := json.Marshal(cov)
	if err != nil {
		t.Fatal(err)
	}
	var decoded models.SurfaceCoverage
	if err := json.Unmarshal(raw, &decoded); err != nil || !strings.Contains(string(raw), `"prioritized":[`) ||
		strings.Join(decoded.Prioritized, "|") != strings.Join(prioritized, "|") {
		t.Fatalf("coverage JSON %s does not carry the prioritised ARNs (%v)", raw, err)
	}

	// Remove the control and the workloads: the sample is the D-86 one again.
	if err := db.Exec(`UPDATE iga_gov_control SET state = 'removed' WHERE workspace_id = ? AND state <> 'removed'`, ws).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`DELETE FROM cloud_workload WHERE workspace_id = ?`, ws).Error; err != nil {
		t.Fatal(err)
	}
	plain := &s3bActivity{}
	again := s3bWorkloadScan(t, db, ws, svc, snap, plain, nil)
	for i, arn := range plain.submitted {
		if want := acct + "role/A-bulk-" + p3Pad(i+1); arn != want {
			t.Fatalf("with no workload and no control, report %d was %s, want %s (byte order)", i+1, arn, want)
		}
	}
	if c := again.Surfaces[models.SurfaceActivity]; c.CappedAfter != acct+"role/A-bulk-500" || len(c.Prioritized) != 0 {
		t.Fatalf("with nothing prioritised: capped_after %q prioritized %v, want A-bulk-500 and none", c.CappedAfter, c.Prioritized)
	}
}

// When the prioritised identities alone fill the cap, the rest is not read at
// all: capped_after is empty, and only the prioritised ARNs are sampled.
func TestP3T303PrioritisedIdentitiesCanFillTheCap(t *testing.T) {
	cov := models.SurfaceCoverage{State: models.CloudCoveragePartial, Prioritized: []string{"arn:b", "arn:d"}}
	for arn, want := range map[string]bool{"arn:a": false, "arn:b": true, "arn:c": false, "arn:d": true, "arn:e": false} {
		if got := cov.ActivitySampled(arn); got != want {
			t.Errorf("ActivitySampled(%s) = %v, want %v", arn, got, want)
		}
	}
	if !(models.SurfaceCoverage{State: models.CloudCoverageReached}).ActivitySampled("arn:anything") {
		t.Error("an uncapped read did not sample every identity")
	}
	legacy := models.SurfaceCoverage{State: models.CloudCoveragePartial, CappedAfter: "arn:m"}
	if !legacy.ActivitySampled("arn:m") || legacy.ActivitySampled("arn:n") {
		t.Error("a D-86 coverage (capped_after only) is not read as before")
	}
}

func p3Pad(n int) string { return fmt.Sprintf("%03d", n) }

func s3bIdentityID(t *testing.T, db *gorm.DB, ws uuid.UUID, arn string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.Raw(`SELECT id FROM cloud_identity WHERE workspace_id = ? AND native_id = ?`, ws, arn).Row().Scan(&id); err != nil {
		t.Fatalf("identity %s: %v", arn, err)
	}
	return id
}

// p3Control inserts an iga_gov_control (049) for a role, with the policy,
// user and graph identity it references, and removes them at cleanup.
func p3Control(t *testing.T, db *gorm.DB, ws, connectorID uuid.UUID, roleARN, roleID, state string) {
	t.Helper()
	user, account, policy := uuid.New(), uuid.New(), uuid.New()
	steps := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, email, workspace_id) VALUES (?, ?, ?)`, []any{user, user.String() + "@p3.test", ws}},
		{`INSERT INTO iga_identity_accounts (id, workspace_id, display_name, account_kind, provider, source_key)
		  VALUES (?, ?, ?, 'iam_role', 'aws', ?)`, []any{account, ws, roleARN, "aws\x1frole\x1f" + roleARN + "\x1f" + account.String()}},
		{`INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by)
		  VALUES (?, ?, ?, 'cloud_access', 'aws', ?)`, []any{policy, ws, "p3-t303 " + roleID, user}},
		{`INSERT INTO iga_gov_control (workspace_id, connector_id, account_id, role_id, role_arn, identity_account_id,
		                               policy_id, boundary_policy_arn, baseline_captured_at, state)
		  VALUES (?, ?, '429418377036', ?, ?, ?, ?, 'arn:aws:iam::429418377036:policy/authsec/boundary', now(), ?)`,
			[]any{ws, connectorID, roleID, roleARN, account, policy, state}},
	}
	for _, st := range steps {
		if err := db.Exec(st.sql, st.args...).Error; err != nil {
			t.Fatalf("control for %s: %v", roleARN, err)
		}
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM iga_gov_control WHERE workspace_id = ? AND policy_id = ?`, ws, policy)
		db.Exec(`DELETE FROM iga_gov_policy WHERE id = ?`, policy)
		db.Exec(`DELETE FROM iga_identity_accounts WHERE id = ?`, account)
		db.Exec(`DELETE FROM users WHERE id = ?`, user)
	})
}
