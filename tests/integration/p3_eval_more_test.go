package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// p3eSQLState is a driver error carrying a SQLSTATE, as pgconn.PgError does.
type p3eSQLState struct{ code string }

func (e p3eSQLState) Error() string    { return "injected SQLSTATE " + e.code }
func (e p3eSQLState) SQLState() string { return e.code }

// §8.2: a deadlock (40P01) or serialization failure (40001) in the
// evaluation transaction is retried -- the whole transaction, nothing of a
// failed attempt survives -- at most 3 attempts; a third failure records
// failed and the job still completes.
//
// Safeguard (mutation-checked): the bound of 3 attempts.
func TestP3T306DeadlockRetriesAreBounded(t *testing.T) {
	l := newP3eLab(t, "p3-t306-retry")
	a := l.account(accountA)
	arn := p3eOldRole(a, "RetryRole", "AROARETRY00001", 200*24*time.Hour, "RetryWork", p3eSQSS3)
	a.lambda("us-east-1", "retry", arn)
	l.activity(a).set(arn, map[string]*time.Time{"s3": nil, "sqs": nil})

	failing := func(n int32, code string) (*services.GovEvaluator, *int32) {
		var calls int32
		return services.NewGovEvaluator(l.db).WithHook(func(stage string, _ int64, _ *gorm.DB) error {
			if stage != "results_half" {
				return nil
			}
			if atomic.AddInt32(&calls, 1) <= n {
				return p3eSQLState{code}
			}
			return nil
		}), &calls
	}
	ev, calls := failing(2, "40P01")
	_, rev := l.cycle(a, ev)
	if e := l.evaluation(rev); e.Status != models.GovEvalComplete || e.Attempts != 1 || *calls != 3 {
		t.Fatalf("two deadlocks then success: %+v after %d transaction attempts, want complete on the third", e, *calls)
	}
	results := l.count(`SELECT count(*) FROM iga_gov_finding_result WHERE workspace_id = ? AND rev = ?`, l.ws, rev)
	findings := l.count(`SELECT count(*) FROM iga_gov_finding WHERE workspace_id = ?`, l.ws)
	if results == 0 || findings == 0 || results > findings {
		t.Fatalf("after retries: %d results for %d findings (a failed attempt left rows?)", results, findings)
	}

	ev, calls = failing(3, "40001")
	_, rev = l.cycle(a, ev)
	e := l.evaluation(rev)
	if e.Status != models.GovEvalFailed || *calls != 3 || !strings.Contains(e.Error, "after 3 attempts") {
		t.Fatalf("three serialization failures: %+v after %d attempts, want failed after 3", e, *calls)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_finding_result WHERE workspace_id = ? AND rev = ?`, l.ws, rev); n != 0 {
		t.Fatalf("a failed evaluation left %d results", n)
	}
	// Any other error is not retried.
	ev, calls = failing(1, "23505")
	_, rev = l.cycle(a, ev)
	if e := l.evaluation(rev); e.Status != models.GovEvalFailed || *calls != 1 {
		t.Fatalf("a unique violation: %+v after %d attempts, want failed without a retry", e, *calls)
	}
}

// §8.7: the evaluation writes ONLY the route facts of an existing posture
// row -- from the role connector's run in the manifest, with its scan --
// under the shared lock order, and never an enforcement fact. An
// enforcement observer holding the control row (its compare-and-swap) makes
// the evaluation wait, not fail; both commit.
func TestP3T306PostureRouteFactsInTheSharedLockOrder(t *testing.T) {
	l := newP3eLab(t, "p3-t306-posture")
	a := l.account(accountA)
	arn := p3eOldRole(a, "PostureRole", "AROAPOSTURE001", 200*24*time.Hour, "PostureWork", p3eSQSS3)
	a.lambda("us-east-1", "posture", arn)
	l.activity(a).set(arn, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	_, rev1 := l.cycle(a, nil)
	ident := bdbIdentity(t, l.p2Lab, "PostureRole")

	u, policy, control := l.user(), uuid.New(), uuid.New()
	for _, st := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by) VALUES (?, ?, 'posture', 'cloud_access', 'aws', ?)`,
			[]any{policy, l.ws, u}},
		{`INSERT INTO iga_gov_control (id, workspace_id, connector_id, account_id, role_id, role_arn, identity_account_id, policy_id,
		                               boundary_policy_arn, state)
		  VALUES (?, ?, ?, ?, 'AROAPOSTURE001', ?, ?, ?, 'arn:aws:iam::429418377036:policy/authsec/AuthSecBoundary-AROAPOSTURE001', 'planned')`,
			[]any{control, l.ws, a.conn, accountA, arn, ident, policy}},
		{`INSERT INTO iga_gov_service_posture (workspace_id, account_id, role_id, service, control_id, exclusion, enforcement_seq,
		                                       enforcement_observed_at, route_state, routes, evidence_rev)
		  VALUES (?, ?, 'AROAPOSTURE001', 'sqs', ?, 'pending', 0, now(), 'not_analysed', '[{"service":"sqs","effect":"not_analysed"}]', ?)`,
			[]any{l.ws, accountA, control, rev1}},
	} {
		if err := l.db.Exec(st.sql, st.args...).Error; err != nil {
			t.Fatalf("posture fixture: %v", err)
		}
	}

	run := l.scanOnly(a)
	p3eCompleteCoverage(t, l, a, run.ID)

	// An enforcement observer wins its compare-and-swap on the control row
	// (§8.7 order 1) and holds it while the projection job evaluates; the
	// evaluation waits for it. (The swap is a no-key update: only the
	// evaluation's own FOR UPDATE on the controls conflicts with it -- the
	// posture rows' foreign key to the control alone would not.)
	observer := l.db.Begin()
	if res := observer.Exec(`UPDATE iga_gov_control SET enforcement_seq = enforcement_seq + 1
	                          WHERE id = ? AND enforcement_seq = 0`, control); res.Error != nil || res.RowsAffected != 1 {
		t.Fatalf("observer swap: %v (%d rows)", res.Error, res.RowsAffected)
	}
	done := make(chan error, 1)
	go func() {
		_, err := l.projector("p3e-posture-projector", nil).RunOnce(context.Background())
		done <- err
	}()
	// The evaluation must be seen BLOCKED on its FOR UPDATE of the controls
	// (§8.7 order 1) -- not merely slow -- before the observer commits.
	waited := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline) && !waited; {
		select {
		case err := <-done:
			observer.Rollback()
			t.Fatalf("the evaluation finished without waiting for the control row: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		var n int64
		l.db.Raw(`SELECT count(*) FROM pg_stat_activity
		           WHERE wait_event_type = 'Lock' AND query LIKE '%FROM iga_gov_control%FOR UPDATE%'`).Scan(&n)
		waited = n > 0
	}
	if !waited {
		observer.Rollback()
		<-done
		t.Fatal("the evaluation never waited on the control row held by the observer")
	}
	if err := observer.Commit().Error; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("projection: %v", err)
	}
	rev := l.latestRev()
	if e := l.evaluation(rev); e.Status != models.GovEvalComplete {
		t.Fatalf("evaluation after waiting: %+v", e)
	}
	var p struct {
		RouteState        string
		Routes            string
		EvidenceRev       int64
		EvidenceScanRunID *uuid.UUID
		Exclusion         string
		EnforcementSeq    int64
		Outcome           string
	}
	if err := l.db.Raw(`SELECT route_state, routes::text AS routes, evidence_rev, evidence_scan_run_id, exclusion, enforcement_seq, outcome
	                      FROM iga_gov_service_posture WHERE workspace_id = ? AND role_id = 'AROAPOSTURE001' AND service = 'sqs'`, l.ws).
		Scan(&p).Error; err != nil {
		t.Fatal(err)
	}
	if p.RouteState != "none_observed" || p.Routes != "[]" || p.EvidenceRev != rev || p.EvidenceScanRunID == nil || *p.EvidenceScanRunID != run.ID {
		t.Fatalf("route facts %+v, want none_observed from run %s at rev %d", p, run.ID, rev)
	}
	if p.Exclusion != "pending" || p.EnforcementSeq != 0 || p.Outcome != "pending" {
		t.Fatalf("enforcement facts changed: %+v", p)
	}
}

// §2.5 retention: evidence and results older than evidence_retention_revs
// complete revisions are pruned -- except a revision a policy version's
// evidence_rev names -- and a read at a pruned revision is 410
// revision_not_retained; the evaluation row stays.
func TestP3T306PruningAndRevisionNotRetained(t *testing.T) {
	l := newP3eLab(t, "p3-t306-prune")
	a := l.account(accountA)
	arn := p3eOldRole(a, "PruneRole", "AROAPRUNE00001", 200*24*time.Hour, "PruneWork", p3eSQSS3)
	a.lambda("us-east-1", "prune", arn)
	l.activity(a).set(arn, map[string]*time.Time{"s3": nil, "sqs": nil})
	if err := l.db.Exec(`INSERT INTO iga_gov_settings (workspace_id, evidence_retention_revs) VALUES (?, 5)`, l.ws).Error; err != nil {
		t.Fatal(err)
	}
	_, rev1 := l.cycle(a, nil)
	u := l.user()
	policy := uuid.New()
	if err := l.db.Exec(`INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by) VALUES (?, ?, 'pinned', 'cloud_access', 'aws', ?)`,
		policy, l.ws, u).Error; err != nil {
		t.Fatal(err)
	}
	if err := l.db.Exec(`INSERT INTO iga_gov_policy_version (workspace_id, policy_id, version_no, intent, intent_hash, catalog_version, evidence_rev, created_by)
	                     VALUES (?, ?, 1, '{}', 'sha256:test', 1, ?, ?)`, l.ws, policy, rev1, u).Error; err != nil {
		t.Fatal(err)
	}
	var last int64
	for i := 0; i < 6; i++ {
		_, last = l.cycle(a, nil)
	}
	// 7 complete revisions, retention 5: revs last-4..last are kept, rev 2 is
	// pruned, and rev 1 is kept because a version names it.
	rev2 := rev1 + 1
	if last-4 != rev2+1 {
		t.Fatalf("revisions %d..%d, want 7", rev1, last)
	}
	api := l.api()
	for _, tc := range []struct {
		rev  int64
		code int
	}{{rev1, http.StatusOK}, {rev2, http.StatusGone}, {last - 4, http.StatusOK}, {last, http.StatusOK}} {
		code, body := api.get(l.ws, fmt.Sprintf("/findings?rev=%d", tc.rev))
		if code != tc.code || (code == http.StatusGone && p3eErr(body) != "revision_not_retained") {
			t.Fatalf("?rev=%d: %d %v, want %d", tc.rev, code, body, tc.code)
		}
		n := l.count(`SELECT count(*) FROM iga_gov_finding_result WHERE workspace_id = ? AND rev = ?`, l.ws, tc.rev)
		if (tc.code == http.StatusOK) != (n > 0) {
			t.Fatalf("rev %d: %d results retained, want retained = %v", tc.rev, n, tc.code == http.StatusOK)
		}
		if e := l.evaluation(tc.rev); e.Status != models.GovEvalComplete {
			t.Fatalf("rev %d evaluation row %+v, want it kept", tc.rev, e)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_activity_evidence WHERE workspace_id = ? AND rev = ?`, l.ws, rev2); n != 0 {
		t.Fatalf("pruned rev %d kept %d evidence rows", rev2, n)
	}
}
