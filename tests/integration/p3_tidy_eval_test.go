package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// fix/p3-tidy item 3a (§2.5, §7 "results already pruned: 410
// revision_not_retained"): pruning is RECORDED (057) by the real evaluator's
// prune, so a pruned revision stays 410 after evidence_retention_revs is
// raised -- it used to come back as an empty 200 because "retained" was
// inferred from the current setting. A revision that was never pruned
// keeps answering 200 with its results.
func TestP3TidyPrunedRevisionStaysGoneAfterRetentionIsRaised(t *testing.T) {
	l := newP3eLab(t, "p3-tidy-prune")
	a := l.account(accountA)
	arn := p3eOldRole(a, "TidyPruneRole", "AROATIDYPRUNE01", 200*24*time.Hour, "TidyPruneWork", p3eSQSS3)
	a.lambda("us-east-1", "tidy-prune", arn)
	l.activity(a).set(arn, map[string]*time.Time{"s3": nil, "sqs": nil})
	if err := l.db.Exec(`INSERT INTO iga_gov_settings (workspace_id, evidence_retention_revs) VALUES (?, 5)`, l.ws).Error; err != nil {
		t.Fatal(err)
	}
	_, first := l.cycle(a, nil)
	var last int64
	for i := 0; i < 6; i++ {
		_, last = l.cycle(a, nil)
	}
	api := l.api()
	get := func(rev int64) (int, map[string]any) { return api.get(l.ws, fmt.Sprintf("/findings?rev=%d", rev)) }
	if code, body := get(first); code != http.StatusGone || p3eErr(body) != "revision_not_retained" {
		t.Fatalf("?rev=%d with retention 5: %d %v, want 410", first, code, body)
	}

	// Raise retention: the pruned rows do not come back, so neither may the
	// revision.
	if err := l.db.Exec(`UPDATE iga_gov_settings SET evidence_retention_revs = 30 WHERE workspace_id = ?`, l.ws).Error; err != nil {
		t.Fatal(err)
	}
	for _, rev := range []int64{first, first + 1} {
		if code, body := get(rev); code != http.StatusGone || p3eErr(body) != "revision_not_retained" {
			t.Fatalf("?rev=%d after raising retention to 30: %d %v, want 410 (it was pruned)", rev, code, body)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_evaluation_pruned WHERE workspace_id = ? AND rev IN (?, ?)`, l.ws, first, first+1); n != 2 {
		t.Fatalf("%d pruned markers for revs %d..%d, want 2", n, first, first+1)
	}
	code, body := get(last - 4)
	if code != http.StatusOK || len(p3eList(body)) == 0 {
		t.Fatalf("?rev=%d (never pruned): %d %v, want 200 with its findings", last-4, code, body)
	}
	// A later evaluation under the raised setting prunes nothing more.
	_, newest := l.cycle(a, nil)
	if n := l.count(`SELECT count(*) FROM iga_gov_evaluation_pruned WHERE workspace_id = ?`, l.ws); n != 2 {
		t.Fatalf("%d pruned markers after rev %d at retention 30, want still 2", n, newest)
	}
}

// fix/p3-tidy item 3b (§8.2 "if a newer revision's evaluation is complete:
// set N superseded"): a newer PUBLICATION alone does not supersede N. Rev
// N fails, rev N+1 fails too; the replay of N is then evaluated (complete),
// not skipped. Once N+2 completes, the replay of N+1 is superseded.
func TestP3TidySupersededOnlyByANewerCompleteEvaluation(t *testing.T) {
	l := newP3eLab(t, "p3-tidy-supersede")
	a := l.account(accountA)
	arn := p3eOldRole(a, "TidySupRole", "AROATIDYSUPER01", 200*24*time.Hour, "TidySupWork", p3eSQSS3)
	a.lambda("us-east-1", "tidy-sup", arn)
	l.activity(a).set(arn, map[string]*time.Time{"s3": nil, "sqs": nil})
	l.cycle(a, nil)

	_, revN := l.cycle(a, p3eFailAt(l.db, "results_half"))
	_, revN1 := l.cycle(a, p3eFailAt(l.db, "results_half"))
	for _, r := range []int64{revN, revN1} {
		if ev := l.evaluation(r); ev.Status != models.GovEvalFailed {
			t.Fatalf("rev %d: %+v, want failed", r, ev)
		}
	}
	noFence := func(*gorm.DB) error { return nil }
	outcome := services.NewGovEvaluator(l.db).EvaluateRevision(context.Background(), l.ws, revN, noFence)
	if ev := l.evaluation(revN); outcome != services.EvalOutcomeComplete || ev.Status != models.GovEvalComplete {
		t.Fatalf("replay of rev %d with rev %d published but not complete: %s, row %+v, want complete", revN, revN1, outcome, ev)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_finding_result WHERE workspace_id = ? AND rev = ?`, l.ws, revN); n == 0 {
		t.Fatalf("rev %d completed without results", revN)
	}

	_, revN2 := l.cycle(a, nil)
	if ev := l.evaluation(revN2); ev.Status != models.GovEvalComplete {
		t.Fatalf("rev %d: %+v", revN2, ev)
	}
	outcome = services.NewGovEvaluator(l.db).EvaluateRevision(context.Background(), l.ws, revN1, noFence)
	if ev := l.evaluation(revN1); outcome != services.EvalOutcomeSuperseded || ev.Status != models.GovEvalSuperseded {
		t.Fatalf("replay of rev %d after rev %d completed: %s, row %+v, want superseded", revN1, revN2, outcome, ev)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_finding WHERE workspace_id = ? AND last_evaluated_rev <> ?`, l.ws, revN2); n != 0 {
		t.Fatalf("%d findings not at rev %d", n, revN2)
	}
}
