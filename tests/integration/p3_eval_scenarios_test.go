package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// T3.06 scenarios of SPEC-iga-phase3-policy.md §14.2, through the REAL
// projection job (scan worker + projection service + evaluation step) and
// the PRODUCTION /api/iga/v1/policy routes.

// p3eFailAt is an evaluator whose hook fails at one stage.
func p3eFailAt(db *gorm.DB, stage string) *services.GovEvaluator {
	return services.NewGovEvaluator(db).WithHook(func(s string, _ int64, _ *gorm.DB) error {
		if s == stage {
			return errors.New("injected failure at " + stage)
		}
		return nil
	})
}

// A32 and A21. Rev 1: s3 and sqs both unused. Rev 2: s3 used, so its
// unused_service clears at 2 -- and a read at ?rev=1 still returns it,
// byte for byte, with the finding's CURRENT status labelled as current. Rev 3:
// the evaluation fails after writing half its results -- none survive, ?rev=3
// is 409 evaluation_incomplete, default reads stay at rev 2 and say rev 3
// failed. Rev 4 completes; a late replay of rev 3 is superseded and changes
// nothing: no older revision overwrites a newer one, and the 048 trigger
// refuses lowering last_evaluated_rev.
//
// Safeguards (mutation-checked): results in the same transaction as the
// complete status; default reads at the newest COMPLETE evaluation; the
// supersede check before a replayed evaluation.
func TestP3T306A32A21RevisionPinnedReadsAndNoOlderOverwrite(t *testing.T) {
	l := newP3eLab(t, "p3-t306-a32")
	a := l.account(accountA)
	arn := p3eOldRole(a, "LedgerRole", "AROALEDGER0001", 200*24*time.Hour, "LedgerWork", p3eSQSS3)
	a.lambda("us-east-1", "ledger", arn)
	act := l.activity(a)
	act.set(arn, map[string]*time.Time{"s3": nil, "sqs": nil})
	api := l.api()

	_, rev1 := l.cycle(a, nil)
	code, body := api.get(l.ws, fmt.Sprintf("/findings?rev=%d&kind=unused_service", rev1))
	if code != http.StatusOK || len(p3eList(body)) != 2 {
		t.Fatalf("rev %d unused_service: %d %v, want s3 and sqs", rev1, code, body)
	}
	rev1Before, _ := json.Marshal(p3eConditions(body))

	act.set(arn, map[string]*time.Time{"s3": p3eTime(24 * time.Hour), "sqs": nil})
	_, rev2 := l.cycle(a, nil)
	code, body = api.get(l.ws, "/findings?kind=unused_service")
	if code != http.StatusOK || len(p3eList(body)) != 1 || p3eList(body)[0]["detail_key"] != "sqs" ||
		p3eMeta(body, "evaluated_rev") != float64(rev2) {
		t.Fatalf("default read: %d %v, want only sqs at rev %d", code, body, rev2)
	}
	code, body = api.get(l.ws, fmt.Sprintf("/findings?rev=%d&kind=unused_service", rev1))
	rev1After, _ := json.Marshal(p3eConditions(body))
	if code != http.StatusOK || string(rev1After) != string(rev1Before) {
		t.Fatalf("rev %d changed after rev %d:\nbefore %s\nafter  %s", rev1, rev2, rev1Before, rev1After)
	}
	for _, f := range p3eList(body) {
		cur, _ := f["current"].(map[string]any)
		if f["detail_key"] == "s3" && (cur["status"] != igagov.StatusCleared || cur["last_evaluated_rev"] != float64(rev2)) {
			t.Fatalf("s3 at rev %d: current %v, want status cleared at rev %d, labelled current", rev1, cur, rev2)
		}
	}

	// Rev 3 fails after half its results.
	_, rev3 := l.cycle(a, p3eFailAt(l.db, "results_half"))
	if ev := l.evaluation(rev3); ev.Status != models.GovEvalFailed || !strings.Contains(ev.Error, "results_half") {
		t.Fatalf("rev %d evaluation %+v, want failed naming the injected failure", rev3, ev)
	}
	for _, table := range []string{"iga_gov_finding_result", "iga_gov_activity_evidence"} {
		if n := l.count(`SELECT count(*) FROM `+table+` WHERE workspace_id = ? AND rev = ?`, l.ws, rev3); n != 0 {
			t.Fatalf("failed rev %d left %d rows in %s", rev3, n, table)
		}
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_finding WHERE workspace_id = ? AND last_evaluated_rev >= ?`, l.ws, rev3); n != 0 {
		t.Fatalf("failed rev %d moved %d findings", rev3, n)
	}
	if code, body = api.get(l.ws, fmt.Sprintf("/findings?rev=%d", rev3)); code != http.StatusConflict || p3eErr(body) != "evaluation_incomplete" {
		t.Fatalf("?rev=%d: %d %v, want 409 evaluation_incomplete", rev3, code, body)
	}
	code, body = api.get(l.ws, "/findings/summary")
	last, _ := p3eMeta(body, "last_evaluation").(map[string]any)
	if code != http.StatusOK || p3eMeta(body, "evaluated_rev") != float64(rev2) || last["rev"] != float64(rev3) || last["status"] != "failed" {
		t.Fatalf("summary after a failed rev %d: %d %v, want evaluated at %d and the failure shown", rev3, code, body, rev2)
	}

	// Rev 4 completes; the late replay of rev 3 is superseded.
	_, rev4 := l.cycle(a, nil)
	if ev := l.evaluation(rev4); ev.Status != models.GovEvalComplete {
		t.Fatalf("rev %d: %+v", rev4, ev)
	}
	outcome := services.NewGovEvaluator(l.db).EvaluateRevision(context.Background(), l.ws, rev3, func(*gorm.DB) error { return nil })
	if ev := l.evaluation(rev3); outcome != services.EvalOutcomeSuperseded || ev.Status != models.GovEvalSuperseded {
		t.Fatalf("replay of rev %d after rev %d: %s, row %+v, want superseded", rev3, rev4, outcome, ev)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_finding WHERE workspace_id = ? AND last_evaluated_rev <> ?`, l.ws, rev4); n != 0 {
		t.Fatalf("%d findings not at rev %d after the late replay", n, rev4)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_finding_result WHERE workspace_id = ? AND rev = ?`, l.ws, rev3); n != 0 {
		t.Fatalf("superseded rev %d gained %d results", rev3, n)
	}
	err := l.db.Exec(`UPDATE iga_gov_finding SET last_evaluated_rev = ? WHERE workspace_id = ?`, rev2, l.ws).Error
	if err == nil || !strings.Contains(err.Error(), "cannot be overwritten") {
		t.Fatalf("lowering last_evaluated_rev: %v, want the 048 trigger's refusal", err)
	}
	if code, body = api.get(l.ws, fmt.Sprintf("/findings?rev=%d", rev3)); code != http.StatusConflict || p3eErr(body) != "evaluation_incomplete" {
		t.Fatalf("?rev=%d (superseded): %d %v, want 409", rev3, code, body)
	}
}

// p3eConditions is each listed finding's frozen condition, by detail key.
func p3eConditions(body map[string]any) map[string]any {
	out := map[string]any{}
	for _, f := range p3eList(body) {
		out[fmt.Sprint(f["kind"], "/", f["detail_key"])] = f["condition"]
	}
	return out
}

// A37. Evaluation N fails on its budget and the worker dies before the
// release; the replayed projection job (AlreadyPublished) moves failed ->
// running with attempt 2 and completes. The worker dies again after that;
// the second replay changes nothing.
//
// Safeguards (mutation-checked): the guarded failed -> running retry with
// attempts + 1; the no-op on a complete evaluation.
func TestP3T306A37RetryAndReplay(t *testing.T) {
	l := newP3eLab(t, "p3-t306-a37")
	a := l.account(accountA)
	arn := p3eOldRole(a, "BatchRole", "AROABATCH00001", 200*24*time.Hour, "BatchWork", p3eSQSS3)
	a.lambda("us-east-1", "batch", arn)
	l.activity(a).set(arn, map[string]*time.Time{"s3": nil, "sqs": nil})

	crashAfter := func(outcome string, ev *services.GovEvaluator) *services.GovEvaluator {
		return ev.WithHook(func(stage string, _ int64, _ *gorm.DB) error {
			if stage == "done:"+outcome {
				panic("worker killed after the evaluation step")
			}
			return nil
		})
	}
	runCrashing := func(owner string, ev *services.GovEvaluator) {
		t.Helper()
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("%s: the worker did not die", owner)
			}
		}()
		_, _ = l.projector(owner, ev).RunOnce(context.Background())
	}
	expire := func() {
		if err := l.db.Exec(`UPDATE iga_projection_job SET lease_expires_at = now() - interval '1 second'
		                      WHERE workspace_id = ? AND status = 'running'`, l.ws).Error; err != nil {
			t.Fatal(err)
		}
	}

	l.scanOnly(a)
	// 1. The budget is spent before the snapshot completes; the worker dies
	//    after recording failed, before the release.
	runCrashing("p3e-a37-1", crashAfter(services.EvalOutcomeFailed, services.NewGovEvaluator(l.db).WithBudget(time.Nanosecond)))
	rev := l.latestRev()
	ev := l.evaluation(rev)
	if ev.Status != models.GovEvalFailed || ev.Attempts != 1 || !strings.Contains(ev.Error, "budget") {
		t.Fatalf("after the budget overrun: %+v, want failed (budget) on attempt 1", ev)
	}
	if l.barrier() != models.PipelineProjecting {
		t.Fatalf("barrier %s: the dead worker must still hold it", l.barrier())
	}

	// 2. Replay: AlreadyPublished -> failed -> running (attempt 2) -> complete;
	//    the worker dies again after the step.
	expire()
	runCrashing("p3e-a37-2", crashAfter(services.EvalOutcomeComplete, services.NewGovEvaluator(l.db)))
	ev = l.evaluation(rev)
	if ev.Status != models.GovEvalComplete || ev.Attempts != 2 || ev.Error != "" {
		t.Fatalf("after the first replay: %+v, want complete on attempt 2", ev)
	}
	results := l.count(`SELECT count(*) FROM iga_gov_finding_result WHERE workspace_id = ? AND rev = ?`, l.ws, rev)
	events := l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, l.ws)
	if results == 0 {
		t.Fatal("the retried evaluation wrote no results")
	}

	// 3. Second replay after completion: nothing changes; the job completes
	//    and the barrier is released.
	expire()
	worked, err := l.projector("p3e-a37-3", nil).RunOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("third pass: %v %v", worked, err)
	}
	again := l.evaluation(rev)
	if again.Status != models.GovEvalComplete || again.Attempts != 2 || !again.FinishedAt.Equal(*ev.FinishedAt) {
		t.Fatalf("after the second replay: %+v, want the complete row untouched (%+v)", again, ev)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_finding_result WHERE workspace_id = ? AND rev = ?`, l.ws, rev); n != results {
		t.Fatalf("results %d -> %d on a no-op replay", results, n)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_event WHERE workspace_id = ?`, l.ws); n != events {
		t.Fatalf("events %d -> %d on a no-op replay", events, n)
	}
	if l.barrier() != models.PipelineIdle {
		t.Fatalf("barrier %s after the replay completed, want idle", l.barrier())
	}
	// The trigger refuses what the code must never attempt: complete is terminal.
	if err := l.db.Exec(`UPDATE iga_gov_evaluation SET status = 'running', attempts = attempts + 1 WHERE workspace_id = ? AND rev = ?`,
		l.ws, rev).Error; err == nil {
		t.Fatal("complete -> running was accepted")
	}
}

// A47. Accounts A and B in one workspace: A publishes rev 1, B rev 2, A
// rescans for rev 3. Rev 2's evidence and results for A's role cite A's
// rev-1 run (the manifest), B's cite B's run; at rev 3 A's cite A's new run
// and B's still B's. Nothing is invented: both roles are collected at every
// revision and neither gets activity_not_read.
//
// Safeguard (mutation-checked): the role's run is the one its own partition
// names in the manifest, never the run that triggered the publication.
func TestP3T306A47TwoAccountsEachRoleOnItsOwnRun(t *testing.T) {
	l := newP3eLab(t, "p3-t306-a47")
	a, b := l.account(accountA), l.account(accountB)
	arnA := p3eOldRole(a, "AlphaRole", "AROAALPHA00001", 200*24*time.Hour, "AlphaWork", p3eSQSS3)
	arnB := p3eOldRole(b, "BetaRole", "AROABETA000001", 200*24*time.Hour, "BetaWork", p3eSQSS3)
	a.lambda("us-east-1", "alpha", arnA)
	b.lambda("us-east-1", "beta", arnB)
	l.activity(a).set(arnA, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	l.activity(b).set(arnB, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})

	runA1, rev1 := l.cycle(a, nil)
	runB1, rev2 := l.cycle(b, nil)
	runA2, rev3 := l.cycle(a, nil)

	check := func(rev int64, roleID string, want uuid.UUID) {
		t.Helper()
		var ev []models.IGAGovActivityEvidence
		l.db.Where("workspace_id = ? AND rev = ? AND role_id = ?", l.ws, rev, roleID).Find(&ev)
		if len(ev) != 2 {
			t.Fatalf("rev %d %s: %d evidence rows, want s3 and sqs", rev, roleID, len(ev))
		}
		for _, e := range ev {
			if e.State != igagov.EvidenceCollected || e.ScanRunID == nil || *e.ScanRunID != want {
				t.Fatalf("rev %d %s/%s: %s from %v, want collected from %s", rev, roleID, e.Service, e.State, e.ScanRunID, want)
			}
		}
		f, ok := l.findingsAt(rev)["unused_service/"+roleID+"/sqs"]
		if !ok || f.ResultRev == nil || f.EvidenceScanRun == nil || *f.EvidenceScanRun != want {
			t.Fatalf("rev %d %s unused_service(sqs): %+v, want a result citing %s", rev, roleID, f, want)
		}
		if g, ok := l.findingsAt(rev)["activity_not_read/"+roleID+"/"]; ok && g.ResultRev != nil {
			t.Fatalf("rev %d %s: an activity_not_read was invented", rev, roleID)
		}
	}
	if ev := l.evaluation(rev1); ev.Status != models.GovEvalComplete {
		t.Fatalf("rev %d: %+v", rev1, ev)
	}
	check(rev1, "AROAALPHA00001", runA1.ID)
	check(rev2, "AROAALPHA00001", runA1.ID) // B's publication: A still on its own rev-1 run
	check(rev2, "AROABETA000001", runB1.ID)
	check(rev3, "AROAALPHA00001", runA2.ID)
	check(rev3, "AROABETA000001", runB1.ID)
}

// A3. One role's activity report fails: one activity_not_read finding for
// it, linking to the connection's coverage (the gap itself is not repeated),
// no unused_service claim for it; the other role is evaluated normally.
func TestP3T306A3ActivityNotReadLinksToTheGap(t *testing.T) {
	l := newP3eLab(t, "p3-t306-a3")
	a := l.account(accountA)
	bad := p3eOldRole(a, "OpsBotRole", "AROAOPSBOT0001", 200*24*time.Hour, "OpsWork", p3eSQSS3)
	good := p3eOldRole(a, "GoodRole", "AROAGOOD000001", 200*24*time.Hour, "GoodWork", p3eSQSS3)
	a.lambda("us-east-1", "ops-bot", bad)
	p3eAddLambda(a, "us-east-1", "good", good)
	act := l.activity(a)
	act.set(good, map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	act.fail[bad] = true
	_, rev := l.cycle(a, nil)

	api := l.api()
	code, body := api.get(l.ws, "/findings?kind=activity_not_read")
	list := p3eList(body)
	if code != http.StatusOK || len(list) != 1 || list[0]["role_id"] != "AROAOPSBOT0001" {
		t.Fatalf("activity_not_read: %d %v, want exactly one, for OpsBotRole", code, body)
	}
	gap, _ := list[0]["collection_gap"].(map[string]any)
	if gap["remedy"] != "/iga/connections/"+a.conn.String()+"/coverage" || gap["reason"] == "" {
		t.Fatalf("collection gap %v, want the connection's coverage link and the reason", gap)
	}
	code, body = api.get(l.ws, "/findings/"+fmt.Sprint(list[0]["id"]))
	d, _ := body["data"].(map[string]any)
	if code != http.StatusOK || d["collection_gap"] == nil || d["condition_holds_at_rev"] != true {
		t.Fatalf("detail: %d %v", code, body)
	}
	fs := l.findingsAt(rev)
	for k, f := range fs {
		if strings.HasPrefix(k, "unused_service/AROAOPSBOT0001/") && f.ResultRev != nil {
			t.Fatalf("%s claimed although the report was not read", k)
		}
	}
	if f, ok := fs["unused_service/AROAGOOD000001/sqs"]; !ok || f.ResultRev == nil {
		t.Fatal("the readable role lost its unused_service(sqs)")
	}
}

// p3eAddLambda adds one more function in the region running as roleARN
// (p2Account.lambda replaces the region's function).
func p3eAddLambda(a *p2Account, region, name, roleARN string) {
	f := a.lambdas[region]
	if f == nil {
		a.lambda(region, name, roleARN)
		return
	}
	f.functions = append(f.functions, lambdatypes.FunctionConfiguration{
		FunctionArn:  aws.String("arn:aws:lambda:" + region + ":" + a.id + ":function:" + name),
		FunctionName: aws.String(name), Role: aws.String(roleARN), State: lambdatypes.StateActive,
	})
}
