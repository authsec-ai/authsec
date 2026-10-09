package integration

// Review P2 (prune_evidence): the daily prune_evidence job is scheduled per
// workspace (dedupe ws:<id>:day:<date>, §8.1), registered on the production
// worker, and prunes BOTH the evaluation evidence (§2.5) and the
// resource-policy evidence (§3.9) -- through the REAL scheduler and job
// worker, over evidence produced by REAL scans with collection and REAL
// evaluations.

import (
	"context"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

func TestP3CovPruneEvidenceScheduledDaily(t *testing.T) {
	// The production worker has the kind and the schedule.
	def := services.NewDefaultPolicyJobWorker(igaDB(t))
	if !p3eHas(def.Kinds(), repositories.GovJobPruneEvidence) || !p3eHas(def.Scheduler().ScheduleNames(), repositories.GovJobPruneEvidence) {
		t.Fatalf("default worker kinds %v schedules %v, want prune_evidence in both", def.Kinds(), def.Scheduler().ScheduleNames())
	}

	l := newP3aLab(t, "p3-cov-prune")
	l.role("PruneRole", "AROACOVPRUNE001", map[string]*time.Time{"s3": p3eTime(time.Hour), "sqs": nil})
	world := newP3covWorld(accountA, "us-east-1")
	var runs []models.CloudScanRun
	for i := 0; i < 7; i++ {
		runs = append(runs, l.publishCollected(world))
	}
	revs := func() int64 {
		return l.count(`SELECT count(DISTINCT rev) FROM iga_gov_activity_evidence WHERE workspace_id = ?`, l.ws)
	}
	scans := func() int64 {
		return l.count(`SELECT count(DISTINCT scan_run_id) FROM cloud_resource_policy_coverage WHERE workspace_id = ?`, l.ws)
	}
	if revs() != 7 || scans() != 7 {
		t.Fatalf("before: %d evaluated revisions, %d scans with evidence; want 7 and 7", revs(), scans())
	}
	// The retention drops to 5 (the minimum 055 allows).
	p3exec(t, l.db, `INSERT INTO iga_gov_settings (workspace_id, evidence_retention_revs) VALUES (?, 5)
	                 ON CONFLICT (workspace_id) DO UPDATE SET evidence_retention_revs = 5`, l.ws)

	w := services.NewPolicyJobWorker(l.db, "p3cov-prune").WithGate(func() bool { return true })
	services.RegisterPruneEvidenceJob(w)
	now := time.Now()
	if _, err := w.Scheduler().RunSchedulesNow(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	key := services.PruneEvidenceDedupeKey(l.ws, now)
	if n := l.count(`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ? AND kind = 'prune_evidence' AND dedupe_key = ?`, l.ws, key); n != 1 {
		t.Fatalf("%d prune_evidence jobs with key %s, want 1", n, key)
	}
	for i := 0; i < 20; i++ {
		ok, err := w.RunOnce(context.Background())
		if err != nil {
			t.Fatalf("worker: %v", err)
		}
		if !ok {
			break
		}
	}
	var status string
	l.db.Raw(`SELECT status FROM iga_gov_job WHERE workspace_id = ? AND kind = 'prune_evidence'`, l.ws).Scan(&status)
	if status != "complete" {
		t.Fatalf("prune_evidence job %s, want complete", status)
	}
	if revs() != 5 {
		t.Fatalf("after: %d evaluated revisions keep activity evidence, want the newest 5", revs())
	}
	if scans() != 5 {
		t.Fatalf("after: %d scans keep resource-policy evidence, want the 5 the newest publications name", scans())
	}
	for _, r := range runs[:2] {
		if n := l.count(`SELECT count(*) FROM cloud_resource_policy_coverage WHERE workspace_id = ? AND scan_run_id = ?`, l.ws, r.ID); n != 0 {
			t.Fatalf("old scan %s kept %d coverage rows", r.ID, n)
		}
	}
	// Daily: the same day enqueues nothing more; the next day does.
	if n, err := w.Scheduler().RunSchedulesNow(context.Background(), now); err != nil || l.count(
		`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ? AND kind = 'prune_evidence'`, l.ws) != 1 {
		t.Fatalf("same day: %d enqueued (%v)", n, err)
	}
	if _, err := w.Scheduler().RunSchedulesNow(context.Background(), now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := l.count(`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ? AND kind = 'prune_evidence'`, l.ws); n != 2 {
		t.Fatalf("next day: %d prune_evidence jobs, want 2", n)
	}
}
