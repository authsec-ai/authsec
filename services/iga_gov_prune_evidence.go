package services

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	repositories "github.com/authsec-ai/authsec/repository"
)

// The daily prune_evidence job (SPEC-iga-phase3-policy.md §8.1 table:
// "prune_evidence | Daily | ws:<id>:day:<date> | §2.5 retention"; §3.9
// "Retention"; review P2). Before it, prune_evidence existed only as a kind
// constant and PruneResourcePolicyEvidence had no production caller, so
// resource-policy evidence grew without limit.
//
// One job per workspace per UTC day, for every workspace holding evaluation
// results or resource-policy evidence. It runs, fenced on the job's lease
// and in ONE transaction:
//
//  1. the evaluation-evidence prune T3.06 has (iga_gov_activity_evidence and
//     iga_gov_finding_result of complete evaluations outside the newest
//     evidence_retention_revs, keeping every revision a policy version's
//     evidence_rev names; §2.5) -- the same PruneTx the evaluator runs best
//     effort after each evaluation;
//  2. the resource-policy prune (PruneResourcePolicyEvidence: coverage and
//     observations of scans older than evidence_retention_revs publications,
//     except scans a current, approved or deployed plan names; then the
//     documents nothing references; §3.9).
//
// DECISION (P2-pe1). Both halves share the job and the transaction: a lost
// lease writes nothing, and a failure retries the whole day's prune (both
// are idempotent).

// PruneEvidenceEvery is the job's interval.
const PruneEvidenceEvery = 24 * time.Hour

// PruneEvidenceDedupeKey is ws:<id>:day:<YYYY-MM-DD> (UTC).
func PruneEvidenceDedupeKey(ws uuid.UUID, now time.Time) string {
	return "ws:" + ws.String() + ":day:" + now.UTC().Format("2006-01-02")
}

// PruneEvidenceSchedule is prune_evidence's daily schedule.
func PruneEvidenceSchedule() PolicyJobSchedule {
	return PolicyJobSchedule{Kind: repositories.GovJobPruneEvidence, Every: PruneEvidenceEvery, Due: duePruneEvidence}
}

// duePruneEvidence lists, for today (UTC), every workspace with evaluation
// results or resource-policy evidence; the day's dedupe key enqueues each
// at most once (EnqueueOnceTx).
func duePruneEvidence(ctx context.Context, db *gorm.DB, now time.Time) ([]ScheduledPolicyJob, error) {
	var evaluated []uuid.UUID
	if err := db.Raw(`SELECT DISTINCT workspace_id FROM iga_gov_evaluation`).Scan(&evaluated).Error; err != nil {
		return nil, fmt.Errorf("evaluated workspaces: %w", err)
	}
	collected, err := cloudReads.ResourcePolicyWorkspaces(db)
	if err != nil {
		return nil, fmt.Errorf("resource-policy workspaces: %w", err)
	}
	set := map[uuid.UUID]bool{}
	for _, ws := range append(evaluated, collected...) {
		set[ws] = true
	}
	wss := make([]uuid.UUID, 0, len(set))
	for ws := range set {
		wss = append(wss, ws)
	}
	sort.Slice(wss, func(i, j int) bool { return wss[i].String() < wss[j].String() })
	out := make([]ScheduledPolicyJob, 0, len(wss))
	for _, ws := range wss {
		out = append(out, ScheduledPolicyJob{WorkspaceID: ws, DedupeKey: PruneEvidenceDedupeKey(ws, now), Once: true})
	}
	return out, nil
}

// PruneEvidenceHandler runs one workspace's daily prune (see above).
func PruneEvidenceHandler(ctx context.Context, run *PolicyJobRun) error {
	ws := run.Job.WorkspaceID
	return run.InTx(ctx, func(tx *gorm.DB) error {
		settings, err := repositories.NewIGAGovSettingsRepository(tx).Get(ws)
		if err != nil {
			return fmt.Errorf("read retention setting: %w", err)
		}
		results, err := repositories.NewIGAGovEvaluationRepository().PruneTx(tx, ws, settings.EvidenceRetentionRevs)
		if err != nil {
			return fmt.Errorf("evaluation evidence: %w", err)
		}
		rp, err := PruneResourcePolicyEvidence(tx, ws)
		if err != nil {
			return fmt.Errorf("resource-policy evidence: %w", err)
		}
		log.Printf("[policy] prune_evidence %s: %d evaluation rows, %d scans (%d coverage rows), %d documents",
			ws, results, len(rp.Scans), rp.CoverageRows, rp.Documents)
		return nil
	})
}

// RegisterPruneEvidenceJob installs prune_evidence and its daily schedule.
func RegisterPruneEvidenceJob(w *PolicyJobWorker) {
	w.Register(PolicyJobKind{Kind: repositories.GovJobPruneEvidence, Handler: PruneEvidenceHandler,
		Backoff: func(n int) time.Duration { return time.Duration(n) * 10 * time.Minute }})
	w.Scheduler().Add(PruneEvidenceSchedule())
}
