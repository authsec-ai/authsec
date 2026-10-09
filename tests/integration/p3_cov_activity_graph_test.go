package integration

// Review P3 (T3.03): "workload-bound" in the Access Advisor sample's
// priority is the PUBLISHED GRAPH's executes_as / task_execution_role
// relationships, with the scan's own cloud_workload rows kept as the
// fallback -- through the REAL scan worker and the REAL projection.
//
// 600 roles "A-bulk-NNN" sort before zz-bound and fill the 500-identity cap,
// so zz-bound is read only when it is prioritised.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// p3covScan is one scan through the REAL worker with act answering Access
// Advisor, then (project) one REAL projection.
func (l *p2Lab) p3covScan(a *p2Account, act *s3bActivity, project bool) models.SurfaceCoverage {
	l.t.Helper()
	scanSeq++
	queued, err := l.runs.Enqueue(l.ws, a.conn, "manual")
	if err != nil {
		l.t.Fatalf("enqueue: %v", err)
	}
	base := a.hook()
	w := services.NewAWSScanWorker(l.db, a.svc).WithOwner(fmt.Sprintf("p3cov-act-%d", scanSeq)).
		WithGraphProjection(l.gate).
		WithScannerHook(func(i *services.AWSIAMScanner, p *services.AWSPermissionScanner, wl *services.AWSWorkloadScanner) {
			base(i, p, wl)
			wl.WithActivityAPI(act, func(context.Context, time.Duration) error { return nil })
		})
	if worked, err := w.RunOnce(context.Background()); err != nil || !worked {
		l.t.Fatalf("scan worker: worked=%v err=%v", worked, err)
	}
	var run models.CloudScanRun
	if err := l.db.First(&run, "id = ?", queued.ID).Error; err != nil || run.Status != models.CloudScanRunPublished {
		l.t.Fatalf("run %+v: %v", run, err)
	}
	if project {
		l.project(fmt.Sprintf("p3cov-act-projector-%d", scanSeq))
	}
	return models.DecodeScanCoverage(run.Coverage).Surfaces[models.SurfaceActivity]
}

func p3covSubmitted(act *s3bActivity, arn string) bool {
	act.mu.Lock()
	defer act.mu.Unlock()
	for _, s := range act.submitted {
		if s == arn {
			return true
		}
	}
	return false
}

func TestP3CovActivitySampleUsesGraphRelationships(t *testing.T) {
	l := newP2Lab(t, "p3-cov-activity-graph", true)
	a := l.account(testAccount)
	for i := 1; i <= 600; i++ {
		a.role(fmt.Sprintf("A-bulk-%03d", i), fmt.Sprintf("AROABULK%04d", i))
	}
	bound := a.role("zz-bound", "AROAZZBOUND0001")
	a.lambda("us-east-1", "bound-fn", bound)

	// Scan 1, before any publication: the graph has nothing, and the scan's
	// own workload row (the fallback) prioritises zz-bound.
	act1 := &s3bActivity{}
	cov := l.p3covScan(a, act1, true)
	if !p3covSubmitted(act1, bound) || !p3eHas(cov.Prioritized, bound) {
		t.Fatalf("first scan: zz-bound sampled=%v prioritized=%v, want prioritised by its own workload row", p3covSubmitted(act1, bound), cov.Prioritized)
	}
	// The published graph binds it.
	if n := l.count(`SELECT count(*) FROM iga_relationship r JOIN iga_identity_accounts ia ON ia.id = r.target_identity_account_id
	                  WHERE r.workspace_id = ? AND r.relationship_type = 'executes_as' AND r.state <> 'ended' AND ia.display_name = 'zz-bound'`, l.ws); n != 1 {
		t.Fatalf("published executes_as edges to zz-bound: %d, want 1", n)
	}

	// Scan 2: the function is gone, and no cloud_workload row names zz-bound
	// any more (within one connector the scan's own rows otherwise keep a
	// binding until the scan's end -- a stale row is reconciled only after
	// activity is read, and a failed detail call keeps its attribution,
	// D-53 -- so the row is removed here to isolate the graph). The
	// published graph still binds it, and that alone must prioritise it.
	a.lambda("us-east-1", "bound-fn", "")
	p3exec(t, l.db, `DELETE FROM cloud_workload WHERE workspace_id = ? AND identity_id IN
	                   (SELECT id FROM cloud_identity WHERE workspace_id = ? AND native_id = ?)`, l.ws, l.ws, bound)
	act2 := &s3bActivity{}
	cov = l.p3covScan(a, act2, true)
	if n := l.count(`SELECT count(*) FROM cloud_workload w JOIN cloud_identity ci ON ci.id = w.identity_id
	                  WHERE w.workspace_id = ? AND ci.native_id = ?`, l.ws, bound); n != 0 {
		t.Fatalf("scan 2 still has %d workload rows for zz-bound", n)
	}
	if !p3covSubmitted(act2, bound) || !p3eHas(cov.Prioritized, bound) {
		t.Fatalf("second scan: zz-bound sampled=%v prioritized=%v, want prioritised by the graph's executes_as", p3covSubmitted(act2, bound), cov.Prioritized)
	}

	// Scan 3: the graph ended the edge at scan 2's projection; nothing binds
	// zz-bound any more, so it falls back to byte order (past the cap).
	act3 := &s3bActivity{}
	cov = l.p3covScan(a, act3, false)
	if p3covSubmitted(act3, bound) || p3eHas(cov.Prioritized, bound) {
		t.Fatalf("third scan: zz-bound still prioritised (%v) with no relationship and no workload", cov.Prioritized)
	}
}
