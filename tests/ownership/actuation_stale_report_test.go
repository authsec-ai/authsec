// The lease fence on an instruction report (disposition plan §2, "Stale-report
// defect"; SPEC-iga-phase3-policy.md §13.1 Stage 0).
//
// Report used to check only that the instruction belonged to the calling
// connector. A worker whose lease had been reclaimed -- it stalled, the reaper
// returned its work to the queue, another worker took it -- could still land
// its late outcome: over the new holder's lease, over a pending row nobody
// held, or over an instruction already failed or superseded.
//
// The properties: only the holder of a LIVE lease may report; a refused report
// changes nothing at all (instruction or agent); the legitimate holder's report
// behaves exactly as before, with or without naming itself.
package ownership

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/controllers/platform"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// leasedQuarantine quarantines the fixture's agent and leases the resulting
// quarantine instruction to holder.
func leasedQuarantine(t *testing.T, f actFixture, holder string) uuid.UUID {
	t.Helper()
	if _, err := f.dm.QuarantineAgent(f.ws, f.agent, "exfiltration", nil); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	leased, err := f.am.Lease(f.source, holder, 10, time.Minute)
	if err != nil || len(leased) != 1 {
		t.Fatalf("lease: %v (%d)", err, len(leased))
	}
	return leased[0].ID
}

// expireLease puts an instruction's lease in the past, as a stalled worker's.
func expireLease(t *testing.T, f actFixture, id uuid.UUID) {
	t.Helper()
	exec(t, f.raw, `UPDATE provisioning_instructions
	                   SET lease_expires_at = now() - interval '1 minute' WHERE id = $1`, id)
}

// instructionState is everything a report could change: the instruction row
// and the agent row, as JSON text.
func instructionState(t *testing.T, f actFixture, id uuid.UUID) string {
	t.Helper()
	var inst, agent string
	if err := f.raw.QueryRow(`SELECT row_to_json(p)::text FROM provisioning_instructions p
	                           WHERE id = $1`, id).Scan(&inst); err != nil {
		t.Fatalf("read instruction: %v", err)
	}
	if err := f.raw.QueryRow(`SELECT row_to_json(a)::text FROM discovered_agents a
	                           WHERE id = $1`, f.agent).Scan(&agent); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	return inst + "\n" + agent
}

func assertRefused(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: want %v, got %v", what, want, err)
	}
}

// The legitimate holder, naming itself, is accepted exactly as before.
func TestReportFromTheLeaseHolderIsAccepted(t *testing.T) {
	f := newActFixture(t)
	id := leasedQuarantine(t, f, "pod-a")

	out, err := f.am.Report(f.source, id, services.ReportInput{
		Success: true, LeasedBy: "pod-a",
		Result: map[string]interface{}{"network_policy": "authsec-quarantine-research-agent"},
	})
	if err != nil {
		t.Fatalf("the holder of a live lease must be able to report: %v", err)
	}
	if out.Status != models.InstructionApplied || out.AppliedAt == nil || out.LeasedBy != "" {
		t.Errorf("want applied with the lease cleared, got %+v", out)
	}
	var enforcedAt *time.Time
	if err := f.raw.QueryRow(`SELECT quarantine_enforced_at FROM discovered_agents WHERE id = $1`,
		f.agent).Scan(&enforcedAt); err != nil {
		t.Fatalf("read agent: %v", err)
	}
	if enforcedAt == nil {
		t.Error("the holder's success must still fold into the agent's state")
	}

	// A duplicate of the holder's own report stays idempotent.
	again, err := f.am.Report(f.source, id, services.ReportInput{Success: true, LeasedBy: "pod-a"})
	if err != nil || again.Status != models.InstructionApplied {
		t.Errorf("a duplicate report after success must stay idempotent: %v %+v", err, again)
	}
}

// THE defect: worker A stalls, its lease is reclaimed and the work re-leased
// to worker B. A's late report must not land; B's must.
func TestReclaimedWorkersLateReportIsRefused(t *testing.T) {
	f := newActFixture(t)
	id := leasedQuarantine(t, f, "pod-a")
	expireLease(t, f, id)
	if n, err := f.am.ReclaimExpiredLeases(); err != nil || n != 1 {
		t.Fatalf("reclaim: %v (%d)", err, n)
	}
	retry, err := f.am.Lease(f.source, "pod-b", 10, time.Minute)
	if err != nil || len(retry) != 1 || retry[0].ID != id {
		t.Fatalf("re-lease to pod-b: %v %+v", err, retry)
	}

	before := instructionState(t, f, id)
	_, err = f.am.Report(f.source, id, services.ReportInput{
		Success: false, Error: "late failure from the stalled worker", LeasedBy: "pod-a",
	})
	assertRefused(t, "pod-a reporting on pod-b's lease", err, services.ErrInstructionLeaseNotHeld)
	if after := instructionState(t, f, id); after != before {
		t.Errorf("a refused report must change nothing.\nbefore: %s\nafter:  %s", before, after)
	}

	// The current holder is unaffected.
	out, err := f.am.Report(f.source, id, services.ReportInput{Success: true, LeasedBy: "pod-b"})
	if err != nil || out.Status != models.InstructionApplied {
		t.Fatalf("the current holder must still report: %v %+v", err, out)
	}
}

// Reclaimed and not yet re-leased: nobody holds it. A late FAILURE is
// refused (the instruction is already back in the queue for a retry).
func TestLateFailureOnAReclaimedPendingInstructionIsRefused(t *testing.T) {
	f := newActFixture(t)
	id := leasedQuarantine(t, f, "pod-a")
	expireLease(t, f, id)
	if _, err := f.am.ReclaimExpiredLeases(); err != nil {
		t.Fatalf("reclaim: %v", err)
	}

	before := instructionState(t, f, id)
	_, err := f.am.Report(f.source, id, services.ReportInput{Success: false, Error: "late"})
	assertRefused(t, "late failure on a pending instruction", err, services.ErrInstructionLeaseNotHeld)
	if after := instructionState(t, f, id); after != before {
		t.Errorf("a refused report must change nothing.\nbefore: %s\nafter:  %s", before, after)
	}
}

// Review fix R1a P2: a late SUCCESS on a reclaimed, re-queued instruction is
// RECORDED -- applied, with a note, folded into the agent -- not refused and
// re-run: the work was done in the cluster, and re-running it is the
// duplicate apply the fence exists to prevent. Once applied, nothing leases
// it again; the reaper has nothing to reclaim.
func TestLateSuccessOnAReclaimedInstructionIsRecordedNotRerun(t *testing.T) {
	for _, holder := range []string{"pod-a", ""} {
		t.Run("holder="+holder, func(t *testing.T) {
			f := newActFixture(t)
			id := leasedQuarantine(t, f, "pod-a")
			expireLease(t, f, id)
			if n, err := f.am.ReclaimExpiredLeases(); err != nil || n != 1 {
				t.Fatalf("reclaim: %v (%d)", err, n)
			}
			out, err := f.am.Report(f.source, id, services.ReportInput{Success: true, LeasedBy: holder,
				Result: map[string]interface{}{"network_policy": "authsec-quarantine-research-agent"}})
			if err != nil {
				t.Fatalf("a late success must be recorded: %v", err)
			}
			if out.Status != models.InstructionApplied || out.AppliedAt == nil || out.LeasedBy != "" ||
				!strings.Contains(string(out.Result), "authsec_late_report") || !strings.Contains(string(out.Result), "network_policy") {
				t.Fatalf("want applied with the agent's result and a note, got %+v (%s)", out, out.Result)
			}
			var enforcedAt *time.Time
			if err := f.raw.QueryRow(`SELECT quarantine_enforced_at FROM discovered_agents WHERE id = $1`, f.agent).Scan(&enforcedAt); err != nil {
				t.Fatal(err)
			}
			if enforcedAt == nil {
				t.Error("the late success must fold into the agent's state")
			}
			// Never handed out again: no duplicate apply through the queue.
			if again, err := f.am.Lease(f.source, "pod-b", 10, time.Minute); err != nil || len(again) != 0 {
				t.Fatalf("an applied instruction was leased again: %v %+v", err, again)
			}
			// A duplicate of the same report stays idempotent.
			if dup, err := f.am.Report(f.source, id, services.ReportInput{Success: true}); err != nil || dup.Status != models.InstructionApplied {
				t.Fatalf("duplicate: %v %+v", err, dup)
			}
		})
	}
}

// Reclaimed AND re-leased to pod-b: pod-a's late success is refused (pod-b
// holds a live lease and its run is the one recorded), and changes nothing.
func TestLateSuccessAfterReLeaseIsRefused(t *testing.T) {
	f := newActFixture(t)
	id := leasedQuarantine(t, f, "pod-a")
	expireLease(t, f, id)
	if _, err := f.am.ReclaimExpiredLeases(); err != nil {
		t.Fatal(err)
	}
	if again, err := f.am.Lease(f.source, "pod-b", 10, time.Minute); err != nil || len(again) != 1 {
		t.Fatalf("re-lease: %v %+v", err, again)
	}
	before := instructionState(t, f, id)
	_, err := f.am.Report(f.source, id, services.ReportInput{Success: true, LeasedBy: "pod-a"})
	assertRefused(t, "pod-a's late success on pod-b's lease", err, services.ErrInstructionLeaseNotHeld)
	if after := instructionState(t, f, id); after != before {
		t.Errorf("a refused report must change nothing.\nbefore: %s\nafter:  %s", before, after)
	}
	// pod-b's run is the one recorded.
	if out, err := f.am.Report(f.source, id, services.ReportInput{Success: true, LeasedBy: "pod-b"}); err != nil ||
		out.Status != models.InstructionApplied || strings.Contains(string(out.Result), "authsec_late_report") {
		t.Fatalf("pod-b's report: %v %+v", err, out)
	}
}

// The lease ran out before the report arrived and the reaper has not run
// yet: a late failure is refused as expired (the reaper reclaims it as
// usual); a late success is recorded and the reaper has nothing to reclaim.
func TestReportAfterLeaseExpiry(t *testing.T) {
	f := newActFixture(t)
	id := leasedQuarantine(t, f, "pod-a")
	expireLease(t, f, id)

	before := instructionState(t, f, id)
	for _, holder := range []string{"pod-a", ""} {
		_, err := f.am.Report(f.source, id, services.ReportInput{Success: false, Error: "late", LeasedBy: holder})
		assertRefused(t, "late failure on an expired lease (holder "+holder+")", err,
			services.ErrInstructionLeaseExpired)
	}
	if after := instructionState(t, f, id); after != before {
		t.Errorf("a refused report must change nothing.\nbefore: %s\nafter:  %s", before, after)
	}
	out, err := f.am.Report(f.source, id, services.ReportInput{Success: true, LeasedBy: "pod-a"})
	if err != nil || out.Status != models.InstructionApplied || !strings.Contains(string(out.Result), "authsec_late_report") {
		t.Fatalf("late success on an expired lease: %v %+v", err, out)
	}
	if n, err := f.am.ReclaimExpiredLeases(); err != nil || n != 0 {
		t.Errorf("an applied instruction must not be reclaimed: %v (%d)", err, n)
	}
}

// A live lease held by someone else: a reporter naming a different holder is
// refused.
func TestReportNamingAnotherHolderIsRefused(t *testing.T) {
	f := newActFixture(t)
	id := leasedQuarantine(t, f, "pod-b")

	before := instructionState(t, f, id)
	_, err := f.am.Report(f.source, id, services.ReportInput{Success: true, LeasedBy: "pod-a"})
	assertRefused(t, "pod-a reporting on pod-b's live lease", err, services.ErrInstructionLeaseNotHeld)
	if after := instructionState(t, f, id); after != before {
		t.Errorf("a refused report must change nothing.\nbefore: %s\nafter:  %s", before, after)
	}
}

// A late success must not reopen an instruction that is already closed.
// Before the fence it flipped 'failed' and 'superseded' to 'applied'.
func TestLateReportCannotReopenAClosedInstruction(t *testing.T) {
	for _, status := range []string{models.InstructionFailed, models.InstructionSuperseded} {
		t.Run(status, func(t *testing.T) {
			f := newActFixture(t)
			id := leasedQuarantine(t, f, "pod-a")
			exec(t, f.raw, `UPDATE provisioning_instructions
			                   SET status = $2, applied_at = now(), error = 'closed',
			                       lease_expires_at = NULL, leased_by = ''
			                 WHERE id = $1`, id, status)

			before := instructionState(t, f, id)
			_, err := f.am.Report(f.source, id, services.ReportInput{Success: true, LeasedBy: "pod-a"})
			assertRefused(t, "late report on a "+status+" instruction", err,
				services.ErrInstructionLeaseNotHeld)
			if after := instructionState(t, f, id); after != before {
				t.Errorf("a refused report must change nothing.\nbefore: %s\nafter:  %s", before, after)
			}
		})
	}
}

// Over HTTP: the agent's report endpoint answers a stale report 409 with a
// code, and the holder (naming itself with ?pod= as on the lease) gets 200.
func TestReportEndpointAnswersAStaleReport409(t *testing.T) {
	f := newActFixture(t)
	gin.SetMode(gin.TestMode)
	ctl := platform.NewGovernanceController(gormFor(t, f.raw))
	r := gin.New()
	r.POST("/authsec/provisioning/instructions/:id/result", ctl.ReportInstruction)

	post := func(id uuid.UUID, pod string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"success": true})
		path := "/authsec/provisioning/instructions/" + id.String() + "/result"
		if pod != "" {
			path += "?pod=" + pod
		}
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+f.token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	id := leasedQuarantine(t, f, "pod-b")
	rec := post(id, "pod-a")
	if rec.Code != http.StatusConflict {
		t.Fatalf("a stale report must be 409, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != "lease_not_held" || body.Error == "" {
		t.Errorf("want code lease_not_held with a message, got %s", rec.Body.String())
	}

	if rec := post(id, "pod-b"); rec.Code != http.StatusOK {
		t.Fatalf("the holder's report must be 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// A late success on a reclaimed instruction: 200 and recorded, not 409.
	f2 := newActFixture(t)
	ctl2 := platform.NewGovernanceController(gormFor(t, f2.raw))
	r2 := gin.New()
	r2.POST("/authsec/provisioning/instructions/:id/result", ctl2.ReportInstruction)
	id2 := leasedQuarantine(t, f2, "pod-a")
	expireLease(t, f2, id2)
	if _, err := f2.am.ReclaimExpiredLeases(); err != nil {
		t.Fatal(err)
	}
	lateBody, _ := json.Marshal(map[string]any{"success": true})
	req := httptest.NewRequest(http.MethodPost, "/authsec/provisioning/instructions/"+id2.String()+"/result?pod=pod-a", bytes.NewReader(lateBody))
	req.Header.Set("Authorization", "Bearer "+f2.token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"applied"`) {
		t.Fatalf("a late success must be 200 and recorded, got %d: %s", w.Code, w.Body.String())
	}
}
