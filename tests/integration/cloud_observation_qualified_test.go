package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// The regression this file exists to catch, stated plainly:
//
// The Phase 2 projector's evidence pass looks up permission observations by a
// FULLY-QUALIFYING subject key (holder ARN, statement id, resource ARN), and
// igagraph.indexObservations SKIPS any permission observation whose stored
// subject_native_id is not qualified. If the permission SCANNER writes a bare
// nativeID instead -- as it did before P2-2 -- every permission observation is
// skipped, every access edge is projected with NO evidence, silently, with no
// error.
//
// That defect shipped once precisely because no test drove the scanner's
// evidence output. This one does: it runs the real IAM + permission scanners
// with an evidence writer attached and asserts that what lands in
// cloud_observation is what the projector will actually find.
func TestPermissionEvidenceSubjectKeyIsQualified(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-permission-evidence-qualified")
	defer cleanPermissionTables(t, db, ws)
	defer db.Exec(`DELETE FROM cloud_observation WHERE workspace_id = ?`, ws)

	fake := iamWithConcreteResourceARNs()
	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	// A claimed run so the evidence writer has a real (workspace, run,
	// generation) to anchor to. Claim sets generation = connector.scan_generation
	// + 1, which is exactly what the IAM scanner computes for this same fresh
	// connector -- so the observation rows and the inventory rows share one
	// generation, as they do under the real worker.
	runs := scanRuns(t, db)
	if _, err := runs.Enqueue(ws, c.ID, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	run, err := runs.Claim("worker-a", time.Minute, time.Now())
	if err != nil || run == nil {
		t.Fatalf("claim: %v %v", run, err)
	}
	writer := services.NewObservationWriter(db, ws, c.ID, run.ID, run.Generation)
	if writer == nil {
		t.Fatal("expected an observation writer for a claimed run")
	}

	iamScanner := services.NewAWSIAMScanner(db, svc).WithIAMAPI(fake).WithEvidence(writer)
	snap, err := iamScanner.Scan(context.Background(), ws, c.ID)
	if err != nil {
		t.Fatalf("iam scan: %v", err)
	}
	permScanner := services.NewAWSPermissionScanner(db, svc).WithIAMAPI(fake).WithEvidence(writer)
	if _, err := permScanner.ScanFromSnapshot(context.Background(), ws, snap); err != nil {
		t.Fatalf("permission scan: %v", err)
	}

	// Every permission observation this scan wrote.
	var rows []struct {
		SubjectNativeID string
		SourceAPI       string
	}
	if err := db.Raw(`
		SELECT subject_native_id, source_api
		  FROM cloud_observation
		 WHERE workspace_id = ? AND permission_id IS NOT NULL`, ws).Scan(&rows).Error; err != nil {
		t.Fatalf("read observations: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("the permission scan wrote no permission evidence -- the test would be vacuous")
	}

	for _, r := range rows {
		// THE ASSERTION THE BUG VIOLATED. A bare nativeID contains no unit
		// separator, so Qualified() is false and the projector skips it.
		if !igagraph.Qualified(r.SubjectNativeID) {
			t.Errorf("permission observation (%s) has an UNQUALIFIED subject_native_id %q; "+
				"the projector will skip it and the access edge will get no evidence",
				r.SourceAPI, r.SubjectNativeID)
			continue
		}
		// It must lead with the holder ARN -- the key the projector rebuilds
		// from the identity, not the policy id.
		if !strings.HasPrefix(r.SubjectNativeID, "arn:aws:iam::429418377036:role/data-reader"+igagraph.Sep) {
			t.Errorf("qualified key is not holder-led: %q", r.SubjectNativeID)
		}
		// Three segments: holder, statement id, resource-or-*.
		if got := strings.Count(r.SubjectNativeID, igagraph.Sep); got != 2 {
			t.Errorf("want 2 separators (holder|statement|resource), got %d in %q", got, r.SubjectNativeID)
		}
	}
}

// The dedupe-path half of P2-2 (SPEC §4.8): an unchanged rescan writes no new
// row and takes the DO UPDATE branch, so a pre-change UNQUALIFIED key already
// in the table must be UPGRADED there -- or it would survive indefinitely for
// stable IAM and the edge would never get evidence.
//
// Guarded so it only ever adds qualification: a qualified key is never
// downgraded, and a bare-ARN subject (identity/resource/workload) is untouched.
func TestObservationDedupeUpgradesUnqualifiedKey(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-observation-upgrade")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)
	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	run, err := runs.Claim("worker-a", time.Minute, time.Now())
	if err != nil || run == nil {
		t.Fatalf("claim: %v %v", run, err)
	}

	permissionID := uuid.New()
	identityID := uuid.New()
	holderARN := "arn:aws:iam::1234:role/legacy-" + identityID.String()[:8]
	if err := db.Exec(`
		INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name, last_seen_generation)
		VALUES (?, ?, ?, 'iam_role', ?, 'legacy', ?)`,
		identityID, ws, conn, holderARN, run.Generation).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	if err := db.Exec(`
		INSERT INTO cloud_permission
		  (id, workspace_id, connector_id, identity_id, effect, actions, scope_kind, native_id, last_seen_generation)
		VALUES (?, ?, ?, ?, 'allow', '{"s3:GetObject"}', 'account_wide', ?, ?)`,
		permissionID, ws, conn, identityID, "inline:Legacy#s0", run.Generation).Error; err != nil {
		t.Fatalf("seed permission: %v", err)
	}

	w := services.NewObservationWriter(db, ws, conn, run.ID, run.Generation)
	facts := map[string]any{"effect": "allow", "actions": []string{"s3:GetObject"}}

	// First write: the PRE-P2-2 shape -- a bare nativeID as subject_native_id.
	if err := w.Record(services.PermissionSubject(permissionID), "iam:GetRolePolicy",
		"iam_policies", "reached", time.Now(), "inline:Legacy#s0", facts); err != nil {
		t.Fatalf("first record: %v", err)
	}
	var stored string
	db.Raw(`SELECT subject_native_id FROM cloud_observation WHERE workspace_id=? AND permission_id=?`,
		ws, permissionID).Scan(&stored)
	if igagraph.Qualified(stored) {
		t.Fatalf("precondition failed: first write should be unqualified, got %q", stored)
	}

	// Second write: SAME content (so it dedupes onto the same row and takes the
	// DO UPDATE branch), now supplying the qualified key the scanner produces.
	qualified := igagraph.PermissionSubjectKey(
		models.CloudPermission{NativeID: "inline:Legacy#s0"}, holderARN, "")
	if err := w.Record(services.PermissionSubject(permissionID), "iam:GetRolePolicy",
		"iam_policies", "reached", time.Now(), qualified, facts); err != nil {
		t.Fatalf("second record: %v", err)
	}

	var count int64
	db.Raw(`SELECT count(*) FROM cloud_observation WHERE workspace_id=? AND permission_id=?`,
		ws, permissionID).Scan(&count)
	if count != 1 {
		t.Fatalf("the upgrade must reuse the deduped row, got %d rows", count)
	}
	db.Raw(`SELECT subject_native_id FROM cloud_observation WHERE workspace_id=? AND permission_id=?`,
		ws, permissionID).Scan(&stored)
	if !igagraph.Qualified(stored) {
		t.Fatalf("the dedupe path did not upgrade the unqualified key: still %q", stored)
	}
	if stored != qualified {
		t.Fatalf("upgraded to the wrong key: got %q want %q", stored, qualified)
	}

	// A THIRD write with the qualified key must not thrash it -- the guard only
	// upgrades an unqualified stored value, never rewrites a qualified one.
	if err := w.Record(services.PermissionSubject(permissionID), "iam:GetRolePolicy",
		"iam_policies", "reached", time.Now(), qualified, facts); err != nil {
		t.Fatalf("third record: %v", err)
	}
	db.Raw(`SELECT subject_native_id FROM cloud_observation WHERE workspace_id=? AND permission_id=?`,
		ws, permissionID).Scan(&stored)
	if stored != qualified {
		t.Fatalf("a qualified key was disturbed on re-confirmation: %q", stored)
	}
}
