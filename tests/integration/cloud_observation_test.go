package integration

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
)

// Evidence: why a cloud_* row exists.
//
// Two properties carry the weight. Re-reading unchanged data must not grow the
// table, or evidence grows linearly with scan count for an account nobody is
// changing. And the hash must be of REDACTED content: hashing the raw response
// would keep a deterministic derivative of material we refused to store, which
// gives away the privacy property while keeping the liability.

func TestRedactionHappensBeforeHashing(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE-super-secret-value"
	withSecret := map[string]any{
		"function": "support-orchestrator",
		"env":      map[string]any{"Variables": map[string]any{"API_KEY": secret}},
	}
	withDifferentSecret := map[string]any{
		"function": "support-orchestrator",
		"env":      map[string]any{"Variables": map[string]any{"API_KEY": "a-completely-different-secret"}},
	}

	payloadA, hashA, err := services.HashObservation(withSecret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	payloadB, hashB, err := services.HashObservation(withDifferentSecret)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// The stored payload must not contain the secret.
	if strings.Contains(string(payloadA), secret) {
		t.Fatalf("the secret survived into the stored payload: %s", payloadA)
	}
	// And the HASH must not distinguish them. If it did, the hash would be a
	// deterministic derivative of a value we refused to store — an oracle for
	// exactly the material redaction removed.
	if hashA != hashB {
		t.Fatalf("two payloads differing only in a redacted value hashed differently:\n%s\n%s",
			payloadA, payloadB)
	}
}

func TestRedactionKeepsTheShapeAndTheMetadata(t *testing.T) {
	payload, _, err := services.HashObservation(map[string]any{
		"function": "support-orchestrator",
		"env":      map[string]any{"Variables": map[string]any{"LANGCHAIN_TRACING_V2": "true"}},
	})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The function name is metadata and must survive: it is what a reviewer
	// reads. Only the values are removed.
	if decoded["function"] != "support-orchestrator" {
		t.Errorf("metadata was redacted along with the secret: %v", decoded)
	}
	env, _ := decoded["env"].(map[string]any)
	if env == nil || env["Variables"] != "[redacted by authsec]" {
		t.Errorf("the redaction marker should replace the value, keeping the shape: %v", decoded)
	}
}

func TestAnUnchangedRereadWritesNoNewEvidence(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-observation-dedupe")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	run, err := runs.Claim("worker-a", time.Minute, time.Now())
	if err != nil || run == nil {
		t.Fatalf("claim: %v %v", run, err)
	}

	// An identity to hang the evidence on.
	identityID := uuid.New()
	if err := db.Exec(`
		INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name)
		VALUES (?, ?, ?, 'iam_role', ?, 'SharedToolRole')`,
		identityID, ws, conn, "arn:aws:iam::491056652413:role/SharedToolRole-"+identityID.String()[:8],
	).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	w := services.NewObservationWriter(db, ws, conn, run.ID, run.Generation)
	facts := map[string]any{"kind": "iam_role", "name": "SharedToolRole"}

	for i := 0; i < 3; i++ {
		if err := w.Record(services.IdentitySubject(identityID), "iam:GetRole",
			models.SurfaceIAMRoles, models.CloudCoverageReached, time.Now(), facts); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	var count int64
	db.Raw(`SELECT count(*) FROM cloud_observation WHERE workspace_id = ? AND identity_id = ?`,
		ws, identityID).Scan(&count)
	if count != 1 {
		t.Fatalf("three identical reads produced %d observations, want 1", count)
	}
	written, skipped := w.Counts()
	if written != 1 || skipped != 2 {
		t.Errorf("counts = %d written / %d skipped, want 1/2", written, skipped)
	}
}

func TestChangedFactsProduceNewEvidence(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-observation-change")
	conn := connectorFor(t, db, ws)
	runs := scanRuns(t, db)

	if _, err := runs.Enqueue(ws, conn, "manual"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	run, _ := runs.Claim("worker-a", time.Minute, time.Now())

	identityID := uuid.New()
	if err := db.Exec(`
		INSERT INTO cloud_identity (id, workspace_id, connector_id, kind, native_id, name)
		VALUES (?, ?, ?, 'iam_role', ?, 'R')`,
		identityID, ws, conn, "arn:aws:iam::491056652413:role/R-"+identityID.String()[:8],
	).Error; err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	w := services.NewObservationWriter(db, ws, conn, run.ID, run.Generation)
	_ = w.Record(services.IdentitySubject(identityID), "iam:GetRole",
		models.SurfaceIAMRoles, models.CloudCoverageReached, time.Now(),
		map[string]any{"permissions_boundary_arn": ""})
	// The customer attaches a boundary. That is a different fact and must be
	// recorded, not absorbed as a duplicate.
	_ = w.Record(services.IdentitySubject(identityID), "iam:GetRole",
		models.SurfaceIAMRoles, models.CloudCoverageReached, time.Now(),
		map[string]any{"permissions_boundary_arn": "arn:aws:iam::491056652413:policy/B01"})

	var count int64
	db.Raw(`SELECT count(*) FROM cloud_observation WHERE workspace_id = ? AND identity_id = ?`,
		ws, identityID).Scan(&count)
	if count != 2 {
		t.Fatalf("a changed fact produced %d observations, want 2", count)
	}
}

func TestEvidenceWithoutARunIsNotWritten(t *testing.T) {
	db := igaDB(t)
	// No durable run to anchor to. The writer is nil and every call is a no-op,
	// so a caller with no run degrades to writing no evidence rather than
	// panicking or, worse, writing evidence nothing can explain.
	w := services.NewObservationWriter(db, uuid.New(), uuid.New(), uuid.Nil, 0)
	if w != nil {
		t.Fatal("a writer with no run should be nil")
	}
	if err := w.Record(services.IdentitySubject(uuid.New()), "iam:GetRole", "", "", time.Now(), nil); err != nil {
		t.Fatalf("a nil writer must be safe to call: %v", err)
	}
}
