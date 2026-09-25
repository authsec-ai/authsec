package services

import (
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
)

// D-29: the request hash binds an operation to its request. It must be the
// same for a byte-identical retry (or a replay would be refused as
// operation_id_reused) and differ when ANY bound field differs (or a reused id
// would replay someone else's decision).
func TestP2ClassRequestHash(t *testing.T) {
	undo := uuid.New()
	base := ClassifyRequest{
		WorkloadID: uuid.New(), ActorUserID: uuid.New(), OperationID: uuid.New(),
		Decision: models.ClassificationClassified, Purpose: "Customer support triage",
		Reason: "Owns tier-1 ticket routing", ExpectedVersion: 3,
	}
	h := ClassificationRequestHash(base)
	if len(h) != 64 {
		t.Fatalf("hash %q is not hex SHA-256", h)
	}
	if ClassificationRequestHash(base) != h {
		t.Fatal("the hash is not deterministic")
	}

	// The operation id itself is NOT content: the lookup is by it.
	sameIntent := base
	sameIntent.OperationID = uuid.New()
	if ClassificationRequestHash(sameIntent) != h {
		t.Fatal("the hash covers operation_id, which is the lookup key, not the request")
	}
	// Surrounding whitespace is not content (strings trimmed).
	padded := base
	padded.Purpose, padded.Reason = "  "+base.Purpose, base.Reason+"\n"
	if ClassificationRequestHash(padded) != h {
		t.Fatal("the hash depends on surrounding whitespace")
	}

	for name, edit := range map[string]func(r *ClassifyRequest){
		"workload":         func(r *ClassifyRequest) { r.WorkloadID = uuid.New() },
		"actor":            func(r *ClassifyRequest) { r.ActorUserID = uuid.New() },
		"decision":         func(r *ClassifyRequest) { r.Decision = models.ClassificationUnclassified },
		"purpose":          func(r *ClassifyRequest) { r.Purpose = "Refunds" },
		"no purpose":       func(r *ClassifyRequest) { r.Purpose = "" },
		"reason":           func(r *ClassifyRequest) { r.Reason = "owns refunds" },
		"expected_version": func(r *ClassifyRequest) { r.ExpectedVersion = 4 },
		"undoes":           func(r *ClassifyRequest) { r.UndoesDecisionID = &undo },
		// Field boundaries are unambiguous: text moved between purpose and
		// reason is a different request.
		"moved text": func(r *ClassifyRequest) {
			r.Purpose, r.Reason = base.Purpose+base.Reason[:4], base.Reason[4:]
		},
	} {
		r := base
		edit(&r)
		if ClassificationRequestHash(r) == h {
			t.Errorf("changing the %s does not change the hash", name)
		}
	}
}
