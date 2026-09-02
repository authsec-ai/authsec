package gcp

import (
	"testing"

	"github.com/google/uuid"
)

// TestDeriveWIFParams_Deterministic proves DeriveWIFParams is a pure function:
// the SAME (workspace_id, scope_id) always produces the SAME three outputs,
// across repeated calls, with no randomness or I/O involved. This is
// load-bearing for GCP-D9's design — the console's onboarding-package
// renderer and the connector-create cross-check must independently compute
// the identical strings from the same inputs, or a customer's correctly
// pasted provider_resource fails validation for no reason support could
// explain.
func TestDeriveWIFParams_Deterministic(t *testing.T) {
	ws := uuid.New()
	const scopeID = "my-gcp-project"

	poolID1, providerID1, subject1 := DeriveWIFParams(ws, scopeID)
	poolID2, providerID2, subject2 := DeriveWIFParams(ws, scopeID)

	if poolID1 != poolID2 {
		t.Errorf("poolID not deterministic: %q vs %q", poolID1, poolID2)
	}
	if providerID1 != providerID2 {
		t.Errorf("providerID not deterministic: %q vs %q", providerID1, providerID2)
	}
	if subject1 != subject2 {
		t.Errorf("subject not deterministic: %q vs %q", subject1, subject2)
	}
}

// TestDeriveWIFParams_ProviderIDIsFixed proves provider_id is the fixed
// string GCP-D9's design specifies, not derived — there is exactly one
// provider per pool, so there is nothing to disambiguate.
func TestDeriveWIFParams_ProviderIDIsFixed(t *testing.T) {
	_, providerID, _ := DeriveWIFParams(uuid.New(), "any-scope")
	if providerID != "authsec-provider" {
		t.Errorf("providerID = %q, want the fixed \"authsec-provider\"", providerID)
	}
}

// TestDeriveWIFParams_DiffersByInput proves the derivation actually depends
// on both inputs — a pure function that ignored its arguments would also be
// "deterministic" by the test above, so this is the test that actually rules
// that out.
func TestDeriveWIFParams_DiffersByInput(t *testing.T) {
	wsA, wsB := uuid.New(), uuid.New()

	poolA, _, subjA := DeriveWIFParams(wsA, "scope-1")
	poolB, _, subjB := DeriveWIFParams(wsB, "scope-1")
	if poolA == poolB {
		t.Error("pool id must differ across workspaces for the same scope_id")
	}
	if subjA == subjB {
		t.Error("wif_subject must differ across workspaces for the same scope_id")
	}

	poolC, _, subjC := DeriveWIFParams(wsA, "scope-2")
	if poolA == poolC {
		t.Error("pool id must differ across scope_ids for the same workspace")
	}
	if subjA == subjC {
		t.Error("wif_subject must differ across scope_ids for the same workspace")
	}
}

// TestDeriveWIFParams_Shape proves the pool id and subject carry the exact
// prefixes prompt.md's GCP-D9 design specifies, since GCP-04's setup-reader.sh
// renderer and the customer-facing console both bake these directly into a
// gcloud command and an IAM principal string.
func TestDeriveWIFParams_Shape(t *testing.T) {
	poolID, _, subject := DeriveWIFParams(uuid.New(), "some-scope-id")

	const poolPrefix = "authsec-"
	if len(poolID) <= len(poolPrefix) || poolID[:len(poolPrefix)] != poolPrefix {
		t.Errorf("poolID = %q, want it to start with %q", poolID, poolPrefix)
	}
	// "authsec-" + 16 hex chars.
	if got, want := len(poolID), len(poolPrefix)+16; got != want {
		t.Errorf("len(poolID) = %d, want %d", got, want)
	}

	const subjectPrefix = "authsec:"
	if len(subject) <= len(subjectPrefix) || subject[:len(subjectPrefix)] != subjectPrefix {
		t.Errorf("subject = %q, want it to start with %q", subject, subjectPrefix)
	}
	if got, want := len(subject), len(subjectPrefix)+32; got != want {
		t.Errorf("len(subject) = %d, want %d", got, want)
	}
}
