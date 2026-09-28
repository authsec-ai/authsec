package services

import (
	"encoding/json"
	"testing"

	"github.com/authsec-ai/authsec/pkg/collectorcontract"
)

// Flag-off sync uses this struct with Desired set to JSON null. The bytes are
// the pre-delivery receipt. Adding a field here changes every agent receipt.
func TestFlagOffSyncDesiredNull(t *testing.T) {
	resp := collectorcontract.SyncResponse{
		ReceiptID:              "30000000-0000-4000-8000-000000000007",
		AcceptedSequence:       1,
		ReceiptState:           "accepted",
		ProjectionState:        "queued",
		PublishedGraphRevision: 0,
		MappingURL:             "/api/iga/v2/receipts/30000000-0000-4000-8000-000000000007",
		Desired:                json.RawMessage("null"),
		NextSyncSeconds:        15,
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"receipt_id":"30000000-0000-4000-8000-000000000007","accepted_sequence":1,"receipt_state":"accepted","projection_state":"queued","published_graph_revision":0,"mapping_url":"/api/iga/v2/receipts/30000000-0000-4000-8000-000000000007","desired":null,"next_sync_seconds":15}`
	if string(raw) != want {
		t.Fatalf("flag-off receipt bytes changed:\n got %s", raw)
	}
}
