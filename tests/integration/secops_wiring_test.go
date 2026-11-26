package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/services"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// A case pins its evidence in the evidence store (W3 -> W1): only the case's
// own workspace's rows move, and unpinning never goes below zero.
func TestSecOpsCaseEvidencePinsStayInTheWorkspace(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "wiring-pin-a")
	b := p3NewGov(t, db, "wiring-pin-b")
	hash := strings.Repeat("ab", 32)
	for _, ws := range []uuid.UUID{a.ws, b.ws} {
		p3exec(t, db, `INSERT INTO agent_evidence_event (workspace_id, provider, source, event_id, event_time, raw_hash)
			VALUES (?, 'aws', 'cloudtrail_poll', 'evt-pin-1', now(), ?)`, ws, hash)
	}
	pins := services.SecOpsCaseEvidencePinner()
	refs := []services.AgentCaseEvidenceRef{{Source: "cloudtrail", EventID: "evt-pin-1"}}
	pin := func(delta int) {
		err := tenancy.InWorkspace(context.Background(), db, a.ws, func(tx *gorm.DB) error {
			if delta > 0 {
				return pins.Pin(tx, a.ws, uuid.New(), refs)
			}
			return pins.Unpin(tx, a.ws, uuid.New(), refs)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	count := func(ws uuid.UUID) int {
		var n int
		db.Raw(`SELECT pin_count FROM agent_evidence_event WHERE workspace_id = ? AND event_id = 'evt-pin-1'`, ws).Scan(&n)
		return n
	}
	pin(1)
	if count(a.ws) != 1 || count(b.ws) != 0 {
		t.Fatalf("pin: A %d, B %d", count(a.ws), count(b.ws))
	}
	pin(-1)
	pin(-1)
	if count(a.ws) != 0 || count(b.ws) != 0 {
		t.Fatalf("unpin floors at zero: A %d, B %d", count(a.ws), count(b.ws))
	}
}
