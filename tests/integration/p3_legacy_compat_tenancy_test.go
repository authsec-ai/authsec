package integration

import (
	"context"
	"errors"
	"testing"

	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	"github.com/authsec-ai/authsec/services"
)

// AS-108: the legacy agent-policy compatibility service runs every call in a
// transaction under row-level security for the caller's workspace. Workspace
// B neither sees, pauses nor removes workspace A's legacy policy (404, i.e.
// gorm.ErrRecordNotFound), and A's policy is unchanged; A still can.
func TestP3LegacyCompatTenancy(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "p3-legacy-ten-a")
	b := p3NewGov(t, db, "p3-legacy-ten-b")
	p, err := services.NewAgentPolicyManager(db).Create(a.ws, a.author.String(), services.AgentPolicyInput{Name: "ten namespace",
		Selector: &models.AgentPolicySelector{Namespace: "p3-legacy-ten"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM agent_policies WHERE id = ?`, p.ID) })
	ctx := context.Background()
	svc := services.NewLegacyAgentPolicyCompat(db)

	if has, err := svc.HasPolicies(ctx, b.ws); err != nil || has {
		t.Fatalf("B has policies: %v %v", has, err)
	}
	if rows, _, err := svc.Page(ctx, b.ws, nil, 50); err != nil || len(rows) != 0 {
		t.Fatalf("B's page: %v %v", rows, err)
	}
	if _, err := svc.View(ctx, b.ws, p.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("B views A's policy: %v", err)
	}
	if _, _, err := svc.Pause(ctx, b.ws, p.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("B pauses A's policy: %v", err)
	}
	if _, err := svc.Remove(ctx, b.ws, p.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("B removes A's policy: %v", err)
	}
	if n := p3sCount(t, db, `SELECT count(*) FROM agent_policies WHERE id = ? AND workspace_id = ? AND enabled`, p.ID, a.ws); n != 1 {
		t.Fatal("A's policy changed under B's calls")
	}

	if has, err := svc.HasPolicies(ctx, a.ws); err != nil || !has {
		t.Fatalf("A has policies: %v %v", has, err)
	}
	before, after, err := svc.Pause(ctx, a.ws, p.ID)
	if err != nil || !before.Enabled || after.Enabled {
		t.Fatalf("A pauses its policy: %+v %+v %v", before, after, err)
	}
	if _, err := svc.Remove(ctx, a.ws, p.ID); err != nil {
		t.Fatalf("A removes its policy: %v", err)
	}
}
