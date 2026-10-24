package integration

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// An Azure agent has no discovery source, so the Sightings tenant filter runs
// on its metadata's tenant_id, on the server: the page and the total count
// only that tenant (before, the console filtered one page of every tenant).
func TestListAgentsByTenant(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-sightings-tenant")
	tA, tB := uuid.NewString(), uuid.NewString()
	for i, tenant := range []string{tA, tA, tA, tB} {
		if err := db.Exec(`INSERT INTO discovered_agents (workspace_id, source, fingerprint, display_name, metadata, status, runtime_status)
			VALUES (?, ?, ?, ?, jsonb_build_object('tenant_id', ?::text), 'unregistered', 'running')`,
			ws, models.DiscoverySourceAzure, "fp-"+uuid.NewString(), "agent", tenant).Error; err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	repo := repositories.NewDiscoveryRepository(db)
	rows, total, err := repo.ListAgents(ws, repositories.AgentFilter{TenantID: tA, Limit: 2})
	if err != nil || total != 3 || len(rows) != 2 {
		t.Fatalf("tenant A: %d rows, total %d, %v", len(rows), total, err)
	}
	// Case-insensitive, as tenant ids are stored lower case.
	if _, total, _ := repo.ListAgents(ws, repositories.AgentFilter{TenantID: strings.ToUpper(tB)}); total != 1 {
		t.Fatalf("tenant B: total %d", total)
	}
}
