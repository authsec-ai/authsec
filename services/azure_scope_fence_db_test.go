package services

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	repositories "github.com/authsec-ai/authsec/repository"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Database-backed checks of three fixes from review:
//
//   - an Azure pass whose lease expired cannot overwrite rows a newer pass
//     wrote (the upserts are fenced by generation);
//   - an AWS route does not act on an Azure connector (not found);
//   - reconnecting a tenant takes the subscriptions not selected out of scope.
//
// They run against TEST_DATABASE_URL, a throwaway database rebuilt from
// 001_bootstrap.sql (requireThrowawayDatabase refuses any other).

func setupAzureScopeTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Azure database tests")
	}
	requireThrowawayDatabase(t, dsn)

	raw, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	for _, stmt := range []string{"DROP SCHEMA IF EXISTS public CASCADE", "CREATE SCHEMA public"} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("reset schema (%q): %v", stmt, err)
		}
	}
	p, err := filepath.Abs(filepath.Join("..", "migrations", "master", "001_bootstrap.sql"))
	if err != nil {
		t.Fatalf("resolve bootstrap: %v", err)
	}
	body, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read bootstrap: %v", err)
	}
	if _, err := raw.Exec(string(body)); err != nil {
		t.Fatalf("apply bootstrap: %v", err)
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("gorm open: %v", err)
	}
	return db
}

func azureTestConnector(t *testing.T, db *gorm.DB, ws uuid.UUID, kind, scopeID string, parent *string, authRef string) *models.CloudConnector {
	t.Helper()
	if err := db.Exec(`INSERT INTO workspaces (id, name) VALUES (?, ?) ON CONFLICT (id) DO NOTHING`, ws, "test "+ws.String()[:8]).Error; err != nil {
		t.Fatalf("workspace: %v", err)
	}
	c := &models.CloudConnector{
		WorkspaceID: ws, Provider: models.CloudProviderAzure, ScopeKind: kind, ScopeID: scopeID,
		ParentScopeID: parent, AuthRef: authRef, Status: models.CloudConnectorActive, CreatedBy: "test",
		Attrs: []byte(`{}`),
	}
	stored, _, err := repositories.NewCloudConnectorRepository(db).Upsert(c)
	if err != nil {
		t.Fatalf("connector %s: %v", scopeID, err)
	}
	return stored
}

func TestAzureUpsertIsFencedByGeneration(t *testing.T) {
	db := setupAzureScopeTestDB(t)
	ws := uuid.New()
	tenant := azureTestConnector(t, db, ws, models.CloudScopeTenant, "11111111-1111-1111-1111-111111111111", nil, "azure-app:test")
	repo := repositories.NewCloudAzureRepository(db)

	write := func(gen int, name string) {
		t.Helper()
		row := models.CloudIdentity{NativeID: "object-1", Kind: models.CloudIdentityEntraUser, Name: name}
		if _, err := repo.UpsertIdentities(ws, tenant.ID, gen, []models.CloudIdentity{row}); err != nil {
			t.Fatalf("upsert gen %d: %v", gen, err)
		}
	}
	read := func() (string, int) {
		var got models.CloudIdentity
		if err := db.Where("workspace_id = ? AND native_id = ?", ws, "object-1").First(&got).Error; err != nil {
			t.Fatalf("read: %v", err)
		}
		return got.Name, got.LastSeenGeneration
	}

	write(2, "newer pass")
	write(1, "expired older pass")
	if name, gen := read(); name != "newer pass" || gen != 2 {
		t.Fatalf("an expired pass overwrote a newer one: %q gen %d", name, gen)
	}
	write(3, "next pass")
	if name, gen := read(); name != "next pass" || gen != 3 {
		t.Fatalf("a newer pass was refused: %q gen %d", name, gen)
	}
}

func TestAWSRoutesDoNotActOnAzureConnectors(t *testing.T) {
	db := setupAzureScopeTestDB(t)
	ws := uuid.New()
	tenant := azureTestConnector(t, db, ws, models.CloudScopeTenant, "22222222-2222-2222-2222-222222222222", nil, "azure-app:test")
	svc := &AWSOnboardingService{repo: repositories.NewCloudConnectorRepository(db)}

	if _, err := svc.Connector(ws, tenant.ID); !errors.Is(err, repositories.ErrCloudConnectorNotFound) {
		t.Fatalf("AWS Connector on an Azure connector = %v, want not found", err)
	}
	if _, err := svc.ForRun(ws, tenant.ID); !errors.Is(err, repositories.ErrCloudConnectorNotFound) {
		t.Fatalf("AWS ForRun on an Azure connector = %v, want not found", err)
	}
	if err := svc.RevokeConnector(ws, tenant.ID); !errors.Is(err, repositories.ErrCloudConnectorNotFound) {
		t.Fatalf("AWS revoke on an Azure connector = %v, want not found", err)
	}
	var stored models.CloudConnector
	if err := db.First(&stored, "id = ?", tenant.ID).Error; err != nil || stored.Status != models.CloudConnectorActive {
		t.Fatalf("the Azure connector was changed through an AWS route: %v %s", err, stored.Status)
	}
}

func TestReconnectRevokesUnselectedSubscriptions(t *testing.T) {
	db := setupAzureScopeTestDB(t)
	ws := uuid.New()
	tid := "33333333-3333-3333-3333-333333333333"
	azureTestConnector(t, db, ws, models.CloudScopeTenant, tid, nil, "azure-app:authsec")
	parent := tid
	kept := azureTestConnector(t, db, ws, models.CloudScopeSubscription, "aaaaaaaa-0000-0000-0000-000000000001", &parent, "azure-app:authsec")
	dropped := azureTestConnector(t, db, ws, models.CloudScopeSubscription, "aaaaaaaa-0000-0000-0000-000000000002", &parent, "azure-app:authsec")
	other := azureTestConnector(t, db, uuid.New(), models.CloudScopeSubscription, "aaaaaaaa-0000-0000-0000-000000000003", &parent, "azure-app:authsec")

	s := &AzureOnboardingService{db: db, connectors: repositories.NewCloudConnectorRepository(db)}
	n := s.revokeUnselectedSubscriptions(ws, tid, map[string]bool{kept.ScopeID: true})
	if n != 1 {
		t.Fatalf("revoked %d, want 1 (only the unselected subscription of this workspace)", n)
	}
	status := func(id uuid.UUID) string {
		var c models.CloudConnector
		if err := db.First(&c, "id = ?", id).Error; err != nil {
			t.Fatalf("read connector: %v", err)
		}
		return c.Status
	}
	if status(kept.ID) != models.CloudConnectorActive {
		t.Fatal("the selected subscription was taken out of scope")
	}
	if status(dropped.ID) != models.CloudConnectorRevoked {
		t.Fatal("the unselected subscription stayed in scope: a later scan would read it")
	}
	if status(other.ID) != models.CloudConnectorActive {
		t.Fatal("another workspace's subscription was touched")
	}
	// Selected again on a later connect, it is back in scope.
	again := azureTestConnector(t, db, ws, models.CloudScopeSubscription, dropped.ScopeID, &parent, "azure-app:authsec")
	if again.ID != dropped.ID || status(dropped.ID) != models.CloudConnectorActive {
		t.Fatal("a subscription selected again did not return to scope")
	}
}
