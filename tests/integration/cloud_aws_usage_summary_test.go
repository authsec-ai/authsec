package integration

// UsageSummary -- the per-identity activity aggregate behind the identities
// inventory's "With unused access" column.
//
// It exists because the inventory's question is an aggregate, and the browser
// used to answer it by walking every usage row: a paged read that stopped at a
// 2,000-row cap against an account holding ~9,500, so every total it showed was
// a floor and a permanent "service activity is partial" warning sat above the
// table. These tests pin the two things that make the aggregate trustworthy --
// exact counts, and tenant/connector scoping -- plus the distinction between
// "nothing reported" and "all used" that the column renders differently.

import (
	"context"
	"testing"
	"time"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func cleanUsage(t *testing.T, db *gorm.DB, ws uuid.UUID) {
	t.Helper()
	db.Exec(`DELETE FROM cloud_usage WHERE workspace_id = ?`, ws)
	db.Exec(`DELETE FROM cloud_identity WHERE workspace_id = ?`, ws)
	db.Exec(`DELETE FROM cloud_connector WHERE workspace_id = ?`, ws)
}

// seedUsageIdentity creates one identity and `used` + `never` usage rows for
// it, returning its id. The services are named apart per identity so the
// (identity, service) grain is never accidentally collided.
func seedUsageIdentity(t *testing.T, db *gorm.DB, ws, conn uuid.UUID, name string, used, never int) uuid.UUID {
	t.Helper()
	id := models.CloudIdentity{
		WorkspaceID: ws,
		ConnectorID: conn,
		Kind:        "iam_role",
		NativeID:    "arn:aws:iam::429418377036:role/" + name,
		Name:        name,
		Attrs:       []byte("{}"),
	}
	if err := db.Create(&id).Error; err != nil {
		t.Fatalf("seed identity %s: %v", name, err)
	}
	when := time.Now().UTC().Add(-24 * time.Hour)
	for i := 0; i < used+never; i++ {
		u := models.CloudUsage{
			WorkspaceID: ws,
			ConnectorID: conn,
			IdentityID:  id.ID,
			Service:     name + "-svc-" + string(rune('a'+i)),
			Attrs:       []byte("{}"),
		}
		if i < used {
			u.LastUsedAt = &when
		}
		if err := db.Create(&u).Error; err != nil {
			t.Fatalf("seed usage for %s: %v", name, err)
		}
	}
	return id.ID
}

// The counts must be exact, per identity, and must not bleed between
// identities -- the bug the old client-side walk could not avoid.
func TestUsageSummaryCountsServicesAndNeverUsedPerIdentity(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-usage-summary")
	defer cleanUsage(t, db, ws)

	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}

	busy := seedUsageIdentity(t, db, ws, c.ID, "busy", 5, 2)
	idle := seedUsageIdentity(t, db, ws, c.ID, "idle", 0, 4)
	clean := seedUsageIdentity(t, db, ws, c.ID, "clean", 3, 0)
	// No usage rows at all: must be ABSENT, not zeroed. The column says "Not
	// reported" for this, which is a different claim from "all used".
	silent := seedUsageIdentity(t, db, ws, c.ID, "silent", 0, 0)

	rows, err := repositories.NewCloudWorkloadRepository(db).UsageSummary(ws, &c.ID)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	got := map[uuid.UUID]repositories.CloudUsageSummaryRow{}
	for _, r := range rows {
		got[r.IdentityID] = r
	}

	for _, tc := range []struct {
		name            string
		id              uuid.UUID
		services, never int64
	}{
		{"busy", busy, 7, 2},
		{"idle", idle, 4, 4},
		{"clean", clean, 3, 0},
	} {
		r, ok := got[tc.id]
		if !ok {
			t.Errorf("%s missing from the summary", tc.name)
			continue
		}
		if r.Services != tc.services || r.NeverUsed != tc.never {
			t.Errorf("%s = {services:%d never_used:%d}, want {services:%d never_used:%d}",
				tc.name, r.Services, r.NeverUsed, tc.services, tc.never)
		}
	}
	if _, ok := got[silent]; ok {
		t.Error("an identity with no usage rows must be absent, not reported with zeroes")
	}
	if len(rows) != 3 {
		t.Errorf("summary rows = %d, want 3 (the identity with no usage is omitted)", len(rows))
	}
	t.Log("PASS: exact per-identity totals, and no row for an identity nothing was reported for")
}

// The tenant predicate is the whole security boundary on this read.
func TestUsageSummaryIsWorkspaceScoped(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-usage-owner")
	other := newWorkspace(t, db, "ws-usage-other")
	defer cleanUsage(t, db, ws)
	defer cleanUsage(t, db, other)

	svc, _ := newOnboarding(db, okVerifier())
	c, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard: %v", err)
	}
	seedUsageIdentity(t, db, ws, c.ID, "owned", 2, 1)

	rows, err := repositories.NewCloudWorkloadRepository(db).UsageSummary(other, nil)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("another workspace's summary returned %d rows, want 0", len(rows))
	}
	t.Log("PASS: a workspace sees none of another's usage")
}

// A nil connector means the whole workspace; a set one narrows to that account.
// The inventory passes it whenever a single account is selected.
func TestUsageSummaryFiltersByConnector(t *testing.T) {
	db := igaDB(t)
	ws := newWorkspace(t, db, "ws-usage-conn")
	defer cleanUsage(t, db, ws)

	v := okVerifier()
	svc, _ := newOnboarding(db, v)
	a, _, err := svc.Onboard(context.Background(), ws, validInput(mustMint(t, ws)), "admin")
	if err != nil {
		t.Fatalf("onboard a: %v", err)
	}
	inB := validInput(mustMint(t, ws))
	inB.RoleARN = "arn:aws:iam::210987654321:role/authsec-reader"
	// STS must answer for B's own account: onboarding refuses a role whose
	// ARN names a different account than the one it resolved to.
	v.identity = &awsdiscovery.Identity{
		AccountID: "210987654321",
		ARN:       "arn:aws:sts::210987654321:assumed-role/authsec-reader/authsec-onboarding-b",
		UserID:    "AROAEXAMPLEB:authsec-onboarding-b",
	}
	b, _, err := svc.Onboard(context.Background(), ws, inB, "admin")
	if err != nil {
		t.Fatalf("onboard b: %v", err)
	}
	seedUsageIdentity(t, db, ws, a.ID, "in-a", 1, 1)
	seedUsageIdentity(t, db, ws, b.ID, "in-b", 2, 2)

	repo := repositories.NewCloudWorkloadRepository(db)
	all, err := repo.UsageSummary(ws, nil)
	if err != nil {
		t.Fatalf("summary all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("unfiltered summary = %d rows, want 2", len(all))
	}
	onlyB, err := repo.UsageSummary(ws, &b.ID)
	if err != nil {
		t.Fatalf("summary b: %v", err)
	}
	if len(onlyB) != 1 || onlyB[0].Services != 4 || onlyB[0].NeverUsed != 2 {
		t.Fatalf("connector-filtered summary = %+v, want one row {services:4 never_used:2}", onlyB)
	}
	t.Log("PASS: nil connector is the whole workspace, a set one narrows to that account")
}
