package integration

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
	"github.com/authsec-ai/authsec/services"
)

// AS-108: a job runs under row-level security for its own workspace. A job
// of workspace B reads none of A's rows through ReadTx and changes none
// through InTx, though its SQL names A explicitly; the scheduler enqueues
// each due item in its own workspace.
func TestP3PolicyJobTenancy(t *testing.T) {
	db := igaDB(t)
	a := p3NewGov(t, db, "p3-jobs-ten-a")
	b := p3NewGov(t, db, "p3-jobs-ten-b")
	repo := repositories.NewIGAGovJobRepository(db)
	ja := &models.IGAGovJob{WorkspaceID: a.ws, Kind: repositories.GovJobDriftCheck, DedupeKey: "ten:a", RunAfter: time.Now().Add(time.Hour)}
	if _, err := repo.EnqueueTx(db, ja); err != nil {
		t.Fatal(err)
	}
	jb := &models.IGAGovJob{WorkspaceID: b.ws, Kind: repositories.GovJobMetricsRollup, DedupeKey: "ten:b", RunAfter: time.Now().Add(-time.Hour)}
	if _, err := repo.EnqueueTx(db, jb); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM iga_gov_job WHERE id IN (?, ?)`, ja.ID, jb.ID) })
	c := p3ClaimOwn(t, db, b.ws, "ten-worker", 2*time.Minute, time.Now(), repositories.GovJobMetricsRollup)
	if c == nil || c.ID != jb.ID {
		t.Fatalf("claim: %+v", c)
	}
	run := services.NewPolicyJobRun(db, *c, "ten-worker")
	ctx := context.Background()

	var seen int64
	if err := run.ReadTx(ctx, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT count(*) FROM iga_gov_job WHERE workspace_id = ?`, a.ws).Scan(&seen).Error
	}); err != nil || seen != 0 {
		t.Fatalf("B's job read A's jobs: %d %v", seen, err)
	}
	var changed int64
	if err := run.InTx(ctx, func(tx *gorm.DB) error {
		res := tx.Exec(`UPDATE iga_gov_job SET last_error = 'touched by B' WHERE id = ?`, ja.ID)
		changed = res.RowsAffected
		return res.Error
	}); err != nil || changed != 0 {
		t.Fatalf("B's job changed A's job: %d %v", changed, err)
	}
	if n := p3sCount(t, db, `SELECT count(*) FROM iga_gov_job WHERE id = ? AND last_error = ''`, ja.ID); n != 1 {
		t.Fatal("A's job was changed")
	}
	// B's job still reads its own rows.
	if err := run.ReadTx(ctx, func(tx *gorm.DB) error {
		return tx.Raw(`SELECT count(*) FROM iga_gov_job WHERE id = ?`, jb.ID).Scan(&seen).Error
	}); err != nil || seen != 1 {
		t.Fatalf("B's job reading itself: %d %v", seen, err)
	}
}
