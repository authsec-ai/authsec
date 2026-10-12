package igagovschema_test

// The thin Phase 3 repositories (settings, ownership, finding rules, events)
// against real Postgres, inside one transaction that is rolled back.

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

func TestPhase3ThinRepositories(t *testing.T) {
	_, g := testDB(t)
	tx := g.Begin()
	defer tx.Rollback()

	ws, other, user, wl, ia, pol := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO workspaces (id, name, workspace_type) VALUES (?, 'repo one', 'team'), (?, 'repo two', 'team')`, []any{ws, other}},
		{`INSERT INTO users (id, email, workspace_id) VALUES (?, 'repo@p3repo.test', ?)`, []any{user, ws}},
		{`INSERT INTO iga_workload (id, workspace_id, runtime_kind, source_key) VALUES (?, ?, 'ecs_task', 'aws:ecs:task-definition/x:1')`, []any{wl, ws}},
		{`INSERT INTO iga_identity_accounts (id, workspace_id, account_kind, provider, source_key) VALUES (?, ?, 'role', 'aws', 'aws:iam:role:1:x')`, []any{ia, ws}},
		{`INSERT INTO iga_gov_policy (id, workspace_id, name, family, provider, created_by) VALUES (?, ?, 'p', 'governance', 'aws', ?)`, []any{pol, ws, user}},
	} {
		if err := tx.Exec(q.sql, q.args...).Error; err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}

	t.Run("settings", func(t *testing.T) {
		repo := repositories.NewIGAGovSettingsRepository(tx)
		got, err := repo.Get(ws)
		if err != nil {
			t.Fatal(err)
		}
		// The Go defaults are 055's column defaults.
		if err := tx.Exec(`INSERT INTO iga_gov_settings (workspace_id) VALUES (?)`, other).Error; err != nil {
			t.Fatal(err)
		}
		dbDefaults, err := repo.Get(other)
		if err != nil {
			t.Fatal(err)
		}
		want := models.DefaultIGAGovSettings(other)
		want.UpdatedAt = dbDefaults.UpdatedAt
		if *dbDefaults != want {
			t.Fatalf("database defaults %+v differ from DefaultIGAGovSettings %+v", *dbDefaults, want)
		}
		if got.EnforcementMode != models.GovModeFindingsOnly || got.DefaultWindowDays != 90 {
			t.Fatalf("absent settings = %+v, want the defaults", got)
		}
		got.EnforcementMode, got.CanaryHours, got.UpdatedBy = models.GovModeEnforce, 72, &user
		if err := repo.SaveTx(tx, got); err != nil {
			t.Fatal(err)
		}
		got.CanaryHours = 24
		if err := repo.SaveTx(tx, got); err != nil {
			t.Fatal(err)
		}
		again, _ := repo.Get(ws)
		if again.EnforcementMode != models.GovModeEnforce || again.CanaryHours != 24 {
			t.Fatalf("saved settings = %+v", again)
		}
		bad := *again
		bad.CanaryHours = 1000
		if err := repo.SaveTx(tx.SavePoint("bad"), &bad); err == nil {
			t.Fatal("canary_hours 1000 was accepted; the CHECK must refuse it")
		}
		tx.RollbackTo("bad")
	})

	t.Run("ownership", func(t *testing.T) {
		repo := repositories.NewIGAGovOwnershipRepository(tx)
		rule := &models.IGAGovOwnerRule{WorkspaceID: ws, TagKey: "owner", AppliesTo: "both", Role: models.GovOwnerAccountable, Enabled: true, CreatedBy: user}
		if err := repo.CreateRule(rule); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetRuleEnabled(ws, rule.ID, false); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetRuleEnabled(other, rule.ID, true); !errors.Is(err, repositories.ErrIGAGovNotFound) {
			t.Fatalf("another workspace's rule: %v, want ErrIGAGovNotFound", err)
		}
		rules, _ := repo.ListRules(ws)
		if len(rules) != 1 || rules[0].Enabled {
			t.Fatalf("rules = %+v", rules)
		}
		byRule := &models.IGAGovOwner{WorkspaceID: ws, ObjectKind: models.GovObjectWorkload, WorkloadID: &wl, UserID: user,
			Role: models.GovOwnerAccountable, Source: models.GovOwnerSourceTagRule, RuleID: &rule.ID}
		manual := &models.IGAGovOwner{WorkspaceID: ws, ObjectKind: models.GovObjectIdentityAccount, IdentityAccountID: &ia, UserID: user,
			Role: models.GovOwnerTechnical, Source: models.GovOwnerSourceManual, CreatedBy: &user}
		for _, o := range []*models.IGAGovOwner{byRule, manual} {
			if err := repo.AddOwner(o); err != nil {
				t.Fatal(err)
			}
		}
		due := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)
		if err := repo.SetReviewDue(ws, manual.ID, &due); err != nil {
			t.Fatal(err)
		}
		owners, _ := repo.ListOwners(ws, models.GovObjectIdentityAccount, ia)
		if len(owners) != 1 || owners[0].ReviewDueAt == nil || !owners[0].ReviewDueAt.Equal(due) {
			t.Fatalf("identity owners = %+v", owners)
		}
		if err := repo.DeleteRule(ws, rule.ID); err != nil {
			t.Fatal(err)
		}
		if left, _ := repo.ListOwners(ws, models.GovObjectWorkload, wl); len(left) != 0 {
			t.Fatalf("deleting a rule must remove the owners it assigned; %d left", len(left))
		}
		if err := repo.RemoveOwner(ws, manual.ID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("finding rules", func(t *testing.T) {
		repo := repositories.NewIGAGovFindingRuleRepository(tx)
		r := &models.IGAGovFindingRule{WorkspaceID: ws, Kind: "require_review_date", Params: json.RawMessage(`{"days":90}`), Enabled: true, CreatedBy: user}
		if err := repo.Create(r); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetEnabled(ws, r.ID, false); err != nil {
			t.Fatal(err)
		}
		list, _ := repo.List(ws)
		if len(list) != 1 || list[0].Enabled || string(list[0].Scope) != "{}" {
			t.Fatalf("finding rules = %+v", list)
		}
	})

	t.Run("events", func(t *testing.T) {
		repo := repositories.NewIGAGovEventRepository(tx)
		a := &models.IGAGovEvent{WorkspaceID: ws, Event: "policy.created", ActorKind: models.GovActorUser, ActorID: user.String(), PolicyID: &pol}
		b := &models.IGAGovEvent{WorkspaceID: ws, Event: "settings.changed", ActorKind: models.GovActorUser, ActorID: user.String(),
			Payload: json.RawMessage(`{"enforcement_mode":"enforce"}`)}
		for _, e := range []*models.IGAGovEvent{a, b} {
			if err := repo.AppendTx(tx, e); err != nil {
				t.Fatal(err)
			}
		}
		if a.ID == 0 || b.ID <= a.ID {
			t.Fatalf("identity ids not returned: %d, %d", a.ID, b.ID)
		}
		if err := repo.AppendTx(tx, a); err == nil {
			t.Fatal("re-appending an event with an id was accepted")
		}
		all, _ := repo.List(ws, 0, 10)
		after, _ := repo.List(ws, a.ID, 10)
		byPol, _ := repo.ListByPolicy(ws, pol, 0, 10)
		if len(all) != 2 || len(after) != 1 || len(byPol) != 1 || string(all[0].Payload) != "{}" {
			t.Fatalf("events: all=%d after=%d byPolicy=%d payload=%s", len(all), len(after), len(byPol), all[0].Payload)
		}
		if err := tx.SavePoint("upd").Exec(`UPDATE iga_gov_event SET event = 'x' WHERE id = ?`, a.ID).Error; err == nil {
			t.Fatal("an event was updated")
		}
		tx.RollbackTo("upd")
	})
}
