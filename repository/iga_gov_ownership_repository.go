package repositories

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/models"
)

// IGAGovOwnershipRepository reads and writes owners and owner tag rules
// (047, SPEC-iga-phase3-policy.md §2.9).
//
// Thin by design. The schema fixes every write rule used here: an owner
// belongs to exactly one workload or identity of the same workspace, a
// tag_rule owner names its rule (and goes when the rule is deleted), and one
// (object, user, role) appears once. What is NOT here is service semantics
// (T3.07): evaluating rules after a publication, resolving a role's owners
// as its own plus the accountable owners of every workload running as it,
// and raising missing_owner. T3.07 adds the set-shaped writes below
// (ReplaceManualOwners, SyncRuleOwners): build the repository on a
// transaction to make them atomic with their iga_gov_event.
type IGAGovOwnershipRepository interface {
	CreateRule(r *models.IGAGovOwnerRule) error
	ListRules(ws uuid.UUID) ([]models.IGAGovOwnerRule, error)
	SetRuleEnabled(ws, id uuid.UUID, enabled bool) error
	// DeleteRule deletes the rule and, by FK cascade, the owners it assigned.
	DeleteRule(ws, id uuid.UUID) error

	AddOwner(o *models.IGAGovOwner) error
	// ListOwners returns the owners recorded directly on one object.
	ListOwners(ws uuid.UUID, objectKind string, objectID uuid.UUID) ([]models.IGAGovOwner, error)
	SetReviewDue(ws, id uuid.UUID, due *time.Time) error
	RemoveOwner(ws, id uuid.UUID) error

	// GetRule and GetOwner return one row of this workspace, or
	// ErrIGAGovNotFound (another workspace's id is not found, never another
	// error, so ids do not leak existence).
	GetRule(ws, id uuid.UUID) (*models.IGAGovOwnerRule, error)
	GetOwner(ws, id uuid.UUID) (*models.IGAGovOwner, error)
	// ListOwnersFor returns the owners recorded directly on any of the given
	// workloads and identities. Nil slices select nothing of that kind.
	ListOwnersFor(ws uuid.UUID, workloadIDs, identityIDs []uuid.UUID) ([]models.IGAGovOwner, error)
	// ReplaceManualOwners makes the object's MANUAL owners exactly want
	// (user, role, review_due_at). Tag-rule owners are kept, except that one
	// with the same (user, role) as a wanted entry is taken over as manual
	// (rule_id cleared) -- DECISION: an explicit assignment outranks a rule,
	// and uq_iga_gov_owner allows one row per (object, user, role). It
	// returns the object's owners before and after.
	ReplaceManualOwners(ws uuid.UUID, objectKind string, objectID uuid.UUID, want []models.IGAGovOwner, actor uuid.UUID) (before, after []models.IGAGovOwner, err error)
	// SyncRuleOwners makes the workspace's tag_rule owners exactly desired
	// (each with ObjectKind, the object id, UserID, Role, RuleID): rows no
	// longer desired are deleted, missing ones inserted, and a desired owner
	// whose (object, user, role) already has a row (a manual one) is skipped.
	SyncRuleOwners(ws uuid.UUID, desired []models.IGAGovOwner) (added, removed int, err error)
}

type igaGovOwnershipRepository struct{ db *gorm.DB }

func NewIGAGovOwnershipRepository(db *gorm.DB) IGAGovOwnershipRepository {
	return &igaGovOwnershipRepository{db: db}
}

func (r *igaGovOwnershipRepository) CreateRule(rule *models.IGAGovOwnerRule) error {
	return r.db.Create(rule).Error
}

func (r *igaGovOwnershipRepository) ListRules(ws uuid.UUID) ([]models.IGAGovOwnerRule, error) {
	var out []models.IGAGovOwnerRule
	err := r.db.Where("workspace_id = ?", ws).Order("tag_key, applies_to, role").Find(&out).Error
	return out, err
}

func (r *igaGovOwnershipRepository) SetRuleEnabled(ws, id uuid.UUID, enabled bool) error {
	return affectedOne(r.db.Model(&models.IGAGovOwnerRule{}).
		Where("workspace_id = ? AND id = ?", ws, id).Update("enabled", enabled))
}

func (r *igaGovOwnershipRepository) DeleteRule(ws, id uuid.UUID) error {
	return affectedOne(r.db.Where("workspace_id = ? AND id = ?", ws, id).Delete(&models.IGAGovOwnerRule{}))
}

func (r *igaGovOwnershipRepository) AddOwner(o *models.IGAGovOwner) error {
	return r.db.Create(o).Error
}

func (r *igaGovOwnershipRepository) ListOwners(ws uuid.UUID, objectKind string, objectID uuid.UUID) ([]models.IGAGovOwner, error) {
	col := "workload_id"
	if objectKind == models.GovObjectIdentityAccount {
		col = "identity_account_id"
	}
	var out []models.IGAGovOwner
	err := r.db.Where("workspace_id = ? AND object_kind = ? AND "+col+" = ?", ws, objectKind, objectID).
		Order("role, created_at").Find(&out).Error
	return out, err
}

func (r *igaGovOwnershipRepository) SetReviewDue(ws, id uuid.UUID, due *time.Time) error {
	return affectedOne(r.db.Model(&models.IGAGovOwner{}).Where("workspace_id = ? AND id = ?", ws, id).
		Updates(map[string]any{"review_due_at": due, "updated_at": gorm.Expr("now()")}))
}

func (r *igaGovOwnershipRepository) RemoveOwner(ws, id uuid.UUID) error {
	return affectedOne(r.db.Where("workspace_id = ? AND id = ?", ws, id).Delete(&models.IGAGovOwner{}))
}

func (r *igaGovOwnershipRepository) GetRule(ws, id uuid.UUID) (*models.IGAGovOwnerRule, error) {
	var out []models.IGAGovOwnerRule
	if err := r.db.Where("workspace_id = ? AND id = ?", ws, id).Limit(1).Find(&out).Error; err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrIGAGovNotFound
	}
	return &out[0], nil
}

func (r *igaGovOwnershipRepository) GetOwner(ws, id uuid.UUID) (*models.IGAGovOwner, error) {
	var out []models.IGAGovOwner
	if err := r.db.Where("workspace_id = ? AND id = ?", ws, id).Limit(1).Find(&out).Error; err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrIGAGovNotFound
	}
	return &out[0], nil
}

func (r *igaGovOwnershipRepository) ListOwnersFor(ws uuid.UUID, workloadIDs, identityIDs []uuid.UUID) ([]models.IGAGovOwner, error) {
	var out []models.IGAGovOwner
	if len(workloadIDs) == 0 && len(identityIDs) == 0 {
		return out, nil
	}
	q := r.db.Where("workspace_id = ?", ws)
	switch {
	case len(workloadIDs) > 0 && len(identityIDs) > 0:
		q = q.Where("(object_kind = 'workload' AND workload_id IN ?) OR (object_kind = 'identity_account' AND identity_account_id IN ?)",
			workloadIDs, identityIDs)
	case len(workloadIDs) > 0:
		q = q.Where("object_kind = 'workload' AND workload_id IN ?", workloadIDs)
	default:
		q = q.Where("object_kind = 'identity_account' AND identity_account_id IN ?", identityIDs)
	}
	err := q.Order("object_kind, coalesce(workload_id, identity_account_id), role, created_at, id").Find(&out).Error
	return out, err
}

func (r *igaGovOwnershipRepository) ReplaceManualOwners(ws uuid.UUID, objectKind string, objectID uuid.UUID,
	want []models.IGAGovOwner, actor uuid.UUID) ([]models.IGAGovOwner, []models.IGAGovOwner, error) {
	if objectKind != models.GovObjectWorkload && objectKind != models.GovObjectIdentityAccount {
		return nil, nil, errors.New("object kind must be workload or identity_account")
	}
	before, err := r.ListOwners(ws, objectKind, objectID)
	if err != nil {
		return nil, nil, err
	}
	type key struct {
		user uuid.UUID
		role string
	}
	wanted := map[key]models.IGAGovOwner{}
	for _, w := range want {
		wanted[key{w.UserID, w.Role}] = w
	}
	seen := map[key]bool{}
	for _, o := range before {
		k := key{o.UserID, o.Role}
		w, keep := wanted[k]
		switch {
		case keep:
			seen[k] = true
			// Kept, or a rule's row taken over as manual, with the wanted
			// review date.
			if err := r.db.Model(&models.IGAGovOwner{}).Where("workspace_id = ? AND id = ?", ws, o.ID).
				Updates(map[string]any{
					"source": models.GovOwnerSourceManual, "rule_id": nil, "review_due_at": w.ReviewDueAt,
					"updated_at": gorm.Expr("now()"),
				}).Error; err != nil {
				return nil, nil, err
			}
		case o.Source == models.GovOwnerSourceManual:
			if err := r.db.Where("workspace_id = ? AND id = ?", ws, o.ID).Delete(&models.IGAGovOwner{}).Error; err != nil {
				return nil, nil, err
			}
		}
	}
	for _, w := range want {
		k := key{w.UserID, w.Role}
		if seen[k] {
			continue
		}
		seen[k] = true
		row := models.IGAGovOwner{
			WorkspaceID: ws, ObjectKind: objectKind, UserID: w.UserID, Role: w.Role,
			Source: models.GovOwnerSourceManual, ReviewDueAt: w.ReviewDueAt, CreatedBy: &actor,
		}
		id := objectID
		if objectKind == models.GovObjectWorkload {
			row.WorkloadID = &id
		} else {
			row.IdentityAccountID = &id
		}
		if err := r.db.Create(&row).Error; err != nil {
			return nil, nil, err
		}
	}
	after, err := r.ListOwners(ws, objectKind, objectID)
	return before, after, err
}

func (r *igaGovOwnershipRepository) SyncRuleOwners(ws uuid.UUID, desired []models.IGAGovOwner) (int, int, error) {
	type key struct {
		kind string
		obj  uuid.UUID
		user uuid.UUID
		role string
	}
	keyOf := func(o models.IGAGovOwner) key {
		k := key{kind: o.ObjectKind, user: o.UserID, role: o.Role}
		if o.WorkloadID != nil {
			k.obj = *o.WorkloadID
		} else if o.IdentityAccountID != nil {
			k.obj = *o.IdentityAccountID
		}
		return k
	}
	var existing []models.IGAGovOwner
	// Locked: two evaluations of the same workspace serialise here instead of
	// racing an insert into uq_iga_gov_owner.
	if err := r.db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("workspace_id = ?", ws).
		Order("id").Find(&existing).Error; err != nil {
		return 0, 0, err
	}
	have := map[key]models.IGAGovOwner{}
	for _, o := range existing {
		have[keyOf(o)] = o
	}
	want := map[key]models.IGAGovOwner{}
	for _, d := range desired {
		want[keyOf(d)] = d
	}
	removed := 0
	for k, o := range have {
		if o.Source != models.GovOwnerSourceTagRule {
			continue
		}
		d, ok := want[k]
		if ok && d.RuleID != nil && o.RuleID != nil && *d.RuleID == *o.RuleID {
			continue
		}
		if ok && d.RuleID != nil {
			// Same owner, now from another rule: re-point it, keeping the row
			// and its review date.
			if err := r.db.Model(&models.IGAGovOwner{}).Where("workspace_id = ? AND id = ?", ws, o.ID).
				Updates(map[string]any{"rule_id": *d.RuleID, "updated_at": gorm.Expr("now()")}).Error; err != nil {
				return 0, removed, err
			}
			continue
		}
		if err := r.db.Where("workspace_id = ? AND id = ?", ws, o.ID).Delete(&models.IGAGovOwner{}).Error; err != nil {
			return 0, removed, err
		}
		removed++
	}
	added := 0
	for k, d := range want {
		if _, ok := have[k]; ok {
			continue // the rule's own row (handled above) or a manual one
		}
		row := models.IGAGovOwner{
			WorkspaceID: ws, ObjectKind: d.ObjectKind, WorkloadID: d.WorkloadID, IdentityAccountID: d.IdentityAccountID,
			UserID: d.UserID, Role: d.Role, Source: models.GovOwnerSourceTagRule, RuleID: d.RuleID,
		}
		if err := r.db.Create(&row).Error; err != nil {
			return added, removed, err
		}
		added++
	}
	return added, removed, nil
}

// affectedOne maps "no row in this workspace" to ErrIGAGovNotFound.
func affectedOne(res *gorm.DB) error {
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrIGAGovNotFound
	}
	return nil
}
