package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// IGAGovOwnershipService is Phase 3 ownership (SPEC-iga-phase3-policy.md
// §2.9, §7.1; T3.07): owners of workloads and identities, owner tag rules,
// and role-owner resolution.
//
//   - A role's owners are its own owners (accountable and technical) PLUS
//     the accountable owners of every workload that runs as it: a live
//     (current or stale, never ended) executes_as or task_execution_role
//     relationship from the workload to the role. DECISION: both relationship
//     types count as "runs as it" -- §2.12 names both as consumers, and the
//     ECS execution role's workload is affected by a boundary on it.
//   - discovered_agents.owner_user_id (legacy) is neither read nor migrated.
//   - Every mutation writes iga_gov_event in the same transaction; the route
//     adds auditAdminMutation.
type IGAGovOwnershipService struct {
	db      *gorm.DB
	members WorkspaceMemberDirectory
	events  repositories.IGAGovEventRepository
	jobs    repositories.IGAGovJobRepository
}

// NewIGAGovOwnershipService builds the service over db.
func NewIGAGovOwnershipService(db *gorm.DB) *IGAGovOwnershipService {
	return &IGAGovOwnershipService{db: db, events: repositories.NewIGAGovEventRepository(db), jobs: repositories.NewIGAGovJobRepository(db)}
}

// Errors the routes map (§7.12 envelope).
var (
	ErrOwnerObjectNotFound = errors.New("object not found")
	ErrOwnerRuleNotFound   = errors.New("owner rule not found")
	ErrOwnerNotFound       = errors.New("owner not found")
	ErrOwnerRuleExists     = errors.New("an owner rule with this tag key, scope and role exists")
)

// OwnerInputError is a field-level refusal of an owner write (400).
type OwnerInputError struct {
	Field  string
	Reason string
}

func (e *OwnerInputError) Error() string { return e.Field + ": " + e.Reason }

// RelConsumerTypes are the relationships by which a workload runs as a role.
var RelConsumerTypes = []string{models.RelTypeExecutesAs, models.RelTypeTaskExecutionRole}

// liveRelStates: a stale relationship is still believed (Phase 2 §2.7); only
// an ended one no longer counts.
var liveRelStates = []string{models.RelCurrent, models.RelStale}

// OwnerView is one owner row as the API shows it.
type OwnerView struct {
	ID          uuid.UUID  `json:"id"`
	ObjectKind  string     `json:"object_kind"`
	ObjectID    uuid.UUID  `json:"object_id"`
	UserID      uuid.UUID  `json:"user_id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	Role        string     `json:"role"`
	Source      string     `json:"source"`
	RuleID      *uuid.UUID `json:"rule_id"`
	ReviewDueAt *time.Time `json:"review_due_at"`
	// Member is false when the user is no longer an active member of the
	// workspace (the row stays until a person or the rule changes it).
	Member    bool      `json:"member"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ConsumerOwners is one workload running as a role, and its owners.
type ConsumerOwners struct {
	WorkloadID   uuid.UUID   `json:"workload_id"`
	Name         string      `json:"name"`
	RuntimeKind  string      `json:"runtime_kind"`
	Relationship string      `json:"relationship"`
	Owners       []OwnerView `json:"owners"`
}

// OwnerOf is one reason a user is an owner of a role.
type OwnerOf struct {
	ObjectKind string    `json:"object_kind"`
	ObjectID   uuid.UUID `json:"object_id"`
	// Name is the workload's name for a consumer; "" for the role itself.
	Name   string `json:"name"`
	Role   string `json:"role"`
	Source string `json:"source"`
}

// ResolvedOwner is one person who owns the object, directly or through a
// consumer, with every reason (A10: on a shared role both workloads' owners
// appear, each with the workload it owns).
type ResolvedOwner struct {
	UserID  uuid.UUID `json:"user_id"`
	Email   string    `json:"email"`
	Name    string    `json:"name"`
	Member  bool      `json:"member"`
	OwnerOf []OwnerOf `json:"owner_of"`
}

// ObjectOwnership is GET /owners for one object.
type ObjectOwnership struct {
	ObjectKind string      `json:"object_kind"`
	ObjectID   uuid.UUID   `json:"object_id"`
	Name       string      `json:"name"`
	Owners     []OwnerView `json:"owners"`
	// Consumers is the identity's live consuming workloads and their
	// ACCOUNTABLE owners (the derived owners of §2.9); empty for a workload.
	Consumers []ConsumerOwners `json:"consumers"`
	// Resolved is everyone who owns the object, by user: for an identity its
	// own owners plus its consumers' accountable owners (§2.9).
	Resolved []ResolvedOwner `json:"resolved"`
	// HasAccountable is whether any accountable owner exists in Resolved
	// (missing_owner is raised for a workload-bound role without one).
	HasAccountable bool `json:"has_accountable"`
}

// objectName returns the object's display name, or ErrOwnerObjectNotFound
// when it is not this workspace's.
func (s *IGAGovOwnershipService) objectName(db *gorm.DB, ws uuid.UUID, kind string, id uuid.UUID) (string, error) {
	var names []string
	var err error
	switch kind {
	case models.GovObjectIdentityAccount:
		err = db.Raw(`SELECT display_name FROM iga_identity_accounts WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&names).Error
	case models.GovObjectWorkload:
		err = db.Raw(`SELECT display_name FROM iga_workload WHERE workspace_id = ? AND id = ?`, ws, id).Scan(&names).Error
	default:
		return "", &OwnerInputError{Field: "object_kind", Reason: "must be workload or identity_account"}
	}
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", ErrOwnerObjectNotFound
	}
	return names[0], nil
}

// Owners is GET /owners: the object's owners, and for an identity its
// consumers' accountable owners and the resolved set (§2.9).
func (s *IGAGovOwnershipService) Owners(ctx context.Context, ws uuid.UUID, kind string, id uuid.UUID) (*ObjectOwnership, error) {
	db := s.db.WithContext(ctx)
	name, err := s.objectName(db, ws, kind, id)
	if err != nil {
		return nil, err
	}
	out := &ObjectOwnership{ObjectKind: kind, ObjectID: id, Name: name, Owners: []OwnerView{}, Consumers: []ConsumerOwners{}, Resolved: []ResolvedOwner{}}
	if kind == models.GovObjectWorkload {
		own, err := repositories.NewIGAGovOwnershipRepository(db).ListOwners(ws, kind, id)
		if err != nil {
			return nil, err
		}
		views, err := s.views(db, ws, own)
		if err != nil {
			return nil, err
		}
		out.Owners = views
		out.Resolved = resolve(views, nil)
	} else {
		ro, err := s.resolveRole(db, ws, id)
		if err != nil {
			return nil, err
		}
		out.Owners, out.Consumers, out.Resolved = ro.Owners, ro.Consumers, ro.Resolved
	}
	for _, r := range out.Resolved {
		for _, o := range r.OwnerOf {
			if o.Role == models.GovOwnerAccountable {
				out.HasAccountable = true
			}
		}
	}
	return out, nil
}

// RoleOwnership is a role's owners resolved per §2.9: what owner review
// (T3.12), target resolution (T3.06b) and impact (T3.11) consume.
type RoleOwnership struct {
	IdentityAccountID uuid.UUID
	// Owners recorded on the role itself (accountable and technical).
	Owners []OwnerView
	// Consumers: every live consuming workload with its ACCOUNTABLE owners.
	Consumers []ConsumerOwners
	// Resolved: one entry per person, every reason listed, sorted by user id.
	Resolved []ResolvedOwner
}

// UserIDs returns the resolved owners' user ids, sorted (impact_hash's
// "sorted owner user ids", §2.8).
func (r *RoleOwnership) UserIDs() []uuid.UUID {
	out := make([]uuid.UUID, 0, len(r.Resolved))
	for _, o := range r.Resolved {
		out = append(out, o.UserID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// UnownedConsumers returns the consuming workloads with no accountable
// owner: a shared role's review cannot reach those consumers (§11).
func (r *RoleOwnership) UnownedConsumers() []ConsumerOwners {
	var out []ConsumerOwners
	for _, c := range r.Consumers {
		if len(c.Owners) == 0 {
			out = append(out, c)
		}
	}
	return out
}

// ResolveRoleOwners resolves a role's owners per §2.9 over db (a transaction
// is fine). ErrOwnerObjectNotFound when the identity is not this workspace's.
func (s *IGAGovOwnershipService) ResolveRoleOwners(db *gorm.DB, ws, identityAccountID uuid.UUID) (*RoleOwnership, error) {
	if _, err := s.objectName(db, ws, models.GovObjectIdentityAccount, identityAccountID); err != nil {
		return nil, err
	}
	return s.resolveRole(db, ws, identityAccountID)
}

type consumerRow struct {
	WorkloadID       uuid.UUID
	DisplayName      string
	RuntimeKind      string
	RelationshipType string
}

func (s *IGAGovOwnershipService) consumers(db *gorm.DB, ws uuid.UUID, identityIDs []uuid.UUID) (map[uuid.UUID][]consumerRow, error) {
	var rows []struct {
		Target           uuid.UUID
		WorkloadID       uuid.UUID
		DisplayName      string
		RuntimeKind      string
		RelationshipType string
	}
	err := db.Raw(`
		SELECT r.target_identity_account_id AS target, w.id AS workload_id, w.display_name, w.runtime_kind, r.relationship_type
		  FROM iga_relationship r
		  JOIN iga_workload w ON w.workspace_id = r.workspace_id AND w.id = r.source_workload_id
		 WHERE r.workspace_id = ? AND r.target_identity_account_id IN ? AND r.relationship_type IN ? AND r.state IN ?
		 ORDER BY w.display_name, w.id, r.relationship_type`,
		ws, identityIDs, RelConsumerTypes, liveRelStates).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID][]consumerRow{}
	for _, r := range rows {
		out[r.Target] = append(out[r.Target], consumerRow{WorkloadID: r.WorkloadID, DisplayName: r.DisplayName,
			RuntimeKind: r.RuntimeKind, RelationshipType: r.RelationshipType})
	}
	return out, nil
}

func (s *IGAGovOwnershipService) resolveRole(db *gorm.DB, ws, id uuid.UUID) (*RoleOwnership, error) {
	cons, err := s.consumers(db, ws, []uuid.UUID{id})
	if err != nil {
		return nil, err
	}
	var wlIDs []uuid.UUID
	seenWL := map[uuid.UUID]bool{}
	for _, c := range cons[id] {
		if !seenWL[c.WorkloadID] {
			seenWL[c.WorkloadID] = true
			wlIDs = append(wlIDs, c.WorkloadID)
		}
	}
	rows, err := repositories.NewIGAGovOwnershipRepository(db).ListOwnersFor(ws, wlIDs, []uuid.UUID{id})
	if err != nil {
		return nil, err
	}
	views, err := s.views(db, ws, rows)
	if err != nil {
		return nil, err
	}
	out := &RoleOwnership{IdentityAccountID: id, Owners: []OwnerView{}, Consumers: []ConsumerOwners{}}
	byWorkload := map[uuid.UUID][]OwnerView{}
	for _, v := range views {
		if v.ObjectKind == models.GovObjectIdentityAccount {
			out.Owners = append(out.Owners, v)
		} else if v.Role == models.GovOwnerAccountable {
			byWorkload[v.ObjectID] = append(byWorkload[v.ObjectID], v)
		}
	}
	names := map[uuid.UUID]string{}
	for _, c := range cons[id] {
		names[c.WorkloadID] = c.DisplayName
		owners := byWorkload[c.WorkloadID]
		if owners == nil {
			owners = []OwnerView{}
		}
		out.Consumers = append(out.Consumers, ConsumerOwners{
			WorkloadID: c.WorkloadID, Name: c.DisplayName, RuntimeKind: c.RuntimeKind,
			Relationship: c.RelationshipType, Owners: owners,
		})
	}
	var derived []OwnerView
	for _, wl := range wlIDs {
		derived = append(derived, byWorkload[wl]...)
	}
	out.Resolved = resolve(append(append([]OwnerView{}, out.Owners...), derived...), names)
	return out, nil
}

// resolve folds owner rows into one entry per person.
func resolve(views []OwnerView, workloadNames map[uuid.UUID]string) []ResolvedOwner {
	idx := map[uuid.UUID]int{}
	out := []ResolvedOwner{}
	for _, v := range views {
		i, ok := idx[v.UserID]
		if !ok {
			i = len(out)
			idx[v.UserID] = i
			out = append(out, ResolvedOwner{UserID: v.UserID, Email: v.Email, Name: v.Name, Member: v.Member})
		}
		of := OwnerOf{ObjectKind: v.ObjectKind, ObjectID: v.ObjectID, Role: v.Role, Source: v.Source}
		if v.ObjectKind == models.GovObjectWorkload {
			of.Name = workloadNames[v.ObjectID]
		}
		out[i].OwnerOf = append(out[i].OwnerOf, of)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserID.String() < out[j].UserID.String() })
	return out
}

func (s *IGAGovOwnershipService) views(db *gorm.DB, ws uuid.UUID, rows []models.IGAGovOwner) ([]OwnerView, error) {
	ids := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.UserID)
	}
	members, err := s.members.ActiveMembers(db, ws, ids)
	if err != nil {
		return nil, err
	}
	out := make([]OwnerView, 0, len(rows))
	for _, r := range rows {
		v := OwnerView{ID: r.ID, ObjectKind: r.ObjectKind, UserID: r.UserID, Role: r.Role, Source: r.Source,
			RuleID: r.RuleID, ReviewDueAt: r.ReviewDueAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
		if r.WorkloadID != nil {
			v.ObjectID = *r.WorkloadID
		} else if r.IdentityAccountID != nil {
			v.ObjectID = *r.IdentityAccountID
		}
		if m, ok := members[r.UserID]; ok {
			v.Member, v.Email, v.Name = true, m.Email, m.Name
		}
		out = append(out, v)
	}
	return out, nil
}

/* ------------------------------- mutations -------------------------------- */

// OwnerAssignment is one wanted manual owner (PUT /owners).
type OwnerAssignment struct {
	UserID      uuid.UUID
	Role        string
	ReviewDueAt *time.Time
}

// OwnerChange is a mutation's result: the object's owners before and after.
type OwnerChange struct {
	Before *ObjectOwnership
	After  *ObjectOwnership
}

// SetManualOwners is PUT /owners: the object's MANUAL owners become exactly
// want (an empty list clears them); tag-rule owners are kept, except one with
// the same (user, role) as a wanted entry, which is taken over as manual.
// Every wanted user must be an active member of the workspace. One
// transaction with its iga_gov_event (owners.set).
func (s *IGAGovOwnershipService) SetManualOwners(ctx context.Context, ws, actor uuid.UUID, kind string, id uuid.UUID, want []OwnerAssignment) (*OwnerChange, error) {
	type key struct {
		u uuid.UUID
		r string
	}
	dup := map[key]bool{}
	rows := make([]models.IGAGovOwner, 0, len(want))
	userIDs := make([]uuid.UUID, 0, len(want))
	for i, w := range want {
		if w.Role == "" {
			w.Role = models.GovOwnerAccountable
		}
		if w.Role != models.GovOwnerAccountable && w.Role != models.GovOwnerTechnical {
			return nil, &OwnerInputError{Field: fmt.Sprintf("owners[%d].role", i), Reason: "must be accountable or technical"}
		}
		if w.UserID == uuid.Nil {
			return nil, &OwnerInputError{Field: fmt.Sprintf("owners[%d].user_id", i), Reason: "is required"}
		}
		k := key{w.UserID, w.Role}
		if dup[k] {
			return nil, &OwnerInputError{Field: fmt.Sprintf("owners[%d]", i), Reason: "the same user and role appear twice"}
		}
		dup[k] = true
		rows = append(rows, models.IGAGovOwner{UserID: w.UserID, Role: w.Role, ReviewDueAt: w.ReviewDueAt})
		userIDs = append(userIDs, w.UserID)
	}
	var change OwnerChange
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := s.objectName(tx, ws, kind, id); err != nil {
			return err
		}
		members, err := s.members.ActiveMembers(tx, ws, userIDs)
		if err != nil {
			return err
		}
		for i, w := range rows {
			if _, ok := members[w.UserID]; !ok {
				return &OwnerInputError{Field: fmt.Sprintf("owners[%d].user_id", i), Reason: "is not an active member of this workspace"}
			}
		}
		if change.Before, err = s.ownersTx(tx, ws, kind, id); err != nil {
			return err
		}
		if _, _, err := repositories.NewIGAGovOwnershipRepository(tx).ReplaceManualOwners(ws, kind, id, rows, actor); err != nil {
			return err
		}
		if change.After, err = s.ownersTx(tx, ws, kind, id); err != nil {
			return err
		}
		return s.event(tx, ws, "owners.set", actor, map[string]any{
			"object_kind": kind, "object_id": id,
			"before": ownerDigest(change.Before.Owners), "after": ownerDigest(change.After.Owners),
		})
	})
	if err != nil {
		return nil, err
	}
	return &change, nil
}

// ownersTx is Owners inside a transaction.
func (s *IGAGovOwnershipService) ownersTx(tx *gorm.DB, ws uuid.UUID, kind string, id uuid.UUID) (*ObjectOwnership, error) {
	inner := &IGAGovOwnershipService{db: tx, members: s.members, events: s.events, jobs: s.jobs}
	return inner.Owners(context.Background(), ws, kind, id)
}

// SetReviewDate sets (or clears, nil) one owner row's review_due_at -- the
// "Set review date" remedy of missing_review_date (§2.5), for a manual or a
// tag-rule owner alike. ErrOwnerNotFound when not this workspace's.
func (s *IGAGovOwnershipService) SetReviewDate(ctx context.Context, ws, actor, ownerID uuid.UUID, due *time.Time) (before, after *OwnerView, err error) {
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		repo := repositories.NewIGAGovOwnershipRepository(tx)
		o, err := repo.GetOwner(ws, ownerID)
		if errors.Is(err, repositories.ErrIGAGovNotFound) {
			return ErrOwnerNotFound
		}
		if err != nil {
			return err
		}
		bv, err := s.views(tx, ws, []models.IGAGovOwner{*o})
		if err != nil {
			return err
		}
		if err := repo.SetReviewDue(ws, ownerID, due); err != nil {
			return err
		}
		o2, err := repo.GetOwner(ws, ownerID)
		if err != nil {
			return err
		}
		av, err := s.views(tx, ws, []models.IGAGovOwner{*o2})
		if err != nil {
			return err
		}
		before, after = &bv[0], &av[0]
		return s.event(tx, ws, "owner.review_date_set", actor, map[string]any{
			"owner_id": ownerID, "object_kind": o.ObjectKind, "object_id": bv[0].ObjectID,
			"before": o.ReviewDueAt, "after": due,
		})
	})
	return before, after, err
}

// CreateRule is POST /owner-rules. It enqueues evaluate_owner_rules so the
// rule applies without waiting for the next publication (DECISION: dedupe
// key rules:changed). ErrOwnerRuleExists on a duplicate (tag_key,
// applies_to, role).
func (s *IGAGovOwnershipService) CreateRule(ctx context.Context, ws, actor uuid.UUID, tagKey, appliesTo, role string) (*models.IGAGovOwnerRule, error) {
	tagKey = strings.TrimSpace(tagKey)
	if tagKey == "" || len(tagKey) > 128 {
		return nil, &OwnerInputError{Field: "tag_key", Reason: "is required, at most 128 characters (an AWS tag key)"}
	}
	if appliesTo == "" {
		appliesTo = "both"
	}
	if appliesTo != "workload" && appliesTo != "identity_account" && appliesTo != "both" {
		return nil, &OwnerInputError{Field: "applies_to", Reason: "must be workload, identity_account or both"}
	}
	if role == "" {
		role = models.GovOwnerAccountable
	}
	if role != models.GovOwnerAccountable && role != models.GovOwnerTechnical {
		return nil, &OwnerInputError{Field: "role", Reason: "must be accountable or technical"}
	}
	rule := &models.IGAGovOwnerRule{ID: uuid.New(), WorkspaceID: ws, TagKey: tagKey, AppliesTo: appliesTo, Role: role, Enabled: true, CreatedBy: actor}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&models.IGAGovOwnerRule{}).
			Where("workspace_id = ? AND tag_key = ? AND applies_to = ? AND role = ?", ws, tagKey, appliesTo, role).
			Count(&n).Error; err != nil {
			return err
		}
		if n > 0 {
			return ErrOwnerRuleExists
		}
		if err := repositories.NewIGAGovOwnershipRepository(tx).CreateRule(rule); err != nil {
			if isUniqueViolation(err, "iga_gov_owner_rule") {
				return ErrOwnerRuleExists
			}
			return err
		}
		if err := s.enqueueRuleEvaluation(tx, ws); err != nil {
			return err
		}
		return s.event(tx, ws, "owner_rule.created", actor, map[string]any{
			"rule_id": rule.ID, "tag_key": tagKey, "applies_to": appliesTo, "role": role})
	})
	if err != nil {
		return nil, err
	}
	return rule, nil
}

// DeleteRule is DELETE /owner-rules/:id: the rule and, by FK cascade, every
// owner it assigned. ErrOwnerRuleNotFound when not this workspace's.
func (s *IGAGovOwnershipService) DeleteRule(ctx context.Context, ws, actor, id uuid.UUID) (*models.IGAGovOwnerRule, int64, error) {
	var rule *models.IGAGovOwnerRule
	var removed int64
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		repo := repositories.NewIGAGovOwnershipRepository(tx)
		var err error
		rule, err = repo.GetRule(ws, id)
		if errors.Is(err, repositories.ErrIGAGovNotFound) {
			return ErrOwnerRuleNotFound
		}
		if err != nil {
			return err
		}
		if err := tx.Model(&models.IGAGovOwner{}).Where("workspace_id = ? AND rule_id = ?", ws, id).Count(&removed).Error; err != nil {
			return err
		}
		if err := repo.DeleteRule(ws, id); err != nil {
			return err
		}
		return s.event(tx, ws, "owner_rule.deleted", actor, map[string]any{
			"rule_id": id, "tag_key": rule.TagKey, "applies_to": rule.AppliesTo, "role": rule.Role, "owners_removed": removed})
	})
	if errors.Is(err, ErrOwnerRuleNotFound) {
		return nil, 0, err
	}
	return rule, removed, err
}

// ListRules pages the workspace's rules by id (keyset): after is the last id
// of the previous page (uuid.Nil for the first), limit 1..200.
func (s *IGAGovOwnershipService) ListRules(ctx context.Context, ws uuid.UUID, after uuid.UUID, limit int) ([]models.IGAGovOwnerRule, bool, error) {
	if limit < 1 || limit > 200 {
		limit = 200
	}
	var out []models.IGAGovOwnerRule
	q := s.db.WithContext(ctx).Where("workspace_id = ?", ws)
	if after != uuid.Nil {
		q = q.Where("id > ?", after)
	}
	if err := q.Order("id").Limit(limit + 1).Find(&out).Error; err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

func (s *IGAGovOwnershipService) enqueueRuleEvaluation(tx *gorm.DB, ws uuid.UUID) error {
	var rev []int64
	if err := tx.Raw(`SELECT max(rev) FROM iga_publication WHERE workspace_id = ?`, ws).Scan(&rev).Error; err != nil {
		return err
	}
	job := &models.IGAGovJob{WorkspaceID: ws, Kind: repositories.GovJobEvaluateOwnerRules, DedupeKey: "rules:changed"}
	if len(rev) == 1 && rev[0] > 0 {
		r := rev[0]
		job.Rev = &r
	}
	_, err := s.jobs.EnqueueTx(tx, job)
	return err
}

/* --------------------------- tag-rule evaluation -------------------------- */

// RuleEvaluation is what applying the tag rules found and changed.
type RuleEvaluation struct {
	Added, Removed int
	// UnmatchedIdentityTags and UnmatchedWorkloadTags: per object id, each
	// "key=value" owner tag whose value names no active member (§2.9).
	UnmatchedIdentityTags map[string][]string
	UnmatchedWorkloadTags map[string][]string
}

type taggedObject struct {
	ID   uuid.UUID
	Tags map[string]string
}

// DECISION: an owner tag's value is ONE email, trimmed and compared case-
// insensitively; it matches an active member with that email (more than one
// such member: unmatched). The unmatched form shown on missing_owner is
// "key=value".
func (s *IGAGovOwnershipService) ruleTargets(db *gorm.DB, ws uuid.UUID) (rules []models.IGAGovOwnerRule, idents, wls []taggedObject, err error) {
	if err = db.Where("workspace_id = ? AND enabled", ws).Order("tag_key, applies_to, role, id").Find(&rules).Error; err != nil {
		return
	}
	if len(rules) == 0 {
		return
	}
	keys := map[string]bool{}
	for _, r := range rules {
		keys[r.TagKey] = true
	}
	load := func(table, extra string) ([]taggedObject, error) {
		var rows []struct {
			ID   uuid.UUID
			Tags []byte
		}
		// Tags are display-only provider facts in provider_attrs (028); for
		// workloads the collector records none today, so a workload rule
		// matches nothing until it does.
		if err := db.Raw(`SELECT id, provider_attrs->'tags' AS tags FROM `+table+`
			WHERE workspace_id = ? AND jsonb_typeof(provider_attrs->'tags') = 'object'`+extra, ws).Scan(&rows).Error; err != nil {
			return nil, err
		}
		var out []taggedObject
		for _, r := range rows {
			var tags map[string]any
			if json.Unmarshal(r.Tags, &tags) != nil {
				continue
			}
			t := map[string]string{}
			for k, v := range tags {
				if sv, ok := v.(string); ok && keys[k] {
					t[k] = sv
				}
			}
			if len(t) > 0 {
				out = append(out, taggedObject{ID: r.ID, Tags: t})
			}
		}
		return out, nil
	}
	if idents, err = load("iga_identity_accounts", " AND lifecycle = 'active'"); err != nil {
		return
	}
	wls, err = load("iga_workload", " AND lifecycle = 'active'")
	return
}

// evaluateRules computes the desired tag-rule owners and the unmatched tags,
// without writing.
func (s *IGAGovOwnershipService) evaluateRules(db *gorm.DB, ws uuid.UUID) ([]models.IGAGovOwner, *RuleEvaluation, error) {
	rules, idents, wls, err := s.ruleTargets(db, ws)
	if err != nil {
		return nil, nil, err
	}
	ev := &RuleEvaluation{UnmatchedIdentityTags: map[string][]string{}, UnmatchedWorkloadTags: map[string][]string{}}
	if len(rules) == 0 {
		return nil, ev, nil
	}
	var emails []string
	for _, set := range [][]taggedObject{idents, wls} {
		for _, o := range set {
			for _, v := range o.Tags {
				emails = append(emails, v)
			}
		}
	}
	members, err := s.members.MembersByEmail(db, ws, emails)
	if err != nil {
		return nil, nil, err
	}
	var desired []models.IGAGovOwner
	apply := func(kind string, objs []taggedObject, unmatched map[string][]string) {
		for _, o := range objs {
			seenTag := map[string]bool{}
			for _, r := range rules {
				if r.AppliesTo != "both" && r.AppliesTo != kind {
					continue
				}
				val, ok := o.Tags[r.TagKey]
				if !ok {
					continue
				}
				m, found := members[NormalizeMemberEmail(val)]
				if !found {
					tag := r.TagKey + "=" + val
					if !seenTag[tag] {
						seenTag[tag] = true
						unmatched[o.ID.String()] = append(unmatched[o.ID.String()], tag)
					}
					continue
				}
				id, ruleID := o.ID, r.ID
				row := models.IGAGovOwner{WorkspaceID: ws, ObjectKind: kind, UserID: m.UserID, Role: r.Role,
					Source: models.GovOwnerSourceTagRule, RuleID: &ruleID}
				if kind == models.GovObjectWorkload {
					row.WorkloadID = &id
				} else {
					row.IdentityAccountID = &id
				}
				desired = append(desired, row)
			}
		}
	}
	apply(models.GovObjectIdentityAccount, idents, ev.UnmatchedIdentityTags)
	apply(models.GovObjectWorkload, wls, ev.UnmatchedWorkloadTags)
	for _, m := range []map[string][]string{ev.UnmatchedIdentityTags, ev.UnmatchedWorkloadTags} {
		for k := range m {
			sort.Strings(m[k])
		}
	}
	return desired, ev, nil
}

// ApplyOwnerRulesTx is the evaluate_owner_rules job's work (§8.1: "Tag rules
// -> owners"): the workspace's tag_rule owners become exactly what the
// enabled rules, the current tags and the active members say, in the
// caller's (fenced) transaction, with an owner_rule.evaluated event.
func (s *IGAGovOwnershipService) ApplyOwnerRulesTx(tx *gorm.DB, ws uuid.UUID, rev *int64) (*RuleEvaluation, error) {
	desired, ev, err := s.evaluateRules(tx, ws)
	if err != nil {
		return nil, err
	}
	ev.Added, ev.Removed, err = repositories.NewIGAGovOwnershipRepository(tx).SyncRuleOwners(ws, desired)
	if err != nil {
		return nil, err
	}
	unmatched := 0
	for _, m := range []map[string][]string{ev.UnmatchedIdentityTags, ev.UnmatchedWorkloadTags} {
		for _, v := range m {
			unmatched += len(v)
		}
	}
	payload := map[string]any{"added": ev.Added, "removed": ev.Removed, "unmatched_tags": unmatched}
	if rev != nil {
		payload["rev"] = *rev
	}
	raw, _ := json.Marshal(payload)
	return ev, s.events.AppendTx(tx, &models.IGAGovEvent{WorkspaceID: ws, Event: "owner_rule.evaluated",
		ActorKind: models.GovActorSystem, ActorID: "policy-worker", Payload: raw})
}

// EvaluateOwnerRulesHandler is the evaluate_owner_rules job handler: tag
// rules applied in one fenced transaction.
func (s *IGAGovOwnershipService) EvaluateOwnerRulesHandler(ctx context.Context, run *PolicyJobRun) error {
	return run.InTx(ctx, func(tx *gorm.DB) error {
		_, err := s.ApplyOwnerRulesTx(tx, run.Job.WorkspaceID, run.Job.Rev)
		return err
	})
}

/* ------------------------- inputs for the evaluator ----------------------- */

// OwnershipInputs is what §8.2's evaluation needs from ownership to raise
// missing_owner and missing_review_date (igagov.Evaluate): the owner rows of
// the roles and consuming workloads, and the owner-rule tag values that match
// no active member, per role and per workload (shown on missing_owner).
type OwnershipInputs struct {
	// Owners: every iga_gov_owner row of the given identities and workloads
	// (Snapshot.Owners).
	Owners []igagov.OwnerRecord
	// UnmatchedIdentityTags: identity_account id -> "key=value" tags
	// (RoleSnapshot.UnmatchedOwnerTags).
	UnmatchedIdentityTags map[string][]string
	// UnmatchedWorkloadTags: workload id -> "key=value" tags
	// (WorkloadSnapshot.UnmatchedOwnerTags).
	UnmatchedWorkloadTags map[string][]string
}

// EvaluatorOwnershipInputs is the function the T3.06 evaluator calls while
// building igagov.Snapshot for revision N, on ITS transaction (db may be
// the barrier-held tx): owner rows as persisted (tag-rule owners are synced
// by the evaluate_owner_rules job, which §8.2 enqueues after evaluation N
// completes, so a tag change takes effect in the next evaluation), and the
// unmatched owner tags computed live from the enabled rules, the objects'
// current tags and the active members. Nil id slices select nothing.
// Read-only.
func (s *IGAGovOwnershipService) EvaluatorOwnershipInputs(db *gorm.DB, ws uuid.UUID, identityAccountIDs, workloadIDs []uuid.UUID) (*OwnershipInputs, error) {
	rows, err := repositories.NewIGAGovOwnershipRepository(db).ListOwnersFor(ws, workloadIDs, identityAccountIDs)
	if err != nil {
		return nil, err
	}
	out := &OwnershipInputs{Owners: make([]igagov.OwnerRecord, 0, len(rows)),
		UnmatchedIdentityTags: map[string][]string{}, UnmatchedWorkloadTags: map[string][]string{}}
	for _, r := range rows {
		rec := igagov.OwnerRecord{ID: r.ID.String(), ObjectKind: r.ObjectKind, UserID: r.UserID.String(),
			Role: r.Role, ReviewDueAt: r.ReviewDueAt}
		if r.WorkloadID != nil {
			rec.WorkloadID = r.WorkloadID.String()
		}
		if r.IdentityAccountID != nil {
			rec.IdentityAccountID = r.IdentityAccountID.String()
		}
		out.Owners = append(out.Owners, rec)
	}
	_, ev, err := s.evaluateRules(db, ws)
	if err != nil {
		return nil, err
	}
	want := func(ids []uuid.UUID) map[string]bool {
		m := map[string]bool{}
		for _, id := range ids {
			m[id.String()] = true
		}
		return m
	}
	wi, ww := want(identityAccountIDs), want(workloadIDs)
	for id, tags := range ev.UnmatchedIdentityTags {
		if wi[id] {
			out.UnmatchedIdentityTags[id] = tags
		}
	}
	for id, tags := range ev.UnmatchedWorkloadTags {
		if ww[id] {
			out.UnmatchedWorkloadTags[id] = tags
		}
	}
	return out, nil
}

/* --------------------------------- events --------------------------------- */

func (s *IGAGovOwnershipService) event(tx *gorm.DB, ws uuid.UUID, name string, actor uuid.UUID, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return repositories.NewIGAGovEventRepository(tx).AppendTx(tx, &models.IGAGovEvent{
		WorkspaceID: ws, Event: name, ActorKind: models.GovActorUser, ActorID: actor.String(), Payload: raw,
	})
}

func ownerDigest(vs []OwnerView) []map[string]any {
	out := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		out = append(out, map[string]any{"id": v.ID, "user_id": v.UserID, "role": v.Role, "source": v.Source, "review_due_at": v.ReviewDueAt})
	}
	return out
}
