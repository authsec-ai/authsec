package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
)

// Finding rules and finding exceptions (SPEC-iga-phase3-policy.md §7.1, §2.5;
// review fix R1a P2 "missing §7.1 routes"):
//
//	GET    /finding-rules?cursor&limit     governance:author  the workspace's rules, keyset-paged by id
//	POST   /finding-rules                  governance:author  {kind, scope?, params?, enabled?}
//	PATCH  /finding-rules/:id              governance:author  {scope?, params?, enabled?}
//	DELETE /finding-rules/:id              governance:author
//	POST   /findings/:id/exception         governance:author  {until, reason}
//	DELETE /findings/:id/exception         governance:author  {reason?}
//
// A finding rule is workspace configuration the evaluator reads at every
// publication (services/iga_gov_snapshot.go -> igagov.ParseFindingRule):
// require_review_date raises missing_review_date for a workload class whose
// accountable owner has no review date; unused_window widens the qualified
// window of unused_service for a workload class. A rule changes nothing until
// the next evaluation (§8.2: findings are evaluated per publication, never
// recomputed on a write).
//
// DECISIONS (review fix, recorded here and in the report):
//   - A rule is validated by the SAME parser the evaluator uses
//     (igagov.ParseFindingRule) after a strict decode, so the API never
//     stores a rule the evaluator would skip. scope is
//     {runtime_kinds, stages, classifications} (each list optional; empty
//     matches anything); stages and classifications are the iga_workload
//     CHECK vocabularies; runtime_kinds are lower-case identifiers.
//     require_review_date takes no params; unused_window takes
//     {window_days} in igagov.MinWindowDays..MaxWindowDays.
//   - kind is immutable (PATCH may not change it): a different kind is a
//     different rule. 048 has no updated_at, so PATCH carries no expected
//     state; the event records before and after.
//   - DELETE removes the row (048 has no tombstone); every change is in
//     iga_gov_event and audit_events.
//   - An exception may be recorded on a finding that is open, reopened or
//     already excepted (a new until/reason replaces the old one); every
//     other status is 409 finding_not_exceptable: under_review (a proposal
//     targets it: withdraw it or retain the service in owner review),
//     resolved / mitigated (AuthSec acted), cleared, superseded (nothing to
//     except). until must lie in the future and at most
//     GovMaxFindingExceptionDays ahead: an exception is time-bound, never
//     indefinite (§2.5 "exception until T").
//   - Clearing (DELETE) moves excepted -> open; the next evaluation applies
//     the lifecycle from there (condition false -> cleared).
//   - The evaluator honours exceptions in igagov.PlanFindingUpdates (excepted
//     stays excepted while its condition holds and until has not passed;
//     a lapsed exception -> open; condition false -> cleared). The owner
//     gate honours them in IGAGovOwnerReviewService.CheckGate: a version
//     that REMOVES a service whose unused_service finding is excepted on
//     that role is refused (409 review_incomplete, reason
//     finding_excepted) until the exception is cleared or the service is
//     retained. A finding exception never SATISFIES an owner-gate item
//     (age or route confirmation): it is recorded by governance:author, and
//     §2.10 forbids the author settling their own version's owner gate --
//     the "recorded exception" of §2.6 / A36 is the approver's review
//     exception (POST /reviews/:id/exception).

// GovMaxFindingExceptionDays bounds how far ahead an exception may run.
const GovMaxFindingExceptionDays = 365

// Finding-rule and exception error codes.
const (
	GovCodeFindingNotExceptable = "finding_not_exceptable"
	GovCodeFindingNotExcepted   = "finding_not_excepted"
)

// Event names written here.
const (
	GovEventFindingRuleCreated      = "finding_rule.created"
	GovEventFindingRuleUpdated      = "finding_rule.updated"
	GovEventFindingRuleDeleted      = "finding_rule.deleted"
	GovEventFindingExcepted         = "finding.excepted"
	GovEventFindingExceptionCleared = "finding.exception_cleared"
)

// The iga_workload CHECK vocabularies a rule scope may name.
var (
	govRuleStages          = map[string]bool{"production": true, "non_production": true, "unknown": true}
	govRuleClassifications = map[string]bool{"unclassified": true, "provider_native_agent": true, "classified_agent": true}
	govRuleRuntimeKind     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

const govRuleMaxScopeItems = 20

// GovFindingRules is the §7.1 finding-rule and finding-exception service.
type GovFindingRules struct {
	db  *gorm.DB
	now func() time.Time
}

// NewGovFindingRules builds the service over db.
func NewGovFindingRules(db *gorm.DB) *GovFindingRules {
	return &GovFindingRules{db: db, now: time.Now}
}

// WithClock replaces the clock (tests).
func (s *GovFindingRules) WithClock(now func() time.Time) *GovFindingRules {
	s.now = now
	return s
}

// GovFindingRuleView is one rule as the API returns it.
type GovFindingRuleView struct {
	ID        uuid.UUID       `json:"id"`
	Kind      string          `json:"kind"`
	Scope     json.RawMessage `json:"scope"`
	Params    json.RawMessage `json:"params"`
	Enabled   bool            `json:"enabled"`
	CreatedBy uuid.UUID       `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
}

func govFindingRuleView(r models.IGAGovFindingRule) GovFindingRuleView {
	return GovFindingRuleView{ID: r.ID, Kind: r.Kind, Scope: r.Scope, Params: r.Params, Enabled: r.Enabled,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt.UTC()}
}

// GovFindingRuleRequest is POST /finding-rules (Kind required) and PATCH
// /finding-rules/:id (Kind must be absent or equal). Absent fields keep
// their value (PATCH) or default (POST: {} scope, {} params, enabled).
type GovFindingRuleRequest struct {
	Kind    string           `json:"kind"`
	Scope   *json.RawMessage `json:"scope"`
	Params  *json.RawMessage `json:"params"`
	Enabled *bool            `json:"enabled"`
}

// strictDecode decodes raw into v, refusing unknown fields and trailing data.
func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func normList(field string, in []string, ok func(string) bool) ([]string, error) {
	if len(in) > govRuleMaxScopeItems {
		return nil, GovBadParam(field, fmt.Sprintf("%s may list at most %d values.", field, govRuleMaxScopeItems))
	}
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if !ok(v) {
			return nil, GovBadParam(field, fmt.Sprintf("%s: %q is not a valid value.", field, v))
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out, nil
}

// normalizeRule validates kind, scope and params and returns their canonical
// stored forms. The final check is the evaluator's own parser.
func normalizeRule(kind string, scope, params json.RawMessage) (json.RawMessage, json.RawMessage, error) {
	if kind != igagov.RuleRequireReviewDate && kind != igagov.RuleUnusedWindow {
		return nil, nil, GovBadParam("kind", "kind must be require_review_date or unused_window.")
	}
	var sc igagov.RuleScope
	if len(bytes.TrimSpace(scope)) > 0 && string(bytes.TrimSpace(scope)) != "null" {
		if err := strictDecode(scope, &sc); err != nil {
			return nil, nil, GovBadParam("scope", "scope must be {runtime_kinds?, stages?, classifications?}, each a list of strings.")
		}
	}
	var err error
	if sc.RuntimeKinds, err = normList("scope.runtime_kinds", sc.RuntimeKinds, govRuleRuntimeKind.MatchString); err != nil {
		return nil, nil, err
	}
	if sc.Stages, err = normList("scope.stages", sc.Stages, func(v string) bool { return govRuleStages[v] }); err != nil {
		return nil, nil, err
	}
	if sc.Classifications, err = normList("scope.classifications", sc.Classifications, func(v string) bool { return govRuleClassifications[v] }); err != nil {
		return nil, nil, err
	}
	scopeOut, err := json.Marshal(sc)
	if err != nil {
		return nil, nil, err
	}
	paramsOut := json.RawMessage(`{}`)
	hasParams := len(bytes.TrimSpace(params)) > 0 && string(bytes.TrimSpace(params)) != "null"
	switch kind {
	case igagov.RuleRequireReviewDate:
		if hasParams {
			var empty struct{}
			if err := strictDecode(params, &empty); err != nil {
				return nil, nil, GovBadParam("params", "A require_review_date rule takes no params ({}).")
			}
		}
	case igagov.RuleUnusedWindow:
		var p struct {
			WindowDays *int `json:"window_days"`
		}
		if !hasParams || strictDecode(params, &p) != nil || p.WindowDays == nil {
			return nil, nil, GovBadParam("params.window_days",
				fmt.Sprintf("An unused_window rule needs params {window_days: %d..%d}.", igagov.MinWindowDays, igagov.MaxWindowDays))
		}
		if *p.WindowDays < igagov.MinWindowDays || *p.WindowDays > igagov.MaxWindowDays {
			return nil, nil, GovBadParam("params.window_days",
				fmt.Sprintf("window_days must be %d..%d.", igagov.MinWindowDays, igagov.MaxWindowDays))
		}
		paramsOut, _ = json.Marshal(map[string]int{"window_days": *p.WindowDays})
	}
	// The evaluator's parser must accept exactly what is stored.
	if _, err := igagov.ParseFindingRule("new", kind, true, scopeOut, paramsOut); err != nil {
		return nil, nil, GovBadParam("params", err.Error())
	}
	return scopeOut, paramsOut, nil
}

// ListRules pages the workspace's finding rules by id (keyset): after is the
// last id of the previous page (uuid.Nil for the first), limit 1..200.
func (s *GovFindingRules) ListRules(ctx context.Context, ws, after uuid.UUID, limit int) ([]GovFindingRuleView, *string, error) {
	if limit < 1 || limit > MaxGovPage {
		limit = MaxGovPage
	}
	var rows []models.IGAGovFindingRule
	q := s.db.WithContext(ctx).Where("workspace_id = ?", ws)
	if after != uuid.Nil {
		q = q.Where("id > ?", after)
	}
	if err := q.Order("id").Limit(limit + 1).Find(&rows).Error; err != nil {
		return nil, nil, err
	}
	var next *string
	if len(rows) > limit {
		rows = rows[:limit]
		n := rows[len(rows)-1].ID.String()
		next = &n
	}
	out := make([]GovFindingRuleView, 0, len(rows))
	for _, r := range rows {
		out = append(out, govFindingRuleView(r))
	}
	return out, next, nil
}

// GetRule is one rule of the workspace, or GovNotFound.
func (s *GovFindingRules) GetRule(ctx context.Context, ws, id uuid.UUID) (*GovFindingRuleView, error) {
	r, err := s.rule(s.db.WithContext(ctx), ws, id, false)
	if err != nil {
		return nil, err
	}
	v := govFindingRuleView(*r)
	return &v, nil
}

func (s *GovFindingRules) rule(db *gorm.DB, ws, id uuid.UUID, lock bool) (*models.IGAGovFindingRule, error) {
	q := db.Where("workspace_id = ? AND id = ?", ws, id).Limit(1)
	if lock {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var rows []models.IGAGovFindingRule
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

func rawOrNil(p *json.RawMessage) json.RawMessage {
	if p == nil {
		return nil
	}
	return *p
}

func govRulePayload(r *models.IGAGovFindingRule) map[string]any {
	return map[string]any{"finding_rule_id": r.ID, "kind": r.Kind, "scope": json.RawMessage(r.Scope),
		"params": json.RawMessage(r.Params), "enabled": r.Enabled}
}

// CreateRule is POST /finding-rules.
func (s *GovFindingRules) CreateRule(ctx context.Context, ws, actor uuid.UUID, req GovFindingRuleRequest) (*GovFindingRuleView, error) {
	scope, params, err := normalizeRule(strings.TrimSpace(req.Kind), rawOrNil(req.Scope), rawOrNil(req.Params))
	if err != nil {
		return nil, err
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	r := &models.IGAGovFindingRule{ID: uuid.New(), WorkspaceID: ws, Kind: strings.TrimSpace(req.Kind), Scope: scope, Params: params,
		Enabled: enabled, CreatedBy: actor, CreatedAt: s.now().UTC()}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(r).Error; err != nil {
			return err
		}
		k, a := userActor(actor)
		return appendGovEvent(tx, ws, GovEventFindingRuleCreated, k, a, govEventRefs{}, govRulePayload(r))
	})
	if err != nil {
		return nil, err
	}
	v := govFindingRuleView(*r)
	return &v, nil
}

// UpdateRule is PATCH /finding-rules/:id. It returns the rule before and
// after.
func (s *GovFindingRules) UpdateRule(ctx context.Context, ws, actor, id uuid.UUID, req GovFindingRuleRequest) (before, after *GovFindingRuleView, err error) {
	if req.Scope == nil && req.Params == nil && req.Enabled == nil {
		return nil, nil, GovBadParam("body", "Nothing to change: give scope, params or enabled.")
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		cur, err := s.rule(tx, ws, id, true)
		if err != nil {
			return err
		}
		if k := strings.TrimSpace(req.Kind); k != "" && k != cur.Kind {
			return GovBadParam("kind", "A rule's kind cannot change; create a new rule.")
		}
		b := govFindingRuleView(*cur)
		before = &b
		scope, params := cur.Scope, cur.Params
		if req.Scope != nil {
			scope = *req.Scope
		}
		if req.Params != nil {
			params = *req.Params
		}
		ns, np, err := normalizeRule(cur.Kind, scope, params)
		if err != nil {
			return err
		}
		next := *cur
		next.Scope, next.Params = ns, np
		if req.Enabled != nil {
			next.Enabled = *req.Enabled
		}
		if err := tx.Model(&models.IGAGovFindingRule{}).Where("workspace_id = ? AND id = ?", ws, id).
			Updates(map[string]any{"scope": ns, "params": np, "enabled": next.Enabled}).Error; err != nil {
			return err
		}
		a := govFindingRuleView(next)
		after = &a
		k, ac := userActor(actor)
		p := govRulePayload(&next)
		p["before"] = govRulePayload(cur)
		return appendGovEvent(tx, ws, GovEventFindingRuleUpdated, k, ac, govEventRefs{}, p)
	})
	if err != nil {
		return nil, nil, err
	}
	return before, after, nil
}

// DeleteRule is DELETE /finding-rules/:id. It returns the deleted rule.
func (s *GovFindingRules) DeleteRule(ctx context.Context, ws, actor, id uuid.UUID) (*GovFindingRuleView, error) {
	var out *GovFindingRuleView
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		cur, err := s.rule(tx, ws, id, true)
		if err != nil {
			return err
		}
		if err := tx.Where("workspace_id = ? AND id = ?", ws, id).Delete(&models.IGAGovFindingRule{}).Error; err != nil {
			return err
		}
		v := govFindingRuleView(*cur)
		out = &v
		k, a := userActor(actor)
		return appendGovEvent(tx, ws, GovEventFindingRuleDeleted, k, a, govEventRefs{}, govRulePayload(cur))
	})
	return out, err
}

/* ------------------------------- exceptions ------------------------------- */

// GovFindingExceptionView is a finding's workflow state after an exception
// change (the API's data).
type GovFindingExceptionView struct {
	ID              uuid.UUID  `json:"id"`
	Kind            string     `json:"kind"`
	Status          string     `json:"status"`
	ExceptedUntil   *time.Time `json:"excepted_until"`
	ExceptionReason string     `json:"exception_reason"`
	StatusChangedAt time.Time  `json:"status_changed_at"`
}

func govFindingExceptionView(f models.IGAGovFinding) GovFindingExceptionView {
	v := GovFindingExceptionView{ID: f.ID, Kind: f.Kind, Status: f.Status, ExceptionReason: f.ExceptionReason,
		StatusChangedAt: f.StatusChangedAt.UTC()}
	if f.ExceptedUntil != nil {
		u := f.ExceptedUntil.UTC()
		v.ExceptedUntil = &u
	}
	return v
}

// GovFindingExceptionRequest is POST /findings/:id/exception.
type GovFindingExceptionRequest struct {
	Until  string `json:"until"`
	Reason string `json:"reason"`
}

func (s *GovFindingRules) lockFinding(tx *gorm.DB, ws, id uuid.UUID) (*models.IGAGovFinding, error) {
	var rows []models.IGAGovFinding
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("workspace_id = ? AND id = ?", ws, id).
		Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, GovNotFound()
	}
	return &rows[0], nil
}

func findingRefs(id uuid.UUID) govEventRefs {
	f := id
	return govEventRefs{FindingID: &f}
}

// RecordException is POST /findings/:id/exception: the finding becomes
// excepted until `until` with the reason. It returns before and after.
func (s *GovFindingRules) RecordException(ctx context.Context, ws, actor, id uuid.UUID, req GovFindingExceptionRequest) (before, after *GovFindingExceptionView, err error) {
	reason := strings.TrimSpace(req.Reason)
	if reason == "" || len(reason) > 2000 {
		return nil, nil, GovBadParam("reason", "reason is required (at most 2000 characters).")
	}
	until, perr := time.Parse(time.RFC3339, strings.TrimSpace(req.Until))
	if perr != nil {
		return nil, nil, GovBadParam("until", "until must be an RFC 3339 time.")
	}
	now := s.now().UTC()
	if !until.After(now) {
		return nil, nil, GovBadParam("until", "until must be in the future.")
	}
	if until.After(now.Add(GovMaxFindingExceptionDays * 24 * time.Hour)) {
		return nil, nil, GovBadParam("until", fmt.Sprintf("An exception may run at most %d days.", GovMaxFindingExceptionDays))
	}
	until = until.UTC().Truncate(time.Second)
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		f, err := s.lockFinding(tx, ws, id)
		if err != nil {
			return err
		}
		b := govFindingExceptionView(*f)
		before = &b
		switch f.Status {
		case igagov.StatusOpen, igagov.StatusReopened, igagov.StatusExcepted:
		default:
			return govErr(http.StatusConflict, GovCodeFindingNotExceptable,
				"Only an open, reopened or excepted finding can be excepted.", map[string]any{"status": f.Status})
		}
		if err := tx.Model(&models.IGAGovFinding{}).Where("workspace_id = ? AND id = ?", ws, id).
			Updates(map[string]any{"status": igagov.StatusExcepted, "excepted_until": until, "exception_reason": reason,
				"status_changed_at": now}).Error; err != nil {
			return err
		}
		next := *f
		next.Status, next.ExceptedUntil, next.ExceptionReason, next.StatusChangedAt = igagov.StatusExcepted, &until, reason, now
		a := govFindingExceptionView(next)
		after = &a
		k, ac := userActor(actor)
		return appendGovEvent(tx, ws, GovEventFindingExcepted, k, ac, findingRefs(id), map[string]any{
			"finding_id": id, "kind": f.Kind, "role_id": f.RoleID, "detail_key": f.DetailKey,
			"from_status": f.Status, "until": until, "reason": reason, "previous_until": f.ExceptedUntil})
	})
	if err != nil {
		return nil, nil, err
	}
	return before, after, nil
}

// ClearException is DELETE /findings/:id/exception: excepted -> open.
func (s *GovFindingRules) ClearException(ctx context.Context, ws, actor, id uuid.UUID, reason string) (before, after *GovFindingExceptionView, err error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 2000 {
		return nil, nil, GovBadParam("reason", "reason may be at most 2000 characters.")
	}
	now := s.now().UTC()
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		f, err := s.lockFinding(tx, ws, id)
		if err != nil {
			return err
		}
		b := govFindingExceptionView(*f)
		before = &b
		if f.Status != igagov.StatusExcepted {
			return govErr(http.StatusConflict, GovCodeFindingNotExcepted, "The finding has no exception to clear.",
				map[string]any{"status": f.Status})
		}
		if err := tx.Model(&models.IGAGovFinding{}).Where("workspace_id = ? AND id = ?", ws, id).
			Updates(map[string]any{"status": igagov.StatusOpen, "excepted_until": nil, "exception_reason": "",
				"status_changed_at": now}).Error; err != nil {
			return err
		}
		next := *f
		next.Status, next.ExceptedUntil, next.ExceptionReason, next.StatusChangedAt = igagov.StatusOpen, nil, "", now
		a := govFindingExceptionView(next)
		after = &a
		k, ac := userActor(actor)
		return appendGovEvent(tx, ws, GovEventFindingExceptionCleared, k, ac, findingRefs(id), map[string]any{
			"finding_id": id, "kind": f.Kind, "role_id": f.RoleID, "detail_key": f.DetailKey,
			"until": f.ExceptedUntil, "exception_reason": f.ExceptionReason, "reason": reason})
	})
	if err != nil {
		return nil, nil, err
	}
	return before, after, nil
}
