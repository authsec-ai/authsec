package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SoDManager evaluates separation-of-duties rules.
//
// PG-7: subject expansion walks the SAME chain the ScopeResolver walks —
// role_bindings → roles → role_permissions → permissions — so SoD sees exactly what
// enforcement grants. A parallel interpretation would drift, and a drifted SoD engine
// gives false assurance, which is worse than none.
//
// PREVENTIVE AND DETECTIVE. Preventive runs inside the provisioning transaction, so a
// grant that would create a violation is refused rather than recorded and reported
// later. Detective catches what predates a rule, or what arrived through a path that
// does not yet call the check.
type SoDManager interface {
	// Check evaluates a HYPOTHETICAL grant: the subject's current capabilities plus
	// the role about to be bound. Call it inside the provisioning transaction, before
	// the binding exists.
	Check(tx *gorm.DB, workspaceID uuid.UUID, in SoDCheckInput) (*SoDDecision, error)

	// Scan evaluates every subject holding a binding in the workspace and records what
	// it finds. Returns a summary for the worker's log.
	Scan(workspaceID uuid.UUID) (*SoDScanResult, error)

	ListRules(workspaceID uuid.UUID) ([]models.SoDRule, error)
	ListViolations(workspaceID uuid.UUID, openOnly bool, limit, offset int) ([]models.SoDViolation, int64, error)
	ResolveViolation(workspaceID, violationID uuid.UUID, status, note string, by *uuid.UUID) (*models.SoDViolation, error)
}

// SoDCheckInput describes the grant being contemplated.
type SoDCheckInput struct {
	SubjectType  string
	SubjectID    uuid.UUID
	SubjectLabel string
	// AddingRoleID is the role about to be bound. Zero means "evaluate what the
	// subject already holds", which is what the detective scan does.
	AddingRoleID uuid.UUID
}

// SoDDecision is the outcome of a check.
type SoDDecision struct {
	Allowed bool `json:"allowed"`
	// Blocking are violations from rules with enforcement='block'. Non-empty means the
	// grant must be refused.
	Blocking []SoDHit `json:"blocking,omitempty"`
	// Warnings are violations from rules in observation mode. Recorded, not refused.
	Warnings []SoDHit `json:"warnings,omitempty"`
}

// SoDHit is one rule matching one subject, with the evidence.
type SoDHit struct {
	RuleID    uuid.UUID `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	Kind      string    `json:"kind"`
	Severity  string    `json:"severity"`
	LeftHits  []string  `json:"left_hits"`
	RightHits []string  `json:"right_hits,omitempty"`
	// Explanation is written for a human deciding what to do, not for a log grep.
	Explanation string `json:"explanation"`
}

// SoDScanResult summarises one detective pass.
type SoDScanResult struct {
	SubjectsScanned int `json:"subjects_scanned"`
	RulesEvaluated  int `json:"rules_evaluated"`
	ViolationsOpen  int `json:"violations_open"`
	ViolationsNew   int `json:"violations_new"`
	// ViolationsCleared is violations that no longer hold — the subject's access
	// changed, or the grant expired. Auto-closed as remediated.
	ViolationsCleared int `json:"violations_cleared"`
}

// capability is one thing a subject holds, plus how it holds it. The path is the whole
// point: a reviewer told "holds governance:admin" cannot act, one told "via role
// platform-admin, binding <id>" can.
type capability struct {
	Permission string    `json:"permission,omitempty"`
	RoleID     uuid.UUID `json:"role_id,omitempty"`
	RoleName   string    `json:"role_name,omitempty"`
	BindingID  uuid.UUID `json:"binding_id,omitempty"`
}

func (c capability) describe() string {
	if c.Permission != "" {
		if c.RoleName != "" {
			return fmt.Sprintf("%s (via role %s)", c.Permission, c.RoleName)
		}
		return c.Permission
	}
	if c.RoleName != "" {
		return "role " + c.RoleName
	}
	return c.RoleID.String()
}

type sodManager struct{ db *gorm.DB }

// NewSoDManager constructs a SoDManager.
func NewSoDManager(db *gorm.DB) SoDManager { return &sodManager{db: db} }

/* -------------------------------- evaluate ------------------------------- */

func (m *sodManager) Check(tx *gorm.DB, workspaceID uuid.UUID, in SoDCheckInput) (*SoDDecision, error) {
	if tx == nil {
		tx = m.db
	}
	rules, err := m.applicableRules(tx, workspaceID, in.SubjectType, in.SubjectID)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return &SoDDecision{Allowed: true}, nil
	}

	caps, err := m.expandSubject(tx, workspaceID, in.SubjectType, in.SubjectID, in.AddingRoleID)
	if err != nil {
		return nil, err
	}

	decision := &SoDDecision{Allowed: true}
	for i := range rules {
		hit, matched := evaluateRule(&rules[i], caps)
		if !matched {
			continue
		}
		if rules[i].Enforcement == models.SoDEnforcementBlock {
			decision.Blocking = append(decision.Blocking, hit)
			decision.Allowed = false
		} else {
			decision.Warnings = append(decision.Warnings, hit)
		}
	}
	return decision, nil
}

// applicableRules returns enabled rules that apply to this subject.
//
// subject_scope='agents' means a service account that is an agent's entitlement
// anchor (service_accounts.oauth_client_id IS NOT NULL) — exactly the population the
// self-modification control targets. Resolving it here rather than in the rule means a
// rule never has to know how agents are modelled.
func (m *sodManager) applicableRules(tx *gorm.DB, workspaceID uuid.UUID,
	subjectType string, subjectID uuid.UUID) ([]models.SoDRule, error) {

	var rules []models.SoDRule
	// Global rules (workspace_id NULL) apply everywhere, same convention as permissions.
	if err := tx.Where("enabled AND (workspace_id IS NULL OR workspace_id = ?)", workspaceID).
		Order("severity DESC, name").Find(&rules).Error; err != nil {
		return nil, fmt.Errorf("load sod rules: %w", err)
	}
	if len(rules) == 0 {
		return nil, nil
	}

	isAgent := false
	if subjectType == models.ProvenanceSubjectServiceAccount {
		var n int64
		if err := tx.Table("service_accounts").
			Where("id = ? AND workspace_id = ? AND oauth_client_id IS NOT NULL", subjectID, workspaceID).
			Count(&n).Error; err != nil {
			return nil, fmt.Errorf("classify subject: %w", err)
		}
		isAgent = n > 0
	}

	out := make([]models.SoDRule, 0, len(rules))
	for _, r := range rules {
		switch r.SubjectScope {
		case models.SoDScopeAgents:
			if !isAgent {
				continue
			}
		case models.SoDScopeHumans:
			// A human subject is a user, or a service account that is NOT an agent
			// anchor (a plain workload identity).
			if isAgent {
				continue
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// expandSubject resolves everything a subject holds, optionally including a role about
// to be bound.
//
// Uses the SAME joins as ScopeResolver.resolveFromRBAC, including the expiry filter —
// a lapsed binding grants nothing, so it must not create a violation either.
func (m *sodManager) expandSubject(tx *gorm.DB, workspaceID uuid.UUID,
	subjectType string, subjectID uuid.UUID, addingRoleID uuid.UUID) ([]capability, error) {

	type row struct {
		Permission string
		RoleID     uuid.UUID
		RoleName   string
		BindingID  uuid.UUID
	}
	var rows []row

	q := tx.Table("role_bindings rb").
		Select(`DISTINCT p.full_permission_string AS permission, ro.id AS role_id,
		        COALESCE(ro.name,'') AS role_name, rb.id AS binding_id`).
		Joins("JOIN roles ro ON rb.role_id = ro.id").
		Joins("JOIN role_permissions rp ON ro.id = rp.role_id").
		Joins("JOIN permissions p ON rp.permission_id = p.id").
		Where("(rb.workspace_id IS NULL OR rb.workspace_id = ?)", workspaceID).
		// A lapsed binding grants nothing, so it must not create a violation either.
		Where("(rb.expires_at IS NULL OR rb.expires_at > NOW())").
		Where("(ro.workspace_id IS NULL OR ro.workspace_id = ?)", workspaceID).
		Where("(p.workspace_id IS NULL OR p.workspace_id = ?)", workspaceID)

	switch subjectType {
	case models.ProvenanceSubjectServiceAccount:
		q = q.Where("rb.service_account_id = ?", subjectID)
	case models.ProvenanceSubjectUser:
		// Groups count: a permission held through a group is held.
		q = q.Where(`(rb.user_id = ? OR rb.group_id IN
		              (SELECT ug.group_id FROM user_groups ug WHERE ug.user_id = ?))`,
			subjectID, subjectID)
	case models.ProvenanceSubjectGroup:
		q = q.Where("rb.group_id = ?", subjectID)
	default:
		return nil, fmt.Errorf("cannot expand subject type %q", subjectType)
	}

	if err := q.Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("expand subject: %w", err)
	}

	caps := make([]capability, 0, len(rows)+8)
	seenRole := map[uuid.UUID]bool{}
	for _, r := range rows {
		caps = append(caps, capability{
			Permission: r.Permission, RoleID: r.RoleID,
			RoleName: r.RoleName, BindingID: r.BindingID,
		})
		seenRole[r.RoleID] = true
	}
	// Roles are capabilities in their own right: a rule may name a role directly, and
	// a role with no permissions attached yet would otherwise be invisible.
	for id := range seenRole {
		caps = append(caps, capability{RoleID: id})
	}

	// The hypothetical: the role about to be bound, expanded the same way. This is what
	// makes the check PREVENTIVE rather than a report on damage already done.
	if addingRoleID != uuid.Nil {
		var perms []struct {
			Permission string
			RoleName   string
		}
		if err := tx.Table("roles ro").
			Select("p.full_permission_string AS permission, COALESCE(ro.name,'') AS role_name").
			Joins("JOIN role_permissions rp ON ro.id = rp.role_id").
			Joins("JOIN permissions p ON rp.permission_id = p.id").
			Where("ro.id = ? AND (ro.workspace_id IS NULL OR ro.workspace_id = ?)", addingRoleID, workspaceID).
			Scan(&perms).Error; err != nil {
			return nil, fmt.Errorf("expand pending role: %w", err)
		}
		for _, p := range perms {
			caps = append(caps, capability{
				Permission: p.Permission, RoleID: addingRoleID, RoleName: p.RoleName,
			})
		}
		caps = append(caps, capability{RoleID: addingRoleID})
	}
	return caps, nil
}

// evaluateRule tests one rule against a capability set.
func evaluateRule(r *models.SoDRule, caps []capability) (SoDHit, bool) {
	left := matchSide(r.LeftRoles, r.LeftPermissions, caps)
	if len(left) == 0 {
		return SoDHit{}, false
	}

	hit := SoDHit{
		RuleID: r.ID, RuleName: r.Name, Kind: r.Kind, Severity: r.Severity,
		LeftHits: describeAll(left),
	}

	if r.Kind == models.SoDKindProhibition {
		hit.Explanation = fmt.Sprintf(
			"holds %s, which %s must never hold (%s)",
			joinMax(hit.LeftHits, 3), subjectScopeLabel(r.SubjectScope), r.Name)
		return hit, true
	}

	// A conflict needs BOTH sides.
	right := matchSide(r.RightRoles, r.RightPermissions, caps)
	if len(right) == 0 {
		return SoDHit{}, false
	}
	hit.RightHits = describeAll(right)
	hit.Explanation = fmt.Sprintf(
		"holds %s (%s) AND %s (%s), which must stay separate (%s)",
		joinMax(hit.LeftHits, 3), defaultLabel(r.LeftLabel, "side A"),
		joinMax(hit.RightHits, 3), defaultLabel(r.RightLabel, "side B"), r.Name)
	return hit, true
}

// matchSide returns the capabilities intersecting one side of a rule.
//
// Role ids are compared as strings because the rule stores them in a text[] — there is
// no pq.UUIDArray, and a custom array type for one column is not worth the surface.
func matchSide(roles []string, permissions []string, caps []capability) []capability {
	roleSet := make(map[string]bool, len(roles))
	for _, r := range roles {
		roleSet[r] = true
	}
	permSet := make(map[string]bool, len(permissions))
	for _, p := range permissions {
		permSet[p] = true
	}

	var out []capability
	seen := map[string]bool{}
	for _, c := range caps {
		matched := (c.Permission != "" && permSet[c.Permission]) ||
			(c.Permission == "" && c.RoleID != uuid.Nil && roleSet[c.RoleID.String()])
		if !matched {
			continue
		}
		// De-duplicate: the same permission reached through two bindings is one hit for
		// display, though both paths matter for remediation and both are kept in
		// evidence by the caller.
		key := c.Permission + "|" + c.RoleID.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	return out
}

func describeAll(caps []capability) []string {
	out := make([]string, 0, len(caps))
	for _, c := range caps {
		out = append(out, c.describe())
	}
	sort.Strings(out)
	return out
}

func joinMax(items []string, max int) string {
	if len(items) == 0 {
		return "nothing"
	}
	if len(items) <= max {
		return joinComma(items)
	}
	return fmt.Sprintf("%s and %d more", joinComma(items[:max]), len(items)-max)
}

func joinComma(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func subjectScopeLabel(scope string) string {
	switch scope {
	case models.SoDScopeAgents:
		return "an agent principal"
	case models.SoDScopeHumans:
		return "a human principal"
	default:
		return "this principal"
	}
}

func defaultLabel(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

/* --------------------------------- scan ---------------------------------- */

func (m *sodManager) Scan(workspaceID uuid.UUID) (*SoDScanResult, error) {
	res := &SoDScanResult{}

	var rules []models.SoDRule
	if err := m.db.Where("enabled AND (workspace_id IS NULL OR workspace_id = ?)", workspaceID).
		Find(&rules).Error; err != nil {
		return nil, err
	}
	res.RulesEvaluated = len(rules)
	if len(rules) == 0 {
		return res, nil
	}

	// Every subject currently holding a live binding. Expired bindings grant nothing,
	// so a subject whose only binding has lapsed is not in scope.
	type subject struct {
		SubjectType string
		SubjectID   uuid.UUID
		Label       string
	}
	var subjects []subject
	if err := m.db.Raw(`
		SELECT 'service_account' AS subject_type, rb.service_account_id AS subject_id,
		       COALESCE(sa.name,'') AS label
		  FROM role_bindings rb JOIN service_accounts sa ON sa.id = rb.service_account_id
		 WHERE rb.service_account_id IS NOT NULL AND rb.workspace_id = ?
		   AND (rb.expires_at IS NULL OR rb.expires_at > NOW())
		UNION
		SELECT 'user', rb.user_id, COALESCE(u.email,'')
		  FROM role_bindings rb JOIN users u ON u.id = rb.user_id
		 WHERE rb.user_id IS NOT NULL AND rb.workspace_id = ?
		   AND (rb.expires_at IS NULL OR rb.expires_at > NOW())`,
		workspaceID, workspaceID).Scan(&subjects).Error; err != nil {
		return nil, fmt.Errorf("enumerate subjects: %w", err)
	}
	res.SubjectsScanned = len(subjects)

	// Track which (rule, subject) pairs still hold, so anything previously open and now
	// clean can be closed rather than lingering as a false alarm.
	stillOpen := map[string]bool{}

	for _, s := range subjects {
		decision, err := m.Check(nil, workspaceID, SoDCheckInput{
			SubjectType: s.SubjectType, SubjectID: s.SubjectID, SubjectLabel: s.Label,
		})
		if err != nil {
			return nil, err
		}
		// Both blocking and warning rules produce a recorded violation; enforcement
		// only decides whether a GRANT is refused, not whether the problem is real.
		for _, hit := range append(append([]SoDHit{}, decision.Blocking...), decision.Warnings...) {
			stillOpen[hit.RuleID.String()+"|"+s.SubjectType+"|"+s.SubjectID.String()] = true
			created, err := m.recordViolation(workspaceID, s.SubjectType, s.SubjectID, s.Label,
				hit, models.SoDDetectedDetective)
			if err != nil {
				return nil, err
			}
			res.ViolationsOpen++
			if created {
				res.ViolationsNew++
			}
		}
	}

	// Close what no longer holds.
	var open []models.SoDViolation
	if err := m.db.Where("workspace_id = ? AND status = 'open' AND detected_via = ?",
		workspaceID, models.SoDDetectedDetective).Find(&open).Error; err != nil {
		return nil, err
	}
	for _, v := range open {
		key := v.RuleID.String() + "|" + v.SubjectType + "|" + v.SubjectID.String()
		if stillOpen[key] {
			continue
		}
		now := time.Now()
		if err := m.db.Model(&models.SoDViolation{}).Where("id = ?", v.ID).
			Updates(map[string]interface{}{
				"status":          models.SoDViolationRemediated,
				"resolution_note": "no longer detected: the subject's access changed or the grant lapsed",
				"resolved_at":     now,
			}).Error; err != nil {
			return nil, fmt.Errorf("close violation %s: %w", v.ID, err)
		}
		res.ViolationsCleared++
	}
	return res, nil
}

// recordViolation upserts one violation, reporting whether it was newly opened.
func (m *sodManager) recordViolation(workspaceID uuid.UUID, subjectType string, subjectID uuid.UUID,
	label string, hit SoDHit, via string) (bool, error) {

	leftJSON, _ := json.Marshal(hit.LeftHits)
	rightJSON, _ := json.Marshal(hit.RightHits)
	if len(rightJSON) == 0 || string(rightJSON) == "null" {
		rightJSON = []byte("[]")
	}

	// Refresh an existing open row rather than inserting a duplicate, so the count
	// means "how many problems" and not "how many times the scan ran".
	res := m.db.Model(&models.SoDViolation{}).
		Where(`workspace_id = ? AND rule_id = ? AND subject_type = ? AND subject_id = ?
		       AND status = 'open'`, workspaceID, hit.RuleID, subjectType, subjectID).
		Updates(map[string]interface{}{
			"last_seen_at":   time.Now(),
			"left_evidence":  leftJSON,
			"right_evidence": rightJSON,
			"subject_label":  label,
		})
	if res.Error != nil {
		return false, res.Error
	}
	if res.RowsAffected > 0 {
		return false, nil
	}

	v := models.SoDViolation{
		ID:            uuid.New(),
		WorkspaceID:   workspaceID,
		RuleID:        hit.RuleID,
		RuleName:      hit.RuleName,
		SubjectType:   subjectType,
		SubjectID:     subjectID,
		SubjectLabel:  label,
		LeftEvidence:  leftJSON,
		RightEvidence: rightJSON,
		Status:        models.SoDViolationOpen,
		DetectedVia:   via,
		DetectedAt:    time.Now(),
		LastSeenAt:    time.Now(),
	}
	if err := m.db.Create(&v).Error; err != nil {
		return false, fmt.Errorf("record violation: %w", err)
	}
	return true, nil
}

// RecordPreventiveViolation persists a refusal, so an attempt to create a conflict is
// evidence rather than only a rejected request.
func (m *sodManager) RecordPreventiveViolation(workspaceID uuid.UUID, in SoDCheckInput, hit SoDHit) error {
	_, err := m.recordViolation(workspaceID, in.SubjectType, in.SubjectID, in.SubjectLabel,
		hit, models.SoDDetectedPreventive)
	return err
}

/* --------------------------------- reads --------------------------------- */

func (m *sodManager) ListRules(workspaceID uuid.UUID) ([]models.SoDRule, error) {
	var rules []models.SoDRule
	err := m.db.Where("workspace_id IS NULL OR workspace_id = ?", workspaceID).
		Order("is_system DESC, severity DESC, name").Find(&rules).Error
	return rules, err
}

func (m *sodManager) ListViolations(workspaceID uuid.UUID, openOnly bool, limit, offset int) ([]models.SoDViolation, int64, error) {
	q := m.db.Model(&models.SoDViolation{}).Where("workspace_id = ?", workspaceID)
	if openOnly {
		q = q.Where("status = ?", models.SoDViolationOpen)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	var out []models.SoDViolation
	// Critical first: a reviewer's attention should go to the worst thing, not the
	// newest thing.
	err := q.Order(`CASE (SELECT severity FROM sod_rules WHERE id = sod_violations.rule_id)
	                  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`).
		Order("detected_at DESC").Limit(limit).Offset(offset).Find(&out).Error
	return out, total, err
}

func (m *sodManager) ResolveViolation(workspaceID, violationID uuid.UUID,
	status, note string, by *uuid.UUID) (*models.SoDViolation, error) {

	if status != models.SoDViolationAccepted && status != models.SoDViolationRemediated {
		return nil, fmt.Errorf("status must be %q or %q",
			models.SoDViolationAccepted, models.SoDViolationRemediated)
	}
	if note == "" {
		// An unexplained acceptance is indistinguishable from neglect.
		return nil, errors.New("a resolution note is required: accepting or closing a " +
			"violation is a decision somebody has to answer for")
	}

	now := time.Now()
	res := m.db.Model(&models.SoDViolation{}).
		Where("id = ? AND workspace_id = ? AND status = 'open'", violationID, workspaceID).
		Updates(map[string]interface{}{
			"status":          status,
			"resolution_note": note,
			"resolved_by":     by,
			"resolved_at":     now,
		})
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	var out models.SoDViolation
	if err := m.db.First(&out, "id = ?", violationID).Error; err != nil {
		return nil, err
	}
	return &out, nil
}
