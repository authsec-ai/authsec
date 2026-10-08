package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagov"
	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// Finding reads (SPEC-iga-phase3-policy.md §7 "Evaluation rule", §7.1, §2.5
// "Reads"). A read at revision N joins iga_gov_finding_result at N -- the
// condition, severity, confidence and detail AS OF N, frozen when N's
// evaluation completed -- with iga_gov_finding's identity and its CURRENT
// workflow status, labelled as current. Without ?rev reads use the newest
// complete evaluation, never the newest publication; ?rev=N is 409
// evaluation_incomplete unless N's evaluation is complete, and 410
// revision_not_retained once its results are pruned.

// GovError is a Phase 3 API error: {"error": {"code", "message", "detail"}}.
type GovError struct {
	Status  int
	Code    string
	Message string
	Detail  map[string]any
}

func (e *GovError) Error() string { return e.Code + ": " + e.Message }

// Body is the §7 error envelope.
func (e *GovError) Body() map[string]any {
	d := e.Detail
	if d == nil {
		d = map[string]any{}
	}
	return map[string]any{"error": map[string]any{"code": e.Code, "message": e.Message, "detail": d}}
}

func govErr(status int, code, msg string, detail map[string]any) *GovError {
	return &GovError{Status: status, Code: code, Message: msg, Detail: detail}
}

// GovBadParam is 400 invalid_parameter naming the parameter.
func GovBadParam(param, msg string) *GovError {
	return govErr(http.StatusBadRequest, "invalid_parameter", msg, map[string]any{"parameter": param})
}

// GovNotFound is 404 not_found: absent, or another workspace's (never 403).
func GovNotFound() *GovError { return govErr(http.StatusNotFound, "not_found", "Not found.", nil) }

// MaxGovPage bounds a page (§7 intro: cursor paging, limit <= 200).
const MaxGovPage = 200

// GovRevMeta is the meta every finding read carries.
type GovRevMeta struct {
	EvaluatedRev   *int64          `json:"evaluated_rev"`
	LatestRev      *int64          `json:"latest_rev"`
	LastEvaluation *GovEvalSummary `json:"last_evaluation"`
	NextCursor     *string         `json:"next_cursor"`
}

// GovEvalSummary is the newest evaluation of any status: so a reader can
// say "evaluated at rev N-k; evaluation of rev N failed" (§2.5).
type GovEvalSummary struct {
	Rev        int64      `json:"rev"`
	Status     string     `json:"status"`
	Attempts   int        `json:"attempts"`
	Error      string     `json:"error"`
	FinishedAt *time.Time `json:"finished_at"`
}

// GovReader serves the §7.1 reads.
type GovReader struct {
	db   *gorm.DB
	repo repositories.IGAGovEvaluationRepository
	key  []byte
}

// NewGovReader builds the reader; key signs list cursors.
func NewGovReader(db *gorm.DB, cursorKey []byte) *GovReader {
	return &GovReader{db: db, repo: repositories.NewIGAGovEvaluationRepository(), key: cursorKey}
}

// ResolveRev decides the revision a finding read is served at (§7
// "Evaluation rule") and the meta every read reports. rev 0 with a nil
// error means no evaluation has completed yet.
func (r *GovReader) ResolveRev(ws uuid.UUID, requested *int64) (int64, GovRevMeta, error) {
	var meta GovRevMeta
	var latest int64
	if err := r.db.Raw(`SELECT COALESCE(max(rev), 0) FROM iga_publication WHERE workspace_id = ?`, ws).Scan(&latest).Error; err != nil {
		return 0, meta, err
	}
	if latest > 0 {
		meta.LatestRev = &latest
	}
	last, err := r.repo.Latest(r.db, ws)
	if err != nil {
		return 0, meta, err
	}
	if last != nil {
		meta.LastEvaluation = &GovEvalSummary{Rev: last.Rev, Status: last.Status, Attempts: last.Attempts,
			Error: last.Error, FinishedAt: last.FinishedAt}
	}
	if requested == nil {
		lc, err := r.repo.LatestComplete(r.db, ws)
		if err != nil || lc == nil {
			return 0, meta, err
		}
		meta.EvaluatedRev = &lc.Rev
		return lc.Rev, meta, nil
	}
	rev := *requested
	ev, err := r.repo.GetTx(r.db, ws, rev, false)
	if err != nil {
		return 0, meta, err
	}
	if ev == nil || ev.Status != models.GovEvalComplete {
		status := any(nil)
		if ev != nil {
			status = ev.Status
		}
		return 0, meta, govErr(http.StatusConflict, "evaluation_incomplete",
			fmt.Sprintf("Findings at revision %d are not available: its evaluation is not complete.", rev),
			map[string]any{"rev": rev, "status": status})
	}
	retention := 30
	if s, err := repositories.NewIGAGovSettingsRepository(r.db).Get(ws); err == nil {
		retention = s.EvidenceRetentionRevs
	}
	kept, err := r.repo.RetainedRevs(r.db, ws, retention)
	if err != nil {
		return 0, meta, err
	}
	if !kept[rev] {
		return 0, meta, govErr(http.StatusGone, "revision_not_retained",
			fmt.Sprintf("Findings at revision %d are no longer retained.", rev),
			map[string]any{"rev": rev, "retention_revs": retention})
	}
	meta.EvaluatedRev = &rev
	return rev, meta, nil
}

/* ------------------------------- cursors ---------------------------------- */

type govCursor struct {
	Route string `json:"r"`
	WS    string `json:"w"`
	Rev   int64  `json:"v"`
	After string `json:"a"`
	Q     string `json:"q"` // the filter set the cursor was issued for
}

func (r *GovReader) sign(c govCursor) string {
	raw, _ := json.Marshal(c)
	m := hmac.New(sha256.New, r.key)
	m.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (r *GovReader) open(s string, want govCursor) (string, error) {
	bad := govErr(http.StatusBadRequest, "cursor_invalid", "The cursor is not valid for this list; restart it.", nil)
	parts := strings.Split(s, ".")
	if len(parts) != 2 {
		return "", bad
	}
	raw, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return "", bad
	}
	m := hmac.New(sha256.New, r.key)
	m.Write(raw)
	if !hmac.Equal(sig, m.Sum(nil)) {
		return "", bad
	}
	var c govCursor
	if json.Unmarshal(raw, &c) != nil || c.Route != want.Route || c.WS != want.WS || c.Rev != want.Rev || c.Q != want.Q {
		return "", bad
	}
	return c.After, nil
}

/* ------------------------------- findings --------------------------------- */

// FindingFilter is GET /findings' filter set.
type FindingFilter struct {
	Statuses    []string
	Kinds       []string
	Severities  []string
	Confidences []string
	IdentityID  *uuid.UUID
	WorkloadID  *uuid.UUID
	Account     string
	Q           string
	Cursor      string
	Limit       int
	GroupByRole bool
}

func (f FindingFilter) key() string {
	return strings.Join([]string{strings.Join(f.Statuses, ","), strings.Join(f.Kinds, ","), strings.Join(f.Severities, ","),
		strings.Join(f.Confidences, ","), uuidStr(f.IdentityID), uuidStr(f.WorkloadID), f.Account, f.Q,
		fmt.Sprint(f.GroupByRole)}, "|")
}

func uuidStr(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// FindingView is one finding as read at a revision.
type FindingView struct {
	ID                uuid.UUID      `json:"id"`
	Fingerprint       string         `json:"fingerprint"`
	Kind              string         `json:"kind"`
	Family            string         `json:"family"`
	RoleID            *string        `json:"role_id"`
	IdentityAccountID *uuid.UUID     `json:"identity_account_id"`
	RoleName          string         `json:"role_name"`
	RoleARN           string         `json:"role_arn"`
	AccountID         string         `json:"account_id"`
	ConnectorID       *uuid.UUID     `json:"connector_id"`
	DetailKey         string         `json:"detail_key"`
	Condition         *FindingAtRev  `json:"condition"`
	Current           FindingCurrent `json:"current"`
	Gap               *CollectionGap `json:"collection_gap,omitempty"`
}

// FindingAtRev is the condition at the read revision (frozen).
type FindingAtRev struct {
	Rev               int64           `json:"rev"`
	Severity          string          `json:"severity"`
	Confidence        string          `json:"confidence"`
	Detail            json.RawMessage `json:"detail"`
	EvidenceScanRunID *uuid.UUID      `json:"evidence_scan_run_id"`
}

// FindingCurrent is the finding's CURRENT workflow status (labelled so).
type FindingCurrent struct {
	Status           string     `json:"status"`
	StatusChangedAt  time.Time  `json:"status_changed_at"`
	ExceptedUntil    *time.Time `json:"excepted_until"`
	ExceptionReason  string     `json:"exception_reason"`
	FirstSeenRev     int64      `json:"first_seen_rev"`
	LastEvaluatedRev int64      `json:"last_evaluated_rev"`
}

// CollectionGap is the collection gap a finding depends on (L-16: one place
// per problem -- the finding links to the connection's coverage, it does not
// repeat the gap).
type CollectionGap struct {
	ConnectorID *uuid.UUID `json:"connector_id"`
	ScanRunID   *uuid.UUID `json:"scan_run_id"`
	Reason      string     `json:"reason"`
	Remedy      string     `json:"remedy"`
}

var (
	govKinds = map[string]bool{igagov.KindUnusedService: true, igagov.KindBroadGrant: true, igagov.KindSharedRole: true,
		igagov.KindMissingOwner: true, igagov.KindMissingReviewDate: true, igagov.KindActivityNotRead: true}
	govStatuses = map[string]bool{"open": true, "under_review": true, "excepted": true, "mitigated": true,
		"resolved": true, "cleared": true, "superseded": true, "reopened": true}
	govSeverities  = map[string]bool{"high": true, "medium": true, "low": true, "info": true}
	govConfidences = map[string]bool{"qualified": true, "age_unverified": true, "not_applicable": true}
)

// ValidateFindingFilter checks the enumerations.
func ValidateFindingFilter(f FindingFilter) error {
	for _, c := range []struct {
		param string
		vals  []string
		ok    map[string]bool
	}{{"status", f.Statuses, govStatuses}, {"kind", f.Kinds, govKinds}, {"severity", f.Severities, govSeverities},
		{"confidence", f.Confidences, govConfidences}} {
		for _, v := range c.vals {
			if !c.ok[v] {
				return GovBadParam(c.param, fmt.Sprintf("Unknown %s %q.", c.param, v))
			}
		}
	}
	if f.Limit < 0 || f.Limit > MaxGovPage {
		return GovBadParam("limit", fmt.Sprintf("limit must be 1..%d.", MaxGovPage))
	}
	return nil
}

type findingRow struct {
	ID                uuid.UUID
	Fingerprint       string
	Kind              string
	Family            string
	Status            string
	StatusChangedAt   time.Time
	ExceptedUntil     *time.Time
	ExceptionReason   string
	IdentityAccountID *uuid.UUID
	RoleID            *string
	ConnectorID       *uuid.UUID
	DetailKey         string
	FirstSeenRev      int64
	LastEvaluatedRev  int64
	Severity          *string
	Confidence        *string
	Detail            json.RawMessage
	EvidenceScanRunID *uuid.UUID
	ResultRev         *int64
	RoleName          *string
	SourceKey         *string
}

const findingSelect = `SELECT f.id, f.fingerprint, f.kind, f.family, f.status, f.status_changed_at, f.excepted_until,
       f.exception_reason, f.identity_account_id, f.role_id, f.connector_id, f.detail_key, f.first_seen_rev,
       f.last_evaluated_rev, r.severity, r.confidence, r.detail, r.evidence_scan_run_id, r.rev AS result_rev,
       i.display_name AS role_name, i.source_key
  FROM iga_gov_finding f
  %s JOIN iga_gov_finding_result r ON r.workspace_id = f.workspace_id AND r.finding_id = f.id AND r.rev = ?
  LEFT JOIN iga_identity_accounts i ON i.workspace_id = f.workspace_id AND i.id = f.identity_account_id`

func (fr findingRow) view() FindingView {
	v := FindingView{ID: fr.ID, Fingerprint: fr.Fingerprint, Kind: fr.Kind, Family: fr.Family, RoleID: fr.RoleID,
		IdentityAccountID: fr.IdentityAccountID, ConnectorID: fr.ConnectorID, DetailKey: fr.DetailKey,
		Current: FindingCurrent{Status: fr.Status, StatusChangedAt: fr.StatusChangedAt, ExceptedUntil: fr.ExceptedUntil,
			ExceptionReason: fr.ExceptionReason, FirstSeenRev: fr.FirstSeenRev, LastEvaluatedRev: fr.LastEvaluatedRev}}
	if fr.RoleName != nil {
		v.RoleName = *fr.RoleName
	}
	if fr.SourceKey != nil {
		v.RoleARN = nativeOfSourceKey(*fr.SourceKey)
		v.AccountID = govARNField(v.RoleARN, 4) // an IAM role's account is its ARN's
	}
	if fr.ResultRev != nil && fr.Severity != nil {
		v.Condition = &FindingAtRev{Rev: *fr.ResultRev, Severity: *fr.Severity, Confidence: *fr.Confidence,
			Detail: fr.Detail, EvidenceScanRunID: fr.EvidenceScanRunID}
		if fr.Kind == igagov.KindActivityNotRead {
			var d struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(fr.Detail, &d)
			v.Gap = &CollectionGap{ConnectorID: fr.ConnectorID, ScanRunID: fr.EvidenceScanRunID, Reason: d.Reason,
				Remedy: connectionCoverageLink(fr.ConnectorID)}
		}
	}
	return v
}

func connectionCoverageLink(conn *uuid.UUID) string {
	if conn == nil {
		return "/iga/connections"
	}
	return "/iga/connections/" + conn.String() + "/coverage"
}

// ListFindings is GET /findings at the resolved revision.
func (r *GovReader) ListFindings(ws uuid.UUID, rev int64, f FindingFilter) ([]FindingView, *string, error) {
	if f.Limit == 0 {
		f.Limit = 50
	}
	want := govCursor{Route: "findings", WS: ws.String(), Rev: rev, Q: f.key()}
	after := ""
	if f.Cursor != "" {
		var err error
		if after, err = r.open(f.Cursor, want); err != nil {
			return nil, nil, err
		}
	}
	if rev == 0 {
		return []FindingView{}, nil, nil
	}
	where := []string{"f.workspace_id = ?"}
	args := []any{rev, ws}
	add := func(cond string, a ...any) { where = append(where, cond); args = append(args, a...) }
	if len(f.Statuses) > 0 {
		add("f.status IN ?", f.Statuses)
	}
	if len(f.Kinds) > 0 {
		add("f.kind IN ?", f.Kinds)
	}
	if len(f.Severities) > 0 {
		add("r.severity IN ?", f.Severities)
	}
	if len(f.Confidences) > 0 {
		add("r.confidence IN ?", f.Confidences)
	}
	if f.IdentityID != nil {
		add("f.identity_account_id = ?", *f.IdentityID)
	}
	if f.WorkloadID != nil {
		add(`(f.workload_id = ? OR f.identity_account_id IN (SELECT target_identity_account_id FROM iga_relationship
		      WHERE workspace_id = f.workspace_id AND source_workload_id = ? AND state <> 'ended'
		        AND relationship_type IN ('executes_as','task_execution_role')))`, *f.WorkloadID, *f.WorkloadID)
	}
	if f.Account != "" {
		// The role ARN's account field (source key "aws␟arn:aws:iam::<acct>:role/…").
		add("split_part(i.source_key, ':', 5) = ?", f.Account)
	}
	if f.Q != "" {
		like := "%" + strings.ReplaceAll(strings.ReplaceAll(f.Q, "%", `\%`), "_", `\_`) + "%"
		add("(i.display_name ILIKE ? OR f.role_id ILIKE ? OR f.detail_key ILIKE ?)", like, like, like)
	}
	if after != "" {
		add("f.fingerprint > ?", after)
	}
	q := fmt.Sprintf(findingSelect, "") + " WHERE " + strings.Join(where, " AND ") + " ORDER BY f.fingerprint LIMIT ?"
	args = append(args, f.Limit+1)
	var rows []findingRow
	if err := r.db.Raw(q, args...).Scan(&rows).Error; err != nil {
		return nil, nil, err
	}
	var next *string
	if len(rows) > f.Limit {
		rows = rows[:f.Limit]
		c := want
		c.After = rows[len(rows)-1].Fingerprint
		s := r.sign(c)
		next = &s
	}
	out := make([]FindingView, 0, len(rows))
	for _, fr := range rows {
		out = append(out, fr.view())
	}
	return out, next, nil
}

// RoleGroup is one role's findings (group=role).
type RoleGroup struct {
	RoleID            *string       `json:"role_id"`
	IdentityAccountID *uuid.UUID    `json:"identity_account_id"`
	RoleName          string        `json:"role_name"`
	RoleARN           string        `json:"role_arn"`
	Findings          []FindingView `json:"findings"`
}

// GroupByRole groups one page of findings by role, in first-seen order
// (DECISION E10: the page is of findings; a role whose findings straddle two
// pages appears on both).
func GroupByRole(fs []FindingView) []RoleGroup {
	idx := map[string]int{}
	var out []RoleGroup
	for _, f := range fs {
		k := ""
		if f.IdentityAccountID != nil {
			k = f.IdentityAccountID.String()
		}
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, RoleGroup{RoleID: f.RoleID, IdentityAccountID: f.IdentityAccountID, RoleName: f.RoleName, RoleARN: f.RoleARN})
		}
		out[i].Findings = append(out[i].Findings, f)
	}
	if out == nil {
		out = []RoleGroup{}
	}
	return out
}

// FindingSummary is GET /findings/summary.
type FindingSummary struct {
	Total      int            `json:"total"`
	ByKind     map[string]int `json:"by_kind"`
	ByStatus   map[string]int `json:"by_status"`
	BySeverity map[string]int `json:"by_severity"`
}

// Summary counts the findings whose condition holds at rev.
func (r *GovReader) Summary(ws uuid.UUID, rev int64) (FindingSummary, error) {
	s := FindingSummary{ByKind: map[string]int{}, ByStatus: map[string]int{}, BySeverity: map[string]int{}}
	if rev == 0 {
		return s, nil
	}
	var rows []struct {
		Kind     string
		Status   string
		Severity string
		N        int
	}
	if err := r.db.Raw(`SELECT f.kind, f.status, r.severity, count(*) AS n
	                      FROM iga_gov_finding_result r
	                      JOIN iga_gov_finding f ON f.workspace_id = r.workspace_id AND f.id = r.finding_id
	                     WHERE r.workspace_id = ? AND r.rev = ?
	                     GROUP BY f.kind, f.status, r.severity`, ws, rev).Scan(&rows).Error; err != nil {
		return s, err
	}
	for _, x := range rows {
		s.Total += x.N
		s.ByKind[x.Kind] += x.N
		s.ByStatus[x.Status] += x.N
		s.BySeverity[x.Severity] += x.N
	}
	return s, nil
}

// FindingDetail is GET /findings/:id.
type FindingDetail struct {
	FindingView
	ConditionHoldsAtRev bool                            `json:"condition_holds_at_rev"`
	Evidence            []models.IGAGovActivityEvidence `json:"evidence"`
	Owners              []TargetOwnerView               `json:"owners"`
	LinkedPolicy        *LinkedPolicy                   `json:"linked_policy"`
	Consumers           []ConsumerView                  `json:"consumers"`
}

// LinkedPolicy is the live control on the finding's role, if any.
type LinkedPolicy struct {
	ControlID uuid.UUID `json:"control_id"`
	PolicyID  uuid.UUID `json:"policy_id"`
	State     string    `json:"state"`
}

// Finding reads one finding at rev. Another workspace's id is 404.
func (r *GovReader) Finding(ws, id uuid.UUID, rev int64) (*FindingDetail, error) {
	var rows []findingRow
	q := fmt.Sprintf(findingSelect, "LEFT") + " WHERE f.workspace_id = ? AND f.id = ?"
	if err := r.db.Raw(q, rev, ws, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, GovNotFound()
	}
	d := &FindingDetail{FindingView: rows[0].view()}
	d.ConditionHoldsAtRev = d.Condition != nil
	d.Evidence = []models.IGAGovActivityEvidence{}
	d.Owners, d.Consumers = []TargetOwnerView{}, []ConsumerView{}
	if d.IdentityAccountID == nil {
		return d, nil
	}
	q2 := r.db.Where("workspace_id = ? AND rev = ? AND identity_account_id = ?", ws, rev, *d.IdentityAccountID)
	if d.Kind == igagov.KindUnusedService {
		q2 = q2.Where("service = ?", d.DetailKey)
	}
	if err := q2.Order("service").Find(&d.Evidence).Error; err != nil {
		return nil, err
	}
	if d.Gap == nil {
		// Evidence not collected for the role is the gap the finding depends on.
		for _, e := range d.Evidence {
			if e.State == igagov.EvidenceNotCollected {
				d.Gap = &CollectionGap{ConnectorID: d.ConnectorID, ScanRunID: e.ScanRunID, Reason: e.Reason,
					Remedy: connectionCoverageLink(d.ConnectorID)}
				break
			}
		}
	}
	var err error
	if d.Consumers, err = consumersOf(r.db, ws, *d.IdentityAccountID); err != nil {
		return nil, err
	}
	if d.Owners, err = ownersOf(r.db, ws, *d.IdentityAccountID, d.Consumers); err != nil {
		return nil, err
	}
	if d.RoleID != nil {
		var lp []LinkedPolicy
		if err := r.db.Raw(`SELECT id AS control_id, policy_id, state FROM iga_gov_control
		                     WHERE workspace_id = ? AND role_id = ? AND state <> 'removed'`, ws, *d.RoleID).Scan(&lp).Error; err != nil {
			return nil, err
		}
		if len(lp) == 1 {
			d.LinkedPolicy = &lp[0]
		}
	}
	return d, nil
}

// ActivityEvidence is GET /identities/:id/activity-evidence at rev.
func (r *GovReader) ActivityEvidence(ws, identity uuid.UUID, rev int64) ([]models.IGAGovActivityEvidence, error) {
	var n int64
	if err := r.db.Raw(`SELECT count(*) FROM iga_identity_accounts WHERE workspace_id = ? AND id = ?`, ws, identity).Scan(&n).Error; err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, GovNotFound()
	}
	out := []models.IGAGovActivityEvidence{}
	if rev == 0 {
		return out, nil
	}
	err := r.db.Where("workspace_id = ? AND rev = ? AND identity_account_id = ?", ws, rev, identity).Order("service").Find(&out).Error
	return out, err
}

// EvidenceBundle is GET /evidence-bundles/:id: the stored canonical facts,
// re-verified (igagov.ParseBundle), with trust re-derived from the facts.
func (r *GovReader) EvidenceBundle(ws, id uuid.UUID) (map[string]any, error) {
	var b models.IGAGovEvidenceBundle
	if err := r.db.Where("workspace_id = ? AND id = ?", ws, id).Take(&b).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, GovNotFound()
		}
		return nil, err
	}
	facts, trust, reasons, err := igagov.ParseBundle([]byte(b.Canonical), b.BundleHash)
	if err != nil {
		return nil, fmt.Errorf("evidence bundle %s does not verify: %w", id, err)
	}
	return map[string]any{"id": b.ID, "provider": b.Provider, "bundle_hash": b.BundleHash, "trust": trust,
		"trust_reasons": reasons, "facts": facts, "created_at": b.CreatedAt}, nil
}

/* --------------------------- consumers and owners -------------------------- */

// ConsumerView is one workload running as a role.
type ConsumerView struct {
	WorkloadID   uuid.UUID `json:"workload_id"`
	Name         string    `json:"name"`
	RuntimeKind  string    `json:"runtime_kind"`
	Relationship string    `json:"relationship"`
}

// TargetOwnerView is one owner of a role or of a workload consuming it.
type TargetOwnerView struct {
	OwnerID     uuid.UUID  `json:"owner_id"`
	UserID      uuid.UUID  `json:"user_id"`
	Role        string     `json:"role"`
	Source      string     `json:"source"`
	ObjectKind  string     `json:"object_kind"`
	ObjectID    uuid.UUID  `json:"object_id"`
	For         string     `json:"for"`
	ReviewDueAt *time.Time `json:"review_due_at"`
}

// consumersOf reads every live executes_as / task_execution_role consumer of
// an identity, by key, with no list cap (§2.12).
func consumersOf(db *gorm.DB, ws, identity uuid.UUID) ([]ConsumerView, error) {
	out := []ConsumerView{}
	err := db.Raw(`SELECT w.id AS workload_id, w.display_name AS name, w.runtime_kind, r.relationship_type AS relationship
	                 FROM iga_relationship r
	                 JOIN iga_workload w ON w.workspace_id = r.workspace_id AND w.id = r.source_workload_id
	                WHERE r.workspace_id = ? AND r.target_identity_account_id = ? AND r.state <> 'ended'
	                  AND r.relationship_type IN ('executes_as','task_execution_role')
	                ORDER BY w.display_name, w.id, r.relationship_type`, ws, identity).Scan(&out).Error
	return out, err
}

// ownersOf is the role's own owners plus the owners of every consuming
// workload ("derived consumer owners", §7.1).
func ownersOf(db *gorm.DB, ws, identity uuid.UUID, consumers []ConsumerView) ([]TargetOwnerView, error) {
	names := map[uuid.UUID]string{}
	var wids []uuid.UUID
	for _, c := range consumers {
		if _, ok := names[c.WorkloadID]; !ok {
			wids = append(wids, c.WorkloadID)
		}
		names[c.WorkloadID] = c.Name
	}
	var rows []models.IGAGovOwner
	var q *gorm.DB
	if len(wids) > 0 {
		q = db.Where("workspace_id = ? AND ((object_kind = 'identity_account' AND identity_account_id = ?) OR (object_kind = 'workload' AND workload_id IN ?))",
			ws, identity, wids)
	} else {
		q = db.Where("workspace_id = ? AND object_kind = 'identity_account' AND identity_account_id = ?", ws, identity)
	}
	if err := q.Order("object_kind, role, user_id").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := []TargetOwnerView{}
	for _, o := range rows {
		v := TargetOwnerView{OwnerID: o.ID, UserID: o.UserID, Role: o.Role, Source: o.Source, ObjectKind: o.ObjectKind,
			ReviewDueAt: o.ReviewDueAt}
		if o.WorkloadID != nil {
			v.ObjectID, v.For = *o.WorkloadID, names[*o.WorkloadID]
		} else if o.IdentityAccountID != nil {
			v.ObjectID, v.For = *o.IdentityAccountID, "role"
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ObjectKind > out[j].ObjectKind })
	return out, nil
}
