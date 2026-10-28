package igaread

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Runtime reads (TRD 2 S12b). These URLs are new, so they do not change a
// default AWS response. graph=v2 is accepted and stamps graph_revision; it
// is not required. runtime-policy-status stays not_configured until A6.

const (
	runtimeRef     = "runtime_instance"
	runtimeDefault = 100
	runtimeEvents  = 50
	runtimeMaxPage = 100
)

// RuntimeInstanceView is one iga_runtime_instances row. ttl_basis is
// runtime_unobserved when ended_at is set, and null while the row is live.
type RuntimeInstanceView struct {
	Ref            string  `json:"ref"`
	RuntimeKey     string  `json:"runtime_key"`
	RuntimeKind    string  `json:"runtime_kind"`
	StartedAt      any     `json:"started_at"`
	EndedAt        any     `json:"ended_at"`
	LastObservedAt any     `json:"last_observed_at"`
	TTLBasis       *string `json:"ttl_basis"`
}

// AssignmentStatus is one target-to-policy assignment within the enforcement
// overlay. It summarises the latest receipt for that target.
type AssignmentStatus struct {
	TargetID    uuid.UUID  `json:"target_id"`
	PolicyID    uuid.UUID  `json:"policy_id"`
	Generation  int64      `json:"generation"`
	State       string     `json:"state"`
	LastReceipt *time.Time `json:"last_receipt,omitempty"`
}

// ControlStatus is one control kind in the enforcement overlay, with its
// current state and whether the policy requires it.
type ControlStatus struct {
	Kind     string `json:"kind"`
	State    string `json:"state"`
	Required bool   `json:"required"`
}

// RuntimePolicyStatus is the enforcement overlay for a workload. It replaces
// the A6 placeholder with real status derived from runtime_policy_targets and
// runtime_policy_receipts.
type RuntimePolicyStatus struct {
	WorkloadID       string             `json:"workload_id"`
	Status           string             `json:"status"`
	DesiredGeneration int64             `json:"desired_generation"`
	ActiveGeneration  int64             `json:"active_generation"`
	LastVerifiedAt   *time.Time         `json:"last_verified_at,omitempty"`
	Assignments      []AssignmentStatus `json:"assignments"`
	Controls         []ControlStatus    `json:"controls"`
	RestartRequired  bool               `json:"restart_required"`
	Errors           []string           `json:"errors"`
}

// ObservedAccessGroup is the default observed-access page: one row per
// resource, action, outcome and attribution.
type ObservedAccessGroup struct {
	Resource        string `json:"resource"`
	Action          string `json:"action"`
	Outcome         string `json:"outcome"`
	Attribution     string `json:"attribution"`
	Count           int64  `json:"count"`
	FirstObservedAt any    `json:"first_observed_at"`
	LastObservedAt  any    `json:"last_observed_at"`
	AccessClass     string `json:"access_class"`
	Phase           string `json:"phase,omitempty"`
	ResultDetail    string `json:"result_detail,omitempty"`
	Source          string `json:"source,omitempty"`
}

// ObservedAccessEvent is one iga_observed_access row (view=events).
type ObservedAccessEvent struct {
	Ref             string `json:"ref"`
	Resource        string `json:"resource"`
	RuntimeInstance string `json:"runtime_instance"`
	Action          string `json:"action"`
	Outcome         string `json:"outcome"`
	Attribution     string `json:"attribution"`
	ObservedAt      any    `json:"observed_at"`
	AccessClass     string `json:"access_class"`
	Phase           string `json:"phase,omitempty"`
	ResultDetail    string `json:"result_detail,omitempty"`
	Source          string `json:"source,omitempty"`
}

// ObservedBinding is one iga_runtime_identity_bindings row.
type ObservedBinding struct {
	Ref             string `json:"ref"`
	RuntimeInstance string `json:"runtime_instance"`
	Workload        string `json:"workload"`
	BindingKind     string `json:"binding_kind"`
	Basis           string `json:"basis"`
	ValidFrom       any    `json:"valid_from"`
	ValidTo         any    `json:"valid_to"`
}

// ObservedUse is bindings plus the identity's observed access.
type ObservedUse struct {
	Bindings       []ObservedBinding     `json:"bindings"`
	ObservedAccess []ObservedAccessGroup `json:"observed_access"`
}

type observedFilter struct {
	from, to    *time.Time
	action      string
	outcome     string
	runtime     *uuid.UUID
	attribution string
	hasAttr     bool
}

type cursorAt struct {
	At string `json:"at"`
}

func (r *Reader) RuntimeInstances(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	if perr := RouteParams(vals, "rev", "limit", "cursor"); perr != nil {
		return nil, perr
	}
	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}
	id, nerr := RouteID(RefWorkload, rawID)
	if nerr != nil {
		return nil, nerr
	}
	limit, perr := runtimeLimit(vals, MaxLimit, runtimeDefault)
	if perr != nil {
		return nil, perr
	}
	ctx, perr = bindOptIn(ctx, vals)
	if perr != nil {
		return nil, perr
	}
	route := "workloads/runtime-instances/" + id.String()
	pin := Pin{Rev: rev}
	after, afterID, perr := r.openAtCursor(vals.Get("cursor"), CursorContext{WS: ws, Route: route, Filter: FilterHash(vals), Sort: "last_observed_at"})
	if perr != nil {
		return nil, perr
	}
	if tok := vals.Get("cursor"); tok != "" {
		c, cerr := r.OpenCursor(tok, CursorContext{WS: ws, Route: route, Filter: FilterHash(vals), Sort: "last_observed_at"})
		if cerr != nil {
			return nil, cerr
		}
		cursorRev := c.Rev
		pin.CursorRev = &cursorRev
	}
	var out Envelope
	err := r.Read(ctx, ws, pin, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		ok, err := q.graphWorkload(id)
		if err != nil || !ok {
			if err != nil {
				return err
			}
			return NotFound()
		}
		rows, more, lastAt, lastID, err := q.runtimeInstances(id, limit, after, afterID)
		if err != nil {
			return err
		}
		meta := NewListMeta(q, limit)
		if more && q.Rev != nil {
			tok := r.signAtCursor(ws, q.Rev.Rev, route, FilterHash(vals), "last_observed_at", lastAt, lastID)
			meta.NextCursor = &tok
		}
		if rows == nil {
			rows = []RuntimeInstanceView{}
		}
		out = Envelope{Data: rows, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Reader) RuntimePolicyStatus(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	if perr := RouteParams(vals, "rev"); perr != nil {
		return nil, perr
	}
	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}
	id, nerr := RouteID(RefWorkload, rawID)
	if nerr != nil {
		return nil, nerr
	}
	ctx, perr = bindOptIn(ctx, vals)
	if perr != nil {
		return nil, perr
	}
	var out Envelope
	err := r.Read(ctx, ws, Pin{Rev: rev}, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		ok, err := q.graphWorkload(id)
		if err != nil || !ok {
			if err != nil {
				return err
			}
			return NotFound()
		}
		ps, err := q.policyStatus(id)
		if err != nil {
			return err
		}
		out = Envelope{Data: ps, Meta: NewDetailMeta(q)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// policyStatus queries runtime_policy_targets and runtime_policy_receipts to
// build the enforcement overlay for one workload. The status logic:
//   - not_configured: no targets exist for this workload
//   - assigned: targets exist but no receipt at all
//   - pending: receipt exists, receipt state is not "applied"/"enforced"
//   - applied: all receipts have "applied" state
//   - enforced: all receipts are "enforced" with all required controls passing
//   - partial: some controls applied, some missing
//   - stale: latest receipt generation < desired generation
//   - error: any receipt has an error
func (q *Query) policyStatus(workloadID uuid.UUID) (RuntimePolicyStatus, error) {
	ps := RuntimePolicyStatus{
		WorkloadID:  workloadID.String(),
		Status:      "not_configured",
		Assignments: []AssignmentStatus{},
		Controls:    []ControlStatus{},
		Errors:      []string{},
	}

	// Fetch targets for this workload, joined with their latest receipt and
	// the owning publication's policy_id.
	var targets []struct {
		TargetID         uuid.UUID
		PolicyID         uuid.UUID
		DesiredRevision  int64
		RequiredControls string
		ReceiptID        *uuid.UUID
		DeliveryRevision *int64
		ControlStatusRaw *string
		ReceiptError     *string
		ObservedAt       *time.Time
	}
	err := q.DB().Raw(`SELECT
		t.id AS target_id,
		pub.policy_id,
		t.desired_delivery_revision AS desired_revision,
		t.required_controls::text AS required_controls,
		r.id AS receipt_id,
		r.delivery_revision,
		r.control_status::text AS control_status_raw,
		r.error AS receipt_error,
		r.observed_at
		FROM runtime_policy_targets t
		JOIN runtime_policy_publications pub
		  ON pub.workspace_id = t.workspace_id AND pub.id = t.publication_id
		LEFT JOIN LATERAL (
			SELECT r2.id, r2.delivery_revision, r2.control_status, r2.error, r2.observed_at
			FROM runtime_policy_receipts r2
			WHERE r2.workspace_id = t.workspace_id AND r2.target_id = t.id
			ORDER BY r2.observed_at DESC
			LIMIT 1
		) r ON true
		WHERE t.workspace_id = ? AND t.workload_id = ?
		ORDER BY t.id`, q.WS, workloadID).Scan(&targets).Error
	if err != nil {
		return ps, err
	}

	if len(targets) == 0 {
		return ps, nil
	}

	// Aggregate.
	var (
		desiredGen      int64
		activeGen       int64
		lastVerified    *time.Time
		hasError        bool
		hasReceipt      bool
		allApplied      = true
		allEnforced     = true
		anyMissing      bool
		anyApplied      bool
		restartRequired bool
		controlMap      = map[string]*ControlStatus{} // kind -> status
		requiredSet     = map[string]bool{}
	)

	for _, tgt := range targets {
		if tgt.DesiredRevision > desiredGen {
			desiredGen = tgt.DesiredRevision
		}

		// Parse required controls from the target.
		var reqControls []string
		_ = json.Unmarshal([]byte(tgt.RequiredControls), &reqControls)
		for _, rc := range reqControls {
			requiredSet[rc] = true
		}

		asn := AssignmentStatus{
			TargetID:   tgt.TargetID,
			PolicyID:   tgt.PolicyID,
			Generation: tgt.DesiredRevision,
		}

		if tgt.ReceiptID == nil {
			asn.State = "assigned"
			allApplied = false
			allEnforced = false
			anyMissing = true
		} else {
			hasReceipt = true
			asn.LastReceipt = tgt.ObservedAt

			if tgt.DeliveryRevision != nil && *tgt.DeliveryRevision > activeGen {
				activeGen = *tgt.DeliveryRevision
			}

			if tgt.ReceiptError != nil && *tgt.ReceiptError != "" {
				hasError = true
				ps.Errors = append(ps.Errors, *tgt.ReceiptError)
				asn.State = "error"
				allApplied = false
				allEnforced = false
			} else if tgt.DeliveryRevision != nil && *tgt.DeliveryRevision < tgt.DesiredRevision {
				asn.State = "stale"
				restartRequired = true
				allApplied = false
				allEnforced = false
			} else {
				// Parse control_status to derive per-control states.
				receiptState, controls := parseControlStatusJSON(tgt.ControlStatusRaw)

				for _, c := range controls {
					st := c.State
					isReq := requiredSet[c.Kind]
					if _, ok := controlMap[c.Kind]; !ok {
						controlMap[c.Kind] = &ControlStatus{Kind: c.Kind, State: st, Required: isReq}
					} else {
						existing := controlMap[c.Kind]
						if isReq {
							existing.Required = true
						}
						// Keep the worst state across assignments.
						if controlRank(st) > controlRank(existing.State) {
							existing.State = st
						}
					}
				}

				switch receiptState {
				case "enforced":
					asn.State = "enforced"
					anyApplied = true
					// Check required controls.
					enforcedOK := true
					for _, rc := range reqControls {
						if cs, ok := controlMap[rc]; !ok || cs.State != "verified" {
							enforcedOK = false
						}
					}
					if !enforcedOK {
						allEnforced = false
					}
					if lastVerified == nil || (tgt.ObservedAt != nil && tgt.ObservedAt.After(*lastVerified)) {
						lastVerified = tgt.ObservedAt
					}
				case "applied":
					asn.State = "applied"
					anyApplied = true
					allEnforced = false
				default:
					asn.State = "pending"
					allApplied = false
					allEnforced = false
				}
			}
		}
		ps.Assignments = append(ps.Assignments, asn)
	}

	// Build the controls slice.
	for _, cs := range controlMap {
		ps.Controls = append(ps.Controls, *cs)
	}
	// Mark required controls that have no receipt at all.
	for rc := range requiredSet {
		if _, ok := controlMap[rc]; !ok {
			ps.Controls = append(ps.Controls, ControlStatus{Kind: rc, State: "requested", Required: true})
			anyMissing = true
		}
	}

	ps.DesiredGeneration = desiredGen
	ps.ActiveGeneration = activeGen
	ps.LastVerifiedAt = lastVerified
	ps.RestartRequired = restartRequired

	// Determine aggregate status.
	switch {
	case hasError:
		ps.Status = "error"
	case !hasReceipt:
		ps.Status = "assigned"
	case restartRequired:
		ps.Status = "stale"
	case allEnforced && !anyMissing:
		ps.Status = "enforced"
	case allApplied && !anyMissing:
		ps.Status = "applied"
	case anyApplied && anyMissing:
		ps.Status = "partial"
	case anyApplied:
		ps.Status = "applied"
	default:
		ps.Status = "pending"
	}

	return ps, nil
}

// parseControlStatusJSON parses the control_status JSONB from a receipt. It
// accepts either the wrapped form {"receipt_state": "...", "controls": [...]}
// or the bare array [{"kind": "...", "state": "..."}].
func parseControlStatusJSON(raw *string) (string, []ControlStatus) {
	if raw == nil {
		return "", nil
	}
	s := strings.TrimSpace(*raw)
	if s == "" || s == "null" || s == "[]" {
		return "", nil
	}
	if strings.HasPrefix(s, "{") {
		var wrap struct {
			ReceiptState string `json:"receipt_state"`
			Controls     []struct {
				Kind  string `json:"kind"`
				State string `json:"state"`
			} `json:"controls"`
		}
		if json.Unmarshal([]byte(s), &wrap) == nil {
			out := make([]ControlStatus, 0, len(wrap.Controls))
			for _, c := range wrap.Controls {
				out = append(out, ControlStatus{Kind: c.Kind, State: c.State})
			}
			return wrap.ReceiptState, out
		}
	}
	var arr []struct {
		Kind  string `json:"kind"`
		State string `json:"state"`
	}
	if json.Unmarshal([]byte(s), &arr) == nil {
		out := make([]ControlStatus, 0, len(arr))
		allVerified := true
		for _, c := range arr {
			out = append(out, ControlStatus{Kind: c.Kind, State: c.State})
			if c.State != "verified" {
				allVerified = false
			}
		}
		if allVerified && len(arr) > 0 {
			return "enforced", out
		}
		return "applied", out
	}
	return "", nil
}

// controlRank orders control states from best (0) to worst (5).
func controlRank(state string) int {
	switch state {
	case "verified":
		return 0
	case "active":
		return 1
	case "staged":
		return 2
	case "requested", "supported":
		return 3
	case "degraded", "unsupported":
		return 4
	case "failed":
		return 5
	default:
		return 3
	}
}

func (r *Reader) ObservedAccess(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	if perr := RouteParams(vals, "rev", "limit", "cursor", "view", "from", "to", "action", "outcome", "runtime_instance", "attribution"); perr != nil {
		return nil, perr
	}
	view := vals.Get("view")
	switch view {
	case "", "aggregate":
		view = ""
	case "events":
	default:
		return nil, InvalidParameter("view", "view must be aggregate or events")
	}
	id, nerr := RouteID(RefWorkload, rawID)
	if nerr != nil {
		return nil, nerr
	}
	f, perr := parseObservedFilter(vals)
	if perr != nil {
		return nil, perr
	}
	max, def := MaxLimit, runtimeDefault
	if view == "events" {
		max, def = runtimeMaxPage, runtimeEvents
	}
	limit, perr := runtimeLimit(vals, max, def)
	if perr != nil {
		return nil, perr
	}
	if vals.Get("cursor") != "" && view != "events" {
		return nil, InvalidParameter("cursor", "cursor requires view=events")
	}
	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}
	ctx, perr = bindOptIn(ctx, vals)
	if perr != nil {
		return nil, perr
	}
	route := "workloads/observed-access/" + id.String()
	cctx := CursorContext{WS: ws, Route: route, Filter: FilterHash(vals), Sort: "observed_at"}
	pin := Pin{Rev: rev}
	after, afterID, perr := r.openAtCursor(vals.Get("cursor"), cctx)
	if perr != nil {
		return nil, perr
	}
	if vals.Get("cursor") != "" {
		c, cerr := r.OpenCursor(vals.Get("cursor"), cctx)
		if cerr != nil {
			return nil, cerr
		}
		pin.CursorRev = &c.Rev
	}
	var out Envelope
	err := r.Read(ctx, ws, pin, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		ok, err := q.graphWorkload(id)
		if err != nil || !ok {
			if err != nil {
				return err
			}
			return NotFound()
		}
		meta := NewListMeta(q, limit)
		if view == "events" {
			rows, more, lastAt, lastID, err := q.observedEvents(id, f, limit, after, afterID)
			if err != nil {
				return err
			}
			if more && q.Rev != nil {
				tok := r.signAtCursor(ws, q.Rev.Rev, route, FilterHash(vals), "observed_at", lastAt, lastID)
				meta.NextCursor = &tok
			}
			if rows == nil {
				rows = []ObservedAccessEvent{}
			}
			out = Envelope{Data: rows, Meta: meta}
			return nil
		}
		rows, err := q.observedGroups(id, f, limit)
		if err != nil {
			return err
		}
		if rows == nil {
			rows = []ObservedAccessGroup{}
		}
		out = Envelope{Data: rows, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Reader) ObservedUse(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	if perr := RouteParams(vals, "rev"); perr != nil {
		return nil, perr
	}
	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}
	id, nerr := RouteID(RefIdentity, rawID)
	if nerr != nil {
		return nil, nerr
	}
	ctx, perr = bindOptIn(ctx, vals)
	if perr != nil {
		return nil, perr
	}
	var out Envelope
	err := r.Read(ctx, ws, Pin{Rev: rev}, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		ok, err := q.graphIdentity(id)
		if err != nil || !ok {
			if err != nil {
				return err
			}
			return NotFound()
		}
		bindings, err := q.observedBindings(id)
		if err != nil {
			return err
		}
		access, err := q.observedGroupsForIdentity(id)
		if err != nil {
			return err
		}
		out = Envelope{Data: ObservedUse{Bindings: bindings, ObservedAccess: access}, Meta: NewDetailMeta(q)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CollectorWorkloadRow is one workload within a collector's estate.
type CollectorWorkloadRow struct {
	Ref            string `json:"ref"`
	Name           string `json:"name"`
	RuntimeKind    string `json:"runtime_kind"`
	HealthStatus   string `json:"health_status"`
	MappingStatus  string `json:"mapping_status"`
	LastObservedAt any    `json:"last_observed_at"`
}

// CollectorWorkloadsResponse is the paginated response for collector workloads.
type CollectorWorkloadsResponse struct {
	Data []CollectorWorkloadRow `json:"data"`
	Meta any                    `json:"meta"`
}

// CollectorWorkloads returns paginated workloads within a collector's estate,
// with health and mapping state.
func (r *Reader) CollectorWorkloads(ctx context.Context, ws uuid.UUID, collectorID string, vals url.Values) (any, error) {
	if perr := RouteParams(vals, "rev", "limit", "cursor"); perr != nil {
		return nil, perr
	}
	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}
	cid, err := uuid.Parse(collectorID)
	if err != nil {
		return nil, NotFound()
	}
	limit, perr := runtimeLimit(vals, MaxLimit, runtimeDefault)
	if perr != nil {
		return nil, perr
	}
	ctx, perr = bindOptIn(ctx, vals)
	if perr != nil {
		return nil, perr
	}
	route := "collectors/" + cid.String() + "/workloads"
	pin := Pin{Rev: rev}
	after, afterID, perr := r.openAtCursor(vals.Get("cursor"), CursorContext{WS: ws, Route: route, Filter: FilterHash(vals), Sort: "last_observed_at"})
	if perr != nil {
		return nil, perr
	}
	if tok := vals.Get("cursor"); tok != "" {
		c, cerr := r.OpenCursor(tok, CursorContext{WS: ws, Route: route, Filter: FilterHash(vals), Sort: "last_observed_at"})
		if cerr != nil {
			return nil, cerr
		}
		cursorRev := c.Rev
		pin.CursorRev = &cursorRev
	}
	var out Envelope
	rerr := r.Read(ctx, ws, pin, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		rows, more, lastAt, lastID, qerr := q.collectorWorkloads(cid, limit, after, afterID)
		if qerr != nil {
			return qerr
		}
		meta := NewListMeta(q, limit)
		if more && q.Rev != nil {
			tok := r.signAtCursor(ws, q.Rev.Rev, route, FilterHash(vals), "last_observed_at", lastAt, lastID)
			meta.NextCursor = &tok
		}
		if rows == nil {
			rows = []CollectorWorkloadRow{}
		}
		out = Envelope{Data: rows, Meta: meta}
		return nil
	})
	if rerr != nil {
		return nil, rerr
	}
	return out, nil
}

func (q *Query) collectorWorkloads(collectorID uuid.UUID, limit int, after time.Time, afterID uuid.UUID) ([]CollectorWorkloadRow, bool, time.Time, uuid.UUID, error) {
	args := []any{q.WS, collectorID}
	sql := `SELECT DISTINCT ON (w.id) w.id, w.display_name, w.runtime_kind,
		'healthy' AS health_status,
		'unmapped' AS mapping_status,
		ri.last_observed_at
		FROM iga_workload w
		JOIN iga_runtime_instances ri ON ri.workspace_id = w.workspace_id AND ri.workload_id = w.id
		JOIN collector_instances ci ON ci.workspace_id = w.workspace_id AND ci.id = ?
		  AND ci.estate_scope_id = ri.estate_scope_id
		WHERE w.workspace_id = ?
		  AND w.provider IN ('ad','aws','kubernetes','linux')
		  AND ` + SupportedSQL("w", "workload_id")
	if afterID != uuid.Nil {
		sql += ` AND (ri.last_observed_at, w.id) < (?, ?)`
		args = append(args, after, afterID)
	}
	sql += ` ORDER BY w.id, ri.last_observed_at DESC`
	// Wrap in a subquery so we can sort and limit on last_observed_at.
	args = append(args, limit+1)
	sql = `SELECT id, display_name, runtime_kind, health_status, mapping_status, last_observed_at
		FROM (` + sql + `) sub
		ORDER BY last_observed_at DESC, id DESC
		LIMIT ?`
	var rows []struct {
		ID             uuid.UUID
		DisplayName    string
		RuntimeKind    string
		HealthStatus   string
		MappingStatus  string
		LastObservedAt *time.Time
	}
	if err := q.DB().Raw(sql, args...).Scan(&rows).Error; err != nil {
		return nil, false, time.Time{}, uuid.Nil, err
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]CollectorWorkloadRow, 0, len(rows))
	var lastAt time.Time
	var lastID uuid.UUID
	for _, row := range rows {
		out = append(out, CollectorWorkloadRow{
			Ref: R(RefWorkload, row.ID), Name: row.DisplayName, RuntimeKind: row.RuntimeKind,
			HealthStatus: row.HealthStatus, MappingStatus: row.MappingStatus,
			LastObservedAt: TS(row.LastObservedAt),
		})
		if row.LastObservedAt != nil {
			lastAt = *row.LastObservedAt
		}
		lastID = row.ID
	}
	return out, more, lastAt, lastID, nil
}

func runtimeLimit(vals url.Values, max, def int) (int, *Error) {
	raw := vals.Get("limit")
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > max {
		return 0, InvalidParameter("limit", "limit is out of range")
	}
	return n, nil
}

func (r *Reader) openAtCursor(tok string, want CursorContext) (time.Time, uuid.UUID, *Error) {
	if tok == "" {
		return time.Time{}, uuid.Nil, nil
	}
	c, err := r.OpenCursor(tok, want)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	var k cursorAt
	if json.Unmarshal(c.Key, &k) != nil {
		return time.Time{}, uuid.Nil, CursorInvalid("Malformed cursor.")
	}
	at, perr := time.Parse(time.RFC3339Nano, k.At)
	if perr != nil {
		return time.Time{}, uuid.Nil, CursorInvalid("Malformed cursor.")
	}
	return at, c.ID, nil
}

func (r *Reader) signAtCursor(ws uuid.UUID, rev int64, route, filter, sort string, at time.Time, id uuid.UUID) string {
	key, _ := json.Marshal(cursorAt{At: at.UTC().Format(time.RFC3339Nano)})
	return r.SignCursor(Cursor{WS: ws, Rev: rev, Route: route, Filter: filter, Sort: sort, Key: key, ID: id})
}

func (q *Query) graphWorkload(id uuid.UUID) (bool, error) {
	var n int
	err := q.DB().Raw(`SELECT count(*) FROM iga_workload w
		WHERE w.workspace_id = ? AND w.id = ?
		  AND w.provider IN ('ad','aws','kubernetes','linux')
		  AND `+SupportedSQL("w", "workload_id"), q.WS, id).Scan(&n).Error
	return n == 1, err
}

func (q *Query) graphIdentity(id uuid.UUID) (bool, error) {
	var n int
	err := q.DB().Raw(`SELECT count(*) FROM iga_identity_accounts ia
		WHERE ia.workspace_id = ? AND ia.id = ?
		  AND ia.provider IN ('ad','aws','kubernetes','linux')
		  AND `+SupportedSQL("ia", "identity_account_id"), q.WS, id).Scan(&n).Error
	return n == 1, err
}

func (q *Query) runtimeInstances(workload uuid.UUID, limit int, after time.Time, afterID uuid.UUID) ([]RuntimeInstanceView, bool, time.Time, uuid.UUID, error) {
	args := []any{q.WS, workload}
	sql := `SELECT id, runtime_key, runtime_kind, started_at, ended_at, last_observed_at
		FROM iga_runtime_instances
		WHERE workspace_id = ? AND workload_id = ?`
	if afterID != uuid.Nil {
		sql += ` AND (last_observed_at, id) < (?, ?)`
		args = append(args, after, afterID)
	}
	sql += ` ORDER BY last_observed_at DESC, id DESC LIMIT ?`
	args = append(args, limit+1)
	var rows []struct {
		ID             uuid.UUID
		RuntimeKey     string
		RuntimeKind    string
		StartedAt      *time.Time
		EndedAt        *time.Time
		LastObservedAt time.Time
	}
	if err := q.DB().Raw(sql, args...).Scan(&rows).Error; err != nil {
		return nil, false, time.Time{}, uuid.Nil, err
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]RuntimeInstanceView, 0, len(rows))
	var lastAt time.Time
	var lastID uuid.UUID
	for _, row := range rows {
		out = append(out, RuntimeInstanceView{
			Ref: R(runtimeRef, row.ID), RuntimeKey: row.RuntimeKey, RuntimeKind: row.RuntimeKind,
			StartedAt: TS(row.StartedAt), EndedAt: TS(row.EndedAt), LastObservedAt: TS(&row.LastObservedAt),
			TTLBasis: endedRuntimeBasis(row.EndedAt != nil),
		})
		lastAt, lastID = row.LastObservedAt, row.ID
	}
	return out, more, lastAt, lastID, nil
}

func parseObservedFilter(vals url.Values) (observedFilter, *Error) {
	var f observedFilter
	if raw := strings.TrimSpace(vals.Get("from")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return f, InvalidParameter("from", "from must be RFC3339")
		}
		f.from = &t
	}
	if raw := strings.TrimSpace(vals.Get("to")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return f, InvalidParameter("to", "to must be RFC3339")
		}
		f.to = &t
	}
	f.action = strings.TrimSpace(vals.Get("action"))
	f.outcome = strings.TrimSpace(vals.Get("outcome"))
	if f.outcome != "" {
		switch f.outcome {
		case "attempted", "success", "denied", "unknown":
		default:
			return f, InvalidParameter("outcome", "outcome must be attempted, success, denied or unknown")
		}
	}
	if raw := strings.TrimSpace(vals.Get("runtime_instance")); raw != "" {
		id, err := uuid.Parse(strings.TrimPrefix(raw, runtimeRef+":"))
		if err != nil {
			return f, InvalidParameter("runtime_instance", "runtime_instance must be a UUID")
		}
		f.runtime = &id
	}
	if _, ok := vals["attribution"]; ok {
		f.hasAttr = true
		f.attribution = vals.Get("attribution")
	}
	return f, nil
}

func (f observedFilter) where(args []any) (string, []any) {
	sql := ` AND ` + observedEvidenceSQL("far")
	if f.from != nil {
		sql += ` AND e0.observed_at >= ?`
		args = append(args, *f.from)
	}
	if f.to != nil {
		sql += ` AND e0.observed_at <= ?`
		args = append(args, *f.to)
	}
	if f.action != "" {
		sql += ` AND e0.action = ?`
		args = append(args, f.action)
	}
	if f.outcome != "" {
		sql += ` AND e0.outcome = ?`
		args = append(args, f.outcome)
	}
	if f.runtime != nil {
		sql += ` AND e0.runtime_instance_id = ?`
		args = append(args, *f.runtime)
	}
	if f.hasAttr {
		sql += ` AND e0.attribution = ?`
		args = append(args, f.attribution)
	}
	return sql, args
}

func (q *Query) observedGroups(workload uuid.UUID, f observedFilter, limit int) ([]ObservedAccessGroup, error) {
	args := []any{q.WS, workload}
	extra, args := f.where(args)
	args = append(args, limit)
	var rows []struct {
		ResourceID  uuid.UUID
		Action      string
		Outcome     string
		Attribution string
		N           int64
		FirstAt     time.Time
		LastAt      time.Time
		Phase       string
		Result      string
		Source      string
	}
	err := q.DB().Raw(`SELECT e0.resource_id, e0.action, e0.outcome, e0.attribution,
		count(*) AS n, min(e0.observed_at) AS first_at, max(e0.observed_at) AS last_at,
		COALESCE(MAX(ra.phase), '') AS phase,
		COALESCE(MAX(ra.result), '') AS result,
		COALESCE(MAX(ra.source), '') AS source
		FROM iga_observed_access e0
		JOIN iga_resources far ON far.workspace_id = e0.workspace_id AND far.id = e0.resource_id
		LEFT JOIN iga_runtime_activity ra ON ra.workspace_id = e0.workspace_id
		  AND ra.workload_id = e0.workload_id AND ra.resource_id = e0.resource_id
		  AND ra.operation = e0.action AND ra.outcome = e0.outcome
		WHERE e0.workspace_id = ? AND e0.workload_id = ?`+extra+`
		GROUP BY e0.resource_id, e0.action, e0.outcome, e0.attribution
		ORDER BY max(e0.observed_at) DESC, e0.resource_id, e0.action, e0.outcome, e0.attribution
		LIMIT ?`, args...).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]ObservedAccessGroup, 0, len(rows))
	for _, row := range rows {
		out = append(out, ObservedAccessGroup{
			Resource: R(RefResource, row.ResourceID), Action: row.Action, Outcome: row.Outcome,
			Attribution: row.Attribution, Count: row.N, AccessClass: "observed",
			FirstObservedAt: TS(&row.FirstAt), LastObservedAt: TS(&row.LastAt),
			Phase: row.Phase, ResultDetail: row.Result, Source: row.Source,
		})
	}
	return out, nil
}

func (q *Query) observedEvents(workload uuid.UUID, f observedFilter, limit int, after time.Time, afterID uuid.UUID) ([]ObservedAccessEvent, bool, time.Time, uuid.UUID, error) {
	args := []any{q.WS, workload}
	extra, args := f.where(args)
	if afterID != uuid.Nil {
		extra += ` AND (e0.observed_at, e0.id) > (?, ?)`
		args = append(args, after, afterID)
	}
	args = append(args, limit+1)
	var rows []struct {
		ID                uuid.UUID
		ResourceID        uuid.UUID
		RuntimeInstanceID uuid.UUID
		Action            string
		Outcome           string
		Attribution       string
		ObservedAt        time.Time
		Phase             string
		Result            string
		Source            string
	}
	err := q.DB().Raw(`SELECT e0.id, e0.resource_id, e0.runtime_instance_id, e0.action, e0.outcome,
		e0.attribution, e0.observed_at,
		COALESCE(ra.phase, '') AS phase,
		COALESCE(ra.result, '') AS result,
		COALESCE(ra.source, '') AS source
		FROM iga_observed_access e0
		JOIN iga_resources far ON far.workspace_id = e0.workspace_id AND far.id = e0.resource_id
		LEFT JOIN LATERAL (
			SELECT ra2.phase, ra2.result, ra2.source
			FROM iga_runtime_activity ra2
			WHERE ra2.workspace_id = e0.workspace_id
			  AND ra2.workload_id = e0.workload_id
			  AND ra2.resource_id = e0.resource_id
			  AND ra2.operation = e0.action
			  AND ra2.outcome = e0.outcome
			  AND ra2.observed_at = e0.observed_at
			LIMIT 1
		) ra ON TRUE
		WHERE e0.workspace_id = ? AND e0.workload_id = ?`+extra+`
		ORDER BY e0.observed_at, e0.id
		LIMIT ?`, args...).Scan(&rows).Error
	if err != nil {
		return nil, false, time.Time{}, uuid.Nil, err
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]ObservedAccessEvent, 0, len(rows))
	var lastAt time.Time
	var lastID uuid.UUID
	for _, row := range rows {
		out = append(out, ObservedAccessEvent{
			Ref: "observed_access:" + row.ID.String(), Resource: R(RefResource, row.ResourceID),
			RuntimeInstance: R(runtimeRef, row.RuntimeInstanceID), Action: row.Action, Outcome: row.Outcome,
			Attribution: row.Attribution, ObservedAt: TS(&row.ObservedAt), AccessClass: "observed",
			Phase: row.Phase, ResultDetail: row.Result, Source: row.Source,
		})
		lastAt, lastID = row.ObservedAt, row.ID
	}
	return out, more, lastAt, lastID, nil
}

func (q *Query) observedBindings(identity uuid.UUID) ([]ObservedBinding, error) {
	var rows []struct {
		ID          uuid.UUID
		RuntimeID   uuid.UUID
		WorkloadID  uuid.UUID
		BindingKind string
		Basis       string
		ValidFrom   time.Time
		ValidTo     *time.Time
	}
	err := q.DB().Raw(`SELECT b.id, b.runtime_instance_id AS runtime_id, ri.workload_id,
		b.binding_kind, b.basis, b.valid_from, b.valid_to
		FROM iga_runtime_identity_bindings b
		JOIN iga_runtime_instances ri ON ri.workspace_id = b.workspace_id AND ri.id = b.runtime_instance_id
		WHERE b.workspace_id = ? AND b.identity_account_id = ?
		ORDER BY b.valid_from, b.id`, q.WS, identity).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]ObservedBinding, 0, len(rows))
	for _, row := range rows {
		out = append(out, ObservedBinding{
			Ref: "runtime_binding:" + row.ID.String(), RuntimeInstance: R(runtimeRef, row.RuntimeID),
			Workload: R(RefWorkload, row.WorkloadID), BindingKind: row.BindingKind, Basis: row.Basis,
			ValidFrom: TS(&row.ValidFrom), ValidTo: TS(row.ValidTo),
		})
	}
	return out, nil
}

func (q *Query) observedGroupsForIdentity(identity uuid.UUID) ([]ObservedAccessGroup, error) {
	var rows []struct {
		ResourceID  uuid.UUID
		Action      string
		Outcome     string
		Attribution string
		N           int64
		FirstAt     time.Time
		LastAt      time.Time
	}
	err := q.DB().Raw(`SELECT e0.resource_id, e0.action, e0.outcome, e0.attribution,
		count(*) AS n, min(e0.observed_at) AS first_at, max(e0.observed_at) AS last_at
		FROM iga_observed_access e0
		JOIN iga_resources far ON far.workspace_id = e0.workspace_id AND far.id = e0.resource_id
		WHERE e0.workspace_id = ? AND e0.identity_account_id = ? AND `+observedEvidenceSQL("far")+`
		GROUP BY e0.resource_id, e0.action, e0.outcome, e0.attribution
		ORDER BY max(e0.observed_at) DESC, e0.resource_id
		LIMIT ?`, q.WS, identity, runtimeDefault).Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]ObservedAccessGroup, 0, len(rows))
	for _, row := range rows {
		out = append(out, ObservedAccessGroup{
			Resource: R(RefResource, row.ResourceID), Action: row.Action, Outcome: row.Outcome,
			Attribution: row.Attribution, Count: row.N, AccessClass: "observed",
			FirstObservedAt: TS(&row.FirstAt), LastObservedAt: TS(&row.LastAt),
		})
	}
	return out, nil
}
