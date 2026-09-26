package igaread

// GET /api/iga/v1/workloads/:id (SPEC-iga-phase2-graph.md §5.3 Agents &
// workloads, T6.3; D-2, D-3, D-4, D-5, D-6, D-32, D-63, D-73, D-83, D-85): the
// workload's list row, plus what only the detail shows -- its continuity, the
// provider's display facts, the connectors whose support rows hold it, and
// its latest classification decision. The two tabs are workload_identities.go
// and workload_resources.go; the pieces all three share are here.
//
// Every read of a request runs in ONE snapshot (Reader.Read). The id is this
// workspace's AWS workload with at least one support row, in ANY lifecycle
// (§5.2 "Retired objects", D-6). Anything else -- another workspace's id, a
// GitHub row, an AWS row no projection pass supported, a malformed id,
// another type's reference, or any id before the first publication (D-4) --
// is 404 not_found with no hint.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

/* ---------------------------------- shapes --------------------------------- */

// WorkloadProviderAttrs is the detail's provider_attrs (§5.3, D-85): an
// allowlist, never the raw jsonb. The projector writes these from the
// collected workload (igagraph workloadProviderAttrs); there is no read-side
// fallback to cloud_*. A fact the collector did not record for this kind is
// null (not applicable, or not collected -- including a list the latest scan
// could not read, never the list an earlier scan kept); an empty list is a
// collected answer. Environment variable NAMES only -- values are never
// collected.
type WorkloadProviderAttrs struct {
	Status          *string                   `json:"status"`
	FoundationModel *string                   `json:"foundation_model"`
	EnvVarNames     []string                  `json:"env_var_names"`
	GatewayTargets  []models.AWSGatewayTarget `json:"gateway_targets"`
}

// workloadProviderAttrsOf renders the stored provider_attrs through the D-85
// allowlist: keys outside it are dropped by decoding into the allowlist
// struct, so nothing the projector adds later leaks through unreviewed.
func workloadProviderAttrsOf(raw json.RawMessage) WorkloadProviderAttrs {
	var stored struct {
		Status          string                    `json:"status"`
		FoundationModel string                    `json:"foundation_model"`
		EnvVarNames     []string                  `json:"env_var_names"`
		GatewayTargets  []models.AWSGatewayTarget `json:"gateway_targets"`
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &stored)
	}
	return WorkloadProviderAttrs{
		Status:          strPtr(stored.Status),
		FoundationModel: strPtr(stored.FoundationModel),
		EnvVarNames:     stored.EnvVarNames,
		GatewayTargets:  stored.GatewayTargets,
	}
}

// WorkloadDetail is data of GET /workloads/:id: every list row field (the
// same builder, so a list row and the object it opens never disagree,
// §2.14.11), plus the detail's own.
//
// retired_reason is always present here (null while active) -- the list row
// omits it on active rows, and the detail must say why a retired object is
// retired (§5.2). decision is the latest classification decision in the shape
// the classification POST returns it as data.decision (§5.5), plus the
// decision value, or null when nobody has decided anything.
type WorkloadDetail struct {
	WorkloadRow
	RetiredReason *string               `json:"retired_reason"`
	Continuity    string                `json:"continuity"`
	ProviderAttrs WorkloadProviderAttrs `json:"provider_attrs"`
	// Sources is §5.3's "the connectors whose support rows hold it, with
	// state" in the SAME shape identity and resource details give it
	// (SupportSources): one entry per support row, as presence:<id>, with its
	// connector, that connector's account, its state and dates (D-98). Ended
	// supports are listed, not dropped: "A current, B ended" is E10's answer,
	// and a retired workload's sources say who last held it.
	Sources  []SupportSource `json:"sources"`
	Decision *LatestDecision `json:"decision"`
}

// WorkloadDetailMeta is the detail envelope's meta (§5.2) with the detail's
// coverage (D-73: the gaps of the object's own partitions).
type WorkloadDetailMeta struct {
	DetailMeta
	Coverage []CoverageNote `json:"coverage"`
}

// WorkloadDetailResponse is the whole GET /workloads/:id body. The handler
// sets Meta.Capabilities (can_classify, D-83): it depends on the caller's
// session, which this package does not see.
type WorkloadDetailResponse struct {
	Data WorkloadDetail     `json:"data"`
	Meta WorkloadDetailMeta `json:"meta"`
}

// Classification and Lifecycle are what can_classify is decided over, as the
// snapshot read them.
func (w *WorkloadDetailResponse) Classification() string { return w.Data.Classification }
func (w *WorkloadDetailResponse) Lifecycle() string      { return w.Data.Lifecycle }

// SetCanClassify states meta.capabilities.can_classify -- always stated,
// never absent (D-83).
func (w *WorkloadDetailResponse) SetCanClassify(can bool) {
	w.Meta.Capabilities = map[string]any{"can_classify": can}
}

/* ------------------------------ the route itself --------------------------- */

// WorkloadDetail serves GET /api/iga/v1/workloads/:id. rawID is the route
// parameter: a bare UUID or workload:<uuid> (D-5). The only query parameter
// is rev (§5.1); any other is 400 naming it (D-75).
func (r *Reader) WorkloadDetail(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (*WorkloadDetailResponse, error) {
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
	var out *WorkloadDetailResponse
	err := r.Read(ctx, ws, Pin{Rev: rev}, func(q *Query) error {
		if !q.Published() {
			return NotFound() // D-4: no object exists before the first publication
		}
		w, err := q.LoadWorkload(id)
		if err != nil {
			return err
		}
		if w == nil {
			return NotFound()
		}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}
		var stale *[]StaleReason
		if w.State == StateStale {
			reasons, err := NodeStaleReasons(q, accts, "workload_id", []StaleSubject{w.StaleSubject()})
			if err != nil {
				return err
			}
			stale = StaleReasonOf(w.State, w.ID, reasons)
		}
		sources, err := SupportSources(q, accts, "workload_id", w.ID)
		if err != nil {
			return err
		}
		decision, err := LatestClassification(q, w.ID)
		if err != nil {
			return err
		}
		nodes, err := q.workloadNodeParts(w.ID)
		if err != nil {
			return err
		}
		d := WorkloadDetail{
			WorkloadRow:   w.Row(accts, stale),
			RetiredReason: strPtr(w.RetiredReason),
			Continuity:    w.Continuity,
			ProviderAttrs: workloadProviderAttrsOf(w.ProviderAttrs),
			Sources:       sources,
			Decision:      decision,
		}
		out = &WorkloadDetailResponse{Data: d, Meta: WorkloadDetailMeta{
			DetailMeta: NewDetailMeta(q),
			// The detail shows the workload and its execution role: its node
			// partition and its executes_as partition.
			Coverage: q.workloadCoverage(accts, &w.WorkloadRecord, nodes, workloadCoverageScope{Execution: true}),
		}}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

/* ------------------------- pieces the tabs share too ------------------------ */

// WorkloadDetailRecord is one workload as a detail route reads it: the list
// row's columns, plus continuity and the stored provider_attrs.
type WorkloadDetailRecord struct {
	WorkloadRecord
	Continuity    string
	ProviderAttrs json.RawMessage
}

// LoadWorkload reads one workload for a detail route or tab in the snapshot:
// this workspace's, provider aws, with at least one support row (D-6), in any
// lifecycle. nil when there is none -- the caller answers 404, with no hint.
// It reads through WorkloadColumns / WorkloadFrom, the list row's own
// expressions.
func (q *Query) LoadWorkload(id uuid.UUID) (*WorkloadDetailRecord, error) {
	var rows []WorkloadDetailRecord
	if err := q.DB().Raw(`SELECT `+WorkloadColumns+`, w.continuity, w.provider_attrs
	                        FROM `+WorkloadFrom+`
	                       WHERE w.workspace_id = ? AND w.id = ? AND w.provider = 'aws'
	                         AND `+SupportedSQL("w", "workload_id"), q.WS, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// RouteParams is D-75 for a per-object route: every query parameter must be
// one the route defines; the first unknown one (in name order, so the answer
// is deterministic) is 400 invalid_parameter naming it.
func RouteParams(vals url.Values, allowed ...string) *Error {
	names := make([]string, 0, len(vals))
	for name := range vals {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !contains(allowed, name) && !isOptInParam(name) {
			return InvalidParameter(name, fmt.Sprintf("%s is not a parameter of this route", name))
		}
	}
	return nil
}

// ParseIncludeEnded reads include_ended (D-12): absent or false keeps a tab to
// current and stale rows; true adds ended ones, so the console can show "1
// current · 1 ended" (UI5). Anything else is 400.
func ParseIncludeEnded(vals url.Values) (bool, *Error) {
	switch strings.TrimSpace(vals.Get("include_ended")) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	}
	return false, InvalidParameter("include_ended", "include_ended must be true or false")
}

// EdgeStates is the edge lifecycle filter a tab reads with (§5.4, D-12):
// current and stale by default -- stale rows are returned and marked, never
// dropped -- and ended too when asked.
func EdgeStates(includeEnded bool) []string {
	if includeEnded {
		return []string{StateCurrent, StateStale, StateEnded}
	}
	return []string{StateCurrent, StateStale}
}

// IdentityBrief is how a tab names an identity at the far end of a claim:
// {ref, name, kind, arn, account} (§5.3 Identities tab).
type IdentityBrief struct {
	Ref     string   `json:"ref"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	ARN     string   `json:"arn"`
	Account *Account `json:"account"`
}

// workloadIdentityBriefOf renders an identity from its id, name, kind and source key.
// Its account is its ARN's (§2.14.10, D-3) -- never unknown for a collected
// identity.
func workloadIdentityBriefOf(accts *Accounts, id uuid.UUID, name, kind, sourceKey string) IdentityBrief {
	arn := NativeOfKey(sourceKey)
	return IdentityBrief{Ref: R(RefIdentity, id), Name: name, Kind: kind, ARN: arn, Account: accts.Of(ARNAccount(arn))}
}

// PolicyBrief names the policy a statement belongs to: {ref, name, kind}
// (kind aws_managed | customer_managed | inline).
type PolicyBrief struct {
	Ref  string `json:"ref"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// StatementBrief names one policy statement on a grant line: {ref, sid,
// index, actions, not_actions, conditional} (§5.3). index is 1-based (D-84);
// sid is "" for a Sid-less statement, never invented.
type StatementBrief struct {
	Ref         string   `json:"ref"`
	Sid         string   `json:"sid"`
	Index       *int     `json:"index"`
	Actions     []string `json:"actions"`
	NotActions  []string `json:"not_actions"`
	Conditional bool     `json:"conditional"`
}

// APIStatementIndex is the API's statement index (D-84): the stored 0-based
// statement_index plus one, converted here and nowhere else. Ordering uses the
// stored value. nil stays nil (a statement with no stored index).
func APIStatementIndex(stored *int) *int {
	if stored == nil {
		return nil
	}
	n := *stored + 1
	return &n
}

// StatementActions reads a statement's Action and NotAction lists from its
// stored native_rights -- the statement verbatim as AWS returned it, where
// either element may be a string or a list -- with the collector's own parser
// (awsdiscovery.ParsePolicyDocument), so the read side and the projector
// never disagree about what a statement says. native_rights written in the
// projector's fallback shape (models.NativeRights, when the verbatim bytes
// were missing) is read too. Both lists are non-nil ([] when absent).
// normalized_rights is NOT used: it holds Actions only.
func StatementActions(native json.RawMessage) (actions, notActions []string) {
	actions, notActions = []string{}, []string{}
	if len(native) == 0 {
		return
	}
	if sts, _, err := awsdiscovery.ParsePolicyDocument(`{"Statement":[` + string(native) + `]}`); err == nil && len(sts) == 1 &&
		(len(sts[0].Actions) > 0 || len(sts[0].NotActions) > 0) {
		return append(actions, sts[0].Actions...), append(notActions, sts[0].NotActions...)
	}
	var fb models.NativeRights
	if err := json.Unmarshal(native, &fb); err == nil {
		actions = append(actions, fb.Actions...)
		notActions = append(notActions, fb.NotActions...)
	}
	return
}
