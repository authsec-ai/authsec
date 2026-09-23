package igaread

// GET /api/iga/v1/evidence?claim=<claim or object ref>[&claim=...][&include=raw][&rev=N]
// (SPEC-iga-phase2-graph.md §5.3 Evidence, §2.14.7 "The Evidence panel", T6.5;
// P2-DECISIONS D-20..D-24, D-65, D-66, D-79, D-80): why does the product claim
// this?
//
// Five parts, in the panel's order: the claim and its sentence; the four
// status dimensions (§2.14.9); the supporting facts; freshness; limitations
// (limitations.go). Everything is read in ONE snapshot (§5.1) -- the claim's
// rows, its evidence junctions and observations, its coverage -- one query per
// claim or edge type, never per row (§5.6).
//
// A claim is one of (§5.2):
//
//	grant:<id>          iga_access_edges, provider aws, ALLOW statement only
//	assignment:<id>     iga_policy_assignment
//	relationship:<id>   iga_relationship (executes_as, task_execution_role,
//	                    member_of, can_assume)
//	target:<id>         iga_entitlement_target
//	presence:<id>       ONE iga_object_support row (D-65)
//	coverage:<run>:<s>  a run the current revision was built from (D-80)
//
// or an object ref -- workload, identity, resource, policy, statement,
// external_principal -- which means that object's presence: all its support
// rows (D-65), or for an external principal its can_assume edges (D-47, D-80).
//
// Facts (D-24) are the claim's junction rows (relation 'supports') whose
// observation existed at the claim's last confirming run and was still
// confirmed as of it (asOfRunSQL): an observation last confirmed by an EARLIER
// run of the claim's connector (an older policy version, a workload's earlier
// detail read) is dropped on read, because the junction is never pruned; one
// first recorded by a LATER run -- a run collected but not yet projected --
// is not the revision's (D-25). Only observations that bear on the claim type
// are kept (§4.8's table): a user's credential report is linked to every
// grant the user holds, and it proves none of them. Each fact carries the
// CLAIM's run and confirmation time, never the observation's own, which
// collection stamps before publication. Sentences are composed from the claim
// rows, never from observation contents (which differ by collector) -- with
// one exception, a policy-version fact's version label, which is the version
// its own observation read, so the label and the raw record cannot disagree.
//
// A statement is described by its content as of the run in question
// (contentAsOf, evidence_content.go): a Sid-keyed statement's row carries its
// latest content, and an ended or stale grant -- or a support row of an
// account that has not re-read the policy since -- confirmed an earlier one.
//
// Targets have no junction (032/036 define three, D-66): a target's facts are
// its statement's policy-version observation. Presence has none either: an
// object's facts are its own observation per support row -- the identity's
// authorization-details entry, the workload's listing, the policy version --
// found by the observation's subject_native_id in that row's connector,
// confirmed as of that row's last run. A resource reference has no
// observation of its own (nothing enumerates resources): its facts are the
// policy versions of the statements that name it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// EvidenceMaxClaims bounds a repeated claim parameter (D-79).
const EvidenceMaxClaims = 50

// EffectiveAccessNotEvaluated is status.effective_access, always, this phase
// (D-20; §2.14.9 calls the same value "unknown").
const EffectiveAccessNotEvaluated = "not_evaluated"

// evidenceClaimTypes are the references /evidence accepts (§5.2, D-65).
var evidenceClaimTypes = []string{
	RefGrant, RefAssignment, RefRelationship, RefTarget, RefPresence, RefCoverage,
	RefWorkload, RefIdentity, RefExternalPrincipal, RefResource, RefPolicy, RefStatement,
}

// EvidenceData is one claim's evidence: the panel's five parts, and the raw
// record when include=raw asked for it.
type EvidenceData struct {
	Claim       EvidenceClaim     `json:"claim"`
	Status      EvidenceStatus    `json:"status"`
	Facts       []EvidenceFact    `json:"facts"`
	Freshness   EvidenceFreshness `json:"freshness"`
	Limitations []Limitation      `json:"limitations"`
	// Raw is null unless include=raw: then one entry per fact, aligned with
	// facts (D-80).
	Raw []EvidenceRaw `json:"raw"`
}

// EvidenceClaim is the claim and its one sentence (§2.14.8 wording).
type EvidenceClaim struct {
	Ref      string `json:"ref"`
	Sentence string `json:"sentence"`
}

// EvidenceStatus is the four dimensions (§2.14.9), as four separate facts.
// basis is null for a coverage claim, which no configuration declares.
type EvidenceStatus struct {
	Basis           any    `json:"basis"`
	Lifecycle       string `json:"lifecycle"`
	Collection      string `json:"collection"`
	EffectiveAccess string `json:"effective_access"`
}

// EvidenceFact is one supporting fact (§5.3): the call, the account and
// region, the run and time the CLAIM was last confirmed by (D-24), and a
// sentence. A policy-version fact also names the policy version, the
// statement (Sid and 1-based index, D-84) and the verbatim statement excerpt
// (§2.14.7 "for a grant the policy, Sid, statement index and the statement
// excerpt").
type EvidenceFact struct {
	SourceAPI        any              `json:"source_api"`
	AccountID        any              `json:"account_id"`
	Region           any              `json:"region"`
	ObservedInRun    any              `json:"observed_in_run"`
	LastConfirmedAt  any              `json:"last_confirmed_at"`
	Fact             string           `json:"fact"`
	PolicyVersion    *string          `json:"policy_version,omitempty"`
	StatementExcerpt json.RawMessage  `json:"statement_excerpt,omitempty"`
	Policy           *EvidencePolicy  `json:"policy,omitempty"`
	Statement        *EvidenceStmtRef `json:"statement,omitempty"`

	rank int
	obs  *uuid.UUID
	raw  json.RawMessage
}

// EvidencePolicy names the policy a fact is about.
type EvidencePolicy struct {
	Ref  string `json:"ref"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// EvidenceStmtRef names the statement a fact is about: its Sid ("" when it
// has none) and its 1-based position in the policy (D-84).
type EvidenceStmtRef struct {
	Ref   string `json:"ref"`
	Sid   string `json:"sid"`
	Index *int   `json:"index"`
}

// EvidenceFreshness is first seen, last confirmed, and when stale, since when
// (D-23); valid_to and ended_reason for an ended claim (D-80, §2.14.5 "the
// panel opens on the ended claim with its valid_to and ended_reason").
type EvidenceFreshness struct {
	FirstSeenAt     any `json:"first_seen_at"`
	LastConfirmedAt any `json:"last_confirmed_at"`
	StaleSince      any `json:"stale_since"`
	ValidTo         any `json:"valid_to"`
	EndedReason     any `json:"ended_reason"`
}

// EvidenceRaw is one fact's stored record: the observation it came from and
// its sanitized_facts, redacted AT WRITE TIME by the observation writer and
// exposed through this authorized route only (§5.3). observation and
// sanitized_facts are null for a fact no observation carries (Access Advisor,
// coverage).
type EvidenceRaw struct {
	Observation    any             `json:"observation"`
	SourceAPI      any             `json:"source_api"`
	SanitizedFacts json.RawMessage `json:"sanitized_facts"`
}

// EvidenceMeta is the detail meta plus, for a request naming several claims,
// the summary sentence D-79 allows.
type EvidenceMeta struct {
	DetailMeta
	Summary *EvidenceSummary `json:"summary,omitempty"`
}

// EvidenceSummary is one sentence over every claim of the request -- only
// when every claim is a grant of the same holder with the same group_key
// (D-37, D-79): "SharedToolRole is granted s3:GetObject on support-tickets/*
// by 2 statements."
type EvidenceSummary struct {
	Sentence string `json:"sentence"`
}

// RefObservation names a cloud_observation row in a raw record.
const RefObservation = "cloud_observation"

/* ---------------------------------- route ---------------------------------- */

// Evidence serves GET /evidence. 400 for a missing, malformed or disallowed
// claim or parameter; 404 when any claim is not in this workspace (or is not
// a graph row: a GitHub row, a Deny statement as a grant, D-6) -- and when
// nothing is published (D-4: no claim exists before the first publication);
// 409 for a stale rev.
func (r *Reader) Evidence(ctx context.Context, ws uuid.UUID, vals url.Values) (any, error) {
	for name := range vals {
		switch name {
		case "claim", "include", "rev":
		default:
			return nil, InvalidParameter(name, name+" is not a parameter of /evidence")
		}
	}
	raws := vals["claim"]
	if len(raws) == 0 {
		return nil, InvalidParameter("claim", "claim is required")
	}
	if len(raws) > EvidenceMaxClaims {
		return nil, InvalidParameter("claim", fmt.Sprintf("at most %d claims per request", EvidenceMaxClaims))
	}
	refs := make([]Ref, 0, len(raws))
	for _, raw := range raws {
		ref, perr := ParseRefParam("claim", raw, evidenceClaimTypes...)
		if perr != nil {
			return nil, perr
		}
		refs = append(refs, ref)
	}
	includeRaw := false
	for _, inc := range vals["include"] {
		for _, part := range strings.Split(inc, ",") {
			switch strings.TrimSpace(part) {
			case "raw":
				includeRaw = true
			case "":
			default:
				return nil, InvalidParameter("include", "include accepts only raw")
			}
		}
	}
	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}

	var out Envelope
	err := r.Read(ctx, ws, Pin{Rev: rev}, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}
		claims, err := loadClaims(q, accts, refs, loadOpts{facts: true, raw: includeRaw})
		if err != nil {
			return err
		}
		ins := make([]*limInput, len(claims))
		for i, c := range claims {
			if c == nil {
				return NotFound()
			}
			ins[i] = &c.lim
		}
		lims, cov, err := computeLimitationsAndCoverage(q, accts, ins, nil)
		if err != nil {
			return err
		}
		if err := loadStaleSince(q, claims); err != nil {
			return err
		}
		data := make([]EvidenceData, len(claims))
		for i, c := range claims {
			data[i] = c.render(lims[i], cov.collection(i), includeRaw)
		}
		meta := EvidenceMeta{DetailMeta: NewDetailMeta(q)}
		if len(claims) == 1 {
			out = Envelope{Data: data[0], Meta: meta}
			return nil
		}
		meta.Summary = groupSummary(claims)
		out = Envelope{Data: data, Meta: meta}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ClaimLimitations computes, in this snapshot, the limitations of claims and
// objects named by refs -- the SAME computation /evidence uses (D-35), so an
// edge on the canvas and the evidence panel it opens never disagree. codes
// restricts the result (nil = every code; the graph routes pass
// FactFreeLimitations). A ref that is not a readable graph row in this
// workspace is absent from the result. Keyed by Ref.String().
func (q *Query) ClaimLimitations(accts *Accounts, refs []Ref, codes map[string]bool) (map[string][]Limitation, error) {
	claims, err := loadClaims(q, accts, refs, loadOpts{facts: codes == nil || codes[LimActivityAttemptsNotOutcomes]})
	if err != nil {
		return nil, err
	}
	var ins []*limInput
	var found []*evClaim
	for _, c := range claims {
		if c != nil {
			ins = append(ins, &c.lim)
			found = append(found, c)
		}
	}
	lims, err := computeLimitations(q, accts, ins, codes)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]Limitation, len(found))
	for i, c := range found {
		out[c.ref.String()] = lims[i]
	}
	return out, nil
}

// computeLimitations is the limitations of each input (limitations.go).
func computeLimitations(q *Query, accts *Accounts, ins []*limInput, codes map[string]bool) ([][]Limitation, error) {
	lims, _, err := computeLimitationsAndCoverage(q, accts, ins, codes)
	return lims, err
}

/* ------------------------------ claim model -------------------------------- */

// evClaim is one claim as loaded: what the five parts render from.
type evClaim struct {
	ref      Ref
	sentence string
	basis    any
	state    string

	firstSeen     *time.Time
	lastConfirmed *time.Time
	validTo       *time.Time
	endedReason   string

	// The D-23 anchor: the connector and last confirming run the claim's
	// staleness is dated from. For a node, the support row D-1 draws
	// last_confirmed_at from.
	anchorConnector *uuid.UUID
	anchorRun       *uuid.UUID
	staleSince      *time.Time

	lim      limInput
	facts    []EvidenceFact
	supports []evSupport // a presence claim's support rows

	// grouping (D-79): a grant's holder, the text of its actions and targets,
	// and its D-37 group key.
	holderID     uuid.UUID
	holderName   string
	actionsText  string
	targetsText  string
	groupKey     string
	isGrantClaim bool
}

type loadOpts struct {
	facts bool
	raw   bool
}

func (c *evClaim) render(lims []Limitation, collection string, includeRaw bool) EvidenceData {
	facts := c.facts
	sort.SliceStable(facts, func(i, j int) bool {
		if facts[i].rank != facts[j].rank {
			return facts[i].rank < facts[j].rank
		}
		if facts[i].Fact != facts[j].Fact {
			return facts[i].Fact < facts[j].Fact
		}
		return idStr(facts[i].obs) < idStr(facts[j].obs)
	})
	if facts == nil {
		facts = []EvidenceFact{}
	}
	d := EvidenceData{
		Claim: EvidenceClaim{Ref: c.ref.String(), Sentence: c.sentence},
		Status: EvidenceStatus{
			Basis: c.basis, Lifecycle: c.state, Collection: collection,
			EffectiveAccess: EffectiveAccessNotEvaluated,
		},
		Facts: facts,
		Freshness: EvidenceFreshness{
			FirstSeenAt: TS(c.firstSeen), LastConfirmedAt: TS(c.lastConfirmed),
			StaleSince: nil, ValidTo: nil, EndedReason: nil,
		},
		Limitations: lims,
	}
	if c.state == StateStale {
		d.Freshness.StaleSince = TS(c.staleSince)
	}
	if c.state == StateEnded {
		d.Freshness.ValidTo = TS(c.validTo)
		d.Freshness.EndedReason = nullIfBlank(c.endedReason)
	}
	if includeRaw {
		d.Raw = make([]EvidenceRaw, 0, len(facts))
		for _, f := range facts {
			e := EvidenceRaw{Observation: nil, SourceAPI: f.SourceAPI, SanitizedFacts: json.RawMessage("null")}
			if f.obs != nil {
				e.Observation = R(RefObservation, *f.obs)
				if len(f.raw) > 0 {
					e.SanitizedFacts = f.raw
				}
			}
			d.Raw = append(d.Raw, e)
		}
	}
	return d
}

func idStr(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// groupSummary is D-79's summary sentence, or nil: every claim a grant of one
// holder with one group key -- the canvas's grouped edge (§2.14.11).
func groupSummary(claims []*evClaim) *EvidenceSummary {
	if len(claims) < 2 {
		return nil
	}
	first := claims[0]
	for _, c := range claims {
		if !c.isGrantClaim || c.holderID != first.holderID || c.groupKey != first.groupKey {
			return nil
		}
	}
	distinct := map[string]bool{}
	for _, c := range claims {
		distinct[c.ref.String()] = true
	}
	if len(distinct) < 2 {
		return nil // one grant named twice is not a group
	}
	return &EvidenceSummary{Sentence: fmt.Sprintf("%s is granted %s on %s by %d statements.",
		first.holderName, first.actionsText, first.targetsText, len(distinct))}
}

// loadClaims loads every ref, in request order; a ref that is not a readable
// graph row of this workspace is nil. Each claim type is ONE query for all
// the refs of that type (§5.6).
func loadClaims(q *Query, accts *Accounts, refs []Ref, opts loadOpts) ([]*evClaim, error) {
	byType := map[string][]uuid.UUID{}
	var coverage []Ref
	for _, ref := range refs {
		if ref.Type == RefCoverage {
			coverage = append(coverage, ref)
			continue
		}
		byType[ref.Type] = append(byType[ref.Type], ref.ID)
	}
	l := &claimLoader{q: q, accts: accts, opts: opts, claims: map[string]*evClaim{}}
	steps := []struct {
		typ string
		fn  func([]uuid.UUID) error
	}{
		{RefGrant, l.grants},
		{RefAssignment, l.assignments},
		{RefRelationship, l.relationships},
		{RefTarget, l.targets},
		{RefPresence, l.presenceRows},
		{RefWorkload, l.objects(RefWorkload)},
		{RefIdentity, l.objects(RefIdentity)},
		{RefResource, l.objects(RefResource)},
		{RefPolicy, l.objects(RefPolicy)},
		{RefStatement, l.objects(RefStatement)},
		{RefExternalPrincipal, l.externalPrincipals},
	}
	for _, s := range steps {
		if ids := byType[s.typ]; len(ids) > 0 {
			if err := s.fn(uniqueIDs(ids)); err != nil {
				return nil, err
			}
		}
	}
	if err := l.coverage(coverage); err != nil {
		return nil, err
	}
	if opts.facts {
		if err := l.loadFacts(); err != nil {
			return nil, err
		}
	}
	out := make([]*evClaim, len(refs))
	for i, ref := range refs {
		out[i] = l.claims[ref.String()]
	}
	return out, nil
}

// claimLoader carries one request's loaded claims and the fact work they
// queue.
type claimLoader struct {
	q      *Query
	accts  *Accounts
	opts   loadOpts
	claims map[string]*evClaim

	// Fact work, run once per kind after every claim is loaded.
	junction   map[string][]junctionWant // edge table -> claims
	anchors    []obsAnchor
	usage      []usageWant
	namedByRes map[uuid.UUID][]*evClaim // resource presence claims, by resource
}

/* ---------------------------------- grants --------------------------------- */

type grantRow struct {
	ID              uuid.UUID
	State           string
	Basis           string
	ValidFrom       time.Time
	ValidTo         *time.Time
	EndedReason     string
	LastConfirmedAt time.Time
	LastConfirmedBy *uuid.UUID
	ConnectorID     *uuid.UUID
	PartitionKey    string
	AssignmentKind  string
	HolderID        uuid.UUID
	HolderName      string
	HolderKind      string
	HolderKey       string
	StatementRow
}

// StatementRow is the scan target of stmtColumns: a statement and its
// policy. Exported only because gorm skips the fields of an embedded
// unexported struct; nothing outside this package needs it.
type StatementRow struct {
	StatementID     uuid.UUID
	Sid             string
	StatementIndex  *int
	Effect          string
	Negated         bool
	Conditional     bool
	NativeRights    json.RawMessage
	PolicyID        uuid.UUID
	PolicyName      string
	PolicyKind      string
	PolicyNativeRef string
	PolicySourceKey string
}

// stmtColumns / stmtJoins read a statement (alias e) with its policy (p). No
// bind variables. They read the statement's CURRENT content; a claim or fact
// of an earlier run describes the content as of that run (contentAsOf), and a
// fact's policy version is its own observation's (obsRow.VersionID).
const stmtColumns = `e.id AS statement_id, e.sid, e.statement_index, e.effect, e.negated, e.conditional,
       e.native_rights, p.id AS policy_id, p.display_name AS policy_name, p.policy_kind,
       p.native_ref AS policy_native_ref, p.source_key AS policy_source_key`

const stmtJoins = `JOIN iga_policy p ON p.workspace_id = e.workspace_id AND p.id = e.policy_id AND p.provider = 'aws'`

func (s StatementRow) statement() *evStatement {
	return &evStatement{
		ID: s.StatementID, Sid: s.Sid, Index: s.StatementIndex, Effect: s.Effect,
		Negated: s.Negated, Conditional: s.Conditional, NativeRights: s.NativeRights,
		PolicyID: s.PolicyID, PolicyName: s.PolicyName, PolicyKind: s.PolicyKind,
		text: parseStatementText(s.NativeRights),
	}
}

// grants loads grant claims. EVERY grant read joins its statement with effect
// 'allow' (§3 rule 7): a projector defect can never surface a Deny as access
// -- such a row is simply not a readable grant (404).
//
// A grant is described -- sentence, targets, group key, limitations and the
// policy-version fact's excerpt -- by its statement's content as of the
// grant's last confirming run (contentAsOf): an ended grant, a stale one, or
// one whose account has not re-read a shared AWS-managed policy since another
// account saw it revised never claims the revised actions or targets.
func (l *claimLoader) grants(ids []uuid.UUID) error {
	var rows []grantRow
	if err := l.q.DB().Raw(`SELECT g.id, g.state, g.basis, g.valid_from, g.valid_to, g.ended_reason,
	                               g.last_confirmed_at, g.last_confirmed_by, g.connector_id, g.partition_key,
	                               pa.assignment_kind,
	                               ia.id AS holder_id, ia.display_name AS holder_name,
	                               ia.account_kind AS holder_kind, ia.source_key AS holder_key,
	                               `+stmtColumns+`
	                          FROM iga_access_edges g
	                          JOIN iga_identity_accounts ia
	                            ON ia.workspace_id = g.workspace_id AND ia.id = g.subject_identity_account_id
	                           AND ia.provider = 'aws'
	                          JOIN iga_policy_assignment pa ON pa.workspace_id = g.workspace_id AND pa.id = g.assignment_id
	                          JOIN iga_entitlements e ON e.workspace_id = g.workspace_id AND e.id = g.entitlement_id
	                           AND e.provider = 'aws' AND e.effect = ?
	                          `+stmtJoins+`
	                         WHERE g.workspace_id = ? AND g.provider = 'aws' AND g.id IN ?`,
		models.EffectAllow, l.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	stmtIDs := make([]uuid.UUID, 0, len(rows))
	wants := make([]contentWant, 0, len(rows))
	for _, r := range rows {
		stmtIDs = append(stmtIDs, r.StatementID)
		wants = append(wants, contentWant{stmt: r.StatementID, run: r.LastConfirmedBy, at: tptr(r.LastConfirmedAt)})
	}
	targets, err := loadTargets(l.q, stmtIDs)
	if err != nil {
		return err
	}
	asOf, err := contentAsOf(l.q, wants)
	if err != nil {
		return err
	}
	for i, r := range rows {
		st := r.statement()
		pos, excl := splitTargets(targets[r.StatementID])
		if h := asOf[i]; h != nil {
			st = h.applyTo(st)
			pos, excl = splitTargets(h.targets)
		}
		holder := r.HolderID
		c := &evClaim{
			ref: Ref{Type: RefGrant, ID: r.ID}, basis: r.Basis, state: r.State,
			firstSeen: tptr(r.ValidFrom), lastConfirmed: tptr(r.LastConfirmedAt),
			validTo: r.ValidTo, endedReason: r.EndedReason,
			anchorConnector: r.ConnectorID, anchorRun: r.LastConfirmedBy,
			holderID: r.HolderID, holderName: r.HolderName,
			actionsText: actionsPhrase(st.text), targetsText: targetsPhrase(pos, excl, true),
			groupKey: StatementGroupKey(st.text, targetIDs(pos), targetIDs(excl)), isGrantClaim: true,
		}
		if r.State == StateEnded {
			// §2.14.8: never "removed" -- the grant ended; and never in the
			// present tense, which would claim access the data no longer shows.
			c.sentence = fmt.Sprintf("%s was granted %s on %s by %s (statement %s); the grant ended.",
				r.HolderName, c.actionsText, c.targetsText, r.PolicyName, st.label())
		} else {
			c.sentence = fmt.Sprintf("%s is granted %s on %s by %s (statement %s).",
				r.HolderName, c.actionsText, c.targetsText, r.PolicyName, st.label())
		}
		named := resolvedTargets(pos)
		c.lim = limInput{
			grant: true, stmt: st, named: named, policyTargets: named,
			holder: &holder, holderKind: r.HolderKind,
			parts: partsOf(r.ConnectorID, r.PartitionKey), stale: r.State == StateStale, docProtected: true,
		}
		c.lim.endpoints = append(l.connectorEndpoints(r.ConnectorID), l.identityEndpoint(r.HolderKey))
		for _, t := range named {
			c.lim.endpoints = append(c.lim.endpoints, l.resourceEndpoint(t))
		}
		l.claims[c.ref.String()] = c
		l.wantJunction(tableAccessEvidence, c, r.ID, r.LastConfirmedBy, c.lastConfirmed, grantFactsFor(r, st, pos, excl))
	}
	return nil
}

// loadTargets reads the targets of statements, joined to their resource
// references, in their stored order.
func loadTargets(q *Query, stmtIDs []uuid.UUID) (map[uuid.UUID][]evTarget, error) {
	out := map[uuid.UUID][]evTarget{}
	if len(stmtIDs) == 0 {
		return out, nil
	}
	var rows []evTarget
	if err := q.DB().Raw(`SELECT t.id AS target_id, t.entitlement_id AS statement_id, t.target_mode AS mode, t.ordinal,
	                             r.id AS resource_id, r.display_name AS text, r.resource_kind,
	                             COALESCE(r.provider_attrs->>'reference', '') AS reference,
	                             `+ResourceAccountSQL+` AS account_id,
	                             `+ResourceAccountConnectedSQL+` AS account_connected
	                        FROM iga_entitlement_target t
	                        JOIN iga_resources r ON r.workspace_id = t.workspace_id AND r.id = t.resource_id
	                         AND r.provider = 'aws'
	                       WHERE t.workspace_id = ? AND t.entitlement_id IN ?
	                       ORDER BY t.entitlement_id, t.target_mode, t.ordinal, r.id`,
		q.WS, uniqueIDs(stmtIDs)).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, t := range rows {
		out[t.StatementID] = append(out[t.StatementID], t)
	}
	return out, nil
}

// splitTargets separates a statement's positive targets from its NotResource
// exclusions.
func splitTargets(ts []evTarget) (pos, excl []evTarget) {
	for _, t := range ts {
		if t.Mode == models.TargetNotResource {
			excl = append(excl, t)
		} else {
			pos = append(pos, t)
		}
	}
	return pos, excl
}

func targetIDs(ts []evTarget) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.ResourceID)
	}
	return out
}

/* ------------------------------- assignments ------------------------------- */

type assignmentRow struct {
	ID              uuid.UUID
	AssignmentKind  string
	Basis           string
	State           string
	ValidFrom       time.Time
	ValidTo         *time.Time
	EndedReason     string
	LastConfirmedAt time.Time
	LastConfirmedBy *uuid.UUID
	ConnectorID     *uuid.UUID
	PartitionKey    string
	HolderID        uuid.UUID
	HolderName      string
	HolderKind      string
	HolderKey       string
	PolicyID        uuid.UUID
	PolicyName      string
	PolicyKind      string
}

// assignments loads assignment claims. The policy-version fact names the
// version its own observation read (obsRow.VersionID) -- for an ended
// assignment the version it was last confirmed with, never the policy's
// current one.
func (l *claimLoader) assignments(ids []uuid.UUID) error {
	var rows []assignmentRow
	if err := l.q.DB().Raw(`SELECT pa.id, pa.assignment_kind, pa.basis, pa.state, pa.valid_from, pa.valid_to,
	                               pa.ended_reason, pa.last_confirmed_at, pa.last_confirmed_by,
	                               pa.connector_id, pa.partition_key,
	                               ia.id AS holder_id, ia.display_name AS holder_name,
	                               ia.account_kind AS holder_kind, ia.source_key AS holder_key,
	                               p.id AS policy_id, p.display_name AS policy_name, p.policy_kind
	                          FROM iga_policy_assignment pa
	                          JOIN iga_identity_accounts ia
	                            ON ia.workspace_id = pa.workspace_id AND ia.id = pa.holder_identity_account_id
	                           AND ia.provider = 'aws'
	                          JOIN iga_policy p ON p.workspace_id = pa.workspace_id AND p.id = pa.policy_id
	                           AND p.provider = 'aws'
	                         WHERE pa.workspace_id = ? AND pa.id IN ?`,
		l.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		c := &evClaim{
			ref: Ref{Type: RefAssignment, ID: r.ID}, basis: r.Basis, state: r.State,
			firstSeen: tptr(r.ValidFrom), lastConfirmed: tptr(r.LastConfirmedAt),
			validTo: r.ValidTo, endedReason: r.EndedReason,
			anchorConnector: r.ConnectorID, anchorRun: r.LastConfirmedBy,
		}
		c.sentence = assignmentSentence(r.AssignmentKind, r.PolicyName, r.HolderName, r.State == StateEnded) + "."
		c.lim = limInput{parts: partsOf(r.ConnectorID, r.PartitionKey), stale: r.State == StateStale}
		c.lim.endpoints = append(l.connectorEndpoints(r.ConnectorID), l.identityEndpoint(r.HolderKey))
		l.claims[c.ref.String()] = c
		pol := &EvidencePolicy{Ref: R(RefPolicy, r.PolicyID), Name: r.PolicyName, Kind: r.PolicyKind}
		l.wantJunction(tableAssignmentEvidence, c, r.ID, r.LastConfirmedBy, c.lastConfirmed, func(kind string, o obsRow) (EvidenceFact, bool) {
			switch {
			case isHolderEntry(kind):
				return EvidenceFact{Fact: holderAttachmentFact(r.AssignmentKind, r.HolderName, r.PolicyName), rank: 0}, true
			case kind == factPolicyVersion:
				return EvidenceFact{Fact: policyReadFact(r.PolicyName, o.VersionID), rank: 2,
					PolicyVersion: strPtr(o.VersionID), Policy: pol}, true
			}
			return EvidenceFact{}, false
		})
	}
	return nil
}

// assignmentSentence states an assignment; an ended one in the past tense,
// saying it ended (§2.14.8: "Removed" is never said).
func assignmentSentence(kind, policy, holder string, ended bool) string {
	if ended {
		switch kind {
		case models.CloudAttachmentInline:
			return fmt.Sprintf("%s was an inline policy of %s; the assignment ended", policy, holder)
		case models.CloudAttachmentBoundary:
			return fmt.Sprintf("%s was the permissions boundary of %s; the assignment ended", policy, holder)
		}
		return fmt.Sprintf("%s was attached to %s; the assignment ended", policy, holder)
	}
	switch kind {
	case models.CloudAttachmentInline:
		return fmt.Sprintf("%s is an inline policy of %s", policy, holder)
	case models.CloudAttachmentBoundary:
		return fmt.Sprintf("%s is the permissions boundary of %s", policy, holder)
	}
	return fmt.Sprintf("%s is attached to %s", policy, holder)
}

func holderAttachmentFact(kind, holder, policy string) string {
	switch kind {
	case models.CloudAttachmentInline:
		return fmt.Sprintf("%s has inline policy %s", holder, policy)
	case models.CloudAttachmentBoundary:
		return fmt.Sprintf("%s has %s as its permissions boundary", holder, policy)
	}
	return fmt.Sprintf("%s has %s attached", holder, policy)
}

func policyReadFact(policy, version string) string {
	if version == "" {
		return fmt.Sprintf("Policy %s was read", policy)
	}
	return fmt.Sprintf("Policy %s version %s was read", policy, version)
}

/* ------------------------------ relationships ------------------------------ */

type relationshipRow struct {
	ID                uuid.UUID
	RelationshipType  string
	Basis             string
	State             string
	ValidFrom         time.Time
	ValidTo           *time.Time
	EndedReason       string
	LastConfirmedAt   time.Time
	LastConfirmedBy   *uuid.UUID
	ConnectorID       *uuid.UUID
	PartitionKey      string
	StatementKey      string
	Conditions        json.RawMessage
	Mechanism         string
	SrcIdentityID     *uuid.UUID
	SrcIdentityName   *string
	SrcIdentityKey    *string
	SrcWorkloadID     *uuid.UUID
	SrcWorkloadName   *string
	SrcExternalID     *uuid.UUID
	EpIssuer          *string
	EpSubject         *string
	EpKind            *string
	TargetID          uuid.UUID
	TargetName        string
	TargetKey         string
	TrustNotPrincipal bool
	TrustNegated      json.RawMessage
}

// relationshipColumns / relationshipFrom read a relationship (alias r) with
// both endpoints and its target role's trust flags. No bind variables.
const relationshipColumns = `r.id, r.relationship_type, r.basis, r.state, r.valid_from, r.valid_to, r.ended_reason,
       r.last_confirmed_at, r.last_confirmed_by, r.connector_id, r.partition_key, r.statement_key,
       r.conditions, r.mechanism,
       si.id AS src_identity_id, si.display_name AS src_identity_name, si.source_key AS src_identity_key,
       sw.id AS src_workload_id, sw.display_name AS src_workload_name,
       ep.id AS src_external_id, ep.issuer AS ep_issuer, ep.subject_claim AS ep_subject, ep.mechanism AS ep_kind,
       t.id AS target_id, t.display_name AS target_name, t.source_key AS target_key,
       COALESCE(t.provider_attrs->>'` + igagraph.TrustHasNotPrincipalAttr + `' = 'true', false) AS trust_not_principal,
       COALESCE(t.provider_attrs->'` + igagraph.TrustNegatedStatementsAttr + `', '[]'::jsonb) AS trust_negated`

const relationshipFrom = `iga_relationship r
  JOIN iga_identity_accounts t ON t.workspace_id = r.workspace_id AND t.id = r.target_identity_account_id
   AND t.provider = 'aws'
  LEFT JOIN iga_identity_accounts si ON si.workspace_id = r.workspace_id AND si.id = r.source_identity_account_id
  LEFT JOIN iga_workload sw ON sw.workspace_id = r.workspace_id AND sw.id = r.source_workload_id
  LEFT JOIN iga_external_principal ep ON ep.workspace_id = r.workspace_id AND ep.id = r.source_external_principal_id`

func (l *claimLoader) relationships(ids []uuid.UUID) error {
	var rows []relationshipRow
	if err := l.q.DB().Raw(`SELECT `+relationshipColumns+` FROM `+relationshipFrom+`
	                         WHERE r.workspace_id = ? AND r.id IN ?`, l.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		r := r
		c := &evClaim{
			ref: Ref{Type: RefRelationship, ID: r.ID}, basis: r.Basis, state: r.State,
			firstSeen: tptr(r.ValidFrom), lastConfirmed: tptr(r.LastConfirmedAt),
			validTo: r.ValidTo, endedReason: r.EndedReason,
			anchorConnector: r.ConnectorID, anchorRun: r.LastConfirmedBy,
		}
		src := r.sourceLabel()
		c.sentence = relationshipSentence(r.RelationshipType, r.Mechanism, src, r.TargetName, r.State == StateEnded) + "."
		c.lim = limInput{relType: r.RelationshipType, parts: partsOf(r.ConnectorID, r.PartitionKey), stale: r.State == StateStale}
		c.lim.endpoints = append(l.connectorEndpoints(r.ConnectorID), l.identityEndpoint(r.TargetKey))
		if r.SrcIdentityKey != nil {
			c.lim.endpoints = append(c.lim.endpoints, l.identityEndpoint(*r.SrcIdentityKey))
		}
		if r.SrcExternalID != nil {
			c.lim.endpoints = append(c.lim.endpoints, l.externalEndpoint(deref(r.EpKind), deref(r.EpSubject)))
		}
		if r.RelationshipType == models.RelTypeCanAssume {
			c.lim.trustConditions = r.Conditions
			c.lim.trustStatementKey = r.StatementKey
			c.lim.trustNotPrincipal = r.TrustNotPrincipal
			_ = json.Unmarshal(r.TrustNegated, &c.lim.trustNegated)
		}
		l.claims[c.ref.String()] = c
		l.wantJunction(tableRelationshipEvidence, c, r.ID, r.LastConfirmedBy, c.lastConfirmed, relationshipFactsFor(r, src))
	}
	return nil
}

func (r relationshipRow) sourceLabel() string {
	switch {
	case r.SrcIdentityName != nil:
		return *r.SrcIdentityName
	case r.SrcWorkloadName != nil:
		return *r.SrcWorkloadName
	case r.SrcExternalID != nil:
		return ExternalPrincipalLabel(deref(r.EpKind), deref(r.EpIssuer), deref(r.EpSubject))
	}
	return "an unknown principal"
}

// relationshipSentence uses the §2.14.11 edge labels: "configured to run as",
// "may assume" -- never "can access" or "uses". An ended relationship is
// stated in the past tense and says it ended: the present tense would claim a
// configuration the data no longer shows.
func relationshipSentence(relType, mechanism, source, target string, ended bool) string {
	if ended {
		switch relType {
		case models.RelTypeExecutesAs:
			return fmt.Sprintf("%s was configured to run as %s; the relationship ended", source, target)
		case models.RelTypeTaskExecutionRole:
			return fmt.Sprintf("%s was configured with %s as its task execution role; the relationship ended", source, target)
		case models.RelTypeMemberOf:
			return fmt.Sprintf("%s was a member of %s; the membership ended", source, target)
		case models.RelTypeCanAssume:
			if mechanism == models.MechanismEKSPodIdentity {
				return fmt.Sprintf("An EKS Pod Identity association named %s for %s; the relationship ended", source, target)
			}
			return fmt.Sprintf("The trust policy of %s named %s; the relationship ended", target, source)
		}
		return fmt.Sprintf("%s was related to %s; the relationship ended", source, target)
	}
	switch relType {
	case models.RelTypeExecutesAs:
		return fmt.Sprintf("%s is configured to run as %s", source, target)
	case models.RelTypeTaskExecutionRole:
		return fmt.Sprintf("%s is configured with %s as its task execution role", source, target)
	case models.RelTypeMemberOf:
		return fmt.Sprintf("%s is a member of %s", source, target)
	case models.RelTypeCanAssume:
		if mechanism == models.MechanismEKSPodIdentity {
			return fmt.Sprintf("%s may assume %s through an EKS Pod Identity association", source, target)
		}
		return fmt.Sprintf("%s may assume %s", source, target)
	}
	return fmt.Sprintf("%s is related to %s", source, target)
}

func relationshipFactsFor(r relationshipRow, src string) factMaker {
	return func(kind string, _ obsRow) (EvidenceFact, bool) {
		switch r.RelationshipType {
		case models.RelTypeExecutesAs:
			if kind == factWorkload {
				return EvidenceFact{Fact: fmt.Sprintf("%s is configured to run as %s", src, r.TargetName)}, true
			}
		case models.RelTypeTaskExecutionRole:
			if kind == factWorkload {
				return EvidenceFact{Fact: fmt.Sprintf("%s names %s as its task execution role", src, r.TargetName)}, true
			}
		case models.RelTypeMemberOf:
			if kind == factUserEntry {
				return EvidenceFact{Fact: fmt.Sprintf("The entry of %s lists group %s", src, r.TargetName)}, true
			}
		case models.RelTypeCanAssume:
			switch kind {
			case factRoleEntry:
				return EvidenceFact{Fact: fmt.Sprintf("The trust policy of %s names %s", r.TargetName, src)}, true
			case factPodAssociation:
				return EvidenceFact{Fact: fmt.Sprintf("An EKS Pod Identity association names %s for %s", src, r.TargetName), rank: 1}, true
			}
		}
		return EvidenceFact{}, false
	}
}

/* ---------------------------------- targets -------------------------------- */

type targetClaimRow struct {
	TargetID         uuid.UUID
	Mode             string
	Ordinal          int
	ResourceID       uuid.UUID
	Text             string
	ResourceKind     string
	Reference        string
	AccountID        string
	AccountConnected bool
	StatementRow
}

// targets loads target claims: "statement names resource". A target row has
// no lifecycle or times of its own; they are its statement's (the target set
// is rewritten with the statement's content, §4.9), and its facts are its
// statement's policy-version observation per support row (D-66).
//
// The claim is the CURRENT content's: a target row exists only while the
// statement's latest content names it, and D-1's anchor -- the latest
// confirmation of any support row -- is the run that wrote that content (every
// projection that reads the statement confirms its support). Each FACT,
// though, is one support row's run, which may have read an earlier content (an
// account that has not re-read a shared AWS-managed policy since another
// account saw it revised): that fact stands only if the content as of its run
// named the target (obsAnchor.names), and quotes that content.
func (l *claimLoader) targets(ids []uuid.UUID) error {
	var rows []targetClaimRow
	if err := l.q.DB().Raw(`SELECT t.id AS target_id, t.target_mode AS mode, t.ordinal,
	                               r.id AS resource_id, r.display_name AS text, r.resource_kind,
	                               COALESCE(r.provider_attrs->>'reference', '') AS reference,
	                               `+ResourceAccountSQL+` AS account_id,
	                               `+ResourceAccountConnectedSQL+` AS account_connected,
	                               `+stmtColumns+`
	                          FROM iga_entitlement_target t
	                          JOIN iga_resources r ON r.workspace_id = t.workspace_id AND r.id = t.resource_id
	                           AND r.provider = 'aws'
	                          JOIN iga_entitlements e ON e.workspace_id = t.workspace_id AND e.id = t.entitlement_id
	                           AND e.provider = 'aws'
	                          `+stmtJoins+`
	                         WHERE t.workspace_id = ? AND t.id IN ?`, l.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	stmtIDs := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		stmtIDs = append(stmtIDs, r.StatementID)
	}
	nodes, err := l.statementNodes(stmtIDs)
	if err != nil {
		return err
	}
	for _, r := range rows {
		st := r.statement()
		n := nodes[r.StatementID]
		if n == nil {
			continue // a statement no support row stands behind is not a graph row (D-6)
		}
		t := evTarget{TargetID: r.TargetID, StatementID: r.StatementID, Mode: r.Mode, Ordinal: r.Ordinal,
			ResourceID: r.ResourceID, Text: r.Text, ResourceKind: r.ResourceKind, Reference: r.Reference,
			AccountID: r.AccountID, AccountConnected: r.AccountConnected}
		c := &evClaim{ref: Ref{Type: RefTarget, ID: r.TargetID}, basis: models.BasisDeclared}
		n.applyTo(c)
		// The statement's content, which names this target, began with its
		// live revision (Sid-keyed) or with the statement itself (content-keyed).
		if n.revisionFrom != nil {
			c.firstSeen = n.revisionFrom
		}
		verb := "names"
		if t.Mode == models.TargetNotResource {
			verb = "excludes"
		}
		prefix := "Statement"
		if st.Effect == models.EffectDeny {
			prefix = "Deny statement"
		}
		obj := resourcePhrase(t.Text)
		if t.Mode == models.TargetNotResource {
			obj += " (NotResource)"
		}
		c.sentence = fmt.Sprintf("%s %s of %s %s %s.", prefix, st.label(), st.PolicyName, verb, obj)
		c.lim = limInput{stmt: st, named: []evTarget{t}, policyTargets: []evTarget{t},
			parts: n.parts(), stale: c.state == StateStale, docProtected: true}
		c.lim.endpoints = append(l.supportEndpoints(n.supports), l.resourceEndpoint(t))
		l.claims[c.ref.String()] = c
		pol := &EvidencePolicy{Ref: R(RefPolicy, st.PolicyID), Name: st.PolicyName, Kind: st.PolicyKind}
		fact := fmt.Sprintf("Statement %s of %s %s %s", st.label(), st.PolicyName, verb, t.Text)
		named := t
		l.wantPolicyObservations(c, n.supports, r.PolicyKind, r.PolicyNativeRef, r.PolicySourceKey, st, &named,
			func(o obsRow, st *evStatement) EvidenceFact {
				return EvidenceFact{Fact: fact, rank: 2, PolicyVersion: strPtr(o.VersionID),
					StatementExcerpt: excerpt(st.NativeRights), Policy: pol, Statement: stmtRef(st)}
			})
	}
	return nil
}

/* ----------------------------------- nodes --------------------------------- */

// evSupport is one iga_object_support row.
type evSupport struct {
	ID                 uuid.UUID
	NodeID             uuid.UUID
	ConnectorID        uuid.UUID
	PartitionKey       string
	State              string
	FirstSeenAt        time.Time
	LastConfirmedRunID *uuid.UUID
	LastConfirmedAt    *time.Time
	EndedReason        string
}

// evNode is a node's presence: its support rows and what D-1 derives from
// them.
type evNode struct {
	id            uuid.UUID
	firstSeen     time.Time
	lifecycle     string
	retiredReason string
	supports      []evSupport
	revisionFrom  *time.Time
	retiredAt     *time.Time
}

// d1 is D-1 over the node's support rows: current if any is current, else
// stale if any is stale, else ended; last_confirmed_at the latest; the anchor
// the row that time is drawn from.
func d1(ss []evSupport) (state string, last *time.Time, anchor *evSupport) {
	state = StateEnded
	for i := range ss {
		s := &ss[i]
		switch {
		case s.State == StateCurrent:
			state = StateCurrent
		case s.State == StateStale && state != StateCurrent:
			state = StateStale
		}
		if s.LastConfirmedAt != nil && (last == nil || s.LastConfirmedAt.After(*last) ||
			(s.LastConfirmedAt.Equal(*last) && s.ID.String() < anchor.ID.String())) {
			t := *s.LastConfirmedAt
			last, anchor = &t, s
		}
	}
	return state, last, anchor
}

// applyTo sets a presence-shaped claim's lifecycle, times and anchor.
func (n *evNode) applyTo(c *evClaim) {
	state, last, anchor := d1(n.supports)
	c.state, c.lastConfirmed = state, last
	c.firstSeen = tptr(n.firstSeen)
	if anchor != nil {
		conn := anchor.ConnectorID
		c.anchorConnector, c.anchorRun = &conn, anchor.LastConfirmedRunID
	}
	if state == StateEnded {
		c.validTo = n.retiredAt
		c.endedReason = n.retiredReason
		if c.endedReason == "" && len(n.supports) > 0 {
			c.endedReason = n.supports[0].EndedReason
		}
	}
}

// parts is every partition the node's LIVE support rows stand on (all of
// them when every row has ended, so an ended node still names its sources).
func (n *evNode) parts() []evPart {
	var out []evPart
	for _, s := range n.supports {
		if s.State != StateEnded {
			out = append(out, evPart{s.ConnectorID, s.PartitionKey})
		}
	}
	if len(out) == 0 {
		for _, s := range n.supports {
			out = append(out, evPart{s.ConnectorID, s.PartitionKey})
		}
	}
	return out
}

func loadSupports(q *Query, column string, ids []uuid.UUID) (map[uuid.UUID][]evSupport, error) {
	mustSupportColumn(column)
	out := map[uuid.UUID][]evSupport{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []evSupport
	if err := q.DB().Raw(`SELECT s.id, s.`+column+` AS node_id, s.connector_id, s.partition_key, s.state,
	                             s.first_seen_at, s.last_confirmed_run_id, s.last_confirmed_at, s.ended_reason
	                        FROM iga_object_support s
	                       WHERE s.workspace_id = ? AND s.`+column+` IN ?
	                       ORDER BY s.connector_id, s.id`, q.WS, uniqueIDs(ids)).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, s := range rows {
		out[s.NodeID] = append(out[s.NodeID], s)
	}
	return out, nil
}

// retiredAt is when each retired node's latest retirement was recorded
// (iga_lifecycle_event, 036): an ended presence's valid_to.
func retiredAt(q *Query, column string, ids []uuid.UUID) (map[uuid.UUID]time.Time, error) {
	mustSupportColumn(column)
	out := map[uuid.UUID]time.Time{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []struct {
		NodeID uuid.UUID
		At     time.Time
	}
	if err := q.DB().Raw(`SELECT le.`+column+` AS node_id, max(le.occurred_at) AS at
	                        FROM iga_lifecycle_event le
	                       WHERE le.workspace_id = ? AND le.event = ? AND le.`+column+` IN ?
	                       GROUP BY le.`+column,
		q.WS, models.LifecycleRetired, uniqueIDs(ids)).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.NodeID] = r.At
	}
	return out, nil
}

// nodeRow is a node as the presence loaders read it; kind is the class's
// own kind column, region a workload's.
type nodeRow struct {
	ID               uuid.UUID
	Name             string
	Kind             string
	SourceKey        string
	Region           string
	Lifecycle        string
	RetiredReason    string
	FirstSeenAt      time.Time
	NativeRef        string
	Reference        string
	AccountID        string
	AccountConnected bool
	StatementRow
}

// nodeSpec is how each object class is read for presence.
type nodeSpec struct {
	column string // iga_object_support column
	sql    string // SELECT ... WHERE n.workspace_id = ? AND n.id IN ?, aliased as nodeRow
}

var nodeSpecs = map[string]nodeSpec{
	RefWorkload: {"workload_id", `SELECT n.id, n.display_name AS name, n.runtime_kind AS kind, n.source_key, n.region,
	                                     n.lifecycle, n.retired_reason, n.first_seen_at
	                                FROM iga_workload n
	                               WHERE n.workspace_id = ? AND n.id IN ? AND n.provider = 'aws'`},
	RefIdentity: {"identity_account_id", `SELECT n.id, n.display_name AS name, n.account_kind AS kind, n.source_key,
	                                             n.lifecycle, n.retired_reason, n.first_seen_at
	                                        FROM iga_identity_accounts n
	                                       WHERE n.workspace_id = ? AND n.id IN ? AND n.provider = 'aws'`},
	RefResource: {"resource_id", `SELECT r.id, r.display_name AS name, r.resource_kind AS kind, r.source_key,
	                                     r.lifecycle, r.retired_reason, r.first_seen_at,
	                                     COALESCE(r.provider_attrs->>'reference', '') AS reference,
	                                     ` + ResourceAccountSQL + ` AS account_id,
	                                     ` + ResourceAccountConnectedSQL + ` AS account_connected
	                                FROM iga_resources r
	                               WHERE r.workspace_id = ? AND r.id IN ? AND r.provider = 'aws'`},
	RefPolicy: {"policy_id", `SELECT n.id, n.display_name AS name, n.policy_kind AS kind, n.source_key,
	                                 n.lifecycle, n.retired_reason, n.first_seen_at, n.native_ref
	                            FROM iga_policy n
	                           WHERE n.workspace_id = ? AND n.id IN ? AND n.provider = 'aws'`},
	RefStatement: {"entitlement_id", `SELECT e.id, e.lifecycle, e.retired_reason, e.first_seen_at, ` + stmtColumns + `
	                                    FROM iga_entitlements e
	                                    ` + stmtJoins + `
	                                   WHERE e.workspace_id = ? AND e.id IN ? AND e.provider = 'aws'`},
}

// loadNodes reads nodes of one class with their support rows. A node with no
// support row at all is not a graph row (D-6) and is absent.
func (l *claimLoader) loadNodes(refType string, ids []uuid.UUID) (map[uuid.UUID]*nodeRow, map[uuid.UUID]*evNode, error) {
	spec := nodeSpecs[refType]
	var rows []nodeRow
	if err := l.q.DB().Raw(spec.sql, l.q.WS, ids).Scan(&rows).Error; err != nil {
		return nil, nil, err
	}
	found := make([]uuid.UUID, 0, len(rows))
	var retired []uuid.UUID
	for _, r := range rows {
		found = append(found, r.ID)
		if r.Lifecycle == models.IGALifecycleRetired {
			retired = append(retired, r.ID)
		}
	}
	sup, err := loadSupports(l.q, spec.column, found)
	if err != nil {
		return nil, nil, err
	}
	at, err := retiredAt(l.q, spec.column, retired)
	if err != nil {
		return nil, nil, err
	}
	var revs map[uuid.UUID]time.Time
	if refType == RefStatement {
		if revs, err = revisionStarts(l.q, found); err != nil {
			return nil, nil, err
		}
	}
	rowsBy, nodes := map[uuid.UUID]*nodeRow{}, map[uuid.UUID]*evNode{}
	for i := range rows {
		r := &rows[i]
		if len(sup[r.ID]) == 0 {
			continue
		}
		n := &evNode{id: r.ID, firstSeen: r.FirstSeenAt, lifecycle: r.Lifecycle, retiredReason: r.RetiredReason, supports: sup[r.ID]}
		if t, ok := at[r.ID]; ok {
			n.retiredAt = tptr(t)
		}
		if t, ok := revs[r.ID]; ok {
			n.revisionFrom = tptr(t)
		}
		rowsBy[r.ID], nodes[r.ID] = r, n
	}
	return rowsBy, nodes, nil
}

// revisionStarts is when each statement's live revision began (Sid-keyed
// statements only; a content-keyed statement's content began with it).
func revisionStarts(q *Query, ids []uuid.UUID) (map[uuid.UUID]time.Time, error) {
	out := map[uuid.UUID]time.Time{}
	if len(ids) == 0 {
		return out, nil
	}
	var rows []struct {
		EntitlementID uuid.UUID
		ValidFrom     time.Time
	}
	if err := q.DB().Raw(`SELECT sr.entitlement_id, sr.valid_from FROM iga_statement_revision sr
	                       WHERE sr.workspace_id = ? AND sr.entitlement_id IN ? AND sr.valid_to IS NULL`,
		q.WS, uniqueIDs(ids)).Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.EntitlementID] = r.ValidFrom
	}
	return out, nil
}

// statementNodes is the presence of statements (for target claims).
func (l *claimLoader) statementNodes(ids []uuid.UUID) (map[uuid.UUID]*evNode, error) {
	if len(ids) == 0 {
		return map[uuid.UUID]*evNode{}, nil
	}
	_, nodes, err := l.loadNodes(RefStatement, uniqueIDs(ids))
	return nodes, err
}

// objects loads object refs of one class as presence claims over all their
// support rows (D-65).
func (l *claimLoader) objects(refType string) func([]uuid.UUID) error {
	return func(ids []uuid.UUID) error {
		rows, nodes, err := l.loadNodes(refType, ids)
		if err != nil {
			return err
		}
		for id, n := range nodes {
			l.presence(Ref{Type: refType, ID: id}, refType, rows[id], n)
		}
		return nil
	}
}

// presenceRows loads presence:<support row id> claims: ONE support row's
// claim that its object exists in that source (D-65).
func (l *claimLoader) presenceRows(ids []uuid.UUID) error {
	var rows []struct {
		ID                uuid.UUID
		IdentityAccountID *uuid.UUID
		WorkloadID        *uuid.UUID
		ResourceID        *uuid.UUID
		EntitlementID     *uuid.UUID
		PolicyID          *uuid.UUID
	}
	if err := l.q.DB().Raw(`SELECT s.id, s.identity_account_id, s.workload_id, s.resource_id, s.entitlement_id, s.policy_id
	                          FROM iga_object_support s WHERE s.workspace_id = ? AND s.id IN ?`,
		l.q.WS, ids).Scan(&rows).Error; err != nil {
		return err
	}
	byType := map[string]map[uuid.UUID][]uuid.UUID{} // class -> node -> support rows asked for
	for _, r := range rows {
		typ, node := "", (*uuid.UUID)(nil)
		switch {
		case r.IdentityAccountID != nil:
			typ, node = RefIdentity, r.IdentityAccountID
		case r.WorkloadID != nil:
			typ, node = RefWorkload, r.WorkloadID
		case r.ResourceID != nil:
			typ, node = RefResource, r.ResourceID
		case r.EntitlementID != nil:
			typ, node = RefStatement, r.EntitlementID
		case r.PolicyID != nil:
			typ, node = RefPolicy, r.PolicyID
		default:
			continue
		}
		if byType[typ] == nil {
			byType[typ] = map[uuid.UUID][]uuid.UUID{}
		}
		byType[typ][*node] = append(byType[typ][*node], r.ID)
	}
	for typ, want := range byType {
		ids := make([]uuid.UUID, 0, len(want))
		for id := range want {
			ids = append(ids, id)
		}
		rows, nodes, err := l.loadNodes(typ, ids)
		if err != nil {
			return err
		}
		for nodeID, supportIDs := range want {
			n := nodes[nodeID]
			if n == nil {
				continue
			}
			for _, sid := range supportIDs {
				one := *n
				one.supports = nil
				for _, s := range n.supports {
					if s.ID == sid {
						one.supports = []evSupport{s}
					}
				}
				if len(one.supports) == 0 {
					continue
				}
				// A single support row's own freshness: when THIS source
				// first and last supported it.
				one.firstSeen = one.supports[0].FirstSeenAt
				if one.supports[0].State == StateEnded {
					one.retiredReason = one.supports[0].EndedReason
				}
				l.presence(Ref{Type: RefPresence, ID: sid}, typ, rows[nodeID], &one)
			}
		}
	}
	return nil
}

// presence builds one presence claim for a node of class refType.
func (l *claimLoader) presence(ref Ref, refType string, row *nodeRow, n *evNode) {
	c := &evClaim{ref: ref, basis: models.BasisDeclared, supports: n.supports}
	n.applyTo(c)
	name := nodeLabel(refType, row)
	sources := l.sourceLabels(n.supports)
	switch {
	case c.state == StateEnded:
		c.sentence = fmt.Sprintf("%s is no longer present in any scan.", name)
	case strings.Contains(sources, " and "):
		c.sentence = fmt.Sprintf("%s is present in the scans of %s.", name, sources)
	default:
		c.sentence = fmt.Sprintf("%s is present in the scan of %s.", name, sources)
	}
	c.lim = limInput{parts: n.parts(), stale: c.state == StateStale}
	c.lim.endpoints = l.supportEndpoints(n.supports)
	switch refType {
	case RefIdentity:
		c.lim.endpoints = append(c.lim.endpoints, l.identityEndpoint(row.SourceKey))
		l.wantIdentityObservations(c, n.supports, row)
	case RefWorkload:
		l.wantWorkloadObservations(c, n.supports, row)
	case RefResource:
		t := evTarget{ResourceID: row.ID, Text: row.Name, ResourceKind: row.Kind, Reference: row.Reference,
			AccountID: row.AccountID, AccountConnected: row.AccountConnected}
		c.lim.named = []evTarget{t}
		c.lim.endpoints = append(c.lim.endpoints, l.resourceEndpoint(t))
		c.lim.docProtected = true
		l.wantResourceNamers(c, row.ID)
	case RefPolicy:
		// Each support row's fact names the version ITS observation read.
		c.lim.docProtected = true
		pol := &EvidencePolicy{Ref: R(RefPolicy, row.ID), Name: row.Name, Kind: row.Kind}
		l.wantPolicyObservations(c, n.supports, row.Kind, row.NativeRef, row.SourceKey, nil, nil,
			func(o obsRow, _ *evStatement) EvidenceFact {
				return EvidenceFact{Fact: policyReadFact(row.Name, o.VersionID), rank: 2,
					PolicyVersion: strPtr(o.VersionID), Policy: pol}
			})
	case RefStatement:
		// Each support row's fact quotes the content as of ITS run.
		c.lim.docProtected = true
		st := row.statement()
		pol := &EvidencePolicy{Ref: R(RefPolicy, st.PolicyID), Name: st.PolicyName, Kind: st.PolicyKind}
		fact := fmt.Sprintf("Statement %s is in policy %s", st.label(), st.PolicyName)
		l.wantPolicyObservations(c, n.supports, row.PolicyKind, row.PolicyNativeRef, row.PolicySourceKey, st, nil,
			func(o obsRow, st *evStatement) EvidenceFact {
				return EvidenceFact{Fact: fact, rank: 2, PolicyVersion: strPtr(o.VersionID),
					StatementExcerpt: excerpt(st.NativeRights), Policy: pol, Statement: stmtRef(st)}
			})
	}
	l.claims[ref.String()] = c
}

// nodeLabel names a node in a sentence: its kind in words and its name.
func nodeLabel(refType string, row *nodeRow) string {
	switch refType {
	case RefWorkload:
		return runtimeKindWords(row.Kind) + " " + row.Name
	case RefIdentity:
		return identityKindWords(row.Kind) + " " + row.Name
	case RefResource:
		return "Resource reference " + row.Name
	case RefPolicy:
		return "Policy " + row.Name
	case RefStatement:
		st := row.statement()
		return fmt.Sprintf("Statement %s of %s", st.label(), st.PolicyName)
	}
	return row.Name
}

func runtimeKindWords(kind string) string {
	switch kind {
	case models.WorkloadLambdaFunction:
		return "Lambda function"
	case models.WorkloadECSTaskDefinition:
		return "ECS task definition"
	case models.WorkloadEC2Instance:
		return "EC2 instance"
	case models.WorkloadBedrockAgent:
		return "Bedrock agent"
	case models.WorkloadBedrockAgentCoreRT:
		return "AgentCore runtime"
	case models.WorkloadBedrockAgentCoreGW:
		return "AgentCore gateway"
	}
	return "Workload"
}

func identityKindWords(kind string) string {
	switch kind {
	case models.CloudIdentityIAMRole:
		return "IAM role"
	case models.CloudIdentityIAMUser:
		return "IAM user"
	case models.CloudIdentityIAMGroup:
		return "IAM group"
	}
	return "Identity"
}

// sourceLabels names the accounts of a node's live support rows ("production
// (220171243705)"), joined; every row's when none is live.
func (l *claimLoader) sourceLabels(ss []evSupport) string {
	var names []string
	add := func(s evSupport) {
		label := "an unknown account"
		if c := l.accts.Connector(s.ConnectorID); c != nil {
			label = c.Label
			if c.Label != c.AccountID {
				label = fmt.Sprintf("%s (%s)", c.Label, c.AccountID)
			}
		}
		if !contains(names, label) {
			names = append(names, label)
		}
	}
	for _, s := range ss {
		if s.State != StateEnded {
			add(s)
		}
	}
	if len(names) == 0 {
		for _, s := range ss {
			add(s)
		}
	}
	sort.Strings(names)
	return joinWords(names)
}

/* ---------------------------- external principals -------------------------- */

// externalPrincipals loads external principal refs as presence claims: the
// node has no support rows (D-47), so its lifecycle, times and partitions are
// its can_assume edges' (D-1), and its facts the trusting roles'
// observations behind those edges (D-80).
func (l *claimLoader) externalPrincipals(ids []uuid.UUID) error {
	var eps []struct {
		ID           uuid.UUID
		Issuer       string
		SubjectClaim string
		Mechanism    string
		FirstSeenAt  time.Time
	}
	if err := l.q.DB().Raw(`SELECT ep.id, ep.issuer, ep.subject_claim, ep.mechanism, ep.first_seen_at
	                          FROM iga_external_principal ep WHERE ep.workspace_id = ? AND ep.id IN ?`,
		l.q.WS, ids).Scan(&eps).Error; err != nil {
		return err
	}
	if len(eps) == 0 {
		return nil
	}
	found := make([]uuid.UUID, 0, len(eps))
	for _, ep := range eps {
		found = append(found, ep.ID)
	}
	var edges []relationshipRow
	if err := l.q.DB().Raw(`SELECT `+relationshipColumns+` FROM `+relationshipFrom+`
	                         WHERE r.workspace_id = ? AND r.relationship_type = ?
	                           AND r.source_external_principal_id IN ?
	                         ORDER BY r.id`, l.q.WS, models.RelTypeCanAssume, found).Scan(&edges).Error; err != nil {
		return err
	}
	byEP := map[uuid.UUID][]relationshipRow{}
	for _, e := range edges {
		byEP[*e.SrcExternalID] = append(byEP[*e.SrcExternalID], e)
	}
	for _, ep := range eps {
		label := ExternalPrincipalLabel(ep.Mechanism, ep.Issuer, ep.SubjectClaim)
		es := byEP[ep.ID]
		c := &evClaim{ref: Ref{Type: RefExternalPrincipal, ID: ep.ID}, basis: models.BasisDeclared, state: StateEnded,
			firstSeen: tptr(ep.FirstSeenAt)}
		var trusting []string
		var latest *relationshipRow
		var everyPart []evPart
		for i := range es {
			e := &es[i]
			switch {
			case e.State == StateCurrent:
				c.state = StateCurrent
			case e.State == StateStale && c.state != StateCurrent:
				c.state = StateStale
			}
			if latest == nil || e.LastConfirmedAt.After(latest.LastConfirmedAt) {
				latest = e
			}
			everyPart = append(everyPart, partsOf(e.ConnectorID, e.PartitionKey)...)
			if e.State != StateEnded {
				c.lim.parts = append(c.lim.parts, partsOf(e.ConnectorID, e.PartitionKey)...)
				c.lim.endpoints = append(c.lim.endpoints, l.connectorEndpoints(e.ConnectorID)...)
				if !contains(trusting, e.TargetName) {
					trusting = append(trusting, e.TargetName)
				}
			}
		}
		if len(c.lim.parts) == 0 {
			// Every edge ended: the partitions it last stood on still name
			// its sources, as an ended node's support rows do.
			c.lim.parts = everyPart
		}
		if latest != nil {
			c.lastConfirmed = tptr(latest.LastConfirmedAt)
			c.anchorConnector, c.anchorRun = latest.ConnectorID, latest.LastConfirmedBy
			if c.state == StateEnded {
				c.validTo, c.endedReason = latest.ValidTo, latest.EndedReason
			}
		}
		sort.Strings(trusting)
		if len(trusting) == 0 {
			c.sentence = fmt.Sprintf("%s is no longer named by any trust policy.", label)
		} else {
			c.sentence = fmt.Sprintf("%s is named by the trust policy of %s.", label, joinWords(trusting))
		}
		c.lim.stale = c.state == StateStale
		c.lim.endpoints = append(c.lim.endpoints, l.externalEndpoint(ep.Mechanism, ep.SubjectClaim))
		l.claims[c.ref.String()] = c
		for _, e := range es {
			if e.State == StateEnded {
				continue
			}
			e := e
			l.wantJunction(tableRelationshipEvidence, c, e.ID, e.LastConfirmedBy, tptr(e.LastConfirmedAt), relationshipFactsFor(e, label))
		}
	}
	return nil
}

// ExternalPrincipalLabel is how an external principal is named (D-87):
// aws_account -> the account id ("*" -> "any AWS principal"); aws_principal
// -> the ARN; aws_service -> the service principal; oidc and saml -> issuer
// and subject; k8s_service_account -> namespace/name.
func ExternalPrincipalLabel(kind, issuer, subject string) string {
	switch kind {
	case models.ExternalPrincipalAWSAccount:
		if subject == "*" {
			return "any AWS principal"
		}
		return subject
	case models.ExternalPrincipalAWSPrincipal, models.ExternalPrincipalAWSService:
		return subject
	case models.ExternalPrincipalOIDC, models.ExternalPrincipalSAML:
		return issuer + " " + subject
	case models.ExternalPrincipalK8sServiceAccount:
		ref := strings.TrimPrefix(subject, "pod:")
		if parts := strings.Split(ref, ":"); len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" {
			return parts[2] + "/" + parts[3]
		}
		return ref
	}
	return subject
}

// ExternalPrincipalAccountID is the account id an external principal names,
// when its kind states one (D-87: aws_account and aws_principal only). The
// account OBJECT, connected as of the revision, is ExternalPrincipalAccount.
func ExternalPrincipalAccountID(kind, subject string) string {
	switch kind {
	case models.ExternalPrincipalAWSAccount:
		if isAccountID(subject) {
			return subject
		}
	case models.ExternalPrincipalAWSPrincipal:
		return ARNAccount(subject)
	}
	return ""
}

/* --------------------------------- coverage -------------------------------- */

// coverage loads coverage:<run>:<surface> claims: what a run the current
// revision was built from recorded for one surface (D-80). A run no
// partition watermark names -- not published, superseded everywhere, another
// workspace's -- or a surface its report does not carry is 404.
func (l *claimLoader) coverage(refs []Ref) error {
	if len(refs) == 0 {
		return nil
	}
	runIDs := make([]uuid.UUID, 0, len(refs))
	for _, r := range refs {
		runIDs = append(runIDs, r.ID)
	}
	var runs []coverageRun
	if err := l.q.DB().Raw(`SELECT r.id, r.connector_id, r.published_at, r.coverage
	                          FROM cloud_scan_run r
	                          JOIN cloud_connector c ON c.workspace_id = r.workspace_id AND c.id = r.connector_id
	                           AND c.provider = ?
	                         WHERE r.workspace_id = ? AND r.id IN ?
	                           AND EXISTS (SELECT 1 FROM iga_projection_state ps
	                                        WHERE ps.workspace_id = r.workspace_id AND ps.last_run_id = r.id)`,
		models.CloudProviderAWS, l.q.WS, uniqueIDs(runIDs)).Scan(&runs).Error; err != nil {
		return err
	}
	byID := map[uuid.UUID]*coverageRun{}
	for i := range runs {
		byID[runs[i].ID] = &runs[i]
	}
	for _, ref := range refs {
		run := byID[ref.ID]
		if run == nil {
			continue
		}
		cov := models.DecodeScanCoverage(run.Coverage)
		s, ok := cov.Surfaces[ref.Surface]
		if !ok {
			continue
		}
		pub := pubTime(*run)
		c := &evClaim{ref: ref, basis: nil, state: StateCurrent, firstSeen: tptr(pub), lastConfirmed: tptr(pub)}
		label, acct := "an unknown account", ""
		if conn := l.accts.Connector(run.ConnectorID); conn != nil {
			label, acct = conn.Label, conn.AccountID
		}
		c.sentence = fmt.Sprintf("The scan of %s recorded %s as %s.", label, ref.Surface, s.State)
		c.lim = limInput{coverage: &evCoverage{run: run.ID, connector: run.ConnectorID, publishedAt: pub,
			surface: ref.Surface, state: s.State}}
		conn := run.ConnectorID
		c.lim.endpoints = l.connectorEndpoints(&conn)
		fact := fmt.Sprintf("The scan recorded %s as %s", ref.Surface, s.State)
		if s.State == models.CloudCoverageReached {
			fact += fmt.Sprintf(" (%d read)", s.Count)
		} else if s.Error != "" {
			fact += ": " + s.Error
		}
		region := ""
		if _, rg, ok := strings.Cut(ref.Surface, ":"); ok {
			region = rg
		}
		c.facts = []EvidenceFact{{
			SourceAPI: nullIfBlank(s.API), AccountID: nullIfBlank(acct), Region: nullIfBlank(region),
			ObservedInRun: R(RefScanRun, run.ID), LastConfirmedAt: TS(&pub), Fact: fact,
		}}
		l.claims[ref.String()] = c
	}
	return nil
}

/* --------------------------------- endpoints ------------------------------- */

// connectorEndpoints is D-89's rule: a claim collected by a REVOKED connector
// is from an account that is no longer connected.
func (l *claimLoader) connectorEndpoints(connector *uuid.UUID) []evEndpoint {
	if connector == nil {
		return nil
	}
	c := l.accts.Connector(*connector)
	if c == nil {
		return nil
	}
	return []evEndpoint{{account: c.AccountID, connected: c.Status != models.CloudConnectorRevoked}}
}

func (l *claimLoader) supportEndpoints(ss []evSupport) []evEndpoint {
	var out []evEndpoint
	for _, s := range ss {
		id := s.ConnectorID
		out = append(out, l.connectorEndpoints(&id)...)
	}
	return out
}

// identityEndpoint: an identity's account is its ARN's, connected when a live
// connector reads it (D-3: connected by construction as of the revision,
// unless revoked since, D-89).
func (l *claimLoader) identityEndpoint(sourceKey string) evEndpoint {
	acct := ARNAccount(NativeOfKey(sourceKey))
	return evEndpoint{account: acct, connected: acct == "" || l.accts.Connected(acct)}
}

// resourceEndpoint: a reference's account is what its ARN states; connected
// only when the revision PROJECTED it connected (D-3) and its connector is
// not revoked since (D-89). A reference stating no account has no endpoint
// account to name.
func (l *claimLoader) resourceEndpoint(t evTarget) evEndpoint {
	return evEndpoint{account: t.AccountID, connected: t.AccountID == "" || (t.AccountConnected && l.accts.Connected(t.AccountID))}
}

// externalEndpoint: the account an external principal names (D-87), read
// against the live connectors -- it has no projected flag.
func (l *claimLoader) externalEndpoint(kind, subject string) evEndpoint {
	acct := ExternalPrincipalAccountID(kind, subject)
	return evEndpoint{account: acct, connected: acct == "" || l.accts.Connected(acct)}
}

/* ---------------------------------- phrases -------------------------------- */

// actionsPhrase renders a statement's actions: "s3:GetObject", "s3:GetObject,
// s3:PutObject", or for NotAction "all actions except iam:*" (§2.6).
func actionsPhrase(t statementText) string {
	if len(t.NotActions) > 0 {
		return "all actions except " + strings.Join(t.NotActions, ", ")
	}
	if len(t.Actions) == 0 {
		return "no stated action"
	}
	return strings.Join(t.Actions, ", ")
}

// targetsPhrase renders a statement's targets: the positive ones, or for
// NotResource "all resources except finance/*" (§2.6). short uses the
// customer's short form for S3 (support-tickets/*), as the §5.3 sentence
// does.
func targetsPhrase(pos, excl []evTarget, short bool) string {
	name := func(t evTarget) string {
		if short {
			return resourcePhrase(t.Text)
		}
		return t.Text
	}
	if len(excl) > 0 {
		parts := make([]string, 0, len(excl))
		for _, t := range excl {
			parts = append(parts, name(t))
		}
		return "all resources except " + strings.Join(parts, ", ")
	}
	if len(pos) == 0 {
		return "no stated resource"
	}
	parts := make([]string, 0, len(pos))
	for _, t := range pos {
		parts = append(parts, name(t))
	}
	return strings.Join(parts, ", ")
}

// resourcePhrase is a reference as a sentence names it: an S3 ARN by its
// bucket and key ("support-tickets/*" -- S3 ARNs state no account or region,
// so nothing is lost), "*" as "all resources", anything else in full.
func resourcePhrase(text string) string {
	if text == "*" {
		return "all resources"
	}
	if parts := strings.SplitN(text, ":", 6); len(parts) == 6 && parts[0] == "arn" && parts[2] == "s3" &&
		parts[3] == "" && parts[4] == "" && parts[5] != "" {
		return parts[5]
	}
	return text
}

func joinWords(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}

func excerpt(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil
	}
	return raw
}

func stmtRef(st *evStatement) *EvidenceStmtRef {
	var idx *int
	if st.Index != nil {
		i := *st.Index + 1 // D-84: 1-based in the API
		idx = &i
	}
	return &EvidenceStmtRef{Ref: R(RefStatement, st.ID), Sid: st.Sid, Index: idx}
}

// StatementGroupKey is D-37's group_key: the sorted actions (NotActions
// prefixed "!"), "→", the sorted positive target refs, and a digest of the
// condition and the exclusions -- so statements differing in either never
// share a key.
func StatementGroupKey(t statementText, positive, exclusions []uuid.UUID) string {
	acts := append([]string{}, t.Actions...)
	for _, a := range t.NotActions {
		acts = append(acts, "!"+a)
	}
	sort.Strings(acts)
	refs := make([]string, 0, len(positive))
	for _, id := range uniqueIDs(positive) {
		refs = append(refs, R(RefResource, id))
	}
	excl := make([]string, 0, len(exclusions))
	for _, id := range uniqueIDs(exclusions) {
		excl = append(excl, R(RefResource, id))
	}
	var cond any
	if hasCondition(t.Condition) {
		_ = json.Unmarshal(t.Condition, &cond)
	}
	canon, _ := json.Marshal(struct {
		C any      `json:"c"`
		X []string `json:"x"`
	}{cond, excl})
	return strings.Join(acts, ",") + "→" + strings.Join(refs, ",") + "#" + shortDigest(canon)
}

func partsOf(connector *uuid.UUID, key string) []evPart {
	if connector == nil || key == "" {
		return nil
	}
	return []evPart{{*connector, key}}
}

func tptr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
