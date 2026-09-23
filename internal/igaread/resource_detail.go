package igaread

// GET /api/iga/v1/resources/:id (SPEC-iga-phase2-graph.md §5.3 Resources,
// T6.3): a resource reference's Overview -- the list row, plus
// existence: "not_verified", resource_policy and sources.
//
// The row is read through the SAME record, columns and Row builder as the
// resources list (nodes.go), so the Overview can never say one thing about a
// reference's kind, account or counts while the row it was opened from says
// another (§2.14.11 "The graph and the lists must agree"). Retired references
// are readable (§5.2 "Retired objects"): lifecycle, retired_reason and
// last_confirmed_at come from the row.
//
// Everything is read inside Reader.Read: one snapshot, one deadline, the
// revision checked in the same snapshot (§5.1). The counts are OPTIONAL work
// ({value: null, exact: false} when they time out); the row, sources,
// resource_policy and meta.coverage are mandatory -- dropping any of them
// would present a partial answer as a complete one.

import (
	"context"
	"net/url"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ResourceExistenceNotVerified is every reference's existence this phase:
// nothing enumerates resources (§1.2 "Comprehensive resource inventory" is
// deferred), so a reference is what a statement NAMED, never proof the
// resource exists (§2.14.12). It is a constant, not the stored attribute: the
// read side never claims "verified" on a value no collector could have
// established.
const ResourceExistenceNotVerified = "not_verified"

// ResourcePolicySourceAPIs are the calls the permission scanner records a
// resource policy under (services.resourcePolicySourceAPI): the only
// observations resource_policy is computed from.
var ResourcePolicySourceAPIs = []string{"s3:GetBucketPolicy", "kms:GetKeyPolicy"}

// ResourceDetailView is data of GET /resources/:id: the §5.3 list row (its
// fields flattened in), plus existence, resource_policy and sources.
type ResourceDetailView struct {
	ResourceRow
	Existence      string              `json:"existence"`
	ResourcePolicy ResourcePolicyState `json:"resource_policy"`
	Sources        []ResourceSource    `json:"sources"`
}

// ResourcePolicyState is resource_policy (§5.3, D-19): whether a bucket or key
// policy was read for this exact reference, and whether it contains a Deny.
// has_deny is null whenever read is false -- and also when the latest policy
// read did not parse, since an unparsed document proves neither a Deny nor its
// absence.
type ResourcePolicyState struct {
	Read    bool  `json:"read"`
	HasDeny *bool `json:"has_deny"`
}

// ResourceSource is one entry of sources (§5.3, §2.10B): one support row of
// the reference -- which connector vouches for it, in which state. Ended
// supports are listed (E10: "sources shows A current, B ended"). presence is
// the support row's typed reference, which /evidence accepts (D-65).
type ResourceSource struct {
	Presence        string   `json:"presence"`
	Integration     string   `json:"integration"`
	Account         *Account `json:"account"`
	State           string   `json:"state"`
	FirstSeenAt     any      `json:"first_seen_at"`
	LastConfirmedAt any      `json:"last_confirmed_at"`
	EndedReason     *string  `json:"ended_reason"`
}

// ResourceDetailMeta is the detail envelope's meta (§5.2) with meta.coverage,
// which every detail response carries (§2.14.14, D-73).
type ResourceDetailMeta struct {
	DetailMeta
	Coverage []CoverageNote `json:"coverage"`
}

// ResourceDetail serves GET /resources/:id. rawID is the route parameter: the
// bare UUID or resource:<uuid> (D-5); anything else, another workspace's id, a
// GitHub row, an AWS row no projection pass supports (D-6), and every id before
// the first publication (D-4) are 404 not_found with no hint.
func (r *Reader) ResourceDetail(ctx context.Context, ws uuid.UUID, rawID string, vals url.Values) (any, error) {
	for name := range vals {
		if name != "rev" {
			return nil, InvalidParameter(name, name+" is not a parameter of this route")
		}
	}
	rev, perr := ParseRev(vals)
	if perr != nil {
		return nil, perr
	}
	id, perr := RouteID(RefResource, rawID)
	if perr != nil {
		return nil, perr
	}

	var out Envelope
	err := r.Read(ctx, ws, Pin{Rev: rev}, func(q *Query) error {
		if !q.Published() {
			return NotFound()
		}
		rec, err := ResourceByID(q, id)
		if err != nil {
			return err
		}
		if rec == nil {
			return NotFound()
		}
		accts, err := q.LoadAccounts()
		if err != nil {
			return err
		}

		// D-17's counts: optional, so a hub reference (the implicit "*") costs
		// the same as a leaf and a timeout reads "unknown", never a number.
		var counts map[uuid.UUID]TargetCounts
		ok, err := q.Optional(func(tx *gorm.DB) error {
			var err error
			counts, err = ResourceTargetCounts(tx, q.WS, []uuid.UUID{rec.ID})
			return err
		})
		if err != nil {
			return err
		}
		named, excluded := Unknown(), Unknown()
		if c, has := counts[rec.ID]; ok && has {
			named, excluded = c.NamedBy, c.ExcludedBy
		}

		var reasons map[uuid.UUID][]StaleReason
		if rec.State == StateStale {
			if reasons, err = NodeStaleReasons(q, accts, "resource_id", []StaleSubject{rec.StaleSubject()}); err != nil {
				return err
			}
		}

		policy, err := ResourcePolicyOf(q, rec.DisplayName)
		if err != nil {
			return err
		}
		sources, err := ResourceSourcesOf(q, accts, rec.ID)
		if err != nil {
			return err
		}
		cov, err := ResourceCoverage(q, accts)
		if err != nil {
			return err
		}

		out = Envelope{
			Data: ResourceDetailView{
				ResourceRow:    rec.Row(accts, named, excluded, StaleReasonOf(rec.State, rec.ID, reasons)),
				Existence:      ResourceExistenceNotVerified,
				ResourcePolicy: policy,
				Sources:        sources,
			},
			Meta: ResourceDetailMeta{DetailMeta: NewDetailMeta(q), Coverage: cov},
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ResourceByID reads one resource reference as a graph row (D-6): this
// workspace, provider = 'aws', supported by at least one projection pass, in
// any lifecycle (retired references are readable, §5.2). nil when it is not
// one -- the caller answers 404 with no hint.
func ResourceByID(q *Query, id uuid.UUID) (*ResourceRecord, error) {
	var rows []ResourceRecord
	if err := q.DB().Raw(`SELECT `+ResourceColumns+`
	                        FROM `+ResourceFrom+`
	                       WHERE r.workspace_id = ? AND r.id = ? AND r.provider = 'aws'
	                         AND `+SupportedSQL("r", "resource_id"),
		q.WS, id).Scan(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// ResourceCoverage is meta.coverage for a resource's detail and its tabs: the
// resources list's own notes (listsCoverage over every connector's resource
// partitions), unnarrowed. A reference's account is what its ARN states, not
// who scanned it, and any connector's unread policies may name it -- so every
// connector's resource-surface gap bears on its named-by counts and its
// Access, whether or not that connector supports it today (the same reasoning
// listsResourceFilters records for the list). One definition, so the list and
// the Overview never disagree about what is complete.
func ResourceCoverage(q *Query, accts *Accounts) ([]CoverageNote, error) {
	return listsCoverage(q, accts, listsRouteResources, listsScope{})
}

// ResourcePolicyOf is resource_policy (D-19) for a reference's text, at the
// snapshot's revision. An observation counts only when it belongs to the
// revision:
//
//   - its subject is THIS exact ARN (subject_native_id = the reference text):
//     a selector never matches a bucket's policy, and a bucket's policy says
//     nothing about another bucket;
//   - it came from a resource-policy read (ResourcePolicySourceAPIs);
//   - it was first recorded at or before the revision's published_at, by a run
//     that published at a rev at or below the current one (iga_publication is
//     unique per run) -- so a collection in flight, or one whose projection
//     never committed, cannot change the answer at a revision (§5.1, D-25).
//
// Of the observations that qualify, the latest first-recorded one decides
// has_deny. First-recorded, not last-confirmed: last_confirmed_* is moved by
// every later collection, published or not, so ordering on it would let a
// run that has not published change the answer at the same revision
// (§2.14.11). None qualifies: {read: false, has_deny: null} -- "not read" and
// "read, no policy" are indistinguishable today (D-19's Raise: the scanner
// records nothing for an absent policy). A policy that did not parse is read,
// with has_deny null: its has_deny fact is false only because nothing was
// parsed.
//
// Keyed on subject_native_id, which no index serves; see the report's
// proposed index. Resource ids are not used because reconciliation SETs NULL
// an observation's resource_id when the cloud_resource row goes, and that
// happens during collection -- again, before any publication.
func ResourcePolicyOf(q *Query, text string) (ResourcePolicyState, error) {
	if q.Rev == nil {
		return ResourcePolicyState{}, nil
	}
	var rows []struct {
		HasDeny     *bool
		ParseFailed *bool
	}
	if err := q.DB().Raw(`SELECT (o.sanitized_facts->>'has_deny')::boolean AS has_deny,
	                             (o.sanitized_facts->>'parse_failed')::boolean AS parse_failed
	                        FROM cloud_observation o
	                       WHERE o.workspace_id = ? AND o.source_api IN ? AND o.subject_native_id = ?
	                         AND o.ingested_at <= ?
	                         AND EXISTS (SELECT 1 FROM iga_publication pb
	                                      WHERE pb.workspace_id = o.workspace_id AND pb.scan_run_id = o.scan_run_id
	                                        AND pb.rev <= ?)
	                       ORDER BY o.ingested_at DESC, o.id DESC
	                       LIMIT 1`,
		q.WS, ResourcePolicySourceAPIs, text, q.Rev.PublishedAt, q.Rev.Rev).Scan(&rows).Error; err != nil {
		return ResourcePolicyState{}, err
	}
	if len(rows) == 0 {
		return ResourcePolicyState{Read: false, HasDeny: nil}, nil
	}
	st := ResourcePolicyState{Read: true}
	if rows[0].HasDeny != nil && (rows[0].ParseFailed == nil || !*rows[0].ParseFailed) {
		v := *rows[0].HasDeny
		st.HasDeny = &v
	}
	return st, nil
}

// ResourceSourcesOf is sources: every support row of the reference, in any
// state, one entry each (a resource has one partition per connector, so one
// row per connector), ordered by the connector's account, then connector, then
// first seen. Each names its connector and that connector's account -- the
// SCANNING account, which is who vouches for the reference, not the account
// its ARN states.
func ResourceSourcesOf(q *Query, accts *Accounts, resourceID uuid.UUID) ([]ResourceSource, error) {
	var rows []struct {
		ID              uuid.UUID
		ConnectorID     uuid.UUID
		State           string
		FirstSeenAt     time.Time
		LastConfirmedAt *time.Time
		EndedReason     string
	}
	if err := q.DB().Raw(`SELECT s.id, s.connector_id, s.state, s.first_seen_at, s.last_confirmed_at, s.ended_reason
	                        FROM iga_object_support s
	                       WHERE s.workspace_id = ? AND s.resource_id = ?
	                       ORDER BY s.connector_id, s.first_seen_at, s.id`,
		q.WS, resourceID).Scan(&rows).Error; err != nil {
		return nil, err
	}
	type keyed struct {
		account string // "" (first) when the connector row is gone
		src     ResourceSource
	}
	all := make([]keyed, 0, len(rows))
	for _, s := range rows {
		k := keyed{src: ResourceSource{
			Presence:        R(RefPresence, s.ID),
			Integration:     R(RefConnector, s.ConnectorID),
			State:           s.State,
			FirstSeenAt:     T(s.FirstSeenAt),
			LastConfirmedAt: TS(s.LastConfirmedAt),
		}}
		if c := accts.Connector(s.ConnectorID); c != nil {
			k.account, k.src.Account = c.AccountID, accts.Of(c.AccountID)
		}
		if s.EndedReason != "" {
			reason := s.EndedReason
			k.src.EndedReason = &reason
		}
		all = append(all, k)
	}
	// Stable: within an account the rows keep their connector, first-seen, id
	// order from the query.
	sort.SliceStable(all, func(i, j int) bool { return all[i].account < all[j].account })
	out := make([]ResourceSource, 0, len(all))
	for _, k := range all {
		out = append(out, k.src)
	}
	return out, nil
}
