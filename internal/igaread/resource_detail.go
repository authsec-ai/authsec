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
	"encoding/json"
	"net/url"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/models"
)

// ResourceExistenceNotVerified is every reference's existence this phase:
// nothing enumerates resources (§1.2 "Comprehensive resource inventory" is
// deferred), so a reference is what a statement NAMED, never proof the
// resource exists (§2.14.12). It is a constant, not the stored attribute: the
// read side never claims "verified" on a value no collector could have
// established.
const ResourceExistenceNotVerified = "not_verified"

// ResourcePolicySourceAPIs are the calls the permission scanner records a
// resource policy under (services.resourcePolicySourceAPI, including its
// default arm): the only observations resource_policy -- and evidence's
// resource_policy_not_projected, which uses the same rule (D-19) -- is
// computed from.
var ResourcePolicySourceAPIs = []string{"s3:GetBucketPolicy", "kms:GetKeyPolicy", "resource:GetPolicy"}

// ResourceDetailView is data of GET /resources/:id: the §5.3 list row (its
// fields flattened in), plus existence, resource_policy and sources.
// retired_reason is always present (null while active), as on every detail
// route (§5.2 "Retired objects"; D-98); the list row omits it on active rows.
type ResourceDetailView struct {
	ResourceRow
	RetiredReason  *string             `json:"retired_reason"`
	Existence      string              `json:"existence"`
	ResourcePolicy ResourcePolicyState `json:"resource_policy"`
	Sources        []ResourceSource    `json:"sources"`
}

// ResourcePolicyState is resource_policy (§5.3, D-19): whether a bucket or key
// policy was read for this exact reference, and whether it contains a Deny.
// has_deny is null whenever read is false -- and also when the latest policy
// read did not parse, since an unparsed document proves neither a Deny nor its
// absence, and when the revision cannot prove which of two disagreeing reads
// is the latest (resourcePolicyState).
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
		cov, err := ResourceDetailCoverage(q, accts, rec)
		if err != nil {
			return err
		}

		out = Envelope{
			Data: ResourceDetailView{
				ResourceRow:    rec.Row(accts, named, excluded, StaleReasonOf(rec.State, rec.ID, reasons)),
				RetiredReason:  strPtr(rec.RetiredReason),
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

// ResourcePolicyTypes are the typed kinds (ResourceType) whose resource policy
// the permission scanner reads (services' getOrCreateResource collects exactly
// these as resource-policy candidates): the only references a
// resource_policies gap bears on.
var ResourcePolicyTypes = map[string]bool{"s3_bucket": true, "kms_key": true}

// ResourcePolicyAffects is the affects of a resource_policies note on a
// resource's Overview: the read behind resource_policy failed.
const ResourcePolicyAffects = "whether this resource's policy was read"

// The identity-listing surfaces, per result. A resource partition requires
// them (igagraph.Partitions: iam_roles, iam_users, iam_groups, iam_policies,
// permission_scan), and the resources list's table (D-73) does not carry
// them: inline policies arrive WITH the identity listing
// (GetAccountAuthorizationDetails, one filter per surface), so a gap there is
// a set of unread policies that may name ANY reference -- in any account's,
// for the same reason the list's iam_policies notes are never narrowed. On
// Access they also decide who holds what: iam_users and iam_groups are the
// member_of partitions' surfaces, which D-18's member rows depend on.
var (
	resourceDetailIdentityAffects = map[string]string{
		models.SurfaceIAMRoles:  "resources named by roles' inline policies",
		models.SurfaceIAMUsers:  "resources named by users' inline policies",
		models.SurfaceIAMGroups: "resources named by groups' inline policies",
	}
	resourceAccessIdentityAffects = map[string]string{
		models.SurfaceIAMRoles:  "access held by roles",
		models.SurfaceIAMUsers:  "access held by users, directly or as group members",
		models.SurfaceIAMGroups: "access held by groups and their members",
	}
)

// ResourceDetailCoverage is meta.coverage on GET /resources/:id: every gap
// that bears on the Overview (§2.14.14) -- the resources list's notes (its
// counts are the row's), every account's identity-listing gaps (the rest of
// the reference's own partitions' surfaces, D-73), and, for a bucket or key,
// the resource_policies read of each connector that names it (D-93): the one
// gap that explains resource_policy.read = false.
func ResourceDetailCoverage(q *Query, accts *Accounts, rec *ResourceRecord) ([]CoverageNote, error) {
	return resourceCoverage(q, accts, rec.ID, resourceDetailIdentityAffects,
		ResourcePolicyTypes[ResourceType(rec.DisplayName)])
}

// ResourceAccessCoverage is meta.coverage on GET /resources/:id/access: the
// resources list's notes and every account's identity-listing gaps. No
// resource_policies: Access lists identity-policy grants only, and a bucket
// policy's own grants are not projected (resource_policy_not_projected).
func ResourceAccessCoverage(q *Query, accts *Accounts, rec *ResourceRecord) ([]CoverageNote, error) {
	return resourceCoverage(q, accts, rec.ID, resourceAccessIdentityAffects, false)
}

// resourceCoverage is the resources list's notes (listsCoverage over every
// connector's resource partitions, unnarrowed), plus the identity surfaces
// with their affects, plus -- when policy is set -- resource_policies.
//
// The list's notes stay unnarrowed on a detail: a reference's account is what
// its ARN states, not who scanned it, and any connector's unread policies may
// name it -- so every connector's gap on a surface that carries policies bears
// on its counts and its Access, whether or not that connector supports it
// today (the reasoning listsResourceFilters records for the list). Dropping
// them would present an Overview as complete where the list row it came from
// is not; the identity surfaces follow the same rule.
//
// The runs are the ones listsCoverage reads: each connector's resource
// partitions' last projected runs (iga_projection_state, D-57), the runs this
// revision was built from. Per account and surface the newest such run
// decides; reached and unsupported are no gap and not_selected is stale
// (D-58); a surface the run did not report is not guessed at.
//
// resource_policies is narrower. A run reads the policy of the buckets and
// keys ITS policies named (services' resourcePolicyCandidates), so only a
// connector whose partition still supports the reference (current or stale,
// in the run its partition was built from) tried to read it; an ended one's
// run no longer named it and its resource_policies gap is about other
// resources. names_it is that support, per partition.
func resourceCoverage(q *Query, accts *Accounts, resourceID uuid.UUID, identity map[string]string, policy bool) ([]CoverageNote, error) {
	notes, err := listsCoverage(q, accts, listsRouteResources, listsScope{})
	if err != nil {
		return nil, err
	}
	var runs []struct {
		ConnectorID uuid.UUID
		Coverage    json.RawMessage
		NamesIt     bool
	}
	if err := q.DB().Raw(`SELECT sr.connector_id, sr.coverage,
	                             EXISTS (SELECT 1 FROM iga_object_support s
	                                      WHERE s.workspace_id = ps.workspace_id AND s.resource_id = ?
	                                        AND s.connector_id = ps.connector_id AND s.partition_key = ps.partition_key
	                                        AND s.state IN ?) AS names_it
	                        FROM iga_projection_state ps
	                        JOIN cloud_scan_run sr ON sr.workspace_id = ps.workspace_id AND sr.id = ps.last_run_id
	                       WHERE ps.workspace_id = ? AND ps.object_class = ?
	                       ORDER BY sr.published_at DESC NULLS LAST, sr.requested_at DESC, sr.id`,
		resourceID, []string{StateCurrent, StateStale}, q.WS, models.ObjectResource).Scan(&runs).Error; err != nil {
		return nil, err
	}
	affects := map[string]string{}
	for s, a := range identity {
		affects[s] = a
	}
	if policy {
		affects[models.SurfaceResourcePolicies] = ResourcePolicyAffects
	}
	surfaces := make([]string, 0, len(affects))
	for s := range affects {
		surfaces = append(surfaces, s)
	}
	sort.Strings(surfaces)

	type key struct{ account, surface string }
	decided := map[key]bool{}
	for _, run := range runs { // newest first
		conn := accts.Connector(run.ConnectorID)
		if conn == nil {
			continue
		}
		cov := models.DecodeScanCoverage(run.Coverage)
		for _, surface := range surfaces {
			if surface == models.SurfaceResourcePolicies && !run.NamesIt {
				continue // this partition's run never tried to read the reference's policy
			}
			k := key{conn.AccountID, surface}
			s, reported := cov.Surfaces[surface]
			if decided[k] || !reported {
				continue
			}
			decided[k] = true
			state := s.State
			switch state {
			case models.CloudCoverageReached, models.CloudCoverageUnsupported:
				continue
			case models.CloudCoverageNotSelected:
				state = models.CloudCoverageStale
			}
			notes = append(notes, CoverageNote{AccountID: conn.AccountID, Surface: surface, State: state, Affects: affects[surface]})
		}
	}
	sort.SliceStable(notes, func(i, j int) bool {
		if notes[i].AccountID != notes[j].AccountID {
			return notes[i].AccountID < notes[j].AccountID
		}
		return notes[i].Surface < notes[j].Surface
	})
	return notes, nil
}

// ResourcePolicyOf is resource_policy (D-19) for a reference's text, at the
// snapshot's revision. Only observations about THIS exact ARN
// (subject_native_id = the reference text) from a resource-policy read
// (ResourcePolicySourceAPIs), first recorded at or before the revision's
// published_at, are candidates: a selector never matches a bucket's policy, a
// bucket's policy says nothing about another bucket, and a collection that
// started after the revision cannot change its answer (§5.1, D-25).
//
// An unchanged re-read writes no new row: it dedupes onto the existing one and
// moves only last_confirmed_run_id / last_confirmed_at / confirmation_count
// (services.ObservationWriter.Record). So a row names only TWO of the runs
// that read that content -- the first (scan_run_id) and the latest
// (last_confirmed_run_id) -- plus how many did. A candidate BELONGS to the
// revision (D-19: "by a run that published") when either of the two published
// at a rev at or below the current one (iga_publication is unique per run).
// Keying on the first recorder alone would leave a policy first read by a run
// that never published -- superseded, abandoned, or collected while
// IGA_GRAPH_PROJECTION was off -- "not read" at every revision until its
// content changed, hiding its Deny for good.
//
// "The latest such observation" (D-19) is the one whose latest confirmation
// the revision can PROVE is latest -- never simply the latest first-recorded:
// a policy whose Deny is removed and then restored dedupes the restored read
// onto the OLD row, and ordering on first-recorded would keep answering "no
// Deny". resourcePolicyState has the rule, including the case the two named
// runs cannot settle (a later collection moved last_confirmed_run_id past the
// revision): has_deny is then null, never a guess. None belongs: {read:
// false, has_deny: null} -- "not read" and "read, no policy" are
// indistinguishable today (D-19's Raise: the scanner records nothing for an
// absent policy). A policy that did not parse is read, with has_deny null: its
// has_deny fact is false only because nothing was parsed.
//
// Keyed on subject_native_id, which no index serves (a proposed index is
// raised as a spec question). Resource ids are not used because
// reconciliation SETs NULL an observation's resource_id when the
// cloud_resource row goes, and that happens during collection -- before any
// publication -- so a resource_id key would change the answer at a revision.
func ResourcePolicyOf(q *Query, text string) (ResourcePolicyState, error) {
	if q.Rev == nil {
		return ResourcePolicyState{}, nil
	}
	var rows []ResourcePolicyObservation
	if err := q.DB().Raw(`SELECT o.id, o.ingested_at, o.last_confirmed_at, o.confirmation_count,
	                             (o.sanitized_facts->>'has_deny')::boolean AS has_deny,
	                             (o.sanitized_facts->>'parse_failed')::boolean AS parse_failed,
	                             EXISTS (SELECT 1 FROM iga_publication pb
	                                      WHERE pb.workspace_id = o.workspace_id AND pb.scan_run_id = o.scan_run_id
	                                        AND pb.rev <= ?) AS first_in,
	                             EXISTS (SELECT 1 FROM iga_publication pb
	                                      WHERE pb.workspace_id = o.workspace_id AND pb.scan_run_id = o.last_confirmed_run_id
	                                        AND pb.rev <= ?) AS last_in
	                        FROM cloud_observation o
	                       WHERE o.workspace_id = ? AND o.source_api IN ? AND o.subject_native_id = ?
	                         AND o.ingested_at <= ?
	                       ORDER BY o.ingested_at DESC, o.id DESC`,
		q.Rev.Rev, q.Rev.Rev, q.WS, ResourcePolicySourceAPIs, text, q.Rev.PublishedAt).Scan(&rows).Error; err != nil {
		return ResourcePolicyState{}, err
	}
	return resourcePolicyState(rows, q.Rev.PublishedAt), nil
}

// ResourcePolicyObservation is one candidate observation for resource_policy:
// its content's verdict, its times, and whether each of the two runs it names
// belongs to the revision.
type ResourcePolicyObservation struct {
	ID                uuid.UUID
	IngestedAt        time.Time  // when the first recording run wrote it
	LastConfirmedAt   *time.Time // when the latest confirming run re-read it
	ConfirmationCount int        // how many reads, the first included
	HasDeny           *bool
	ParseFailed       *bool
	FirstIn           bool // scan_run_id published at a rev <= the current one
	LastIn            bool // last_confirmed_run_id did
}

// verdict is what the observation says about a Deny: "deny", "no_deny", or ""
// when nothing parsed proves either.
func (o ResourcePolicyObservation) verdict() string {
	if o.HasDeny == nil || (o.ParseFailed != nil && *o.ParseFailed) {
		return ""
	}
	if *o.HasDeny {
		return "deny"
	}
	return "no_deny"
}

// window is the time, as far as the revision can prove it, of the observation's
// LATEST read by a run that belongs to the revision: at least lo, at most hi.
// proven is false when no such read is proven; possible is false when none can
// have happened.
//
//   - Its latest confirmer belongs: that read is exact (lo = hi =
//     last_confirmed_at) -- no later read of this content exists at all.
//   - Otherwise the reads that may belong are the first one and the
//     confirmation_count - 2 unnamed reads between it and the latest. With
//     none unnamed (count <= 2), the first read is the only candidate, exact
//     when it belongs. With some, an unnamed read may belong, as late as the
//     latest confirmation or the revision's publication, whichever is earlier;
//     only the first read, if it belongs, is proven.
func (o ResourcePolicyObservation) window(publishedAt time.Time) (lo, hi time.Time, proven, possible bool) {
	if o.LastIn && o.LastConfirmedAt != nil {
		return *o.LastConfirmedAt, *o.LastConfirmedAt, true, true
	}
	if o.ConfirmationCount <= 2 {
		return o.IngestedAt, o.IngestedAt, o.FirstIn, o.FirstIn
	}
	hi = publishedAt
	if o.LastConfirmedAt != nil && o.LastConfirmedAt.Before(hi) {
		hi = *o.LastConfirmedAt
	}
	return o.IngestedAt, hi, o.FirstIn, true
}

// resourcePolicyState decides resource_policy from the candidates (D-19).
// read is true when any candidate is PROVEN to belong to the revision. The
// winner is the proven candidate with the latest proven read (then the latest
// first recorded, then the highest id: deterministic). has_deny is the
// winner's verdict -- unless another candidate that disagrees with it MAY have
// been read by the revision after the winner's proven read: the data cannot
// say which is latest, so has_deny is null (never a guessed false over a
// possible Deny, nor the reverse).
func resourcePolicyState(obs []ResourcePolicyObservation, publishedAt time.Time) ResourcePolicyState {
	winner := -1
	var best time.Time
	for i, o := range obs {
		lo, _, proven, _ := o.window(publishedAt)
		if !proven {
			continue
		}
		if winner < 0 || lo.After(best) || (lo.Equal(best) && rdetailLater(o, obs[winner])) {
			winner, best = i, lo
		}
	}
	if winner < 0 {
		return ResourcePolicyState{Read: false, HasDeny: nil}
	}
	st := ResourcePolicyState{Read: true}
	v := obs[winner].verdict()
	for i, o := range obs {
		if i == winner || o.verdict() == v {
			continue
		}
		if _, hi, _, possible := o.window(publishedAt); possible && hi.After(best) {
			return st // undecidable: read, has_deny null
		}
	}
	if v != "" {
		deny := v == "deny"
		st.HasDeny = &deny
	}
	return st
}

// rdetailLater breaks a tie between two equally late proven reads: the later
// first recorded, then the higher id.
func rdetailLater(a, b ResourcePolicyObservation) bool {
	if !a.IngestedAt.Equal(b.IngestedAt) {
		return a.IngestedAt.After(b.IngestedAt)
	}
	return a.ID.String() > b.ID.String()
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
