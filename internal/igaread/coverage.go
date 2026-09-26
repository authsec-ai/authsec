package igaread

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// GET /api/iga/v1/coverage (SPEC-iga-phase2-graph.md §5.3, §2.14.13; D-57,
// D-58, D-71, D-72): per account and surface, what the runs the CURRENT
// REVISION was built from could read -- and which conclusion each gap
// prevents.
//
// "The runs the current revision was built from" are read from
// iga_projection_state: every partition's watermark, last_run_id, per
// connector (D-57). The rows are written in the publication's own
// transaction, so inside this request's snapshot they are exactly the current
// revision's. A revision published by account B's run is still BUILT FROM
// account A's last projected run for A's partitions: the coverage is
// cumulative across accounts, never just the publishing run's.
//
// NEVER a guessed missing permission (§2.14.13, E9): error_code and api are
// what the SDK reported when the read failed (awsdiscovery.FailedCall, stamped
// on the run's coverage at collection, D-71), or null. Nothing here maps a
// failed call to an IAM action someone should grant, and the Error prose is
// never parsed into a code.

// Limitation codes a coverage gap prevents (§5.3 Evidence vocabulary; D-58).
const (
	PreventsSurfaceDenied  = "surface_denied"
	PreventsSurfacePartial = "surface_partial"
	PreventsSurfaceStale   = "surface_stale"
	PreventsOrganizations  = "organizations_not_collected"
)

// FixChangeRegions is the one fix the evidence supports on a surface
// (§2.14.13): a region that is not selected is fixed by selecting it.
const FixChangeRegions = "change_regions"

// SurfaceOrganizations is the AWS Organizations surface (recorded unsupported
// until a collector exists).
const SurfaceOrganizations = "organizations"

// sinceWalkLimit bounds the walk back through a connector's published runs
// that finds when a surface entered its current state (D-72): a streak longer
// than this is reported as not known (null), never guessed.
const sinceWalkLimit = 50

// Prevents maps a surface's state to the limitation it imposes (D-58):
//
//	denied                                   -> surface_denied
//	partial                                  -> surface_partial
//	throttled, not_selected, unknown, stale,
//	constrained                              -> surface_stale
//	unsupported on organizations             -> organizations_not_collected
//	any other unsupported, not_configured,
//	reached                                  -> null
//
// not_selected is surface_stale because an unselected region's earlier results
// are KEPT and marked stale (§2.14.13 l.1856-1859): nothing is claimed about
// it now. A state this build does not know is surface_stale too -- a read we
// meant to make is not known to have completed, so nothing it covers may be
// treated as confirmed.
func Prevents(surface, state string) any {
	switch state {
	case models.CloudCoverageReached, models.CloudCoverageNotConfigured:
		return nil
	case models.CloudCoverageDenied:
		return PreventsSurfaceDenied
	case models.CloudCoveragePartial:
		return PreventsSurfacePartial
	case models.CloudCoverageUnsupported:
		if surface == SurfaceOrganizations {
			return PreventsOrganizations
		}
		return nil
	}
	return PreventsSurfaceStale
}

// CoverageAccount is one account's coverage in the current revision.
type CoverageAccount struct {
	Integration string   `json:"integration"`
	Account     *Account `json:"account"`
	// ConnectorStatus is active | error | revoked (additive): a revoked
	// connector's runs still built part of the revision (D-89).
	ConnectorStatus string `json:"connector_status"`
	// Template is the CloudFormation stack version recorded when the account
	// was onboarded against the one this build ships (D-72): a fact, never the
	// cause of a denial. Nothing refreshes the recorded value after a stack
	// update.
	Template map[string]any `json:"template"`
	// Runs are the runs the current revision was built from for this account,
	// newest first -- empty when the revision holds nothing of it yet, so an
	// empty surfaces list is never read as "no gaps".
	Runs     []string          `json:"runs"`
	Surfaces []CoverageSurface `json:"surfaces"`
}

// CoverageSurface is one surface of one account, from the newest run the
// current revision holds for it.
type CoverageSurface struct {
	Surface string `json:"surface"`
	State   string `json:"state"`
	// Count is the stored count only when the surface was reached (D-72): a
	// count from a surface that was not is a floor, not a total.
	Count     *int `json:"count"`
	ErrorCode any  `json:"error_code"`
	API       any  `json:"api"`
	// Error is the provider's own words (or the scanner's account of a partial
	// read), shown as written -- never parsed.
	Error any `json:"error"`
	// Items is the per-document detail of a policy_documents surface, stamped
	// at collection (D-71): [{policy, version, error}], bounded, with
	// Truncated when the bound bit. null for a run collected without it.
	Items     []CoverageItem `json:"items"`
	Truncated bool           `json:"truncated"`
	Since     any            `json:"since"`
	SinceRun  any            `json:"since_run"`
	Prevents  any            `json:"prevents"`
	Fix       any            `json:"fix"`
	Run       string         `json:"run"`
	// Ref is the coverage claim (§5.2), for the Evidence panel.
	Ref string `json:"ref"`

	connectorID uuid.UUID
	runID       uuid.UUID
	publishedAt time.Time
}

// CoverageItem is one unreadable document of a policy_documents surface
// (D-71). Only these three fields are rendered, whatever else was stored.
type CoverageItem struct {
	Policy  string `json:"policy"`
	Version string `json:"version"`
	Error   string `json:"error"`
}

// coverageRun is one run the current revision was built from.
type coverageRun struct {
	ID          uuid.UUID
	ConnectorID uuid.UUID
	PublishedAt *time.Time
	Coverage    []byte
}

// coverageWatermark is one partition's watermark (iga_projection_state): the
// run the current revision holds that partition from.
type coverageWatermark struct {
	ConnectorID   uuid.UUID
	EstateScopeID uuid.UUID
	PartitionKey  string
	LastRunID     uuid.UUID
}

// coverageScope is the set of surfaces an OLDER run still speaks for: the
// RequiredSurfaces and RequiredScanners of the partitions whose watermark it
// is -- the surfaces that decided what those partitions could end.
//
// The partitions are the projector's own (igagraph.Partitions over this run's
// coverage, with the watermark's scope and connector), matched by key, so the
// read side never re-derives which surface a partition needs. A watermark
// whose key this build does not produce (a partition kind renamed since, D-60)
// cannot be scoped: nil, and the run's every surface is shown -- an old gap
// shown is a claim of less, a hidden one would be a claim of more.
func coverageScope(run coverageRun, cov models.ScanCoverage, marks []coverageWatermark) map[string]bool {
	if len(marks) == 0 {
		return nil
	}
	byKey := map[string]igagraph.Partition{}
	built := map[uuid.UUID]bool{}
	scope := map[string]bool{}
	for _, m := range marks {
		if !built[m.EstateScopeID] {
			built[m.EstateScopeID] = true
			snap := &igagraph.Snapshot{
				ScopeID:  m.EstateScopeID,
				Run:      models.CloudScanRun{ID: run.ID, ConnectorID: run.ConnectorID},
				Coverage: cov.Surfaces,
			}
			for _, p := range igagraph.Partitions(snap) {
				byKey[p.Key()] = p
			}
		}
		p, ok := byKey[m.PartitionKey]
		if !ok {
			return nil
		}
		for _, name := range p.RequiredSurfaces {
			scope[name] = true
		}
		for _, name := range p.RequiredScanners {
			scope[name] = true
		}
	}
	return scope
}

// coverageDetail decodes the optional per-surface detail D-71 adds to a run's
// coverage, beside the typed models.ScanCoverage.
type coverageDetail struct {
	Surfaces map[string]struct {
		Items     []CoverageItem `json:"items"`
		Truncated bool           `json:"truncated"`
	} `json:"surfaces"`
}

// Coverage reads per-account, per-surface coverage in the snapshot. accounts
// filters by account id (?account=, repeatable); empty means every account.
// With nothing published the result is empty (the caller reports
// graph_state: not_published).
func (q *Query) Coverage(accounts []string) ([]CoverageAccount, error) {
	out := []CoverageAccount{}
	if !q.Published() {
		return out, nil
	}
	tx := q.DB()

	dir, err := q.LoadAccounts()
	if err != nil {
		return nil, err
	}
	var connectors []models.CloudConnector
	if q.includeProvider(models.ProviderAWS) {
		if err := tx.Where("workspace_id = ? AND provider = ?", q.WS, models.CloudProviderAWS).
			Find(&connectors).Error; err != nil {
			return nil, err
		}
	}
	want := map[string]bool{}
	for _, a := range accounts {
		want[a] = true
	}
	byConnector := map[uuid.UUID]*CoverageAccount{}
	labels := map[uuid.UUID]string{}
	order := []uuid.UUID{}
	for i := range connectors {
		c := &connectors[i]
		if len(want) > 0 && !want[c.ScopeID] {
			continue
		}
		recorded := c.AWSAttrs().TemplateVersion
		byConnector[c.ID] = &CoverageAccount{
			Integration:     R(RefConnector, c.ID),
			Account:         dir.Of(c.ScopeID),
			ConnectorStatus: c.Status,
			Template: map[string]any{
				"deployed": nullIfBlank(recorded),
				"current":  awsdiscovery.TemplateVersion,
				"outdated": awsdiscovery.TemplateOutdated(recorded),
			},
			Runs:     []string{},
			Surfaces: []CoverageSurface{},
		}
		labels[c.ID] = strings.ToLower(connectorLabel(c.Attrs, c.ScopeID))
		order = append(order, c.ID)
	}
	if len(order) == 0 {
		return q.appendIntegrationCoverage(out)
	}
	// Ordered by label then id, like /pipeline (D-92).
	sort.SliceStable(order, func(i, j int) bool {
		if labels[order[i]] != labels[order[j]] {
			return labels[order[i]] < labels[order[j]]
		}
		return order[i].String() < order[j].String()
	})

	// The runs the current revision was built from: every partition watermark
	// of these connectors. Usually one run per connector (its latest projected
	// run); an older one where a partition the latest run did not carry still
	// stands on it.
	var watermarks []coverageWatermark
	if err := tx.Raw(`
		SELECT ps.connector_id, ps.estate_scope_id, ps.partition_key, ps.last_run_id
		  FROM iga_projection_state ps
		 WHERE ps.workspace_id = ? AND ps.connector_id IN ?`,
		q.WS, order).Scan(&watermarks).Error; err != nil {
		return nil, err
	}
	standing := map[uuid.UUID][]coverageWatermark{} // run -> the partitions standing on it
	runIDs := []uuid.UUID{}
	for _, w := range watermarks {
		if _, ok := standing[w.LastRunID]; !ok {
			runIDs = append(runIDs, w.LastRunID)
		}
		standing[w.LastRunID] = append(standing[w.LastRunID], w)
	}
	var runs []coverageRun
	if len(runIDs) > 0 {
		if err := tx.Raw(`
			SELECT r.id, r.connector_id, r.published_at, r.coverage
			  FROM cloud_scan_run r
			 WHERE r.workspace_id = ? AND r.id IN ?`,
			q.WS, runIDs).Scan(&runs).Error; err != nil {
			return nil, err
		}
	}
	// Newest first, so each surface is taken from the newest run that carries
	// it: that run is the latest word on the surface in this revision.
	sort.Slice(runs, func(i, j int) bool {
		if !pubTime(runs[i]).Equal(pubTime(runs[j])) {
			return pubTime(runs[i]).After(pubTime(runs[j]))
		}
		return runs[i].ID.String() > runs[j].ID.String()
	})
	seen := map[uuid.UUID]map[string]bool{}
	for _, run := range runs {
		acct := byConnector[run.ConnectorID]
		if acct == nil {
			continue
		}
		// The connector's NEWEST run is the latest word on every surface it
		// carries. An OLDER run speaks only for the partitions still standing
		// on it: a surface is taken from it only when one of those partitions
		// requires or vetoes on it (coverageScope). Its connector-wide
		// failure -- a permission_scan stand-in, say -- stood for partitions a
		// newer run has since re-read, and showing it would claim a gap the
		// revision no longer has.
		newest := seen[run.ConnectorID] == nil
		acct.Runs = append(acct.Runs, R(RefScanRun, run.ID))
		if newest {
			seen[run.ConnectorID] = map[string]bool{}
		}
		cov := models.DecodeScanCoverage(run.Coverage)
		var scope map[string]bool
		if !newest {
			scope = coverageScope(run, cov, standing[run.ID])
		}
		var detail coverageDetail
		_ = json.Unmarshal(run.Coverage, &detail) // optional; absent is null
		for name, s := range cov.Surfaces {
			if seen[run.ConnectorID][name] {
				continue
			}
			if scope != nil && !scope[name] {
				continue
			}
			seen[run.ConnectorID][name] = true
			entry := CoverageSurface{
				Surface: name, State: s.State,
				ErrorCode: nullIfBlank(s.ErrorCode), API: nullIfBlank(s.API),
				Error:    nullIfBlank(s.Error),
				Prevents: Prevents(name, s.State),
				Run:      R(RefScanRun, run.ID),
				Ref:      CoverageRef(run.ID, name),

				connectorID: run.ConnectorID,
				runID:       run.ID,
				publishedAt: pubTime(run),
			}
			if d, ok := detail.Surfaces[name]; ok && d.Items != nil {
				entry.Items, entry.Truncated = d.Items, d.Truncated
			}
			switch s.State {
			case models.CloudCoverageReached:
				// A reached surface failed nothing: its count stands, and it
				// has no call, no code and no detail, however it was written.
				count := s.Count
				entry.Count = &count
				entry.ErrorCode, entry.API, entry.Error = nil, nil, nil
				entry.Items, entry.Truncated = nil, false
			case models.CloudCoverageNotSelected:
				entry.Fix = FixChangeRegions
			}
			acct.Surfaces = append(acct.Surfaces, entry)
		}
	}

	all := []*CoverageSurface{}
	for _, id := range order {
		acct := byConnector[id]
		sort.Slice(acct.Surfaces, func(i, j int) bool { return acct.Surfaces[i].Surface < acct.Surfaces[j].Surface })
		for i := range acct.Surfaces {
			all = append(all, &acct.Surfaces[i])
		}
	}
	if err := q.coverageSince(all); err != nil {
		return nil, err
	}
	for _, id := range order {
		out = append(out, *byConnector[id])
	}
	return q.appendIntegrationCoverage(out)
}

// appendIntegrationCoverage adds one row per opted-in iga integration after
// the AWS account rows. A default read leaves the AWS slice as it was.
func (q *Query) appendIntegrationCoverage(out []CoverageAccount) ([]CoverageAccount, error) {
	if !q.V2 {
		return out, nil
	}
	var rows []struct {
		ID            uuid.UUID
		Provider      string
		Status        string
		CoverageState *string
		RunID         *uuid.UUID
	}
	if err := q.DB().Raw(`SELECT i.id, i.provider, i.status, ps.coverage_state, ps.last_iga_scan_run_id AS run_id
		FROM iga_integrations i
		LEFT JOIN iga_projection_state ps
		  ON ps.workspace_id = i.workspace_id AND ps.integration_id = i.id
		WHERE i.workspace_id = ?
		ORDER BY i.provider, i.id`, q.WS).Scan(&rows).Error; err != nil {
		return nil, err
	}
	seen := map[uuid.UUID]bool{}
	for _, r := range rows {
		if !q.includeProvider(r.Provider) || r.Provider == models.ProviderAWS || seen[r.ID] {
			continue
		}
		seen[r.ID] = true
		acct := CoverageAccount{
			Integration:     "integration:" + r.ID.String(),
			ConnectorStatus: r.Status,
			Template:        map[string]any{},
			Runs:            []string{},
			Surfaces:        []CoverageSurface{},
		}
		run := ""
		if r.RunID != nil {
			run = "iga_scan_run:" + r.RunID.String()
			acct.Runs = append(acct.Runs, run)
		}
		if r.CoverageState != nil && *r.CoverageState != "" {
			acct.Surfaces = append(acct.Surfaces, CoverageSurface{
				Surface: "projection", State: *r.CoverageState, Run: run,
			})
		}
		out = append(out, acct)
	}
	return out, nil
}

// coverageSince fills since (D-72: "first run in the current state", §5.3):
// the published_at of the EARLIEST run of the unbroken streak, walking back
// from the run shown through the connector's published runs, in which the
// surface had this state. A run whose coverage lacks the surface breaks the
// streak -- absent is not the same state -- so since is never earlier than the
// runs prove. The walk covers at most sinceWalkLimit runs; a streak longer
// than that is null (not known), never the oldest run looked at.
//
// OPTIONAL work (§5.1): the walk reads run history, which grows without bound,
// so it runs in a savepoint; if it does not finish, since and since_run are
// null, never guessed, and the rest of the response stands.
func (q *Query) coverageSince(entries []*CoverageSurface) error {
	if len(entries) == 0 {
		return nil
	}
	// One walk per (connector, run shown): every surface an account shows from
	// the same run shares it.
	type start struct {
		connector, run uuid.UUID
		at             time.Time
	}
	var starts []start
	index := map[uuid.UUID]int{}
	for _, e := range entries {
		if _, ok := index[e.runID]; !ok {
			index[e.runID] = len(starts)
			starts = append(starts, start{connector: e.connectorID, run: e.runID, at: e.publishedAt})
		}
	}
	values := make([]string, 0, len(starts))
	args := []any{}
	for i, s := range starts {
		values = append(values, "(?::int, ?::uuid, ?::uuid, ?::timestamptz)")
		args = append(args, i, s.connector, s.run, s.at)
	}
	// The state of every surface of each walked run, as one small object --
	// not the whole coverage blob -- newest first, one more than the limit so
	// a streak that fills the window can be told from one that ends in it.
	stmt := fmt.Sprintf(`
		SELECT v.k, w.id, w.published_at, w.states
		  FROM (VALUES %s) AS v(k, cid, rid, at)
		  CROSS JOIN LATERAL (
		        SELECT r.id, r.published_at,
		               CASE WHEN jsonb_typeof(r.coverage->'surfaces') = 'object'
		                    THEN (SELECT jsonb_object_agg(s.key, s.value->>'state')
		                            FROM jsonb_each(r.coverage->'surfaces') s)
		               END AS states
		          FROM cloud_scan_run r
		         WHERE r.workspace_id = ? AND r.connector_id = v.cid AND r.status = ?
		           AND (r.published_at, r.id) <= (v.at, v.rid)
		         ORDER BY r.published_at DESC, r.id DESC
		         LIMIT %d) w
		 ORDER BY v.k, w.published_at DESC, w.id DESC`, strings.Join(values, ", "), sinceWalkLimit+1)
	args = append(args, q.WS, models.CloudScanRunPublished)

	var rows []struct {
		K           int
		ID          uuid.UUID
		PublishedAt time.Time
		States      []byte
	}
	ok, err := q.Optional(func(tx *gorm.DB) error {
		return tx.Raw(stmt, args...).Scan(&rows).Error
	})
	if err != nil {
		return err
	}
	if !ok {
		return nil // not known in time: since stays null
	}

	type walked struct {
		id     uuid.UUID
		at     time.Time
		states map[string]string
	}
	walks := make([][]walked, len(starts))
	for _, r := range rows {
		if r.K < 0 || r.K >= len(starts) {
			continue
		}
		w := walked{id: r.ID, at: r.PublishedAt, states: map[string]string{}}
		_ = json.Unmarshal(r.States, &w.states) // null states: every surface absent
		walks[r.K] = append(walks[r.K], w)
	}
	for _, e := range entries {
		walk := walks[index[e.runID]]
		if len(walk) == 0 || walk[0].id != e.runID {
			continue // the run shown is not where the walk starts: not known
		}
		earliest := -1
		broken := false
		for i := 0; i < len(walk) && i < sinceWalkLimit; i++ {
			if st, ok := walk[i].states[e.Surface]; !ok || st != e.State {
				broken = true
				break
			}
			earliest = i
		}
		if earliest < 0 {
			continue
		}
		if !broken && len(walk) > sinceWalkLimit {
			if st, ok := walk[sinceWalkLimit].states[e.Surface]; ok && st == e.State {
				continue // the streak runs past the walk: not known
			}
		}
		at := walk[earliest].at
		e.Since = TS(&at)
		e.SinceRun = R(RefScanRun, walk[earliest].id)
	}
	return nil
}

func pubTime(r coverageRun) time.Time {
	if r.PublishedAt == nil {
		return time.Time{}
	}
	return *r.PublishedAt
}

func nullIfBlank(s string) any {
	if s == "" {
		return nil
	}
	return s
}
