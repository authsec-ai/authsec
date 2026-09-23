package igaread

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/awsdiscovery"
	"github.com/authsec-ai/authsec/models"
)

// GET /api/iga/v1/coverage (SPEC-iga-phase2-graph.md §5.3, §2.14.13): per
// account and surface, what the runs the CURRENT REVISION was built from could
// read -- and which conclusion each gap prevents.
//
// "The runs the current revision was built from" (D-57, corrected): every
// partition's watermark, iga_projection_state.last_run_id, per connector. The
// rows are written in the publication's own transaction, so inside this
// request's snapshot they are exactly the current revision's. The manifest is
// not used: its key (Partition.Key()) omits the connector.
//
// NEVER a guessed missing permission (§2.14.13, E9): error_code and api are
// what the SDK reported when the read failed (awsdiscovery.FailedCall, stored
// with the run's coverage), or null. Nothing here maps a failed call to an IAM
// action someone should grant.

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

// SurfaceOrganizations is the AWS Organizations surface (T3.8 records it
// unsupported).
const SurfaceOrganizations = "organizations"

// Prevents maps a surface's state to the limitation it imposes (D-58):
// denied -> surface_denied; partial -> surface_partial; throttled, error,
// unknown -> surface_stale; organizations unsupported ->
// organizations_not_collected; reached and not_selected -> null.
//
// States D-58 does not name are mapped by what they mean for the rows:
// constrained is a refused read (surface_denied); stale is surface_stale;
// not_configured and any other unsupported surface claim nothing, like
// not_selected. An unrecognised state is surface_stale -- a read we meant to
// make did not complete, so nothing it covers may be treated as confirmed.
func Prevents(surface, state string) any {
	switch state {
	case models.CloudCoverageReached, models.CloudCoverageNotSelected, models.CloudCoverageNotConfigured:
		return nil
	case models.CloudCoverageDenied, models.CloudCoverageConstrained:
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

// CoverageAccount is one account's coverage.
type CoverageAccount struct {
	Integration string   `json:"integration"`
	Account     *Account `json:"account"`
	// TemplateVersion is the CloudFormation template version recorded when
	// the account was onboarded, and the one this build ships. Facts only:
	// nothing refreshes the recorded value after a stack update, so "update
	// the stack" is not offered on it (spec question raised).
	TemplateVersion map[string]any    `json:"template_version"`
	Surfaces        []CoverageSurface `json:"surfaces"`
}

// CoverageSurface is one surface of one account, from the newest run the
// current revision holds for it.
type CoverageSurface struct {
	Surface   string `json:"surface"`
	State     string `json:"state"`
	Count     int    `json:"count"`
	ErrorCode any    `json:"error_code"`
	API       any    `json:"api"`
	// Error is the provider's own words (or the scanner's account of a partial
	// read, naming the documents it could not read).
	Error    any    `json:"error"`
	Since    any    `json:"since"`
	SinceRun any    `json:"since_run"`
	Prevents any    `json:"prevents"`
	Fix      any    `json:"fix"`
	Run      string `json:"run"`
	// Ref is the coverage claim (§5.2), for the Evidence panel.
	Ref string `json:"ref"`

	connectorID uuid.UUID
	publishedAt time.Time
}

// coverageRun is one run the current revision was built from.
type coverageRun struct {
	ID          uuid.UUID
	ConnectorID uuid.UUID
	PublishedAt *time.Time
	Coverage    []byte
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
	if err := tx.Where("workspace_id = ? AND provider = ?", q.WS, models.CloudProviderAWS).
		Order("created_at, id").Find(&connectors).Error; err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, a := range accounts {
		want[a] = true
	}
	byConnector := map[uuid.UUID]*CoverageAccount{}
	order := []uuid.UUID{}
	for i := range connectors {
		c := &connectors[i]
		if len(want) > 0 && !want[c.ScopeID] {
			continue
		}
		recorded := c.AWSAttrs().TemplateVersion
		acct := &CoverageAccount{
			Integration: R(RefConnector, c.ID),
			Account:     dir.Of(c.ScopeID),
			TemplateVersion: map[string]any{
				"recorded": nullIfBlank(recorded),
				"current":  awsdiscovery.TemplateVersion,
				// Template versions are dates (YYYY-MM-DD), so string order is
				// date order.
				"recorded_older_than_current": recorded != "" && recorded < awsdiscovery.TemplateVersion,
			},
			Surfaces: []CoverageSurface{},
		}
		byConnector[c.ID] = acct
		order = append(order, c.ID)
	}
	if len(order) == 0 {
		return out, nil
	}

	// The runs the current revision was built from: every partition watermark
	// of these connectors. Usually one run per connector (its latest projected
	// run); an older one where a partition the latest run did not carry still
	// stands on it.
	var runs []coverageRun
	if err := tx.Raw(`
		SELECT r.id, r.connector_id, r.published_at, r.coverage
		  FROM cloud_scan_run r
		 WHERE r.workspace_id = ?
		   AND r.id IN (SELECT DISTINCT ps.last_run_id FROM iga_projection_state ps
		                 WHERE ps.workspace_id = ? AND ps.connector_id IN ?)`,
		q.WS, q.WS, order).Scan(&runs).Error; err != nil {
		return nil, err
	}
	// Newest first, so each surface is taken from the newest run that carries
	// it: that run is the latest word on the surface in this revision.
	sort.Slice(runs, func(i, j int) bool {
		return pubTime(runs[i]).After(pubTime(runs[j]))
	})
	seen := map[uuid.UUID]map[string]bool{}
	for _, run := range runs {
		acct := byConnector[run.ConnectorID]
		if acct == nil {
			continue
		}
		if seen[run.ConnectorID] == nil {
			seen[run.ConnectorID] = map[string]bool{}
		}
		cov := models.DecodeScanCoverage(run.Coverage)
		for name, s := range cov.Surfaces {
			if seen[run.ConnectorID][name] {
				continue
			}
			seen[run.ConnectorID][name] = true
			entry := CoverageSurface{
				Surface: name, State: s.State, Count: s.Count,
				ErrorCode: nullIfBlank(s.ErrorCode), API: nullIfBlank(s.API),
				Error:    nullIfBlank(s.Error),
				Prevents: Prevents(name, s.State),
				Run:      R(RefScanRun, run.ID),
				Ref:      CoverageRef(run.ID, name),

				connectorID: run.ConnectorID,
				publishedAt: pubTime(run),
			}
			if s.State == models.CloudCoverageReached {
				// A reached surface failed nothing: no call, no code, however
				// the entry was written.
				entry.ErrorCode, entry.API, entry.Error = nil, nil, nil
			}
			if s.State == models.CloudCoverageNotSelected {
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
	return out, nil
}

// coverageSince fills since (first run in the current state, §5.3): walking
// back from the run shown, through the connector's published runs, the
// earliest run of the unbroken streak in which the surface had this state. A
// run whose coverage lacks the surface breaks the streak -- absent is not the
// same state -- so since is never earlier than the runs prove.
//
// OPTIONAL work (§5.1): the walk reads run history, which grows without bound,
// so it runs in a savepoint; if it does not finish, since and since_run are
// null (not known), never guessed, and the rest of the response stands.
func (q *Query) coverageSince(entries []*CoverageSurface) error {
	if len(entries) == 0 {
		return nil
	}
	values := make([]string, 0, len(entries))
	args := []any{}
	for i, e := range entries {
		values = append(values, "(?::int, ?::uuid, ?::text, ?::text, ?::timestamptz)")
		args = append(args, i, e.connectorID, e.Surface, e.State, e.publishedAt)
	}
	stmt := fmt.Sprintf(`
		SELECT v.k, s.id AS since_run, s.published_at AS since
		  FROM (VALUES %s) AS v(k, cid, surface, state, at)
		  LEFT JOIN LATERAL (
		        SELECT r.id, r.published_at
		          FROM cloud_scan_run r
		         WHERE r.workspace_id = ? AND r.connector_id = v.cid AND r.status = ?
		           AND r.published_at <= v.at
		           AND r.published_at > COALESCE((
		                 SELECT max(b.published_at) FROM cloud_scan_run b
		                  WHERE b.workspace_id = ? AND b.connector_id = v.cid AND b.status = ?
		                    AND b.published_at < v.at
		                    AND (b.coverage->'surfaces'->v.surface->>'state') IS DISTINCT FROM v.state),
		               '-infinity'::timestamptz)
		         ORDER BY r.published_at ASC, r.id ASC
		         LIMIT 1) s ON true`, strings.Join(values, ", "))
	args = append(args, q.WS, models.CloudScanRunPublished, q.WS, models.CloudScanRunPublished)

	var rows []struct {
		K        int
		SinceRun *uuid.UUID
		Since    *time.Time
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
	for _, r := range rows {
		if r.K < 0 || r.K >= len(entries) || r.SinceRun == nil {
			continue
		}
		entries[r.K].Since = TS(r.Since)
		entries[r.K].SinceRun = R(RefScanRun, *r.SinceRun)
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
