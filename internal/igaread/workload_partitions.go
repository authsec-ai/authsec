package igaread

// The partitions behind a workload's answers (SPEC-iga-phase2-graph.md §4.10,
// §2.14.14; D-57, D-58, D-73, D-74), for GET /workloads/:id and its tabs.
//
// Every row the workload routes return was reconciled under one partition of
// one connector, and the current revision holds that partition from one run:
// its watermark, iga_projection_state.last_run_id, written in the
// publication's own transaction (D-57), so this snapshot sees exactly the run
// the row came from. Two things are read from that run:
//
//   - meta.coverage (D-73): every surface the partitions behind THIS answer
//     required and that run did not reach -- "detail responses carry entries
//     for the object's own partitions". Nothing about a region or a service
//     the answer does not rest on.
//   - stale_reason on a stale edge (D-74): the gaps of the edge's own
//     partition in the run it was last projected from.
//
// The partitions are igagraph's own -- igagraph.Partitions over the run's
// coverage, with the watermark's scope and connector -- matched by key, so the
// read side never re-derives which surface a partition needs (coverageScope
// does the same). A key this build does not produce (a partition kind renamed
// since, D-60) matches nothing and explains nothing, which can only
// under-explain a stale row, never invent a reason.

import (
	"sort"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/authsec-ai/authsec/internal/igagraph"
	"github.com/authsec-ai/authsec/models"
)

// PartitionPair names one partition a row was reconciled under: the connector
// and the partition key stamped on the row (support rows, relationships,
// assignments and grants all carry both).
type PartitionPair struct {
	ConnectorID  uuid.UUID
	PartitionKey string
}

// workloadResolvedPart is one partition with the run the current revision holds
// it from, and every partition igagraph builds for that run (so a tab can pick
// the partitions its other rows are reconciled under from the same run).
type workloadResolvedPart struct {
	part igagraph.Partition
	run  *staleRun
	all  []igagraph.Partition
}

// resolveWorkloadParts finds each pair's partition and watermark run, in the
// snapshot. A pair with no watermark, or whose key igagraph does not build for
// that run, is absent from the result.
func (q *Query) resolveWorkloadParts(pairs []PartitionPair) (map[PartitionPair]*workloadResolvedPart, error) {
	out := map[PartitionPair]*workloadResolvedPart{}
	if len(pairs) == 0 {
		return out, nil
	}
	conns, keys := []uuid.UUID{}, []string{}
	seenC, seenK := map[uuid.UUID]bool{}, map[string]bool{}
	want := map[PartitionPair]bool{}
	for _, p := range pairs {
		want[p] = true
		if !seenC[p.ConnectorID] {
			seenC[p.ConnectorID] = true
			conns = append(conns, p.ConnectorID)
		}
		if !seenK[p.PartitionKey] {
			seenK[p.PartitionKey] = true
			keys = append(keys, p.PartitionKey)
		}
	}
	var marks []coverageWatermark
	if err := q.DB().Raw(`SELECT connector_id, estate_scope_id, partition_key, last_run_id
	                        FROM iga_projection_state
	                       WHERE workspace_id = ? AND connector_id IN ? AND partition_key IN ?`,
		q.WS, conns, keys).Scan(&marks).Error; err != nil {
		return nil, err
	}
	return q.resolveWatermarks(marks, want)
}

// resolveWatermarks resolves watermark rows to their partitions and runs: one
// read of the runs, and one igagraph.Partitions per (scope, run). want, when
// not nil, keeps only those pairs.
func (q *Query) resolveWatermarks(marks []coverageWatermark, want map[PartitionPair]bool) (map[PartitionPair]*workloadResolvedPart, error) {
	out := map[PartitionPair]*workloadResolvedPart{}
	runIDs := []uuid.UUID{}
	seenR := map[uuid.UUID]bool{}
	for _, m := range marks {
		if !seenR[m.LastRunID] {
			seenR[m.LastRunID] = true
			runIDs = append(runIDs, m.LastRunID)
		}
	}
	if len(runIDs) == 0 {
		return out, nil
	}
	var runs []staleRun
	if err := q.DB().Raw(`SELECT id, connector_id, published_at, coverage FROM cloud_scan_run
	                       WHERE workspace_id = ? AND id IN ?`, q.WS, runIDs).Scan(&runs).Error; err != nil {
		return nil, err
	}
	runByID := map[uuid.UUID]*staleRun{}
	for i := range runs {
		runs[i].decode()
		runByID[runs[i].ID] = &runs[i]
	}

	// One igagraph.Partitions per (scope, run): the same list the projector
	// built that run's keys from.
	type built struct {
		all   []igagraph.Partition
		byKey map[string]igagraph.Partition
	}
	cache := map[[2]uuid.UUID]*built{}
	for _, m := range marks {
		pair := PartitionPair{ConnectorID: m.ConnectorID, PartitionKey: m.PartitionKey}
		run := runByID[m.LastRunID]
		if (want != nil && !want[pair]) || run == nil {
			continue
		}
		ck := [2]uuid.UUID{m.EstateScopeID, run.ID}
		b := cache[ck]
		if b == nil {
			snap := &igagraph.Snapshot{
				ScopeID:  m.EstateScopeID,
				Run:      models.CloudScanRun{ID: run.ID, ConnectorID: run.ConnectorID},
				Coverage: run.cov.Surfaces,
			}
			b = &built{all: igagraph.Partitions(snap), byKey: map[string]igagraph.Partition{}}
			for _, p := range b.all {
				b.byKey[p.Key()] = p
			}
			cache[ck] = b
		}
		if p, ok := b.byKey[m.PartitionKey]; ok {
			out[pair] = &workloadResolvedPart{part: p, run: run, all: b.all}
		}
	}
	return out, nil
}

// workloadCoverageGaps is every required surface and scanner of p that run reported
// and did not reach, as meta.coverage names it (D-73, the lists' rule):
// unsupported is ours to build, never the customer's gap; not_selected is
// reported stale (nobody looked; earlier results are kept and marked stale,
// D-58, §2.14.13).
func workloadCoverageGaps(p igagraph.Partition, cov models.ScanCoverage) []surfaceGap {
	var gaps []surfaceGap
	for _, name := range append(append([]string{}, p.RequiredSurfaces...), p.RequiredScanners...) {
		st, present := stateIn(cov, name)
		if !present {
			continue
		}
		switch st {
		case models.CloudCoverageReached, models.CloudCoverageUnsupported:
			continue
		case models.CloudCoverageNotSelected:
			st = models.CloudCoverageStale
		}
		gaps = append(gaps, surfaceGap{name, st})
	}
	return gaps
}

// workloadCoverageAffects is the fixed per-surface affects text (D-73): the list
// routes' own table (listsAffects), read in the order a workload's answer
// rests on it -- its runtime surfaces, then its identities, then the
// permissions its identities hold.
func workloadCoverageAffects(surface string) string {
	for _, list := range []string{listsRouteWorkloads, listsRouteIdentities, listsRouteResources} {
		if a := listsAffects(list, surface, listsScope{}); a != "" {
			return a
		}
	}
	return "this workload's graph"
}

// workloadNodeParts resolves the workload's own node partitions: one per
// non-ended support row (normally one: the connector that collected it, its
// runtime and region). A retired workload has none, and its tabs report no
// coverage -- there is no current answer for a gap to bear on.
func (q *Query) workloadNodeParts(workloadID uuid.UUID) ([]*workloadResolvedPart, error) {
	var rows []PartitionPair
	if err := q.DB().Raw(`SELECT connector_id, partition_key FROM iga_object_support
	                       WHERE workspace_id = ? AND workload_id = ? AND state <> 'ended'
	                       ORDER BY connector_id, partition_key`, q.WS, workloadID).Scan(&rows).Error; err != nil {
		return nil, err
	}
	res, err := q.resolveWorkloadParts(rows)
	if err != nil {
		return nil, err
	}
	out := []*workloadResolvedPart{}
	for _, r := range rows {
		if rp := res[r]; rp != nil {
			out = append(out, rp)
		}
	}
	return out, nil
}

// workloadTrustParts resolves the trust-document partition (can_assume, kind
// "trust") of EVERY connector of the workspace, each from the run the current
// revision holds it from: what the Identities tab's may_assume rests on.
//
// Not only the workload's own connector's: a can_assume edge is reconciled
// under the connector that READ the trust document -- the trusting role's
// account (igagraph trust.go stamps the reading run's connector and
// partition) -- and a role in any connected account may name the execution
// identity as its principal. So an account whose roles were not read bears on
// may_assume whether or not an edge from it exists yet: its rows could be
// stale (stale_reason says so, row by row) or missing altogether, and only
// meta.coverage can say that (§2.14.14 "every gap that bears on this
// result"). Which partitions are trust partitions is igagraph's own
// MatchesEdge over the watermark's stored relationship_type, never parsed from
// the key (D-57). Two statements: the watermarks, then their runs.
func (q *Query) workloadTrustParts() ([]*workloadResolvedPart, error) {
	var marks []coverageWatermark
	if err := q.DB().Raw(`SELECT connector_id, estate_scope_id, partition_key, last_run_id
	                        FROM iga_projection_state
	                       WHERE workspace_id = ? AND relationship_type = ?
	                       ORDER BY connector_id, partition_key`,
		q.WS, models.RelTypeCanAssume).Scan(&marks).Error; err != nil {
		return nil, err
	}
	res, err := q.resolveWatermarks(marks, nil)
	if err != nil {
		return nil, err
	}
	out := []*workloadResolvedPart{}
	for _, m := range marks {
		rp := res[PartitionPair{ConnectorID: m.ConnectorID, PartitionKey: m.PartitionKey}]
		if rp != nil && rp.part.MatchesEdge(models.RelTypeCanAssume, "trust", "") {
			out = append(out, rp)
		}
	}
	return out, nil
}

// workloadCoverageScope chooses, from the runs a workload's node partitions
// were projected from, the partitions one response rests on. The node
// partition itself is always included.
type workloadCoverageScope struct {
	// Execution: the workload's executes_as partition (and ECS's
	// task_execution_role): its runtime surface plus iam_roles.
	Execution bool
	// Memberships: member_of (the Identities tab's groups).
	Memberships bool
	// Trust: the trust partitions may_assume rests on (workloadTrustParts),
	// each reported under its OWN connector's account, with that connector's
	// revoked note when it is revoked (D-73 "a revoked account in scope").
	Trust []*workloadResolvedPart
	// Permissions: assignments and grants, plus policy_documents -- an
	// unreadable document protects its grants row by row, not through a
	// partition (§4.10), so it is named when the run did not reach it.
	Permissions bool
}

// workloadCoverage is meta.coverage for a workload detail or tab (D-73): the
// gaps of the partitions this answer rests on, per account and surface, from
// the runs the current revision holds them from; plus {account_id, surface:
// "*", state: "revoked"} for each revoked connector in scope -- the
// workload's own, or one whose trust partition may_assume rests on (D-73,
// D-89). Sorted by account, then surface; one entry per (account, surface).
func (q *Query) workloadCoverage(accts *Accounts, w *WorkloadRecord, nodes []*workloadResolvedPart, scope workloadCoverageScope) []CoverageNote {
	type key struct{ account, surface string }
	seen := map[key]bool{}
	notes := []CoverageNote{}
	add := func(conn uuid.UUID, gaps []surfaceGap) {
		acct := ""
		if c := accts.Connector(conn); c != nil {
			acct = c.AccountID
		}
		for _, g := range gaps {
			k := key{acct, g.surface}
			if seen[k] {
				continue
			}
			seen[k] = true
			notes = append(notes, CoverageNote{AccountID: acct, Surface: g.surface, State: g.state, Affects: workloadCoverageAffects(g.surface)})
		}
	}
	revoked := map[uuid.UUID]bool{}
	noteRevoked := func(conn uuid.UUID) {
		if c := accts.Connector(conn); c != nil && c.Status == models.CloudConnectorRevoked && !revoked[conn] {
			revoked[conn] = true
			k := key{c.AccountID, "*"}
			if !seen[k] {
				seen[k] = true
				notes = append(notes, CoverageNote{AccountID: c.AccountID, Surface: "*",
					State: models.CloudConnectorRevoked, Affects: "everything this account's connector collected"})
			}
		}
	}
	for _, n := range nodes {
		conn := n.part.ConnectorID
		add(conn, workloadCoverageGaps(n.part, n.run.cov))
		for _, p := range n.all {
			if p.Target == "" {
				continue
			}
			pick := false
			switch {
			case scope.Execution && p.MatchesEdge(models.RelTypeExecutesAs, w.RuntimeKind, w.Region):
				pick = true
			case scope.Execution && w.RuntimeKind == models.WorkloadECSTaskDefinition &&
				p.MatchesEdge(models.RelTypeTaskExecutionRole, w.RuntimeKind, w.Region):
				pick = true
			case scope.Memberships && p.RelationshipType == models.RelTypeMemberOf:
				pick = true
			case scope.Permissions && (p.Target == "assignment" || p.Target == "access_edge"):
				pick = true
			}
			if pick {
				add(conn, workloadCoverageGaps(p, n.run.cov))
			}
		}
		if scope.Permissions {
			if st, present := stateIn(n.run.cov, models.SurfacePolicyDocuments); present &&
				st != models.CloudCoverageReached && st != models.CloudCoverageUnsupported {
				if st == models.CloudCoverageNotSelected {
					st = models.CloudCoverageStale
				}
				add(conn, []surfaceGap{{models.SurfacePolicyDocuments, st}})
			}
		}
		noteRevoked(conn)
	}
	for _, t := range scope.Trust {
		add(t.part.ConnectorID, workloadCoverageGaps(t.part, t.run.cov))
		noteRevoked(t.part.ConnectorID)
	}
	sort.Slice(notes, func(i, j int) bool {
		if notes[i].AccountID != notes[j].AccountID {
			return notes[i].AccountID < notes[j].AccountID
		}
		return notes[i].Surface < notes[j].Surface
	})
	return notes
}

// EdgePartition is one edge row (a relationship or a grant) for
// EdgeStaleReasons: its id and the partition it was reconciled under.
type EdgePartition struct {
	ID           uuid.UUID
	ConnectorID  *uuid.UUID
	PartitionKey string
	// Documents: the row is protected by its policy document (a grant), so
	// an unreached policy_documents surface explains its staleness when no
	// partition surface does (D-74 "a document-protected row names
	// policy_documents").
	Documents bool
}

// EdgeStaleReasons is D-74's stale_reason for STALE edges, the edge
// counterpart of NodeStaleReasons: for each edge, the gaps its own partition
// had in the run the current revision holds that partition from -- required
// surfaces and scanners present and not reached; failing those, required
// surfaces absent from the report ("unknown": the run did not look); failing
// those, for a document-protected row, the run's policy_documents surface.
// since is the start of the surface's unbroken streak in that state over the
// connector's last StaleHistoryRuns published runs, read as OPTIONAL work
// (null when it does not finish, or the window does not show the start).
//
// Pass only stale edges. Every edge passed is in the result, with [] when no
// recorded coverage explains it.
func (q *Query) EdgeStaleReasons(accts *Accounts, edges []EdgePartition) (map[uuid.UUID][]StaleReason, error) {
	out := map[uuid.UUID][]StaleReason{}
	pairs := []PartitionPair{}
	for _, e := range edges {
		out[e.ID] = []StaleReason{}
		if e.ConnectorID != nil && e.PartitionKey != "" {
			pairs = append(pairs, PartitionPair{ConnectorID: *e.ConnectorID, PartitionKey: e.PartitionKey})
		}
	}
	res, err := q.resolveWorkloadParts(pairs)
	if err != nil {
		return nil, err
	}
	type pending struct {
		edge uuid.UUID
		run  *staleRun
		gap  surfaceGap
	}
	var found []pending
	for _, e := range edges {
		if e.ConnectorID == nil {
			continue
		}
		rp := res[PartitionPair{ConnectorID: *e.ConnectorID, PartitionKey: e.PartitionKey}]
		if rp == nil {
			continue
		}
		class := ""
		if e.Documents {
			class = models.ObjectEntitlement // partitionGaps' document-protected fallback
		}
		for _, g := range partitionGaps(rp.part, rp.run.cov, class) {
			found = append(found, pending{edge: e.ID, run: rp.run, gap: g})
		}
	}
	if len(found) == 0 {
		return out, nil
	}

	// since: one optional read of each involved connector's recent published
	// runs, bounded by the newest run any of its partitions was projected
	// from -- NodeStaleReasons' walk, over the same window.
	conns := []uuid.UUID{}
	seenConn := map[uuid.UUID]bool{}
	for _, f := range found {
		if !seenConn[f.run.ConnectorID] {
			seenConn[f.run.ConnectorID] = true
			conns = append(conns, f.run.ConnectorID)
		}
	}
	var hist []staleRun
	haveHistory, err := q.Optional(func(tx *gorm.DB) error {
		return tx.Raw(`SELECT id, connector_id, published_at, coverage FROM (
		                   SELECT sr.id, sr.connector_id, sr.published_at, sr.coverage,
		                          row_number() OVER (PARTITION BY sr.connector_id
		                                             ORDER BY sr.published_at DESC, sr.id DESC) AS n
		                     FROM cloud_scan_run sr
		                    WHERE sr.workspace_id = ? AND sr.connector_id IN ? AND sr.published_at IS NOT NULL
		                      AND sr.published_at <= (
		                          SELECT max(pr.published_at)
		                            FROM iga_projection_state ps
		                            JOIN cloud_scan_run pr ON pr.workspace_id = ps.workspace_id AND pr.id = ps.last_run_id
		                           WHERE ps.workspace_id = sr.workspace_id AND ps.connector_id = sr.connector_id)) x
		                WHERE n <= ?
		                ORDER BY connector_id, published_at DESC, id DESC`,
			q.WS, conns, StaleHistoryRuns+1).Scan(&hist).Error
	})
	if err != nil {
		return nil, err
	}
	history := map[uuid.UUID][]staleRun{}
	for i := range hist {
		hist[i].decode()
		history[hist[i].ConnectorID] = append(history[hist[i].ConnectorID], hist[i])
	}
	for _, f := range found {
		var since any
		if haveHistory {
			since = TS(streakSince(history[f.run.ConnectorID], f.run.ID, f.gap.surface, f.gap.state))
		}
		acct := ""
		if c := accts.Connector(f.run.ConnectorID); c != nil {
			acct = c.AccountID
		}
		out[f.edge] = append(out[f.edge], StaleReason{AccountID: acct, Surface: f.gap.surface, State: f.gap.state, Since: since})
	}
	for id := range out {
		rs := out[id]
		sort.Slice(rs, func(i, j int) bool {
			if rs[i].AccountID != rs[j].AccountID {
				return rs[i].AccountID < rs[j].AccountID
			}
			return rs[i].Surface < rs[j].Surface
		})
		out[id] = dedupeReasons(rs)
	}
	return out, nil
}
