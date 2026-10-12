package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/authsec-ai/authsec/internal/ghgraph"
	"github.com/authsec-ai/authsec/internal/tenancy"
	"github.com/authsec-ai/authsec/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

/*
GitHub → the shared IGA graph, keyed.

Two GitHub readings already exist and neither is changed here. The IGA scan
(iga_service.go) writes its own canonical rows -- unkeyed, re-inserted on every
scan, never ended -- and the existing GitHub screens read exactly those. The
repository scanner (discovery_github_scanner.go) writes discovered_agents.

This projects both, a second time, into KEYED rows under provider 'github':
upserted on source_key so a rescan never duplicates, carrying iga_object_support
so the unified inventory can list them, and reconciled so a repository GitHub no
longer reports is retired rather than kept forever. The legacy rows keep
source_key = '' and the legacy readers select only those, so neither reading
can see the other's rows.

Gated on IGA_GRAPH_PROJECTION, like the Kubernetes path: with the switch off
nothing here writes.
*/

// GitHubGraphProjector writes both GitHub readings into the graph.
type GitHubGraphProjector struct {
	db *gorm.DB
	// gate nil means the process-wide gate, read when a projection runs rather
	// than when the projector is built -- a worker started before main sets the
	// switch must still see it.
	gate *GraphProjectionGate
	now  func() time.Time
}

// NewGitHubGraphProjector builds the projector.
func NewGitHubGraphProjector(db *gorm.DB, gate *GraphProjectionGate) *GitHubGraphProjector {
	return &GitHubGraphProjector{db: db, gate: gate, now: time.Now}
}

func (p *GitHubGraphProjector) enabled() bool {
	g := p.gate
	if g == nil {
		g = GraphProjection()
	}
	return g.Enabled()
}

// GitHubGraphResult reports one IGA-scan projection.
type GitHubGraphResult struct {
	// Projected is false when nothing was written, and Reason says why: a
	// projection that wrote nothing because a newer scan already had and one
	// that wrote nothing because nothing was there are the same zeros and
	// opposite facts.
	Projected bool   `json:"projected"`
	Reason    string `json:"reason,omitempty"`

	Resources   int `json:"resources"`
	Identities  int `json:"identities"`
	Credentials int `json:"credentials"`
	Statements  int `json:"statements"`
	Grants      int `json:"grants"`
	Workloads   int `json:"workloads"`

	Reconcile *ghgraph.ReconcileResult `json:"reconcile,omitempty"`
}

// ProjectScan projects one GitHub IGA scan.
//
// succeeded=false is a scan that failed before it read anything: nothing is
// upserted, and every row the integration supports that this scan did not
// confirm is marked stale -- never ended, since a failed scan proves nothing.
//
// Returns (nil, nil) with the switch off.
func (p *GitHubGraphProjector) ProjectScan(workspaceID, scanRunID uuid.UUID,
	snap ghgraph.Snapshot, succeeded bool) (*GitHubGraphResult, error) {

	if !p.enabled() {
		return nil, nil
	}
	if snap.Host == "" {
		snap.Host = "github.com"
	}
	observed := p.now().UTC()
	res := &GitHubGraphResult{}

	// The whole projection runs under row-level security for the workspace.
	ctx := tenancy.WithContext(context.Background(), tenancy.Context{WorkspaceID: workspaceID})
	err := tenancy.RLSTransaction(ctx, p.db, nil, func(tx *gorm.DB, _ uuid.UUID) error {
		// One projection per integration at a time. Two concurrent scans of
		// the same integration would each end what the other just confirmed.
		if err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended(?, 0))`,
			"ghgraph:"+snap.IntegrationID.String()).Error; err != nil {
			return fmt.Errorf("lock integration: %w", err)
		}

		var run struct{ Generation int64 }
		if err := tx.Table("iga_scan_runs").Select("generation").
			Where("workspace_id = ? AND id = ? AND integration_id = ?",
				workspaceID, scanRunID, snap.IntegrationID).
			Take(&run).Error; err != nil {
			return fmt.Errorf("read scan run: %w", err)
		}
		// Fence on the generation, never the clock: a scan that finishes after
		// a newer one has published must not end what the newer one confirmed.
		// The newer scan projects (or projected) the fresher reading.
		var newer int64
		if err := tx.Table("iga_scan_runs").
			Where("workspace_id = ? AND integration_id = ? AND status = ? AND generation > ?",
				workspaceID, snap.IntegrationID, models.ScanSucceeded, run.Generation).
			Count(&newer).Error; err != nil {
			return fmt.Errorf("fence: %w", err)
		}
		if newer > 0 {
			res.Reason = "a newer scan of this integration has already published; " +
				"this one is superseded and wrote nothing"
			return nil
		}

		if succeeded {
			if err := p.attachWorkflows(tx, workspaceID, snap.IntegrationID, run.Generation, &snap); err != nil {
				return fmt.Errorf("workflows: %w", err)
			}
			out := ghgraph.Project(snap)
			if err := p.writeScan(tx, workspaceID, scanRunID, snap, out, observed, res); err != nil {
				return err
			}
		}

		rr, err := ghgraph.NewReconciler(func() time.Time { return observed }).
			Reconcile(tx, ghgraph.ReconcileInput{
				WorkspaceID: workspaceID,
				Scope:       ghgraph.ScopeOf(snap, scanRunID, succeeded),
			})
		if err != nil {
			return fmt.Errorf("reconcile: %w", err)
		}
		res.Reconcile = rr
		res.Projected = true
		if !succeeded {
			res.Reason = "scan failed, so absence is not evidence of deletion; " +
				"what it could not confirm was marked stale, not ended"
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// writeScan upserts one scan's nodes, support and grants.
func (p *GitHubGraphProjector) writeScan(tx *gorm.DB, ws, scanRunID uuid.UUID,
	snap ghgraph.Snapshot, out ghgraph.Result, observed time.Time, res *GitHubGraphResult) error {

	if err := upsertGitHubNodes(tx, "iga_resources", ws, out.Resources, observed,
		func(n ghgraph.Node) map[string]any {
			return map[string]any{"resource_kind": n.Kind, "stage": "unknown"}
		}); err != nil {
		return fmt.Errorf("resources: %w", err)
	}
	if err := upsertGitHubNodes(tx, "iga_identity_accounts", ws, out.Identities, observed,
		func(n ghgraph.Node) map[string]any {
			backing := "provider_native"
			if n.Kind == ghgraph.KindAppInstallation {
				backing = "provider_app"
			}
			return map[string]any{"account_kind": n.Kind, "identity_backing": backing}
		}); err != nil {
		return fmt.Errorf("identities: %w", err)
	}
	if err := upsertGitHubNodes(tx, "iga_workload", ws, out.Workloads, observed,
		func(n ghgraph.Node) map[string]any {
			return map[string]any{"runtime_kind": n.Kind, "retired_reason": ""}
		}); err != nil {
		return fmt.Errorf("workloads: %w", err)
	}

	// Read back rather than remember what we wrote: an upsert that collided
	// with a live row kept THAT row's id, not the one we generated.
	resourceIDs, err := liveGitHubIDs(tx, ws, "iga_resources", liveNode)
	if err != nil {
		return err
	}
	identityIDs, err := liveGitHubIDs(tx, ws, "iga_identity_accounts", liveNode)
	if err != nil {
		return err
	}
	workloadIDs, err := liveGitHubIDs(tx, ws, "iga_workload", liveNode)
	if err != nil {
		return err
	}

	if err := upsertGitHubCredentials(tx, ws, snap.Host, out.Credentials, identityIDs, observed); err != nil {
		return fmt.Errorf("credentials: %w", err)
	}
	if err := upsertGitHubStatements(tx, ws, out.Statements, resourceIDs, observed); err != nil {
		return fmt.Errorf("statements: %w", err)
	}
	statementIDs, err := liveGitHubIDs(tx, ws, "iga_entitlements", liveNode)
	if err != nil {
		return err
	}
	grants, err := upsertGitHubGrants(tx, ws, snap.IntegrationID, scanRunID, out.Grants,
		identityIDs, statementIDs, resourceIDs, observed)
	if err != nil {
		return fmt.Errorf("grants: %w", err)
	}

	// Support is what makes a node listable and what reconciliation reads. A
	// node written without one is never reconciled: it lives forever.
	type item struct {
		col       string
		id        uuid.UUID
		partition ghgraph.Partition
	}
	var items []item
	add := func(col string, ids map[string]uuid.UUID, key string, part ghgraph.Partition) {
		if id, ok := ids[key]; ok {
			items = append(items, item{col, id, part})
		}
	}
	for _, n := range out.Resources {
		add("resource_id", resourceIDs, n.SourceKey, n.Partition)
	}
	for _, n := range out.Identities {
		add("identity_account_id", identityIDs, n.SourceKey, n.Partition)
	}
	for _, n := range out.Workloads {
		add("workload_id", workloadIDs, n.SourceKey, n.Partition)
	}
	for _, s := range out.Statements {
		add("entitlement_id", statementIDs, s.SourceKey, s.Partition)
	}
	for _, it := range items {
		if err := upsertGitHubSupport(tx, ws, it.col, it.id, it.partition.Key(), observed,
			map[string]any{
				"integration_id":             snap.IntegrationID,
				"last_confirmed_scan_run_id": scanRunID,
			}); err != nil {
			return err
		}
	}

	res.Resources = len(out.Resources)
	res.Identities = len(out.Identities)
	res.Credentials = len(out.Credentials)
	res.Statements = len(out.Statements)
	res.Grants = grants
	res.Workloads = len(out.Workloads)
	return nil
}

// attachWorkflows adds the workflows this scan recorded to their repositories.
//
// Read from the scan's own evidence rather than collected while it ran: an
// unchanged workflow is not refetched (its blob SHA matched), so the scan only
// TOUCHES its source object -- advancing scan_generation -- and never sees its
// content. Its source object is still this generation's, and its observation
// still names the rule that recognised it, which is exactly "a workflow the
// scan recorded".
// txTenant returns ws as the tenant context, on tx's own context, and tx's
// connection, so a raw statement of the caller's transaction runs through the
// tenancy layer: workspace_id = $1 is bound to ws (and, on a transaction
// opened by tenancy.RLSTransaction, row-level security holds as well). A
// context already carrying another workspace is refused rather than
// overridden.
func txTenant(tx *gorm.DB, ws uuid.UUID) (context.Context, tenancy.Querier, error) {
	ctx := tx.Statement.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if tc, err := tenancy.FromContext(ctx); err == nil && tc.WorkspaceID != ws {
		return nil, nil, fmt.Errorf("tenancy: a transaction of workspace %s used for workspace %s", tc.WorkspaceID, ws)
	}
	return tenancy.WithContext(ctx, tenancy.Context{WorkspaceID: ws}), tx.Statement.ConnPool, nil
}

func (p *GitHubGraphProjector) attachWorkflows(tx *gorm.DB, ws, integrationID uuid.UUID,
	generation int64, snap *ghgraph.Snapshot) error {

	ctx, q, err := txTenant(tx, ws)
	if err != nil {
		return err
	}
	var rows []struct {
		Repo string
		Path string
		Name string
	}
	res, err := tenancy.QueryContext(ctx, q, `
		SELECT so.source_subject_key                     AS repo,
		       COALESCE(so.locator->>'name', '')         AS path,
		       COALESCE(so.normalized_payload->>'name', '') AS name
		  FROM iga_source_objects so
		 WHERE so.workspace_id = $1 AND so.integration_id = $2
		   AND so.object_type = $3 AND so.lifecycle = $4
		   AND so.scan_generation = $5
		   AND EXISTS (SELECT 1 FROM iga_observations o
		                WHERE o.workspace_id = so.workspace_id
		                  AND o.source_object_id = so.id
		                  AND o.rule_id = $6)
		 ORDER BY so.source_subject_key, so.recognition_key`,
		integrationID, models.ClassRepoDeclaration, models.LifecycleActive,
		generation, ghgraph.WorkflowRuleID)
	if err != nil {
		return err
	}
	defer res.Close()
	for res.Next() {
		var r struct {
			Repo string
			Path string
			Name string
		}
		if err := res.Scan(&r.Repo, &r.Path, &r.Name); err != nil {
			return err
		}
		rows = append(rows, r)
	}
	if err := res.Err(); err != nil {
		return err
	}
	byRepo := map[string]int{}
	for i := range snap.Repos {
		byRepo[snap.Repos[i].NativeID] = i
	}
	for _, r := range rows {
		i, ok := byRepo[r.Repo]
		if !ok || r.Path == "" {
			continue // a scope this scan did not list cannot own a workflow it read
		}
		snap.Repos[i].Workflows = append(snap.Repos[i].Workflows,
			ghgraph.Workflow{Path: r.Path, Name: r.Name})
	}
	return nil
}

/* ------------------------------ repo scanner ------------------------------ */

// GitHubDeclaredResult reports one repo-scan projection.
type GitHubDeclaredResult struct {
	Projected      bool   `json:"projected"`
	Reason         string `json:"reason,omitempty"`
	Workloads      int    `json:"workloads"`
	SupportEnded   int    `json:"support_ended"`
	SupportStale   int    `json:"support_stale"`
	ObjectsRetired int    `json:"objects_retired"`
}

// ProjectRepoScanRun projects the declared agents one finished repo-scan run
// reported, and retires what a complete run no longer reports.
//
//	run                         reported agents   not reported
//	succeeded, complete         upserted          ended (unless its repository
//	                                              was excluded from the plan)
//	succeeded, not complete     upserted          stale
//	failed / cancelled          upserted          stale
//
// Returns (nil, nil) with the switch off.
func (p *GitHubGraphProjector) ProjectRepoScanRun(workspaceID, runID uuid.UUID) (*GitHubDeclaredResult, error) {
	if !p.enabled() {
		return nil, nil
	}
	observed := p.now().UTC()
	res := &GitHubDeclaredResult{}

	// The whole projection runs under row-level security for the workspace.
	ctx := tenancy.WithContext(context.Background(), tenancy.Context{WorkspaceID: workspaceID})
	err := tenancy.RLSTransaction(ctx, p.db, nil, func(tx *gorm.DB, _ uuid.UUID) error {
		var run models.DiscoveryScanRun
		if err := tx.Where("workspace_id = ? AND id = ?", workspaceID, runID).
			Take(&run).Error; err != nil {
			return fmt.Errorf("read run: %w", err)
		}
		if !run.Terminal() {
			res.Reason = "run has not finished"
			return nil
		}
		if err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtextextended(?, 0))`,
			"ghgraph-repo-scan:"+run.SourceID.String()).Error; err != nil {
			return fmt.Errorf("lock source: %w", err)
		}
		// A run that finished before a later one of the same source must not
		// end what the later one confirmed.
		var newer int64
		if err := tx.Model(&models.DiscoveryScanRun{}).
			Where("workspace_id = ? AND source_id = ? AND id <> ? AND status IN ? AND finished_at > ?",
				workspaceID, run.SourceID, run.ID,
				[]string{models.ScanRunSucceeded, models.ScanRunFailed, models.ScanRunCancelled},
				run.FinishedAt).
			Count(&newer).Error; err != nil {
			return fmt.Errorf("fence: %w", err)
		}
		if newer > 0 {
			res.Reason = "a later run of this source has already finished; this one wrote nothing"
			return nil
		}

		var src models.DiscoverySource
		if err := tx.Where("workspace_id = ? AND id = ?", workspaceID, run.SourceID).
			Take(&src).Error; err != nil {
			return fmt.Errorf("read source: %w", err)
		}
		if src.Kind != models.DiscoverySourceRepoScan {
			res.Reason = "source is not a repo scan"
			return nil
		}
		var cfg githubScannerConfig
		if len(src.Config) > 0 {
			_ = json.Unmarshal(src.Config, &cfg)
		}
		host := cfg.ProviderHost
		if host == "" {
			host = "github.com"
		}
		account := ""
		if id, perr := uuid.Parse(cfg.IntegrationID); perr == nil {
			var integ struct{ AccountNativeID *string }
			if err := tx.Table("iga_integrations").Select("account_native_id").
				Where("workspace_id = ? AND id = ?", workspaceID, id).
				Scan(&integ).Error; err == nil && integ.AccountNativeID != nil {
				account = *integ.AccountNativeID
			}
		}

		// "Reported by this run" is read off the inventory: every sighting the
		// scanner reports -- including an unchanged file it skipped fetching --
		// advances last_seen_at. started_at is the FIRST claim's time, so a
		// resumed run still counts what its earlier attempts reported.
		since := run.QueuedAt
		if run.StartedAt != nil {
			since = *run.StartedAt
		}
		var sight []ghgraph.DeclaredSighting
		if err := tx.Raw(`
			SELECT id, fingerprint, display_name,
			       COALESCE(metadata->>'repository', '') AS repository,
			       COALESCE(metadata->>'path', '')       AS path,
			       COALESCE(metadata->>'rule_id', '')    AS rule_id,
			       COALESCE(metadata->>'branch', '')     AS branch,
			       COALESCE((metadata->>'is_default_branch')::boolean, false) AS default_branch,
			       COALESCE((metadata->>'counts_as_agent')::boolean, false)   AS counts_as_agent
			  FROM discovered_agents
			 WHERE workspace_id = ? AND source = ? AND discovery_source_id = ?
			   AND evidence_mode = 'declared' AND last_seen_at >= ?
			 ORDER BY fingerprint`,
			workspaceID, models.DiscoverySourceRepoScan, run.SourceID, since).
			Scan(&sight).Error; err != nil {
			return fmt.Errorf("load sightings: %w", err)
		}

		nodes := ghgraph.ProjectDeclared(host, account, sight)
		if err := upsertGitHubNodes(tx, "iga_workload", workspaceID, nodes, observed,
			func(n ghgraph.Node) map[string]any {
				return map[string]any{"runtime_kind": n.Kind, "retired_reason": ""}
			}); err != nil {
			return fmt.Errorf("workloads: %w", err)
		}
		workloadIDs, err := liveGitHubIDs(tx, workspaceID, "iga_workload", liveNode)
		if err != nil {
			return err
		}
		partition := ghgraph.DeclaredPartitionKey(run.SourceID)
		var confirmed []uuid.UUID
		for _, n := range nodes {
			id, ok := workloadIDs[n.SourceKey]
			if !ok {
				continue
			}
			confirmed = append(confirmed, id)
			if err := upsertGitHubSupport(tx, workspaceID, "workload_id", id, partition, observed,
				map[string]any{"discovery_source_id": run.SourceID}); err != nil {
				return err
			}
		}
		res.Workloads = len(nodes)

		ended, stale, err := reconcileDeclared(tx, workspaceID, run, partition, confirmed)
		if err != nil {
			return fmt.Errorf("reconcile: %w", err)
		}
		res.SupportEnded, res.SupportStale = ended, stale

		retired, err := ghgraph.RetireUnsupported(tx, workspaceID,
			ghgraph.SourceDiscovery, run.SourceID, observed)
		if err != nil {
			return fmt.Errorf("retire unsupported: %w", err)
		}
		res.ObjectsRetired = retired
		res.Projected = true
		if run.Status != models.ScanRunSucceeded || !run.Complete {
			res.Reason = "run was not complete, so absence is not evidence of deletion; " +
				"what it did not report was marked stale, not ended"
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// reconcileDeclared ends or stales the support of declared agents this run did
// not report.
//
// Only a run that SUCCEEDED and was COMPLETE for its selected scope may end
// anything -- and even then not in a repository the plan excluded: the run
// never looked there, so silence about it is not an observation.
func reconcileDeclared(tx *gorm.DB, ws uuid.UUID, run models.DiscoveryScanRun,
	partition string, confirmed []uuid.UUID) (ended, stale int, err error) {

	q := tx.Table("iga_object_support s").
		Select("s.id, COALESCE(w.provider_attrs->>'sub_scope', '') AS sub_scope").
		Joins("JOIN iga_workload w ON w.workspace_id = s.workspace_id AND w.id = s.workload_id").
		Where("s.workspace_id = ? AND s.discovery_source_id = ? AND s.partition_key = ? AND s.state <> ?",
			ws, run.SourceID, partition, models.RelEnded)
	// NOT IN over an empty list is NOT IN (NULL), which matches nothing -- the
	// one case where every row is unreported would then end nothing at all.
	if len(confirmed) > 0 {
		q = q.Where("s.workload_id NOT IN ?", confirmed)
	}
	var rows []struct {
		ID       uuid.UUID
		SubScope string
	}
	if err := q.Scan(&rows).Error; err != nil {
		return 0, 0, err
	}

	closing := run.Status == models.ScanRunSucceeded && run.Complete
	excluded := map[string]bool{}
	var names []string
	if len(run.ExcludedRepositories) > 0 {
		_ = json.Unmarshal(run.ExcludedRepositories, &names)
	}
	for _, n := range names {
		excluded[strings.ToLower(n)] = true
	}

	var endIDs, staleIDs []uuid.UUID
	for _, r := range rows {
		if closing && !excluded[strings.ToLower(r.SubScope)] {
			endIDs = append(endIDs, r.ID)
		} else {
			staleIDs = append(staleIDs, r.ID)
		}
	}
	if len(endIDs) > 0 {
		r := tx.Model(&models.IGAObjectSupport{}).
			Where("workspace_id = ? AND id IN ?", ws, endIDs).
			Updates(map[string]any{"state": models.RelEnded, "ended_reason": models.EndedNotSeen})
		if r.Error != nil {
			return 0, 0, r.Error
		}
		ended = int(r.RowsAffected)
	}
	if len(staleIDs) > 0 {
		r := tx.Model(&models.IGAObjectSupport{}).
			Where("workspace_id = ? AND id IN ? AND state = ?", ws, staleIDs, models.RelCurrent).
			Update("state", models.RelStale)
		if r.Error != nil {
			return 0, 0, r.Error
		}
		stale = int(r.RowsAffected)
	}
	return ended, stale, nil
}

/* --------------------------------- upserts -------------------------------- */

// liveNode is the partial-index predicate of the four node tables' source-key
// indexes, restated so the conflict target can be inferred (see conflictOn).
const liveNode = liveByLifecycle

// liveCredential is uq_iga_credentials_source_key's predicate.
const liveCredential = "source_key <> '' AND lifecycle NOT IN ('revoked', 'expired')"

// upsertGitHubNodes writes keyed nodes to one of the node tables.
//
// first_seen_at is never updated: it is when the graph first saw the object,
// and overwriting it every scan would erase the only evidence of its age.
func upsertGitHubNodes(tx *gorm.DB, table string, ws uuid.UUID, nodes []ghgraph.Node,
	observed time.Time, kindCols func(ghgraph.Node) map[string]any) error {

	for i := range nodes {
		n := nodes[i]
		attrs, err := jsonAttrs(n.Attrs)
		if err != nil {
			return err
		}
		row := map[string]any{
			"id":             uuid.New(),
			"workspace_id":   ws,
			"display_name":   n.DisplayName,
			"lifecycle":      models.IGALifecycleActive,
			"provider":       models.ProviderGitHub,
			"source_key":     n.SourceKey,
			"continuity":     models.ContinuityRecognitionOnly,
			"provider_attrs": attrs,
			"first_seen_at":  observed,
			"last_seen_at":   observed,
			"created_at":     observed,
			"updated_at":     observed,
		}
		for k, v := range kindCols(n) {
			row[k] = v
		}
		if err := tx.Table(table).
			Clauses(conflictOn(liveNode, map[string]any{
				"display_name":   n.DisplayName,
				"provider_attrs": attrs,
				"last_seen_at":   observed,
				"updated_at":     observed,
			})).Create(row).Error; err != nil {
			return fmt.Errorf("%s %s: %w", table, n.SourceKey, err)
		}
	}
	return nil
}

// liveGitHubIDs maps every LIVE keyed GitHub row in a table to its id.
//
// Live only: a retired row keeps its source_key, so reading every row would
// let a retired incarnation and its live successor race for the same key, and
// support or a grant could attach to the dead one.
func liveGitHubIDs(tx *gorm.DB, ws uuid.UUID, table, live string) (map[string]uuid.UUID, error) {
	var rows []struct {
		ID        uuid.UUID
		SourceKey string
	}
	if err := tx.Table(table).Select("id, source_key").
		Where("workspace_id = ? AND provider = ?", ws, models.ProviderGitHub).
		Where(live).
		Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("resolve %s ids: %w", table, err)
	}
	out := make(map[string]uuid.UUID, len(rows))
	for _, r := range rows {
		out[r.SourceKey] = r.ID
	}
	return out, nil
}

// upsertGitHubCredentials writes a deploy key's non-secret metadata. Never a
// value: GitHub returns the public key, and even that is not stored.
func upsertGitHubCredentials(tx *gorm.DB, ws uuid.UUID, host string, creds []ghgraph.Credential,
	identityIDs map[string]uuid.UUID, observed time.Time) error {

	for _, c := range creds {
		holder, ok := identityIDs[c.IdentityKey]
		if !ok {
			continue // identity_account_id is NOT NULL; no holder, no row
		}
		row := map[string]any{
			"id":                  uuid.New(),
			"workspace_id":        ws,
			"identity_account_id": holder,
			"credential_type":     "deploy_key",
			"issuer":              host,
			"key_identifier":      c.KeyIdentifier,
			// GitHub deploy keys carry no expiry.
			"rotation_posture": rotationPosture(nil, observed),
			"lifecycle":        "active",
			"provider":         models.ProviderGitHub,
			"source_key":       c.SourceKey,
			"continuity":       models.ContinuityRecognitionOnly,
			"first_seen_at":    observed,
			"last_seen_at":     observed,
			"created_at":       observed,
			"updated_at":       observed,
		}
		if err := tx.Table("iga_credentials").
			Clauses(conflictOn(liveCredential, map[string]any{
				"identity_account_id": holder,
				"key_identifier":      c.KeyIdentifier,
				"last_seen_at":        observed,
				"updated_at":          observed,
			})).Create(row).Error; err != nil {
			return fmt.Errorf("credential %s: %w", c.SourceKey, err)
		}
	}
	return nil
}

// upsertGitHubStatements writes the right each deploy key carries, on its
// repository. native_rights keeps GitHub's wording; normalized_rights is the
// reading derived from it, never instead of it.
func upsertGitHubStatements(tx *gorm.DB, ws uuid.UUID, sts []ghgraph.Statement,
	resourceIDs map[string]uuid.UUID, observed time.Time) error {

	for _, s := range sts {
		native, err := json.Marshal(s.Rights)
		if err != nil {
			return err
		}
		normalized, err := json.Marshal(NormalizeRights(s.Rights))
		if err != nil {
			return err
		}
		row := map[string]any{
			"id":                uuid.New(),
			"workspace_id":      ws,
			"native_grant_kind": "deploy_key",
			"native_rights":     native,
			"normalized_rights": normalized,
			"native_scope":      s.NativeScope,
			// Deleting the key is a supported provider path.
			"remediable":    true,
			"lifecycle":     models.IGALifecycleActive,
			"provider":      models.ProviderGitHub,
			"source_key":    s.SourceKey,
			"statement_key": s.SourceKey,
			"continuity":    models.ContinuityRecognitionOnly,
			// A deploy key grants; there is no deny form of one.
			"effect":        "allow",
			"first_seen_at": observed,
			"last_seen_at":  observed,
			"created_at":    observed,
			"updated_at":    observed,
		}
		update := map[string]any{
			"native_rights":     native,
			"normalized_rights": normalized,
			"native_scope":      s.NativeScope,
			"last_seen_at":      observed,
			"updated_at":        observed,
		}
		if id, ok := resourceIDs[s.ResourceKey]; ok {
			row["resource_id"] = id
			update["resource_id"] = id
		}
		if err := tx.Table("iga_entitlements").
			Clauses(conflictOn(liveNode, update)).Create(row).Error; err != nil {
			return fmt.Errorf("statement %s: %w", s.SourceKey, err)
		}
	}
	return nil
}

// upsertGitHubGrants writes deploy key -> statement edges on the repository,
// carrying the integration and scan run that confirmed them.
func upsertGitHubGrants(tx *gorm.DB, ws, integrationID, scanRunID uuid.UUID, grants []ghgraph.Grant,
	identityIDs, statementIDs, resourceIDs map[string]uuid.UUID, observed time.Time) (int, error) {

	written := 0
	for _, g := range grants {
		subject, ok := identityIDs[g.SubjectKey]
		if !ok {
			continue // an edge whose holder is unknown names nobody
		}
		row := map[string]any{
			"id":           uuid.New(),
			"workspace_id": ws,
			// All three agree, as iga_access_edges_subject_agree_chk requires.
			"subject_kind":                "identity_account",
			"subject_id":                  subject,
			"subject_identity_account_id": subject,
			"provider":                    models.ProviderGitHub,
			"direction":                   "outbound",
			"path_kind":                   "deploy_key",
			// Read from GitHub, not declared to us.
			"basis":                      "observed",
			"calculation_state":          g.CalculationState,
			"effective_conclusion":       g.EffectiveConclusion,
			"native_scope":               g.NativeScope,
			"state":                      models.RelCurrent,
			"valid_from":                 observed,
			"last_confirmed_at":          observed,
			"observed_at":                observed,
			"source_key":                 g.SourceKey,
			"partition_key":              g.Partition.Key(),
			"integration_id":             integrationID,
			"last_confirmed_scan_run_id": scanRunID,
			"created_at":                 observed,
			"updated_at":                 observed,
		}
		update := map[string]any{
			"subject_id":                  subject,
			"subject_identity_account_id": subject,
			"calculation_state":           g.CalculationState,
			"effective_conclusion":        g.EffectiveConclusion,
			"state":                       models.RelCurrent,
			"last_confirmed_at":           observed,
			"observed_at":                 observed,
			"partition_key":               g.Partition.Key(),
			"integration_id":              integrationID,
			"last_confirmed_scan_run_id":  scanRunID,
			"updated_at":                  observed,
		}
		if id, ok := statementIDs[g.StatementKey]; ok {
			row["entitlement_id"] = id
			update["entitlement_id"] = id
		}
		if id, ok := resourceIDs[g.ResourceKey]; ok {
			row["resource_id"] = id
			update["resource_id"] = id
		}
		if err := tx.Table("iga_access_edges").
			Clauses(conflictOn(liveEdge, update)).Create(row).Error; err != nil {
			return written, fmt.Errorf("grant %s: %w", g.SourceKey, err)
		}
		written++
	}
	return written, nil
}

// upsertGitHubSupport records that a reading saw an object.
//
// source names the evidence stream -- integration_id (+ the scan run) for the
// IGA scan, discovery_source_id for the repo scan -- and exactly one of them,
// as iga_object_support_source_chk requires. The upsert is idempotent on
// (workspace, object, source_ref, partition), the partial unique indexes 042
// rebuilt on source_ref, so a rescan refreshes the row rather than adding one.
func upsertGitHubSupport(tx *gorm.DB, ws uuid.UUID, col string, id uuid.UUID, partition string,
	observed time.Time, source map[string]any) error {

	row := map[string]any{
		"id":                uuid.New(),
		"workspace_id":      ws,
		col:                 id,
		"partition_key":     partition,
		"state":             models.RelCurrent,
		"first_seen_at":     observed,
		"last_confirmed_at": observed,
	}
	update := map[string]any{
		// Re-confirming revives a row an earlier reading ended or staled: the
		// object is plainly here again, and leaving it ended would retire a
		// live object.
		"state":             models.RelCurrent,
		"ended_reason":      "",
		"last_confirmed_at": observed,
	}
	for k, v := range source {
		row[k] = v
		update[k] = v
	}
	if err := tx.Table("iga_object_support").
		Clauses(clause.OnConflict{
			Columns: []clause.Column{
				{Name: "workspace_id"}, {Name: col},
				{Name: "source_ref"}, {Name: "partition_key"},
			},
			TargetWhere: clause.Where{Exprs: []clause.Expression{gorm.Expr(col + " IS NOT NULL")}},
			DoUpdates:   clause.Assignments(update),
		}).Create(row).Error; err != nil {
		return fmt.Errorf("%s support: %w", col, err)
	}
	return nil
}

/* -------------------------------- collector ------------------------------- */

// githubGraphCollector gathers what an IGA scan read, as it reads it, into a
// ghgraph.Snapshot.
//
// It rides along with RunScan rather than re-reading the scan's rows afterwards
// because the legacy writer keeps no keyed record of most of it: deploy keys
// become anonymous identity rows, and the repository listing becomes a resource
// per grant. Every method is safe on a nil collector, which is what RunScan
// holds when no projector is configured -- so the scan path is unchanged.
type githubGraphCollector struct {
	snap  ghgraph.Snapshot
	repos []*ghgraph.Repo
}

func newGitHubGraphCollector(integ *models.IGAIntegration) *githubGraphCollector {
	c := &githubGraphCollector{snap: ghgraph.Snapshot{
		IntegrationID: integ.ID,
		Host:          integ.ProviderHost,
	}}
	if integ.AccountNativeID != nil {
		c.snap.Account = *integ.AccountNativeID
	}
	if integ.InstallationID != nil {
		c.snap.InstallationID = *integ.InstallationID
	}
	return c
}

// repo starts the entry for one listed scope. Only repositories are nodes; an
// organisation scope returns nil and every later call on it is a no-op.
func (c *githubGraphCollector) repo(scope ProviderScope) *ghgraph.Repo {
	if c == nil || scope.Kind != "repository" {
		return nil
	}
	r := &ghgraph.Repo{
		NativeID: scope.NativeID, NodeID: scope.NodeID, FullName: scope.DisplayName,
		DefaultBranch: scope.DefaultBranch, Archived: scope.Archived,
		Coverage: map[string]string{},
	}
	c.repos = append(c.repos, r)
	return r
}

func (c *githubGraphCollector) agents(r *ghgraph.Repo, objs []ProviderObject) {
	if c == nil || r == nil {
		return
	}
	for _, o := range objs {
		if o.ObjectType != models.ClassAgentProfile || o.NativeID == "" {
			continue
		}
		a := ghgraph.CopilotAgent{ID: o.NativeID, Name: o.DisplayName}
		if v, ok := o.Payload["name"].(string); ok && v != "" {
			a.Name = v
		}
		if v, ok := o.Payload["description"].(string); ok {
			a.Description = v
		}
		switch tools := o.Payload["declared_tools"].(type) {
		case []string:
			a.Tools = tools
		case []interface{}:
			for _, t := range tools {
				if s, ok := t.(string); ok {
					a.Tools = append(a.Tools, s)
				}
			}
		}
		r.CopilotAgents = append(r.CopilotAgents, a)
	}
}

// grants keeps the deploy keys. Installation and PAT grants are not projected:
// the installation is projected once from the binding, and GitHub's REST API
// exposes no PAT a repository listing could attribute.
func (c *githubGraphCollector) grants(r *ghgraph.Repo, gs []ProviderGrant) {
	if c == nil || r == nil {
		return
	}
	for _, g := range gs {
		if g.SubjectKind != "deploy_key" || g.SubjectNativeID == "" {
			continue
		}
		title := g.SubjectName
		if title == "" {
			title = "deploy key " + g.SubjectNativeID
		}
		rights := map[string]string{}
		for k, v := range g.NativeRights {
			rights[k] = v
		}
		r.DeployKeys = append(r.DeployKeys, ghgraph.DeployKey{
			ID: g.SubjectNativeID, Title: title, Rights: rights, Conditional: g.Conditional,
		})
	}
}

func (c *githubGraphCollector) coverage(r *ghgraph.Repo, class, state string) {
	if c == nil || r == nil {
		return
	}
	r.Coverage[class] = state
}

func (c *githubGraphCollector) snapshot() ghgraph.Snapshot {
	s := c.snap
	s.Repos = make([]ghgraph.Repo, 0, len(c.repos))
	for _, r := range c.repos {
		s.Repos = append(s.Repos, *r)
	}
	return s
}
