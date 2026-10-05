package igaread

// GET /authsec/discovery/connections (SPEC-console-revamp.md B3): every
// connected source of every provider in one shape, with the four independent
// conditions the console never collapses into one word -- connection, latest
// scan, coverage and graph publication -- plus what Discovery may do with it.
//
// It is NOT a graph read: it does not need IGA_GRAPH_PROJECTION, takes the
// workspace only from the token and writes nothing. It reads through the
// Reader only to get what the graph reads get -- one REPEATABLE READ snapshot
// under one deadline -- so a publication that commits while the request runs
// cannot appear beside the barrier state that preceded it.
//
// Sources, one statement each, never one per connection:
//
//	AWS, GCP   cloud_connector (status, verified_at, last_error_code, coverage)
//	AWS        + PipelineLatestRunsSQL (the latest run, its projection job)
//	           + the newest iga_publication of each connector's runs
//	Kubernetes discovery_sources kind k8s_webhook (heartbeat, config, runtime)
//	           + k8sread.LatestSweeps and the newest projected sweep per source
//	GitHub     discovery_sources kind repo_scan + its iga_integrations row
//	           + LATERAL latest and latest-succeeded discovery_scan_runs
//
// Every mapping below is a pure function of what those rows say, so the same
// rows always render the same connection.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/internal/k8sread"
	"github.com/authsec-ai/authsec/models"
)

// Provider words, scope kinds and the closed vocabularies of the Connection
// shape (connectionsApi.ts). They are the console's contract: additive only.
const (
	ConnProviderAWS    = "aws"
	ConnProviderGCP    = "gcp"
	ConnProviderK8s    = "k8s"
	ConnProviderGitHub = "github"

	connScopeAccount      = "account"
	connScopeProject      = "project"
	connScopeCluster      = "cluster"
	connScopeOrganisation = "organisation"

	connConnected       = "connected"
	connAuthFailed      = "authentication_failed"
	connRevoked         = "revoked"
	connNotVerified     = "not_verified"
	connScanNever       = "never_run"
	connScanQueued      = "queued"
	connScanRunning     = "running"
	connScanFinished    = "finished"
	connScanFailed      = "failed"
	connCovComplete     = "complete"
	connCovPartial      = "partial"
	connCovDenied       = "denied"
	connCovUnknown      = "unknown"
	connGraphPublished  = "published"
	connGraphPublishing = "publishing"
	connGraphFailed     = "failed"
	connGraphNone       = "not_published"
	connGraphLive       = "unrevisioned"
	connGraphNA         = "not_applicable"
)

// Reasons a Kubernetes or GitHub connection is not connected, as reason_code.
// AWS and GCP use the connector's stored last_error_code instead
// (services.ConnErr*). Stable, lowercase, additive only.
const (
	connReasonNoHeartbeat      = "no_heartbeat"
	connReasonHeartbeatLost    = "heartbeat_lost"
	connReasonDisabled         = "disabled"
	connReasonIntegrationNone  = "integration_missing"
	connReasonUnverified       = "integration_unverified"
	connReasonIntegrationState = "integration_" // + iga_integrations.status
)

// connAuthErrorCodes are the cloud_connector.last_error_code classes that mean
// the customer's account refused or could not use the credential
// (services.ConnErrAuthRefused, ConnErrCredentialInvalid,
// ConnErrExternalIDNotIssued). Literals, not imports: services imports this
// package's neighbours, and the codes are a stored contract (migration 039).
var connAuthErrorCodes = map[string]bool{
	"auth_refused":           true,
	"credential_invalid":     true,
	"external_id_not_issued": true,
}

// connGCPRunningFor is how long a GCP report marked running is believed
// (services.gcpScanTimeout): older, it is a dead scan, which the scanner
// itself no longer treats as in flight.
const connGCPRunningFor = 30 * time.Minute

// connSweepReceivedFor is how long a Kubernetes sweep that has arrived and not
// been applied (status received) is shown as running. A projection that failed
// its transaction leaves the sweep received for good (041: "the honest record
// that a reading arrived and was never applied"), and that must not read as
// running forever.
const connSweepReceivedFor = 30 * time.Minute

// Connection is one connected source: a cloud connector or a discovery source.
type Connection struct {
	// ID is the connection's own id -- the connector's or discovery source's --
	// which is the value iga_object_support.source_ref records for the rows the
	// connection supports (AWS: the connector; Kubernetes: the source). GitHub
	// is the exception to name: its support rows will carry the iga_integrations
	// id (042), which the discovery source records in config.integration_id, and
	// the id here is the discovery source's, the one every GitHub action
	// (scan, repositories) addresses.
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	ScopeKind string `json:"scope_kind"`
	// Name is the display name, else NativeID.
	Name string `json:"name"`
	// NativeID is the account id, project id, cluster name or organisation login.
	NativeID string `json:"native_id"`
	// ScopeID is what the unified inventory calls scope.id for this
	// connection's rows, so scope=<scope_id> returns exactly its rows:
	//
	//	AWS         the account id (WorkloadAccountSQL and its siblings)
	//	Kubernetes  provider_attrs.scope_id, which k8sgraph.WithScope sets to the
	//	            cluster name -- the cluster of its newest sweep, else the
	//	            source's cluster_name
	//	GCP, GitHub "": the inventory lists no GCP object, and no GitHub writer
	//	            records rows yet
	ScopeID   string `json:"scope_id"`
	CreatedAt any    `json:"created_at"`

	Connection ConnectionCondition `json:"connection"`
	Scan       ConnectionScan      `json:"scan"`
	Coverage   ConnectionCoverage  `json:"coverage"`
	Graph      ConnectionGraph     `json:"graph"`
	// ScopeSummary is "3 regions", "all namespaces", "12 repositories".
	ScopeSummary string              `json:"scope_summary"`
	Discovery    ConnectionDiscovery `json:"discovery"`
	// Capabilities is what the provider can do, whoever asks. Authorisation is
	// the server's, per route.
	Capabilities ConnectionCapabilities `json:"capabilities"`
}

// ConnectionCondition is "can AuthSec reach it".
type ConnectionCondition struct {
	State      string  `json:"state"`
	ReasonCode *string `json:"reason_code"`
	VerifiedAt any     `json:"verified_at"`
}

// ConnectionScan is "the most recent attempt to read it".
type ConnectionScan struct {
	State string `json:"state"`
	At    any    `json:"at"`
	RunID any    `json:"run_id"`
	// HeartbeatAt and ReportsEverySeconds are Kubernetes only (omitted for the
	// others): the agent's last heartbeat -- connection health, never inventory
	// currency -- and how often it reports, when known.
	HeartbeatAt         any    `json:"heartbeat_at,omitempty"`
	ReportsEverySeconds *int64 `json:"reports_every_seconds,omitempty"`
}

// ConnectionCoverage is "could the read see everything it was asked to".
type ConnectionCoverage struct {
	State string `json:"state"`
	// Gaps names only the surfaces that were not fully read; [] otherwise.
	Gaps []ConnectionGap `json:"gaps"`
}

// ConnectionGap is one surface not fully read.
type ConnectionGap struct {
	Surface string `json:"surface"`
	State   string `json:"state"`
}

// ConnectionGraph is "is what was read in a numbered publication".
type ConnectionGraph struct {
	State       string `json:"state"`
	Rev         *int64 `json:"rev"`
	PublishedAt any    `json:"published_at"`
}

// ConnectionDiscovery is whether Discovery is ready for the connection by its
// provider's own rule, and from when.
type ConnectionDiscovery struct {
	Ready bool `json:"ready"`
	AsOf  any  `json:"as_of"`
}

// ConnectionCapabilities is what a provider can do.
type ConnectionCapabilities struct {
	Scan      bool `json:"scan"`
	Verify    bool `json:"verify"`
	EditScope bool `json:"edit_scope"`
	Revoke    bool `json:"revoke"`
	Rules     bool `json:"rules"`
}

// connCapabilities are fixed per provider (SPEC-console-revamp "Actions by
// provider"). GCP's scope is not editable: there is no route that changes a
// GCP connector after onboarding. Kubernetes scans on the agent's own
// schedule and its scope is the agent's config, so it can only be removed
// (Revoke here is "remove the connection": there is no token to revoke).
var connCapabilities = map[string]ConnectionCapabilities{
	ConnProviderAWS:    {Scan: true, Verify: true, EditScope: true, Revoke: true},
	ConnProviderGCP:    {Scan: true, Verify: true, Revoke: true},
	ConnProviderK8s:    {Revoke: true},
	ConnProviderGitHub: {Scan: true, EditScope: true, Revoke: true, Rules: true}, // no verify route exists for GitHub
}

// ConnectionList is the response body.
type ConnectionList struct {
	Connections []Connection `json:"connections"`
}

// ListConnections serves GET /authsec/discovery/connections for the workspace
// in the token.
func (r *Reader) ListConnections(ctx context.Context, ws uuid.UUID) (any, error) {
	out := ConnectionList{Connections: []Connection{}}
	err := r.Read(ctx, ws, Pin{}, func(q *Query) error {
		now := time.Now().UTC()
		cloud, err := connCloud(q, now)
		if err != nil {
			return err
		}
		k8s, err := connKubernetes(q, now)
		if err != nil {
			return err
		}
		gh, err := connGitHub(q)
		if err != nil {
			return err
		}
		out.Connections = append(append(append(out.Connections, cloud...), k8s...), gh...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	rank := map[string]int{ConnProviderAWS: 0, ConnProviderGCP: 1, ConnProviderK8s: 2, ConnProviderGitHub: 3}
	sort.SliceStable(out.Connections, func(i, j int) bool {
		a, b := out.Connections[i], out.Connections[j]
		if rank[a.Provider] != rank[b.Provider] {
			return rank[a.Provider] < rank[b.Provider]
		}
		if an, bn := strings.ToLower(a.Name), strings.ToLower(b.Name); an != bn {
			return an < bn
		}
		return a.ID < b.ID
	})
	return out, nil
}

func strPtr0(s string) *string { return &s }

// reasonOf is a stored error code as reason_code: null when there is none.
func reasonOf(code string) *string {
	if code == "" {
		return nil
	}
	return &code
}

/* ------------------------------- AWS and GCP ------------------------------- */

// connCloud is every AWS and GCP connector (cloud_connector).
//
// connection.state, from status, verified_at and last_error_code:
//
//	revoked                   -> revoked
//	status error, auth class  -> authentication_failed (reason_code = the code)
//	status error, any other   -> not_verified: the connection cannot be proven
//	                             right now (throttled, timeout, policy block, our
//	                             own misconfiguration, an unclassified failure),
//	                             which is not the customer's credential failing;
//	                             reason_code carries the stored code, null when
//	                             unclassified
//	status active, never verified (verified_at null) -> not_verified
//	status active, verified   -> connected
func connCloud(q *Query, now time.Time) ([]Connection, error) {
	var connectors []models.CloudConnector
	if err := q.DB().Where("workspace_id = ? AND provider IN ?", q.WS,
		[]string{models.CloudProviderAWS, models.CloudProviderGCP}).
		Order("created_at, id").Find(&connectors).Error; err != nil {
		return nil, err
	}
	if len(connectors) == 0 {
		return nil, nil
	}

	// AWS: each connector's latest run with its projection job -- the very
	// statement /pipeline reads -- and the newest publication of its runs.
	var latest []pipelineRun
	if err := q.DB().Raw(PipelineLatestRunsSQL,
		models.CloudScanRunQueued, models.CloudScanRunRunning,
		q.WS, models.CloudProviderAWS).Scan(&latest).Error; err != nil {
		return nil, err
	}
	runs := make(map[uuid.UUID]*pipelineRun, len(latest))
	for i := range latest {
		runs[latest[i].ConnectorID] = &latest[i]
	}
	var pubs []struct {
		ConnectorID uuid.UUID
		Rev         int64
		PublishedAt time.Time
	}
	if err := q.DB().Raw(`
		SELECT DISTINCT ON (r.connector_id) r.connector_id, p.rev, p.published_at
		  FROM iga_publication p
		  JOIN cloud_scan_run r ON r.workspace_id = p.workspace_id AND r.id = p.scan_run_id
		 WHERE p.workspace_id = ?
		 ORDER BY r.connector_id, p.rev DESC`, q.WS).Scan(&pubs).Error; err != nil {
		return nil, err
	}
	pubOf := make(map[uuid.UUID]*Revision, len(pubs))
	for _, p := range pubs {
		pubOf[p.ConnectorID] = &Revision{Rev: p.Rev, PublishedAt: p.PublishedAt}
	}

	out := make([]Connection, 0, len(connectors))
	for i := range connectors {
		c := &connectors[i]
		cov := models.DecodeScanCoverage(c.Coverage)
		conn := Connection{
			ID:        c.ID.String(),
			NativeID:  c.ScopeID,
			CreatedAt: T(c.CreatedAt),
			Connection: ConnectionCondition{
				State: connCloudState(c), ReasonCode: connCloudReason(c), VerifiedAt: TS(c.VerifiedAt),
			},
			Coverage: connCloudCoverage(cov),
			Graph:    ConnectionGraph{State: connGraphNA},
		}
		switch c.Provider {
		case models.CloudProviderAWS:
			attrs := c.AWSAttrs()
			conn.Provider, conn.ScopeKind = ConnProviderAWS, connScopeAccount
			conn.Name, conn.ScopeID = nameOr(attrs.DisplayName, c.ScopeID), c.ScopeID
			conn.ScopeSummary = countWord(len(attrs.Regions), "region", "regions", "no regions selected")
			run := runs[c.ID]
			conn.Scan = connAWSScan(run)
			conn.Graph = connAWSGraph(c, run, pubOf[c.ID])
			conn.Discovery = connAWSDiscovery(run, cov)
		default: // gcp
			attrs := c.GCPAttrs()
			conn.Provider = ConnProviderGCP
			conn.ScopeKind, conn.ScopeSummary = connGCPScope(c.ScopeKind)
			conn.Name = nameOr(attrs.DisplayName, c.ScopeID)
			conn.Scan, conn.Discovery = connGCPScanAndReady(cov, now)
		}
		conn.Capabilities = connCapabilities[conn.Provider]
		out = append(out, conn)
	}
	return out, nil
}

func nameOr(name, fallback string) string {
	if name != "" {
		return name
	}
	return fallback
}

// countWord is "1 region" / "3 regions", or none when n is 0.
func countWord(n int, singular, plural, none string) string {
	switch n {
	case 0:
		return none
	case 1:
		return "1 " + singular
	default:
		return fmt.Sprintf("%d %s", n, plural)
	}
}

func connCloudState(c *models.CloudConnector) string {
	switch {
	case c.Status == models.CloudConnectorRevoked:
		return connRevoked
	case c.Status == models.CloudConnectorError:
		if connAuthErrorCodes[c.LastErrorCode] {
			return connAuthFailed
		}
		return connNotVerified
	case c.VerifiedAt == nil:
		return connNotVerified
	default:
		return connConnected
	}
}

// connCloudReason is the stored error code while the connection is not
// connected (and not revoked by the operator, whose reason is the revoke).
func connCloudReason(c *models.CloudConnector) *string {
	if c.Status == models.CloudConnectorError {
		return reasonOf(c.LastErrorCode)
	}
	return nil
}

// connGCPScope is a GCP connector's scope kind and summary: a project is
// "project"; a folder or an organisation is named as what it is.
func connGCPScope(kind string) (scopeKind, summary string) {
	switch kind {
	case models.CloudScopeOrg:
		return connScopeOrganisation, "1 organisation"
	case models.CloudScopeFolder:
		return connScopeProject, "1 folder"
	default:
		return connScopeProject, "1 project"
	}
}

// connCloudCoverage is the connector's per-surface coverage as one state and
// the surfaces not fully read, with the graph lists' own reading of a
// surface (listsCoverage): reached and unsupported are not gaps; a surface
// the scope did not select is a gap stated as stale (its earlier results are
// kept and marked stale); everything else is a gap in its own state.
//
//	no surfaces, or none ever attempted  -> unknown
//	no gap                               -> complete
//	a gap and a surface reached          -> partial
//	gaps and nothing reached             -> denied
//
// Sorted by surface, so the answer is stable.
func connCloudCoverage(cov models.ScanCoverage) ConnectionCoverage {
	out := ConnectionCoverage{Gaps: []ConnectionGap{}}
	reached, attempted := 0, 0
	for surface, s := range cov.Surfaces {
		switch s.State {
		case models.CloudCoverageReached:
			reached++
			attempted++
			continue
		case models.CloudCoverageUnsupported:
			continue
		case models.CloudCoverageNotSelected:
			out.Gaps = append(out.Gaps, ConnectionGap{Surface: surface, State: models.CloudCoverageStale})
			continue
		case models.CloudCoverageUnknown, models.CloudCoverageNotConfigured:
		default:
			attempted++
		}
		out.Gaps = append(out.Gaps, ConnectionGap{Surface: surface, State: s.State})
	}
	sort.Slice(out.Gaps, func(i, j int) bool { return out.Gaps[i].Surface < out.Gaps[j].Surface })
	// "denied" is a refusal and only a refusal: a scan that reached nothing
	// because every surface was throttled or timed out was not refused, and
	// saying so would send the operator to fix permissions that are fine.
	denied := false
	for _, g := range out.Gaps {
		if g.State == models.CloudCoverageDenied {
			denied = true
		}
	}
	switch {
	case attempted == 0:
		out.State = connCovUnknown
	case len(out.Gaps) == 0:
		out.State = connCovComplete
	case reached > 0:
		out.State = connCovPartial
	case denied:
		out.State = connCovDenied
	default:
		out.State = connCovUnknown
	}
	return out
}

// connAWSScan is the latest run (the live one, else the newest) as a scan
// state: queued -> queued, running -> running, published -> finished (the
// collection finished; the publication is graph.state's), failed and
// abandoned -> failed. No run -> never_run. at is when the state began: queued
// at requested_at, running at started_at, finished at published_at, failed at
// its last update (D-91).
func connAWSScan(run *pipelineRun) ConnectionScan {
	if run == nil {
		return ConnectionScan{State: connScanNever}
	}
	s := ConnectionScan{RunID: run.ID.String()}
	switch run.Status {
	case models.CloudScanRunQueued:
		s.State, s.At = connScanQueued, T(run.RequestedAt)
	case models.CloudScanRunRunning:
		s.State, s.At = connScanRunning, TS(run.StartedAt)
	case models.CloudScanRunPublished:
		s.State, s.At = connScanFinished, TS(run.PublishedAt)
	default: // failed, abandoned, and a status this build does not know
		s.State, s.At = connScanFailed, T(run.UpdatedAt)
	}
	return s
}

// connAWSGraph is the publication state of what this connector read, from the
// pipeline tables:
//
//	publishing  its latest run's projection job is queued, running, or failed
//	            with attempts left (D-59: still holding the barrier)
//	failed      that job failed for good or was abandoned -- the PUBLICATION
//	            failed; a failed collection leaves the earlier publication
//	published   otherwise, when a publication of this connector's runs exists
//	not_published otherwise (never published, or first publication pending)
//
// rev and published_at are that newest publication of the connector's own
// runs. A revoked connector keeps its earlier results in the graph, so it is
// published when it ever was.
func connAWSGraph(c *models.CloudConnector, run *pipelineRun, pub *Revision) ConnectionGraph {
	g := ConnectionGraph{State: connGraphNone}
	if pub != nil {
		rev := pub.Rev
		g.State, g.Rev, g.PublishedAt = connGraphPublished, &rev, T(PublicationTime(pub.PublishedAt))
	}
	if c.Status == models.CloudConnectorRevoked || run == nil || run.Status != models.CloudScanRunPublished || run.JobStatus == nil {
		return g
	}
	switch *run.JobStatus {
	case models.ProjectionQueued, models.ProjectionRunning:
		g.State = connGraphPublishing
	case models.ProjectionFailed:
		if jobRetrying(run) {
			g.State = connGraphPublishing
		} else {
			g.State = connGraphFailed
		}
	case models.ProjectionAbandoned:
		g.State = connGraphFailed
	}
	return g
}

// connAWSDiscovery is the Latest-collected rule (SPEC "First successful
// journey"): ready when the latest scan finished, as_of its published_at. The
// Published rule is graph.state's. While a later scan is queued, running or
// failed, the inventory of the last finished scan still stands, so it is read
// from the connector's coverage (written with that scan) instead of reporting
// not ready.
func connAWSDiscovery(run *pipelineRun, cov models.ScanCoverage) ConnectionDiscovery {
	if run != nil && run.Status == models.CloudScanRunPublished && run.PublishedAt != nil {
		return ConnectionDiscovery{Ready: true, AsOf: TS(run.PublishedAt)}
	}
	if connCoverageFinished(cov) {
		return ConnectionDiscovery{Ready: true, AsOf: TS(cov.FinishedAt)}
	}
	return ConnectionDiscovery{}
}

// connCoverageFinished: the report is of a scan that finished with data
// (complete or partial), not one still running or failed.
func connCoverageFinished(cov models.ScanCoverage) bool {
	return (cov.Status == models.ScanStatusComplete || cov.Status == models.ScanStatusPartial) && cov.FinishedAt != nil
}

// connGCPScanAndReady: GCP has no scan-run table; its scan reports on the
// connector's coverage (cloud_gcp_scan.go): running (believed for gcpScanTimeout,
// then it is a dead scan, failed), complete or partial -> finished, failed ->
// failed, no report -> never_run. Ready is a finished collection, with
// finished_at as_of; zero identities is still ready.
func connGCPScanAndReady(cov models.ScanCoverage, now time.Time) (ConnectionScan, ConnectionDiscovery) {
	s := ConnectionScan{State: connScanNever}
	switch cov.Status {
	case models.ScanStatusRunning:
		if cov.StartedAt != nil && now.Sub(*cov.StartedAt) >= connGCPRunningFor {
			s.State, s.At = connScanFailed, TS(cov.StartedAt)
		} else {
			s.State, s.At = connScanRunning, TS(cov.StartedAt)
		}
	case models.ScanStatusComplete, models.ScanStatusPartial:
		s.State, s.At = connScanFinished, TS(cov.FinishedAt)
	case models.ScanStatusFailed:
		s.State, s.At = connScanFailed, TS(cov.FinishedAt)
	}
	if connCoverageFinished(cov) {
		return s, ConnectionDiscovery{Ready: true, AsOf: TS(cov.FinishedAt)}
	}
	return s, ConnectionDiscovery{}
}

/* ------------------------------- Kubernetes -------------------------------- */

// connKubernetes is every Kubernetes discovery source (kind k8s_webhook).
//
// connection.state: a disabled source is revoked; otherwise the heartbeat
// decides, by the derivation the console already shows
// (DiscoverySource.DeriveConnected, a grace of HeartbeatGracePeriod): recent ->
// connected (verified_at = that heartbeat); never heartbeated -> not_verified,
// reason no_heartbeat; silent for longer -> not_verified, reason
// heartbeat_lost. The heartbeat is connection health only: it is never read as
// inventory currency, which is the sweep's.
func connKubernetes(q *Query, now time.Time) ([]Connection, error) {
	var sources []models.DiscoverySource
	if err := q.DB().Select("id, display_name, config, enabled, cluster_name, last_heartbeat_at, runtime, created_at").
		Where("workspace_id = ? AND kind = ?", q.WS, models.DiscoverySourceK8sWebhook).
		Order("created_at, id").Find(&sources).Error; err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, nil
	}
	sweeps, err := k8sread.New(q.DB(), q.WS).LatestSweeps()
	if err != nil {
		return nil, err
	}
	// The newest sweep of each source (a source normally has one cluster), by
	// observed_at then generation, as the k8sread vocabulary reports it.
	newest := map[uuid.UUID]k8sread.ClusterSweep{}
	for _, cs := range sweeps {
		if cs.Sweep == nil {
			continue
		}
		if prev, ok := newest[cs.SourceID]; !ok || cs.Sweep.ObservedAt.After(prev.Sweep.ObservedAt) ||
			(cs.Sweep.ObservedAt.Equal(prev.Sweep.ObservedAt) && cs.Sweep.Generation > prev.Sweep.Generation) {
			newest[cs.SourceID] = cs
		}
	}
	// The newest APPLIED sweep of each source -- the one whose rows are in the
	// inventory. It is what makes Discovery ready, even when a later sweep
	// failed, and what coverage and scope describe: a sweep that has arrived
	// and not been applied says nothing about rows that do not exist yet.
	projected, err := k8sread.New(q.DB(), q.WS).LatestProjectedSweeps()
	if err != nil {
		return nil, err
	}
	usable := map[uuid.UUID]*k8sread.Sweep{}
	for key, sw := range projected {
		if prev, ok := usable[key.SourceID]; !ok || sw.ObservedAt.After(prev.ObservedAt) {
			usable[key.SourceID] = sw
		}
	}

	out := make([]Connection, 0, len(sources))
	for i := range sources {
		s := &sources[i]
		s.DeriveConnected(now)
		cluster := s.ClusterName
		sweep := newest[s.ID]
		if sweep.Sweep != nil {
			cluster = sweep.Cluster
		}
		native := nameOr(cluster, s.DisplayName)
		conn := Connection{
			ID: s.ID.String(), Provider: ConnProviderK8s, ScopeKind: connScopeCluster,
			Name: nameOr(s.DisplayName, native), NativeID: native, ScopeID: cluster,
			CreatedAt:    T(s.CreatedAt),
			Connection:   connK8sCondition(s),
			Scan:         connK8sScan(s, sweep.Sweep, now),
			Coverage:     connK8sCoverage(usable[s.ID]),
			Graph:        ConnectionGraph{State: connGraphLive},
			ScopeSummary: connK8sScope(s, firstSweep(usable[s.ID], sweep.Sweep)),
			Capabilities: connCapabilities[ConnProviderK8s],
		}
		if sw, ok := usable[s.ID]; ok {
			conn.Discovery = ConnectionDiscovery{Ready: true, AsOf: T(sw.ObservedAt)}
		}
		out = append(out, conn)
	}
	return out, nil
}

func connK8sCondition(s *models.DiscoverySource) ConnectionCondition {
	switch {
	case !s.Enabled:
		return ConnectionCondition{State: connRevoked, ReasonCode: strPtr0(connReasonDisabled)}
	case s.Connected:
		return ConnectionCondition{State: connConnected, VerifiedAt: TS(s.LastHeartbeatAt)}
	case s.LastHeartbeatAt == nil:
		return ConnectionCondition{State: connNotVerified, ReasonCode: strPtr0(connReasonNoHeartbeat)}
	default:
		return ConnectionCondition{State: connNotVerified, ReasonCode: strPtr0(connReasonHeartbeatLost), VerifiedAt: TS(s.LastHeartbeatAt)}
	}
}

// connK8sScan is the newest sweep as a scan: its status received (arrived, not
// yet applied) -> running, projected -> finished, failed -> failed; no sweep ->
// never_run. at is the sweep's observed_at. heartbeat_at is the agent's last
// heartbeat, and reports_every_seconds the interval the source's config states
// for the agent's periodic report (resync_minutes), null when the config does
// not say: nothing else records how often an agent reports.
func connK8sScan(s *models.DiscoverySource, sw *k8sread.Sweep, now time.Time) ConnectionScan {
	out := ConnectionScan{State: connScanNever, HeartbeatAt: TS(s.LastHeartbeatAt)}
	var cfg struct {
		ResyncMinutes *int64 `json:"resync_minutes"`
	}
	if len(s.Config) > 0 {
		_ = json.Unmarshal(s.Config, &cfg)
	}
	if cfg.ResyncMinutes != nil && *cfg.ResyncMinutes > 0 {
		sec := *cfg.ResyncMinutes * 60
		out.ReportsEverySeconds = &sec
	}
	if sw == nil {
		return out
	}
	out.RunID, out.At = sw.ID.String(), T(sw.ObservedAt)
	switch sw.Status {
	case models.K8sSweepProjected:
		out.State = connScanFinished
	case models.K8sSweepFailed:
		out.State = connScanFailed
	default: // received
		if now.Sub(sw.ObservedAt) >= connSweepReceivedFor {
			out.State = connScanFailed
		} else {
			out.State = connScanRunning
		}
	}
	return out
}

// connK8sCoverage maps the sweep's coverage word (k8sread's vocabulary):
// complete -> complete; namespaced_only -> partial, naming the gap; incomplete
// -> partial (a read failed: not "denied", nothing was refused), naming it;
// not swept -> unknown, no gap to name.
func connK8sCoverage(sw *k8sread.Sweep) ConnectionCoverage {
	out := ConnectionCoverage{State: connCovUnknown, Gaps: []ConnectionGap{}}
	if sw == nil {
		return out
	}
	switch sw.Coverage {
	case k8sread.CoverageComplete:
		out.State = connCovComplete
	case k8sread.CoverageNamespaced, k8sread.CoverageIncomplete:
		out.State = connCovPartial
		out.Gaps = append(out.Gaps, ConnectionGap{Surface: inventoryK8sSurface, State: sw.Coverage})
	}
	return out
}

// connK8sScope is "all namespaces" or "N namespaces": what the agent reports it
// resolved (runtime.only_namespaces, set from its own configuration), else the
// source's config (namespace_mode include + namespaces), else what the newest
// sweep read (a cluster-scoped sweep is all namespaces; a namespaced one its
// namespaces). Nothing known: "scope not reported".
func connK8sScope(s *models.DiscoverySource, sw *k8sread.Sweep) string {
	var rt struct {
		Only *[]string `json:"only_namespaces"`
	}
	if len(s.Runtime) > 0 {
		_ = json.Unmarshal(s.Runtime, &rt)
	}
	if rt.Only != nil {
		return namespacesWord(len(*rt.Only))
	}
	var cfg struct {
		Mode       string   `json:"namespace_mode"`
		Namespaces []string `json:"namespaces"`
	}
	if len(s.Config) > 0 {
		_ = json.Unmarshal(s.Config, &cfg)
	}
	switch {
	case cfg.Mode == "include" && len(cfg.Namespaces) > 0:
		return namespacesWord(len(cfg.Namespaces))
	case cfg.Mode == "all":
		return namespacesWord(0)
	case sw != nil && sw.ClusterScoped:
		return namespacesWord(0)
	case sw != nil && len(sw.Namespaces) > 0:
		return namespacesWord(len(sw.Namespaces))
	}
	return "scope not reported"
}

func namespacesWord(n int) string {
	if n == 0 {
		return "all namespaces"
	}
	return countWord(n, "namespace", "namespaces", "")
}

/* --------------------------------- GitHub ---------------------------------- */

// connGitHubRow is a repo_scan discovery source, its integration and its two
// latest runs, as one row.
type connGitHubRow struct {
	ID          uuid.UUID
	DisplayName string
	Config      json.RawMessage
	Enabled     bool
	CreatedAt   time.Time

	IntegStatus     *string
	IntegVerifiedAt *time.Time

	LatestID         *uuid.UUID
	LatestStatus     *string
	LatestQueuedAt   *time.Time
	LatestStartedAt  *time.Time
	LatestFinishedAt *time.Time

	DoneID            *uuid.UUID
	DoneFinishedAt    *time.Time
	DoneComplete      *bool
	DoneReposSelected int
	DoneReposScanned  int
	DoneReposFailed   int
	DoneBranchesSkip  int
	DoneFilesFailed   int
}

// connGitHubSQL: one row per repo_scan source -- its iga_integrations row
// (config.integration_id, a guarded uuid cast), its latest run that is not
// cancelled (an operator cancelling a scan did not make it fail, so the
// attempt before it still speaks for the source), and its latest succeeded
// run -- by index probes per source, in one statement.
const connGitHubSQL = `
	SELECT s.id, s.display_name, s.config, s.enabled, s.created_at,
	       i.status AS integ_status, i.verified_at AS integ_verified_at,
	       l.id AS latest_id, l.status AS latest_status, l.queued_at AS latest_queued_at,
	       l.started_at AS latest_started_at, l.finished_at AS latest_finished_at,
	       d.id AS done_id, d.finished_at AS done_finished_at, d.complete AS done_complete,
	       d.repos_selected AS done_repos_selected, d.repos_scanned AS done_repos_scanned,
	       d.repos_failed AS done_repos_failed, d.branches_skipped AS done_branches_skip,
	       d.files_failed AS done_files_failed
	  FROM discovery_sources s
	  LEFT JOIN iga_integrations i
	         ON i.workspace_id = s.workspace_id
	        AND i.id = (CASE WHEN s.config->>'integration_id' ~ '^[0-9a-fA-F-]{36}$'
	                         THEN (s.config->>'integration_id')::uuid END)
	  LEFT JOIN LATERAL (
	        SELECT r.id, r.status, r.queued_at, r.started_at, r.finished_at
	          FROM discovery_scan_runs r
	         WHERE r.workspace_id = s.workspace_id AND r.source_id = s.id AND r.status <> 'cancelled'
	         ORDER BY r.queued_at DESC, r.id DESC LIMIT 1) l ON true
	  LEFT JOIN LATERAL (
	        SELECT r.id, r.finished_at, r.complete, r.repos_selected, r.repos_scanned,
	               r.repos_failed, r.branches_skipped, r.files_failed
	          FROM discovery_scan_runs r
	         WHERE r.workspace_id = s.workspace_id AND r.source_id = s.id AND r.status = 'succeeded'
	         ORDER BY r.queued_at DESC, r.id DESC LIMIT 1) d ON true
	 WHERE s.workspace_id = ? AND s.kind = ?
	 ORDER BY s.created_at, s.id`

// connGitHub is every GitHub discovery source (kind repo_scan).
//
// connection.state, from the source and its integration (the App
// installation the source is bound to, config.integration_id): a disabled
// source, or an integration disconnected or revoked -> revoked; a degraded
// integration -> authentication_failed; an integration pending, missing or
// never verified -> not_verified; active and verified -> connected. reason_code
// names the cause: disabled, integration_<status>, or integration_missing.
//
// scan: the latest non-cancelled run (queued, running, succeeded -> finished,
// failed). coverage: the latest SUCCEEDED run's repositories scanned against
// those selected (what data exists). graph: not_applicable -- there is no
// GitHub graph writer, so nothing of a GitHub source is in a publication
// (042 added the columns; nothing writes them). discovery: ready when a
// succeeded scan exists, as_of its finished_at.
func connGitHub(q *Query) ([]Connection, error) {
	var rows []connGitHubRow
	if err := q.DB().Raw(connGitHubSQL, q.WS, models.DiscoverySourceRepoScan).Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Connection, 0, len(rows))
	for i := range rows {
		g := &rows[i]
		var cfg struct {
			Account      string `json:"account"`
			Repositories struct {
				Mode    string   `json:"mode"`
				Include []string `json:"include"`
			} `json:"repositories"`
		}
		_ = json.Unmarshal(g.Config, &cfg)
		native := nameOr(cfg.Account, g.DisplayName)
		conn := Connection{
			ID: g.ID.String(), Provider: ConnProviderGitHub, ScopeKind: connScopeOrganisation,
			Name: nameOr(g.DisplayName, native), NativeID: native, ScopeID: cfg.Account,
			CreatedAt:    T(g.CreatedAt),
			Connection:   connGitHubCondition(g),
			Scan:         connGitHubScan(g),
			Coverage:     connGitHubCoverage(g),
			Graph:        ConnectionGraph{State: connGraphNA},
			ScopeSummary: connGitHubScope(cfg.Repositories.Mode, len(cfg.Repositories.Include)),
			Capabilities: connCapabilities[ConnProviderGitHub],
		}
		if g.DoneID != nil && g.DoneFinishedAt != nil {
			conn.Discovery = ConnectionDiscovery{Ready: true, AsOf: TS(g.DoneFinishedAt)}
		}
		out = append(out, conn)
	}
	return out, nil
}

func connGitHubCondition(g *connGitHubRow) ConnectionCondition {
	if !g.Enabled {
		return ConnectionCondition{State: connRevoked, ReasonCode: strPtr0(connReasonDisabled)}
	}
	if g.IntegStatus == nil {
		return ConnectionCondition{State: connNotVerified, ReasonCode: strPtr0(connReasonIntegrationNone)}
	}
	reason := strPtr0(connReasonIntegrationState + *g.IntegStatus)
	switch *g.IntegStatus {
	case "disconnected", "revoked":
		return ConnectionCondition{State: connRevoked, ReasonCode: reason}
	case "degraded":
		return ConnectionCondition{State: connAuthFailed, ReasonCode: reason, VerifiedAt: TS(g.IntegVerifiedAt)}
	case "active":
		if g.IntegVerifiedAt != nil {
			return ConnectionCondition{State: connConnected, VerifiedAt: TS(g.IntegVerifiedAt)}
		}
		reason = strPtr0(connReasonUnverified)
	}
	return ConnectionCondition{State: connNotVerified, ReasonCode: reason}
}

func connGitHubScan(g *connGitHubRow) ConnectionScan {
	if g.LatestID == nil || g.LatestStatus == nil {
		return ConnectionScan{State: connScanNever}
	}
	s := ConnectionScan{RunID: g.LatestID.String()}
	switch *g.LatestStatus {
	case models.ScanRunQueued:
		s.State, s.At = connScanQueued, TS(g.LatestQueuedAt)
	case models.ScanRunRunning:
		s.State, s.At = connScanRunning, TS(g.LatestStartedAt)
	case models.ScanRunSucceeded:
		s.State, s.At = connScanFinished, TS(g.LatestFinishedAt)
	default: // failed
		s.State, s.At = connScanFailed, TS(g.LatestFinishedAt)
	}
	return s
}

// connGitHubCoverage reads the latest succeeded run: complete_for_selected_scope
// -> complete; otherwise partial with the surfaces that fell short
// (repositories that failed to open, branches skipped by the cap, files that
// failed), or denied when repositories were selected and none was read; no
// succeeded run -> unknown.
func connGitHubCoverage(g *connGitHubRow) ConnectionCoverage {
	out := ConnectionCoverage{State: connCovUnknown, Gaps: []ConnectionGap{}}
	if g.DoneID == nil || g.DoneComplete == nil {
		return out
	}
	if *g.DoneComplete {
		out.State = connCovComplete
		return out
	}
	out.State = connCovPartial
	if g.DoneReposFailed > 0 || (g.DoneBranchesSkip == 0 && g.DoneFilesFailed == 0) {
		state := connCovPartial
		if g.DoneReposSelected > 0 && g.DoneReposScanned == 0 {
			state, out.State = connCovDenied, connCovDenied
		}
		out.Gaps = append(out.Gaps, ConnectionGap{Surface: "repositories", State: state})
	}
	if g.DoneBranchesSkip > 0 {
		out.Gaps = append(out.Gaps, ConnectionGap{Surface: "branches", State: connCovPartial})
	}
	if g.DoneFilesFailed > 0 {
		out.Gaps = append(out.Gaps, ConnectionGap{Surface: "files", State: connCovPartial})
	}
	return out
}

// connGitHubScope is the scan plan: mode all -> "all repositories"; selected
// -> "N repositories".
func connGitHubScope(mode string, selected int) string {
	if mode == "all" {
		return "all repositories"
	}
	return countWord(selected, "repository", "repositories", "no repositories selected")
}

// firstSweep is the first sweep that exists.
func firstSweep(sweeps ...*k8sread.Sweep) *k8sread.Sweep {
	for _, sw := range sweeps {
		if sw != nil {
			return sw
		}
	}
	return nil
}
