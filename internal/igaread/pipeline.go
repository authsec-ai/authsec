package igaread

import (
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// GET /api/iga/v1/pipeline (SPEC-iga-phase2-graph.md §5.3, §2.14.7; D-55,
// D-56, D-59, D-89, D-92): the workspace's collection and projection state,
// per AWS account.
//
// It reads, inside the request's §5.1 snapshot, the barrier
// (iga_pipeline_lease), each connector's latest run (cloud_scan_run, D-25),
// that run's projection job and publication, and the current revision. One
// snapshot matters here as much as on any graph read: a run that publishes
// while the request is in flight must not appear as published beside a
// barrier still collecting it. It reports LIVE state (D-82): it is not pinned
// to a revision, and a queued scan is visible the moment it is queued (§2.15).

// Per-account states, §2.14.7 "Pipeline and first-run states". Additive to the
// §5.3 shape: the console renders the state it is TOLD rather than deriving it
// from run and job statuses -- the derivation (D-59's retrying job in
// particular) is the server's to own. PipelineRevoked is D-89's: the
// connection was revoked, nothing will scan it again, and its earlier results
// stay in the graph with connected: false.
const (
	PipelineNeverScanned     = "never_scanned"
	PipelineQueued           = "queued"
	PipelineCollecting       = "collecting"
	PipelineProjecting       = "projecting"
	PipelinePublished        = "published"
	PipelineFailed           = "failed"
	PipelineFirstPublication = "first_publication_pending"
	PipelineRevoked          = "revoked"
)

// PipelineView is the /pipeline data object.
type PipelineView struct {
	Barrier            PipelineBarrier   `json:"barrier"`
	Accounts           []PipelineAccount `json:"accounts"`
	CurrentRev         *int64            `json:"current_rev"`
	CurrentPublishedAt any               `json:"current_published_at"`
}

// PipelineBarrier is the workspace barrier (§2.10A). integration, account_id,
// label and started_at are additive: "Queued behind the scan of sandbox, which
// started 4 min ago" (§2.14.7) needs the holder's account and start, and the
// run the barrier holds may be no account's latest_run (a connector can have a
// new queued run while its previous, published run is still projecting). All
// null when the barrier is idle.
type PipelineBarrier struct {
	State       string `json:"state"`
	ScanRun     any    `json:"scan_run"`
	Since       any    `json:"since"`
	Integration any    `json:"integration"`
	AccountID   any    `json:"account_id"`
	Label       any    `json:"label"`
	StartedAt   any    `json:"started_at"`
}

// PipelineAccount is one AWS connector's line.
type PipelineAccount struct {
	Integration string `json:"integration"`
	AccountID   string `json:"account_id"`
	Label       string `json:"label"`
	// ConnectorStatus is active | error | revoked (additive, D-89, D-92): a
	// connector whose last verification failed still scans; a revoked one
	// never will.
	ConnectorStatus  string         `json:"connector_status"`
	State            string         `json:"state"`
	LatestRun        map[string]any `json:"latest_run"`
	Projection       map[string]any `json:"projection"`
	LastPublishedRev *int64         `json:"last_published_rev"`
}

// pipelineRun is a run with its projection job and publication (033: at most
// one of each per run), and whether the graph holds its connector at all.
type pipelineRun struct {
	models.CloudScanRun
	JobStatus     *string
	JobAttempts   *int
	JobLastError  *string
	PubRev        *int64
	EverPublished bool
}

// PipelineLatestRunsSQL reads each AWS connector's latest run (D-92) with its
// projection job, its publication, and whether the graph holds the connector
// at all -- a FIXED amount of work per connector, however long its run history
// (cloud_scan_run has no retention, and the console polls this route under the
// §5.1 3 s budget). Exported so a test can EXPLAIN it; nothing else runs it.
//
// Per connector, two index probes of LIMIT 1, never a sort of its history:
//   - its live run -- queued or running, at most one (uq_cloud_scan_run_live);
//   - else its newest run by (requested_at DESC, id DESC)
//     (idx_cloud_scan_run_history).
//
// Ranked explicitly rather than trusting requested_at alone: a refused claim
// moves a live run's requested_at (T1.3), and the ranking must not depend on
// which way it moved. Named columns, never r.*: the coverage jsonb is not read.
//
// ever_published: the connector has a partition watermark (iga_projection_state,
// one index probe). A watermark is written in the SAME transaction as the
// publication of the run it names (the projector's recordState), so "the graph
// holds a publication of this connector's runs" and "it has a watermark" are
// one fact -- and the watermark answers it without walking the history.
const PipelineLatestRunsSQL = `
	SELECT r.id, r.connector_id, r.status, r.requested_at, r.started_at, r.published_at,
	       r.updated_at, r.last_error,
	       j.status AS job_status, j.attempts AS job_attempts, j.last_error AS job_last_error,
	       p.rev AS pub_rev,
	       EXISTS (SELECT 1 FROM iga_projection_state ps
	                WHERE ps.workspace_id = c.workspace_id AND ps.connector_id = c.id) AS ever_published
	  FROM cloud_connector c
	 CROSS JOIN LATERAL (
	        SELECT x.id, x.connector_id, x.status, x.requested_at, x.started_at, x.published_at,
	               x.updated_at, x.last_error
	          FROM ((SELECT 0 AS pick, l.id, l.connector_id, l.status, l.requested_at, l.started_at,
	                        l.published_at, l.updated_at, l.last_error
	                   FROM cloud_scan_run l
	                  WHERE l.connector_id = c.id AND l.workspace_id = c.workspace_id
	                    AND l.status IN (?, ?)
	                  ORDER BY l.requested_at DESC, l.id DESC
	                  LIMIT 1)
	                UNION ALL
	                (SELECT 1 AS pick, n.id, n.connector_id, n.status, n.requested_at, n.started_at,
	                        n.published_at, n.updated_at, n.last_error
	                   FROM cloud_scan_run n
	                  WHERE n.workspace_id = c.workspace_id AND n.connector_id = c.id
	                  ORDER BY n.requested_at DESC, n.id DESC
	                  LIMIT 1)) x
	         ORDER BY x.pick
	         LIMIT 1) r
	  LEFT JOIN iga_projection_job j ON j.workspace_id = c.workspace_id AND j.scan_run_id = r.id
	  LEFT JOIN iga_publication p ON p.workspace_id = c.workspace_id AND p.scan_run_id = r.id
	 WHERE c.workspace_id = ? AND c.provider = ?`

// Pipeline reads the workspace's pipeline state in the snapshot.
func (q *Query) Pipeline() (*PipelineView, error) {
	tx := q.DB()
	view := &PipelineView{Accounts: []PipelineAccount{}}
	if q.Rev != nil {
		rev := q.Rev.Rev
		view.CurrentRev = &rev
		view.CurrentPublishedAt = T(q.Rev.PublishedAt)
	}

	// EVERY AWS connector, with its status (D-92) -- a revoked one included
	// and said to be revoked (D-89), never silently dropped: its results are
	// still in the graph. "No integration" (§2.14.7) is no connector that is
	// not revoked, which the console reads from these lines.
	var connectors []models.CloudConnector
	if err := tx.Where("workspace_id = ? AND provider = ?", q.WS, models.CloudProviderAWS).
		Find(&connectors).Error; err != nil {
		return nil, err
	}

	// Each connector's latest run (D-92): its newest NON-TERMINAL run when it
	// has one -- uq_cloud_scan_run_live allows at most one -- else its newest
	// terminal run; and whether the graph holds the connector. One row per
	// connector that has any run (PipelineLatestRunsSQL); a connector with
	// none was never scanned, so never published either.
	var latest []pipelineRun
	if err := tx.Raw(PipelineLatestRunsSQL,
		models.CloudScanRunQueued, models.CloudScanRunRunning,
		q.WS, models.CloudProviderAWS).Scan(&latest).Error; err != nil {
		return nil, err
	}
	latestBy := make(map[uuid.UUID]*pipelineRun, len(latest))
	everPublished := make(map[uuid.UUID]bool, len(latest))
	for i := range latest {
		latestBy[latest[i].ConnectorID] = &latest[i]
		everPublished[latest[i].ConnectorID] = latest[i].EverPublished
	}

	barrier, holderRun, err := q.pipelineBarrier()
	if err != nil {
		return nil, err
	}
	view.Barrier = barrier

	for i := range connectors {
		c := &connectors[i]
		acct := PipelineAccount{
			Integration:     R(RefConnector, c.ID),
			AccountID:       c.ScopeID,
			Label:           connectorLabel(c.Attrs, c.ScopeID),
			ConnectorStatus: c.Status,
		}
		// D-56: last_published_rev is the revision the graph is at -- the
		// current rev -- for every connector the graph holds a publication of;
		// null before its first ("First publication pending"). The rev that
		// published the connector's own run is on the run, projection.rev.
		if everPublished[c.ID] && view.CurrentRev != nil {
			rev := *view.CurrentRev
			acct.LastPublishedRev = &rev
		}
		run := latestBy[c.ID]
		acct.State = accountState(c.Status, run, everPublished[c.ID])
		if run != nil {
			acct.LatestRun = latestRunView(run, barrier.State, holderRun)
			acct.Projection = projectionView(run)
		}
		view.Accounts = append(view.Accounts, acct)
	}
	// Ordered by label then id (D-92): stable across requests, and the order
	// the operator named the accounts in.
	sort.SliceStable(view.Accounts, func(i, j int) bool {
		a, b := view.Accounts[i], view.Accounts[j]
		if la, lb := strings.ToLower(a.Label), strings.ToLower(b.Label); la != lb {
			return la < lb
		}
		return a.Integration < b.Integration
	})
	return view, nil
}

// connectorLabel is the operator's display name, falling back to the account
// id (D-3) -- display only.
func connectorLabel(attrs []byte, accountID string) string {
	label := (&models.CloudConnector{Attrs: attrs}).AWSAttrs().DisplayName
	if label == "" {
		return accountID
	}
	return label
}

// pipelineBarrier reads the workspace barrier and the run it holds.
//
// since is NEVER the lease's updated_at (D-92): the heartbeat bumps that on
// every renewal. Collecting -> the held run's started_at (a refused claim
// clears it, D-55, so it is when collection began); projecting -> its
// published_at, the moment the barrier was handed to the projection job in
// the publish transaction; idle -> null. A workspace that never scanned in
// pipeline mode has no row: idle.
func (q *Query) pipelineBarrier() (PipelineBarrier, *uuid.UUID, error) {
	b := PipelineBarrier{State: models.PipelineIdle}
	var leases []models.IGAPipelineLease
	if err := q.DB().Raw(`SELECT * FROM iga_pipeline_lease WHERE workspace_id = ?`, q.WS).
		Scan(&leases).Error; err != nil {
		return b, nil, err
	}
	if len(leases) == 0 {
		return b, nil, nil
	}
	lease := leases[0]
	b.State = lease.State
	if lease.State == models.PipelineIdle || lease.ScanRunID == nil {
		return b, nil, nil
	}
	runID := *lease.ScanRunID
	b.ScanRun = R(RefScanRun, runID)

	var held []struct {
		ConnectorID uuid.UUID
		StartedAt   *time.Time
		PublishedAt *time.Time
		ScopeID     string
		Attrs       []byte
	}
	if err := q.DB().Raw(`
		SELECT r.connector_id, r.started_at, r.published_at, c.scope_id, c.attrs
		  FROM cloud_scan_run r
		  JOIN cloud_connector c ON c.workspace_id = r.workspace_id AND c.id = r.connector_id
		 WHERE r.workspace_id = ? AND r.id = ?`, q.WS, runID).Scan(&held).Error; err != nil {
		return b, nil, err
	}
	if len(held) == 1 {
		h := held[0]
		b.Integration = R(RefConnector, h.ConnectorID)
		b.AccountID = h.ScopeID
		b.Label = connectorLabel(h.Attrs, h.ScopeID)
		b.StartedAt = TS(h.StartedAt)
		switch lease.State {
		case models.PipelineCollecting:
			b.Since = TS(h.StartedAt)
		case models.PipelineProjecting:
			b.Since = TS(h.PublishedAt)
		}
	}
	return b, &runID, nil
}

// accountState derives §2.14.7's per-account state from the connector's
// status, its latest run and that run's projection job -- the table's
// conditions, in its order of precedence for one account.
func accountState(connectorStatus string, run *pipelineRun, everPublished bool) string {
	if connectorStatus == models.CloudConnectorRevoked {
		return PipelineRevoked // D-89
	}
	if run == nil {
		return PipelineNeverScanned // Connected, never scanned
	}
	switch run.Status {
	case models.CloudScanRunQueued:
		return PipelineQueued
	case models.CloudScanRunRunning:
		return PipelineCollecting
	case models.CloudScanRunFailed, models.CloudScanRunAbandoned:
		return PipelineFailed
	case models.CloudScanRunPublished:
		if run.JobStatus == nil {
			// Published with no projection job: scanned while the switch was
			// off. The graph holds an earlier run of this account, or nothing
			// of it yet ("Connector scanned, no publication yet").
			if everPublished {
				return PipelinePublished
			}
			return PipelineFirstPublication
		}
		switch *run.JobStatus {
		case models.ProjectionQueued, models.ProjectionRunning:
			return PipelineProjecting
		case models.ProjectionFailed:
			// D-59: below the attempts ceiling the job is retried and still
			// holds the barrier -- projecting, retrying.
			if jobRetrying(run) {
				return PipelineProjecting
			}
			return PipelineFailed
		case models.ProjectionAbandoned:
			return PipelineFailed
		case models.ProjectionComplete:
			return PipelinePublished
		}
	}
	// A status this build does not know: never claim it is fine.
	return PipelineFailed
}

func jobRetrying(run *pipelineRun) bool {
	return run.JobStatus != nil && *run.JobStatus == models.ProjectionFailed &&
		run.JobAttempts != nil && *run.JobAttempts < repositories.MaxProjectionAttempts
}

// latestRunView renders latest_run with the fields §5.3 shows for its status:
// queued -> queued_at and waiting_on; running -> started_at; finished runs ->
// their start and end, and the error of a failed or abandoned one (D-92).
//
// queued_at is requested_at: when the run LAST (re)entered the queue (D-55).
// No column keeps the original enqueue time, and a refused claim moves
// requested_at (T1.3).
//
// waiting_on names the run the barrier holds whenever another run holds it
// (D-92): the workspace barrier serializes collection and projection
// (§2.10A), so a queued run behind a busy barrier is waiting on exactly that
// run -- another account's scan, or this account's own previous run still
// projecting.
func latestRunView(run *pipelineRun, barrierState string, holder *uuid.UUID) map[string]any {
	v := map[string]any{"ref": R(RefScanRun, run.ID), "status": run.Status}
	switch run.Status {
	case models.CloudScanRunQueued:
		v["queued_at"] = T(run.RequestedAt)
		var waiting any
		if barrierState != models.PipelineIdle && holder != nil && *holder != run.ID {
			waiting = R(RefScanRun, *holder)
		}
		v["waiting_on"] = waiting
	case models.CloudScanRunRunning:
		v["started_at"] = TS(run.StartedAt)
	case models.CloudScanRunPublished:
		v["started_at"] = TS(run.StartedAt)
		v["published_at"] = TS(run.PublishedAt)
	case models.CloudScanRunFailed, models.CloudScanRunAbandoned:
		v["started_at"] = TS(run.StartedAt)
		// "Last updated" (D-91): 020 has no finished_at, and the scan path
		// does not touch a terminal run again.
		v["finished_at"] = T(run.UpdatedAt)
		var e any
		if run.LastError != "" {
			e = run.LastError
		}
		v["error"] = e
	}
	return v
}

// projectionView is the latest run's projection: null when the run has no job,
// else {status, rev} (§5.3), plus D-59's retrying, attempts and last_error.
func projectionView(run *pipelineRun) map[string]any {
	if run.JobStatus == nil {
		return nil
	}
	v := map[string]any{"status": *run.JobStatus, "rev": nil}
	if run.PubRev != nil {
		v["rev"] = *run.PubRev
	}
	attempts := 0
	if run.JobAttempts != nil {
		attempts = *run.JobAttempts
	}
	v["attempts"] = attempts
	v["retrying"] = jobRetrying(run)
	var lastErr any
	if run.JobLastError != nil && *run.JobLastError != "" {
		lastErr = *run.JobLastError
	}
	v["last_error"] = lastErr
	return v
}
