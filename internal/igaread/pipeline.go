package igaread

import (
	"time"

	"github.com/google/uuid"

	"github.com/authsec-ai/authsec/models"
	repositories "github.com/authsec-ai/authsec/repository"
)

// GET /api/iga/v1/pipeline (SPEC-iga-phase2-graph.md §5.3, §2.14.7): the
// workspace's collection and projection state, per AWS account.
//
// It reads, inside the request's §5.1 snapshot, the barrier (iga_pipeline_lease),
// each connector's latest run (cloud_scan_run, D-25), that run's projection job
// and publication, and the revision that last published each connector. One
// snapshot matters here as much as on any graph read: a run that publishes
// while the request is in flight must not appear as published beside a barrier
// still collecting it.

// Per-account states, §2.14.7 "Pipeline and first-run states". Additive to the
// §5.3 shape: the console renders the state it is TOLD rather than deriving it
// from run and job statuses -- the derivation (D-59's retrying job in
// particular) is the server's to own.
const (
	PipelineNeverScanned     = "never_scanned"
	PipelineQueued           = "queued"
	PipelineCollecting       = "collecting"
	PipelineProjecting       = "projecting"
	PipelinePublished        = "published"
	PipelineFailed           = "failed"
	PipelineFirstPublication = "first_publication_pending"
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
// new queued run while its previous, published run is still projecting).
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
	// ConnectorStatus is active | error (additive): a connector whose last
	// verification failed still scans, and still has a line here.
	ConnectorStatus  string         `json:"connector_status"`
	State            string         `json:"state"`
	LatestRun        map[string]any `json:"latest_run"`
	Projection       map[string]any `json:"projection"`
	LastPublishedRev *int64         `json:"last_published_rev"`
}

// pipelineRun is a run with its projection job and publication (033: at most
// one of each per run).
type pipelineRun struct {
	models.CloudScanRun
	JobStatus    *string
	JobAttempts  *int
	JobLastError *string
	PubRev       *int64
}

// Pipeline reads the workspace's pipeline state in the snapshot.
func (q *Query) Pipeline() (*PipelineView, error) {
	tx := q.DB()
	view := &PipelineView{Accounts: []PipelineAccount{}}
	if q.Rev != nil {
		rev := q.Rev.Rev
		view.CurrentRev = &rev
		view.CurrentPublishedAt = T(q.Rev.PublishedAt)
	}

	// "No integration: no active AWS connector" (§2.14.7) -- no accounts and no
	// zeros. A revoked connector is not an integration any more; its earlier
	// results stay in the graph (connected: false), but nothing will scan it.
	var connectors []models.CloudConnector
	if err := tx.Where("workspace_id = ? AND provider = ? AND status <> ?",
		q.WS, models.CloudProviderAWS, models.CloudConnectorRevoked).
		Order("created_at, id").Find(&connectors).Error; err != nil {
		return nil, err
	}

	// Each connector's LATEST run. requested_at DESC is creation order per
	// connector: at most one run of a connector is live (uq_cloud_scan_run_live),
	// a new one can be enqueued only once the previous is terminal, and a refused
	// claim only ever moves the live run's requested_at forward.
	var latest []pipelineRun
	if err := tx.Raw(`
		SELECT DISTINCT ON (r.connector_id) r.*,
		       j.status AS job_status, j.attempts AS job_attempts, j.last_error AS job_last_error,
		       p.rev AS pub_rev
		  FROM cloud_scan_run r
		  LEFT JOIN iga_projection_job j ON j.workspace_id = r.workspace_id AND j.scan_run_id = r.id
		  LEFT JOIN iga_publication p ON p.workspace_id = r.workspace_id AND p.scan_run_id = r.id
		 WHERE r.workspace_id = ?
		 ORDER BY r.connector_id, r.requested_at DESC, r.id DESC`, q.WS).Scan(&latest).Error; err != nil {
		return nil, err
	}
	latestBy := make(map[uuid.UUID]*pipelineRun, len(latest))
	for i := range latest {
		latestBy[latest[i].ConnectorID] = &latest[i]
	}

	// D-56: last_published_rev is the revision that published this connector's
	// latest projected run.
	var pubs []struct {
		ConnectorID uuid.UUID
		Rev         int64
	}
	if err := tx.Raw(`
		SELECT DISTINCT ON (r.connector_id) r.connector_id, p.rev
		  FROM iga_publication p
		  JOIN cloud_scan_run r ON r.workspace_id = p.workspace_id AND r.id = p.scan_run_id
		 WHERE p.workspace_id = ?
		 ORDER BY r.connector_id, p.rev DESC`, q.WS).Scan(&pubs).Error; err != nil {
		return nil, err
	}
	lastRev := make(map[uuid.UUID]int64, len(pubs))
	for _, p := range pubs {
		lastRev[p.ConnectorID] = p.Rev
	}

	barrier, holderRun, err := q.pipelineBarrier()
	if err != nil {
		return nil, err
	}
	view.Barrier = barrier

	for i := range connectors {
		c := &connectors[i]
		attrs := c.AWSAttrs()
		label := attrs.DisplayName
		if label == "" {
			label = c.ScopeID
		}
		acct := PipelineAccount{
			Integration:     R(RefConnector, c.ID),
			AccountID:       c.ScopeID,
			Label:           label,
			ConnectorStatus: c.Status,
		}
		if rev, ok := lastRev[c.ID]; ok {
			r := rev
			acct.LastPublishedRev = &r
		}
		run := latestBy[c.ID]
		acct.State = accountState(run, acct.LastPublishedRev != nil)
		if run != nil {
			acct.LatestRun = latestRunView(run, barrier.State, holderRun)
			acct.Projection = projectionView(run)
		}
		view.Accounts = append(view.Accounts, acct)
	}
	return view, nil
}

// pipelineBarrier reads the workspace barrier and the run it holds.
//
// since: collecting -> the held run's started_at (a refused claim clears it,
// D-55, so it is when collection began); projecting -> its published_at, the
// moment the barrier was handed to the projection job in the publish
// transaction; idle -> updated_at, which only a transition to idle writes (the
// heartbeat that bumps it runs only while the barrier is held). A workspace
// that never scanned in pipeline mode has no row: idle, since null.
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
		b.Since = T(lease.UpdatedAt)
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
		conn := models.CloudConnector{Attrs: h.Attrs}
		label := conn.AWSAttrs().DisplayName
		if label == "" {
			label = h.ScopeID
		}
		b.Integration = R(RefConnector, h.ConnectorID)
		b.AccountID = h.ScopeID
		b.Label = label
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

// accountState derives §2.14.7's per-account state from the connector's latest
// run and its projection job -- the table's conditions, in its order of
// precedence for one account.
func accountState(run *pipelineRun, everPublished bool) string {
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
	return PipelineFailed
}

func jobRetrying(run *pipelineRun) bool {
	return run.JobStatus != nil && *run.JobStatus == models.ProjectionFailed &&
		run.JobAttempts != nil && *run.JobAttempts < repositories.MaxProjectionAttempts
}

// latestRunView renders latest_run with the fields §5.3 shows for its status:
// queued -> queued_at and waiting_on; running -> started_at; finished runs ->
// their start and end, and the error of a failed one.
//
// queued_at is requested_at: when the run last (re)entered the queue. D-55:
// no column keeps the original enqueue time, and a refused claim moves
// requested_at (T1.3).
//
// waiting_on names the run the barrier holds when it is not this one: the
// workspace barrier serializes collection and projection (§2.10A), so a queued
// run behind a busy barrier is waiting on exactly that run -- another
// account's scan, or this account's own previous run still projecting.
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
		// A terminal failed or abandoned run is never updated again, so its
		// updated_at is when it finished (020 has no finished_at).
		v["finished_at"] = T(run.UpdatedAt)
		v["last_error"] = run.LastError
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
